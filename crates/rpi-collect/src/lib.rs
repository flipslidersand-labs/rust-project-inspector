//! Workspace collection and AST parsing.
//!
//! [`collect`] resolves a workspace via `cargo metadata`, discovers every `.rs`
//! file belonging to each member crate, and parses each file **once** with
//! `syn`. Inspections then read the shared [`Context`] without re-parsing.

use std::collections::{BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

mod worker;
pub use worker::{ParseWorker, WorkerError, MAX_WORKER_PATH_BYTES};

use anyhow::{Context as _, Result};
use cargo_metadata::MetadataCommand;
use rpi_core::{AuditVuln, Config, Context, CrateData, SourceFile, WorkspaceInfo};

/// `eprintln!` for diagnostics that may embed untrusted paths or names from the
/// inspected repository: control/bidi characters are escaped first.
macro_rules! safe_eprintln {
    ($($arg:tt)*) => {
        eprintln!("{}", rpi_core::sanitize_for_terminal(&format!($($arg)*)))
    };
}

/// Options controlling optional, potentially-slow collection steps.
#[derive(Debug, Clone, Copy, Default)]
pub struct CollectOptions {
    /// Run `cargo audit --json` and populate [`Context::audit`]. Off by default
    /// so a normal `rpi inspect` stays fast and network-free.
    pub run_audit: bool,
}

/// Build a [`Context`] for the workspace rooted at `root`.
///
/// `.rs` files that cannot be read or parsed are skipped with a warning on
/// stderr (path, and line for syntax errors) so a single bad file never aborts
/// the whole run.
pub fn collect(root: &Path, opts: CollectOptions) -> Result<Context> {
    collect_inner(root, opts, None)
        .with_context(|| format!("failed to inspect workspace at {}", root.display()))
}

/// Like [`collect`], but every `.rs` file is first judged by a child
/// `parse-worker` process, so input that makes `syn` abort (or hang) skips only
/// that file with a warning instead of killing the caller. `worker_exe` must be
/// an `rpi` binary (e.g. `std::env::current_exe()` from the CLI).
pub fn collect_isolated(root: &Path, opts: CollectOptions, worker_exe: &Path) -> Result<Context> {
    let mut worker = ParseWorker::new(worker_exe);
    collect_inner(root, opts, Some(&mut worker))
        .with_context(|| format!("failed to inspect workspace at {}", root.display()))
}

/// Parse `path`, asking the worker first when isolation is on.
fn parse_file_via(worker: &mut Option<&mut ParseWorker>, path: &Path) -> Option<SourceFile> {
    if let Some(w) = worker.as_deref_mut() {
        match w.verdict(path) {
            Ok(()) => {}
            Err(WorkerError::Parse(msg)) => {
                safe_eprintln!("{msg}");
                return None;
            }
            Err(e) => {
                safe_eprintln!("warn: skipping {} ({e})", path.display());
                return None;
            }
        }
    }
    parse_file(path)
}

/// Apply `rpi.toml` to the worker: `parse_isolation = false` drops it and
/// `parse_memory_limit_mb` (0 = none) caps the child's address space.
fn configure_worker<'a>(
    worker: Option<&'a mut ParseWorker>,
    config: &Config,
) -> Option<&'a mut ParseWorker> {
    let w = worker.filter(|_| config.parse_isolation)?;
    let mb = config.parse_memory_limit_mb;
    w.set_memory_limit((mb > 0).then(|| mb.saturating_mul(1024 * 1024)));
    Some(w)
}

fn collect_inner(
    root: &Path,
    opts: CollectOptions,
    worker: Option<&mut ParseWorker>,
) -> Result<Context> {
    // Full metadata (deps resolved) so `dep-hygiene` can inspect the whole
    // graph for duplicate versions.
    //
    // Run from a neutral directory and point at the target via `--manifest-path`
    // so the *target's* `.cargo/config.toml` (`build.rustc`, ...) and
    // `rust-toolchain.toml` are not picked up and executed (#100). Trust
    // boundary: cargo still reads the target's manifest and build scripts are
    // never run by `cargo metadata`.
    // Like cargo, use the nearest enclosing Cargo.toml so a subdirectory
    // (`src/`) works; the cwd stays neutral, so this search is safe.
    let resolved = root
        .canonicalize()
        .with_context(|| format!("cannot resolve {}", root.display()))?;
    let manifest = resolved
        .ancestors()
        .map(|d| d.join("Cargo.toml"))
        .find(|m| m.is_file())
        .unwrap_or_else(|| resolved.join("Cargo.toml"));
    let metadata = run_metadata(&manifest)?;
    let root_dir = metadata.workspace_root.clone().into_std_path_buf();
    let config = load_config(&root_dir);
    let mut worker = configure_worker(worker, &config);

    // Names of workspace members, used to split intra- vs external deps.
    let member_names: BTreeSet<String> = metadata
        .workspace_packages()
        .iter()
        .map(|p| p.name.to_string())
        .collect();

    let mut crates = Vec::new();
    for pkg in metadata.workspace_packages() {
        let manifest_path: PathBuf = pkg.manifest_path.clone().into_std_path_buf();
        let root_dir = manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.to_path_buf());

        let mut workspace_deps = Vec::new();
        let mut external_deps = Vec::new();
        let mut external_dep_packages = HashMap::new();
        for dep in &pkg.dependencies {
            // Only normal dependencies form the build graph. A dev/build edge
            // between members (a --dev--> b --normal--> a) is legal in Cargo and
            // must not be read as a cycle (#62).
            if dep.kind != cargo_metadata::DependencyKind::Normal {
                continue;
            }
            // The same dependency under several `[target.*.dependencies]`
            // tables arrives as one edge per table; list it once (#133).
            if member_names.contains(&dep.name) {
                if !workspace_deps.contains(&dep.name) {
                    workspace_deps.push(dep.name.clone());
                }
            } else {
                // Code refers to a renamed dependency by its rename; keep the
                // original package name separately for display (#66).
                let reference = dep.rename.as_deref().unwrap_or(&dep.name);
                if !external_deps.iter().any(|d| d == reference) {
                    external_deps.push(reference.to_string());
                }
                if reference != dep.name {
                    external_dep_packages.insert(reference.to_string(), dep.name.clone());
                }
            }
        }

        let files = collect_rs_files(&root_dir)
            .into_iter()
            .filter_map(|path| parse_file_via(&mut worker, &path))
            .collect();

        crates.push(CrateData {
            name: pkg.name.to_string(),
            manifest_path,
            root_dir,
            workspace_deps,
            external_deps,
            external_dep_packages,
            files,
        });
    }

    let resolved_versions = metadata
        .packages
        .iter()
        .map(|p| (p.name.to_string(), p.version.to_string()))
        .collect();

    let audit = if opts.run_audit {
        run_cargo_audit(&root_dir)
    } else {
        Vec::new()
    };
    let churn = collect_churn(
        &root_dir,
        Duration::from_secs(config.churn_git_timeout_secs),
    );

    let workspace = WorkspaceInfo {
        root: root_dir,
        crates: crates.iter().map(|c| c.name.clone()).collect(),
        crate_manifests: crates
            .iter()
            .map(|c| (c.name.clone(), c.manifest_path.clone()))
            .collect(),
    };

    Ok(Context {
        workspace,
        crates,
        config,
        resolved_versions,
        audit,
        churn,
    })
}

/// Run `cargo metadata` without letting it touch the target's `Cargo.lock` or
/// the network (#135). `--frozen` fails when the lock is missing or stale; then
/// warn and retry the plain call, restoring the original lock state afterwards
/// so the inspected repository is left unmodified.
fn run_metadata(manifest: &Path) -> Result<cargo_metadata::Metadata> {
    let build = |frozen: bool| {
        let mut cmd = MetadataCommand::new();
        cmd.current_dir(neutral_dir()).manifest_path(manifest);
        if frozen {
            cmd.other_options(vec!["--frozen".to_string()]);
        }
        cmd.exec()
    };
    let first = match build(true) {
        Ok(m) => return Ok(m),
        Err(e) => e,
    };
    safe_eprintln!(
        "warn: `cargo metadata --frozen` failed ({first}); retrying without it (Cargo.lock is restored afterwards)"
    );
    // cargo writes the lock at the workspace root, which may be any ancestor
    // of a member manifest (or not exist yet), so snapshot every candidate.
    let snapshot: Vec<(PathBuf, Option<Vec<u8>>)> = manifest
        .ancestors()
        .skip(1)
        .map(|d| d.join("Cargo.lock"))
        .filter_map(|lock| match fs::read(&lock) {
            Ok(bytes) => Some((lock, Some(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some((lock, None)),
            Err(e) => {
                safe_eprintln!(
                    "warn: cannot read {} ({e}); it will not be restored",
                    lock.display()
                );
                None
            }
        })
        .collect();
    let result = build(false);
    for (lock, original) in snapshot {
        let restored = match &original {
            Some(bytes) => {
                if fs::read(&lock).ok().as_deref() == Some(bytes.as_slice()) {
                    continue;
                }
                fs::write(&lock, bytes)
            }
            None => match fs::remove_file(&lock) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                r => r,
            },
        };
        if let Err(e) = restored {
            safe_eprintln!("warn: failed to restore {} ({e})", lock.display());
        }
    }
    result.context("failed to run `cargo metadata`")
}

/// Count how many commits touched each `.rs` file, via `git log --name-only`.
///
/// Best-effort: returns an empty map (after a `[skip]` notice) when `git` is not
/// on PATH, and silently when the root is not a git repo, git fails, or the
/// command exceeds `timeout`. The timeout prevents hangs on repositories with
/// very long histories.
fn collect_churn(root: &Path, timeout: Duration) -> HashMap<PathBuf, usize> {
    if let Some(notice) = skip_notice(
        "churn-hotspot",
        "git",
        "install git and ensure it is on PATH",
        search_path().as_deref(),
    ) {
        safe_eprintln!("{notice}");
        return HashMap::new();
    }
    collect_churn_with(Command::new("git"), root, timeout, CHURN_MAX_OUTPUT)
}

/// [`collect_churn`] with the git invocation injected (`git` is the program and
/// any leading arguments), so tests can substitute a stub.
fn collect_churn_with(
    mut git: Command,
    root: &Path,
    timeout: Duration,
    max: usize,
) -> HashMap<PathBuf, usize> {
    // core.quotepath=false: otherwise git C-quotes non-ASCII paths ("\346...")
    // and they would be dropped by the `.rs` filter below.
    git.args(["-c", "core.quotepath=false", "-C"])
        .arg(root)
        .args(["log", "--name-only", "--pretty=format:"]);
    // Raw bytes: git paths need not be UTF-8; decode lossily afterwards.
    let raw = match run_limited(git, timeout, max) {
        // Require success: a git that fails midway (e.g. a corrupt older
        // object) leaves partial output that would silently undercount churn.
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        Ok(_) | Err(LimitedError::Spawn(_)) => return HashMap::new(),
        Err(LimitedError::Timeout) => {
            safe_eprintln!(
                "warn: `git log` timed out after {}s; churn-hotspot will be skipped \
                 (increase churn_git_timeout_secs in rpi.toml to raise the limit)",
                timeout.as_secs()
            );
            return HashMap::new();
        }
        Err(LimitedError::TooLarge) => {
            safe_eprintln!(
                "warn: `git log` output exceeded {} MiB; churn-hotspot will be skipped",
                max / (1024 * 1024)
            );
            return HashMap::new();
        }
    };

    if raw.is_empty() {
        return HashMap::new();
    }

    // git prints paths relative to the repo toplevel, which may differ from the
    // workspace root; anchor against the toplevel so keys are absolute and match
    // the paths inspections carry.
    let anchor = git_toplevel(root).unwrap_or_else(|| root.to_path_buf());
    let mut churn: HashMap<PathBuf, usize> = HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || !line.ends_with(".rs") {
            continue;
        }
        *churn.entry(anchor.join(line)).or_insert(0) += 1;
    }
    churn
}

/// Absolute path of the git repository root containing `dir`, if any.
pub fn git_toplevel(dir: &Path) -> Option<PathBuf> {
    git_toplevel_with(
        Command::new("git"),
        dir,
        GIT_REV_PARSE_TIMEOUT,
        GIT_REV_PARSE_MAX_OUTPUT,
    )
}

/// Upper bound on `git log` stdout for churn (full history can be large).
const CHURN_MAX_OUTPUT: usize = 64 * 1024 * 1024;

const GIT_REV_PARSE_TIMEOUT: Duration = Duration::from_secs(10);
const GIT_REV_PARSE_MAX_OUTPUT: usize = 1024 * 1024;

/// Why [`run_limited`] gave up on a command.
#[derive(Debug)]
enum LimitedError {
    Spawn(std::io::Error),
    Timeout,
    TooLarge,
}

/// Captured result of [`run_limited`].
#[derive(Debug)]
struct Limited {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run `cmd` with a wall-clock `timeout` and a `max` byte cap on stdout. On
/// timeout or stdout overflow the child is killed. stderr is kept up to `max`
/// bytes and the rest is drained and discarded (it never fails the run).
fn run_limited(mut cmd: Command, timeout: Duration, max: usize) -> Result<Limited, LimitedError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(LimitedError::Spawn)?;
    let mut out = child.stdout.take().expect("stdout was piped");
    let mut err = child.stderr.take().expect("stderr was piped");
    let deadline = std::time::Instant::now() + timeout;

    // (bytes, overflowed)
    let (otx, orx) = mpsc::channel::<(Vec<u8>, bool)>();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut out).take(max as u64 + 1).read_to_end(&mut buf);
        let over = buf.len() > max;
        let _ = otx.send((buf, over));
    });
    let (etx, erx) = mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        let mut keep = Vec::new();
        let _ = (&mut err).take(max as u64).read_to_end(&mut keep);
        let _ = std::io::copy(&mut err, &mut std::io::sink());
        let _ = etx.send(keep);
    });

    let fail = |child: &mut std::process::Child, e: LimitedError| {
        let _ = child.kill();
        let _ = child.wait();
        Err(e)
    };
    let left = |d: std::time::Instant| d.saturating_duration_since(std::time::Instant::now());
    let (stdout, over) = match orx.recv_timeout(left(deadline)) {
        Ok(v) => v,
        Err(_) => return fail(&mut child, LimitedError::Timeout),
    };
    if over {
        return fail(&mut child, LimitedError::TooLarge);
    }
    // stdout closed; the process should exit promptly.
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            _ => return fail(&mut child, LimitedError::Timeout),
        }
    };
    let stderr = erx.recv_timeout(left(deadline)).unwrap_or_default();
    Ok(Limited {
        status,
        stdout,
        stderr,
    })
}

fn git_toplevel_with(
    mut git: Command,
    dir: &Path,
    timeout: Duration,
    max: usize,
) -> Option<PathBuf> {
    git.args(["-C"])
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"]);
    let out = run_limited(git, timeout, max).ok()?;
    if !out.status.success() {
        return None;
    }
    let top = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!top.is_empty()).then(|| PathBuf::from(top))
}

/// Run `cargo audit --json` at `root` and parse advisories. Best-effort:
/// `cargo-audit` is looked up on PATH first and, when absent, a `[skip]` notice
/// is printed and the command is not run. Other failures warn once and return
/// no vulns rather than aborting the inspection.
fn run_cargo_audit(root: &Path) -> Vec<AuditVuln> {
    run_cargo_audit_with(root, search_path().as_deref())
}

fn run_cargo_audit_with(root: &Path, search: Option<&OsStr>) -> Vec<AuditVuln> {
    if let Some(notice) = skip_notice(
        "audit-bridge",
        "cargo-audit",
        "install with `cargo install cargo-audit`",
        search,
    ) {
        safe_eprintln!("{notice}");
        return Vec::new();
    }
    // Call the binary directly: `cargo audit` would let the target's
    // `[alias] audit = ...` run arbitrary code (#101). Neutral cwd + explicit
    // lockfile keep the target's `.cargo/config.toml` out of the picture.
    let Some(bin) = search.and_then(|d| which::which_in("cargo-audit", Some(d), ".").ok()) else {
        return Vec::new();
    };
    let lock = match root.canonicalize() {
        Ok(r) => r.join("Cargo.lock"),
        Err(e) => {
            safe_eprintln!(
                "warn: cannot resolve {} ({e}); skipping audit-bridge",
                root.display()
            );
            return Vec::new();
        }
    };
    if !lock.is_file() {
        safe_eprintln!(
            "[skip] audit-bridge: {} not found (run `cargo generate-lockfile` first)",
            lock.display()
        );
        return Vec::new();
    }
    let mut cmd = Command::new(bin);
    cmd.args(["audit", "--json", "--file"])
        .arg(lock)
        .current_dir(neutral_dir());
    run_audit_command(cmd).unwrap_or_else(|warning| {
        safe_eprintln!("{warning}");
        Vec::new()
    })
}

const AUDIT_TIMEOUT: Duration = Duration::from_secs(120);
const AUDIT_MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// Run a prepared `cargo-audit` command and interpret its output. Non-empty
/// stdout is parsed (cargo-audit exits 1 when it finds vulnerabilities, so the
/// exit status is deliberately ignored). `Err` carries the `warn: ...` message
/// to print; `Ok(vec![])` with nothing to report is a silent empty result.
fn run_audit_command(cmd: Command) -> Result<Vec<AuditVuln>, String> {
    run_audit_command_with(cmd, AUDIT_TIMEOUT, AUDIT_MAX_OUTPUT)
}

fn run_audit_command_with(
    cmd: Command,
    timeout: Duration,
    max: usize,
) -> Result<Vec<AuditVuln>, String> {
    match run_limited(cmd, timeout, max) {
        Ok(out) if !out.stdout.is_empty() => {
            parse_audit_json(&String::from_utf8_lossy(&out.stdout))
        }
        Ok(out) => {
            if out.stderr.is_empty() {
                Ok(Vec::new())
            } else {
                let msg = String::from_utf8_lossy(&out.stderr);
                Err(format!(
                    "warn: `cargo audit` produced no output ({msg}); skipping audit-bridge"
                ))
            }
        }
        Err(LimitedError::Spawn(e)) => Err(format!(
            "warn: `cargo audit` failed to run ({e}); skipping audit-bridge"
        )),
        Err(LimitedError::Timeout) => Err(format!(
            "warn: `cargo audit` timed out after {}s; skipping audit-bridge",
            timeout.as_secs()
        )),
        Err(LimitedError::TooLarge) => Err(format!(
            "warn: `cargo audit` output exceeded {max} bytes; skipping audit-bridge"
        )),
    }
}

/// Working directory for child cargo/cargo-audit processes. cargo, rustup and
/// cargo-audit read `.cargo/config.toml`, `rust-toolchain.toml` and
/// `.cargo/audit.toml` from the cwd (cargo and rustup also from its ancestors),
/// so it must not sit under a world-writable directory like `/tmp` (#100, #101).
fn neutral_dir() -> PathBuf {
    if cfg!(unix) {
        PathBuf::from("/")
    } else {
        std::env::temp_dir()
    }
}

/// Directories searched for external tools: `PATH` plus `$CARGO_HOME/bin`
/// (default `~/.cargo/bin`), which is where `cargo` itself also looks for
/// `cargo-*` subcommands. `None` when neither is known.
fn search_path() -> Option<OsString> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .filter(|d| d.is_absolute())
                .collect()
        })
        .unwrap_or_default();
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")));
    dirs.extend(cargo_home.map(|h| h.join("bin")));
    std::env::join_paths(dirs).ok()
}

/// Whether executable `tool` exists in `search` (a PATH-style list). `None` or
/// an empty list never matches.
fn tool_available(tool: &str, search: Option<&OsStr>) -> bool {
    search.is_some_and(|dirs| which::which_in(tool, Some(dirs), ".").is_ok())
}

/// Pre-flight check for an external tool. `Some(message)` (with a `[skip]`
/// line and an install hint) when `tool` is missing and the inspection must be
/// skipped; `None` when it is available and the command may run.
fn skip_notice(inspection: &str, tool: &str, hint: &str, search: Option<&OsStr>) -> Option<String> {
    (!tool_available(tool, search))
        .then(|| format!("[skip] {inspection}: {tool} not found\nhint: {hint}"))
}

/// Parse the `cargo audit --json` document into [`AuditVuln`]s. Tolerant of
/// missing per-entry fields. Unparseable JSON or a missing
/// `vulnerabilities.list` is an `Err` holding a `warn: ...` message, so the
/// caller can tell it apart from a genuinely clean audit (`Ok(vec![])`).
fn parse_audit_json(text: &str) -> Result<Vec<AuditVuln>, String> {
    let doc = serde_json::from_str::<serde_json::Value>(text).map_err(|e| {
        format!("warn: `cargo audit` output is not valid JSON ({e}); skipping audit-bridge")
    })?;
    let list = doc
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            "warn: `cargo audit` output lacks vulnerabilities.list; skipping audit-bridge"
                .to_string()
        })?;

    Ok(list
        .iter()
        .map(|v| {
            let s = |ptr: &[&str]| -> String {
                let mut cur = v;
                for k in ptr {
                    match cur.get(k) {
                        Some(next) => cur = next,
                        None => return String::new(),
                    }
                }
                cur.as_str().unwrap_or("").to_string()
            };
            AuditVuln {
                id: s(&["advisory", "id"]),
                package: s(&["package", "name"]),
                version: s(&["package", "version"]),
                title: s(&["advisory", "title"]),
            }
        })
        .collect())
}

/// Load `rpi.toml` from the workspace root, falling back to defaults when the
/// file is absent or unreadable. A malformed file warns and uses defaults
/// rather than aborting the run. Unknown keys (typos) warn on stderr but the
/// known keys are still applied (#35).
fn load_config(root: &Path) -> Config {
    let path = root.join("rpi.toml");
    let Ok(text) = fs::read_to_string(&path) else {
        return Config::default();
    };
    match parse_config(&text) {
        Ok((cfg, unknown)) => {
            for key in unknown {
                // `{:?}`: the target repo is untrusted; escape control chars.
                safe_eprintln!("{}", unknown_key_warning(&key, &path));
            }
            cfg
        }
        Err(e) => {
            safe_eprintln!("warn: ignoring {} (parse error: {e})", path.display());
            Config::default()
        }
    }
}

/// Warning text for an unknown `rpi.toml` key.
fn unknown_key_warning(key: &str, path: &Path) -> String {
    format!(
        "warn: unknown key {key:?} in {} (ignored; check for typos)",
        path.display()
    )
}

/// Parse `rpi.toml` text into a [`Config`] plus the top-level keys that are
/// not recognised config fields.
fn parse_config(text: &str) -> Result<(Config, Vec<String>), toml::de::Error> {
    let table: toml::Table = text.parse()?;
    let unknown = table
        .keys()
        .filter(|k| !Config::KNOWN_KEYS.contains(&k.as_str()))
        .cloned()
        .collect();
    let cfg = toml::from_str(text)?;
    Ok((cfg, unknown))
}

/// Recursively gather `.rs` files under `dir`, skipping the crate root's own
/// `target/` output (a deeper `src/target/` module is real source; #97)
/// and any subdirectory that holds its own `Cargo.toml` (another crate or a
/// nested workspace, which is collected separately or not at all; #75).
/// `dir` itself is the crate root and is always walked.
fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, true, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, is_root: bool, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        //  does not follow symlinks; skip them to avoid cycles.
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if is_root && path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            if path.join("Cargo.toml").is_file() {
                continue;
            }
            walk(&path, false, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Read and parse a single `.rs` file, best-effort.
///
/// Returns `None` after printing a warning to stderr when the file cannot be
/// read or does not parse (syntax error, or syntax `syn` does not support yet),
/// so one bad file — e.g. a trybuild compile-fail fixture under `tests/ui` —
/// never aborts the whole run.
fn parse_file(path: &Path) -> Option<SourceFile> {
    match try_parse_file(path) {
        Ok(f) => Some(f),
        Err(msg) => {
            safe_eprintln!("{msg}");
            None
        }
    }
}

/// Stack size of the large-stack thread that runs collection (see [`run_on_big_stack`]). The stack is reserved lazily
/// (virtual memory only), so this is not resident memory. 5000-level inputs of
/// every shape tried (worst: debug-build generics, ~60 KiB/level) fit; 1 GiB covers ~15k levels. Group depth beyond MAX_GROUP_DEPTH is stopped by
/// the lexical backstop below before it gets here.
const PARSER_STACK_BYTES: usize = 1024 * 1024 * 1024;

/// Sizes tried in order when the thread cannot be created (e.g. `ulimit -v`
/// makes the 1 GiB reservation fail with EAGAIN). Smaller stacks leave less
/// headroom for bracket-free deep shapes (the known residual class, which can
/// abort `syn` before any limit applies and is only fully safe at 1 GiB; see
/// #119). The group limit (512 levels, ~2 KiB/level) fits even in 16 MiB; the
/// AST limit (144) is not guaranteed there.
const PARSER_STACK_FALLBACKS: [usize; 4] = [
    PARSER_STACK_BYTES,
    256 * 1024 * 1024,
    64 * 1024 * 1024,
    16 * 1024 * 1024,
];

/// Run `spawn(size)` for each size until one succeeds; the last error if none.
fn spawn_with_fallback<T>(
    sizes: &[usize],
    mut spawn: impl FnMut(usize) -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mut last = None;
    for &size in sizes {
        match spawn(size) {
            Ok(v) => return Ok(v),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no stack sizes to try")))
}

/// Run `f` on one thread with a large stack (falling back to smaller stacks,
/// and finally to the calling thread with a warning if no thread can be
/// created). Parsing happens on the thread that calls [`collect`], so the CLI
/// runs collection through output inside this; the parse result is reused
/// as-is, with no second parse. A panic in `f` is propagated.
pub fn run_on_big_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    let slot = std::sync::Mutex::new(Some(f));
    let take = || slot.lock().ok().and_then(|mut g| g.take());
    let spawned = thread::scope(|scope| {
        let handle = spawn_with_fallback(&PARSER_STACK_FALLBACKS, |size| {
            thread::Builder::new()
                .name("rpi-main".into())
                .stack_size(size)
                .spawn_scoped(scope, || take().map(|f| f()))
        });
        match handle {
            Ok(h) => Some(h.join()),
            Err(e) => {
                safe_eprintln!(
                    "warn: could not start a large-stack thread ({e}); running on the current stack"
                );
                None
            }
        }
    });
    match spawned {
        Some(Ok(Some(v))) => v,
        Some(Ok(None)) => unreachable!("closure is taken exactly once"),
        Some(Err(payload)) => std::panic::resume_unwind(payload),
        None => take().expect("closure not consumed when no thread started")(),
    }
}

/// Backstop for bracket nesting (macro token groups are not bounded by
/// `syn`). Measured with a lexer-aware scan, so brackets inside strings,
/// comments, chars and raw strings are ignored.
const MAX_GROUP_DEPTH: usize = 512;

/// The AST we hand to the inspections is walked recursively on ordinary
/// stacks, so reject trees deeper than this. `syn`'s own parse limit is 128
/// nested expressions; the margin covers the wrapping item/type/pattern nodes so
/// a file `syn` accepts at its limit is not skipped. `Block` is not counted:
/// every nested block already goes through an `Expr` (or an `Item`).
const MAX_AST_DEPTH: usize = 144;

/// Greatest `(`/`[`/`{` depth, skipping comments, string/char/raw-string
/// literals and lifetimes.
fn max_group_depth(src: &str) -> usize {
    let b = src.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let (mut i, mut depth, mut max) = (0usize, 0usize, 0usize);
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut nest = 1;
                i += 2;
                while i < b.len() && nest > 0 {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        nest += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        nest -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'r' if i == 0
                || !is_ident(b[i - 1])
                || (i >= 1
                    && matches!(b[i - 1], b'b' | b'c')
                    && (i == 1 || !is_ident(b[i - 2]))) =>
            {
                let mut j = i + 1;
                while b.get(j) == Some(&b'#') {
                    j += 1;
                }
                if b.get(j) == Some(&b'"') {
                    let hashes = j - i - 1;
                    i = j + 1;
                    while i < b.len() {
                        if b[i] == b'"' && (0..hashes).all(|k| b.get(i + 1 + k) == Some(&b'#')) {
                            i += 1 + hashes;
                            break;
                        }
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            b'\'' => {
                // Char literal (`'x'`, `'\n'`) vs lifetime (`'a`).
                if b.get(i + 1) == Some(&b'\\') {
                    i += 2;
                    while i < b.len() && b[i] != b'\'' {
                        i += 1;
                    }
                    i += 1;
                } else if let Some(c) = src.get(i + 1..).and_then(|r| r.chars().next()) {
                    if b.get(i + 1 + c.len_utf8()) == Some(&b'\'') {
                        i += 2 + c.len_utf8();
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => i += 1,
        }
    }
    max
}

/// Tracks the deepest expression/type/pattern/item nesting of an AST.
#[derive(Default)]
struct AstDepth {
    cur: usize,
    max: usize,
}

macro_rules! counted {
    ($($method:ident => $func:ident: $ty:ty),* $(,)?) => {$(
        fn $method(&mut self, n: &'ast $ty) {
            self.cur += 1;
            self.max = self.max.max(self.cur);
            syn::visit::$func(self, n);
            self.cur -= 1;
        }
    )*};
}

impl<'ast> syn::visit::Visit<'ast> for AstDepth {
    counted! {
        visit_expr => visit_expr: syn::Expr,
        visit_type => visit_type: syn::Type,
        visit_pat => visit_pat: syn::Pat,
        visit_item => visit_item: syn::Item,
    }
}

/// Like [`parse_file`] but returns the warning text instead of printing it.
///
/// The message always carries the file path; for syntax errors it also carries
/// the `line:column` of the error (requires `proc-macro2`'s `span-locations`).
fn try_parse_file(path: &Path) -> Result<SourceFile, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("warn: skipping {} (read error: {e})", path.display()))?;
    let too_deep = || format!("warn: skipping {} (nesting too deep)", path.display());
    if max_group_depth(&content) > MAX_GROUP_DEPTH {
        return Err(too_deep());
    }
    let loc = content.lines().count();
    let ast = syn::parse_file(&content).map_err(|e| {
        let start = e.span().start();
        format!(
            "warn: skipping {}:{}:{} (parse error: {e})",
            path.display(),
            start.line,
            start.column + 1
        )
    })?;
    let mut depth = AstDepth::default();
    syn::visit::Visit::visit_file(&mut depth, &ast);
    if depth.max > MAX_AST_DEPTH {
        return Err(too_deep());
    }
    Ok(SourceFile {
        path: path.to_path_buf(),
        loc,
        ast,
    })
}

/// Parse verdict for one file, sharing [`try_parse_file`] (syntax, `MAX_GROUP_DEPTH`, `MAX_AST_DEPTH`)
/// so the hidden parse worker never re-implements the decision. `Err` carries the
/// unsanitized warning text; callers must sanitize before printing.
pub fn parse_verdict(path: &Path) -> Result<(), String> {
    try_parse_file(path).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/sample")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn collects_fixture_crate_and_parses_sources() {
        let ctx = collect(&fixture(), CollectOptions::default()).unwrap();
        assert_eq!(ctx.workspace.crates, vec!["sample".to_string()]);

        let krate = &ctx.crates[0];
        assert_eq!(krate.name, "sample");
        assert!(!krate.files.is_empty(), "expected parsed .rs files");
        assert!(
            krate.files.iter().all(|f| f.loc > 0),
            "every file should have a line count"
        );
        // The fixture is a leaf crate: no intra-workspace deps.
        assert!(krate.workspace_deps.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn walk_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("rpi_issue64_symlink_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("a.rs"),
            "fn a() {}
",
        )
        .unwrap();
        // Cycle: src/loop -> root, and a symlink to a .rs file.
        symlink(&root, src.join("loop")).unwrap();
        symlink(src.join("a.rs"), src.join("link.rs")).unwrap();

        let files = collect_rs_files(&root);
        let _ = fs::remove_dir_all(&root);
        assert_eq!(files, vec![src.join("a.rs")]);
    }

    fn root_and_member() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/root-and-member")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn root_package_does_not_absorb_member_or_nested_crates() {
        let ctx = collect(&root_and_member(), CollectOptions::default()).unwrap();
        let mut seen: Vec<(String, PathBuf)> = Vec::new();
        for c in &ctx.crates {
            for f in &c.files {
                seen.push((c.name.clone(), f.path.clone()));
            }
        }
        let mut paths: Vec<_> = seen.iter().map(|(_, p)| p.clone()).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(
            paths.len(),
            seen.len(),
            "a file belongs to two crates: {seen:?}"
        );

        let owner = |suffix: &str| -> Vec<&str> {
            seen.iter()
                .filter(|(_, p)| p.ends_with(suffix))
                .map(|(n, _)| n.as_str())
                .collect()
        };
        assert_eq!(owner("member/src/lib.rs"), vec!["member"]);
        assert_eq!(owner("root-and-member/src/lib.rs"), vec!["root_pkg"]);
        assert!(
            seen.iter()
                .all(|(_, p)| !p.ends_with("tests/fixtures/nested/src/lib.rs")),
            "nested workspace under tests/fixtures must not be collected: {seen:?}"
        );
    }

    #[test]
    fn walk_skips_target_and_nested_crates_but_not_git_or_node_modules() {
        let root = std::env::temp_dir().join(format!("rpi_issue75_walk_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in [
            "src",
            "target/debug",
            "node_modules/x",
            ".git/hooks",
            "sub/src",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        for f in [
            "src/a.rs",
            "target/debug/gen.rs",
            "node_modules/x/n.rs",
            ".git/hooks/h.rs",
            "sub/src/b.rs",
        ] {
            fs::write(root.join(f), "fn f() {}\n").unwrap();
        }
        fs::write(root.join("Cargo.toml"), "").unwrap();
        fs::write(root.join("sub/Cargo.toml"), "").unwrap();

        let files = collect_rs_files(&root);
        let _ = fs::remove_dir_all(&root);
        // Documented policy: only `target/` and directories holding their own
        // Cargo.toml are pruned; .git / node_modules are walked like any dir.
        assert_eq!(
            files,
            vec![
                root.join(".git/hooks/h.rs"),
                root.join("node_modules/x/n.rs"),
                root.join("src/a.rs"),
            ]
        );
    }

    #[test]
    fn walk_keeps_nested_target_module_but_skips_root_target() {
        let root = std::env::temp_dir().join(format!("rpi_issue97_walk_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["src/target", "target/debug"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        for f in ["src/target/mod.rs", "target/debug/gen.rs"] {
            fs::write(root.join(f), "pub fn f() {}\n").unwrap();
        }
        let files = collect_rs_files(&root);
        let _ = fs::remove_dir_all(&root);
        assert_eq!(files, vec![root.join("src/target/mod.rs")]);
    }

    #[test]
    fn skips_target_directory() {
        let files = collect_rs_files(&fixture());
        assert!(
            files
                .iter()
                .all(|p| !p.components().any(|c| c.as_os_str() == "target")),
            "target/ must be excluded"
        );
    }

    #[test]
    fn parses_cargo_audit_json() {
        let json = r#"{
            "vulnerabilities": { "count": 1, "list": [
                { "advisory": { "id": "RUSTSEC-2021-0001", "title": "boom" },
                  "package": { "name": "badcrate", "version": "1.2.3" } }
            ]}
        }"#;
        let vulns = parse_audit_json(json).unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].id, "RUSTSEC-2021-0001");
        assert_eq!(vulns[0].package, "badcrate");
        assert_eq!(vulns[0].version, "1.2.3");
        assert_eq!(vulns[0].title, "boom");
    }

    #[test]
    fn audit_json_garbage_and_missing_list_are_reported() {
        let e = parse_audit_json("not json").unwrap_err();
        assert!(e.starts_with("warn: "), "{e}");
        let e = parse_audit_json("{}").unwrap_err();
        assert!(
            e.starts_with("warn: ") && e.contains("vulnerabilities.list"),
            "{e}"
        );
    }

    #[test]
    fn audit_json_empty_list_is_clean_not_warned() {
        let json = r#"{ "vulnerabilities": { "count": 0, "list": [] } }"#;
        assert_eq!(parse_audit_json(json).unwrap().len(), 0);
    }

    /// Fresh scratch dir under the system temp dir (removed by the caller).
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rpi_test_{name}_{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn syntax_error_is_skipped_with_path_and_line() {
        let dir = scratch("syntax_error");
        let path = dir.join("bad.rs");
        // The error is on line 3.
        std::fs::write(&path, "fn ok() {}\n\nfn f() { let = ; }\n").unwrap();
        let result = try_parse_file(&path);
        std::fs::remove_dir_all(&dir).ok();
        let msg = result
            .err()
            .expect("syntax error must not yield a SourceFile");
        assert!(
            msg.contains("bad.rs"),
            "warning must mention the path: {msg}"
        );
        assert!(
            msg.contains("bad.rs:3:"),
            "warning must mention the line: {msg}"
        );
        assert!(parse_file(&path).is_none());
    }

    fn nested_parens_source(depth: usize) -> String {
        format!(
            "fn f() {{ let _ = {}1{}; }}\n",
            "(".repeat(depth),
            ")".repeat(depth)
        )
    }

    #[test]
    fn deeply_nested_file_is_skipped_not_crashed() {
        let dir = scratch("deep_nesting");
        let path = dir.join("deep.rs");
        std::fs::write(&path, nested_parens_source(5000)).unwrap();
        let result = run_on_big_stack(|| try_parse_file(&path).map(|_| ()));
        std::fs::remove_dir_all(&dir).ok();
        let msg = result.expect_err("deeply nested file must be skipped");
        assert!(msg.contains("deep.rs"), "{msg}");
        assert!(msg.contains("nesting too deep"), "{msg}");
    }

    #[test]
    fn realistic_deep_shapes_are_not_skipped() {
        let dir = scratch("effective_depth");
        let cases = [
            (
                "blocks_120",
                format!("fn f() {}1{}\n", "{".repeat(120), "}".repeat(120)),
            ),
            (
                "unary_127",
                format!("fn f() {{ let _ = {}1; }}\n", "-".repeat(127)),
            ),
        ];
        for (name, src) in cases {
            let path = dir.join(format!("{name}.rs"));
            std::fs::write(&path, src).unwrap();
            let r = run_on_big_stack(|| try_parse_file(&path).map(|_| ()));
            assert!(r.is_ok(), "{name}: {:?}", r.err());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn moderately_nested_and_normal_files_still_parse() {
        let dir = scratch("ok_nesting");
        let ok = dir.join("ok.rs");
        std::fs::write(&ok, "fn main() { let _ = vec![(1, [2])]; }\n").unwrap();
        let nested = dir.join("nested.rs");
        std::fs::write(&nested, nested_parens_source(50)).unwrap();
        let r1 = try_parse_file(&ok);
        let r2 = try_parse_file(&nested);
        std::fs::remove_dir_all(&dir).ok();
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }

    /// `fn f() { let _ = <expr>; }` bodies that are 5000 levels deep in
    /// different shapes, including ones that fool a naive bracket counter.
    fn evasion_sources(n: usize) -> Vec<(&'static str, String)> {
        let wrap = |e: String| format!("fn f() {{ let _ = {e}; }}\n");
        let mut v = Vec::new();
        for (name, open) in [
            ("paren_str", "(\")\","),
            ("paren_char", "(')',"),
            ("paren_block_comment", "(/*)*/"),
            ("paren_line_comment", "(// )\n"),
            ("paren_closure_unary_ref", "(|| -!&"),
        ] {
            v.push((name, wrap(format!("{}1{}", open.repeat(n), ")".repeat(n)))));
        }
        v.push(("binop", wrap(format!("{}1", "1+".repeat(n)))));
        v.push(("unary", wrap(format!("{}1", "-".repeat(n)))));
        v.push(("ref", wrap(format!("{}1", "&".repeat(n)))));
        v.push(("closure", wrap(format!("{}1", "||".repeat(n)))));
        v.push(("elseif", wrap(format!("{}{{}}", "if a {} else ".repeat(n)))));
        v.push(("field", wrap(format!("x{}", ".a".repeat(n)))));
        v.push((
            "generic",
            format!("fn f(_: {}u8{}) {{}}\n", "Vec<".repeat(n), ">".repeat(n)),
        ));
        v.push(("reftype", format!("fn f(_: {}u8) {{}}\n", "&".repeat(n))));
        v
    }

    #[test]
    fn deep_evasion_shapes_never_crash() {
        let dir = scratch("evasion");
        for n in [250, 5000] {
            for (name, src) in evasion_sources(n) {
                let path = dir.join(format!("{name}_{n}.rs"));
                std::fs::write(&path, src).unwrap();
                // Ok or Err are both fine; the process must simply survive.
                run_on_big_stack(|| {
                    let _ = try_parse_file(&path);
                });
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn brackets_in_literals_and_comments_do_not_cause_skips() {
        let dir = scratch("literal_brackets");
        let path = dir.join("lit.rs");
        let src = format!(
            "// {}\n/* {} */\nfn f() {{ let _ = \"{}\"; let _ = r#\"{}\"#; let _ = '('; let _: &'static str = \"\"; }}\n",
            "(".repeat(600),
            "[".repeat(600),
            "{".repeat(600),
            "(".repeat(600),
        );
        std::fs::write(&path, src).unwrap();
        let r = try_parse_file(&path);
        std::fs::remove_dir_all(&dir).ok();
        assert!(r.is_ok(), "{:?}", r.err());
    }

    #[test]
    fn spawn_falls_back_to_smaller_stack() {
        let mut tried = Vec::new();
        let r = spawn_with_fallback(&[3, 2, 1], |size| {
            tried.push(size);
            if size > 2 {
                Err(std::io::Error::other("EAGAIN"))
            } else {
                Ok(size)
            }
        });
        assert_eq!(r.unwrap(), 2);
        assert_eq!(tried, vec![3, 2]);
        assert!(spawn_with_fallback(&[1], |_| -> std::io::Result<()> {
            Err(std::io::Error::other("x"))
        })
        .is_err());
    }

    #[test]
    fn unreadable_file_is_skipped_with_path() {
        let path = Path::new("/nonexistent/totally/fake.rs");
        let msg = try_parse_file(path)
            .err()
            .expect("unreadable file must not yield a SourceFile");
        assert!(
            msg.contains("fake.rs"),
            "warning must mention the path: {msg}"
        );
        assert!(parse_file(path).is_none());
    }

    #[test]
    fn bad_file_does_not_stop_collection_of_other_files() {
        let dir = scratch("bad_among_good");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"scratch_ws\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("tests/ui")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
        std::fs::write(dir.join("src/other.rs"), "pub fn b() {}\n").unwrap();
        std::fs::write(dir.join("tests/ui/bad.rs"), "fn f() { let = ; }\n").unwrap();

        let ctx = collect(&dir, CollectOptions::default());
        std::fs::remove_dir_all(&dir).ok();
        let ctx = ctx.expect("a syntax-error file must not abort collection");

        let names: Vec<String> = ctx.crates[0]
            .files
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["lib.rs", "other.rs"],
            "good files must all be collected"
        );
    }

    #[test]
    fn renamed_dependency_is_keyed_by_reference_name() {
        // `foo = { package = "bar" }` is referenced as `foo` in code (#66).
        let dir = scratch("renamed_dep");
        std::fs::create_dir_all(dir.join("bar/src")).unwrap();
        std::fs::create_dir_all(dir.join("app/src")).unwrap();
        std::fs::write(
            dir.join("bar/Cargo.toml"),
            "[package]\nname = \"bar\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(dir.join("bar/src/lib.rs"), "pub fn b() {}\n").unwrap();
        std::fs::write(
            dir.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
             [dependencies]\nfoo = { package = \"bar\", path = \"../bar\" }\n",
        )
        .unwrap();
        std::fs::write(dir.join("app/src/lib.rs"), "pub use foo::b;\n").unwrap();

        let ctx = collect(&dir.join("app"), CollectOptions::default());
        std::fs::remove_dir_all(&dir).ok();
        let ctx = ctx.expect("collection must succeed");

        let krate = &ctx.crates[0];
        assert_eq!(krate.external_deps, vec!["foo".to_string()]);
        assert_eq!(
            krate.external_dep_packages.get("foo").map(String::as_str),
            Some("bar")
        );
    }

    /// #133: the same dependency under several `[target.*.dependencies]`
    /// tables must be listed once.
    #[test]
    fn target_specific_duplicate_dependency_is_listed_once() {
        let dir = scratch("target_dup_dep");
        std::fs::create_dir_all(dir.join("bar/src")).unwrap();
        std::fs::create_dir_all(dir.join("app/src")).unwrap();
        std::fs::write(
            dir.join("bar/Cargo.toml"),
            "[package]\nname = \"bar\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(dir.join("bar/src/lib.rs"), "pub fn b() {}\n").unwrap();
        std::fs::write(
            dir.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
             [target.'cfg(unix)'.dependencies]\nbar = { path = \"../bar\" }\n\
             [target.'cfg(windows)'.dependencies]\nbar = { path = \"../bar\" }\n",
        )
        .unwrap();
        std::fs::write(dir.join("app/src/lib.rs"), "").unwrap();

        let ctx = collect(&dir.join("app"), CollectOptions::default());
        std::fs::remove_dir_all(&dir).ok();
        let ctx = ctx.expect("collection must succeed");
        assert_eq!(ctx.crates[0].external_deps, vec!["bar".to_string()]);
    }

    #[test]
    fn hyphenated_rename_keeps_toml_key_as_reference_name() {
        let dir = scratch("renamed_dep_hyphen");
        std::fs::create_dir_all(dir.join("bar/src")).unwrap();
        std::fs::create_dir_all(dir.join("app/src")).unwrap();
        std::fs::write(
            dir.join("bar/Cargo.toml"),
            "[package]\nname = \"bar\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(dir.join("bar/src/lib.rs"), "pub fn b() {}\n").unwrap();
        std::fs::write(
            dir.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
             [dependencies]\nmy-foo = { package = \"bar\", path = \"../bar\" }\n",
        )
        .unwrap();
        std::fs::write(dir.join("app/src/lib.rs"), "pub use my_foo::b;\n").unwrap();

        let ctx = collect(&dir.join("app"), CollectOptions::default());
        std::fs::remove_dir_all(&dir).ok();
        let ctx = ctx.expect("collection must succeed");

        // Stored as written in TOML; dep-hygiene normalizes `-` to `_` itself.
        let krate = &ctx.crates[0];
        assert_eq!(krate.external_deps, vec!["my-foo".to_string()]);
        assert_eq!(
            krate
                .external_dep_packages
                .get("my-foo")
                .map(String::as_str),
            Some("bar")
        );
    }

    #[test]
    fn collect_error_mentions_workspace_path() {
        match collect(
            std::path::Path::new("/no/such/workspace"),
            CollectOptions::default(),
        ) {
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(
                    msg.contains("/no/such/workspace"),
                    "error must mention workspace path: {msg}"
                );
            }
            Ok(_) => panic!("expected Err for non-existent workspace"),
        }
    }

    #[test]
    fn collect_churn_returns_empty_outside_a_git_repo() {
        // A directory with no .git yields no churn: either git exits non-zero
        // (not a repo) or git is absent and the pre-flight check skips it.
        let tmp = std::env::temp_dir().join(format!("rpi_issue21_no_git_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let churn = collect_churn(&tmp, Duration::from_secs(10));
        std::fs::remove_dir_all(&tmp).ok();
        assert!(churn.is_empty());
    }

    #[test]
    fn missing_tool_is_reported_with_skip_and_hint() {
        // No search path at all, and an empty one: nothing can be found.
        for search in [None, Some(OsStr::new(""))] {
            let notice = skip_notice(
                "audit-bridge",
                "cargo-audit",
                "install with `cargo install cargo-audit`",
                search,
            )
            .expect("tool must be reported missing");
            assert_eq!(
                notice,
                "[skip] audit-bridge: cargo-audit not found\n\
                 hint: install with `cargo install cargo-audit`"
            );
        }
    }

    #[test]
    fn missing_tool_in_nonexistent_dir_is_reported() {
        let dir = std::env::temp_dir().join("rpi_issue21_definitely_absent_dir");
        let notice = skip_notice("churn-hotspot", "git", "install git", Some(dir.as_os_str()));
        assert!(notice.is_some_and(|n| n.starts_with("[skip] churn-hotspot: git not found")));
    }

    #[test]
    fn collect_churn_returns_empty_outside_git() {
        // A directory with no .git returns an empty churn map without panicking.
        let tmp = std::env::temp_dir().join("rpi_churn_no_git_29");
        std::fs::create_dir_all(&tmp).ok();
        let churn = collect_churn(&tmp, Duration::from_secs(10));
        std::fs::remove_dir_all(&tmp).ok();
        assert!(churn.is_empty(), "non-git root must yield empty churn");
    }

    /// Write an executable-free shell stub (run as `sh <script>`) into a fresh
    /// temp dir and return `(dir, command)`. Avoids ETXTBSY and PATH games.
    #[cfg(unix)]
    fn stub_git(name: &str, body: &str) -> (PathBuf, Command) {
        let dir =
            std::env::temp_dir().join(format!("rpi_churn_stub_{name}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("git-stub.sh");
        std::fs::write(&script, body).unwrap();
        let mut cmd = Command::new("sh");
        cmd.arg(script);
        (dir, cmd)
    }

    #[cfg(unix)]
    #[test]
    fn present_tool_proceeds_without_notice() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rpi_issue21_fake_bin_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("cargo-audit");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let found = skip_notice("audit-bridge", "cargo-audit", "hint", Some(dir.as_os_str()));
        // A non-executable file of the same name must not count as available.
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o644)).unwrap();
        let not_exec = skip_notice("audit-bridge", "cargo-audit", "hint", Some(dir.as_os_str()));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(found, None);
        assert!(not_exec.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn collect_churn_rejects_partial_output_from_failed_git() {
        // Emits a commit's paths, then fails (e.g. corrupt older object).
        let (dir, cmd) = stub_git("fail", "printf 'src/a.rs\nsrc/b.rs\n'\nexit 128\n");
        let churn = collect_churn_with(cmd, &dir, Duration::from_secs(10), CHURN_MAX_OUTPUT);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            churn.is_empty(),
            "failed git must not yield partial churn: {churn:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_churn_accepts_successful_git_output() {
        let (dir, cmd) = stub_git("ok", "printf 'src/a.rs\n\nsrc/a.rs\nREADME.md\n'\n");
        let churn = collect_churn_with(cmd, &dir, Duration::from_secs(10), CHURN_MAX_OUTPUT);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(churn.len(), 1);
        assert_eq!(churn.values().copied().next(), Some(2));
    }

    #[cfg(unix)]
    #[test]
    fn collect_churn_survives_non_utf8_paths() {
        // 0xFF is never valid UTF-8; ordinary paths must still be counted.
        let (dir, cmd) = stub_git(
            "nonutf8",
            "printf 'src/ok.rs\nsrc/bad\\377.rs\nsrc/ok.rs\n'\n",
        );
        let churn = collect_churn_with(cmd, &dir, Duration::from_secs(10), CHURN_MAX_OUTPUT);
        std::fs::remove_dir_all(&dir).ok();
        let ok = churn.iter().find(|(p, _)| p.ends_with("src/ok.rs"));
        assert_eq!(ok.map(|(_, n)| *n), Some(2), "UTF-8 paths lost: {churn:?}");
    }

    #[test]
    fn collect_churn_counts_non_ascii_paths() {
        // git quotes non-ASCII paths ("\346...") unless core.quotepath=false.
        if Command::new("git").arg("--version").output().is_err() {
            return; // git unavailable: nothing to exercise
        }
        let dir = std::env::temp_dir().join(format!("rpi_churn_quotepath_{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("日本語")).unwrap();
        std::fs::write(dir.join("日本語/モジュール.rs"), "fn a() {}\n").unwrap();
        let git = |args: &[&str]| {
            let ok = Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
                .args(["-c", "commit.gpgsign=false", "-C"])
                .arg(&dir)
                .args(args)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["add", "日本語/モジュール.rs"]);
        git(&["commit", "-q", "-m", "init"]);

        let churn = collect_churn(&dir, Duration::from_secs(10));
        std::fs::remove_dir_all(&dir).ok();
        let hit = churn
            .iter()
            .find(|(p, _)| p.ends_with("日本語/モジュール.rs"));
        assert_eq!(
            hit.map(|(_, n)| *n),
            Some(1),
            "non-ASCII path lost: {churn:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_churn_oversized_output_returns_empty_quickly() {
        // Endless stdout: must be killed at the cap and yield no churn.
        let (dir, cmd) = stub_git("big", "while :; do echo src/a.rs; done\n");
        let start = std::time::Instant::now();
        let churn = collect_churn_with(cmd, &dir, Duration::from_secs(10), 4096);
        let elapsed = start.elapsed();
        std::fs::remove_dir_all(&dir).ok();
        assert!(churn.is_empty(), "oversized git output must yield no churn");
        assert!(
            elapsed < Duration::from_secs(5),
            "cap not enforced: {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_churn_times_out_and_returns_empty_quickly() {
        // The stub sleeps far longer than the 200ms limit: the timeout branch
        // must kill it and return an empty map well before the sleep ends.
        let (dir, cmd) = stub_git("timeout", "sleep 5\nprintf 'src/a.rs\n'\n");
        let start = std::time::Instant::now();
        let churn = collect_churn_with(cmd, &dir, Duration::from_millis(200), CHURN_MAX_OUTPUT);
        let elapsed = start.elapsed();
        std::fs::remove_dir_all(&dir).ok();
        assert!(churn.is_empty(), "timed-out git must yield empty churn");
        assert!(
            elapsed < Duration::from_secs(1),
            "timeout not enforced promptly: {elapsed:?}"
        );
    }

    #[test]
    fn collect_churn_anchors_keys_at_git_toplevel_for_subdir_workspace() {
        if Command::new("git").arg("--version").output().is_err() {
            return; // git unavailable: nothing to exercise
        }
        let repo = scratch("churn_anchor");
        let ws = repo.join("crates/x");
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(ws.join("src/lib.rs"), "fn a() {}\n").unwrap();
        // Isolate from the host's git configuration.
        let isolated = |cmd: &mut Command| {
            cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1");
        };
        let git = |args: &[&str]| {
            let mut cmd = Command::new("git");
            isolated(&mut cmd);
            let ok = cmd
                .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
                .args(["-c", "commit.gpgsign=false", "-C"])
                .arg(&repo)
                .args(args)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["add", "crates/x/src/lib.rs"]);
        git(&["commit", "-q", "-m", "init"]);

        // The workspace root is the subdirectory, not the repo toplevel.
        let mut cmd = Command::new("git");
        isolated(&mut cmd);
        let churn = collect_churn_with(cmd, &ws, Duration::from_secs(10), CHURN_MAX_OUTPUT);
        // Canonicalize: TMPDIR may be a symlink.
        let expected = ws.join("src/lib.rs").canonicalize().unwrap();
        std::fs::remove_dir_all(&repo).ok();
        assert_eq!(
            churn.get(&expected).copied(),
            Some(1),
            "churn keys must match canonical file paths: {churn:?}"
        );
    }

    #[test]
    fn config_default_timeout_is_thirty_seconds() {
        assert_eq!(rpi_core::Config::default().churn_git_timeout_secs, 30);
    }

    #[cfg(unix)]
    fn write_exec(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// #100: a target's `.cargo/config.toml` `build.rustc` must not run.
    #[cfg(unix)]
    #[test]
    fn untrusted_build_rustc_is_not_executed_by_collect() {
        let root = std::env::temp_dir().join(format!("rpi_issue100_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join(".cargo")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"victim\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        let marker = root.join("PWNED");
        let evil = root.join("evil-rustc.sh");
        write_exec(
            &evil,
            &format!(
                "#!/bin/sh\ntouch '{}'\nexec rustc \"$@\"\n",
                marker.display()
            ),
        );
        fs::write(
            root.join(".cargo/config.toml"),
            format!("[build]\nrustc = \"{}\"\n", evil.display()),
        )
        .unwrap();

        let result = collect(&root, CollectOptions::default());
        let ran = marker.exists();
        let _ = fs::remove_dir_all(&root);
        assert!(result.is_ok(), "collect failed: {:?}", result.err());
        assert!(!ran, "target's build.rustc was executed");
    }

    /// #101: audit must call `cargo-audit` directly (not via `cargo`, whose
    /// alias the target controls), from a neutral cwd, passing the lockfile.
    #[cfg(unix)]
    #[test]
    fn audit_calls_cargo_audit_directly_from_neutral_cwd() {
        let base = std::env::temp_dir().join(format!("rpi_issue101_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("target_repo");
        let bin = base.join("bin");
        fs::create_dir_all(root.join(".cargo")).unwrap();
        fs::create_dir_all(&bin).unwrap();
        fs::write(root.join("Cargo.lock"), "").unwrap();
        fs::write(
            root.join(".cargo/config.toml"),
            "[alias]\naudit = \"run --bin evil --\"\n",
        )
        .unwrap();
        let log = base.join("log");
        write_exec(
            &bin.join("cargo-audit"),
            &format!(
                "#!/bin/sh\necho \"cwd=$(pwd)\" > '{0}'\necho \"args=$*\" >> '{0}'\necho '{{\"vulnerabilities\":{{\"list\":[]}}}}'\n",
                log.display()
            ),
        );

        let vulns = run_cargo_audit_with(&root, Some(bin.as_os_str()));
        let logged = fs::read_to_string(&log).unwrap_or_default();
        let root_str = root.canonicalize().unwrap().display().to_string();
        let _ = fs::remove_dir_all(&base);
        assert!(vulns.is_empty());
        assert!(
            !logged.contains(&format!("cwd={root_str}")),
            "ran inside target: {logged}"
        );
        assert!(
            logged.contains(&format!("args=audit --json --file {root_str}/Cargo.lock")),
            "unexpected invocation: {logged}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn neutral_dir_is_not_under_tmp() {
        assert_eq!(neutral_dir(), PathBuf::from("/"));
    }

    #[test]
    fn audit_without_lockfile_is_skipped() {
        let root = std::env::temp_dir().join(format!("rpi_issue101_nolock_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        #[cfg(unix)]
        write_exec(&bin.join("cargo-audit"), "#!/bin/sh\nexit 1\n");
        let v = run_cargo_audit_with(&root, Some(bin.as_os_str()));
        let _ = fs::remove_dir_all(&root);
        assert!(v.is_empty());
    }

    /// #112: a root without its own Cargo.toml (e.g. `src/`) must resolve to
    /// the enclosing manifest, like cargo itself does.
    #[test]
    fn collect_accepts_subdirectory_of_a_package() {
        let root = std::env::temp_dir().join(format!("rpi_issue112_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"sub\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        let result = collect(&root.join("src"), CollectOptions::default());
        let _ = fs::remove_dir_all(&root);
        assert!(result.is_ok(), "collect failed: {:?}", result.err());
    }

    /// #68: `load_config` falls back to defaults on every bad-input shape and
    /// applies a partial file on top of the defaults.
    fn load_from(name: &str, toml: Option<&str>) -> Config {
        let dir = scratch(name);
        if let Some(t) = toml {
            std::fs::write(dir.join("rpi.toml"), t).unwrap();
        }
        let cfg = load_config(&dir);
        std::fs::remove_dir_all(&dir).ok();
        cfg
    }

    #[test]
    fn load_config_missing_file_is_default() {
        let cfg = load_from("cfg_missing", None);
        assert_eq!(cfg.module_size_loc, Config::default().module_size_loc);
    }

    #[test]
    fn load_config_reads_isolation_keys() {
        let d = Config::default();
        assert!(d.parse_isolation);
        assert_eq!(d.parse_memory_limit_mb, 4096);
        let cfg = load_from(
            "cfg_iso",
            Some("parse_isolation = false\nparse_memory_limit_mb = 0\n"),
        );
        assert!(!cfg.parse_isolation);
        assert_eq!(cfg.parse_memory_limit_mb, 0);
    }

    #[test]
    fn load_config_partial_keeps_other_keys_default() {
        let d = Config::default();
        let cfg = load_from("cfg_partial", Some("module_size_loc = 10\n"));
        assert_eq!(cfg.module_size_loc, 10);
        assert_eq!(cfg.pub_surface_warn, d.pub_surface_warn);
        assert_eq!(cfg.coupling_warn, d.coupling_warn);
        assert_eq!(cfg.churn_git_timeout_secs, d.churn_git_timeout_secs);
    }

    #[test]
    fn load_config_syntax_error_falls_back_to_default() {
        let cfg = load_from("cfg_syntax", Some("module_size_loc = = 10\n[[\n"));
        assert_eq!(cfg.module_size_loc, Config::default().module_size_loc);
    }

    #[test]
    fn load_config_wrong_type_falls_back_to_default() {
        let cfg = load_from(
            "cfg_type",
            Some("module_size_loc = \"x\"\ncoupling_warn = 7\n"),
        );
        // The whole file is rejected, so even the valid key is not applied.
        assert_eq!(cfg.module_size_loc, Config::default().module_size_loc);
        assert_eq!(cfg.coupling_warn, Config::default().coupling_warn);
    }

    /// #35: a typo'd key is reported, valid keys are not, and known values
    /// are still applied.
    #[test]
    fn parse_config_reports_unknown_keys_and_keeps_known_values() {
        let (cfg, unknown) = parse_config("modul_size_loc = 200\ncoupling_warn = 7\n").unwrap();
        assert_eq!(unknown, vec!["modul_size_loc".to_string()]);
        assert_eq!(cfg.coupling_warn, 7);
        assert_eq!(cfg.module_size_loc, Config::default().module_size_loc);
    }

    #[test]
    fn parse_config_known_keys_produce_no_warning() {
        let text: String = Config::KNOWN_KEYS
            .iter()
            .map(|k| match *k {
                "parse_isolation" => format!("{k} = true\n"),
                _ => format!("{k} = 1\n"),
            })
            .collect();
        let (cfg, unknown) = parse_config(&text).unwrap();
        assert!(unknown.is_empty(), "{unknown:?}");
        assert_eq!(cfg.module_size_loc, 1);
        assert_eq!(cfg.churn_git_timeout_secs, 1);
    }

    #[test]
    fn unknown_key_warning_names_key_and_escapes_control_chars() {
        let (_, unknown) = parse_config("\"a\\u001b[31mb\" = 1\n").unwrap();
        assert_eq!(unknown, vec!["a\u{1b}[31mb".to_string()]);
        let msg = unknown_key_warning(&unknown[0], Path::new("rpi.toml"));
        assert!(!msg.contains('\u{1b}'), "{msg:?}");
        assert!(msg.contains("a\\u{1b}[31mb"), "{msg}");
        let plain = unknown_key_warning("modul_size_loc", Path::new("rpi.toml"));
        assert!(plain.contains("\"modul_size_loc\""));
    }

    fn lock_fixture(tag: &str, lock: Option<&str>) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rpi_issue135_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"lk\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
        if let Some(l) = lock {
            fs::write(root.join("Cargo.lock"), l).unwrap();
        }
        root
    }

    #[test]
    fn collect_does_not_rewrite_stale_cargo_lock() {
        // Lock records a different version than the manifest: plain
        // `cargo metadata` would rewrite it (#135).
        let stale = "version = 3\n\n[[package]]\nname = \"lk\"\nversion = \"0.0.1\"\n";
        let root = lock_fixture("stale", Some(stale));
        let ctx = collect(&root, CollectOptions::default());
        let after = fs::read_to_string(root.join("Cargo.lock")).unwrap();
        let _ = fs::remove_dir_all(&root);
        assert_eq!(after, stale, "Cargo.lock must not be modified");
        assert!(ctx.is_ok(), "stale lock must still collect via fallback");
    }

    #[test]
    fn collect_without_cargo_lock_succeeds_and_creates_none() {
        let root = lock_fixture("nolock", None);
        let ctx = collect(&root, CollectOptions::default());
        let created = root.join("Cargo.lock").exists();
        let _ = fs::remove_dir_all(&root);
        assert!(ctx.is_ok(), "missing lock must still collect");
        assert!(!created, "Cargo.lock must not be created in the target");
    }

    #[test]
    fn collect_restores_workspace_root_lock_from_member() {
        let root = std::env::temp_dir().join(format!("rpi_issue135_ws_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("m/src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"m\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fs::write(
            root.join("m/Cargo.toml"),
            "[package]\nname = \"m\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("m/src/lib.rs"), "pub fn a() {}\n").unwrap();
        let stale = "version = 3\n\n[[package]]\nname = \"m\"\nversion = \"0.0.1\"\n";
        fs::write(root.join("Cargo.lock"), stale).unwrap();
        let ctx = collect(&root.join("m"), CollectOptions::default());
        let after = fs::read_to_string(root.join("Cargo.lock")).unwrap();
        let member_lock = root.join("m/Cargo.lock").exists();
        let _ = fs::remove_dir_all(&root);
        assert!(ctx.is_ok());
        assert_eq!(after, stale, "workspace root Cargo.lock must be restored");
        assert!(!member_lock);
    }

    #[cfg(unix)]
    fn audit_stub(name: &str, body: &str) -> (PathBuf, Command) {
        let dir = scratch(&format!("audit_stub_{name}"));
        let script = dir.join("audit-stub.sh");
        fs::write(&script, body).unwrap();
        let mut cmd = Command::new("sh");
        cmd.arg(script);
        (dir, cmd)
    }

    /// cargo-audit exits 1 when it finds vulnerabilities; stdout must still be parsed.
    #[cfg(unix)]
    #[test]
    fn audit_command_parses_json_despite_exit_1() {
        let json = r#"{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-1","title":"t"},"package":{"name":"p","version":"1.0.0"}}]}}"#;
        let (dir, cmd) = audit_stub("exit1", &format!("printf '%s' '{json}'\nexit 1\n"));
        let r = run_audit_command(cmd);
        let _ = fs::remove_dir_all(&dir);
        let v = r.unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, "RUSTSEC-1");
        assert_eq!(v[0].package, "p");
    }

    #[cfg(unix)]
    #[test]
    fn audit_command_empty_stdout_with_stderr_warns() {
        let (dir, cmd) = audit_stub("stderr", "echo boom >&2\nexit 2\n");
        let r = run_audit_command(cmd);
        let _ = fs::remove_dir_all(&dir);
        let w = r.unwrap_err();
        assert!(w.contains("produced no output"), "{w}");
        assert!(w.contains("boom"), "{w}");
    }

    #[cfg(unix)]
    #[test]
    fn audit_command_empty_output_is_silent_empty() {
        let (dir, cmd) = audit_stub("silent", "exit 0\n");
        let r = run_audit_command(cmd);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(r.unwrap().len(), 0);
    }

    #[test]
    fn audit_command_spawn_failure_is_err() {
        let cmd = Command::new("/nonexistent/rpi-no-such-cargo-audit");
        let w = run_audit_command(cmd).unwrap_err();
        assert!(w.contains("failed to run"), "{w}");
    }

    #[cfg(unix)]
    #[test]
    fn audit_command_invalid_json_is_err() {
        let (dir, cmd) = audit_stub("garbage", "echo not-json\n");
        let r = run_audit_command(cmd);
        let _ = fs::remove_dir_all(&dir);
        assert!(r.unwrap_err().contains("not valid JSON"));
    }

    #[cfg(unix)]
    #[test]
    fn audit_command_times_out_quickly() {
        let (dir, cmd) = audit_stub("sleep", "sleep 5\n");
        let start = std::time::Instant::now();
        let r = run_audit_command_with(cmd, Duration::from_millis(200), 1024);
        let elapsed = start.elapsed();
        let _ = fs::remove_dir_all(&dir);
        let w = r.unwrap_err();
        assert!(w.contains("timed out"), "{w}");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[cfg(unix)]
    #[test]
    fn audit_command_output_over_cap_is_err() {
        let (dir, cmd) = audit_stub("big", "head -c 100000 /dev/zero | tr '\\0' 'a'\n");
        let r = run_audit_command_with(cmd, Duration::from_secs(10), 1024);
        let _ = fs::remove_dir_all(&dir);
        let w = r.unwrap_err();
        assert!(w.contains("exceeded"), "{w}");
    }

    #[cfg(unix)]
    #[test]
    fn run_limited_kills_endless_output() {
        let (dir, cmd) = audit_stub("endless", "yes\n");
        let start = std::time::Instant::now();
        let r = run_limited(cmd, Duration::from_secs(10), 1024);
        let elapsed = start.elapsed();
        let _ = fs::remove_dir_all(&dir);
        assert!(matches!(r, Err(LimitedError::TooLarge)), "{r:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    #[cfg(unix)]
    #[test]
    fn git_toplevel_times_out_to_none() {
        let (dir, cmd) = audit_stub("gitsleep", "sleep 5\n");
        let start = std::time::Instant::now();
        let r = git_toplevel_with(cmd, &dir, Duration::from_millis(200), 1024);
        let elapsed = start.elapsed();
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(r, None);
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[cfg(unix)]
    #[test]
    fn git_toplevel_reads_stub_output() {
        let (dir, cmd) = audit_stub("gitok", "echo /some/top\n");
        let r = git_toplevel_with(cmd, &dir, Duration::from_secs(10), 1024);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(r, Some(PathBuf::from("/some/top")));
    }

    #[cfg(unix)]
    #[test]
    fn git_toplevel_over_cap_is_none() {
        let (dir, cmd) = audit_stub("gitbig", "head -c 100000 /dev/zero | tr '\\0' 'a'\n");
        let r = git_toplevel_with(cmd, &dir, Duration::from_secs(10), 1024);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(r, None);
    }

    /// Pinned current behavior: entries missing fields are kept as Findings
    /// with empty-string id/title/package/version (not dropped, not an error).
    #[test]
    fn audit_json_missing_entry_fields_become_empty_strings() {
        let json = r#"{"vulnerabilities":{"list":[{},{"advisory":{"id":"X"}},{"advisory":{"id":5,"title":null},"package":{"name":"p"}}]}}"#;
        let v = parse_audit_json(json).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(
            (
                v[0].id.as_str(),
                v[0].title.as_str(),
                v[0].package.as_str(),
                v[0].version.as_str()
            ),
            ("", "", "", "")
        );
        assert_eq!((v[1].id.as_str(), v[1].title.as_str()), ("X", ""));
        assert_eq!((v[2].id.as_str(), v[2].title.as_str()), ("", ""));
        assert_eq!((v[2].package.as_str(), v[2].version.as_str()), ("p", ""));
    }
}
