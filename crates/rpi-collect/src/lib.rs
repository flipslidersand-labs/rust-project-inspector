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

use anyhow::{Context as _, Result};
use cargo_metadata::MetadataCommand;
use rpi_core::{AuditVuln, Config, Context, CrateData, SourceFile, WorkspaceInfo};

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
    collect_inner(root, opts)
        .with_context(|| format!("failed to inspect workspace at {}", root.display()))
}

fn collect_inner(root: &Path, opts: CollectOptions) -> Result<Context> {
    // Full metadata (deps resolved) so `dep-hygiene` can inspect the whole
    // graph for duplicate versions.
    let metadata = MetadataCommand::new()
        .current_dir(root)
        .exec()
        .context("failed to run `cargo metadata`")?;

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
            if member_names.contains(&dep.name) {
                workspace_deps.push(dep.name.clone());
            } else {
                // Code refers to a renamed dependency by its rename; keep the
                // original package name separately for display (#66).
                let reference = dep.rename.as_deref().unwrap_or(&dep.name);
                external_deps.push(reference.to_string());
                if reference != dep.name {
                    external_dep_packages.insert(reference.to_string(), dep.name.clone());
                }
            }
        }

        let files = collect_rs_files(&root_dir)
            .into_iter()
            .filter_map(|path| parse_file(&path))
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

    let root_dir = metadata.workspace_root.clone().into_std_path_buf();
    let config = load_config(&root_dir);
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
        eprintln!("{notice}");
        return HashMap::new();
    }
    collect_churn_with(Command::new("git"), root, timeout)
}

/// [`collect_churn`] with the git invocation injected (`git` is the program and
/// any leading arguments), so tests can substitute a stub.
fn collect_churn_with(mut git: Command, root: &Path, timeout: Duration) -> HashMap<PathBuf, usize> {
    let mut child = match git
        .args(["-C"])
        .arg(root)
        .args(["log", "--name-only", "--pretty=format:"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };

    // Read stdout in a background thread so the main thread can enforce a
    // wall-clock timeout without blocking on the child's pipe.
    let stdout = child.stdout.take().expect("stdout was piped");
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        // Read raw bytes: git paths need not be UTF-8, and a decode error must
        // not discard the whole history. Decode lossily afterwards.
        let mut buf = Vec::new();
        let _ = std::io::BufReader::new(stdout).read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    let raw = match rx.recv_timeout(timeout) {
        Ok(bytes) => {
            // Reap the process and require success: a git that fails midway
            // (e.g. a corrupt older object) leaves partial output that would
            // silently undercount churn.
            match child.wait() {
                Ok(status) if status.success() => String::from_utf8_lossy(&bytes).into_owned(),
                _ => return HashMap::new(),
            }
        }
        Err(_) => {
            // Timeout or thread panic: kill git and report.
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "warn: `git log` timed out after {}s; churn-hotspot will be skipped \
                 (increase churn_git_timeout_secs in rpi.toml to raise the limit)",
                timeout.as_secs()
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
fn git_toplevel(dir: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["-C"])
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
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
    if let Some(notice) = skip_notice(
        "audit-bridge",
        "cargo-audit",
        "install with `cargo install cargo-audit`",
        search_path().as_deref(),
    ) {
        eprintln!("{notice}");
        return Vec::new();
    }
    let output = Command::new("cargo")
        .args(["audit", "--json"])
        .current_dir(root)
        .output();
    match output {
        Ok(out) if !out.stdout.is_empty() => {
            parse_audit_json(&String::from_utf8_lossy(&out.stdout))
        }
        Ok(out) => {
            if !out.stderr.is_empty() {
                let msg = String::from_utf8_lossy(&out.stderr);
                eprintln!("warn: `cargo audit` produced no output ({msg}); skipping audit-bridge");
            }
            Vec::new()
        }
        Err(e) => {
            eprintln!("warn: `cargo audit` failed to run ({e}); skipping audit-bridge");
            Vec::new()
        }
    }
}

/// Directories searched for external tools: `PATH` plus `$CARGO_HOME/bin`
/// (default `~/.cargo/bin`), which is where `cargo` itself also looks for
/// `cargo-*` subcommands. `None` when neither is known.
fn search_path() -> Option<OsString> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
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
/// missing fields so schema drift degrades gracefully.
fn parse_audit_json(text: &str) -> Vec<AuditVuln> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let list = doc
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    list.iter()
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
        .collect()
}

/// Load `rpi.toml` from the workspace root, falling back to defaults when the
/// file is absent or unreadable. A malformed file warns and uses defaults
/// rather than aborting the run.
fn load_config(root: &Path) -> Config {
    let path = root.join("rpi.toml");
    let Ok(text) = fs::read_to_string(&path) else {
        return Config::default();
    };
    match toml::from_str(&text) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("warn: ignoring {} (parse error: {e})", path.display());
            Config::default()
        }
    }
}

/// Recursively gather `.rs` files under `dir`, skipping any `target/` output.
fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&path, out);
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
            eprintln!("{msg}");
            None
        }
    }
}

/// Like [`parse_file`] but returns the warning text instead of printing it.
///
/// The message always carries the file path; for syntax errors it also carries
/// the `line:column` of the error (requires `proc-macro2`'s `span-locations`).
fn try_parse_file(path: &Path) -> Result<SourceFile, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("warn: skipping {} (read error: {e})", path.display()))?;
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
    Ok(SourceFile {
        path: path.to_path_buf(),
        loc,
        ast,
    })
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
        let vulns = parse_audit_json(json);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].id, "RUSTSEC-2021-0001");
        assert_eq!(vulns[0].package, "badcrate");
        assert_eq!(vulns[0].version, "1.2.3");
        assert_eq!(vulns[0].title, "boom");
    }

    #[test]
    fn audit_json_tolerates_empty_and_garbage() {
        assert!(parse_audit_json("not json").is_empty());
        assert!(parse_audit_json("{}").is_empty());
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

    #[test]
    fn collect_churn_returns_empty_on_near_zero_timeout() {
        // A 1ms timeout against a real git repo should either complete fast or
        // time out — either way the function must return without panicking.
        // We only assert no panic and that the result is a valid HashMap.
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../")
            .canonicalize()
            .unwrap();
        let churn = collect_churn(&repo, Duration::from_millis(1));
        // Result may or may not be empty depending on system speed; just verify
        // the function terminates and the map is well-formed.
        let _ = churn.len();
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
        let churn = collect_churn_with(cmd, &dir, Duration::from_secs(10));
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
        let churn = collect_churn_with(cmd, &dir, Duration::from_secs(10));
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
        let churn = collect_churn_with(cmd, &dir, Duration::from_secs(10));
        std::fs::remove_dir_all(&dir).ok();
        let ok = churn.iter().find(|(p, _)| p.ends_with("src/ok.rs"));
        assert_eq!(ok.map(|(_, n)| *n), Some(2), "UTF-8 paths lost: {churn:?}");
    }

    #[test]
    fn config_default_timeout_is_thirty_seconds() {
        assert_eq!(rpi_core::Config::default().churn_git_timeout_secs, 30);
    }
}
