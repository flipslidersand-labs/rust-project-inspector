//! Workspace collection and AST parsing.
//!
//! [`collect`] resolves a workspace via `cargo metadata`, discovers every `.rs`
//! file belonging to each member crate, and parses each file **once** with
//! `syn`. Inspections then read the shared [`Context`] without re-parsing.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        for dep in &pkg.dependencies {
            if member_names.contains(&dep.name) {
                workspace_deps.push(dep.name.clone());
            } else if dep.kind == cargo_metadata::DependencyKind::Normal {
                external_deps.push(dep.name.clone());
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
    let churn = collect_churn(&root_dir);

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
/// Best-effort: returns empty when the root is not a git repo or git is absent.
fn collect_churn(root: &Path) -> HashMap<PathBuf, usize> {
    let output = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["log", "--name-only", "--pretty=format:"])
        .output();
    let Ok(out) = output else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    // git prints paths relative to the repo toplevel, which may differ from the
    // workspace root; anchor against the toplevel so keys are absolute and match
    // the paths inspections carry.
    let anchor = git_toplevel(root).unwrap_or_else(|| root.to_path_buf());
    let text = String::from_utf8_lossy(&out.stdout);
    let mut churn: HashMap<PathBuf, usize> = HashMap::new();
    for line in text.lines() {
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

/// Run `cargo audit --json` at `root` and parse advisories. Best-effort: if the
/// binary is missing or the command fails, warn once and return no vulns rather
/// than aborting the inspection.
fn run_cargo_audit(root: &Path) -> Vec<AuditVuln> {
    let output = Command::new("cargo")
        .args(["audit", "--json"])
        .current_dir(root)
        .output();
    match output {
        Ok(out) if !out.stdout.is_empty() => {
            parse_audit_json(&String::from_utf8_lossy(&out.stdout))
        }
        Ok(_) => Vec::new(),
        Err(e) => {
            eprintln!("warn: `cargo audit` unavailable ({e}); skipping audit-bridge");
            Vec::new()
        }
    }
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
}
