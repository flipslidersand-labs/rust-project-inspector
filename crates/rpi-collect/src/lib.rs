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
/// I/O errors reading `.rs` files are skipped with a warning so a single
/// unreadable file never aborts the run. Syntax errors in `.rs` files are
/// fatal — they surface as a chained error so the user knows exactly which
/// file is broken.
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
            .map(|path| parse_file(&path))
            .filter_map(|r| r.transpose())
            .collect::<Result<Vec<_>>>()?;

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

/// Read and parse a single `.rs` file.
///
/// Returns `Ok(None)` (with a stderr warning) when the file cannot be read —
/// best-effort so a single unreadable file never aborts a run. Returns `Err`
/// for syntax errors so the caller can propagate them with file-path context.
fn parse_file(path: &Path) -> Result<Option<SourceFile>> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warn: skipping {} (read error: {e})", path.display());
            return Ok(None);
        }
    };
    let loc = content.lines().count();
    let ast = syn::parse_file(&content).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(SourceFile {
        path: path.to_path_buf(),
        loc,
        ast,
    }))
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

    #[test]
    fn parse_file_returns_err_for_syntax_errors() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join("rpi_test_parse_file_22");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("bad.rs");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"fn {{{")
            .unwrap();
        let result = parse_file(&path);
        std::fs::remove_dir_all(&dir).ok();
        match result {
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(
                    msg.contains("bad.rs"),
                    "error must mention the file path: {msg}"
                );
            }
            Ok(_) => panic!("expected Err for file with syntax errors"),
        }
    }

    #[test]
    fn parse_file_returns_ok_none_for_unreadable_file() {
        let result = parse_file(std::path::Path::new("/nonexistent/totally/fake.rs"));
        match result {
            Ok(None) => {}
            Ok(Some(_)) => panic!("expected Ok(None) for unreadable file"),
            Err(e) => panic!("expected Ok(None), got Err({e})"),
        }
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
