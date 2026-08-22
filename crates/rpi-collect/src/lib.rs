//! Workspace collection and AST parsing.
//!
//! [`collect`] resolves a workspace via `cargo metadata`, discovers every `.rs`
//! file belonging to each member crate, and parses each file **once** with
//! `syn`. Inspections then read the shared [`Context`] without re-parsing.

use std::collections::BTreeSet;
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
/// Files that fail to parse are skipped with a warning on stderr so a single
/// bad file never aborts the whole run.
pub fn collect(root: &Path, opts: CollectOptions) -> Result<Context> {
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
    })
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

/// Read and parse a single file. Returns `None` (with a stderr warning) on I/O
/// or syntax errors so collection is best-effort.
fn parse_file(path: &Path) -> Option<SourceFile> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warn: skipping {} (read error: {e})", path.display());
            return None;
        }
    };
    let loc = content.lines().count();
    match syn::parse_file(&content) {
        Ok(ast) => Some(SourceFile {
            path: path.to_path_buf(),
            loc,
            ast,
        }),
        Err(e) => {
            eprintln!("warn: skipping {} (parse error: {e})", path.display());
            None
        }
    }
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
}
