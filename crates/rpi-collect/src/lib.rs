//! Workspace collection and AST parsing.
//!
//! [`collect`] resolves a workspace via `cargo metadata`, discovers every `.rs`
//! file belonging to each member crate, and parses each file **once** with
//! `syn`. Inspections then read the shared [`Context`] without re-parsing.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use cargo_metadata::MetadataCommand;
use rpi_core::{Context, CrateData, SourceFile, WorkspaceInfo};

/// Build a [`Context`] for the workspace rooted at `root`.
///
/// Files that fail to parse are skipped with a warning on stderr so a single
/// bad file never aborts the whole run.
pub fn collect(root: &Path) -> Result<Context> {
    let metadata = MetadataCommand::new()
        .current_dir(root)
        .no_deps()
        .exec()
        .context("failed to run `cargo metadata`")?;

    // Names of workspace members, used to keep only intra-workspace deps.
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

        let workspace_deps = pkg
            .dependencies
            .iter()
            .map(|d| d.name.clone())
            .filter(|name| member_names.contains(name))
            .collect();

        let files = collect_rs_files(&root_dir)
            .into_iter()
            .filter_map(|path| parse_file(&path))
            .collect();

        crates.push(CrateData {
            name: pkg.name.to_string(),
            manifest_path,
            root_dir,
            workspace_deps,
            files,
        });
    }

    let workspace = WorkspaceInfo {
        root: metadata.workspace_root.clone().into_std_path_buf(),
        crates: crates.iter().map(|c| c.name.clone()).collect(),
    };

    Ok(Context { workspace, crates })
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
        let ctx = collect(&fixture()).unwrap();
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
}
