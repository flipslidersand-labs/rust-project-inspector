//! Workspace collection and AST parsing.
//!
//! P0 provides a stub `collect` that yields an empty [`Context`] for the given
//! root. #3 replaces this with `cargo_metadata` + `syn` parsing.

use std::path::{Path, PathBuf};

use anyhow::Result;
use rpi_core::{Context, WorkspaceInfo};

/// Build a [`Context`] for the workspace rooted at `root`.
///
/// Currently a stub: it records the root path and returns no crates. The real
/// implementation lands in #3.
pub fn collect(root: &Path) -> Result<Context> {
    let workspace = WorkspaceInfo {
        root: PathBuf::from(root),
        crates: Vec::new(),
    };
    Ok(Context { workspace })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_records_root() {
        let ctx = collect(Path::new("/tmp/example")).unwrap();
        assert_eq!(ctx.workspace.root, PathBuf::from("/tmp/example"));
        assert!(ctx.workspace.crates.is_empty());
    }
}
