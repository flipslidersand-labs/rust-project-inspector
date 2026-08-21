//! Structural inspections.
//!
//! P0 ships only the registry plumbing. Concrete inspections
//! (`workspace-graph`, `module-size`, ...) land in #4 and #5.

use rpi_core::Inspection;

mod workspace_graph;

pub use workspace_graph::WorkspaceGraph;

/// Return the set of inspections to run.
///
/// Each issue registers its inspection here so the CLI and renderers need no
/// changes as coverage grows.
pub fn all() -> Vec<Box<dyn Inspection>> {
    vec![Box::new(WorkspaceGraph)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_workspace_graph() {
        let names: Vec<_> = all().iter().map(|i| i.name()).collect();
        assert!(names.contains(&"workspace-graph"));
    }
}
