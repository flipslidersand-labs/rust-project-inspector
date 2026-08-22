//! Structural inspections.
//!
//! P0 ships only the registry plumbing. Concrete inspections
//! (`workspace-graph`, `module-size`, ...) land in #4 and #5.

use rpi_core::Inspection;

mod ast_metrics;
mod audit_bridge;
mod coupling;
mod dep_hygiene;
mod imports;
mod workspace_graph;

pub use ast_metrics::{ModuleSize, PubSurface, TestGap, UnsafeSurface};
pub use audit_bridge::AuditBridge;
pub use coupling::Coupling;
pub use dep_hygiene::DepHygiene;
pub use workspace_graph::WorkspaceGraph;

/// Return the set of inspections to run.
///
/// Each issue registers its inspection here so the CLI and renderers need no
/// changes as coverage grows.
pub fn all() -> Vec<Box<dyn Inspection>> {
    vec![
        Box::new(WorkspaceGraph),
        Box::new(ModuleSize),
        Box::new(UnsafeSurface),
        Box::new(PubSurface),
        Box::new(TestGap),
        Box::new(DepHygiene),
        Box::new(Coupling),
        Box::new(AuditBridge),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_all_inspections() {
        let names: Vec<_> = all().iter().map(|i| i.name()).collect();
        for expected in [
            "workspace-graph",
            "module-size",
            "unsafe-surface",
            "pub-surface",
            "test-gap",
            "dep-hygiene",
            "coupling",
            "audit-bridge",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
    }
}
