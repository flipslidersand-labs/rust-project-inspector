//! Structural inspections.
//!
//! P0 ships only the registry plumbing. Concrete inspections
//! (`workspace-graph`, `module-size`, ...) land in #4 and #5.

use rpi_core::Inspection;

/// Return the set of inspections to run.
///
/// Empty in P0; each subsequent issue registers its inspection here so the CLI
/// and renderers need no changes as coverage grows.
pub fn all() -> Vec<Box<dyn Inspection>> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_starts_empty() {
        assert_eq!(all().len(), 0);
    }
}
