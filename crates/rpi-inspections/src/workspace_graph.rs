//! `workspace-graph` — crate dependency-graph health.
//!
//! Builds a directed graph over workspace members (edges = intra-workspace
//! dependencies) and reports:
//! - **circular dependencies** (strongly-connected components of size > 1) — Error
//! - **isolated crates** (no inbound or outbound workspace edges) — Info
//!
//! Dependency data comes from `rpi-collect`, so this inspection never touches
//! the filesystem.

use std::collections::HashMap;

use petgraph::algo::tarjan_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use rpi_core::{Context, Finding, Inspection, Location, Severity};

pub struct WorkspaceGraph;

impl WorkspaceGraph {
    pub const NAME: &'static str = "workspace-graph";
}

impl Inspection for WorkspaceGraph {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut graph: DiGraph<String, ()> = DiGraph::new();
        let mut index: HashMap<&str, NodeIndex> = HashMap::new();

        for krate in &ctx.crates {
            let idx = graph.add_node(krate.name.clone());
            index.insert(krate.name.as_str(), idx);
        }
        for krate in &ctx.crates {
            let from = index[krate.name.as_str()];
            for dep in &krate.workspace_deps {
                if let Some(&to) = index.get(dep.as_str()) {
                    graph.add_edge(from, to, ());
                }
            }
        }

        let mut findings = Vec::new();
        findings.extend(circular_findings(&graph));
        findings.extend(isolated_findings(&graph));
        findings
    }
}

fn circular_findings(graph: &DiGraph<String, ()>) -> Vec<Finding> {
    tarjan_scc(graph)
        .into_iter()
        .filter(|scc| scc.len() > 1)
        .map(|scc| {
            let mut members: Vec<&str> = scc.iter().map(|&i| graph[i].as_str()).collect();
            members.sort();
            Finding {
                inspection: WorkspaceGraph::NAME,
                severity: Severity::Error,
                location: Location::default(),
                message: format!(
                    "circular dependency between crates: {}",
                    members.join(" ⇄ ")
                ),
                metric: Some(scc.len() as f64),
            }
        })
        .collect()
}

fn isolated_findings(graph: &DiGraph<String, ()>) -> Vec<Finding> {
    use petgraph::Direction;

    // Only flag isolation when the workspace actually has more than one crate;
    // a single-crate workspace being "isolated" is meaningless noise.
    if graph.node_count() < 2 {
        return Vec::new();
    }

    graph
        .node_indices()
        .filter(|&i| {
            graph.neighbors_directed(i, Direction::Outgoing).count() == 0
                && graph.neighbors_directed(i, Direction::Incoming).count() == 0
        })
        .map(|i| Finding {
            inspection: WorkspaceGraph::NAME,
            severity: Severity::Info,
            location: Location {
                krate: Some(graph[i].clone()),
                ..Default::default()
            },
            message: format!(
                "crate `{}` has no intra-workspace dependencies (isolated)",
                graph[i]
            ),
            metric: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_core::{CrateData, WorkspaceInfo};
    use std::path::PathBuf;

    fn krate(name: &str, deps: &[&str]) -> CrateData {
        CrateData {
            name: name.to_string(),
            manifest_path: PathBuf::from(format!("/w/{name}/Cargo.toml")),
            root_dir: PathBuf::from(format!("/w/{name}")),
            workspace_deps: deps.iter().map(|s| s.to_string()).collect(),
            external_deps: Vec::new(),
            files: Vec::new(),
        }
    }

    fn ctx(crates: Vec<CrateData>) -> Context {
        Context {
            workspace: WorkspaceInfo::default(),
            crates,
            config: rpi_core::Config::default(),
            resolved_versions: Vec::new(),
            audit: Vec::new(),
        }
    }

    #[test]
    fn detects_circular_dependency() {
        // a -> b -> a
        let c = ctx(vec![krate("a", &["b"]), krate("b", &["a"])]);
        let findings = WorkspaceGraph.run(&c);
        let cyc: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert_eq!(cyc.len(), 1);
        assert!(cyc[0].message.contains("a ⇄ b"));
    }

    #[test]
    fn acyclic_graph_has_no_error() {
        // a -> b, a -> c (no cycle)
        let c = ctx(vec![
            krate("a", &["b", "c"]),
            krate("b", &[]),
            krate("c", &[]),
        ]);
        let findings = WorkspaceGraph.run(&c);
        assert!(findings.iter().all(|f| f.severity != Severity::Error));
    }

    #[test]
    fn flags_isolated_crate() {
        // a -> b connected; lonely stands alone.
        let c = ctx(vec![
            krate("a", &["b"]),
            krate("b", &[]),
            krate("lonely", &[]),
        ]);
        let findings = WorkspaceGraph.run(&c);
        let iso: Vec<_> = findings
            .iter()
            .filter(|f| f.location.krate.as_deref() == Some("lonely"))
            .collect();
        assert_eq!(iso.len(), 1);
        assert_eq!(iso[0].severity, Severity::Info);
    }

    #[test]
    fn single_crate_workspace_is_not_isolated_noise() {
        let c = ctx(vec![krate("solo", &[])]);
        let findings = WorkspaceGraph.run(&c);
        assert!(findings.is_empty());
    }
}
