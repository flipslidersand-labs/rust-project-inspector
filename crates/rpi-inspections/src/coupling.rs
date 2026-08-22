//! `coupling` — per-file efferent coupling ("God module" smell).
//!
//! Counts the distinct external crate roots a file imports. A file that pulls in
//! many different crates is doing too much and is a refactor candidate. This is
//! efferent (outgoing) coupling at file granularity — a syn-level proxy, not a
//! full module-resolution graph.

use rpi_core::{Context, Finding, Inspection, Location, Severity};

use crate::imports::file_use_roots;

pub struct Coupling;

impl Coupling {
    pub const NAME: &'static str = "coupling";
}

impl Inspection for Coupling {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let warn = ctx.config.coupling_warn;
        let mut findings = Vec::new();
        for krate in &ctx.crates {
            for file in &krate.files {
                let count = file_use_roots(&file.ast).len();
                if count > warn {
                    findings.push(Finding {
                        inspection: Self::NAME,
                        severity: Severity::Warn,
                        location: Location {
                            krate: Some(krate.name.clone()),
                            file: Some(file.path.clone()),
                            ..Default::default()
                        },
                        message: format!(
                            "file imports {count} distinct crate roots (> {warn} threshold)"
                        ),
                        metric: Some(count as f64),
                    });
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_core::{Config, CrateData, SourceFile};
    use std::path::PathBuf;

    fn ctx_one_file(src: &str, warn: usize) -> Context {
        let krate = CrateData {
            name: "k".into(),
            manifest_path: PathBuf::from("/w/k/Cargo.toml"),
            root_dir: PathBuf::from("/w/k"),
            workspace_deps: Vec::new(),
            external_deps: Vec::new(),
            files: vec![SourceFile {
                path: PathBuf::from("/w/k/src/lib.rs"),
                loc: src.lines().count(),
                ast: syn::parse_file(src).unwrap(),
            }],
        };
        Context {
            crates: vec![krate],
            config: Config {
                coupling_warn: warn,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn flags_file_over_threshold() {
        let src = "use a::x; use b::y; use c::z;";
        let f = Coupling.run(&ctx_one_file(src, 2));
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("3 distinct"));
    }

    #[test]
    fn under_threshold_is_silent() {
        let src = "use a::x; use b::y;";
        let f = Coupling.run(&ctx_one_file(src, 5));
        assert!(f.is_empty());
    }
}
