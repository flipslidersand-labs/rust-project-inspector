//! `dep-hygiene` — declared-but-unused dependencies and duplicate versions.
//!
//! Two checks:
//! - **unused dep** (per crate): a declared normal dependency whose crate root
//!   is never referenced in the crate's sources. syn-level approximation —
//!   deps reached only via macro expansion may show as false positives.
//! - **duplicate version** (workspace-wide): one crate resolved to more than
//!   one version across the dependency graph (bloat / conflict risk).

use std::collections::{BTreeMap, BTreeSet};

use rpi_core::{Context, Finding, Inspection, Location, Severity};

use crate::imports::file_reference_roots;

pub struct DepHygiene;

impl DepHygiene {
    pub const NAME: &'static str = "dep-hygiene";
}

/// Cargo dependency names use `-`; the crate root in code uses `_`.
fn normalize(name: &str) -> String {
    name.replace('-', "_")
}

impl Inspection for DepHygiene {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();

        // --- unused declared dependencies -----------------------------------
        for krate in &ctx.crates {
            let mut referenced: BTreeSet<String> = BTreeSet::new();
            for file in &krate.files {
                referenced.extend(file_reference_roots(&file.ast));
            }
            for dep in &krate.external_deps {
                if !referenced.contains(&normalize(dep)) {
                    findings.push(Finding {
                        inspection: Self::NAME,
                        severity: Severity::Warn,
                        location: Location {
                            krate: Some(krate.name.clone()),
                            ..Default::default()
                        },
                        message: format!("declared dependency `{dep}` appears unused (approx.)"),
                        metric: None,
                    });
                }
            }
        }

        // --- duplicate resolved versions ------------------------------------
        let mut versions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for (name, version) in &ctx.resolved_versions {
            versions.entry(name).or_default().insert(version);
        }
        for (name, vers) in versions {
            if vers.len() > 1 {
                let list: Vec<&str> = vers.into_iter().collect();
                findings.push(Finding {
                    inspection: Self::NAME,
                    severity: Severity::Warn,
                    location: Location::default(),
                    message: format!(
                        "crate `{name}` resolved to {} versions: {}",
                        list.len(),
                        list.join(", ")
                    ),
                    metric: Some(list.len() as f64),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_core::{Config, CrateData, SourceFile, WorkspaceInfo};
    use std::path::PathBuf;

    fn krate(name: &str, ext_deps: &[&str], src: &str) -> CrateData {
        CrateData {
            name: name.into(),
            manifest_path: PathBuf::from(format!("/w/{name}/Cargo.toml")),
            root_dir: PathBuf::from(format!("/w/{name}")),
            workspace_deps: Vec::new(),
            external_deps: ext_deps.iter().map(|s| s.to_string()).collect(),
            files: vec![SourceFile {
                path: PathBuf::from("lib.rs"),
                loc: src.lines().count(),
                ast: syn::parse_file(src).unwrap(),
            }],
        }
    }

    fn ctx(crates: Vec<CrateData>, resolved: &[(&str, &str)]) -> Context {
        Context {
            workspace: WorkspaceInfo::default(),
            crates,
            config: Config::default(),
            resolved_versions: resolved
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            audit: Vec::new(),
        }
    }

    #[test]
    fn flags_unused_but_not_used_dep() {
        let k = krate(
            "k",
            &["serde", "unused_dep"],
            "use serde::Serialize; fn f() {}",
        );
        let f = DepHygiene.run(&ctx(vec![k], &[]));
        let msgs: Vec<_> = f.iter().map(|x| x.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("`unused_dep`")));
        assert!(!msgs.iter().any(|m| m.contains("`serde`")));
    }

    #[test]
    fn normalizes_hyphenated_dep_names() {
        let k = krate("k", &["foo-bar"], "use foo_bar::baz; fn f() {}");
        let f = DepHygiene.run(&ctx(vec![k], &[]));
        assert!(!f.iter().any(|x| x.message.contains("foo-bar")));
    }

    #[test]
    fn flags_duplicate_versions() {
        let f = DepHygiene.run(&ctx(
            vec![],
            &[("dup", "1.0.0"), ("dup", "2.0.0"), ("solo", "1.0.0")],
        ));
        let dup: Vec<_> = f.iter().filter(|x| x.message.contains("`dup`")).collect();
        assert_eq!(dup.len(), 1);
        assert!(dup[0].message.contains("2 versions"));
    }
}
