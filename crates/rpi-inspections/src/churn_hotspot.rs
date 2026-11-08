//! `churn-hotspot` — files that are both frequently changed and complex.
//!
//! Neither churn nor complexity alone is alarming; their intersection is where
//! bugs cluster and refactoring pays off. Flags files with git change count
//! `>= churn_warn` *and* total cyclomatic complexity `> complexity_warn`.
//!
//! Silent when the workspace has no git history (churn empty).

use rpi_core::{Context, Finding, Inspection, Location, Severity};

use crate::complexity::file_complexity;

pub struct ChurnHotspot;

impl ChurnHotspot {
    pub const NAME: &'static str = "churn-hotspot";
}

impl Inspection for ChurnHotspot {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        if ctx.churn.is_empty() {
            return Vec::new();
        }
        let churn_warn = ctx.config.churn_warn;
        let cx_warn = ctx.config.complexity_warn;
        let mut findings = Vec::new();
        for krate in &ctx.crates {
            for file in &krate.files {
                let changes = ctx.churn.get(&file.path).copied().unwrap_or(0);
                if changes < churn_warn {
                    continue;
                }
                let cx = file_complexity(&file.ast);
                if cx > cx_warn {
                    findings.push(Finding {
                        inspection: Self::NAME,
                        severity: Severity::Warn,
                        location: Location {
                            krate: Some(krate.name.clone()),
                            file: Some(file.path.clone()),
                            ..Default::default()
                        },
                        message: format!(
                            "hotspot: {changes} changes × complexity {cx} \
                             (churn≥{churn_warn}, complexity>{cx_warn})"
                        ),
                        // Risk = churn × complexity for ranking.
                        metric: Some((changes * cx) as f64),
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
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn ctx(src: &str, changes: usize) -> Context {
        let path = PathBuf::from("/w/k/src/lib.rs");
        let krate = CrateData {
            name: "k".into(),
            manifest_path: PathBuf::from("/w/k/Cargo.toml"),
            root_dir: PathBuf::from("/w/k"),
            workspace_deps: Vec::new(),
            external_deps: Vec::new(),
            external_dep_packages: Default::default(),
            files: vec![SourceFile {
                path: path.clone(),
                loc: 1,
                ast: syn::parse_file(src).unwrap(),
            }],
        };
        let mut churn = HashMap::new();
        churn.insert(path, changes);
        Context {
            crates: vec![krate],
            config: Config {
                churn_warn: 3,
                complexity_warn: 2,
                ..Default::default()
            },
            churn,
            ..Default::default()
        }
    }

    // complexity 4 (three ifs), high churn → hotspot
    const COMPLEX: &str = "fn f(a:bool){ if a{} if a{} if a{} }";

    #[test]
    fn flags_high_churn_high_complexity() {
        let f = ChurnHotspot.run(&ctx(COMPLEX, 5));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].metric, Some((5 * 4) as f64));
    }

    #[test]
    fn low_churn_is_ignored() {
        assert!(ChurnHotspot.run(&ctx(COMPLEX, 1)).is_empty());
    }

    #[test]
    fn low_complexity_is_ignored() {
        assert!(ChurnHotspot.run(&ctx("fn f() {}", 9)).is_empty());
    }

    // complexity 2 (one if) == complexity_warn (2)
    const AT_CX_WARN: &str = "fn f(a:bool){ if a{} }";

    #[test]
    fn churn_equal_to_threshold_fires() {
        // changes 3 == churn_warn 3: `changes < churn_warn` is false => not skipped;
        // cx 4 > 2 => fires. metric = 3 * 4.
        let f = ChurnHotspot.run(&ctx(COMPLEX, 3));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].metric, Some((3 * 4) as f64));
    }

    #[test]
    fn churn_one_below_threshold_is_silent() {
        // changes 2 < churn_warn 3 => skipped.
        assert!(ChurnHotspot.run(&ctx(COMPLEX, 2)).is_empty());
    }

    #[test]
    fn complexity_equal_to_threshold_is_silent() {
        // cx 2 == complexity_warn 2: `cx > cx_warn` is false, even with high churn.
        assert!(ChurnHotspot.run(&ctx(AT_CX_WARN, 9)).is_empty());
    }

    #[test]
    fn complexity_one_over_threshold_fires() {
        // cx 3 (two ifs) > complexity_warn 2, changes 9 well above churn_warn => fires.
        let f = ChurnHotspot.run(&ctx("fn f(a:bool){ if a{} if a{} }", 9));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].metric, Some((9 * 3) as f64));
    }

    #[test]
    fn only_files_present_in_churn_are_flagged() {
        // Two equally complex files; only lib.rs is in the churn map (changes 5).
        // other.rs falls back to unwrap_or(0) < churn_warn 3 => skipped.
        let mut c = ctx(COMPLEX, 5);
        let other = PathBuf::from("/w/k/src/other.rs");
        c.crates[0].files.push(SourceFile {
            path: other,
            loc: 1,
            ast: syn::parse_file(COMPLEX).unwrap(),
        });
        let f = ChurnHotspot.run(&c);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].location.file.as_deref(),
            Some(std::path::Path::new("/w/k/src/lib.rs"))
        );
    }

    #[test]
    fn no_git_history_is_silent() {
        let mut c = ctx(COMPLEX, 5);
        c.churn.clear();
        assert!(ChurnHotspot.run(&c).is_empty());
    }
}
