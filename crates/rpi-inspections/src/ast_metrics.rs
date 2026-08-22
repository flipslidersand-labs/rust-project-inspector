//! AST-walking inspections: `module-size`, `unsafe-surface`, `pub-surface`,
//! `test-gap`.
//!
//! All four read the shared, already-parsed [`syn::File`] ASTs from the
//! [`Context`] — no file is re-parsed. A single [`FileStats`] pass per file
//! feeds every inspection.

use rpi_core::{Context, CrateData, Finding, Inspection, Location, Severity, SourceFile};
use syn::visit::{self, Visit};

/// Per-file structural counts gathered in one AST pass.
#[derive(Debug, Default, Clone, Copy)]
struct FileStats {
    items: usize,
    unsafe_count: usize,
    pub_items: usize,
    has_test: bool,
}

/// Walk one file's AST and tally the counts every inspection needs.
fn analyze(file: &SourceFile) -> FileStats {
    let mut c = Counter::default();
    c.visit_file(&file.ast);
    c.stats
}

#[derive(Default)]
struct Counter {
    stats: FileStats,
}

impl<'ast> Visit<'ast> for Counter {
    fn visit_item(&mut self, i: &'ast syn::Item) {
        self.stats.items += 1;
        if item_is_public(i) {
            self.stats.pub_items += 1;
        }
        visit::visit_item(self, i);
    }

    fn visit_expr_unsafe(&mut self, e: &'ast syn::ExprUnsafe) {
        self.stats.unsafe_count += 1;
        visit::visit_expr_unsafe(self, e);
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if matches!(f.sig.safety, syn::Safety::Unsafe(_)) {
            self.stats.unsafe_count += 1;
        }
        visit::visit_item_fn(self, f);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if matches!(f.sig.safety, syn::Safety::Unsafe(_)) {
            self.stats.unsafe_count += 1;
        }
        visit::visit_impl_item_fn(self, f);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if i.unsafety.is_some() {
            self.stats.unsafe_count += 1;
        }
        visit::visit_item_impl(self, i);
    }

    fn visit_item_trait(&mut self, t: &'ast syn::ItemTrait) {
        if t.unsafety.is_some() {
            self.stats.unsafe_count += 1;
        }
        visit::visit_item_trait(self, t);
    }

    fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
        // Catches `#[test]`, `#[tokio::test]`, `#[rstest]`-style last segments.
        if a.path().segments.last().is_some_and(|s| s.ident == "test") {
            self.stats.has_test = true;
        }
        visit::visit_attribute(self, a);
    }
}

/// Whether a top-level item carries `pub` visibility.
fn item_is_public(item: &syn::Item) -> bool {
    let vis = match item {
        syn::Item::Const(i) => &i.vis,
        syn::Item::Enum(i) => &i.vis,
        syn::Item::Fn(i) => &i.vis,
        syn::Item::Mod(i) => &i.vis,
        syn::Item::Static(i) => &i.vis,
        syn::Item::Struct(i) => &i.vis,
        syn::Item::Trait(i) => &i.vis,
        syn::Item::TraitAlias(i) => &i.vis,
        syn::Item::Type(i) => &i.vis,
        syn::Item::Union(i) => &i.vis,
        syn::Item::Use(i) => &i.vis,
        _ => return false,
    };
    matches!(vis, syn::Visibility::Public(_))
}

/// Aggregate a crate's file stats into one struct.
fn crate_stats(krate: &CrateData) -> (FileStats, usize) {
    let mut agg = FileStats::default();
    let mut loc = 0;
    for file in &krate.files {
        let s = analyze(file);
        agg.items += s.items;
        agg.unsafe_count += s.unsafe_count;
        agg.pub_items += s.pub_items;
        agg.has_test |= s.has_test;
        loc += file.loc;
    }
    (agg, loc)
}

// ---------------------------------------------------------------------------
// module-size
// ---------------------------------------------------------------------------

pub struct ModuleSize;

impl ModuleSize {
    pub const NAME: &'static str = "module-size";
}

impl Inspection for ModuleSize {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let limit = ctx.config.module_size_loc;
        let mut findings = Vec::new();
        for krate in &ctx.crates {
            for file in &krate.files {
                if file.loc > limit {
                    findings.push(Finding {
                        inspection: Self::NAME,
                        severity: Severity::Warn,
                        location: Location {
                            krate: Some(krate.name.clone()),
                            file: Some(file.path.clone()),
                            ..Default::default()
                        },
                        message: format!("file is {} lines (> {} threshold)", file.loc, limit),
                        metric: Some(file.loc as f64),
                    });
                }
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// unsafe-surface
// ---------------------------------------------------------------------------

pub struct UnsafeSurface;

impl UnsafeSurface {
    pub const NAME: &'static str = "unsafe-surface";
}

impl Inspection for UnsafeSurface {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        for krate in &ctx.crates {
            let (stats, loc) = crate_stats(krate);
            if stats.unsafe_count == 0 {
                continue;
            }
            let density = if loc > 0 {
                stats.unsafe_count as f64 / loc as f64 * 1000.0
            } else {
                0.0
            };
            let over = density > ctx.config.unsafe_density_warn;
            findings.push(Finding {
                inspection: Self::NAME,
                severity: if over { Severity::Warn } else { Severity::Info },
                location: Location {
                    krate: Some(krate.name.clone()),
                    ..Default::default()
                },
                message: format!("{} unsafe items ({:.1}/kLOC)", stats.unsafe_count, density),
                metric: Some(density),
            });
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// pub-surface
// ---------------------------------------------------------------------------

pub struct PubSurface;

impl PubSurface {
    pub const NAME: &'static str = "pub-surface";
}

impl Inspection for PubSurface {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let warn = ctx.config.pub_surface_warn;
        let mut findings = Vec::new();
        for krate in &ctx.crates {
            let (stats, _) = crate_stats(krate);
            if stats.pub_items == 0 {
                continue;
            }
            let over = stats.pub_items > warn;
            findings.push(Finding {
                inspection: Self::NAME,
                severity: if over { Severity::Warn } else { Severity::Info },
                location: Location {
                    krate: Some(krate.name.clone()),
                    ..Default::default()
                },
                message: format!("{} public items", stats.pub_items),
                metric: Some(stats.pub_items as f64),
            });
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// test-gap
// ---------------------------------------------------------------------------

pub struct TestGap;

impl TestGap {
    pub const NAME: &'static str = "test-gap";
}

impl Inspection for TestGap {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        for krate in &ctx.crates {
            let (stats, _) = crate_stats(krate);
            if !stats.has_test {
                findings.push(Finding {
                    inspection: Self::NAME,
                    severity: Severity::Warn,
                    location: Location {
                        krate: Some(krate.name.clone()),
                        ..Default::default()
                    },
                    message: "crate has no tests".to_string(),
                    metric: None,
                });
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_core::{Config, WorkspaceInfo};
    use std::path::PathBuf;

    fn krate_from_src(name: &str, srcs: &[&str]) -> CrateData {
        let files = srcs
            .iter()
            .enumerate()
            .map(|(i, src)| SourceFile {
                path: PathBuf::from(format!("/w/{name}/src/f{i}.rs")),
                loc: src.lines().count(),
                ast: syn::parse_file(src).expect("fixture must parse"),
            })
            .collect();
        CrateData {
            name: name.to_string(),
            manifest_path: PathBuf::from(format!("/w/{name}/Cargo.toml")),
            root_dir: PathBuf::from(format!("/w/{name}")),
            workspace_deps: Vec::new(),
            files,
        }
    }

    fn ctx_with(config: Config, crates: Vec<CrateData>) -> Context {
        Context {
            workspace: WorkspaceInfo::default(),
            crates,
            config,
        }
    }

    #[test]
    fn counts_unsafe_across_forms() {
        let src = r#"
            pub unsafe fn a() {}
            unsafe trait T {}
            unsafe impl T for () {}
            fn b() { unsafe { let _ = 1; } }
        "#;
        let c = ctx_with(Config::default(), vec![krate_from_src("k", &[src])]);
        let findings = UnsafeSurface.run(&c);
        assert_eq!(findings.len(), 1);
        // unsafe fn + unsafe trait + unsafe impl + unsafe block = 4
        assert_eq!(findings[0].metric.map(|_| ()), Some(()));
        assert!(findings[0].message.starts_with("4 unsafe items"));
    }

    #[test]
    fn counts_public_items_only() {
        let src = "pub fn a() {} fn b() {} pub struct S; enum E {}";
        let c = ctx_with(Config::default(), vec![krate_from_src("k", &[src])]);
        let findings = PubSurface.run(&c);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.starts_with("2 public items"));
    }

    #[test]
    fn test_gap_flags_crate_without_tests() {
        let no_tests = krate_from_src("no", &["pub fn a() {}"]);
        let with_tests = krate_from_src("yes", &["#[test]\nfn t() { assert!(true); }"]);
        let c = ctx_with(Config::default(), vec![no_tests, with_tests]);
        let findings = TestGap.run(&c);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.krate.as_deref(), Some("no"));
    }

    #[test]
    fn module_size_respects_threshold() {
        let big = "\n".repeat(400) + "pub fn a() {}";
        let cfg = Config {
            module_size_loc: 300,
            ..Default::default()
        };
        let c = ctx_with(cfg, vec![krate_from_src("k", &[&big])]);
        let findings = ModuleSize.run(&c);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
    }

    #[test]
    fn unsafe_density_over_threshold_warns() {
        // One unsafe item in a tiny file → very high density.
        let src = "pub unsafe fn a() {}";
        let cfg = Config {
            unsafe_density_warn: 5.0,
            ..Default::default()
        };
        let c = ctx_with(cfg, vec![krate_from_src("k", &[src])]);
        let findings = UnsafeSurface.run(&c);
        assert_eq!(findings[0].severity, Severity::Warn);
    }
}
