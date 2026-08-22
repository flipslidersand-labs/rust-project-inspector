//! `complexity` — per-function cyclomatic complexity (AST approximation).
//!
//! Complexity = 1 + decision points, where a decision point is any `if`,
//! `while`, `for`, `loop`, `match` arm, `&&`/`||`, or `?`. This is a syn-level
//! approximation: nested functions contribute to their enclosing function's
//! count as well as their own.

use rpi_core::{Context, Finding, Inspection, Location, Severity};
use syn::visit::{self, Visit};

pub struct Complexity;

impl Complexity {
    pub const NAME: &'static str = "complexity";
}

impl Inspection for Complexity {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let warn = ctx.config.complexity_warn;
        let mut findings = Vec::new();
        for krate in &ctx.crates {
            for file in &krate.files {
                for (name, score) in function_complexities(&file.ast) {
                    if score > warn {
                        findings.push(Finding {
                            inspection: Self::NAME,
                            severity: Severity::Warn,
                            location: Location {
                                krate: Some(krate.name.clone()),
                                file: Some(file.path.clone()),
                                ..Default::default()
                            },
                            message: format!(
                                "fn `{name}` has cyclomatic complexity {score} (> {warn})"
                            ),
                            metric: Some(score as f64),
                        });
                    }
                }
            }
        }
        findings
    }
}

/// Total cyclomatic complexity of a file (sum over its functions). Used by
/// `churn-hotspot`.
pub(crate) fn file_complexity(ast: &syn::File) -> usize {
    function_complexities(ast).iter().map(|(_, c)| c).sum()
}

/// `(function name, cyclomatic complexity)` for every function in a file.
fn function_complexities(ast: &syn::File) -> Vec<(String, usize)> {
    let mut v = FnCollector::default();
    v.visit_file(ast);
    v.out
}

#[derive(Default)]
struct FnCollector {
    out: Vec<(String, usize)>,
}

impl FnCollector {
    fn record(&mut self, name: String, block: &syn::Block) {
        let mut d = DecisionCounter::default();
        d.visit_block(block);
        self.out.push((name, 1 + d.points));
    }
}

impl<'ast> Visit<'ast> for FnCollector {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.record(f.sig.ident.to_string(), &f.block);
        visit::visit_item_fn(self, f);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.record(f.sig.ident.to_string(), &f.block);
        visit::visit_impl_item_fn(self, f);
    }

    fn visit_trait_item_fn(&mut self, f: &'ast syn::TraitItemFn) {
        if let Some(block) = &f.default {
            self.record(f.sig.ident.to_string(), block);
        }
        visit::visit_trait_item_fn(self, f);
    }
}

/// Counts decision points within a block.
#[derive(Default)]
struct DecisionCounter {
    points: usize,
}

impl<'ast> Visit<'ast> for DecisionCounter {
    fn visit_expr_if(&mut self, e: &'ast syn::ExprIf) {
        self.points += 1;
        visit::visit_expr_if(self, e);
    }
    fn visit_expr_while(&mut self, e: &'ast syn::ExprWhile) {
        self.points += 1;
        visit::visit_expr_while(self, e);
    }
    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        self.points += 1;
        visit::visit_expr_for_loop(self, e);
    }
    fn visit_expr_loop(&mut self, e: &'ast syn::ExprLoop) {
        self.points += 1;
        visit::visit_expr_loop(self, e);
    }
    fn visit_arm(&mut self, a: &'ast syn::Arm) {
        self.points += 1;
        visit::visit_arm(self, a);
    }
    fn visit_expr_try(&mut self, e: &'ast syn::ExprTry) {
        self.points += 1;
        visit::visit_expr_try(self, e);
    }
    fn visit_expr_binary(&mut self, e: &'ast syn::ExprBinary) {
        if matches!(e.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) {
            self.points += 1;
        }
        visit::visit_expr_binary(self, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_core::{Config, CrateData, SourceFile};
    use std::path::PathBuf;

    fn file(src: &str) -> syn::File {
        syn::parse_file(src).unwrap()
    }

    #[test]
    fn simple_fn_is_complexity_one() {
        let c = function_complexities(&file("fn f() { let x = 1; }"));
        assert_eq!(c, vec![("f".to_string(), 1)]);
    }

    #[test]
    fn counts_decision_points() {
        let src = r#"
            fn f(a: bool, b: bool) -> i32 {
                if a && b { return 1; }
                for _ in 0..3 { }
                match a { true => 1, false => 2 }
            }
        "#;
        // 1 base + if(1) + &&(1) + for(1) + 2 arms(2) = 6
        let c = function_complexities(&file(src));
        assert_eq!(c[0].1, 6);
    }

    #[test]
    fn flags_over_threshold_only() {
        let complex = "fn big(a:bool){ if a {} if a {} if a {} }"; // 1+3=4
        let krate = CrateData {
            name: "k".into(),
            manifest_path: PathBuf::from("/w/k/Cargo.toml"),
            root_dir: PathBuf::from("/w/k"),
            workspace_deps: Vec::new(),
            external_deps: Vec::new(),
            files: vec![SourceFile {
                path: PathBuf::from("/w/k/src/lib.rs"),
                loc: 1,
                ast: file(complex),
            }],
        };
        let ctx = Context {
            crates: vec![krate],
            config: Config {
                complexity_warn: 3,
                ..Default::default()
            },
            ..Default::default()
        };
        let f = Complexity.run(&ctx);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("`big`"));
    }
}
