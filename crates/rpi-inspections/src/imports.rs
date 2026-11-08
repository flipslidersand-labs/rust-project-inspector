//! Shared helpers: extract the crate roots a file references.
//!
//! Two granularities, because the callers ask different questions:
//! - [`file_use_roots`] — roots brought in by `use` (and attribute macros).
//!   The honest "how many external crates does this file import" signal for
//!   `coupling`.
//! - [`file_reference_roots`] — the broader set including every leading path
//!   segment, used by `dep-hygiene` to decide whether a declared dependency is
//!   referenced *anywhere* (a dep used without an explicit `use`, e.g. via a
//!   fully-qualified path or macro, must still count as used).
//!
//! Both are syn-level approximations: names reached only through macro
//! expansion may be missed.

use std::collections::BTreeSet;

use syn::visit::{self, Visit};

/// Path-position keywords that are never external crate roots.
const KEYWORDS: [&str; 4] = ["crate", "self", "super", "Self"];

/// Distinct crate roots imported via `use` or attribute macros. This is the
/// efferent-coupling signal for `coupling`.
pub fn file_use_roots(ast: &syn::File) -> BTreeSet<String> {
    let mut v = RootCollector {
        include_all_paths: false,
        roots: BTreeSet::new(),
    };
    v.visit_file(ast);
    v.roots
}

/// Distinct crate roots referenced anywhere — `use` trees, attribute macros,
/// and every leading path segment. Broader (and noisier) than
/// [`file_use_roots`]; used only for `dep-hygiene`'s membership test.
pub fn file_reference_roots(ast: &syn::File) -> BTreeSet<String> {
    let mut v = RootCollector {
        include_all_paths: true,
        roots: BTreeSet::new(),
    };
    v.visit_file(ast);
    v.roots
}

struct RootCollector {
    include_all_paths: bool,
    roots: BTreeSet<String>,
}

impl RootCollector {
    fn add(&mut self, ident: String) {
        if !KEYWORDS.contains(&ident.as_str()) {
            self.roots.insert(ident);
        }
    }

    /// Extract leading idents from a use tree in root position.
    fn collect_use(&mut self, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(p) => self.add(p.ident.to_string()),
            syn::UseTree::Name(n) => self.add(n.ident.to_string()),
            syn::UseTree::Rename(r) => self.add(r.ident.to_string()),
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    self.collect_use(item);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for RootCollector {
    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        self.collect_use(&i.tree);
        visit::visit_item_use(self, i);
    }

    fn visit_path(&mut self, p: &'ast syn::Path) {
        if self.include_all_paths {
            if let Some(first) = p.segments.first() {
                self.add(first.ident.to_string());
            }
        }
        visit::visit_path(self, p);
    }

    fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
        if let Some(first) = a.path().segments.first() {
            self.add(first.ident.to_string());
        }
        visit::visit_attribute(self, a);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_roots_are_imports_only() {
        let src = r#"
            use serde::Serialize;
            use std::collections::{HashMap, BTreeSet};
            fn f() { let x = local_fn(); helper::do_it(); }
        "#;
        let r = file_use_roots(&syn::parse_file(src).unwrap());
        assert!(r.contains("serde"));
        assert!(r.contains("std"));
        // Local call / non-imported path heads must NOT inflate coupling.
        assert!(!r.contains("local_fn"));
        assert!(!r.contains("helper"));
    }

    #[test]
    fn reference_roots_include_path_heads() {
        let src = "fn f() { anyhow::bail!(\"x\"); }";
        let r = file_reference_roots(&syn::parse_file(src).unwrap());
        assert!(r.contains("anyhow"));
    }

    #[test]
    fn excludes_intra_crate_keyword_roots() {
        let r = file_use_roots(&syn::parse_file("use crate::foo; use super::bar;").unwrap());
        assert!(r.is_empty(), "no external roots expected, got {r:?}");
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Expected sets come from Rust syntax semantics: the external crate root
    /// each `use` refers to. Columns: (source, use roots, reference roots).
    #[test]
    fn use_tree_syntax_variants() {
        let cases: &[(&str, &[&str], &[&str])] = &[
            ("use ::serde::X;", &["serde"], &["serde"]),
            ("use {a::X, b::Y};", &["a", "b"], &["a", "b"]),
            ("use a::{b::{c, d}};", &["a"], &["a"]),
            ("use a as b;", &["a"], &["a"]),
            ("use a::b as c;", &["a"], &["a"]),
            ("use {a as b, c::Y};", &["a", "c"], &["a", "c"]),
            ("use a;", &["a"], &["a"]),
            ("use {a, b};", &["a", "b"], &["a", "b"]),
            // `use a::*` is handled by the Path branch; only a root-position
            // glob reaches the Glob branch, which adds nothing.
            ("use a::*;", &["a"], &["a"]),
            ("use {*};", &[], &[]),
            ("use a::{b::*, c};", &["a"], &["a"]),
            ("pub use a::X;", &["a"], &["a"]),
            ("pub(crate) use a::X;", &["a"], &["a"]),
            ("use {crate::a, super::b, self::c};", &[], &[]),
            ("use {crate::a, d::Y};", &["d"], &["d"]),
            // Path heads are reference-only: they must not inflate use roots.
            (
                "fn f() { ::a::b(); c::d(); let _: e::T; }",
                &[],
                &["a", "c", "e"],
            ),
            ("use x::Y; fn f() { z::go(); }", &["x"], &["x", "z"]),
            // Keyword path heads are never roots, even in reference mode.
            ("fn f() { crate::a(); self::b(); super::c(); }", &[], &[]),
            ("fn f() { Self::new(); }", &[], &[]),
        ];
        for (src, want_use, want_ref) in cases {
            let ast = syn::parse_file(src).unwrap_or_else(|e| panic!("parse {src:?}: {e}"));
            assert_eq!(file_use_roots(&ast), set(want_use), "use roots: {src}");
            assert_eq!(
                file_reference_roots(&ast),
                set(want_ref),
                "reference roots: {src}"
            );
        }
    }

    /// 現状の挙動を固定: `extern crate foo;` は collector が扱わず、抽出結果は
    /// 空になる(意味的には foo は外部 crate なので抽出漏れ)。修正は #92 で追跡。
    #[test]
    fn extern_crate_current_behavior() {
        let ast = syn::parse_file("extern crate foo;").unwrap();
        let u = file_use_roots(&ast);
        let r = file_reference_roots(&ast);
        assert!(u.is_empty(), "use roots: {u:?}");
        assert!(r.is_empty(), "reference roots: {r:?}");
    }
}
