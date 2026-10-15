//! End-to-end acceptance test over a committed multi-crate fixture workspace.
//!
//! Runs the real pipeline (collect → all inspections) and asserts the report
//! answers "which crate needs attention". CI-portable: depends only on the
//! in-repo fixture, never on sibling projects.

use std::path::PathBuf;

use rpi_core::{Finding, Severity};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/multi")
        .canonicalize()
        .unwrap()
}

fn run() -> Vec<Finding> {
    let ctx = rpi_collect::collect(&fixture(), Default::default()).expect("collect fixture");
    rpi_inspections::all()
        .iter()
        .flat_map(|i| i.run(&ctx))
        .collect()
}

fn has(findings: &[Finding], inspection: &str, krate: &str) -> bool {
    findings
        .iter()
        .any(|f| f.inspection == inspection && f.location.krate.as_deref() == Some(krate))
}

#[test]
fn collects_both_member_crates() {
    let ctx = rpi_collect::collect(&fixture(), Default::default()).unwrap();
    let mut names = ctx.workspace.crates.clone();
    names.sort();
    assert_eq!(names, vec!["fx_app".to_string(), "fx_lib".to_string()]);
}

#[test]
fn test_gap_flags_only_the_untested_crate() {
    let f = run();
    assert!(has(&f, "test-gap", "fx_app"), "fx_app has no tests");
    assert!(!has(&f, "test-gap", "fx_lib"), "fx_lib has tests");
}

#[test]
fn unsafe_surface_flags_fx_lib() {
    let f = run();
    assert!(has(&f, "unsafe-surface", "fx_lib"));
}

#[test]
fn no_circular_dependency() {
    let f = run();
    let cycles = f
        .iter()
        .filter(|x| x.inspection == "workspace-graph" && x.severity == Severity::Error)
        .count();
    assert_eq!(cycles, 0);
}

#[test]
fn rpi_toml_thresholds_are_honored() {
    // The fixture's rpi.toml lowers module_size_loc to 10, so files above that
    // are flagged; with the default (300) they would not be.
    let f = run();
    assert!(
        f.iter().any(|x| x.inspection == "module-size"),
        "low rpi.toml threshold should trigger module-size"
    );
}

// --- edge-case fixtures ---

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .canonicalize()
        .unwrap()
}

#[test]
fn empty_context_produces_no_findings() {
    // cargo metadata rejects a zero-member virtual workspace, so we test the
    // "empty crates list" invariant at the Context level instead of via collect().
    let ctx = rpi_core::Context::default();
    let findings: Vec<_> = rpi_inspections::all()
        .iter()
        .flat_map(|i| i.run(&ctx))
        .collect();
    assert!(
        findings.is_empty(),
        "empty context must produce zero findings across all inspections"
    );
}

#[test]
fn large_module_triggers_module_size_at_default_threshold() {
    // The large-module fixture has a single file with 310+ lines, which exceeds
    // the default module_size_loc = 300. No rpi.toml override is present.
    let ctx = rpi_collect::collect(&fixture_path("large-module"), Default::default())
        .expect("collect large-module workspace");
    let findings: Vec<_> = rpi_inspections::all()
        .iter()
        .flat_map(|i| i.run(&ctx))
        .collect();
    assert!(
        findings.iter().any(|f| f.inspection == "module-size"
            && f.location.krate.as_deref() == Some("large_module")),
        "file exceeding 300 LOC must trigger module-size with default config"
    );
}

#[test]
fn no_git_workspace_collect_succeeds_with_empty_churn() {
    // A workspace outside any git repository must collect successfully with an
    // empty churn map — churn-hotspot must degrade gracefully rather than panic.
    let tmp = std::env::temp_dir().join("rpi_no_git_fixture_23");
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).expect("create tmp src");
    std::fs::write(
        tmp.join("Cargo.toml"),
        "[package]\nname = \"no_git_test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write Cargo.toml");
    std::fs::write(src.join("lib.rs"), "pub fn hello() {}\n").expect("write lib.rs");

    let result = rpi_collect::collect(&tmp, Default::default());
    std::fs::remove_dir_all(&tmp).ok();

    let ctx = result.expect("collect must succeed outside git");
    assert!(
        ctx.churn.is_empty(),
        "churn must be empty when workspace has no git history"
    );
}
