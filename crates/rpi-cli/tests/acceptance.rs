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
    let ctx = rpi_collect::collect(&fixture()).expect("collect fixture");
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
    let ctx = rpi_collect::collect(&fixture()).unwrap();
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
