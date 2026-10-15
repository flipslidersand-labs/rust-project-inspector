//! End-to-end acceptance test over a committed multi-crate fixture workspace.
//!
//! Runs the real pipeline (collect → all inspections) and asserts the report
//! answers "which crate needs attention". CI-portable: depends only on the
//! in-repo fixture, never on sibling projects.

use std::path::PathBuf;

use rpi_core::{CrateData, Finding, Report, Severity, WorkspaceInfo};

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

// --- cyclic dependency tests (Context-level, cargo rejects manifest-level cycles) ---

/// Build a Context with two crates that mutually depend on each other.
fn cyclic_context() -> rpi_core::Context {
    let make = |name: &str, deps: &[&str]| CrateData {
        name: name.to_string(),
        manifest_path: PathBuf::from(format!("/w/{name}/Cargo.toml")),
        root_dir: PathBuf::from(format!("/w/{name}")),
        workspace_deps: deps.iter().map(|s| s.to_string()).collect(),
        external_deps: Vec::new(),
        files: Vec::new(),
    };
    rpi_core::Context {
        workspace: WorkspaceInfo {
            root: PathBuf::from("/w"),
            crates: vec!["alpha".to_string(), "beta".to_string()],
        },
        crates: vec![make("alpha", &["beta"]), make("beta", &["alpha"])],
        ..Default::default()
    }
}

#[test]
fn cyclic_context_produces_error_finding() {
    // cargo rejects circular deps at the manifest level, so we build the Context
    // synthetically to exercise the full inspect pipeline without a real workspace.
    let ctx = cyclic_context();
    let findings: Vec<Finding> = rpi_inspections::all()
        .iter()
        .flat_map(|i| i.run(&ctx))
        .collect();

    let cycle_errors: Vec<_> = findings
        .iter()
        .filter(|f| f.inspection == "workspace-graph" && f.severity == Severity::Error)
        .collect();

    assert_eq!(
        cycle_errors.len(),
        1,
        "exactly one circular-dep error expected"
    );
    assert!(
        cycle_errors[0].message.contains("alpha") && cycle_errors[0].message.contains("beta"),
        "error message should name both crates: {:?}",
        cycle_errors[0].message
    );
}

#[test]
fn cyclic_finding_is_present_in_json_report() {
    // Verify the full pipeline: cyclic context → inspect → Report → JSON
    // serialises without panicking and the finding survives the round-trip.
    let ctx = cyclic_context();
    let findings: Vec<Finding> = rpi_inspections::all()
        .iter()
        .flat_map(|i| i.run(&ctx))
        .collect();
    let report = Report::new(ctx.workspace, findings, "t".to_string());
    let json = serde_json::to_string_pretty(&report).expect("JSON serialisation must not fail");

    assert!(
        json.contains("workspace-graph"),
        "JSON must contain the workspace-graph finding"
    );
    assert!(
        json.contains("\"error\""),
        "JSON must contain severity=error for the cyclic finding"
    );
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
