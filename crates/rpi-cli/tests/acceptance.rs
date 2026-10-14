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

// ---------------------------------------------------------------------------
// --baseline trend acceptance tests
// ---------------------------------------------------------------------------

/// Write `baseline_json` to a temp file named `label`, run the real `rpi`
/// binary with `--baseline <path>`, and return its stderr.
///
/// Each test passes a unique `label` so parallel test runs don't collide on
/// the same temp-file path.
fn run_with_baseline(label: &str, baseline_json: &serde_json::Value) -> String {
    use std::io::Write as _;
    let path = std::env::temp_dir().join(format!("rpi_acceptance_baseline_{label}.json"));
    let json = serde_json::to_string(baseline_json).unwrap();
    std::fs::File::create(&path)
        .unwrap()
        .write_all(json.as_bytes())
        .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rpi"))
        .args(["inspect"])
        .arg(fixture())
        .arg("--baseline")
        .arg(&path)
        .output()
        .expect("rpi binary must be runnable");

    let _ = std::fs::remove_file(&path);
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn baseline_regression_detected() {
    // Prior report had 0 findings; current fixture has several → regression.
    let prior = serde_json::json!({"metrics": {"finding_count": 0}});
    let stderr = run_with_baseline("regression", &prior);
    assert!(
        stderr.contains("regression"),
        "trend must report regression when findings increased: {stderr}"
    );
}

#[test]
fn baseline_improvement_detected() {
    // Prior report had 9999 findings; current has fewer → improvement.
    let prior = serde_json::json!({"metrics": {"finding_count": 9999}});
    let stderr = run_with_baseline("improvement", &prior);
    assert!(
        stderr.contains("improvement"),
        "trend must report improvement when findings decreased: {stderr}"
    );
}

#[test]
fn baseline_no_change_when_equal() {
    // Get the actual finding count from the fixture, then use it as baseline.
    let count = run().len() as u64;
    let prior = serde_json::json!({"metrics": {"finding_count": count}});
    let stderr = run_with_baseline("no_change", &prior);
    assert!(
        stderr.contains("no change"),
        "trend must report no change when finding count is equal: {stderr}"
    );
}
