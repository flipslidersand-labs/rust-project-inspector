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

/// Write `baseline_json` to a temp file, run the real `rpi` binary with
/// `--baseline <path>`, and return `(exit success, stderr)`.
///
/// `label` only keeps parallel tests from colliding on the same temp path. It
/// ends up in the file name, which is echoed to stderr when the baseline cannot
/// be read, so callers must pass a neutral label and must never assert on a
/// bare word that could also appear in that path.
fn run_with_baseline(label: &str, baseline_json: &serde_json::Value) -> (bool, String) {
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
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run with a baseline of `base` findings and assert that the binary exited 0,
/// read the baseline, and printed exactly the expected trend line.
fn assert_trend(label: &str, base: i64, arrow: &str, verdict: &str) {
    let cur = run().len() as i64;
    let delta = cur - base;
    let prior = serde_json::json!({"metrics": {"finding_count": base}});
    let (ok, stderr) = run_with_baseline(label, &prior);
    assert!(ok, "rpi must exit 0 without --fail-on: {stderr}");
    assert!(
        !stderr.contains("could not read baseline"),
        "baseline must be readable: {stderr}"
    );
    let want = format!("trend: findings {base} → {cur} ({delta:+}) {arrow} {verdict}");
    assert!(
        stderr.lines().any(|l| l == want),
        "expected trend line `{want}` in stderr: {stderr}"
    );
}

#[test]
fn baseline_regression_detected() {
    // Prior report had 0 findings; current fixture has several → regression.
    assert_trend("case1", 0, "▲", "regression");
}

#[test]
fn baseline_improvement_detected() {
    // Prior report had 9999 findings; current has fewer → improvement.
    assert_trend("case2", 9999, "▼", "improvement");
}

#[test]
fn baseline_no_change_when_equal() {
    // Use the fixture's actual finding count as the baseline.
    let count = run().len() as i64;
    assert_trend("case3", count, "=", "no change");
}
