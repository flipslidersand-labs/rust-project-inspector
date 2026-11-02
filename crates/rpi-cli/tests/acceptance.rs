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

// ---------------------------------------------------------------------------
// --baseline trend acceptance tests
// ---------------------------------------------------------------------------

/// Temp baseline file that is removed on drop, so it is cleaned up even when an
/// assertion (or the spawn) panics.
struct TempBaseline(PathBuf);

impl Drop for TempBaseline {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Write `baseline_json` to a temp file, run the real `rpi` binary with
/// `--baseline <path>`, and return `(exit success, stderr)`.
///
/// The path is `<tmp>/rpi_acceptance_baseline_<pid>_<label>.json`: the process
/// id keeps concurrent `cargo test` processes (or CI jobs sharing `TMPDIR`)
/// apart, and `label` keeps the tests within one process apart. The path is
/// echoed to stderr when the baseline cannot be read, so callers must pass a
/// neutral label and must never assert on a bare word (or number) that could
/// also appear in that path.
fn run_with_baseline(label: &str, baseline_json: &serde_json::Value) -> (bool, String) {
    use std::io::Write as _;
    let tmp = TempBaseline(std::env::temp_dir().join(format!(
        "rpi_acceptance_baseline_{}_{label}.json",
        std::process::id()
    )));
    // Guard first: it removes the file even if writing it fails part-way.
    let json = serde_json::to_string(baseline_json).unwrap();
    std::fs::File::create(&tmp.0)
        .unwrap()
        .write_all(json.as_bytes())
        .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rpi"))
        .args(["inspect"])
        .arg(fixture())
        .arg("--baseline")
        .arg(&tmp.0)
        .output()
        .expect("rpi binary must be runnable");

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

// --- edge-case fixtures ---

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .canonicalize()
        .unwrap()
}

#[test]
fn zero_member_workspace_is_rejected_by_collect() {
    // `collect()` runs a full `cargo metadata` (no `--no-deps`), which rejects a
    // virtual workspace with no members. (`cargo metadata --no-deps` would
    // succeed with `packages: []`, but that is not what `collect()` uses.)
    // Verified with cargo 1.94.1; the error must surface instead of panicking.
    let Err(err) = rpi_collect::collect(&fixture_path("empty"), Default::default()) else {
        panic!("zero-member workspace must be rejected");
    };
    let chain = format!("{err:#}");
    assert!(
        chain.contains("failed to run `cargo metadata`"),
        "error should come from the cargo metadata step: {chain}"
    );
}

#[test]
fn empty_context_produces_no_findings() {
    // Since collect() cannot produce an empty crate list (see above), exercise
    // the "empty crates list" invariant of the inspections at the Context level.
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
    // Use a private temp dir (unique per process) and ask git itself whether it
    // is inside a repository; if TMPDIR sits under a git work tree, skip
    // rather than fail, since the precondition cannot be met.
    let tmp = std::env::temp_dir().join(format!("rpi_no_git_fixture_23_{}", std::process::id()));
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).expect("create tmp src");
    let _cleanup = RemoveOnDrop(tmp.clone());

    let inside_git = std::process::Command::new("git")
        .arg("-C")
        .arg(&tmp)
        .args(["rev-parse", "--git-dir"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if inside_git {
        eprintln!("skipping: {} is inside a git repository", tmp.display());
        return;
    }

    std::fs::write(
        tmp.join("Cargo.toml"),
        "[package]\nname = \"no_git_test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write Cargo.toml");
    std::fs::write(src.join("lib.rs"), "pub fn hello() {}\n").expect("write lib.rs");

    let ctx =
        rpi_collect::collect(&tmp, Default::default()).expect("collect must succeed outside git");
    assert!(
        ctx.churn.is_empty(),
        "churn must be empty when workspace has no git history"
    );
}

/// Removes the directory on drop so cleanup also happens when an assert fails.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}
