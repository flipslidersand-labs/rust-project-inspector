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
        external_dep_packages: Default::default(),
        files: Vec::new(),
    };
    rpi_core::Context {
        workspace: WorkspaceInfo {
            root: PathBuf::from("/w"),
            crates: vec!["alpha".to_string(), "beta".to_string()],
            ..Default::default()
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

/// #56: a baseline that parses but lacks `metrics.finding_count` must not be
/// treated as "0 findings" (which would report a bogus regression). It warns
/// instead, and still exits 0 without `--fail-on`.
fn assert_unusable_baseline(name: &str) {
    let (ok, stderr) = run_with_baseline_file(name);
    assert!(ok, "rpi must exit 0 without --fail-on: {stderr}");
    assert!(
        !stderr.contains("regression") && !stderr.contains("trend:"),
        "no trend verdict may be derived from an unusable baseline: {stderr}"
    );
    assert!(
        stderr.contains("warn:") && stderr.contains("finding_count"),
        "a warning naming the missing key is expected: {stderr}"
    );
}

#[test]
fn baseline_without_metrics_warns_instead_of_regression() {
    assert_unusable_baseline("no_metrics.json");
}

#[test]
fn baseline_without_finding_count_warns_instead_of_regression() {
    assert_unusable_baseline("no_count.json");
}

#[test]
fn baseline_with_non_integer_finding_count_warns() {
    assert_unusable_baseline("str_count.json");
}

/// Run the real `rpi` binary against the `multi` fixture with a checked-in
/// baseline from `tests/fixtures/baseline/<name>`; returns `(exit ok, stderr)`.
/// `multi` currently yields 4 findings, all `warn`.
fn run_with_baseline_file(name: &str) -> (bool, String) {
    let path = fixture_path("baseline").join(name);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rpi"))
        .args(["inspect"])
        .arg(fixture())
        .arg("--baseline")
        .arg(path)
        .output()
        .expect("rpi binary must be runnable");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// #56: same finding count but a milder baseline mix is a regression.
#[test]
fn baseline_same_count_but_worse_severity_is_regression() {
    let (ok, stderr) = run_with_baseline_file("multi_milder_same_count.json");
    assert!(ok, "{stderr}");
    assert!(
        stderr.contains("regression (severity worsened)"),
        "{stderr}"
    );
    assert!(stderr.contains("warn 0→4"), "{stderr}");
}

#[test]
fn baseline_same_mix_is_no_change() {
    let (ok, stderr) = run_with_baseline_file("multi_same_mix.json");
    assert!(ok, "{stderr}");
    assert!(stderr.contains("= no change"), "{stderr}");
}

#[test]
fn baseline_old_format_reports_severity_not_comparable() {
    let (ok, stderr) = run_with_baseline_file("old_format_4.json");
    assert!(ok, "{stderr}");
    assert!(stderr.contains("severity: not comparable"), "{stderr}");
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

/// #62: `a --dev-dep--> b --normal--> a` is legal in Cargo (dev-dependencies are
/// not part of the build graph), so it must not be reported as a cycle.
#[test]
fn dev_dependency_cycle_is_not_reported_as_cycle() {
    let ctx = rpi_collect::collect(&fixture_path("dev-cycle"), Default::default())
        .expect("collect dev-cycle fixture");
    let a = ctx.crates.iter().find(|c| c.name == "dc_a").expect("dc_a");
    assert!(
        a.workspace_deps.is_empty(),
        "dev-dependency must not be a workspace edge: {:?}",
        a.workspace_deps
    );
    let findings: Vec<Finding> = rpi_inspections::all()
        .iter()
        .flat_map(|i| i.run(&ctx))
        .collect();
    assert!(
        !findings
            .iter()
            .any(|f| f.inspection == "workspace-graph" && f.severity == Severity::Error),
        "no cycle Error expected: {findings:?}"
    );
}

fn run_inspect(extra: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_rpi"))
        .arg("inspect")
        .arg(fixture())
        .args(extra)
        .output()
        .expect("rpi binary must be runnable")
}

/// #63: `--fail-on` の終了コード。fixture/multi は Warn を含み Error を含まない。
#[test]
fn fail_on_warn_exits_1_after_printing_report() {
    let out = run_inspect(&["--format", "json", "--fail-on", "warn"]);
    assert_eq!(out.status.code(), Some(1));
    // exit する前にレポートが出ている(CI でも結果が読める)。
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("report must be printed as JSON before exiting 1");
    assert!(report["findings"].as_array().is_some_and(|f| !f.is_empty()));
}

#[test]
fn fail_on_error_exits_0_when_only_warnings_exist() {
    let out = run_inspect(&["--fail-on", "error"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(!out.stdout.is_empty(), "report must still be printed");
}

#[test]
fn without_fail_on_exits_0_even_with_findings() {
    let out = run_inspect(&["--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["findings"].as_array().is_some_and(|f| !f.is_empty()));
}

#[test]
fn verbose_prints_per_inspection_timing_to_stderr() {
    let out = run_inspect(&["--verbose"]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    for i in rpi_inspections::all() {
        let line = stderr
            .lines()
            .find(|l| l.starts_with("[rpi] ") && l.contains(i.name()))
            .unwrap_or_else(|| panic!("no timing line for {}: {stderr}", i.name()));
        assert!(line.ends_with("ms"), "timing line must end in ms: {line}");
    }
}

/// #25: collect (cargo metadata・パース・git log) の時間も出す。無いと
/// タイムアウト原因が inspection 側にあるように見える。
#[test]
fn verbose_prints_collect_timing_first() {
    let out = run_inspect(&["--verbose"]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[rpi] ")).collect();
    let first = lines.first().expect("no timing lines");
    assert!(
        first.starts_with("[rpi] collect") && first.ends_with("ms"),
        "collect timing must come first: {first}"
    );
}

#[test]
fn without_verbose_no_timing_and_stdout_unchanged() {
    let plain = run_inspect(&[]);
    let verbose = run_inspect(&["--verbose"]);
    assert!(!String::from_utf8_lossy(&plain.stderr).contains("[rpi]"));
    assert_eq!(plain.stdout, verbose.stdout, "stdout must not change");
    let json_verbose = run_inspect(&["--format", "json", "--verbose"]);
    assert!(!String::from_utf8_lossy(&json_verbose.stdout).contains("[rpi]"));
    serde_json::from_slice::<serde_json::Value>(&json_verbose.stdout)
        .expect("stdout must stay valid JSON with --verbose");
}

fn rpi_inspect(extra: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_rpi"))
        .arg("inspect")
        .arg(fixture())
        .args(extra)
        .output()
        .expect("rpi binary must be runnable")
}

#[test]
fn summary_flag_appends_summary_to_text_and_default_is_unchanged() {
    let plain = String::from_utf8(rpi_inspect(&[]).stdout).unwrap();
    let with = String::from_utf8(rpi_inspect(&["--summary"]).stdout).unwrap();
    assert!(!plain.contains("=== Summary ==="));
    assert!(with.starts_with(&plain), "summary must only append");
    assert!(with.contains("=== Summary ==="));
    assert!(with.contains("Total findings : "));
    assert!(with.contains("Top inspections:"));
    assert!(with.contains("Top crates at risk:"));
}

#[test]
fn summary_flag_embeds_key_in_json_and_keeps_stdout_valid() {
    let plain: serde_json::Value =
        serde_json::from_slice(&rpi_inspect(&["--format", "json"]).stdout).unwrap();
    assert!(plain.get("summary").is_none());
    let v: serde_json::Value =
        serde_json::from_slice(&rpi_inspect(&["--format", "json", "--summary"]).stdout).unwrap();
    let s = &v["summary"];
    let total = v["findings"].as_array().unwrap().len() as u64;
    assert_eq!(s["total"].as_u64().unwrap(), total);
    assert!(s["error"].is_u64() && s["warn"].is_u64() && s["info"].is_u64());
    assert!(s["top_inspections"].is_array() && s["top_crates"].is_array());
}

#[test]
fn summary_flag_goes_to_stderr_for_sarif() {
    let out = rpi_inspect(&["--format", "sarif", "--summary"]);
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("sarif stdout stays JSON");
    assert!(String::from_utf8_lossy(&out.stderr).contains("=== Summary ==="));
}

/// Run the real binary and return its exit code.
fn exit_code(args: &[&std::ffi::OsStr]) -> Option<i32> {
    std::process::Command::new(env!("CARGO_BIN_EXE_rpi"))
        .arg("inspect")
        .args(args)
        .output()
        .expect("rpi binary must be runnable")
        .status
        .code()
}

#[test]
fn exit_code_is_0_on_success() {
    assert_eq!(exit_code(&[fixture().as_os_str()]), Some(0));
}

#[test]
fn exit_code_is_1_when_fail_on_threshold_is_exceeded() {
    let f = fixture();
    let args = [f.as_os_str(), "--fail-on".as_ref(), "warn".as_ref()];
    assert_eq!(exit_code(&args), Some(1));
}

#[test]
fn exit_code_is_2_when_collection_fails() {
    let missing = std::env::temp_dir().join(format!("rpi_missing_{}", std::process::id()));
    assert!(!missing.exists());
    assert_eq!(exit_code(&[missing.as_os_str()]), Some(2));
    // Also with --fail-on: a collection failure must not look like a threshold hit.
    let args = [missing.as_os_str(), "--fail-on".as_ref(), "warn".as_ref()];
    assert_eq!(exit_code(&args), Some(2));
}
