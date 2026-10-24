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
