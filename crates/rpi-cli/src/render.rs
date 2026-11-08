//! Report renderers.
//!
//! `text` answers the tool's core question — *which crate do I fix first?* — by
//! ranking crates on a severity-weighted risk score, then listing findings
//! grouped by severity. `json` is the stable machine format.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use rpi_core::{Report, Severity};

/// Severity weights for the per-crate risk score.
const W_ERROR: u64 = 100;
const W_WARN: u64 = 10;
const W_INFO: u64 = 1;

pub fn json(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// SARIF 2.1.0 for GitHub Code Scanning.
///
/// File paths are emitted relative to the workspace root so GitHub can anchor
/// results to the repository tree; crate-scoped findings without a file are
/// anchored to the workspace `Cargo.toml` (GitHub Code Scanning rejects results
/// that have no location).
pub fn sarif(report: &Report) -> Result<String> {
    use serde_json::json;

    // One rule per distinct inspection that produced a finding.
    let mut rule_ids: Vec<&str> = report.findings.iter().map(|f| f.inspection).collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();
    let rules: Vec<_> = rule_ids
        .iter()
        .map(|id| json!({ "id": id, "name": id }))
        .collect();

    let root = &report.workspace.root;
    let results: Vec<_> = report
        .findings
        .iter()
        .map(|f| {
            let mut result = json!({
                "ruleId": f.inspection,
                "level": sarif_level(f.severity),
                "message": { "text": f.message },
            });
            // Code Scanning requires at least one location; fall back to the
            // workspace manifest for findings without a file.
            let uri = match &f.location.file {
                Some(file) => match file.strip_prefix(root) {
                    Ok(rel) => path_to_uri(rel),
                    // Outside the workspace root: keep the path unchanged.
                    Err(_) => file.display().to_string(),
                },
                None => "Cargo.toml".to_string(),
            };
            let line = f.location.span.map(|(s, _)| s).unwrap_or(1).max(1);
            result["locations"] = json!([{
                "physicalLocation": {
                    "artifactLocation": { "uri": uri },
                    "region": { "startLine": line }
                }
            }]);
            result
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "rust-project-inspector",
                "informationUri": "https://github.com/flipslidersand/rust-project-inspector",
                "rules": rules,
            }},
            "results": results,
        }],
    });
    Ok(serde_json::to_string_pretty(&doc)?)
}

/// Compare the current report against a previously-saved JSON report and
/// describe the trend. `baseline` is the parsed prior report. Returns `Err` when
/// it lacks an integer `metrics.finding_count`: such a baseline must not be
/// read as "0 findings", which would report a bogus regression (#56).
pub fn trend(current: &Report, baseline: &serde_json::Value) -> Result<String, String> {
    let cur = current.metrics.finding_count as i64;
    let base = baseline
        .get("metrics")
        .and_then(|m| m.get("finding_count"))
        .and_then(|v| v.as_i64())
        .ok_or("baseline has no integer metrics.finding_count (not a rpi JSON report?)")?;
    let delta = cur - base;
    let (mut arrow, mut verdict) = match delta.cmp(&0) {
        std::cmp::Ordering::Greater => ("▲", "regression"),
        std::cmp::Ordering::Less => ("▼", "improvement"),
        std::cmp::Ordering::Equal => ("=", "no change"),
    };
    let (ce, cw, ci) = severity_counts(current);
    let mut line = format!("trend: findings {base} → {cur} ({delta:+}) {arrow} {verdict}");
    match baseline_severity_counts(baseline) {
        Some((be, bw, bi)) => {
            line.push_str(&format!(
                "\n  severity: error {be}→{ce}, warn {bw}→{cw}, info {bi}→{ci}"
            ));
            // Same total but a worse mix (more errors, or more warns at equal
            // errors) is still a regression (#56). A shrinking total with more
            // errors is a regression too (#99).
            if (delta == 0 && (ce, cw) > (be, bw)) || (delta < 0 && ce > be) {
                arrow = "▲";
                verdict = "regression (severity worsened)";
                line = format!(
                    "trend: findings {base} → {cur} ({delta:+}) {arrow} {verdict}{}",
                    line.split_once('\n')
                        .map(|(_, r)| format!("\n{r}"))
                        .unwrap_or_default()
                );
            }
        }
        None => line.push_str("\n  severity: not comparable (baseline has no findings[].severity)"),
    }
    Ok(line)
}

/// (error, warn, info) counts from a baseline's `findings[].severity`, or
/// `None` for an old-format baseline without them.
fn baseline_severity_counts(baseline: &serde_json::Value) -> Option<(usize, usize, usize)> {
    let findings = baseline.get("findings")?.as_array()?;
    let (mut e, mut w, mut i) = (0, 0, 0);
    for f in findings {
        match f.get("severity")?.as_str()? {
            "error" => e += 1,
            "warn" => w += 1,
            "info" => i += 1,
            _ => return None,
        }
    }
    Some((e, w, i))
}

/// Joins path components with '/' as required for a SARIF `artifactLocation.uri`,
/// regardless of the host OS separator (#90).
/// 相対パス専用。RootDir/Prefix を含むと '//' になるため、strip_prefix 成功後の相対パスにだけ使う。
fn path_to_uri(p: &Path) -> String {
    p.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => "error",
        Severity::Warn => "warning",
        Severity::Info => "note",
    }
}

pub fn text(report: &Report) -> String {
    let mut out = String::new();
    let m = &report.metrics;
    let (e, w, i) = severity_counts(report);

    push(&mut out, "rust-project-inspector");
    push(
        &mut out,
        &format!("  root:     {}", report.workspace.root.display()),
    );
    push(&mut out, &format!("  crates:   {}", m.crate_count));
    push(
        &mut out,
        &format!(
            "  findings: {}  ({e} error, {w} warn, {i} info)",
            m.finding_count
        ),
    );

    if report.findings.is_empty() {
        push(&mut out, "  (no findings)");
        return out;
    }

    render_ranking(&mut out, report);
    render_findings(&mut out, report);
    out
}

fn severity_counts(report: &Report) -> (usize, usize, usize) {
    let mut e = 0;
    let mut w = 0;
    let mut i = 0;
    for f in &report.findings {
        match f.severity {
            Severity::Error => e += 1,
            Severity::Warn => w += 1,
            Severity::Info => i += 1,
        }
    }
    (e, w, i)
}

/// Rank crates by severity-weighted risk. Findings with no crate scope
/// (workspace-wide) are grouped under `workspace`.
fn render_ranking(out: &mut String, report: &Report) {
    let mut scores: BTreeMap<&str, (u64, u32, u32, u32)> = BTreeMap::new();
    for f in &report.findings {
        let key = f.location.krate.as_deref().unwrap_or("workspace");
        let entry = scores.entry(key).or_default();
        match f.severity {
            Severity::Error => {
                entry.0 += W_ERROR;
                entry.1 += 1;
            }
            Severity::Warn => {
                entry.0 += W_WARN;
                entry.2 += 1;
            }
            Severity::Info => {
                entry.0 += W_INFO;
                entry.3 += 1;
            }
        }
    }

    let mut ranked: Vec<_> = scores.into_iter().collect();
    // Highest risk first; tie-break by name for stable output.
    ranked.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));

    push(out, "");
    push(out, "  crate risk (score = 100·err + 10·warn + 1·info):");
    push(out, "    score  err warn info  crate");
    for (name, (score, err, warn, info)) in ranked {
        push(
            out,
            &format!("    {score:>5}  {err:>3} {warn:>4} {info:>4}  {name}"),
        );
    }
}

fn render_findings(out: &mut String, report: &Report) {
    push(out, "");
    push(out, "  findings:");
    // Error → Warn → Info, stable within a severity (input order).
    for sev in [Severity::Error, Severity::Warn, Severity::Info] {
        for f in report.findings.iter().filter(|f| f.severity == sev) {
            let tag = match sev {
                Severity::Error => "error",
                Severity::Warn => "warn ",
                Severity::Info => "info ",
            };
            let scope = f.location.krate.as_deref().unwrap_or("workspace");
            push(
                out,
                &format!("    [{tag}] {} ({scope}): {}", f.inspection, f.message),
            );
        }
    }
}

fn push(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_core::{Finding, Location, Metrics, WorkspaceInfo};
    use std::path::PathBuf;

    fn finding(inspection: &'static str, sev: Severity, krate: &str) -> Finding {
        Finding {
            inspection,
            severity: sev,
            location: Location {
                krate: Some(krate.to_string()),
                ..Default::default()
            },
            message: "msg".into(),
            metric: None,
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            workspace: WorkspaceInfo::default(),
            metrics: Metrics {
                crate_count: 2,
                finding_count: findings.len(),
            },
            findings,
            generated_at: "t".into(),
        }
    }

    #[test]
    fn ranking_orders_by_weighted_risk() {
        let r = report(vec![
            finding("test-gap", Severity::Warn, "low"),
            finding("workspace-graph", Severity::Error, "high"),
        ]);
        let text = text(&r);
        let high = text.find("high").unwrap();
        let low = text.find("low").unwrap();
        // The error crate must be ranked above the warn crate.
        assert!(high < low, "high-risk crate should appear first:\n{text}");
    }

    #[test]
    fn empty_report_is_terse() {
        let text = text(&report(vec![]));
        assert!(text.contains("(no findings)"));
        assert!(!text.contains("crate risk"));
    }

    #[test]
    fn json_is_valid() {
        let s = json(&report(vec![finding("x", Severity::Info, "k")])).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["findings"][0]["inspection"], "x");
    }

    #[test]
    fn trend_detects_regression_and_improvement() {
        let cur = report(vec![
            finding("a", Severity::Warn, "k"),
            finding("b", Severity::Warn, "k"),
        ]);
        let base_more: serde_json::Value = serde_json::json!({"metrics":{"finding_count":5}});
        let base_less: serde_json::Value = serde_json::json!({"metrics":{"finding_count":0}});
        assert!(trend(&cur, &base_more).unwrap().contains("improvement"));
        assert!(trend(&cur, &base_less).unwrap().contains("regression"));
        assert!(trend(&cur, &base_less).unwrap().contains("(+2)"));
    }

    #[test]
    fn trend_flags_severity_worsening_at_equal_count() {
        let cur = report(vec![finding("a", Severity::Error, "k")]);
        let base: serde_json::Value = serde_json::json!({
            "metrics":{"finding_count":1},
            "findings":[{"severity":"warn"}]
        });
        let t = trend(&cur, &base).unwrap();
        assert!(t.contains("regression (severity worsened)"), "{t}");
        assert!(t.contains("error 0→1, warn 1→0"), "{t}");
    }

    #[test]
    fn trend_flags_more_errors_even_when_total_decreases() {
        let cur = report(vec![finding("a", Severity::Error, "k")]);
        let base: serde_json::Value = serde_json::json!({
            "metrics":{"finding_count":3},
            "findings":[{"severity":"warn"},{"severity":"warn"},{"severity":"info"}]
        });
        let t = trend(&cur, &base).unwrap();
        assert!(t.contains("regression (severity worsened)"), "{t}");
        assert!(!t.contains("improvement"), "{t}");
    }

    #[test]
    fn trend_equal_mix_is_no_change_and_old_format_is_not_comparable() {
        let cur = report(vec![finding("a", Severity::Warn, "k")]);
        let same: serde_json::Value = serde_json::json!({
            "metrics":{"finding_count":1},
            "findings":[{"severity":"warn"}]
        });
        assert!(trend(&cur, &same).unwrap().contains("no change"));
        let old: serde_json::Value = serde_json::json!({"metrics":{"finding_count":1}});
        assert!(trend(&cur, &old).unwrap().contains("not comparable"));
    }

    #[test]
    fn sarif_shape_and_level_mapping() {
        let r = report(vec![
            finding("workspace-graph", Severity::Error, "a"),
            finding("test-gap", Severity::Warn, "b"),
        ]);
        let v: serde_json::Value = serde_json::from_str(&sarif(&r).unwrap()).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["name"],
            "rust-project-inspector"
        );
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        // Two distinct inspections → two rules.
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn sarif_emits_relative_file_uri() {
        use rpi_core::WorkspaceInfo;
        use std::path::PathBuf;
        let f = Finding {
            inspection: "module-size",
            severity: Severity::Warn,
            location: Location {
                krate: Some("k".into()),
                file: Some(PathBuf::from("/repo/crates/k/src/big.rs")),
                span: None,
            },
            message: "big".into(),
            metric: None,
        };
        let r = Report {
            workspace: WorkspaceInfo {
                root: PathBuf::from("/repo"),
                crates: vec!["k".into()],
            },
            metrics: rpi_core::Metrics {
                crate_count: 1,
                finding_count: 1,
            },
            findings: vec![f],
            generated_at: "t".into(),
        };
        let v: serde_json::Value = serde_json::from_str(&sarif(&r).unwrap()).unwrap();
        let uri = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"];
        assert_eq!(uri, "crates/k/src/big.rs");
    }

    /// One finding with the given file/span under workspace root `/repo`.
    fn sarif_one(file: Option<&str>, span: Option<(usize, usize)>) -> serde_json::Value {
        use std::path::PathBuf;
        let mut f = finding("module-size", Severity::Warn, "k");
        f.location.file = file.map(PathBuf::from);
        f.location.span = span;
        let mut r = report(vec![f]);
        r.workspace.root = PathBuf::from("/repo");
        serde_json::from_str(&sarif(&r).unwrap()).unwrap()
    }

    #[test]
    fn sarif_start_line_is_one_based_and_taken_from_span() {
        let loc = |v: &serde_json::Value| v["runs"][0]["results"][0]["locations"][0].clone();
        let v = sarif_one(Some("/repo/a.rs"), Some((12, 15)));
        assert_eq!(loc(&v)["physicalLocation"]["region"]["startLine"], 12);
        // SARIF startLine must be >= 1; a 0 span start is clamped.
        let v = sarif_one(Some("/repo/a.rs"), Some((0, 0)));
        assert_eq!(loc(&v)["physicalLocation"]["region"]["startLine"], 1);
        let v = sarif_one(Some("/repo/a.rs"), None);
        assert_eq!(loc(&v)["physicalLocation"]["region"]["startLine"], 1);
    }

    #[test]
    fn sarif_empty_report_keeps_required_shape() {
        let v: serde_json::Value = serde_json::from_str(&sarif(&report(vec![])).unwrap()).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["results"], serde_json::json!([]));
        assert_eq!(runs[0]["tool"]["driver"]["rules"], serde_json::json!([]));
        assert_eq!(runs[0]["tool"]["driver"]["name"], "rust-project-inspector");
    }

    // OS 非依存: component 列から組み立てたパスを '/' で連結することを検証する。
    // (`Path::new("a\\b")` は Windows では 2 component だが Linux では 1 component
    // のため、ここでは検証しない。)
    #[test]
    fn path_to_uri_joins_components_with_slash() {
        let p = PathBuf::from_iter(["crates", "k", "a.rs"]);
        assert_eq!(path_to_uri(&p), "crates/k/a.rs");
        assert_eq!(path_to_uri(Path::new("a.rs")), "a.rs");
    }

    // `components()` drops a mid-path `.`, `display()` does not: pins the call site.
    #[test]
    fn sarif_uri_goes_through_path_to_uri() {
        let v = sarif_one(Some("/repo/crates/./k/a.rs"), None);
        let uri = v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(uri, "crates/k/a.rs");
    }

    #[test]
    fn sarif_nested_file_uri_is_relative() {
        let v = sarif_one(Some("/repo/crates/k/src/deep/mod.rs"), Some((3, 4)));
        let uri = v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(uri, "crates/k/src/deep/mod.rs");
    }

    /// Pins CURRENT behavior only (#71 (1)): a file outside the workspace root
    /// is emitted as the unchanged absolute path. Whether that is the intended
    /// spec is a human decision; change this test if the spec changes.
    /// Windows で `D:\other\x.rs` が来ると有効な URI にならない可能性。現状の Linux 前提の挙動を固定。
    #[test]
    fn sarif_uri_outside_root_is_absolute_current_behavior() {
        let v = sarif_one(Some("/elsewhere/x.rs"), None);
        let uri = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"];
        assert_eq!(uri, "/elsewhere/x.rs");
    }

    #[test]
    fn sarif_fileless_finding_falls_back_to_cargo_toml() {
        let r = report(vec![finding("pub-surface", Severity::Info, "k")]);
        let v: serde_json::Value = serde_json::from_str(&sarif(&r).unwrap()).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "Cargo.toml");
        assert_eq!(loc["region"]["startLine"], 1);
    }
}
