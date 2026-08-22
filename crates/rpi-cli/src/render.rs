//! Report renderers.
//!
//! `text` answers the tool's core question — *which crate do I fix first?* — by
//! ranking crates on a severity-weighted risk score, then listing findings
//! grouped by severity. `json` is the stable machine format.

use std::collections::BTreeMap;

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
/// reported without a physical location (GitHub shows them at the repo root).
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
            if let Some(file) = &f.location.file {
                let uri = file
                    .strip_prefix(root)
                    .unwrap_or(file)
                    .display()
                    .to_string();
                let line = f.location.span.map(|(s, _)| s).unwrap_or(1).max(1);
                result["locations"] = json!([{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": line }
                    }
                }]);
            }
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
}
