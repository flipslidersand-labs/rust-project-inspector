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
}
