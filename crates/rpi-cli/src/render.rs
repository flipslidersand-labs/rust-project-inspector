//! Report renderers.
//!
//! `text` answers the tool's core question — *which crate do I fix first?* — by
//! ranking crates on a severity-weighted risk score, then listing findings
//! grouped by severity. `json` is the stable machine format.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use rpi_core::{is_hostile_char, sanitize_for_terminal, Report, Severity};

/// Severity weights for the per-crate risk score.
const W_ERROR: u64 = 100;
const W_WARN: u64 = 10;
const W_INFO: u64 = 1;

pub fn json(report: &Report) -> Result<String> {
    Ok(escape_json_hostile(serde_json::to_string_pretty(report)?))
}

const SUMMARY_TOP_N: usize = 3;

/// Aggregated counts behind `--summary` (shared by text and JSON output).
struct Summary {
    total: usize,
    counts: (usize, usize, usize),
    /// (inspection, findings), most hits first.
    inspections: Vec<(&'static str, usize)>,
    /// (crate, score, errors, warns), highest risk first.
    crates: Vec<(String, u64, u32, u32)>,
}

fn summarize(report: &Report) -> Summary {
    let mut by_insp: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_crate: BTreeMap<String, (u64, u32, u32)> = BTreeMap::new();
    for f in &report.findings {
        *by_insp.entry(f.inspection).or_default() += 1;
        let c = by_crate
            .entry(
                f.location
                    .krate
                    .clone()
                    .unwrap_or_else(|| "workspace".into()),
            )
            .or_default();
        match f.severity {
            Severity::Error => {
                c.0 += W_ERROR;
                c.1 += 1;
            }
            Severity::Warn => {
                c.0 += W_WARN;
                c.2 += 1;
            }
            Severity::Info => c.0 += W_INFO,
        }
    }
    let mut inspections: Vec<_> = by_insp.into_iter().collect();
    inspections.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    inspections.truncate(SUMMARY_TOP_N);
    let mut crates: Vec<_> = by_crate
        .into_iter()
        .map(|(n, (s, e, w))| (n, s, e, w))
        .collect();
    crates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    crates.truncate(SUMMARY_TOP_N);
    Summary {
        total: report.findings.len(),
        counts: severity_counts(report),
        inspections,
        crates,
    }
}

/// Aggregate summary block for `--summary` (text form).
pub fn summary(report: &Report) -> String {
    let s = summarize(report);
    let (e, w, i) = s.counts;
    let mut out = String::new();
    push(&mut out, "=== Summary ===");
    push(&mut out, &format!("Total findings : {}", s.total));
    push(&mut out, &format!("  error        : {e:>2}"));
    push(&mut out, &format!("  warn         : {w:>2}"));
    push(&mut out, &format!("  info         : {i:>2}"));
    push(&mut out, "");
    push(&mut out, "Top inspections:");
    for (name, n) in &s.inspections {
        push(
            &mut out,
            &format!("  {} {n:>4} findings", sanitize_for_terminal(name)),
        );
    }
    push(&mut out, "");
    push(&mut out, "Top crates at risk:");
    for (name, score, err, warn) in &s.crates {
        push(
            &mut out,
            &format!(
                "  {}  score={score}  (error={err}, warn={warn})",
                sanitize_for_terminal(name)
            ),
        );
    }
    out
}

/// JSON report with a top-level `summary` object (`--summary --format json`).
pub fn json_with_summary(report: &Report) -> Result<String> {
    let s = summarize(report);
    let mut v = serde_json::to_value(report)?;
    v["summary"] = serde_json::json!({
        "total": s.total,
        "error": s.counts.0,
        "warn": s.counts.1,
        "info": s.counts.2,
        "top_inspections": s.inspections.iter()
            .map(|(n, c)| serde_json::json!({"inspection": n, "count": c})).collect::<Vec<_>>(),
        "top_crates": s.crates.iter()
            .map(|(n, sc, e, w)| serde_json::json!({"crate": n, "score": sc, "error": e, "warn": w}))
            .collect::<Vec<_>>(),
    });
    Ok(escape_json_hostile(serde_json::to_string_pretty(&v)?))
}

/// SARIF 2.1.0 for GitHub Code Scanning.
///
/// File paths are emitted relative to the workspace root so GitHub can anchor
/// results to the repository tree; crate-scoped findings without a file are
/// anchored to the workspace `Cargo.toml` (GitHub Code Scanning rejects results
/// that have no location).
#[cfg(test)]
pub fn sarif(report: &Report) -> Result<String> {
    sarif_in_repo(report, None)
}

/// [`sarif`] with URIs anchored at the git repository root `git_root` (#157):
/// Code Scanning resolves relative URIs against the repo root, so a workspace in
/// a subdirectory needs its path prefix. `None`, or a root that is not an
/// ancestor of the workspace, keeps workspace-root-relative URIs.
pub fn sarif_in_repo(report: &Report, git_root: Option<&Path>) -> Result<String> {
    use serde_json::json;

    let root = &report.workspace.root;
    let prefix: PathBuf = git_root
        .and_then(|g| {
            root.strip_prefix(g)
                .map(Path::to_path_buf)
                .ok()
                .or_else(|| {
                    // git resolves symlinks; the workspace root may not.
                    root.canonicalize()
                        .ok()?
                        .strip_prefix(g)
                        .map(Path::to_path_buf)
                        .ok()
                })
        })
        .unwrap_or_default();

    // One rule per distinct inspection that produced a finding.
    let mut rule_ids: Vec<&str> = report.findings.iter().map(|f| f.inspection).collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();
    let rules: Vec<_> = rule_ids
        .iter()
        .map(|id| json!({ "id": id, "name": id }))
        .collect();

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
                    Ok(rel) => path_to_uri(&prefix.join(rel)),
                    // Outside the workspace root: keep the path unchanged.
                    Err(_) => file.display().to_string(),
                },
                None => {
                    // Crate-scoped: that crate's manifest, else the workspace's.
                    let manifest = f
                        .location
                        .krate
                        .as_ref()
                        .and_then(|k| report.workspace.crate_manifests.get(k))
                        .and_then(|m| m.strip_prefix(root).ok());
                    path_to_uri(&prefix.join(manifest.unwrap_or(Path::new("Cargo.toml"))))
                }
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
    Ok(escape_json_hostile(serde_json::to_string_pretty(&doc)?))
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
            // errors) is still a regression (#56), also when the total shrinks (#99).
            if delta <= 0 && (ce, cw) > (be, bw) {
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
        .map(|c| percent_encode(&c.as_os_str().to_string_lossy()))
        .collect::<Vec<_>>()
        .join("/")
}

/// RFC 3986 percent-encoding: everything except unreserved `A-Za-z0-9-._~` becomes `%XX` per UTF-8 byte.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
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
        &format!(
            "  root:     {}",
            sanitize_for_terminal(&report.workspace.root.display().to_string())
        ),
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
            &format!(
                "    {score:>5}  {err:>3} {warn:>4} {info:>4}  {}",
                sanitize_for_terminal(name)
            ),
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
                &format!(
                    "    [{tag}] {} ({}): {}",
                    sanitize_for_terminal(f.inspection),
                    sanitize_for_terminal(scope),
                    sanitize_for_terminal(&f.message)
                ),
            );
        }
    }
}

/// serde_json escapes only C0 controls. Rewrite DEL, C1 controls and bidi/zero-width
/// characters as `\uXXXX`. Outside string literals the output is ASCII, so this
/// only touches string contents and keeps the document valid and equivalent.
fn escape_json_hostile(json: String) -> String {
    use std::fmt::Write;
    if !json.chars().any(|c| c >= '\u{7f}' && is_hostile_char(c)) {
        return json;
    }
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c >= '\u{7f}' && is_hostile_char(c) {
            let _ = write!(out, "\\u{:04x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
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
    fn text_escapes_control_chars_in_external_strings() {
        let mut f = finding("x", Severity::Warn, "k\u{1b}[31mcrate");
        f.message = "bad \u{1b}]0;title\u{7}\u{9b}x\nfake line".into();
        let mut r = report(vec![f]);
        r.workspace.root = PathBuf::from("/tmp/\u{1b}[2Jroot");
        let out = text(&r);
        assert!(!out.contains('\u{1b}'), "raw ESC leaked: {out:?}");
        assert!(!out.contains('\u{7}') && !out.contains('\u{9b}'));
        assert!(out.contains("\\u{1b}"));
        // Only the renderer's own line breaks remain.
        assert!(!out.contains("bad \u{1b}") && !out.contains("\nfake line"));
    }

    #[test]
    fn json_and_sarif_escape_c1_and_bidi() {
        let mut f = finding("x", Severity::Warn, "k\u{85}a\u{202e}b\u{7f}");
        f.message = "m\u{85}a\u{202e}b\u{7f}".into();
        let r = report(vec![f]);
        for out in [json(&r).unwrap(), sarif(&r).unwrap()] {
            assert!(
                !out.contains('\u{85}') && !out.contains('\u{202e}') && !out.contains('\u{7f}')
            );
            assert!(out.contains("\\u0085") && out.contains("\\u202e"), "{out}");
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert!(v.is_object());
        }
        let v: serde_json::Value = serde_json::from_str(&json(&r).unwrap()).unwrap();
        assert!(v.to_string().contains('\u{85}'), "value must round-trip");
    }

    #[test]
    fn sanitize_keeps_normal_text() {
        let s = "日本語 パス/with space/😀.rs";
        assert_eq!(sanitize_for_terminal(s), s);
        assert_eq!(sanitize_for_terminal("a\tb\u{7f}"), "a\\u{9}b\\u{7f}");
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
    fn trend_flags_more_warns_at_equal_errors_even_when_total_decreases() {
        let cur = report(vec![finding("a", Severity::Warn, "k")]);
        let base: serde_json::Value = serde_json::json!({
            "metrics":{"finding_count":3},
            "findings":[{"severity":"info"},{"severity":"info"},{"severity":"info"}]
        });
        let t = trend(&cur, &base).unwrap();
        assert!(t.contains("regression (severity worsened)"), "{t}");
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
                ..Default::default()
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

    #[test]
    fn path_to_uri_percent_encodes_components() {
        let p = PathBuf::from_iter(["a b", "c#d.rs"]);
        assert_eq!(path_to_uri(&p), "a%20b/c%23d.rs");
        assert_eq!(path_to_uri(Path::new("50%/q?.rs")), "50%25/q%3F.rs");
        assert_eq!(
            path_to_uri(Path::new("日本/é.rs")),
            "%E6%97%A5%E6%9C%AC/%C3%A9.rs"
        );
        assert_eq!(path_to_uri(Path::new("A-z_0.~/x.rs")), "A-z_0.~/x.rs");
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
    fn sarif_crate_finding_points_at_crate_manifest() {
        use std::path::PathBuf;
        let a = finding("workspace-graph", Severity::Warn, "a");
        let b = finding("workspace-graph", Severity::Warn, "b");
        let none = finding("workspace-graph", Severity::Warn, "unknown");
        let mut r = report(vec![a, b, none]);
        r.workspace.root = PathBuf::from("/repo/rust");
        r.workspace.crate_manifests = [
            ("a".to_string(), PathBuf::from("/repo/rust/a/Cargo.toml")),
            ("b".to_string(), PathBuf::from("/repo/rust/b/Cargo.toml")),
        ]
        .into_iter()
        .collect();
        let uris = |g: Option<&Path>| -> Vec<String> {
            let v: serde_json::Value =
                serde_json::from_str(&sarif_in_repo(&r, g).unwrap()).unwrap();
            (0..3)
                .map(|i| {
                    v["runs"][0]["results"][i]["locations"][0]["physicalLocation"]
                        ["artifactLocation"]["uri"]
                        .as_str()
                        .unwrap()
                        .to_string()
                })
                .collect()
        };
        assert_eq!(
            uris(Some(Path::new("/repo"))),
            ["rust/a/Cargo.toml", "rust/b/Cargo.toml", "rust/Cargo.toml"]
        );
        assert_eq!(uris(None), ["a/Cargo.toml", "b/Cargo.toml", "Cargo.toml"]);
    }

    #[test]
    fn sarif_uri_is_git_root_relative_for_subdir_workspace() {
        use std::path::PathBuf;
        let mut f = finding("module-size", Severity::Warn, "a");
        f.location.file = Some(PathBuf::from("/repo/rust/a/src/lib.rs"));
        let g = finding("pub-surface", Severity::Info, "a");
        let mut r = report(vec![f, g]);
        r.workspace.root = PathBuf::from("/repo/rust");
        let v: serde_json::Value =
            serde_json::from_str(&sarif_in_repo(&r, Some(Path::new("/repo"))).unwrap()).unwrap();
        let uri = |i: usize| {
            v["runs"][0]["results"][i]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"]
                .clone()
        };
        assert_eq!(uri(0), "rust/a/src/lib.rs");
        assert_eq!(uri(1), "rust/Cargo.toml");
        // No git root, or an unrelated one: workspace-root-relative as before.
        for g in [None, Some(Path::new("/other"))] {
            let v: serde_json::Value =
                serde_json::from_str(&sarif_in_repo(&r, g).unwrap()).unwrap();
            assert_eq!(
                v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                    ["uri"],
                "a/src/lib.rs"
            );
        }
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
