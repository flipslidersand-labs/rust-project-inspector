//! Core data model and traits for rust-project-inspector.
//!
//! This crate is intentionally dependency-light so that `Inspection`
//! implementations and renderers can share one stable vocabulary.
//! The heavy lifting (cargo metadata, AST parsing) lives in `rpi-collect`.

use std::path::PathBuf;

use serde::Serialize;

/// Severity of a [`Finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

/// Where a [`Finding`] applies. Any level may be omitted when not relevant
/// (e.g. a workspace-wide finding has no `file`/`span`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Location {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub krate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// 1-based `(start_line, end_line)` when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<(usize, usize)>,
}

/// A single structural observation produced by an [`Inspection`].
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Name of the producing inspection, e.g. `"module-size"`.
    pub inspection: &'static str,
    pub severity: Severity,
    pub location: Location,
    pub message: String,
    /// The measured value that tripped a threshold, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric: Option<f64>,
}

/// Coarse workspace facts, filled by `rpi-collect`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WorkspaceInfo {
    pub root: PathBuf,
    pub crates: Vec<String>,
}

/// Aggregate metrics rolled up across all findings.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Metrics {
    pub crate_count: usize,
    pub finding_count: usize,
}

/// The full result of an inspection run — the unit every renderer consumes.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub workspace: WorkspaceInfo,
    pub findings: Vec<Finding>,
    pub metrics: Metrics,
    /// Injected by the caller; `rpi-core` never reads the clock itself.
    pub generated_at: String,
}

impl Report {
    /// Build a report from raw parts, deriving [`Metrics`] automatically.
    pub fn new(workspace: WorkspaceInfo, findings: Vec<Finding>, generated_at: String) -> Self {
        let metrics = Metrics {
            crate_count: workspace.crates.len(),
            finding_count: findings.len(),
        };
        Self {
            workspace,
            findings,
            metrics,
            generated_at,
        }
    }
}

/// One parsed source file. The AST is parsed once by `rpi-collect` and shared;
/// inspections must never re-parse.
pub struct SourceFile {
    pub path: PathBuf,
    /// Physical line count of the file.
    pub loc: usize,
    /// Parsed syntax tree.
    pub ast: syn::File,
}

/// A single workspace-member crate with its parsed sources.
pub struct CrateData {
    pub name: String,
    pub manifest_path: PathBuf,
    /// Directory containing the crate's `Cargo.toml`.
    pub root_dir: PathBuf,
    /// Names of other workspace members this crate depends on (for the
    /// dependency graph). External deps are intentionally excluded.
    pub workspace_deps: Vec<String>,
    /// Names of declared, normal-kind external dependencies (for
    /// `dep-hygiene`'s unused-dependency check).
    ///
    /// Each entry is the name the code uses to refer to the dependency: the
    /// `package` rename when one is declared, otherwise the package name.
    pub external_deps: Vec<String>,
    /// For renamed external deps only: reference name -> original package name
    /// (display only).
    pub external_dep_packages: std::collections::HashMap<String, String>,
    pub files: Vec<SourceFile>,
}

/// One RustSec advisory hit, surfaced by `audit-bridge` from `cargo audit`.
#[derive(Debug, Clone)]
pub struct AuditVuln {
    pub id: String,
    pub package: String,
    pub version: String,
    pub title: String,
}

/// Tunable thresholds, overridable via `rpi.toml` at the workspace root.
///
/// Uses `#[serde(default)]` so a partial `rpi.toml` only overrides the keys it
/// names and everything else keeps its default.
#[derive(Debug, Clone, serde::Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    /// A single file above this many lines is flagged by `module-size`.
    pub module_size_loc: usize,
    /// Per-crate `pub` item count above this is flagged by `pub-surface`.
    pub pub_surface_warn: usize,
    /// Per-crate unsafe items per 1k LOC above this is flagged by
    /// `unsafe-surface`.
    pub unsafe_density_warn: f64,
    /// A single file importing more than this many distinct crate roots is
    /// flagged by `coupling` as a highly-coupled ("God") module.
    pub coupling_warn: usize,
    /// A function whose cyclomatic complexity exceeds this is flagged by
    /// `complexity`.
    pub complexity_warn: usize,
    /// A file changed at least this many times (git history) *and* over
    /// `complexity_warn` total complexity is flagged by `churn-hotspot`.
    pub churn_warn: usize,
    /// Maximum seconds to wait for `git log` before giving up and returning an
    /// empty churn map. Prevents hangs on repositories with very long histories.
    pub churn_git_timeout_secs: u64,
}

impl Config {
    /// Every key accepted in `rpi.toml`; used to flag unknown keys (#35).
    /// Keep in sync with the fields above.
    pub const KNOWN_KEYS: &'static [&'static str] = &[
        "module_size_loc",
        "pub_surface_warn",
        "unsafe_density_warn",
        "coupling_warn",
        "complexity_warn",
        "churn_warn",
        "churn_git_timeout_secs",
    ];
}

impl Default for Config {
    fn default() -> Self {
        Self {
            module_size_loc: 300,
            pub_surface_warn: 50,
            unsafe_density_warn: 5.0,
            coupling_warn: 20,
            complexity_warn: 10,
            churn_warn: 5,
            churn_git_timeout_secs: 30,
        }
    }
}

/// Shared, already-parsed input handed to every [`Inspection`].
///
/// `workspace` is the lightweight, serializable summary that also flows into
/// [`Report`]; `crates` carries the heavy parsed ASTs and is analysis-only.
///
/// Derives [`Default`] so tests and future fields compose via
/// `Context { crates, ..Default::default() }`.
#[derive(Default)]
pub struct Context {
    pub workspace: WorkspaceInfo,
    pub crates: Vec<CrateData>,
    pub config: Config,
    /// Every package `(name, version)` in the resolved dependency graph, used
    /// by `dep-hygiene` to detect the same crate resolved to multiple versions.
    pub resolved_versions: Vec<(String, String)>,
    /// RustSec advisories, populated only when audit collection is enabled.
    pub audit: Vec<AuditVuln>,
    /// Per-file git change counts (commits touching the file), used by
    /// `churn-hotspot`. Empty when the workspace is not a git repo.
    pub churn: std::collections::HashMap<PathBuf, usize>,
}

/// A single structural analysis. Implementations must be side-effect free and
/// read only from [`Context`].
pub trait Inspection {
    /// Stable identifier, e.g. `"workspace-graph"`.
    fn name(&self) -> &'static str;

    /// Produce findings for the given context.
    fn run(&self, ctx: &Context) -> Vec<Finding>;
}

/// True for characters that must not reach a terminal or log verbatim: C0/C1
/// controls and DEL (`char::is_control`), bidirectional controls that can
/// visually reorder text (U+061C, U+200E/F, U+202A-E, U+2066-9) and zero-width
/// characters (U+200B-D, U+2060, U+FEFF).
pub fn is_hostile_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{61c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

/// Makes externally sourced strings (file names, crate names, messages) safe to
/// print to a terminal. Characters for which [`is_hostile_char`] holds become
/// `\u{..}` (this includes `\n` and `\t`: line layout is produced by the
/// renderer itself, so any newline inside a value is hostile). Printable text
/// (CJK, emoji, spaces) is unchanged.
pub fn sanitize_for_terminal(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_hostile_char(c) {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    /// #35: `KNOWN_KEYS` must match the real `Config` fields.
    #[test]
    fn known_keys_match_config_fields() {
        let v = serde_json::to_value(Config::default()).unwrap();
        let mut fields: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        let mut known: Vec<&str> = Config::KNOWN_KEYS.to_vec();
        fields.sort_unstable();
        known.sort_unstable();
        assert_eq!(fields, known);
    }

    use super::*;

    #[test]
    fn report_derives_metrics() {
        let ws = WorkspaceInfo {
            root: PathBuf::from("/tmp/x"),
            crates: vec!["a".into(), "b".into()],
        };
        let report = Report::new(ws, Vec::new(), "1970-01-01T00:00:00Z".into());
        assert_eq!(report.metrics.crate_count, 2);
        assert_eq!(report.metrics.finding_count, 0);
    }

    #[test]
    fn location_skips_empty_fields() {
        let loc = Location {
            krate: Some("core".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&loc).unwrap();
        assert_eq!(json, r#"{"krate":"core"}"#);
    }

    #[test]
    fn sanitize_escapes_c1_and_bidi_but_keeps_text() {
        assert_eq!(sanitize_for_terminal("a\u{85}b\u{9b}"), "a\\u{85}b\\u{9b}");
        assert_eq!(
            sanitize_for_terminal("x\u{202e}y\u{2066}"),
            "x\\u{202e}y\\u{2066}"
        );
        assert_eq!(
            sanitize_for_terminal("\u{200b}\u{feff}"),
            "\\u{200b}\\u{feff}"
        );
        let ok = "日本語 パス/with space/😀.rs ー";
        assert_eq!(sanitize_for_terminal(ok), ok);
    }
}
