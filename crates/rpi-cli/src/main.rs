//! `rpi` — command-line entry point for rust-project-inspector.
//!
//! P0 wires the pipeline end to end with stub stages so the shape is testable:
//! collect → run inspections → aggregate → render.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rpi_core::Report;

mod render;

#[derive(Parser)]
#[command(
    name = "rpi",
    version,
    about = "Structural inspector for Rust workspaces"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a Rust workspace and print a structural report.
    Inspect {
        /// Workspace root (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Exit non-zero when findings reach this severity or higher.
        /// Omit to always exit 0 (report-only).
        #[arg(long, value_enum)]
        fail_on: Option<FailLevel>,

        /// Run `cargo audit` and include RustSec advisories (audit-bridge).
        /// Requires cargo-audit installed; off by default.
        #[arg(long)]
        audit: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    /// SARIF 2.1.0 for GitHub Code Scanning.
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailLevel {
    Warn,
    Error,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect {
            path,
            format,
            fail_on,
            audit,
        } => inspect(path, format, fail_on, audit),
    }
}

fn inspect(path: PathBuf, format: Format, fail_on: Option<FailLevel>, audit: bool) -> Result<()> {
    let opts = rpi_collect::CollectOptions { run_audit: audit };
    let ctx = rpi_collect::collect(&path, opts)?;

    let findings = rpi_inspections::all()
        .iter()
        .flat_map(|inspection| inspection.run(&ctx))
        .collect();

    let report = Report::new(ctx.workspace, findings, now_rfc3339_ish());

    match format {
        Format::Json => println!("{}", render::json(&report)?),
        Format::Sarif => println!("{}", render::sarif(&report)?),
        Format::Text => print!("{}", render::text(&report)),
    }

    if let Some(level) = fail_on {
        if should_fail(&report, level) {
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Whether any finding meets or exceeds the `--fail-on` threshold.
fn should_fail(report: &Report, level: FailLevel) -> bool {
    use rpi_core::Severity;
    report.findings.iter().any(|f| match level {
        FailLevel::Error => f.severity == Severity::Error,
        FailLevel::Warn => matches!(f.severity, Severity::Error | Severity::Warn),
    })
}

/// Best-effort UTC timestamp without pulling in a date crate for P0.
fn now_rfc3339_ish() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_core::{Finding, Location, Severity};

    fn report_with(sev: Severity) -> Report {
        let f = Finding {
            inspection: "x",
            severity: sev,
            location: Location::default(),
            message: "m".into(),
            metric: None,
        };
        Report::new(Default::default(), vec![f], "t".into())
    }

    #[test]
    fn fail_on_error_ignores_warn_and_info() {
        assert!(!should_fail(&report_with(Severity::Warn), FailLevel::Error));
        assert!(!should_fail(&report_with(Severity::Info), FailLevel::Error));
        assert!(should_fail(&report_with(Severity::Error), FailLevel::Error));
    }

    #[test]
    fn fail_on_warn_catches_warn_and_error_but_not_info() {
        assert!(should_fail(&report_with(Severity::Warn), FailLevel::Warn));
        assert!(should_fail(&report_with(Severity::Error), FailLevel::Warn));
        assert!(!should_fail(&report_with(Severity::Info), FailLevel::Warn));
    }
}
