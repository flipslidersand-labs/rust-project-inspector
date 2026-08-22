//! `rpi` — command-line entry point for rust-project-inspector.
//!
//! P0 wires the pipeline end to end with stub stages so the shape is testable:
//! collect → run inspections → aggregate → render.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rpi_core::Report;

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
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect { path, format } => inspect(path, format),
    }
}

fn inspect(path: PathBuf, format: Format) -> Result<()> {
    let ctx = rpi_collect::collect(&path)?;

    let findings = rpi_inspections::all()
        .iter()
        .flat_map(|inspection| inspection.run(&ctx))
        .collect();

    let report = Report::new(ctx.workspace, findings, now_rfc3339_ish());

    match format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        Format::Text => render_text(&report),
    }
    Ok(())
}

/// Best-effort UTC timestamp without pulling in a date crate for P0.
fn now_rfc3339_ish() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

fn render_text(report: &Report) {
    println!("rust-project-inspector");
    println!("  root:     {}", report.workspace.root.display());
    println!("  crates:   {}", report.metrics.crate_count);
    println!("  findings: {}", report.metrics.finding_count);
    if report.findings.is_empty() {
        println!("  (no findings — inspections land in #4/#5)");
    }
}
