//! Validates a workspace and prints each finding, then the counts:
//!
//! ```text
//! cargo run -p opentide --example validate -- path/to/workspace
//! ```
//!
//! Exit status 1 when the workspace does not validate. Built without the
//! `queries` feature, it turns the queries check off and says so (with the
//! check on, it would report `engine_unavailable`).

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use opentide::validate::QueriesMode;
use opentide::{Options, ValidateOptions, Workspace};

/// Validates the workspace at `path` and writes what it found to `out`.
/// Returns whether it validates.
pub fn run(path: &Path, out: &mut dyn Write) -> Result<bool, Box<dyn std::error::Error>> {
    let ws = Workspace::open(path, &Options::default())?;
    let mut options = ValidateOptions::default();
    if !opentide::queries::AVAILABLE {
        writeln!(
            out,
            "queries check off: built without the `queries` feature"
        )?;
        options = options.queries(QueriesMode::Off);
    }
    let validation = ws.validate(&options);
    for finding in validation
        .report
        .issues
        .iter()
        .chain(&validation.report.warnings)
    {
        let place = match (&finding.path, finding.line) {
            (Some(path), Some(line)) => format!("{path}:{line}: "),
            (Some(path), None) => format!("{path}: "),
            _ => String::new(),
        };
        writeln!(
            out,
            "{place}{}[{}]: {}",
            finding.severity.as_str(),
            finding.code,
            finding.message
        )?;
    }
    let summary = validation.summary;
    writeln!(
        out,
        "{} objects checked: {} errors, {} warnings",
        summary.objects, summary.errors, summary.warnings
    )?;
    Ok(!validation.failed)
}

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: validate <workspace>");
        return ExitCode::from(2);
    };
    match run(Path::new(&path), &mut std::io::stdout().lock()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
