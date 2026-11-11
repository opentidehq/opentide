//! Prints a workspace's catalogue: its counts, then each object with the
//! ATT&CK techniques it covers, then the rules covering one technique:
//!
//! ```text
//! cargo run -p opentide --example catalog -- path/to/workspace [T1003]
//! ```
//!
//! The catalogue serialises to `opentide info catalog --json`'s document
//! (`serde_json::to_string(&catalogue)`).

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use opentide::catalog::Row;
use opentide::{Options, Workspace};

/// Writes the catalogue of the workspace at `path` to `out`, then the rules
/// covering `technique`.
pub fn run(
    path: &Path,
    technique: &str,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws = Workspace::open(path, &Options::default())?;
    let info = ws.info();
    writeln!(
        out,
        "{} threats, {} objectives, {} rules, {} files that did not load",
        info.counts.threats, info.counts.objectives, info.counts.rules, info.load_errors
    )?;
    let enabled: Vec<&str> = info
        .platforms
        .iter()
        .filter(|platform| platform.enabled)
        .map(|platform| platform.name.as_str())
        .collect();
    writeln!(out, "platforms enabled: {}", enabled.join(", "))?;
    let catalogue = ws.catalog();
    for row in &catalogue.objects {
        let family = row.loaded_family().unwrap_or("load error");
        let techniques = row.techniques();
        let mut covered: Vec<&str> = techniques
            .own
            .iter()
            .chain(&techniques.inherited)
            .map(String::as_str)
            .collect();
        covered.sort_unstable();
        covered.dedup();
        let name = match row {
            Row::Object(object) => object.name.as_str(),
            Row::LoadError(error) => error.name.as_str(),
        };
        writeln!(out, "{family:<9} {name} [{}]", covered.join(" "))?;
    }
    writeln!(out, "{} edges", catalogue.edges.len())?;
    let coverage = ws.coverage(technique);
    writeln!(
        out,
        "{}: {} rules ({} own, {} inherited)",
        coverage.technique,
        coverage.count,
        coverage.own.len(),
        coverage.inherited.len()
    )?;
    Ok(())
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: catalog <workspace> [technique]");
        return ExitCode::from(2);
    };
    let technique = args.next().map_or_else(
        || "T1003".to_owned(),
        |arg| arg.to_string_lossy().into_owned(),
    );
    match run(Path::new(&path), &technique, &mut std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
