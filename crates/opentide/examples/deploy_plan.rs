//! Plans a deploy without sending anything: the rules a strategy selects,
//! the tenants each reaches and the request bodies a real run would send, as
//! `opentide deploy --dry-run --json` reports them.
//!
//! ```text
//! cargo run -p opentide --example deploy_plan -- path/to/workspace [PREVIEW|RELEASE]
//! ```
//!
//! Exit status 1 when a real run would stop.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use opentide::{DeployPlanOptions, Options, Strategy, Workspace};

/// Plans a deploy of the workspace at `path` for `strategy` and writes the
/// plan to `out`: one line per planned change (`action uuid on platform/tenant`), then the payload. Returns
/// whether a real run would go ahead.
pub fn run(
    path: &Path,
    strategy: Strategy,
    out: &mut dyn Write,
) -> Result<bool, Box<dyn std::error::Error>> {
    let ws = Workspace::open(path, &Options::default())?;
    let plan = ws.deploy_plan(&DeployPlanOptions::new(strategy))?;
    let document = plan.document().value();
    if let Some(changes) = document["changes"].as_array() {
        for change in changes {
            writeln!(
                out,
                "{} {} on {}/{}",
                change["action"].as_str().unwrap_or("?"),
                change["uuid"].as_str().unwrap_or("?"),
                change["platform"].as_str().unwrap_or("?"),
                change["tenant"].as_str().unwrap_or("-"),
            )?;
        }
    }
    if let Some(summary) = plan.summary() {
        writeln!(out, "summary: {summary}")?;
    }
    writeln!(out, "{}", plan.document())?;
    Ok(plan.ok())
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: deploy_plan <workspace> [PREVIEW|RELEASE]");
        return ExitCode::from(2);
    };
    let strategy = match args.next().as_deref().and_then(|arg| arg.to_str()) {
        None | Some("PREVIEW") => Strategy::Preview,
        Some("RELEASE") => Strategy::Release,
        Some(other) => {
            eprintln!("deploy_plan: {other} is not a strategy: PREVIEW or RELEASE");
            return ExitCode::from(2);
        }
    };
    match run(Path::new(&path), strategy, &mut std::io::stdout().lock()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
