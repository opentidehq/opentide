//! Runs a query on one of a workspace's tenants, as `opentide query` does,
//! and prints its rows as JSON lines. Nothing is saved on the tenant.
//!
//! ```text
//! cargo run -p opentide --features connectors --example query -- \
//!     path/to/workspace splunk spl 'index=main | head 5'
//! ```
//!
//! The first tenant the workspace configures for the platform answers; its
//! `$NAME` credentials are read from the environment. Exit
//! status 1 when the tenant refuses the query or cannot be reached.

use std::process::ExitCode;

// docs:start (docs/sdk/rust.md shows this part; tests/examples.rs checks it)
use std::io::Write;
use std::path::Path;

use opentide::connectors::{self, ConnectOptions, Connection, QueryRequest, TimeWindow, Timestamp};
use opentide::{Options, Workspace};

/// Runs `query`, written in `language` (`spl`, `kql`, `esql`, `powerquery`,
/// ...), on the first tenant the workspace at `path` configures for
/// `platform`, over the last 24 hours, and writes each row to `out` as one
/// JSON line.
pub fn run(
    path: &Path,
    platform: &str,
    language: &str,
    query: &str,
    options: &ConnectOptions,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws = Workspace::open(path, &Options::default())?;
    let Some(tenant) = ws.tenants(platform).into_iter().next() else {
        return Err(format!("{} configures no {platform} tenant", path.display()).into());
    };
    let connection = Connection::open(&tenant, options)?;
    let now = Timestamp::now();
    let window = TimeWindow {
        start: now.checked_sub(std::time::Duration::from_secs(24 * 60 * 60))?,
        end: now,
    };
    let mut request = QueryRequest::new(query, language, window);
    request.limit = 10;
    // A synchronous caller runs the async operation on a runtime of its own;
    // in a tokio task, `connection.query(&request).await?` instead.
    let outcome = connectors::block_on(connection.query(&request))??;
    for row in &outcome.rows {
        writeln!(out, "{}", serde_json::to_string(row)?)?;
    }
    if outcome.truncated {
        writeln!(out, "(more than {} rows)", request.limit)?;
    }
    Ok(())
}
// docs:end

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path, platform, language, query] = args.as_slice() else {
        eprintln!("usage: query <workspace> <platform> <language> <query>");
        return ExitCode::from(2);
    };
    let mut out = std::io::stdout().lock();
    match run(
        Path::new(path),
        platform,
        language,
        query,
        &ConnectOptions::default(),
        &mut out,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
