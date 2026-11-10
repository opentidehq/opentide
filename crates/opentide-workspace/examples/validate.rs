//! Validates the workspace of the working directory (or `--repo DIR`) and
//! prints `checks`, `report` and `summary` as `validate --json` writes them:
//! `cargo xtask bench`'s `validate_*` commands for the Rust engine (UC-2.2,
//! #817). Exit status 1 when the run fails, 2 on a usage error.
//!
//! Options: `--check NAME`, `--type FAMILY`, `--uuid UUID`, `--file PATH`
//! (each repeatable but `--check`), `--strict`, `--queries error|warn|off`.
//! The queries check needs the query engines, which sit above this crate
//! (`opentide_cli::queries`, UC-2.5, #820): it reports nothing here.

use std::path::PathBuf;
use std::process::ExitCode;

use opentide_workspace::Workspace;
use opentide_workspace::validate::{Check, Options, QueriesMode, Selection};

fn usage(why: &str) -> ExitCode {
    eprintln!("validate: {why}");
    eprintln!(
        "usage: validate [--repo DIR] [--check NAME] [--type FAMILY] [--uuid UUID] \
         [--file PATH] [--strict] [--queries error|warn|off]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut repo = None;
    let mut selection = Selection::default();
    let mut check = None;
    let mut strict = false;
    let mut queries = QueriesMode::Error;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let Some(value) = (match arg.as_str() {
            "--strict" => {
                strict = true;
                continue;
            }
            _ => args.next(),
        }) else {
            return usage(&format!("{arg} needs a value, or is not an option"));
        };
        match arg.as_str() {
            "--repo" => repo = Some(PathBuf::from(value)),
            "--check" => match Check::parse(&value) {
                Some(found) => check = Some(found),
                None => return usage(&format!("no check {value}")),
            },
            "--type" => selection.types.push(value),
            "--uuid" => selection.uuids.push(value),
            "--file" => selection.files.push(value),
            "--queries" => {
                queries = match value.as_str() {
                    "error" => QueriesMode::Error,
                    "warn" => QueriesMode::Warn,
                    "off" => QueriesMode::Off,
                    _ => return usage(&format!("--queries {value}")),
                };
            }
            other => return usage(&format!("unknown option {other}")),
        }
    }
    let workspace = match Workspace::open_os(repo) {
        Ok(workspace) => workspace,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let validation = workspace.validate(&Options {
        check,
        selection: Some(&selection),
        strict,
        queries,
        query_check: None,
    });
    let document = serde_json::json!({
        "checks": validation.checks_json(),
        "report": validation.report,
        "summary": validation.summary,
        "ok": !validation.failed,
    });
    println!("{document}");
    if validation.failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
