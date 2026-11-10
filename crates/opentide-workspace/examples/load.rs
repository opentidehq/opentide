//! Loads the workspace of the working directory (or `--repo DIR`) and prints
//! what the index holds as one JSON document: `cargo xtask bench`'s `load`
//! command for the Rust engine (UC-2.1, #816).

use std::path::PathBuf;
use std::process::ExitCode;

use opentide_workspace::Workspace;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let repo = match (args.next().as_deref(), args.next()) {
        (Some("--repo"), Some(dir)) => Some(PathBuf::from(dir)),
        (None, None) => None,
        _ => {
            eprintln!("usage: load [--repo DIR]");
            return ExitCode::from(2);
        }
    };
    match Workspace::open_os(repo) {
        Ok(workspace) => {
            let index = workspace.index();
            let stats = workspace.stats();
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "objects": index.len(),
                    "signals": index.signals.len(),
                    "load_errors": index.load_errors.len(),
                    "references": index.references.len(),
                    "file_reads": stats.file_reads,
                    "parses": stats.parses,
                    "config_resolutions": stats.config_resolutions,
                })
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
