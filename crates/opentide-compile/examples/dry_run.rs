//! Times `deploy --dry-run --all` on a workspace: open, index, plan and
//! compile, as the command does. `cargo run -p opentide-compile --example
//! dry_run -- <workspace> [strategy] [json]`; `json` prints the result's
//! payload and summary instead of the timing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use opentide_compile::Owned;
use opentide_compile::dry_run::{self, Request};
use opentide_compile::plan::Scope;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, Options, OsFs, RootOptions, Workspace};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(args.next().ok_or("usage: dry_run <workspace> [strategy]")?);
    let strategy = args.next().unwrap_or_else(|| "PREVIEW".to_owned());
    let json = args.next().is_some_and(|arg| arg == "json");
    let started = Instant::now();
    let workspace = Workspace::open(
        Arc::new(OsFs) as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(root.clone()),
                cwd: root.clone(),
                ..RootOptions::default()
            },
        },
    )?;
    let opened = started.elapsed();
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let request = Request {
        strategies: vec![strategy],
        all: true,
        cwd: root,
        ..Request::default()
    };
    let changed = |_: &std::path::Path, _: &str| -> Result<(Scope, Option<String>), String> {
        Err("--all reads no diff".to_owned())
    };
    let is_set = |name: &str| std::env::var_os(name).is_some();
    let outcome = dry_run::run(&workspace, &owned, &request, &changed, &is_set);
    let total = started.elapsed();
    if json {
        let mut payload = outcome.payload.clone();
        if let Some(summary) = &outcome.summary {
            payload.insert("summary".into(), summary.clone());
        }
        println!("{}", opentide_compile::Json::Object(payload).to_compact());
        return Ok(());
    }
    let summary = outcome
        .summary
        .map(|summary| summary.to_compact())
        .unwrap_or_default();
    println!(
        "open and index {:.3}s, plan and compile {:.3}s, total {:.3}s; exit {}; {summary}",
        opened.as_secs_f64(),
        total.saturating_sub(opened).as_secs_f64(),
        total.as_secs_f64(),
        outcome.exit_code
    );
    Ok(())
}
