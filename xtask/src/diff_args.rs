//! The command line of the `diff` commands that compare recorded cases with
//! this repository's engine (`validate diff`, `lint diff`).

use std::path::PathBuf;

use clap::{Args, Subcommand};

/// The subcommands of `validate` and `lint`.
#[derive(Subcommand, Debug)]
pub enum DiffCmd {
    /// Run the engine on every recorded `--json` case (no `--format`) and
    /// compare the result with the oracle's recording, through the named rules
    /// of the command's `APPROVED`
    Diff(DiffArgs),
}

/// The options of a `diff` command.
#[derive(Args, Debug, Default)]
pub struct DiffArgs {
    /// Only the cases whose id (<command>/json/<fixture>/<variant>) matches
    /// GLOB
    #[arg(long, value_name = "GLOB")]
    pub filter: Option<String>,
    /// Lay the cases out in DIR and keep them
    #[arg(long, value_name = "DIR")]
    pub keep: Option<PathBuf>,
    /// Print each approved difference too
    #[arg(long)]
    pub show_approved: bool,
}
