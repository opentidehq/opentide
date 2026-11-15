//! The command-line pieces the `diff` commands share: the options of
//! `validate diff` and `lint diff` (recorded cases against this repository's
//! engine) and `--against`.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

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
    /// Only the cases whose id (`<command>/json/<fixture>/<variant>`) matches
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

/// What an oracle comparison runs against: the frozen Python oracle is the
/// only reference there is.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Against {
    /// The frozen Python oracle
    Python,
}
