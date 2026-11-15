//! The repository's Rust tooling, run as `cargo xtask <command>`
//! (`.cargo/config.toml`). `xtask/AGENTS.md` describes the commands.
//!
//! The library holds what the commands compute, so that tests drive it
//! without a workspace or a subprocess; `main.rs` reads the inputs and prints.

pub mod astgen;
pub mod bench;
pub mod cassettes;
pub mod codegen;
pub mod compare;
pub mod config;
pub mod conformance;
pub mod corpus;
pub mod coverage;
pub mod diff_args;
pub mod golden;
pub mod layers;
pub mod lint;
pub mod lsp;
pub mod mcp;
pub mod mutants;
pub mod parallel;
pub mod payloads;
pub mod registry;
pub mod schema;
#[cfg(unix)]
pub mod script;
pub mod spec_fields;
pub mod stubs;
pub mod validate;
pub mod verdict;
pub mod vocab;

/// Parses `argv` (without the program name) as the subcommands `C`, as
/// `cargo xtask` does, for the command modules' tests.
#[cfg(test)]
pub(crate) fn parse_subcommand<C: clap::Subcommand + clap::FromArgMatches>(
    argv: &[&str],
) -> Result<C, clap::Error> {
    let command = C::augment_subcommands(
        clap::Command::new("xtask")
            .subcommand_required(true)
            .arg_required_else_help(true),
    );
    let matches =
        command.try_get_matches_from(std::iter::once("xtask").chain(argv.iter().copied()))?;
    C::from_arg_matches(&matches)
}
