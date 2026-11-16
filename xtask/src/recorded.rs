//! The `opentide` command line of a recorded golden case, read by the
//! product's own clap tree (`opentide_cli::tree`): the `validate diff`,
//! `lint diff` and `payloads plan` commands run the options a case recorded,
//! so a flag the product takes is a flag they take, with its value checks.

use clap::Parser as _;
use opentide_cli::tree::{Cli, RootCommand};

/// `argv`'s command line from its `verb` on, as the product parses it.
///
/// `None` when `verb` is absent, the product's parser refuses the words (an
/// unknown flag, a bad value, `--help`), or a global flag (`--json`,
/// `--verbose`, ...) follows the verb: a case that holds one is not what the
/// command replays. Global flags before the verb are the case's recording
/// mode and are left out.
pub(crate) fn command(argv: &[String], verb: &str) -> Option<RootCommand> {
    let at = argv.iter().position(|arg| arg == verb)?;
    let words = ["opentide", verb]
        .into_iter()
        .chain(argv[at + 1..].iter().map(String::as_str));
    let cli = Cli::try_parse_from(words).ok()?;
    let global = cli.debug || cli.quiet || cli.verbose || cli.no_color || cli.json_output;
    (!global).then_some(cli.command).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn the_verb_and_its_flags_are_the_products() {
        let argv = words(&["opentide", "--json", "lint", "--strict", "--file", "x"]);
        let Some(RootCommand::Lint(lint)) = command(&argv, "lint") else {
            panic!("a lint command");
        };
        assert!(lint.strict && lint.file == ["x"]);
        assert!(command(&argv, "validate").is_none());
    }

    #[test]
    fn what_the_product_refuses_or_a_global_flag_after_the_verb_is_not_replayed() {
        for bad in [
            &["opentide", "lint", "--nope"][..],
            &["opentide", "lint", "--check", "filenamez"],
            &["opentide", "lint", "--help"],
            &["opentide", "lint", "--json"],
            &["opentide", "lint", "--verbose"],
        ] {
            assert!(command(&words(bad), "lint").is_none(), "{bad:?}");
        }
        // Before the verb they are the recording's.
        assert!(command(&words(&["opentide", "--quiet", "lint"]), "lint").is_some());
    }
}
