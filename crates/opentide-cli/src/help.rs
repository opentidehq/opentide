//! `--help`: clap's long help of a command path (#841, decision D1).
//!
//! The layout is clap's, never a copy of Typer's panels; what the help says
//! is the command tree's, as the Python CLI said it. Three things the tree
//! holds that clap's default layout cannot say are added here, on a copy of
//! the command made for the help alone (the copy never parses anything):
//!
//! - the root's commands under the headings people find them by
//!   ([`ROOT_HEADINGS`]: Author, Ship, Workspace, Agents and integrations),
//!   after its options;
//! - a flag pair on one line (`--staging, --no-staging`), with the side that
//!   holds when neither is given as its default (`[default: staging]`), where
//!   clap would list the negative flag as an option of its own;
//! - the root's options before its commands, as every other command lists
//!   its options before its subcommands.
//!
//! `cargo xtask golden check --engine compare` holds every help screen to the
//! oracle's by content (`opentide_compare::help`): the same usage path, about
//! text, options, arguments, commands, descriptions, defaults, environment
//! variables and examples.

use clap::builder::StyledStr;
use clap::{Arg, Command};

use crate::catalog::PROGRAM;
use crate::tree_meta;

/// The root's commands by heading, in the order the help lists them.
pub const ROOT_HEADINGS: &[(&str, &[&str])] = &[
    (
        "Author",
        &[
            "validate", "query", "lint", "info", "new", "generate", "rules",
        ],
    ),
    ("Ship", &["deploy", "share"]),
    ("Workspace", &["setup", "doctor", "migrate", "tui"]),
    (
        "Agents and integrations",
        &["explain", "commands", "mcp", "lsp", "serve"],
    ),
];

/// The long help of the command at `path` under `root`: with clap's styles
/// as SGR codes when `styled`, plain text otherwise. Ends with a newline.
pub fn render(root: &Command, path: &[String], styled: bool) -> String {
    let mut command = crate::usage::command_at(root, path).clone();
    let words: Vec<String> = std::iter::once(PROGRAM.to_owned())
        .chain(path.iter().cloned())
        .collect();
    let joined = path.join(" ");
    command = command.bin_name(words.join(" "));
    command = with_pairs(command, &joined);
    if path.is_empty() {
        command = with_root_headings(command);
    }
    let help = command.render_long_help();
    let mut text = if styled {
        help.ansi().to_string()
    } else {
        help.to_string()
    };
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// `command` (the command at `path`) with each flag pair of `tree_meta`
/// shown as one option: the positive flag named with its negative one, its
/// default after its help, and the negative flag hidden.
fn with_pairs(mut command: Command, path: &str) -> Command {
    for (pair_path, primary, secondary, flag) in tree_meta::SECONDARY {
        if *pair_path != path {
            continue;
        }
        let Some(long) = command
            .get_arguments()
            .find(|arg| arg.get_id().as_str() == *primary)
            .and_then(Arg::get_long)
            .map(str::to_owned)
        else {
            continue;
        };
        let default = match tree_meta::default(path, primary) {
            Some("true") => Some(long.clone()),
            Some(_) => None,
            None => Some(flag.trim_start_matches('-').to_owned()),
        };
        let shown = format!("{long}, {flag}");
        command = command
            .mut_arg(*primary, |arg| {
                let help = arg
                    .get_long_help()
                    .or_else(|| arg.get_help())
                    .map(ToString::to_string)
                    .unwrap_or_default();
                let help = match &default {
                    Some(default) => format!("{help}\n\n[default: {default}]"),
                    None => help,
                };
                arg.long(shown.clone()).long_help(help)
            })
            .mut_arg(*secondary, |arg| arg.hide(true));
    }
    command
}

/// The root with its commands under [`ROOT_HEADINGS`], after its options: a
/// help template that lists the options with clap and the commands itself,
/// in clap's styles.
fn with_root_headings(command: Command) -> Command {
    let styles = command.get_styles();
    let header = styles.get_header();
    let literal = styles.get_literal();
    let width = command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(|sub| sub.get_name().len())
        .max()
        .unwrap_or_default();
    let mut template =
        String::from("{before-help}{about-with-newline}\n{usage-heading} {usage}\n\n");
    template.push_str(&format!("{header}Options:{header:#}\n{{options}}"));
    for (heading, names) in ROOT_HEADINGS {
        let rows: Vec<String> = names
            .iter()
            .filter_map(|name| command.find_subcommand(name))
            .filter(|sub| !sub.is_hide_set())
            .map(|sub| {
                let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
                let name = sub.get_name();
                let pad = " ".repeat(width - name.len() + 2);
                format!("  {literal}{name}{literal:#}{pad}{about}")
                    .trim_end()
                    .to_owned()
            })
            .collect();
        if rows.is_empty() {
            continue;
        }
        template.push_str(&format!("\n\n{header}{heading}:{header:#}\n"));
        template.push_str(&rows.join("\n"));
    }
    // A command the headings do not name still shows, under clap's heading.
    let named: Vec<&str> = ROOT_HEADINGS
        .iter()
        .flat_map(|(_, names)| names.iter().copied())
        .collect();
    let others: Vec<String> = command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set() && !named.contains(&sub.get_name()))
        .map(|sub| {
            let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
            let name = sub.get_name();
            let pad = " ".repeat(width - name.len() + 2);
            format!("  {literal}{name}{literal:#}{pad}{about}")
                .trim_end()
                .to_owned()
        })
        .collect();
    if !others.is_empty() {
        template.push_str(&format!("\n\n{header}Commands:{header:#}\n"));
        template.push_str(&others.join("\n"));
    }
    template.push_str("{after-help}");
    command.help_template(StyledStr::from(template))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn help(path: &str) -> String {
        let words: Vec<String> = path.split_whitespace().map(str::to_owned).collect();
        render(&crate::catalog::root(), &words, false)
    }

    #[test]
    fn every_root_command_has_a_heading() {
        let root = crate::catalog::root();
        let named: Vec<&str> = ROOT_HEADINGS
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        for sub in root.get_subcommands().filter(|sub| !sub.is_hide_set()) {
            assert!(named.contains(&sub.get_name()), "{}", sub.get_name());
        }
        let text = help("");
        assert!(!text.contains("\nCommands:"), "{text}");
    }

    #[test]
    fn the_root_lists_its_options_then_its_commands_by_heading() {
        let text = help("");
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("{needle:?} not in\n{text}"))
        };
        assert!(at("Usage: opentide [OPTIONS] <COMMAND>") < at("\nOptions:\n"));
        assert!(at("\nOptions:\n") < at("\nAuthor:\n"));
        assert!(at("\nAuthor:\n  validate  Validate objects and queries\n") < at("\nShip:\n"));
        assert!(
            at("\nShip:\n  deploy    Deploy rules to platform tenants\n") < at("\nWorkspace:\n")
        );
        assert!(at("\nWorkspace:\n") < at("\nAgents and integrations:\n"));
        assert!(at("\nAgents and integrations:\n") < at("\nExamples:\n"));
        assert!(text.contains("      --install-completion\n"), "{text}");
        assert!(text.contains("      --show-completion\n"), "{text}");
        // An environment variable is named, never its value.
        assert!(text.contains("[env: OPENTIDE_PROXY]"), "{text}");
        assert!(text.ends_with("  $ opentide --json validate\n"), "{text}");
    }

    #[test]
    fn help_is_the_only_help_option_and_no_subcommand() {
        let text = help("validate");
        assert!(
            text.contains("      --help\n          Show this message and exit.\n"),
            "{text}"
        );
        assert!(!text.contains("-h,"), "{text}");
        assert!(!text.contains("  help "), "{text}");
    }

    #[test]
    fn a_flag_pair_is_one_option_with_its_default() {
        let text = help("setup ci");
        assert!(
            text.contains("      --staging, --no-staging\n          Deploy to staging tenants from pull requests\n          \n          [default: staging]\n"),
            "{text}"
        );
        assert!(text.contains("      --sharing, --no-sharing\n"), "{text}");
        assert!(text.contains("[default: no-sharing]"), "{text}");
        assert!(!text.contains("      --no-staging\n"), "{text}");
        // A pair whose default the command resolves itself shows none.
        let text = help("deploy");
        assert!(
            text.contains("      --keep-deprecated, --drop-deprecated\n          Include rules"),
            "{text}"
        );
        let block = &text[text.find("--keep-deprecated,").unwrap()..];
        let block = &block[..block.find("\n\n      --").unwrap()];
        assert!(!block.contains("[default:"), "{block}");
    }

    #[test]
    fn styled_help_carries_sgr_codes() {
        let words: Vec<String> = Vec::new();
        let text = render(&crate::catalog::root(), &words, true);
        assert!(text.contains('\u{1b}'), "{text}");
        let plain = render(&crate::catalog::root(), &words, false);
        assert!(!plain.contains('\u{1b}'), "{plain}");
    }
}
