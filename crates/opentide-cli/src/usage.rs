//! clap's parse errors as the CLI contract reports usage errors.
//!
//! Each becomes a [`Failure`] with its `failure.code`, the argument at fault
//! and the closest valid value ([`crate::suggest`], which replaces clap's own
//! suggestion), and the notes the text modes print under `error:`: `help: did
//! you mean …?`, clap's `usage: …` line and `help: run 'opentide … --help'`.
//! Scripts read `failure.code`, `argument` and `suggestion`, never the
//! message's words. Exit 2.

use crate::envelope::{Failure, code};
use crate::suggest::did_you_mean;
use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Arg, ArgAction, Command};

/// A usage error, ready to print.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageError {
    /// The command path the error is about (`validate`), empty for the root.
    pub command: String,
    /// The `failure` object.
    pub failure: Failure,
    /// The `help:` / `usage:` lines under `error:`.
    pub notes: Vec<(String, String)>,
}

/// The command at `path` under `root`.
pub fn command_at<'a>(root: &'a Command, path: &[String]) -> &'a Command {
    let mut command = root;
    for word in path {
        match command.find_subcommand(word) {
            Some(sub) => command = sub,
            None => break,
        }
    }
    command
}

/// The label of an argument: its first flag, or its name.
pub fn label(arg: &Arg) -> String {
    arg.get_long()
        .map(|long| format!("--{long}"))
        .or_else(|| arg.get_short().map(|short| format!("-{short}")))
        .unwrap_or_else(|| positional_name(arg))
}

fn positional_name(arg: &Arg) -> String {
    arg.get_value_names()
        .and_then(|names| names.first())
        .map_or_else(|| arg.get_id().to_string(), ToString::to_string)
}

fn choice_names(arg: &Arg) -> Vec<String> {
    arg.get_possible_values()
        .iter()
        .filter(|value| !value.is_hide_set())
        .map(|value| value.get_name().to_owned())
        .collect()
}

/// `opentide validate [OPTIONS] <COMMAND>`: clap's usage of the command at
/// `path`, as its `--help` shows it, without the `Usage:` in front.
pub fn usage_line(root: &Command, path: &[String]) -> String {
    let mut root = root.clone();
    // Built, every command knows its parents' names (`opentide validate`).
    root.build();
    let usage = usage_of(&mut root, path).to_string();
    usage
        .lines()
        .map(|line| line.trim().trim_start_matches("Usage:").trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
}

fn usage_of(command: &mut Command, path: &[String]) -> clap::builder::StyledStr {
    if let Some((first, rest)) = path.split_first()
        && let Some(sub) = command.find_subcommand_mut(first)
    {
        return usage_of(sub, rest);
    }
    command.render_usage()
}

/// Whether `arg` reads a value after it.
fn takes_value(arg: &Arg) -> bool {
    !matches!(
        arg.get_action(),
        ArgAction::SetTrue
            | ArgAction::SetFalse
            | ArgAction::Count
            | ArgAction::Help
            | ArgAction::HelpShort
            | ArgAction::HelpLong
            | ArgAction::Version
    )
}

/// The option `name` (`--strict`, `-C`) of `command`.
fn find_option<'a>(command: &'a Command, name: &str) -> Option<&'a Arg> {
    command.get_arguments().find(|arg| {
        if let Some(long) = name.strip_prefix("--") {
            arg.get_long_and_visible_aliases()
                .is_some_and(|longs| longs.contains(&long))
                || arg.get_all_aliases().is_some_and(|all| all.contains(&long))
        } else if let Some(short) = name.strip_prefix('-') {
            let mut chars = short.chars();
            matches!((chars.next(), chars.next()), (Some(c), None) if arg.get_short() == Some(c))
        } else {
            false
        }
    })
}

fn context_string(error: &clap::Error, kind: ContextKind) -> Option<String> {
    match error.get(kind)? {
        ContextValue::String(text) => Some(text.clone()),
        ContextValue::Strings(texts) => texts.first().cloned(),
        _ => None,
    }
}

/// The argument named by clap's `--check <CHECK>` or `<ci_platform>`: the
/// command's own, else the nearest one of the commands above it on `path`
/// (`--repo <REPO>` is the root's, wherever it is reported).
fn find_arg<'a>(root: &'a Command, path: &[String], shown: &str) -> Option<&'a Arg> {
    let word = shown.split_whitespace().next().unwrap_or_default();
    let word = word.split('=').next().unwrap_or_default();
    (0..=path.len())
        .rev()
        .find_map(|depth| own_arg(command_at(root, &path[..depth]), word))
}

fn own_arg<'a>(command: &'a Command, word: &str) -> Option<&'a Arg> {
    if word.starts_with('-') {
        return find_option(command, word);
    }
    let name = word.trim_start_matches('<').trim_end_matches(['>', '.']);
    command.get_arguments().find(|arg| {
        arg.is_positional() && (positional_name(arg) == name || arg.get_id().as_str() == name)
    })
}

/// The visible subcommands of `command`, in the order `--help` lists them.
fn command_names(command: &Command) -> Vec<&str> {
    command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(Command::get_name)
        .collect()
}

/// `Unknown option "--json".`, with the closest visible flag of `command`.
fn unknown_option(command: &Command, name: &str) -> Failure {
    let option = name.split('=').next().unwrap_or_default().to_owned();
    let flags = visible_flags(command);
    Failure {
        suggestion: did_you_mean(&option, flags.iter().map(String::as_str)),
        argument: Some(option.clone()),
        ..Failure::new(
            code::USAGE_UNKNOWN_OPTION,
            format!("Unknown option {option:?}."),
        )
    }
}

/// `Unknown command "valdiate".`, with the closest visible command.
fn unknown_command(command: &Command, name: &str) -> Failure {
    Failure {
        suggestion: did_you_mean(name, command_names(command)),
        argument: Some(name.to_owned()),
        ..Failure::new(
            code::USAGE_UNKNOWN_COMMAND,
            format!("Unknown command {name:?}."),
        )
    }
}

fn visible_flags(command: &Command) -> Vec<String> {
    command
        .get_arguments()
        .filter(|arg| !arg.is_positional() && !arg.is_hide_set() && arg.get_id() != "help")
        .flat_map(crate::catalog::flags)
        .collect()
}

/// The failure for a clap error, in the command `args` named.
pub fn describe(root: &Command, args: &[String], error: &clap::Error) -> UsageError {
    // The command the offending word was typed after: a root option's typo
    // (`--jsn validate`) is the root's.
    let offending = match error.kind() {
        ErrorKind::UnknownArgument => context_string(error, ContextKind::InvalidArg),
        ErrorKind::InvalidSubcommand => context_string(error, ContextKind::InvalidSubcommand),
        _ => None,
    };
    // The last occurrence: an unknown `--json` typed after `--` is not the
    // global flag before it.
    let before = offending
        .and_then(|word| {
            args.iter().rposition(|arg| {
                *arg == word || arg.split_once('=').is_some_and(|(name, _)| name == word)
            })
        })
        .unwrap_or(args.len());
    let path = crate::app::command_words(root, &args[..before]);
    let command = command_at(root, &path);
    let shown = context_string(error, ContextKind::InvalidArg).unwrap_or_default();
    let arg = find_arg(root, &path, &shown);
    let at_fault = arg.map_or_else(|| shown.clone(), label);
    let failure = match error.kind() {
        // `--json=1`: a flag given a value.
        ErrorKind::TooManyValues if arg.is_some_and(|arg| !takes_value(arg)) => Failure {
            argument: Some(at_fault.clone()),
            ..Failure::new(
                code::USAGE_ERROR,
                format!("{at_fault} does not take a value."),
            )
        },
        ErrorKind::InvalidSubcommand => {
            let name = context_string(error, ContextKind::InvalidSubcommand).unwrap_or_default();
            // An option-shaped word where the group expects its command
            // (`validate -- --json`): an unknown option when the group has no
            // such option.
            if name.starts_with('-') && find_option(command, &name).is_none() {
                unknown_option(command, &name)
            } else {
                unknown_command(command, &name)
            }
        }
        ErrorKind::UnknownArgument => {
            if shown.starts_with('-') {
                unknown_option(command, &shown)
            } else if command.get_subcommands().any(|sub| !sub.is_hide_set()) {
                // A word where a group expects its command.
                unknown_command(command, &shown)
            } else {
                Failure::new(code::USAGE_ERROR, format!("Unexpected argument {shown:?}."))
            }
        }
        // `--file` with nothing after it.
        ErrorKind::InvalidValue
            if context_string(error, ContextKind::InvalidValue)
                .is_none_or(|value| value.is_empty()) =>
        {
            Failure {
                argument: Some(at_fault.clone()),
                ..Failure::new(code::USAGE_ERROR, format!("{at_fault} requires a value."))
            }
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let value = context_string(error, ContextKind::InvalidValue).unwrap_or_default();
            let choices = arg.map(choice_names).unwrap_or_default();
            let (code, reason, suggestion) = if choices.is_empty() {
                let reason = match arg.map_or("string", crate::catalog::type_name) {
                    "integer" => ": expected an integer",
                    "number" => ": expected a number",
                    _ => "",
                };
                (code::USAGE_INVALID_VALUE, reason.to_owned(), None)
            } else {
                (
                    code::USAGE_INVALID_CHOICE,
                    format!(": choose from {}", choices.join(", ")),
                    did_you_mean(&value, choices.iter().map(String::as_str)),
                )
            };
            Failure {
                suggestion,
                argument: Some(at_fault.clone()),
                ..Failure::new(
                    code,
                    format!("Invalid value {value:?} for {at_fault}{reason}."),
                )
            }
        }
        ErrorKind::MissingRequiredArgument => {
            let what = if arg.is_some_and(Arg::is_positional) {
                "argument"
            } else {
                "option"
            };
            let choices = arg.map(choice_names).unwrap_or_default();
            let message = if choices.is_empty() {
                format!("Missing {what} {at_fault}.")
            } else {
                format!(
                    "Missing {what} {at_fault}: choose from {}.",
                    choices.join(", ")
                )
            };
            Failure {
                argument: Some(at_fault),
                ..Failure::new(code::USAGE_MISSING_OPTION, message)
            }
        }
        ErrorKind::MissingSubcommand => Failure::new(code::USAGE_ERROR, "Missing command."),
        // A group that shows its help when named alone (`opentide mcp`): in
        // the modes that read errors, the commands to choose from.
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            let names = command_names(command);
            let message = if names.is_empty() {
                "Missing command.".to_owned()
            } else {
                format!("Missing command: choose from {}.", names.join(", "))
            };
            Failure::new(code::USAGE_ERROR, message)
        }
        ErrorKind::ArgumentConflict => {
            let other = context_string(error, ContextKind::PriorArg).unwrap_or_default();
            let other = find_arg(root, &path, &other).map_or(other, label);
            Failure {
                argument: arg.map(label),
                ..Failure::new(
                    code::USAGE_ERROR,
                    format!("{at_fault} cannot be used with {other}."),
                )
            }
        }
        _ => Failure {
            argument: arg.map(label),
            ..Failure::new(code::USAGE_ERROR, first_line(error))
        },
    };
    let mut notes = Vec::new();
    if let Some(suggestion) = &failure.suggestion {
        notes.push(("help".to_owned(), format!("did you mean {suggestion:?}?")));
    }
    notes.push(("usage".to_owned(), usage_line(root, &path)));
    let shown_path = std::iter::once(crate::catalog::PROGRAM.to_owned())
        .chain(path.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    notes.push(("help".to_owned(), format!("run '{shown_path} --help'")));
    UsageError {
        command: path.join(" "),
        failure,
        notes,
    }
}

/// clap's message, on one line, without its `error: ` and its tips.
fn first_line(error: &clap::Error) -> String {
    let text = error.render().to_string();
    let line = text.lines().next().unwrap_or_default();
    let line = line.strip_prefix("error: ").unwrap_or(line).trim();
    let mut chars = line.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::root;

    fn parse(text: &str) -> UsageError {
        let root = root();
        let args: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
        let error = root
            .clone()
            .try_get_matches_from(std::iter::once("opentide".to_owned()).chain(args.clone()))
            .unwrap_err();
        describe(&root, &args, &error)
    }

    #[test]
    fn framework_usage_unknown_command_and_option() {
        let typo = parse("valdiate");
        assert_eq!(typo.failure.code, code::USAGE_UNKNOWN_COMMAND);
        assert_eq!(typo.failure.message, "Unknown command \"valdiate\".");
        assert_eq!(typo.failure.suggestion.as_deref(), Some("validate"));
        assert_eq!(typo.command, "");
        assert_eq!(
            typo.notes,
            vec![
                ("help".into(), "did you mean \"validate\"?".into()),
                ("usage".into(), "opentide [OPTIONS] <COMMAND>".into()),
                ("help".into(), "run 'opentide --help'".into()),
            ]
        );
        let option = parse("validate --strictt");
        assert_eq!(option.failure.code, code::USAGE_UNKNOWN_OPTION);
        assert_eq!(option.failure.message, "Unknown option \"--strictt\".");
        assert_eq!(option.failure.suggestion.as_deref(), Some("--strict"));
        assert_eq!(option.command, "validate");
        assert_eq!(option.notes[1].1, "opentide validate [OPTIONS] [COMMAND]");
        let root_option = parse("--jsn validate");
        assert_eq!(root_option.failure.suggestion.as_deref(), Some("--json"));
        assert_eq!(
            parse("rules zzzz").failure.code,
            code::USAGE_UNKNOWN_COMMAND
        );
        assert_eq!(
            parse("doctor extra").failure.message,
            "Unexpected argument \"extra\"."
        );
    }

    #[test]
    fn framework_usage_choices_values_and_missing() {
        let choice = parse("lint --check filenamez");
        assert_eq!(choice.failure.code, code::USAGE_INVALID_CHOICE);
        assert_eq!(
            choice.failure.message,
            "Invalid value \"filenamez\" for --check: choose from filenames, metadata, recommended, placeholders, queries."
        );
        assert_eq!(choice.failure.suggestion.as_deref(), Some("filenames"));
        assert_eq!(choice.notes[1].1, "opentide lint [OPTIONS]");
        let number = parse("query --platform sentinel --limit many x");
        assert_eq!(number.failure.code, code::USAGE_INVALID_VALUE);
        assert_eq!(
            number.failure.message,
            "Invalid value \"many\" for --limit: expected an integer."
        );
        let float = parse("query --platform sentinel --timeout soon x");
        assert!(float.failure.message.ends_with("expected a number."));
        let missing = parse("query x");
        assert_eq!(missing.failure.code, code::USAGE_MISSING_OPTION);
        assert_eq!(
            missing.failure.message,
            "Missing option --platform: choose from sentinel, defender_for_endpoint, splunk, sentinel_one, crowdstrike, harfanglab, carbon_black_cloud, elastic, sysdig, bitdefender, graylog, exabeam, google_secops."
        );
        assert_eq!(
            missing.notes[0].1,
            "opentide query [OPTIONS] --platform <PLATFORM> [query]"
        );
        let argument = parse("setup ci --yes");
        assert_eq!(
            argument.failure.message,
            "Missing argument ci_platform: choose from github, gitlab, azure."
        );
        assert_eq!(
            argument.notes[0].1,
            "opentide setup ci [OPTIONS] <ci_platform>"
        );
        let group = parse("rules");
        assert_eq!(group.failure.message, "Missing command.");
        assert_eq!(group.notes[0].1, "opentide rules [OPTIONS] <COMMAND>");
        let shown = parse("setup skills show");
        assert_eq!(shown.failure.message, "Missing argument name.");
        assert_eq!(
            shown.notes[0].1,
            "opentide setup skills show [OPTIONS] <name>"
        );
    }

    #[test]
    fn framework_usage_a_missing_or_unwanted_value_has_the_usual_notes() {
        let missing_value = parse("validate --file");
        assert_eq!(missing_value.failure.code, code::USAGE_ERROR);
        assert_eq!(missing_value.failure.message, "--file requires a value.");
        assert_eq!(missing_value.failure.argument.as_deref(), Some("--file"));
        // Every usage error names its command and has the same notes.
        assert_eq!(missing_value.command, "validate");
        assert_eq!(
            missing_value.notes,
            vec![
                (
                    "usage".into(),
                    "opentide validate [OPTIONS] [COMMAND]".into()
                ),
                ("help".into(), "run 'opentide validate --help'".into()),
            ]
        );
        let valued = parse("--json=1 explain x");
        assert_eq!(valued.failure.code, code::USAGE_ERROR);
        assert_eq!(valued.failure.message, "--json does not take a value.");
        assert_eq!(valued.failure.argument.as_deref(), Some("--json"));
        assert_eq!(valued.notes[0].0, "usage");
    }

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn matches(text: &str) -> Result<clap::ArgMatches, clap::Error> {
        root().try_get_matches_from(std::iter::once("opentide".to_owned()).chain(args(text)))
    }

    fn value<'a>(matches: &'a clap::ArgMatches, path: &[&str], id: &str) -> Option<&'a String> {
        let mut current = matches;
        for word in path {
            current = current.subcommand_matches(word).unwrap();
        }
        current.get_one::<String>(id)
    }

    #[test]
    fn framework_usage_a_repeated_flag_or_option_keeps_the_last() {
        for line in [
            // `--json commands --json`, once hoisted (`app` runs it whole).
            "--json --json commands",
            "--quiet --quiet commands",
            "--debug --debug commands",
            "--no-color --no-color commands",
            "validate --strict --strict",
            "-V -V commands",
        ] {
            assert!(matches(line).is_ok(), "{line}");
        }
        let repo = matches("--repo a --repo b commands").unwrap();
        assert_eq!(
            repo.get_one::<String>("repo").map(String::as_str),
            Some("b")
        );
        let platform = matches("query --platform sentinel --platform=splunk x").unwrap();
        assert_eq!(
            platform
                .subcommand_matches("query")
                .unwrap()
                .get_one::<crate::tree::PlatformValue>("platform")
                .map(|platform| platform.0.as_str()),
            Some("splunk")
        );
        // A repeatable option (`validate --file`) collects every value.
        let files = matches("validate --file a --file=b").unwrap();
        let all: Vec<&String> = files
            .subcommand_matches("validate")
            .unwrap()
            .get_many::<String>("file")
            .unwrap()
            .collect();
        assert_eq!(all, ["a", "b"]);
        // A repeatable option still collects every value.
        let strategies = matches("deploy --strategy PREVIEW --strategy RELEASE").unwrap();
        let all: Vec<&String> = strategies
            .subcommand_matches("deploy")
            .unwrap()
            .get_many::<String>("strategy")
            .unwrap()
            .collect();
        assert_eq!(all, ["PREVIEW", "RELEASE"]);
    }

    #[test]
    fn framework_usage_an_option_value_starts_with_a_dash_only_after_an_equals_sign() {
        let missing = parse("setup skills discover --query --json");
        assert_eq!(missing.failure.message, "--query requires a value.");
        let query = matches("setup skills discover --query=--json").unwrap();
        assert_eq!(
            value(&query, &["setup", "skills", "discover"], "query").map(String::as_str),
            Some("--json")
        );
        // A negative number is a value.
        let limit = matches("query --platform sentinel --limit -1 x").unwrap();
        assert_eq!(
            limit
                .subcommand_matches("query")
                .unwrap()
                .get_one::<i64>("limit"),
            Some(&-1)
        );
        // A choice or a path is missing its value too.
        for line in ["query --platform --json x", "validate --file --strict"] {
            assert!(
                parse(line).failure.message.ends_with("requires a value."),
                "{line}"
            );
        }
    }

    #[test]
    fn framework_usage_a_group_named_alone_lists_its_commands() {
        assert_eq!(
            parse("mcp").failure.message,
            "Missing command: choose from start."
        );
        assert_eq!(
            parse("lsp").failure.message,
            "Missing command: choose from start."
        );
        assert_eq!(
            parse("new").failure.message,
            "Missing command: choose from threat, objective, rule."
        );
        assert_eq!(parse("new").command, "new");
        // The other groups keep the short message, as they always have.
        assert_eq!(parse("rules").failure.message, "Missing command.");
        assert_eq!(parse("migrate").failure.message, "Missing command.");
    }

    #[test]
    fn framework_usage_an_option_after_double_dash_at_a_group() {
        // The group has no such option: an unknown option, in that group.
        let json = parse("validate -- --json");
        assert_eq!(json.failure.code, code::USAGE_UNKNOWN_OPTION);
        assert_eq!(json.failure.message, "Unknown option \"--json\".");
        assert_eq!(json.failure.argument.as_deref(), Some("--json"));
        assert_eq!(json.command, "validate");
        // With the global `--json` before it: the `--json` after `--` is the
        // one at fault.
        let root = root();
        let hoisted = args("--json validate -- --json");
        let error = root
            .clone()
            .try_get_matches_from(std::iter::once("opentide".to_owned()).chain(hoisted.clone()))
            .unwrap_err();
        let described = describe(&root, &hoisted, &error);
        assert_eq!(described.command, "validate");
        assert_eq!(described.failure.code, code::USAGE_UNKNOWN_OPTION);
        // The group's own option there is no command, as the CLI has said.
        let strict = parse("validate -- --strict");
        assert_eq!(strict.failure.code, code::USAGE_UNKNOWN_COMMAND);
        assert_eq!(strict.failure.message, "Unknown command \"--strict\".");
        assert_eq!(strict.command, "validate");
    }

    /// A tree with what opentide's has none of: a hidden option and command,
    /// and two options that conflict.
    fn synthetic() -> Command {
        Command::new("opentide")
            .arg(
                Arg::new("plan")
                    .long("plan")
                    .action(clap::ArgAction::SetTrue)
                    .hide(true),
            )
            .arg(
                Arg::new("place")
                    .long("place")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(Arg::new("repo").long("repo").conflicts_with("data"))
            .arg(Arg::new("data").long("data"))
            .subcommand(Command::new("plumb").hide(true))
            .subcommand(Command::new("deploy"))
    }

    fn synthetic_parse(text: &str) -> UsageError {
        let root = synthetic();
        let error = root
            .clone()
            .try_get_matches_from(std::iter::once("opentide".to_owned()).chain(args(text)))
            .unwrap_err();
        describe(&root, &args(text), &error)
    }

    #[test]
    fn framework_usage_hidden_options_and_commands_are_never_suggested() {
        // `--plam` is closest to the hidden `--plan`: the visible `--place` is offered.
        let option = synthetic_parse("--plam");
        assert_eq!(option.failure.code, code::USAGE_UNKNOWN_OPTION);
        assert_eq!(option.failure.suggestion.as_deref(), Some("--place"));
        let typo = synthetic_parse("--plan-x");
        assert_ne!(typo.failure.suggestion.as_deref(), Some("--plan"));
        // `plumc` is closest to the hidden `plumb`: nothing visible is close.
        let command = synthetic_parse("plumc");
        assert_eq!(command.failure.code, code::USAGE_UNKNOWN_COMMAND);
        assert_eq!(command.failure.suggestion, None);
        assert!(!command.notes.iter().any(|(_, note)| note.contains("plumb")));
    }

    #[test]
    fn framework_usage_conflicts_name_both_options_by_their_flags() {
        let conflict = synthetic_parse("--repo a --data b");
        assert_eq!(conflict.failure.code, code::USAGE_ERROR);
        assert_eq!(
            conflict.failure.message,
            "--repo cannot be used with --data."
        );
        assert_eq!(conflict.failure.argument.as_deref(), Some("--repo"));
    }

    #[test]
    fn framework_usage_a_root_option_is_found_from_a_command() {
        // `--repo` reported in `validate query` is still the root's.
        let root = root();
        let path = args("validate query");
        let arg = find_arg(&root, &path, "--repo <REPO>").unwrap();
        assert_eq!(label(arg), "--repo");
        assert_eq!(label(find_arg(&root, &path, "--live").unwrap()), "--live");
        assert!(find_arg(&root, &path, "--nothing").is_none());
    }
}
