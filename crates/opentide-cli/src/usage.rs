//! clap's parse errors as the CLI contract reports usage errors.
//!
//! Each becomes a [`Failure`] with its `failure.code`, the argument at fault
//! and the closest valid value ([`crate::suggest`], which replaces clap's own
//! suggestion), and the notes the text modes print under `error:`: `help: did
//! you mean …?`, `usage: …` and `help: run 'opentide … --help'`. The messages
//! keep the wording the CLI has always used, so scripts that match them still
//! do. Exit 2.

use crate::envelope::{Failure, code};
use crate::hoist;
use crate::suggest::did_you_mean;
use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Arg, Command};

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

/// `opentide validate [OPTIONS] COMMAND [ARGS]...`: the usage line.
pub fn usage_line(root: &Command, path: &[String]) -> String {
    let command = command_at(root, path);
    let mut line = vec![crate::catalog::PROGRAM.to_owned()];
    line.extend(path.iter().cloned());
    line.push("[OPTIONS]".to_owned());
    for arg in command
        .get_arguments()
        .filter(|arg| arg.is_positional() && !arg.is_hide_set())
    {
        let name = positional_name(arg);
        let choices = choice_names(arg);
        let shown = if arg.is_required_set() && !choices.is_empty() {
            format!("{{{name}}}:<{}>", choices.join("|"))
        } else if arg.is_required_set() {
            name.to_uppercase()
        } else {
            format!("[{name}]")
        };
        line.push(shown);
    }
    if command.get_subcommands().any(|sub| !sub.is_hide_set()) {
        line.push("COMMAND [ARGS]...".to_owned());
    }
    line.join(" ")
}

fn context_string(error: &clap::Error, kind: ContextKind) -> Option<String> {
    match error.get(kind)? {
        ContextValue::String(text) => Some(text.clone()),
        ContextValue::Strings(texts) => texts.first().cloned(),
        _ => None,
    }
}

/// The argument named by clap's `--check <CHECK>` or `<ci_platform>`.
fn find_arg<'a>(command: &'a Command, shown: &str) -> Option<&'a Arg> {
    let word = shown.split_whitespace().next().unwrap_or_default();
    let word = word.split('=').next().unwrap_or_default();
    if word.starts_with('-') {
        return hoist::find_option(command, word);
    }
    let name = word.trim_start_matches('<').trim_end_matches(['>', '.']);
    command.get_arguments().find(|arg| {
        arg.is_positional() && (positional_name(arg) == name || arg.get_id().as_str() == name)
    })
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
    let before = offending
        .and_then(|word| {
            args.iter().position(|arg| {
                *arg == word || arg.split_once('=').is_some_and(|(name, _)| name == word)
            })
        })
        .unwrap_or(args.len());
    let path = hoist::command_words(root, &args[..before]);
    let command = command_at(root, &path);
    let failure = match error.kind() {
        ErrorKind::InvalidSubcommand => {
            let name = context_string(error, ContextKind::InvalidSubcommand).unwrap_or_default();
            let names: Vec<&str> = command
                .get_subcommands()
                .filter(|sub| !sub.is_hide_set())
                .map(Command::get_name)
                .collect();
            Failure {
                suggestion: did_you_mean(&name, names),
                argument: Some(name.clone()),
                ..Failure::new(
                    code::USAGE_UNKNOWN_COMMAND,
                    format!("No such command '{name}'."),
                )
            }
        }
        ErrorKind::UnknownArgument => {
            let name = context_string(error, ContextKind::InvalidArg).unwrap_or_default();
            if name.starts_with('-') {
                let option = name.split('=').next().unwrap_or_default().to_owned();
                let flags = visible_flags(command);
                Failure {
                    suggestion: did_you_mean(&option, flags.iter().map(String::as_str)),
                    argument: Some(option.clone()),
                    ..Failure::new(
                        code::USAGE_UNKNOWN_OPTION,
                        format!("No such option: {option}"),
                    )
                }
            } else if command.get_subcommands().any(|sub| !sub.is_hide_set()) {
                // A word where a group expects its command.
                let names: Vec<&str> = command
                    .get_subcommands()
                    .filter(|sub| !sub.is_hide_set())
                    .map(Command::get_name)
                    .collect();
                Failure {
                    suggestion: did_you_mean(&name, names),
                    argument: Some(name.clone()),
                    ..Failure::new(
                        code::USAGE_UNKNOWN_COMMAND,
                        format!("No such command '{name}'."),
                    )
                }
            } else {
                Failure::new(
                    code::USAGE_ERROR,
                    format!("Got unexpected extra argument(s) ({name})"),
                )
            }
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let shown = context_string(error, ContextKind::InvalidArg).unwrap_or_default();
            let value = context_string(error, ContextKind::InvalidValue).unwrap_or_default();
            let arg = find_arg(command, &shown);
            let label = arg.map_or_else(|| shown.clone(), label);
            let choices = arg.map(choice_names).unwrap_or_default();
            if value.is_empty() && error.kind() == ErrorKind::InvalidValue {
                // `--file` with nothing after it.
                Failure {
                    argument: Some(label.clone()),
                    ..Failure::new(
                        code::USAGE_ERROR,
                        format!("Option '{label}' requires an argument."),
                    )
                }
            } else if choices.is_empty() {
                let kind = arg.map_or("string", crate::catalog::type_name);
                let what = match kind {
                    "integer" => "is not a valid integer",
                    "number" => "is not a valid float",
                    _ => "is not a valid value",
                };
                Failure {
                    argument: Some(label.clone()),
                    ..Failure::new(
                        code::USAGE_INVALID_VALUE,
                        format!("Invalid value for '{label}': '{value}' {what}."),
                    )
                }
            } else {
                let quoted: Vec<String> = choices.iter().map(|c| format!("'{c}'")).collect();
                Failure {
                    suggestion: did_you_mean(&value, choices.iter().map(String::as_str)),
                    argument: Some(label.clone()),
                    ..Failure::new(
                        code::USAGE_INVALID_CHOICE,
                        format!(
                            "Invalid value for '{label}': '{value}' is not one of {}.",
                            quoted.join(", ")
                        ),
                    )
                }
            }
        }
        ErrorKind::MissingRequiredArgument => {
            let shown = context_string(error, ContextKind::InvalidArg).unwrap_or_default();
            let arg = find_arg(command, &shown);
            let label = arg.map_or_else(|| shown.clone(), label);
            let what = if arg.is_some_and(Arg::is_positional) {
                "argument"
            } else {
                "option"
            };
            let choices = arg.map(choice_names).unwrap_or_default();
            let message = if choices.is_empty() {
                format!("Missing {what} '{label}'.")
            } else {
                format!(
                    "Missing {what} '{label}': choose from {}.",
                    choices.join(", ")
                )
            };
            Failure {
                argument: Some(label),
                ..Failure::new(code::USAGE_MISSING_OPTION, message)
            }
        }
        ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            Failure::new(code::USAGE_ERROR, "Missing command.")
        }
        ErrorKind::NoEquals
        | ErrorKind::InvalidUtf8
        | ErrorKind::TooManyValues
        | ErrorKind::TooFewValues
        | ErrorKind::WrongNumberOfValues
        | ErrorKind::ArgumentConflict => {
            let shown = context_string(error, ContextKind::InvalidArg);
            let arg = shown.as_deref().and_then(|shown| find_arg(command, shown));
            let message = match error.kind() {
                ErrorKind::ArgumentConflict => {
                    let other = context_string(error, ContextKind::PriorArg).unwrap_or_default();
                    format!(
                        "Option '{}' cannot be used with '{other}'.",
                        arg.map_or_else(|| shown.clone().unwrap_or_default(), label)
                    )
                }
                _ => first_line(error),
            };
            Failure {
                argument: arg.map(label),
                ..Failure::new(code::USAGE_ERROR, message)
            }
        }
        _ => Failure::new(code::USAGE_ERROR, first_line(error)),
    };
    let mut notes = Vec::new();
    if let Some(suggestion) = &failure.suggestion {
        notes.push(("help".to_owned(), format!("did you mean '{suggestion}'?")));
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
        assert_eq!(typo.failure.message, "No such command 'valdiate'.");
        assert_eq!(typo.failure.suggestion.as_deref(), Some("validate"));
        assert_eq!(typo.command, "");
        assert_eq!(
            typo.notes,
            vec![
                ("help".into(), "did you mean 'validate'?".into()),
                (
                    "usage".into(),
                    "opentide [OPTIONS] COMMAND [ARGS]...".into()
                ),
                ("help".into(), "run 'opentide --help'".into()),
            ]
        );
        let option = parse("validate --strictt");
        assert_eq!(option.failure.code, code::USAGE_UNKNOWN_OPTION);
        assert_eq!(option.failure.message, "No such option: --strictt");
        assert_eq!(option.failure.suggestion.as_deref(), Some("--strict"));
        assert_eq!(option.command, "validate");
        assert_eq!(
            option.notes[1].1,
            "opentide validate [OPTIONS] COMMAND [ARGS]..."
        );
        let root_option = parse("--jsn validate");
        assert_eq!(root_option.failure.suggestion.as_deref(), Some("--json"));
        assert_eq!(
            parse("rules zzzz").failure.code,
            code::USAGE_UNKNOWN_COMMAND
        );
        assert_eq!(
            parse("doctor extra").failure.message,
            "Got unexpected extra argument(s) (extra)"
        );
    }

    #[test]
    fn framework_usage_choices_values_and_missing() {
        let choice = parse("lint --check filenamez");
        assert_eq!(choice.failure.code, code::USAGE_INVALID_CHOICE);
        assert_eq!(
            choice.failure.message,
            "Invalid value for '--check': 'filenamez' is not one of 'filenames', 'metadata', 'placeholders', 'queries'."
        );
        assert_eq!(choice.failure.suggestion.as_deref(), Some("filenames"));
        assert_eq!(choice.notes[1].1, "opentide lint [OPTIONS]");
        let number = parse("query --platform sentinel --limit many x");
        assert_eq!(number.failure.code, code::USAGE_INVALID_VALUE);
        assert_eq!(
            number.failure.message,
            "Invalid value for '--limit': 'many' is not a valid integer."
        );
        let float = parse("query --platform sentinel --timeout soon x");
        assert!(float.failure.message.ends_with("is not a valid float."));
        let missing = parse("query x");
        assert_eq!(missing.failure.code, code::USAGE_MISSING_OPTION);
        assert_eq!(
            missing.failure.message,
            "Missing option '--platform': choose from sentinel, splunk, crowdstrike, defender_for_endpoint, sentinel_one, carbon_black_cloud, harfanglab, elastic, sysdig."
        );
        assert_eq!(missing.notes[0].1, "opentide query [OPTIONS] [query]");
        let argument = parse("setup ci --yes");
        assert_eq!(
            argument.failure.message,
            "Missing argument 'ci_platform': choose from github, gitlab, azure."
        );
        assert_eq!(
            argument.notes[0].1,
            "opentide setup ci [OPTIONS] {ci_platform}:<github|gitlab|azure>"
        );
        let group = parse("rules");
        assert_eq!(group.failure.message, "Missing command.");
        assert_eq!(
            group.notes[0].1,
            "opentide rules [OPTIONS] COMMAND [ARGS]..."
        );
        let shown = parse("setup skills show");
        assert_eq!(shown.failure.message, "Missing argument 'name'.");
        assert_eq!(
            shown.notes[0].1,
            "opentide setup skills show [OPTIONS] NAME"
        );
    }

    #[test]
    fn framework_usage_other_errors_keep_clap_words() {
        let missing_value = parse("validate --file");
        assert_eq!(missing_value.failure.code, code::USAGE_ERROR);
        assert_eq!(
            missing_value.failure.message,
            "Option '--file' requires an argument."
        );
        assert_eq!(missing_value.failure.argument.as_deref(), Some("--file"));
        let conflict = parse("--repo=a --repo b validate");
        assert!(!conflict.failure.message.starts_with("error"));
    }
}
