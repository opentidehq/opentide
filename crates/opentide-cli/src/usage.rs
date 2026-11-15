//! clap's parse errors under the CLI contract: exit `2` and, under `--json`,
//! the documented envelope (`failure.code`, `argument`, `suggestion`). The
//! words, the usage line and the suggestion are clap's own; the text modes
//! print clap's rendered error as it is.

use crate::envelope::{Failure, code};
use clap::Command;
use clap::error::{ContextKind, ContextValue, ErrorKind};

/// A usage error, ready to print.
#[derive(Clone, Debug)]
pub struct UsageError {
    /// The command path the error is about (`validate`), empty for the root.
    pub command: String,
    /// The `failure` object.
    pub failure: Failure,
    /// clap's rendered error, for the text modes.
    pub rendered: clap::builder::StyledStr,
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

/// A context value of `error`; of a list, the last: clap lists its
/// suggestions closest last.
fn context(error: &clap::Error, kind: ContextKind) -> Option<String> {
    match error.get(kind)? {
        ContextValue::String(text) => Some(text.clone()),
        ContextValue::Strings(texts) => texts.last().cloned(),
        _ => None,
    }
}

/// `--check <CHECK>` → `--check`, `<ci_platform>` or `[name]` → the name,
/// `--json=1` → `--json`.
fn argument_name(shown: &str) -> String {
    let word = shown.split_whitespace().next().unwrap_or_default();
    let word = word.split('=').next().unwrap_or_default();
    word.trim_start_matches(['<', '['])
        .trim_end_matches(['>', ']', '.'])
        .to_owned()
}

/// Every hidden long option in `command` and below it.
fn hidden_longs(command: &Command, into: &mut Vec<String>) {
    into.extend(
        command
            .get_arguments()
            .filter(|arg| arg.is_hide_set())
            .filter_map(|arg| arg.get_long().map(|long| format!("--{long}"))),
    );
    for sub in command.get_subcommands() {
        hidden_longs(sub, into);
    }
}

/// clap's error context without hidden options and commands (a hidden one is
/// removed or internal, never to be offered), and a value's suggestion by the
/// command line's one rule ([`crate::suggest`]: case and `-`/`_` do not count)
/// where clap's Jaro finds none.
fn tidy_context(error: &mut clap::Error, root: &Command, path: &[String]) {
    let mut hidden = Vec::new();
    hidden_longs(root, &mut hidden);
    let command = command_at(root, path);
    let visible_command = |name: &str| {
        command
            .find_subcommand(name)
            .is_some_and(|sub| !sub.is_hide_set())
    };
    let visible_option = |name: &str| !hidden.iter().any(|long| long == name);
    for (kind, visible) in [
        (
            ContextKind::SuggestedArg,
            &visible_option as &dyn Fn(&str) -> bool,
        ),
        (ContextKind::SuggestedSubcommand, &visible_command),
        (ContextKind::ValidSubcommand, &visible_command),
    ] {
        let kept: Vec<String> = match error.remove(kind) {
            Some(ContextValue::String(name)) => vec![name],
            Some(ContextValue::Strings(names)) => names,
            _ => continue,
        }
        .into_iter()
        .filter(|name| visible(name))
        .collect();
        if !kept.is_empty() {
            error.insert(kind, ContextValue::Strings(kept));
        }
    }
    // `tip: 'deploy --plan' exists`: a tip that names a hidden option goes.
    if let Some(ContextValue::StyledStrs(tips)) = error.remove(ContextKind::Suggested) {
        let kept: Vec<_> = tips
            .into_iter()
            .filter(|tip| {
                let text = tip.to_string();
                !hidden.iter().any(|long| {
                    text.split(|c: char| c.is_whitespace() || c == '\'')
                        .any(|word| word == long)
                })
            })
            .collect();
        if !kept.is_empty() {
            error.insert(ContextKind::Suggested, ContextValue::StyledStrs(kept));
        }
    }
    if error.kind() == ErrorKind::InvalidValue
        && error.get(ContextKind::SuggestedValue).is_none()
        && let (Some(ContextValue::String(value)), Some(ContextValue::Strings(valid))) = (
            error.get(ContextKind::InvalidValue),
            error.get(ContextKind::ValidValue),
        )
        && let Some(closest) = crate::suggest::did_you_mean(value, valid.iter().map(String::as_str))
    {
        error.insert(ContextKind::SuggestedValue, ContextValue::String(closest));
    }
}

/// Whether clap shows `arg` as `name` ([`argument_name`]): `--long`, `-s` for
/// an option with no long name, or a positional by its value name (`<NAME>`)
/// or its id.
fn is_shown_as(arg: &clap::Arg, name: &str) -> bool {
    if let Some(long) = arg.get_long() {
        return name.strip_prefix("--") == Some(long);
    }
    if let Some(short) = arg.get_short() {
        return name.strip_prefix('-').is_some_and(|rest| {
            let mut chars = rest.chars();
            chars.next() == Some(short) && chars.next().is_none()
        });
    }
    arg.get_id().as_str() == name
        || arg
            .get_value_names()
            .is_some_and(|names| names.iter().any(|shown| shown.as_str() == name))
}

/// `--platform: choose from sentinel, …` for each missing required argument
/// that takes one of a fixed set of values: clap names a missing argument and
/// its usage but not its choices, which the oracle's missing-option error
/// listed. A hidden value is not listed.
fn choice_hints(error: &clap::Error, command: &Command) -> Vec<String> {
    if error.kind() != ErrorKind::MissingRequiredArgument {
        return Vec::new();
    }
    let Some(ContextValue::Strings(shown)) = error.get(ContextKind::InvalidArg) else {
        return Vec::new();
    };
    shown
        .iter()
        .filter_map(|shown| {
            let name = argument_name(shown);
            let arg = command
                .get_arguments()
                .find(|arg| is_shown_as(arg, &name))?;
            let values: Vec<String> = arg
                .get_possible_values()
                .iter()
                .filter(|value| !value.is_hide_set())
                .map(|value| value.get_name().to_owned())
                .collect();
            (!values.is_empty()).then(|| format!("{name}: choose from {}", values.join(", ")))
        })
        .collect()
}

/// The failure for a clap error, in the command `args` named.
pub fn describe(root: &Command, args: &[String], mut error: clap::Error) -> UsageError {
    let path = crate::app::command_words(root, args);
    let command = command_at(root, &path);
    tidy_context(&mut error, root, &path);
    // The choices a missing option takes, as a tip in the text modes and
    // after the message in the machine ones.
    let hints = choice_hints(&error, command);
    if !hints.is_empty() {
        let mut tips = match error.remove(ContextKind::Suggested) {
            Some(ContextValue::StyledStrs(tips)) => tips,
            _ => Vec::new(),
        };
        tips.extend(hints.iter().cloned().map(Into::into));
        error.insert(ContextKind::Suggested, ContextValue::StyledStrs(tips));
    }
    let error = &error;
    let argument = match (error.kind(), error.get(ContextKind::InvalidArg)) {
        (ErrorKind::InvalidSubcommand, _) => context(error, ContextKind::InvalidSubcommand),
        // Several missing: the first, as `--help` lists them.
        (_, Some(ContextValue::Strings(shown))) => shown.first().cloned(),
        _ => context(error, ContextKind::InvalidArg),
    }
    .map(|shown| argument_name(&shown));
    let suggestion = context(error, ContextKind::SuggestedSubcommand)
        .or_else(|| context(error, ContextKind::SuggestedArg))
        .or_else(|| context(error, ContextKind::SuggestedValue));
    let empty_value = context(error, ContextKind::InvalidValue).is_none_or(|v| v.is_empty());
    let failure_code = match error.kind() {
        ErrorKind::InvalidSubcommand => code::USAGE_UNKNOWN_COMMAND,
        ErrorKind::UnknownArgument if argument.as_deref().is_some_and(|a| a.starts_with('-')) => {
            code::USAGE_UNKNOWN_OPTION
        }
        ErrorKind::UnknownArgument if command.has_subcommands() => code::USAGE_UNKNOWN_COMMAND,
        ErrorKind::InvalidValue if empty_value => code::USAGE_ERROR,
        ErrorKind::InvalidValue | ErrorKind::ValueValidation
            if matches!(
                error.get(ContextKind::ValidValue),
                Some(ContextValue::Strings(valid)) if !valid.is_empty()
            ) =>
        {
            code::USAGE_INVALID_CHOICE
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => code::USAGE_INVALID_VALUE,
        ErrorKind::MissingRequiredArgument => code::USAGE_MISSING_OPTION,
        _ => code::USAGE_ERROR,
    };
    let message = match error.kind() {
        // A group named alone (`opentide --json mcp`): clap renders its help.
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            let names: Vec<&str> = command
                .get_subcommands()
                .filter(|sub| !sub.is_hide_set())
                .map(Command::get_name)
                .collect();
            if names.is_empty() {
                "missing command".to_owned()
            } else {
                format!("missing command: choose from {}", names.join(", "))
            }
        }
        _ if !hints.is_empty() => format!("{}. {}", first_line(error), hints.join(". ")),
        _ => first_line(error),
    };
    // clap renders the group's help for this kind; a person gets the help
    // (`app`), the modes that read errors get one line.
    let rendered = match error.kind() {
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => format!("error: {message}\n").into(),
        _ => error.render(),
    };
    UsageError {
        command: path.join(" "),
        failure: Failure {
            argument,
            suggestion,
            ..Failure::new(failure_code, message)
        },
        rendered,
    }
}

/// clap's message on one line, without its `error: `, tips and usage.
fn first_line(error: &clap::Error) -> String {
    let text = error.render().to_string();
    let text = text.strip_prefix("error: ").unwrap_or(&text);
    text.lines()
        .map(str::trim)
        .take_while(|line| !line.is_empty() && !line.starts_with("Usage:"))
        .filter(|line| !line.starts_with("tip:") && !line.starts_with("For more information"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::root;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn parse_in(root: &Command, text: &str) -> UsageError {
        let error = root
            .clone()
            .try_get_matches_from(std::iter::once("opentide".to_owned()).chain(args(text)))
            .unwrap_err();
        describe(root, &args(text), error)
    }

    fn parse(text: &str) -> UsageError {
        parse_in(&root(), text)
    }

    /// Each clap error kind maps onto the documented `failure.code`, with
    /// the argument at fault and clap's closest suggestion.
    #[test]
    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
    fn framework_usage_codes_arguments_and_suggestions() {
        for (line, command, failure_code, argument, suggestion) in [
            (
                "valdiate",
                "",
                code::USAGE_UNKNOWN_COMMAND,
                Some("valdiate"),
                Some("validate"),
            ),
            (
                "rules zzzz",
                "rules",
                code::USAGE_UNKNOWN_COMMAND,
                Some("zzzz"),
                None,
            ),
            (
                "validate --strictt",
                "validate",
                code::USAGE_UNKNOWN_OPTION,
                Some("--strictt"),
                Some("--strict"),
            ),
            (
                "--jsn validate",
                "",
                code::USAGE_UNKNOWN_OPTION,
                Some("--jsn"),
                Some("--json"),
            ),
            (
                "doctor extra",
                "doctor",
                code::USAGE_ERROR,
                Some("extra"),
                None,
            ),
            (
                "lint --check filenamez",
                "lint",
                code::USAGE_INVALID_CHOICE,
                Some("--check"),
                Some("filenames"),
            ),
            (
                "query --platform sentinel --limit many x",
                "query",
                code::USAGE_INVALID_VALUE,
                Some("--limit"),
                None,
            ),
            (
                "query x",
                "query",
                code::USAGE_MISSING_OPTION,
                Some("--platform"),
                None,
            ),
            (
                "setup ci --yes",
                "setup ci",
                code::USAGE_MISSING_OPTION,
                Some("ci_platform"),
                None,
            ),
            (
                "validate --file",
                "validate",
                code::USAGE_ERROR,
                Some("--file"),
                None,
            ),
            (
                "--json=1 commands",
                "",
                code::USAGE_ERROR,
                Some("--json"),
                None,
            ),
            ("rules", "rules", code::USAGE_ERROR, None, None),
        ] {
            let problem = parse(line);
            assert_eq!(problem.command, command, "{line}");
            assert_eq!(problem.failure.code, failure_code, "{line}");
            assert_eq!(problem.failure.argument.as_deref(), argument, "{line}");
            assert_eq!(problem.failure.suggestion.as_deref(), suggestion, "{line}");
            // The message is clap's, on one line; the text modes print
            // clap's whole rendering.
            assert!(!problem.failure.message.contains('\n'), "{line}");
            assert!(
                problem.rendered.to_string().starts_with("error: "),
                "{line}"
            );
        }
        let missing = parse("query x");
        let platforms = opentide_schema::platforms::ids().join(", ");
        assert_eq!(
            missing.failure.message,
            format!(
                "the following required arguments were not provided: --platform <PLATFORM>. \
                 --platform: choose from {platforms}"
            )
        );
        assert!(
            missing
                .rendered
                .to_string()
                .contains(&format!("tip: --platform: choose from {platforms}")),
            "{}",
            missing.rendered
        );
    }

    /// Every required option or argument with a fixed set of values names the
    /// set when it is missing (the oracle did, in every mode).
    #[test]
    fn framework_usage_a_missing_choice_lists_its_choices() {
        fn walk(command: &Command, path: &mut Vec<String>, found: &mut Vec<(String, String)>) {
            for arg in command.get_arguments() {
                if arg.is_required_set() && !arg.get_possible_values().is_empty() {
                    found.push((path.join(" "), arg.get_id().to_string()));
                }
            }
            for sub in command.get_subcommands() {
                path.push(sub.get_name().to_owned());
                walk(sub, path, found);
                path.pop();
            }
        }
        let mut found = Vec::new();
        walk(&root(), &mut Vec::new(), &mut found);
        assert_eq!(
            found,
            [
                ("query".to_owned(), "platform".to_owned()),
                ("deploy metadata".to_owned(), "platform".to_owned()),
                ("setup ci".to_owned(), "ci_platform".to_owned()),
            ]
        );
        let ci = parse("setup ci --yes");
        assert_eq!(ci.failure.code, code::USAGE_MISSING_OPTION);
        assert!(
            ci.failure.message.contains("ci_platform: choose from "),
            "{}",
            ci.failure.message
        );
        assert!(
            ci.rendered
                .to_string()
                .contains("tip: ci_platform: choose from ")
        );
        let metadata = parse("deploy metadata");
        assert!(
            metadata.failure.message.contains("platform: choose from "),
            "{}",
            metadata.failure.message
        );
        // A missing option with no fixed set says nothing more.
        let plain = parse("setup skills show");
        assert_eq!(plain.failure.code, code::USAGE_MISSING_OPTION);
        assert!(
            !plain.failure.message.contains("choose from"),
            "{}",
            plain.failure.message
        );
    }

    /// The choices are found by how clap shows the argument, not by its id:
    /// a positional with a value name of its own, and an option with a short
    /// name only.
    #[test]
    fn framework_usage_choice_hints_find_an_argument_as_it_is_shown() {
        use clap::Arg;
        let command = Command::new("x")
            .arg(
                Arg::new("kind")
                    .value_name("what")
                    .required(true)
                    .value_parser(["a", "b"]),
            )
            .arg(
                Arg::new("level")
                    .short('l')
                    .required(true)
                    .value_parser(["low", "high"]),
            );
        let Err(error) = command.clone().try_get_matches_from(["x"]) else {
            panic!("x needs its arguments");
        };
        let mut hints = choice_hints(&error, &command);
        hints.sort();
        assert_eq!(
            hints,
            ["-l: choose from low, high", "what: choose from a, b"]
        );
    }

    #[test]
    fn framework_usage_hidden_options_and_commands_are_never_named() {
        let synthetic = Command::new("opentide")
            .arg(
                clap::Arg::new("plan")
                    .long("plan")
                    .action(clap::ArgAction::SetTrue)
                    .hide(true),
            )
            .arg(
                clap::Arg::new("place")
                    .long("place")
                    .action(clap::ArgAction::SetTrue),
            )
            .subcommand(Command::new("plumb").hide(true))
            .subcommand(Command::new("deploy"));
        // `--plam` is closest to the hidden `--plan`: clap keeps only its
        // best match, so nothing is suggested.
        let option = parse_in(&synthetic, "--plam");
        assert_eq!(option.failure.code, code::USAGE_UNKNOWN_OPTION);
        assert_eq!(option.failure.suggestion, None);
        assert!(!option.rendered.to_string().contains("--plan"));
        let command = parse_in(&synthetic, "plumc");
        assert_eq!(command.failure.code, code::USAGE_UNKNOWN_COMMAND);
        assert_eq!(command.failure.suggestion, None);
        assert!(!command.rendered.to_string().contains("plumb"));
        // The tree's own: the hidden commands are not listed, and the
        // removed `--plan` of `deploy` is not offered from the root.
        let bare = parse("");
        let text = format!("{} {}", bare.failure.message, bare.rendered);
        for hidden in ["document", "export", "extract"] {
            assert!(!text.contains(hidden), "{text}");
        }
        let removed = parse("--plan deploy").rendered.to_string();
        assert!(!removed.contains("tip:"), "{removed}");
    }

    #[test]
    fn framework_usage_a_value_suggestion_ignores_case() {
        let upper = parse("lint --check FILENAMES");
        assert_eq!(upper.failure.code, code::USAGE_INVALID_CHOICE);
        assert_eq!(upper.failure.suggestion.as_deref(), Some("filenames"));
        assert!(upper.rendered.to_string().contains("'filenames'"));
    }
}
