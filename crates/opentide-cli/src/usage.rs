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

/// `opentide validate [OPTIONS] [COMMAND]`: clap's usage of the command at
/// `path`, as its `--help` shows it, without the `Usage:` in front.
pub fn usage_line(root: &Command, path: &[String]) -> String {
    fn usage_of(command: &mut Command, path: &[String]) -> clap::builder::StyledStr {
        match path.split_first() {
            Some((first, rest)) => match command.find_subcommand_mut(first) {
                Some(sub) => usage_of(sub, rest),
                None => command.render_usage(),
            },
            None => command.render_usage(),
        }
    }
    let mut root = root.clone();
    // Built, every command knows its parents' names (`opentide validate`).
    root.build();
    usage_of(&mut root, path)
        .to_string()
        .lines()
        .map(|line| line.trim().trim_start_matches("Usage:").trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
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

/// `--check <CHECK>` → `--check`, `<ci_platform>` → `ci_platform`,
/// `--json=1` → `--json`.
fn argument_name(shown: &str) -> String {
    let word = shown.split_whitespace().next().unwrap_or_default();
    let word = word.split('=').next().unwrap_or_default();
    word.trim_start_matches('<')
        .trim_end_matches(['>', '.'])
        .to_owned()
}

/// clap's suggestions without hidden options and commands: a hidden one is
/// removed or internal, never to be offered.
fn drop_hidden_suggestions(error: &mut clap::Error, root: &Command, path: &[String]) {
    let visible_option = |name: &str| {
        let long = name.trim_start_matches('-');
        (0..=path.len()).any(|depth| {
            command_at(root, &path[..depth])
                .get_arguments()
                .any(|arg| !arg.is_hide_set() && arg.get_long() == Some(long))
        })
    };
    let command = command_at(root, path);
    let visible_command = |name: &str| {
        command
            .find_subcommand(name)
            .is_some_and(|sub| !sub.is_hide_set())
    };
    for (kind, visible) in [
        (
            ContextKind::SuggestedArg,
            &visible_option as &dyn Fn(&str) -> bool,
        ),
        (ContextKind::SuggestedSubcommand, &visible_command),
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
}

/// The failure for a clap error, in the command `args` named.
pub fn describe(root: &Command, args: &[String], mut error: clap::Error) -> UsageError {
    let path = crate::app::command_words(root, args);
    let command = command_at(root, &path);
    drop_hidden_suggestions(&mut error, root, &path);
    let error = &error;
    let argument = match error.kind() {
        ErrorKind::InvalidSubcommand => context(error, ContextKind::InvalidSubcommand),
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
            if error.get(ContextKind::ValidValue).is_some() =>
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
            format!("missing command: choose from {}", names.join(", "))
        }
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
        assert_eq!(
            missing.failure.message,
            "the following required arguments were not provided: --platform <PLATFORM>"
        );
    }

    #[test]
    fn framework_usage_hidden_options_and_commands_are_never_suggested() {
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
        // `--plam` is closest to the hidden `--plan`: the visible `--place` is offered.
        let option = parse_in(&synthetic, "--plam");
        assert_eq!(option.failure.code, code::USAGE_UNKNOWN_OPTION);
        assert_ne!(option.failure.suggestion.as_deref(), Some("--plan"));
        // `plumc` is closest to the hidden `plumb`.
        let command = parse_in(&synthetic, "plumc");
        assert_eq!(command.failure.code, code::USAGE_UNKNOWN_COMMAND);
        assert_ne!(command.failure.suggestion.as_deref(), Some("plumb"));
    }

    #[test]
    fn framework_usage_line_is_clap_usage() {
        let root = root();
        assert_eq!(usage_line(&root, &[]), "opentide [OPTIONS] <COMMAND>");
        assert_eq!(
            usage_line(&root, &args("setup ci")),
            "opentide setup ci [OPTIONS] <ci_platform>"
        );
    }
}
