//! Global flags typed after the command (`opentide validate --json`).
//!
//! `--json`, `--no-color`, `--debug`, `--quiet` and `--verbose` are accepted anywhere
//! before `--`, except as the value of the option before them (`query --query
//! --json` searches for `--json`) or where the command defines the flag
//! itself. Root options that take a value (`--repo`, `--data`, `--proxy`)
//! stay before the command. The hoisted flags move in front of everything,
//! so clap reads them as the root's.

use clap::{Arg, ArgAction, Command};

/// The flags hoisted to the root.
pub const HOISTED_FLAGS: &[&str] = &["--json", "--no-color", "--debug", "--quiet", "--verbose"];

/// Whether `arg` reads a value after it.
pub fn takes_value(arg: &Arg) -> bool {
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
pub fn find_option<'a>(command: &'a Command, name: &str) -> Option<&'a Arg> {
    command.get_arguments().find(|arg| {
        if arg.is_positional() {
            return false;
        }
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

/// The index of the first token after the root's own options: the command, or `--`.
pub fn root_options_end(root: &Command, args: &[String]) -> usize {
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if token == "--" || token == "-" || !token.starts_with('-') {
            return index;
        }
        let (name, has_value) = match token.split_once('=') {
            Some((name, _)) => (name, true),
            None => (token.as_str(), false),
        };
        let takes = find_option(root, name).is_some_and(takes_value);
        index += if takes && !has_value { 2 } else { 1 };
    }
    index.min(args.len())
}

/// `args` with every hoisted flag typed after the command moved in front.
pub fn hoist(root: &Command, args: &[String]) -> Vec<String> {
    let start = root_options_end(root, args);
    let end = args
        .iter()
        .position(|token| token == "--")
        .unwrap_or(args.len());
    if start >= end
        || !args[start + 1..end]
            .iter()
            .any(|token| HOISTED_FLAGS.contains(&token.as_str()))
    {
        return args.to_vec();
    }
    let mut hoisted: Vec<String> = Vec::new();
    let mut kept: Vec<String> = vec![args[start].clone()];
    let mut command = root.find_subcommand(&args[start]);
    let mut index = start + 1;
    while index < end {
        let token = &args[index];
        index += 1;
        let own = command.and_then(|command| find_option(command, token));
        if HOISTED_FLAGS.contains(&token.as_str()) && own.is_none() {
            hoisted.push(token.clone());
            continue;
        }
        kept.push(token.clone());
        if token.starts_with('-') && token != "-" {
            let (name, has_value) = match token.split_once('=') {
                Some((name, _)) => (name, true),
                None => (token.as_str(), false),
            };
            let option = command.and_then(|command| find_option(command, name));
            if option.is_some_and(takes_value) && !has_value && index < end {
                kept.push(args[index].clone());
                index += 1;
            }
            continue;
        }
        if let Some(sub) = command.and_then(|command| command.find_subcommand(token)) {
            command = Some(sub);
        }
    }
    let mut out = hoisted;
    out.extend_from_slice(&args[..start]);
    out.extend(kept);
    out.extend_from_slice(&args[end..]);
    out
}

/// `args` without each `--` typed where a group expects its command, before
/// that command's name: `opentide -- commands` and `validate -- query` run
/// the command, as they always have. A `--` before an option-shaped word
/// (`validate -- --json`) stays: that word is no command, and the usage
/// error names it. A `--` after a command's own options or arguments is the
/// usual end of options, left to clap.
pub fn drop_group_separators(root: &Command, args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(args.len());
    let start = root_options_end(root, args);
    out.extend_from_slice(&args[..start]);
    let mut command = root;
    let mut index = start;
    while index < args.len() {
        let token = &args[index];
        index += 1;
        let groups = command.get_subcommands().next().is_some();
        if token == "--" {
            let next = args.get(index);
            if groups && next.is_some_and(|word| !word.starts_with('-')) {
                continue;
            }
            out.extend_from_slice(&args[index - 1..]);
            return out;
        }
        out.push(token.clone());
        if token.starts_with('-') && token != "-" {
            let (name, has_value) = match token.split_once('=') {
                Some((name, _)) => (name, true),
                None => (token.as_str(), false),
            };
            if find_option(command, name).is_some_and(takes_value)
                && !has_value
                && let Some(value) = args.get(index)
            {
                out.push(value.clone());
                index += 1;
            }
            continue;
        }
        match command.find_subcommand(token) {
            Some(sub) => command = sub,
            None => {
                out.extend_from_slice(&args[index..]);
                return out;
            }
        }
    }
    out
}

/// The command path `args` name (`["generate", "docs", "rules"]`): only words
/// that name a subcommand count, and the hoisted flags are skipped.
pub fn command_words(root: &Command, args: &[String]) -> Vec<String> {
    let mut words = Vec::new();
    let mut command = root;
    for token in &args[root_options_end(root, args)..] {
        if HOISTED_FLAGS.contains(&token.as_str()) {
            continue;
        }
        if token.starts_with('-') {
            break;
        }
        let Some(sub) = command.find_subcommand(token) else {
            break;
        };
        words.push(token.clone());
        command = sub;
    }
    words
}

/// The leading words before the first option, whatever they name: what the
/// output mode reads (`mcp start`).
pub fn leading_words(root: &Command, args: &[String]) -> Vec<String> {
    args[root_options_end(root, args)..]
        .iter()
        .take_while(|token| !token.starts_with('-'))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::root;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn framework_hoist_moves_global_flags_in_front() {
        let root = root();
        assert_eq!(
            hoist(&root, &args("validate --json")),
            args("--json validate")
        );
        assert_eq!(
            hoist(&root, &args("--repo r validate query --debug --quiet")),
            args("--debug --quiet --repo r validate query")
        );
        assert_eq!(
            hoist(&root, &args("validate --no-color --strict")),
            args("--no-color validate --strict")
        );
    }

    #[test]
    fn framework_hoist_leaves_values_and_the_rest_after_double_dash() {
        let root = root();
        // `--query` takes a value: `--json` is it.
        assert_eq!(
            hoist(&root, &args("setup skills discover --query --json")),
            args("setup skills discover --query --json")
        );
        assert_eq!(
            hoist(&root, &args("explain -- --json")),
            args("explain -- --json")
        );
        assert_eq!(
            hoist(&root, &args("--json validate")),
            args("--json validate")
        );
        assert_eq!(hoist(&root, &args("")), args(""));
        assert_eq!(
            hoist(&root, &args("query --platform=sentinel --json x")),
            args("--json query --platform=sentinel x")
        );
    }

    #[test]
    fn framework_hoist_skips_root_options_with_values() {
        let root = root();
        assert_eq!(
            root_options_end(&root, &args("--repo x --json validate")),
            3
        );
        assert_eq!(root_options_end(&root, &args("--repo=x validate")), 1);
        assert_eq!(root_options_end(&root, &args("--repo")), 1);
        assert_eq!(root_options_end(&root, &args("--unknown validate")), 1);
        assert_eq!(root_options_end(&root, &args("-")), 0);
    }

    #[test]
    fn framework_command_words_name_commands_only() {
        let root = root();
        assert_eq!(
            command_words(&root, &args("generate docs rules --x")),
            args("generate docs rules")
        );
        assert_eq!(
            command_words(&root, &args("explain invalid_ref")),
            args("explain")
        );
        assert_eq!(
            command_words(&root, &args("--json validate --json query")),
            args("validate query")
        );
        assert_eq!(
            command_words(&root, &args("valdiate")),
            Vec::<String>::new()
        );
        assert_eq!(
            leading_words(&root, &args("--repo r mcp start --x")),
            args("mcp start")
        );
    }

    #[test]
    fn framework_hoist_drops_a_separator_before_a_command_name() {
        let root = root();
        let dropped = |text: &str| drop_group_separators(&root, &args(text));
        assert_eq!(dropped("-- commands"), args("commands"));
        assert_eq!(dropped("--repo r -- commands"), args("--repo r commands"));
        assert_eq!(dropped("validate -- query"), args("validate query"));
        assert_eq!(
            dropped("validate --strict -- query x"),
            args("validate --strict query x")
        );
        // An option-shaped word after it is no command: the `--` stays.
        assert_eq!(dropped("validate -- --json"), args("validate -- --json"));
        // A command's own arguments: the end of options, for clap.
        assert_eq!(dropped("explain -- x"), args("explain -- x"));
        assert_eq!(
            dropped("query --platform -- -- x"),
            args("query --platform -- -- x")
        );
        assert_eq!(dropped("validate query -- x"), args("validate query -- x"));
    }

    #[test]
    fn framework_find_option_reads_long_and_short() {
        let root = root();
        let setup = root.find_subcommand("setup").unwrap();
        assert!(find_option(setup, "-C").is_some());
        assert!(find_option(setup, "--path").is_some());
        assert!(find_option(setup, "-CC").is_none());
        assert!(find_option(setup, "path").is_none());
    }
}
