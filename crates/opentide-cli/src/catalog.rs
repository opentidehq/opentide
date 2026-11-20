//! `opentide commands`: the command tree as a document, read from clap.
//!
//! Every visible command of [`crate::tree`], depth first in the order `--help`
//! lists them, with its arguments, options (types, choices, defaults,
//! environment variables) and its first example. Each command's
//! `output_schema` names the JSON Schema of its `--json` document in `$defs`
//! ([`crate::schemas`]). Plan §3 invariant 2: the document is byte-identical
//! to the oracle's, or differs by approved additions only.

use crate::json::Json;
use crate::tree::Cli;
use crate::tree_meta;
use clap::{Arg, ArgAction, Command, CommandFactory};

/// The program name.
pub const PROGRAM: &str = "opentide";

/// Agent detection's variables, the catalogue's meaning of each.
const AGENT_MEANING: &str = "Set by a coding agent: selects agent output mode";

/// Link schemes of code frames (`OPENTIDE_LINKS`).
pub const LINK_SCHEMES: &[&str] = &["file", "vscode", "cursor", "none"];

/// The environment variables the CLI reads, the root options' own included.
pub fn environment() -> Vec<(String, String)> {
    let mut modes: Vec<&str> = crate::mode::OUTPUT_ENV_VALUES.to_vec();
    modes.sort_unstable();
    let mut rows: Vec<(String, String)> = [
        (
            "OPENTIDE_OUTPUT",
            format!("Output mode: {}", modes.join("|")),
        ),
        ("OPENTIDE_DEBUG", "1 for debug logging, like --debug".into()),
        (
            "NO_COLOR",
            "Any non-empty value turns colour off, like --no-color".into(),
        ),
        (
            "FORCE_COLOR",
            "0, false, no or off turns colour off; any other value forces it in human and \
             plain output; NO_COLOR and --no-color win"
                .into(),
        ),
        (
            "CLICOLOR_FORCE",
            "Any value but 0 forces colour, like FORCE_COLOR=1; FORCE_COLOR wins".into(),
        ),
        (
            "OPENTIDE_JSON_INDENT",
            "0 for one-line JSON, 2 for indented; default: indented on a terminal".into(),
        ),
        ("OPENTIDE_REPO_ROOT", "Repository root, like --repo".into()),
        (
            "OPENTIDE_DATA_ROOT",
            "Data root, like --data: only --technique completion reads it".into(),
        ),
        ("OPENTIDE_PROXY", "HTTP(S) proxy, like --proxy".into()),
        (
            "OPENTIDE_TIDE_WORKSPACE",
            "Folder whose objects are read, when not the repository root".into(),
        ),
        (
            "OPENTIDE_LINKS",
            format!(
                "Link scheme in code frames: {}; default vscode in VS Code, else file",
                LINK_SCHEMES.join("|")
            ),
        ),
        (
            "OPENTIDE_LOG_JSON",
            "1 for one JSON object per log line on stderr".into(),
        ),
        (
            "OPENTIDE_VALIDATE_WORKERS",
            "Most threads validate uses: a number or auto".into(),
        ),
        (
            "OPENTIDE_VALIDATE_PARALLEL_THRESHOLD",
            "Fewest objects before validate runs in parallel".into(),
        ),
        (
            "OPENTIDE_QUERY_CHECK_TIMEOUT",
            "Seconds each validate query --live check may take, like --check-timeout".into(),
        ),
        (
            "OPENTIDE_PROGRESS",
            "0 turns terminal progress (OSC 9;4) off; 1 sends it to any terminal; json writes \
             progress events on stderr"
                .into(),
        ),
    ]
    .into_iter()
    .map(|(name, meaning)| (name.to_owned(), meaning))
    .collect();
    rows.extend(
        crate::mode::AGENT_VARIABLES
            .iter()
            .map(|name| ((*name).to_owned(), AGENT_MEANING.to_owned())),
    );
    rows
}

/// One visible command, with its path.
pub struct Entry {
    /// `generate docs rules`.
    pub path: String,
    /// The clap command.
    pub command: Command,
}

/// The root command: the tree, parsed as the CLI always has
/// ([`parse_settings`]).
pub fn root() -> Command {
    parse_settings(Cli::command())
}

/// The single-value options that refuse to be given twice: they choose where
/// a command acts, and the last of two would drop the first without a word
/// (`deploy --platform elastic --platform splunk` plans only `splunk`, #1729).
/// Every other option keeps the last value it is given.
const REPEAT_IS_AN_ERROR: [&str; 1] = ["platform"];

/// What `--help` says of itself, on every command.
pub const HELP_FLAG_HELP: &str = "Print help";

/// clap's settings for how `command` and everything under it parse:
///
/// - an option or flag given twice keeps the last value (`--json commands
///   --json`, `--repo a --repo b`), as it always has; a repeatable option
///   (`--strategy`) still collects every value. The exception is
///   `REPEAT_IS_AN_ERROR`: `--platform` given twice is a usage error naming
///   it;
/// - a negative number is a value (`--limit -1` is a number out of range);
///   any other word that starts with `-` is an option, so `--query --json`
///   is missing its value (`--query=--json` searches for `--json`);
/// - `--json`, `--no-color`, `--debug`, `--quiet` and `--verbose` are
///   global: they may follow the command (`validate --json`);
/// - `--help` is the one help option, on every command, and there is no
///   `help` subcommand (`opentide validate help` is no command) and no `-h`,
///   as the command tree has always been (#841);
/// - an environment variable an option reads is named in the help, never
///   its value (`--proxy`'s may hold a password).
pub fn parse_settings(command: Command) -> Command {
    command
        .disable_help_subcommand(true)
        .disable_help_flag(true)
        .arg(
            Arg::new("help")
                .long("help")
                .action(ArgAction::Help)
                .help(HELP_FLAG_HELP),
        )
        .allow_negative_numbers(true)
        .mut_args(|arg| {
            let id = arg.get_id().clone();
            let arg = arg.hide_env_values(true);
            // The last value wins, as `args_override_self` would make it for
            // every option. That setting only lifts clap's refusal of a
            // repeated single-value option; spelled on the option it also
            // drops what a repeatable or counting one collected, so it goes
            // on the options that take one value, and not on the exceptions.
            let single = matches!(
                arg.get_action(),
                ArgAction::Set | ArgAction::SetTrue | ArgAction::SetFalse
            );
            if single && !REPEAT_IS_AN_ERROR.contains(&id.as_str()) {
                arg.overrides_with(id)
            } else {
                arg
            }
        })
        .mut_subcommands(parse_settings)
}

/// Every visible command under `root`, depth first.
pub fn entries(root: &Command) -> Vec<Entry> {
    let mut out = Vec::new();
    walk(root, "", &mut out);
    out
}

fn walk(command: &Command, prefix: &str, out: &mut Vec<Entry>) {
    for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        let path = if prefix.is_empty() {
            sub.get_name().to_owned()
        } else {
            format!("{prefix} {}", sub.get_name())
        };
        out.push(Entry {
            path: path.clone(),
            command: sub.clone(),
        });
        walk(sub, &path, out);
    }
}

/// Whether `command` has visible subcommands.
pub fn is_group(command: &Command) -> bool {
    command.get_subcommands().any(|sub| !sub.is_hide_set())
}

/// The first line of the help, words joined by one space.
pub fn summary(command: &Command) -> String {
    let about = command
        .get_about()
        .map(ToString::to_string)
        .unwrap_or_default();
    let first = about.split("\n\n").next().unwrap_or_default();
    first.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The whole help text of a command.
pub fn help_text(command: &Command) -> String {
    command
        .get_long_about()
        .or_else(|| command.get_about())
        .map(ToString::to_string)
        .unwrap_or_default()
}

/// The first `$ opentide …` line of the examples a command's help shows.
pub fn example(command: &Command) -> Option<String> {
    let epilog = command.get_after_help()?.to_string();
    epilog.lines().find_map(|line| {
        line.trim()
            .strip_prefix("$ ")
            .filter(|rest| rest.starts_with(PROGRAM))
            .map(|rest| rest.trim_end().to_owned())
    })
}

/// The catalogue's type name of an argument.
pub fn type_name(arg: &Arg) -> &'static str {
    if is_flag(arg) {
        return "boolean";
    }
    let parser = arg.get_value_parser();
    let id = parser.type_id();
    if id == std::any::TypeId::of::<i64>() {
        "integer"
    } else if id == std::any::TypeId::of::<f64>() {
        "number"
    } else if id == std::any::TypeId::of::<std::path::PathBuf>() {
        "path"
    } else if id == std::any::TypeId::of::<String>() || arg.get_possible_values().is_empty() {
        "string"
    } else {
        // A ValueEnum: the values clap checks are the type.
        "choice"
    }
}

/// Whether the argument is a flag (takes no value).
pub fn is_flag(arg: &Arg) -> bool {
    matches!(arg.get_action(), ArgAction::SetTrue | ArgAction::SetFalse)
}

/// Whether the argument may be given more than once.
pub fn is_multiple(arg: &Arg) -> bool {
    matches!(arg.get_action(), ArgAction::Append)
}

/// The values an argument accepts, or `None`.
pub fn choices(arg: &Arg) -> Option<Vec<String>> {
    let values: Vec<String> = arg
        .get_possible_values()
        .iter()
        .filter(|value| !value.is_hide_set())
        .map(|value| value.get_name().to_owned())
        .collect();
    (!is_flag(arg) && !values.is_empty()).then_some(values)
}

fn default_value(path: &str, arg: &Arg) -> Json {
    if let Some(text) = tree_meta::default(path, arg.get_id().as_str()) {
        return Json::parse(text).unwrap_or(Json::Null);
    }
    if is_flag(arg) {
        return Json::Bool(false);
    }
    let Some(value) = arg.get_default_values().first() else {
        return Json::Null;
    };
    let text = value.to_string_lossy();
    match type_name(arg) {
        "integer" => text.parse().map_or(Json::Null, Json::Int),
        "number" => text.parse().map_or(Json::Null, Json::Float),
        _ => Json::Str(text.into_owned()),
    }
}

fn help_of(arg: &Arg) -> Json {
    let text = arg.get_help().map(ToString::to_string).unwrap_or_default();
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.is_empty() {
        Json::Null
    } else {
        Json::Str(joined)
    }
}

fn envvars(arg: &Arg, root: bool) -> Json {
    let mut found: Vec<Json> = arg
        .get_env()
        .map(|name| Json::Str(name.to_string_lossy().into_owned()))
        .into_iter()
        .collect();
    if root {
        found.extend(
            tree_meta::CALLBACK_ENVVARS
                .iter()
                .filter(|(id, _)| *id == arg.get_id().as_str())
                .map(|(_, name)| Json::str(*name)),
        );
    }
    Json::Array(found)
}

fn strings(values: Option<Vec<String>>) -> Json {
    values.map_or(Json::Null, |values| {
        Json::Array(values.into_iter().map(Json::Str).collect())
    })
}

/// The visible options of `command`, the negative half of a pair left out.
pub fn options<'a>(path: &'a str, command: &'a Command) -> impl Iterator<Item = &'a Arg> + 'a {
    command.get_arguments().filter(move |arg| {
        !arg.is_positional()
            && !arg.is_hide_set()
            && !tree_meta::PLUMBING.contains(&arg.get_id().as_str())
            && !tree_meta::is_secondary(path, arg.get_id().as_str())
    })
}

/// The visible positional arguments of `command`.
pub fn arguments(command: &Command) -> impl Iterator<Item = &Arg> {
    command
        .get_arguments()
        .filter(|arg| arg.is_positional() && !arg.is_hide_set())
}

/// The flags of an option: its long name, then its short one.
pub fn flags(arg: &Arg) -> Vec<String> {
    let mut flags: Vec<String> = arg
        .get_long_and_visible_aliases()
        .unwrap_or_default()
        .into_iter()
        .map(|long| format!("--{long}"))
        .collect();
    flags.extend(arg.get_short().map(|short| format!("-{short}")));
    flags
}

fn option(path: &str, arg: &Arg, root: bool) -> Json {
    let secondary = tree_meta::secondary(path, arg.get_id().as_str())
        .map(|(_, flag)| vec![Json::str(flag)])
        .unwrap_or_default();
    Json::object([
        ("name", Json::str(arg.get_id().as_str())),
        (
            "flags",
            Json::Array(flags(arg).into_iter().map(Json::Str).collect()),
        ),
        ("secondary_flags", Json::Array(secondary)),
        ("type", Json::str(type_name(arg))),
        (
            "choices",
            strings(choices(arg).or_else(|| tree_meta::choices(path, arg.get_id().as_str()))),
        ),
        ("default", default_value(path, arg)),
        ("required", Json::Bool(arg.is_required_set())),
        ("multiple", Json::Bool(is_multiple(arg))),
        ("is_flag", Json::Bool(is_flag(arg))),
        ("envvars", envvars(arg, root)),
        ("help", help_of(arg)),
    ])
}

fn argument(path: &str, arg: &Arg) -> Json {
    Json::object([
        (
            "name",
            Json::str(
                arg.get_value_names()
                    .and_then(|names| names.first())
                    .map_or_else(|| arg.get_id().to_string(), ToString::to_string),
            ),
        ),
        ("type", Json::str(type_name(arg))),
        (
            "choices",
            strings(choices(arg).or_else(|| tree_meta::choices(path, arg.get_id().as_str()))),
        ),
        ("default", default_value(path, arg)),
        ("required", Json::Bool(arg.is_required_set())),
        ("multiple", Json::Bool(is_multiple(arg))),
        ("envvars", envvars(arg, false)),
        ("help", help_of(arg)),
    ])
}

fn command_entry(entry: &Entry, schema: Json) -> Json {
    let command = &entry.command;
    let group = is_group(command);
    Json::object([
        ("path", Json::str(&entry.path)),
        ("name", Json::str(command.get_name())),
        ("summary", Json::Str(summary(command))),
        ("help", Json::Str(help_text(command))),
        ("group", Json::Bool(group)),
        (
            "runs_alone",
            Json::Bool(!group || !command.is_subcommand_required_set()),
        ),
        (
            "subcommands",
            Json::Array(
                command
                    .get_subcommands()
                    .filter(|sub| !sub.is_hide_set())
                    .map(|sub| Json::str(sub.get_name()))
                    .collect(),
            ),
        ),
        ("deprecated", Json::Bool(false)),
        (
            "arguments",
            Json::Array(
                arguments(command)
                    .map(|arg| argument(&entry.path, arg))
                    .collect(),
            ),
        ),
        (
            "options",
            Json::Array(
                options(&entry.path, command)
                    .map(|arg| option(&entry.path, arg, false))
                    .collect(),
            ),
        ),
        ("example", Json::opt_str(example(command))),
        ("output_schema", schema),
    ])
}

/// An object's members, in order.
pub type Members = Vec<(String, Json)>;

/// The command's keys of the `opentide commands` document, and its summary.
pub fn document(version: &str) -> (Members, Members) {
    let root = root();
    let entries = entries(&root);
    let schemas = crate::schemas::Schemas::load();
    let groups = entries
        .iter()
        .filter(|entry| is_group(&entry.command))
        .count();
    let commands: Vec<Json> = entries
        .iter()
        .map(|entry| command_entry(entry, schemas.output_schema(&entry.path)))
        .collect();
    let count = commands.len();
    let data = vec![
        ("program".to_owned(), Json::str(PROGRAM)),
        ("version".to_owned(), Json::str(version)),
        (
            "global_options".to_owned(),
            Json::Array(
                options("", &root)
                    .map(|arg| option("", arg, true))
                    .collect(),
            ),
        ),
        (
            "environment".to_owned(),
            Json::Array(
                environment()
                    .into_iter()
                    .map(|(name, meaning)| {
                        Json::object([("name", Json::Str(name)), ("meaning", Json::Str(meaning))])
                    })
                    .collect(),
            ),
        ),
        ("commands".to_owned(), Json::Array(commands)),
        ("$defs".to_owned(), schemas.defs()),
    ];
    let summary = vec![
        (
            "commands".to_owned(),
            Json::Int(i64::try_from(count).unwrap_or(i64::MAX)),
        ),
        (
            "groups".to_owned(),
            Json::Int(i64::try_from(groups).unwrap_or(i64::MAX)),
        ),
    ];
    (data, summary)
}

/// The command tree as `opentide commands` prints it without `--json`: one
/// line per command, indented by depth, its summary in a column.
pub fn tree_lines() -> Vec<String> {
    let root = root();
    let entries = entries(&root);
    let labels: Vec<(String, String)> = entries
        .iter()
        .map(|entry| {
            let depth = entry.path.split(' ').count() - 1;
            (
                format!("{}{}", "  ".repeat(depth), entry.command.get_name()),
                summary(&entry.command),
            )
        })
        .collect();
    let width = labels
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    labels
        .into_iter()
        .map(|(label, summary)| {
            let pad = width - label.chars().count();
            format!("{label}{}  {summary}", " ".repeat(pad))
        })
        .collect()
}

/// [`parse_settings`]: how every command line parses.
#[cfg(test)]
mod parse_settings_tests {
    use super::root;

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
    fn framework_parse_a_repeated_flag_or_option_keeps_the_last() {
        for line in [
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
        let limit = matches("query --platform sentinel --limit 5 --limit=7 x").unwrap();
        assert_eq!(
            limit
                .subcommand_matches("query")
                .unwrap()
                .get_one::<i64>("limit"),
            Some(&7)
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

    /// E2E-5 (#1729): `deploy --platform elastic --platform splunk` planned
    /// only `splunk`, with no word of `elastic`.
    #[test]
    fn framework_parse_a_repeated_platform_is_a_usage_error_naming_the_flag() {
        for line in [
            "deploy --platform elastic --platform splunk",
            "deploy --platform=elastic --platform elastic",
            "query --platform sentinel --platform=splunk x",
            "info --platform elastic --platform splunk",
            "validate query --platform sentinel --platform splunk",
            "deploy metadata --platform elastic --platform splunk",
        ] {
            let error = matches(line).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{line}"
            );
            assert!(error.to_string().contains("--platform"), "{line}: {error}");
        }
        // One `--platform` is as before, and `setup`'s repeatable one still
        // collects every value.
        assert!(matches("deploy --platform elastic").is_ok());
        assert!(matches("setup --platform elastic --platform splunk").is_ok());
    }

    #[test]
    fn framework_parse_an_option_value_starts_with_a_dash_only_after_an_equals_sign() {
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
        // An option followed by an option is missing its value, a choice
        // or a path alike.
        for line in [
            "setup skills discover --query --json",
            "query --platform --json x",
            "validate --file --strict",
        ] {
            let error = matches(line).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue, "{line}");
        }
    }

    #[test]
    fn framework_parse_a_number_is_checked_as_a_number() {
        for line in [
            "query --platform sentinel --limit many x",
            "query --platform sentinel --timeout soon x",
        ] {
            let error = matches(line).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ValueValidation,
                "{line}"
            );
        }
    }
}
