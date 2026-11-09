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
            "Any value turns colour off, like --no-color".into(),
        ),
        (
            "OPENTIDE_JSON_INDENT",
            "0 for one-line JSON, 2 for indented; default: indented on a terminal".into(),
        ),
        ("OPENTIDE_REPO_ROOT", "Repository root, like --repo".into()),
        (
            "OPENTIDE_DATA_ROOT",
            "Bundled data root, like --data".into(),
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
        (
            "OPENTIDE_CACHE_DIR",
            "Where opentide caches the language-server catalogs it generates".into(),
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
    // Last, as in the Python catalogue: the oracle's list (v0.23.0) is a
    // prefix of this one (UC-0.7, #805).
    rows.push((
        "OPENTIDE_ENGINE".into(),
        "Implementation that runs a command: python (default), rust, or compare (both, failing \
         with exit 70 when they differ)"
            .into(),
    ));
    rows
}

/// One visible command, with its path.
pub struct Entry {
    /// `generate docs rules`.
    pub path: String,
    /// The clap command.
    pub command: Command,
}

/// The root command: the tree, with no `help` subcommand (the CLI has
/// `--help` only), parsed as the CLI always has ([`parse_settings`]).
pub fn root() -> Command {
    parse_settings(Cli::command().disable_help_subcommand(true))
}

/// clap's settings for how `command` and everything under it parse:
///
/// - an option or flag given twice keeps the last value (`--json commands
///   --json`, `--repo a --repo b`), as it always has; a repeatable option
///   (`--strategy`) still collects every value;
/// - an option's value may start with `-` (`--query --json` searches for
///   `--json`, `--limit -1` is a number out of range): the word after an
///   option that takes a value is its value.
pub fn parse_settings(command: Command) -> Command {
    command
        .args_override_self(true)
        .mut_args(|arg| {
            if !arg.is_positional() && crate::hoist::takes_value(&arg) {
                arg.allow_hyphen_values(true)
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
        ("choices", strings(choices(arg))),
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
        ("choices", strings(choices(arg))),
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
