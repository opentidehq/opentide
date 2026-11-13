//! `opentide new threat|objective|rule` (`cli/commands/new.py`,
//! `cli/services/new.py`): one object from the workspace's generated
//! template.
//!
//! The template (`.opentide/templates/<family>.<M>.<m>.template.yaml`) is the
//! starting text, filled line by line ([`scaffold`]): the name, a fresh
//! UUID v4, today's date, the git author, the catalogue's organisation, and
//! for every other required value the first value the generated JSON schema
//! allows, or `...` for free text. Those stand-ins are the result's
//! `placeholders`. When the template or the schema is missing, the
//! `templates` and `schemas` phases of `generate` write them first
//! ([`super::generate::run_phases`]). At an interactive terminal (`human`
//! mode, stdin a terminal) a missing name is asked for (`<Family> name`),
//! and a rule without `--platform` asks which of the enabled platforms get
//! a block (`Platform blocks`), as the Python CLI does (`_ask_name`,
//! `_ask_platforms`), through the setup wizards' [`Prompter`] (UC-6.0d).

pub mod scaffold;

use std::collections::{HashMap, HashSet};
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use opentide_compile::generate::files::shown;
use opentide_schema::configuration::lint::{FilenameConfig, parse_lint_config};
use opentide_schema::generate::router::{schema_artifact_name, template_artifact_name};
use opentide_schema::generate::schema::revision_model_schema;
use opentide_schema::generate::workspace::{
    enabled_platforms, identifiers_for_families, join_path, schemas_dir, templates_dir,
};
use opentide_schema::node::{Node, Value as NodeValue, load_bytes};
use opentide_workspace::Workspace;
use opentide_workspace::lint::stems::{expected_stem, object_stem, slugify, split_object_name};
use serde_json::Value;

use self::scaffold::{FieldPath, Fill, Model, Scalar, collect_fields, fill_template};
use super::setup::wizard::{Prompter, Stop};
use super::{COMMAND_FAILED, Report, open, placement};
use crate::env::Env;
use crate::envelope::{Failure, USAGE_EXIT_CODE, code};
use crate::json::Json;

/// `failure.code` when neither `.opentide/` nor `objects/` marks a workspace.
pub const WORKSPACE_NOT_FOUND: &str = "workspace_not_found";
/// `failure.code` when the target file already exists: `new` never
/// overwrites.
pub const PATH_EXISTS: &str = "path_exists";
/// `failure.code` when the folder or file cannot be written.
pub const PATH_NOT_WRITABLE: &str = "path_not_writable";
/// `failure.code` when `--objective` or `--threat` names no object.
pub const REFERENCE_NOT_FOUND: &str = "reference_not_found";
/// `failure.code` when the template or schema is still missing after
/// generating it.
pub const TEMPLATE_MISSING: &str = "template_missing";
/// `failure.code` of a value only a person at a terminal can give.
pub const USAGE_NEEDS_INPUT: &str = super::setup::USAGE_NEEDS_INPUT;

/// Keys a platform block needs beyond its model's required fields, so it
/// holds detection logic and deploys (`PLATFORM_EXTRA_KEYS`).
const PLATFORM_EXTRA_KEYS: [(&str, &[&[&str]]); 7] = [
    (
        "defender_for_endpoint",
        &[&["scope"], &["scope", "selection"]],
    ),
    ("elastic", &[&["query"]]),
    (
        "sentinel",
        &[
            &["scheduling", "frequency"],
            &["scheduling", "lookback"],
            &["grouping", "event"],
            &["grouping", "alert", "enabled"],
        ],
    ),
    (
        "sentinel_one",
        &[
            &["condition", "single_event"],
            &["condition", "single_event", "query"],
        ],
    ),
    ("harfanglab", &[&["sigma"]]),
    ("sysdig", &[&["condition"]]),
    (
        "bitdefender",
        &[
            &["severity"],
            &["detection", "target"],
            &["detection", "criteria", "field"],
            &["detection", "criteria", "is"],
        ],
    ),
];

/// A key under a platform block, its value, and whether it is a placeholder.
type KnownValue = (&'static [&'static str], &'static str, bool);

/// Values for those keys that compile, with whether each is a placeholder
/// (`PLATFORM_VALUES`): a detection decision nobody has made yet, or the
/// platform's own default.
const PLATFORM_VALUES: [(&str, &[KnownValue]); 2] = [
    (
        "sentinel",
        &[
            (&["scheduling", "frequency"], "1h", true),
            (&["scheduling", "lookback"], "1h", true),
            (&["grouping", "event"], "SingleAlert", false),
        ],
    ),
    (
        "bitdefender",
        &[
            // What GravityZone sends for the scaffold's Informational alert
            // severity, written out so the rule does not earn
            // bitdefender_severity_collapsed.
            (&["severity"], "Low", false),
            (&["detection", "target"], "process", true),
            (&["detection", "criteria", "field"], "Process.Name", true),
            (&["detection", "criteria", "is"], "...", true),
        ],
    ),
];

/// `opentide new <family>`'s arguments.
#[derive(Debug, Clone, Default)]
pub struct NewArgs {
    /// `threat`, `objective` or `rule`.
    pub family: String,
    /// `--name`.
    pub name: Option<String>,
    /// `--path`.
    pub path: Option<String>,
    /// `--platform`, repeatable (rules).
    pub platforms: Vec<String>,
    /// `--objective` (rules).
    pub objective: Option<String>,
    /// `--threat`, repeatable (objectives).
    pub threats: Vec<String>,
}

/// Where `new` runs.
pub struct Context<'a> {
    /// `--repo`.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// opentide's version, the catalogs' label.
    pub version: &'a str,
    /// Whether a person could answer a prompt: `human` mode with a terminal
    /// on stdin.
    pub can_prompt: bool,
    /// Asks the questions when [`Context::can_prompt`]; without one, a run
    /// that would prompt is refused as needing input.
    pub prompter: Option<&'a std::cell::RefCell<dyn Prompter + 'a>>,
    /// Ctrl-C at a question stops the run as Ctrl-C does (exit 130).
    pub interrupt: Option<&'a crate::app::Interrupt>,
}

/// What the platform question says under itself (`_ask_platforms`).
pub const PLATFORMS_HINT: &str = "(space selects, enter for none, arrows move)";

/// The report of a question that was not answered: Ctrl-C stops the run,
/// which the command line reports (`error: interrupted`, exit 130).
fn stopped(command: &str, stop: Stop, cx: &Context<'_>) -> Report {
    match stop {
        Stop::Interrupted => {
            if let Some(interrupt) = cx.interrupt {
                interrupt.request();
            }
            let mut report = Report::failed(
                command,
                crate::envelope::INTERRUPTED_EXIT_CODE,
                Failure::new("interrupted", "Interrupted"),
            );
            report.outcome.message = "Interrupted".into();
            report
        }
        Stop::Failed(message) => Report::error(command, message),
    }
}

/// `family` with its first letter in upper case (`str.capitalize`).
fn capitalised(family: &str) -> String {
    let mut chars = family.chars();
    chars.next().map_or_else(String::new, |first| {
        first
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect()
    })
}

/// Whether stdin is a terminal.
pub fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

/// Where a family's template, schema and objects are.
struct Artifacts {
    template: PathBuf,
    schema: PathBuf,
    objects: PathBuf,
}

/// The template and schema of `family`'s latest revision, and its object
/// folder (`workspace_artifacts`). The configured `artifacts` names are the
/// editor's default revision, which can be older: a new object starts on the
/// latest one.
fn artifacts(workspace: &Workspace, root: &Path, family: &str) -> Artifacts {
    let config = &workspace.configuration().resolved.tree;
    let latest = identifiers_for_families(&[family]).into_iter().last();
    let (template, schema) = latest.map_or_else(
        || (String::new(), String::new()),
        |id| (template_artifact_name(&id), schema_artifact_name(&id)),
    );
    let objects = workspace.configuration().folder(family).map_or_else(
        || root.join("objects").join(format!("{family}s")),
        Path::to_path_buf,
    );
    Artifacts {
        template: root.join(join_path(&templates_dir(config), &template)),
        schema: root.join(join_path(&schemas_dir(config), &schema)),
        objects,
    }
}

/// The generation phases `new` needs before it can scaffold.
fn missing(artifacts: &Artifacts) -> Vec<String> {
    let mut phases = Vec::new();
    if !artifacts.template.is_file() {
        phases.push("templates".to_owned());
    }
    if !artifacts.schema.is_file() {
        phases.push("schemas".to_owned());
    }
    phases
}

/// Whether `path` holds `.opentide/` or an `objects/` catalogue
/// (`is_workspace_root`).
fn is_workspace_root(path: &Path) -> bool {
    if path.components().any(|part| part.as_os_str() == ".git") {
        return false;
    }
    if path.join(".opentide").is_dir() {
        return true;
    }
    let objects = path.join("objects");
    objects.is_dir() && !objects.join("__init__.py").is_file()
}

/// The `.yaml` and `.yml` files under `root`, in path order.
fn object_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &mut files);
    files.sort_by(|a, b| a.components().cmp(b.components()));
    files
}

/// A file's `metadata` mapping, if it parses and has one.
fn metadata_of(path: &Path) -> Option<std::sync::Arc<Node>> {
    let bytes = std::fs::read(path).ok()?;
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    let document = load_bytes(bytes).ok()?;
    let metadata = document.root()?.get("metadata")?.clone();
    matches!(metadata.value, NodeValue::Map(_)).then_some(metadata)
}

fn text_of<'n>(node: &'n Node, key: &str) -> Option<&'n str> {
    node.get(key).and_then(|value| value.value.as_str())
}

/// The organisation most objects in the catalogue carry
/// (`catalogue_organisation`); ties go to the first seen in path order.
fn catalogue_organisation(objects_root: &Path) -> Option<(String, String)> {
    let mut seen: Vec<((String, String), usize)> = Vec::new();
    for path in object_files(objects_root) {
        let Some(metadata) = metadata_of(&path) else {
            continue;
        };
        let Some(organisation) = metadata.get("organisation") else {
            continue;
        };
        let (Some(uuid), Some(name)) =
            (text_of(organisation, "uuid"), text_of(organisation, "name"))
        else {
            continue;
        };
        if uuid.is_empty() || name.is_empty() {
            continue;
        }
        let key = (uuid.trim().to_owned(), name.trim().to_owned());
        match seen.iter_mut().find(|(known, _)| *known == key) {
            Some((_, count)) => *count += 1,
            None => seen.push((key, 1)),
        }
    }
    let most = seen.iter().map(|(_, count)| *count).max()?;
    seen.into_iter()
        .find(|(_, count)| *count == most)
        .map(|(key, _)| key)
}

/// `metadata.uuid` of every object under `folder`, lower-cased.
fn catalogue_uuids(folder: &Path) -> HashSet<String> {
    object_files(folder)
        .iter()
        .filter_map(|path| metadata_of(path))
        .filter_map(|metadata| text_of(&metadata, "uuid").map(|uuid| uuid.trim().to_lowercase()))
        .collect()
}

/// The first configured deployment status whose strategy is `INERT`
/// (`inert_status`): a new platform block starts there.
fn inert_status(config: &Node) -> Option<String> {
    let statuses = config.get("deployment")?.get("statuses")?;
    let NodeValue::Seq(statuses) = &statuses.value else {
        return None;
    };
    statuses.iter().find_map(|status| {
        let strategy = status
            .get("strategy")
            .map(|value| value.value.to_string())?;
        if !strategy.eq_ignore_ascii_case("INERT") {
            return None;
        }
        text_of(status, "name")
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    })
}

/// Whether `value` is a UUID in its canonical 8-4-4-4-12 hex form.
fn is_uuid(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(part, len)| part.len() == len && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `[filenames]`'s convention for `kind` (`threats`).
fn for_kind<'c>(config: &'c FilenameConfig, kind: &str) -> &'c FilenameConfig {
    config
        .kinds
        .iter()
        .find(|(name, _)| name == kind)
        .map_or(config, |(_, convention)| convention)
}

/// Whether `folder` holds `stem.yaml` or `stem.yml`, whatever the case of
/// the stem (`_stem_taken`).
fn stem_taken(folder: &Path, stem: &str) -> bool {
    let wanted = stem.to_lowercase();
    let Ok(entries) = std::fs::read_dir(folder) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let (entry_stem, suffix) = split_object_name(&entry.file_name().to_string_lossy());
        (suffix == ".yaml" || suffix == ".yml") && entry_stem.to_lowercase() == wanted
    })
}

/// Where the new object goes, named the way `opentide lint` expects
/// (`target_path`): the slug of its name (or the name under `style =
/// "name"`), with `-<uuid[:8]>` when that stem is taken.
fn target_path(
    objects: &Path,
    name: &str,
    uuid: &str,
    path: Option<&Path>,
    style: &str,
) -> PathBuf {
    let mut folder = objects.to_path_buf();
    if let Some(path) = path {
        let text = path.to_string_lossy();
        if path.is_dir() || text.ends_with('/') || text.ends_with('\\') {
            folder = path.to_path_buf();
        } else if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
        {
            return path.to_path_buf();
        } else {
            // The loader reads only .yaml and .yml files.
            let file = path
                .file_name()
                .map(|file| file.to_string_lossy().into_owned())
                .unwrap_or_default();
            return path.with_file_name(format!("{file}.yaml"));
        }
    }
    let stem = if style == "name" {
        expected_stem(name, style)
    } else {
        None
    }
    .unwrap_or_else(|| slugify(name));
    let taken = if style == "name" {
        // Names keep their case, and `Rule` is `rule` on macOS and Windows.
        stem_taken(&folder, &stem)
    } else {
        [".yaml", ".yml"]
            .iter()
            .any(|suffix| folder.join(format!("{stem}{suffix}")).exists())
    };
    let stem = if taken {
        format!("{stem}-{}", &uuid[..8.min(uuid.len())])
    } else {
        stem
    };
    folder.join(format!("{stem}.yaml"))
}

/// A folder as the CLI shows it, relative to the working directory or the
/// workspace, without a trailing `/` (`_relative`).
fn folder_shown(folder: &Path, cwd: &Path, root: &Path) -> String {
    let text = shown(folder, cwd, root);
    match text.trim_end_matches('/') {
        "" => text,
        trimmed => trimmed.to_owned(),
    }
}

/// `path` from the workspace root, wherever `new` ran.
fn workspace_relative(path: &Path, root: &Path) -> String {
    let resolved = dunce_canonical(path);
    resolved.strip_prefix(dunce_canonical(root)).map_or_else(
        |_| resolved.to_string_lossy().replace('\\', "/"),
        |relative| relative.to_string_lossy().replace('\\', "/"),
    )
}

fn dunce_canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Today's date where the run is (`TZ`, else the system's zone).
fn today(env: &Env) -> String {
    let zone = env
        .get("TZ")
        .filter(|name| !name.is_empty())
        .and_then(|name| jiff::tz::TimeZone::get(name.trim_start_matches(':')).ok())
        .unwrap_or_else(jiff::tz::TimeZone::system);
    jiff::Timestamp::now().to_zoned(zone).date().to_string()
}

fn path(parts: &[&str]) -> FieldPath {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn needs_input(command: &str, family: &str, missing: &str) -> Report {
    let mut failure = Failure::new(
        USAGE_NEEDS_INPUT,
        format!(
            "opentide new {family} needs {missing}; it prompts only at an interactive terminal"
        ),
    );
    failure.argument = Some(missing.to_owned());
    Report::failed(command, USAGE_EXIT_CODE, failure)
}

/// A scaffold that cannot be written: `failure.code`, exit code, argument.
fn new_error(
    command: &str,
    message: String,
    failure_code: &str,
    exit_code: i32,
    argument: Option<&str>,
) -> Report {
    let mut failure = Failure::new(failure_code, message);
    failure.argument = argument.map(str::to_owned);
    Report::failed(command, exit_code, failure)
}

/// `opentide new <family>`.
#[expect(
    clippy::too_many_lines,
    reason = "the command's steps in the oracle's order, kept in one place"
)]
pub fn run(args: &NewArgs, cx: &Context<'_>) -> Report {
    let family = args.family.as_str();
    let command = format!("new {family}");
    let (shown_root, options) = placement(cx.repo, cx.env, cx.cwd);
    let given = PathBuf::from(&shown_root);
    let root = dunce_canonical(&if given.is_absolute() {
        given
    } else {
        cx.cwd.join(given)
    });
    if !is_workspace_root(&root) {
        // Writing here would make this folder the workspace that every
        // directory below it discovers.
        let mut report = new_error(
            &command,
            format!(
                "No workspace at {}: no .opentide/ or objects/ there or above it",
                root.display()
            ),
            WORKSPACE_NOT_FOUND,
            1,
            None,
        );
        report.next("opentide setup", "create a workspace first");
        return report;
    }
    let name = match args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        Some(name) => name.to_owned(),
        None => match cx.prompter.filter(|_| cx.can_prompt) {
            Some(prompter) => {
                let asked =
                    prompter
                        .borrow_mut()
                        .text(&format!("{} name", capitalised(family)), "", None);
                match asked {
                    Ok(answer) if !answer.trim().is_empty() => answer.trim().to_owned(),
                    Ok(_) => return needs_input(&command, family, "--name"),
                    Err(stop) => return stopped(&command, stop, cx),
                }
            }
            None => return needs_input(&command, family, "--name"),
        },
    };
    let workspace = match open(options) {
        Ok(workspace) => workspace,
        Err(message) => return Report::error(&command, message),
    };
    let config = workspace.configuration().resolved.tree.clone();
    let enabled: Vec<String> = enabled_platforms(&config)
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    let mut chosen = args.platforms.clone();
    if family == "rule" && args.platforms.is_empty() && !enabled.is_empty() {
        if let Some(prompter) = cx.prompter.filter(|_| cx.can_prompt) {
            let labels: Vec<&str> = enabled
                .iter()
                .map(|key| {
                    opentide_schema::platforms::get(key)
                        .map_or(key.as_str(), |platform| platform.label)
                })
                .collect();
            let asked = prompter.borrow_mut().checkbox_hinted(
                "Platform blocks",
                &labels,
                &[],
                false,
                PLATFORMS_HINT,
            );
            match asked {
                Ok(picked) => {
                    chosen = picked
                        .iter()
                        .filter_map(|&index| enabled.get(index).cloned())
                        .collect();
                }
                Err(stop) => return stopped(&command, stop, cx),
            }
        }
    }
    let mut platforms: Vec<String> = Vec::new();
    if family == "rule" {
        for platform in &chosen {
            if !platforms.contains(platform) {
                platforms.push(platform.clone());
            }
        }
    }

    let mut paths = artifacts(&workspace, &root, family);
    let generated = missing(&paths);
    let mut steps = Vec::new();
    if !generated.is_empty() {
        let run = super::generate::run_phases(&generated, &workspace, cx.cwd, cx.version);
        steps = run.steps;
        if let Some((phase, detail)) = run.failed {
            return super::generate::phase_failed(&command, &phase, &detail, Vec::new(), steps);
        }
        paths = artifacts(&workspace, &root, family);
        let still = missing(&paths);
        if !still.is_empty() {
            let file = |path: &Path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            let mut report = new_error(
                &command,
                format!(
                    "opentide generate {} did not write {} and {}",
                    still.join(" "),
                    file(&paths.template),
                    file(&paths.schema)
                ),
                TEMPLATE_MISSING,
                1,
                None,
            );
            report.steps = steps;
            return report;
        }
    }
    let with_steps = |mut report: Report, steps: &[crate::render::progress::Step]| {
        report.steps = steps.to_vec();
        report
    };

    // The references must name objects of the catalogue.
    let mut references: Vec<(&str, &str, &str)> = Vec::new();
    if family == "rule"
        && let Some(objective) = args.objective.as_deref()
    {
        references.push(("--objective", "objective", objective));
    }
    if family == "objective" {
        for threat in &args.threats {
            references.push(("--threat", "threat", threat));
        }
    }
    let mut known: HashMap<&str, HashSet<String>> = HashMap::new();
    for (argument, referred, value) in &references {
        if !is_uuid(value) {
            return with_steps(
                new_error(
                    &command,
                    format!("{argument} takes a UUID, got '{value}'"),
                    code::USAGE_INVALID_VALUE,
                    USAGE_EXIT_CODE,
                    Some(argument),
                ),
                &steps,
            );
        }
        let folder = artifacts(&workspace, &root, referred).objects;
        let uuids = known
            .entry(referred)
            .or_insert_with(|| catalogue_uuids(&folder));
        if !uuids.contains(&value.to_lowercase()) {
            return with_steps(
                new_error(
                    &command,
                    format!(
                        "No {referred} in {} has uuid {value}",
                        folder_shown(&folder, cx.cwd, &root)
                    ),
                    REFERENCE_NOT_FOUND,
                    USAGE_EXIT_CODE,
                    Some(argument),
                ),
                &steps,
            );
        }
    }

    let (Ok(template), Ok(schema_text)) = (
        std::fs::read_to_string(&paths.template),
        std::fs::read_to_string(&paths.schema),
    ) else {
        return with_steps(
            Report::error(&command, "the template or the schema cannot be read"),
            &steps,
        );
    };
    let schema: Value = serde_json::from_str(&schema_text).unwrap_or(Value::Null);
    let schema_id = scaffold::template_schema_id(&template).unwrap_or_else(|| {
        identifiers_for_families(&[family])
            .last()
            .map(ToString::to_string)
            .unwrap_or_default()
    });
    let Some(model_schema) = revision_model_schema(&schema_id) else {
        return with_steps(
            Report::error(
                &command,
                format!("unknown schema identifier: '{schema_id}'"),
            ),
            &steps,
        );
    };
    let model_root = model_schema.to_value();
    let lint = match parse_lint_config(config.get("lint").map(AsRef::as_ref)) {
        Ok(lint) => lint,
        Err(error) => {
            return with_steps(
                new_error(&command, error.0, COMMAND_FAILED, USAGE_EXIT_CODE, None),
                &steps,
            );
        }
    };
    let filenames = for_kind(&lint.filenames, &format!("{family}s")).clone();

    let object_uuid = uuid::Uuid::new_v4().to_string();
    let given_path = args.path.as_deref().map(|path| cx.cwd.join(path));
    let destination = target_path(
        &paths.objects,
        &name,
        &object_uuid,
        given_path.as_deref(),
        &filenames.style,
    );
    let argument = if args.path.is_some() {
        "--path"
    } else {
        "--name"
    };
    let exists = |destination: &Path| {
        new_error(
            &command,
            format!(
                "{} already exists; new never overwrites a file",
                shown(destination, cx.cwd, &root)
            ),
            PATH_EXISTS,
            1,
            Some(argument),
        )
    };
    if destination.exists() {
        return with_steps(exists(&destination), &steps);
    }

    let author = super::super::git_baseline::stdout(cx.env, &root, &["config", "user.name"])
        .filter(|name| !name.is_empty());
    let objects_root = paths
        .objects
        .parent()
        .map_or_else(|| paths.objects.clone(), Path::to_path_buf);
    let organisation = catalogue_organisation(&objects_root);

    let today = today(cx.env);
    let mut values: HashMap<FieldPath, Scalar> = HashMap::from([
        (path(&["name"]), Scalar::Text(name.clone())),
        (
            path(&["metadata", "uuid"]),
            Scalar::Text(object_uuid.clone()),
        ),
        (
            path(&["metadata", "schema"]),
            Scalar::Text(schema_id.clone()),
        ),
        (path(&["metadata", "created"]), Scalar::Date(today.clone())),
        (path(&["metadata", "modified"]), Scalar::Date(today)),
    ]);
    let mut wanted: Vec<FieldPath> = Vec::new();
    if let Some(author) = &author {
        values.insert(path(&["metadata", "author"]), Scalar::Text(author.clone()));
        wanted.push(path(&["metadata", "author"]));
    }
    if let Some((uuid, name)) = &organisation {
        values.insert(
            path(&["metadata", "organisation", "uuid"]),
            Scalar::Text(uuid.clone()),
        );
        values.insert(
            path(&["metadata", "organisation", "name"]),
            Scalar::Text(name.clone()),
        );
        wanted.push(path(&["metadata", "organisation"]));
    }
    let mut marked: HashSet<FieldPath> = HashSet::new();
    let mut status = None;
    if family == "rule" {
        // Optional in the model but live in the template: left empty it
        // loads as null, and a deploy reads its alert_severity.
        wanted.push(path(&["response"]));
        if let Some(objective) = &args.objective {
            values.insert(path(&["detection_model"]), Scalar::Text(objective.clone()));
            wanted.push(path(&["detection_model"]));
        }
        status = if platforms.is_empty() {
            None
        } else {
            inert_status(&config)
        };
        for platform in &platforms {
            let block = path(&["configurations", platform]);
            let at = |rest: &[&str]| {
                let mut full = block.clone();
                full.extend(rest.iter().map(|part| (*part).to_owned()));
                full
            };
            // Without an INERT status the block's status is a marked
            // placeholder, and the block stays disabled so it never deploys.
            values.insert(at(&["enabled"]), Scalar::Bool(status.is_some()));
            if let Some(status) = &status {
                values.insert(at(&["status"]), Scalar::Text(status.clone()));
            }
            wanted.push(block.clone());
            wanted.push(at(&["enabled"]));
            for (key, extras) in PLATFORM_EXTRA_KEYS {
                if key == platform {
                    wanted.extend(extras.iter().map(|extra| at(extra)));
                }
            }
            for (key, known) in PLATFORM_VALUES {
                if key == platform {
                    for (rest, value, invented) in known {
                        values.insert(at(rest), Scalar::Text((*value).to_owned()));
                        if *invented {
                            marked.insert(at(rest));
                        }
                    }
                }
            }
        }
    }
    if family == "objective" && !args.threats.is_empty() {
        values.insert(
            path(&["objective", "threats"]),
            Scalar::List(args.threats.iter().cloned().map(Scalar::Text).collect()),
        );
        wanted.push(path(&["objective", "threats"]));
    }

    let model = Model::new(&model_root);
    let fields = collect_fields(&model, &model_root, &wanted, &[]);
    let make_uuid = || uuid::Uuid::new_v4().to_string();
    let filled = fill_template(
        &template,
        &Fill {
            fields: &fields,
            values: &values,
            schema: &schema,
            model: &model,
            marked: &marked,
            make_uuid: &make_uuid,
        },
    );
    let mut text = filled.text;
    if family == "rule" {
        // After filling: fill_template would uncomment the pointer comment.
        text = scaffold::keep_platform_blocks(
            &text,
            &platforms,
            &workspace_relative(&paths.template, &root),
        );
    }
    if let Some(parent) = destination.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return with_steps(
            not_writable(&command, &destination, cx, &root, &error, args),
            &steps,
        );
    }
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .and_then(|mut file| std::io::Write::write_all(&mut file, text.as_bytes()));
    match written {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return with_steps(exists(&destination), &steps);
        }
        Err(error) => {
            return with_steps(
                not_writable(&command, &destination, cx, &root, &error, args),
                &steps,
            );
        }
    }

    let shown_path = shown(&destination, cx.cwd, &root);
    let count = filled.placeholders.len();
    let mut message = format!("Created {shown_path}");
    if count > 0 {
        message.push_str(&format!(
            " · {count} placeholder{} to replace",
            if count == 1 { "" } else { "s" }
        ));
    }
    let mut data: Vec<(String, Json)> = vec![
        ("path".into(), Json::str(&shown_path)),
        (
            "file_path".into(),
            Json::str(dunce_canonical(&destination).to_string_lossy()),
        ),
        ("uuid".into(), Json::str(&object_uuid)),
        ("type".into(), Json::str(family)),
        ("schema".into(), Json::str(&schema_id)),
        ("name".into(), Json::str(&name)),
        ("author".into(), Json::opt_str(author.clone())),
        (
            "organisation".into(),
            organisation.as_ref().map_or(Json::Null, |(uuid, name)| {
                Json::object([("uuid", Json::str(uuid)), ("name", Json::str(name))])
            }),
        ),
        (
            "platforms".into(),
            Json::Array(platforms.iter().map(Json::str).collect()),
        ),
        (
            "placeholders".into(),
            Json::Array(filled.placeholders.iter().map(Json::str).collect()),
        ),
    ];
    let mut warnings: Vec<String> = Vec::new();
    if family == "rule" && !platforms.is_empty() && status.is_none() {
        warnings.push(
            "No deployment status has strategy INERT, so the new platform blocks are disabled \
             (enabled: false) and their status is a placeholder"
                .to_owned(),
        );
    }
    if let (Some(regex), Some(pattern)) = (&filenames.regex, &filenames.pattern)
        && !regex.is_match(&object_stem(&destination))
    {
        let file = destination
            .file_name()
            .map(|file| file.to_string_lossy().into_owned())
            .unwrap_or_default();
        warnings.push(format!(
            "{file} does not match lint.toml {} {pattern}; rename it before opentide lint runs",
            filenames.pattern_key
        ));
    }
    if count > 0 {
        // A note under the outcome line in the text modes.
        data.push((
            "detail".into(),
            Json::str(format!(
                "each ends in '{}'; opentide lint lists them",
                scaffold::PLACEHOLDER_MARKER
            )),
        ));
    }
    if !generated.is_empty() {
        // Not a warning: a step new took, and the checklist printed it.
        data.push((
            "generated".into(),
            Json::Array(generated.iter().map(Json::str).collect()),
        ));
    }
    for platform in &platforms {
        if !enabled.contains(platform) {
            warnings.push(format!(
                "{platform} is not enabled in this workspace, so this block will not deploy; \
                 enable it with 'opentide setup platforms --{}'",
                platform.replace('_', "-")
            ));
        }
    }
    // One line for what was left out, not one warning per field.
    let left_out: Vec<(&str, &str)> = [
        (
            "metadata.author",
            "no git user.name is set",
            author.is_none(),
        ),
        (
            "metadata.organisation",
            "no catalogue object names one",
            organisation.is_none(),
        ),
    ]
    .into_iter()
    .filter(|(_, _, missing)| *missing)
    .map(|(field, reason, _)| (field, reason))
    .collect();
    if !left_out.is_empty() {
        let fields: Vec<&str> = left_out.iter().map(|(field, _)| *field).collect();
        let reasons: Vec<&str> = left_out.iter().map(|(_, reason)| *reason).collect();
        warnings.push(format!(
            "{} left out: {}",
            fields.join(" and "),
            reasons.join("; ")
        ));
    }
    let mut report = Report::completed(&command, data);
    report.outcome.message = message;
    report.outcome.summary = vec![
        ("created".into(), Json::Int(1)),
        (
            "placeholders".into(),
            Json::Int(i64::try_from(count).unwrap_or(i64::MAX)),
        ),
    ];
    report.next(
        &format!("opentide validate --file {shown_path}"),
        "check it",
    );
    report.warnings = warnings;
    report.steps = steps;
    report
}

/// The folder or file cannot be written: say which, and why.
fn not_writable(
    command: &str,
    destination: &Path,
    cx: &Context<'_>,
    root: &Path,
    error: &std::io::Error,
    args: &NewArgs,
) -> Report {
    let reason = error.to_string();
    let reason = reason
        .rsplit_once(" (os error ")
        .map_or(reason.as_str(), |(text, _)| text)
        .to_owned();
    let mut report = new_error(
        command,
        format!(
            "Could not write {}: {reason}",
            shown(destination, cx.cwd, root)
        ),
        PATH_NOT_WRITABLE,
        1,
        args.path.is_some().then_some("--path"),
    );
    report.next(
        &format!("opentide explain {PATH_NOT_WRITABLE}"),
        "how to fix it",
    );
    report
}

#[cfg(test)]
mod tests;
