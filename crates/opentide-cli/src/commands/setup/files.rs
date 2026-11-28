//! The setup steps that write files from what opentide bundles: `setup env`
//! (`services/setup/env.py`), `setup platforms` (`platforms.py`), `setup
//! repo` (`repo.py`) and `setup mcp` (`mcp.py`). Each reads and writes
//! through the [`Stage`] and returns its result's members in the oracle's
//! order.

use std::path::{Path, PathBuf};

use super::jsonc;
use super::stage::Stage;
use crate::env::Env;
use crate::json::{Json, Object};

/// A step's result: its members, in order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StepResult {
    /// The members.
    pub fields: Object,
}

impl StepResult {
    /// A result from `(key, value)` pairs.
    pub fn new<K: Into<String>>(fields: impl IntoIterator<Item = (K, Json)>) -> StepResult {
        StepResult {
            fields: fields.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        }
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.fields.get(key)
    }

    /// The strings of the list `key` (empty when there is none).
    pub fn strings(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Json::Array(items)) => items
                .iter()
                .filter_map(|item| match item {
                    Json::Str(text) => Some(text.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The string `key`.
    pub fn text(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Json::Str(text)) => Some(text),
            _ => None,
        }
    }

    /// Sets `key`, in its place when it is there, else last.
    pub fn set(&mut self, key: &str, value: Json) {
        self.fields.insert(key.to_owned(), value);
    }

    /// Removes `key`, returning its value.
    pub fn take(&mut self, key: &str) -> Option<Json> {
        self.fields.shift_remove(key)
    }
}

/// A list of strings as JSON.
pub fn strings(items: &[String]) -> Json {
    Json::Array(items.iter().map(Json::str).collect())
}

/// `path` as the results print it.
pub fn shown(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// What `.opentide/` is called in a workspace.
pub const OPENTIDE_DIR: &str = ".opentide";

// ---------------------------------------------------------------- env

const ENV_EXAMPLE_PATH: &str = ".env.example";
const GITIGNORE_PATH: &str = ".gitignore";
const ENV_EXAMPLE_CONTENT: &str = "# opentide environment template. Copy to .env and adjust as needed.\n# The CLI, MCP server, and SDK honour OPENTIDE_REPO_ROOT (same as --repo).\nOPENTIDE_REPO_ROOT=.\n";

/// A file setup must read as UTF-8 text that is not.
fn not_utf8(path: &Path) -> String {
    format!("{}: the file is not UTF-8", path.display())
}

/// The text of the file at `path`, if any.
///
/// # Errors
///
/// It cannot be read, or is not UTF-8.
pub fn read_text(stage: &Stage, path: &Path) -> Result<Option<String>, String> {
    match stage.read(path) {
        Ok(Some(bytes)) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| not_utf8(path)),
        Ok(None) => Ok(None),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// A `.gitignore` pattern as compared: `/opentide-reports/` is `opentide-reports`.
fn ignore_key(line: &str) -> &str {
    let line = line.trim().trim_start_matches('\u{feff}');
    let line = line.strip_prefix('/').unwrap_or(line);
    line.trim_end_matches('/')
}

/// Why `.gitignore` was not changed.
#[derive(Debug)]
pub enum GitignoreError {
    /// It is not UTF-8.
    NotUtf8,
    /// It cannot be read.
    Unreadable(String),
}

/// Adds each of `lines` that `target/.gitignore` lacks; the ones added
/// (`append_gitignore_lines`).
///
/// The file is made when missing. An existing one keeps its content, its
/// byte-order mark and its line endings; a line counts as present with or
/// without a leading or trailing `/`.
///
/// # Errors
///
/// The file is not UTF-8, or cannot be read.
pub fn append_gitignore_lines(
    stage: &mut Stage,
    target: &Path,
    lines: &[&str],
) -> Result<Vec<String>, GitignoreError> {
    let dest = target.join(GITIGNORE_PATH);
    if !stage.is_file(&dest) {
        let text: String = lines.iter().flat_map(|line| [*line, "\n"]).collect();
        stage.write(&dest, text);
        return Ok(lines.iter().map(|line| (*line).to_owned()).collect());
    }
    let bytes = stage
        .read(&dest)
        .map_err(|error| GitignoreError::Unreadable(error.to_string()))?
        .unwrap_or_default();
    let existing = String::from_utf8(bytes).map_err(|_| GitignoreError::NotUtf8)?;
    let present: Vec<&str> = existing.split(['\n', '\r']).map(ignore_key).collect();
    let missing: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| !present.contains(&ignore_key(line)))
        .collect();
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    let newline = opentide_core::text::newline_of(&existing);
    let lead = if existing.is_empty() || existing.ends_with(['\n', '\r']) {
        ""
    } else {
        newline
    };
    let added: String = missing.iter().flat_map(|line| [*line, newline]).collect();
    stage.write(&dest, format!("{existing}{lead}{added}"));
    Ok(missing.iter().map(|line| (*line).to_owned()).collect())
}

/// `setup env`: `.env.example` with `OPENTIDE_REPO_ROOT`, and `.env` ignored.
///
/// # Errors
///
/// A file cannot be read, or is not UTF-8.
pub fn env(stage: &mut Stage, target: &Path) -> Result<StepResult, String> {
    stage.mkdir(target);
    let mut written = Vec::new();
    let mut skipped = Vec::new();
    let example = target.join(ENV_EXAMPLE_PATH);
    let changed = match read_text(stage, &example)? {
        Some(existing) if existing.contains("OPENTIDE_REPO_ROOT") => false,
        Some(existing) => {
            // The file's own line endings, and a line break before the new
            // line when its last line has none.
            let newline = jsonc::newline(&existing);
            let suffix = if existing.is_empty() || existing.ends_with('\n') {
                ""
            } else if existing.ends_with('\r') {
                // A CRLF cut after its CR: complete it.
                "\n"
            } else {
                newline
            };
            stage.write(
                &example,
                format!("{existing}{suffix}OPENTIDE_REPO_ROOT=.{newline}"),
            );
            true
        }
        None => {
            stage.write(&example, ENV_EXAMPLE_CONTENT);
            true
        }
    };
    if changed {
        written.push(ENV_EXAMPLE_PATH.to_owned());
    } else {
        skipped.push(ENV_EXAMPLE_PATH.to_owned());
    }
    match append_gitignore_lines(stage, target, &[".env"]) {
        Ok(added) if !added.is_empty() => written.push(GITIGNORE_PATH.to_owned()),
        Ok(_) => skipped.push(GITIGNORE_PATH.to_owned()),
        Err(GitignoreError::NotUtf8) => return Err(not_utf8(&target.join(GITIGNORE_PATH))),
        Err(GitignoreError::Unreadable(error)) => {
            return Err(format!(
                "{}: {error}",
                target.join(GITIGNORE_PATH).display()
            ));
        }
    }
    let message = if written.iter().any(|path| path == ENV_EXAMPLE_PATH) {
        "Environment example written"
    } else {
        "Environment example already present"
    };
    Ok(StepResult::new([
        ("message", Json::str(message)),
        ("path", Json::str(shown(target))),
        ("files", strings(&written)),
        ("skipped", strings(&skipped)),
    ]))
}

// ---------------------------------------------------------------- platforms

/// A platform's configuration file, `<id>.toml`, when it is built in.
pub fn platform_file(platform: &str) -> Option<String> {
    opentide_schema::platforms::is_builtin(platform).then(|| format!("{platform}.toml"))
}

/// `content` with `enabled = true` in its `[platform]` table
/// (`_enable_platform_toml`), everything else in the file kept: comments,
/// the other tables and keys (another table's `enabled` untouched), and CRLF
/// line endings. A file with no `[platform]` table, or one already enabled,
/// comes back as it is.
///
/// # Errors
///
/// `content` is not TOML.
pub fn enable_platform_toml(content: &str) -> Result<String, toml_edit::TomlError> {
    let mut document: toml_edit::DocumentMut = content.parse()?;
    let changed = match document.get_mut("platform") {
        // A key toml_edit adds goes last: an `enabled` added goes first, as
        // in the bundled templates.
        Some(toml_edit::Item::Table(table)) => {
            let added = !table.contains_key("enabled");
            let changed = set_enabled(table);
            if added {
                table.sort_values_by(|left, _, right, _| enabled_first(left, right));
            }
            changed
        }
        Some(toml_edit::Item::Value(toml_edit::Value::InlineTable(table))) => {
            let added = !table.contains_key("enabled");
            let changed = set_enabled(table);
            if added {
                table.sort_values_by(|left, _, right, _| enabled_first(left, right));
            }
            changed
        }
        _ => false,
    };
    if !changed {
        return Ok(content.to_owned());
    }
    let written = document.to_string();
    // A key toml_edit adds ends in `\n`: a CRLF file keeps CRLF throughout.
    Ok(opentide_core::text::with_newlines_of(written, content))
}

/// Sets `enabled = true` in `table`, the value's comments and spacing kept;
/// false when it already was.
fn set_enabled(table: &mut dyn toml_edit::TableLike) -> bool {
    match table.get_mut("enabled") {
        Some(item) if item.as_bool() == Some(true) => false,
        Some(toml_edit::Item::Value(value)) => {
            let decor = value.decor().clone();
            *value = true.into();
            *value.decor_mut() = decor;
            true
        }
        Some(item) => {
            *item = toml_edit::value(true);
            true
        }
        None => {
            table.insert("enabled", toml_edit::value(true));
            true
        }
    }
}

/// The order that puts `enabled` first and keeps the other keys' order.
fn enabled_first(left: &toml_edit::Key, right: &toml_edit::Key) -> std::cmp::Ordering {
    (left.get() != "enabled").cmp(&(right.get() != "enabled"))
}

/// The top-level keys of a platform file that hold the user's entries.
const USER_DATA_KEYS: [&str; 2] = ["tenants", "modifiers"];

/// Keys of a platform file the model defaults (`PlatformIdentity`), and
/// `enabled`, which `setup` sets itself: a file without one is complete, so
/// the template does not "add" them.
const DEFAULTED_KEYS: [&str; 3] = ["platform.enabled", "platform.name", "platform.description"];

/// The dotted path of every key `table` sets, tables descended into. An
/// array (of tables too) is one key's value, and an array of tables
/// (`[[tenants]]`, `[[modifiers]]`) is the user's data, not part of the
/// template's shape: it is left out.
fn key_paths(table: &dyn toml_edit::TableLike, prefix: &str, out: &mut Vec<String>) {
    for (key, item) in table.iter() {
        // `tenants` and `modifiers` are the user's data, in whatever form
        // (`[[tenants]]`, `tenants = [{ ... }]`).
        if prefix.is_empty() && USER_DATA_KEYS.contains(&key) {
            continue;
        }
        let path = if prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{prefix}.{key}")
        };
        match item {
            toml_edit::Item::ArrayOfTables(_) => {}
            toml_edit::Item::Table(inner) => key_paths(inner, &path, out),
            toml_edit::Item::Value(toml_edit::Value::InlineTable(inner)) => {
                key_paths(inner, &path, out);
            }
            _ => out.push(path),
        }
    }
}

/// The warning for a platform file that has drifted from its bundled
/// template: the keys the template has and the file does not (`added`, but
/// not [`DEFAULTED_KEYS`]) and the keys the file has and the template does
/// not (`removed`), as dotted paths. `None` when the two have the same keys, or one is not TOML.
fn platform_key_changes(relative: &str, current: &str, template: &str) -> Option<String> {
    let paths = |text: &str| -> Option<Vec<String>> {
        let document: toml_edit::DocumentMut = text.parse().ok()?;
        let mut out = Vec::new();
        key_paths(document.as_table(), "", &mut out);
        Some(out)
    };
    let (have, want) = (paths(current)?, paths(template)?);
    let added: Vec<&str> = want
        .iter()
        .filter(|path| !have.contains(path) && !DEFAULTED_KEYS.contains(&path.as_str()))
        .map(String::as_str)
        .collect();
    let removed: Vec<&str> = have
        .iter()
        .filter(|path| !want.contains(path))
        .map(String::as_str)
        .collect();
    if added.is_empty() && removed.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if !added.is_empty() {
        parts.push(format!("the new template adds {}", added.join(", ")));
    }
    if !removed.is_empty() {
        parts.push(format!("the new template removes {}", removed.join(", ")));
    }
    Some(format!(
        "{relative} was kept with your values: {}. Add or delete those keys by hand.",
        parts.join("; ")
    ))
}

/// `setup platforms`: each platform's bundled configuration, enabled.
///
/// # Errors
///
/// A file cannot be read, or is not UTF-8.
pub fn platforms(
    stage: &mut Stage,
    target: &Path,
    chosen: &[String],
) -> Result<StepResult, String> {
    let dest = target.join(OPENTIDE_DIR).join("configurations/platforms");
    stage.mkdir(&dest);
    let (mut written, mut updated, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
    let mut warnings: Vec<String> = Vec::new();
    for platform in chosen {
        let Some(file) = platform_file(platform) else {
            continue;
        };
        let Some(template) =
            opentide_schema::configuration::bundled::text(&format!("platforms/{file}"))
        else {
            tracing::warn!(platform = %platform, "platform_template_missing");
            continue;
        };
        let out = dest.join(&file);
        let relative = format!("{OPENTIDE_DIR}/configurations/platforms/{file}");
        if let Some(current) = read_text(stage, &out)? {
            let enabled = enable_platform_toml(&current)
                .map_err(|error| format!("{}: {error}", out.display()))?;
            warnings.extend(platform_key_changes(&relative, &current, template));
            if enabled == current {
                skipped.push(relative);
            } else {
                stage.write(&out, enabled);
                updated.push(relative);
            }
            continue;
        }
        let enabled =
            enable_platform_toml(template).map_err(|error| format!("platforms/{file}: {error}"))?;
        stage.write(&out, enabled);
        written.push(relative);
    }
    let message = if !written.is_empty() {
        "Platform configuration files created"
    } else if !updated.is_empty() {
        "Platform enabled flags updated"
    } else {
        "Platform configuration files already present"
    };
    // The README `setup repo` wrote lists the platforms it enabled: list
    // these too, unless the section is no longer the one setup wrote.
    let readme_path = target.join("README.md");
    if let Ok(Some(current)) = read_text(stage, &readme_path)
        && let Some(listed) = readme_with_platforms(&current, chosen)
    {
        stage.write(&readme_path, listed);
        updated.push("README.md".to_owned());
    }
    let mut result = StepResult::new([
        ("message", Json::str(message)),
        ("path", Json::str(shown(target))),
        ("platforms", strings(chosen)),
        ("files", strings(&written)),
    ]);
    if !updated.is_empty() {
        result.set("updated", strings(&updated));
    }
    if !skipped.is_empty() {
        result.set("skipped", strings(&skipped));
    }
    if !warnings.is_empty() {
        result.set("warnings", strings(&warnings));
    }
    Ok(result)
}

/// The line a README lists no platform with.
fn readme_no_platform() -> String {
    format!("- (configure platforms in {OPENTIDE_DIR}/configurations/)")
}

/// `text`, a README, with each of `chosen` added to the `## Platforms` list
/// [`readme`] writes; `None` when nothing is missing or the section is not
/// that list (a heading other than the last, a line other than `- <platform>`).
fn readme_with_platforms(text: &str, chosen: &[String]) -> Option<String> {
    let newline = opentide_core::text::newline_of(text);
    let heading = format!("{newline}## Platforms{newline}{newline}");
    let (head, section) = text.rsplit_once(&heading)?;
    let empty = readme_no_platform();
    let mut listed: Vec<String> = Vec::new();
    for line in section.split(newline).filter(|line| !line.is_empty()) {
        if line == empty {
            continue;
        }
        let platform = line.strip_prefix("- ")?;
        opentide_schema::platforms::get(platform)?;
        listed.push(platform.to_owned());
    }
    let before = listed.len();
    for platform in chosen {
        if opentide_schema::platforms::get(platform).is_some() && !listed.contains(platform) {
            listed.push(platform.clone());
        }
    }
    if listed.len() == before {
        return None;
    }
    let lines: Vec<String> = listed
        .iter()
        .map(|platform| format!("- {platform}"))
        .collect();
    Some(format!("{head}{heading}{}{newline}", lines.join(newline)))
}

// ---------------------------------------------------------------- repo

const SCAFFOLD_DIRS: [&str; 11] = [
    "objects/threats",
    "objects/objectives",
    "objects/rules",
    ".opentide/configurations/platforms",
    ".opentide/schemas",
    ".opentide/templates",
    ".opentide/exports",
    ".opentide/inflight",
    "docs/rules",
    "docs/threats",
    "docs/objectives",
];

/// What a new repository's `.gitignore` holds besides [`OPENTIDE_IGNORES`].
const PYTHON_IGNORES: [&str; 7] = [
    "__pycache__/",
    "*.pyc",
    ".venv/",
    "dist/",
    "build/",
    "*.egg-info/",
    ".pytest_cache/",
];

/// The files opentide writes that a repository must not commit.
const OPENTIDE_IGNORES: [&str; 3] = [
    ".opentide/exports/*.export.json",
    ".opentide/states/sharing.jsonl",
    "opentide-reports/",
];

/// `setup repo`'s README and scaffold choices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepoOptions {
    /// `--name`.
    pub name: Option<String>,
    /// `--org`.
    pub org: Option<String>,
    /// `--description`.
    pub description: Option<String>,
    /// `--platform`, in order.
    pub platforms: Vec<String>,
}

/// The folder name of `target`, the repository's default name.
pub fn folder_name(target: &Path) -> String {
    target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `value` without its surrounding spaces; `None` when nothing is left.
pub fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// The repository's name: `--name` without its surrounding spaces, else the folder's.
fn repo_name(options: &RepoOptions, target: &Path) -> String {
    trimmed(options.name.as_deref()).map_or_else(|| folder_name(target), str::to_owned)
}

fn readme(target: &Path, options: &RepoOptions) -> String {
    let name = repo_name(options, target);
    let platforms = if options.platforms.is_empty() {
        readme_no_platform()
    } else {
        options
            .platforms
            .iter()
            .map(|platform| format!("- {platform}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let mut metadata = String::new();
    if let Some(description) = options
        .description
        .as_deref()
        .filter(|text| !text.is_empty())
    {
        metadata.push_str(&format!("\n{description}\n"));
    }
    if let Some(org) = options.org.as_deref().filter(|text| !text.is_empty()) {
        metadata.push_str(&format!("\n**Organisation:** {org}\n"));
    }
    let deploy = if options.platforms.is_empty() {
        "opentide deploy --dry-run --strategy PREVIEW --all".to_owned()
    } else {
        options
            .platforms
            .iter()
            .map(|platform| {
                format!("opentide deploy --platform {platform} --dry-run --strategy PREVIEW --all")
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "# {name}\n{metadata}\n## Quick start\n\n```bash\nopentide setup\nopentide validate\nopentide generate\n{deploy}\n```\n\n## Platforms\n\n{platforms}\n"
    )
}

/// Where `setup repo --org` keeps the organisation, relative to the
/// repository: the organisation `opentide new` writes (`commands/new.rs`).
pub const ORGANISATION_FILE: &str = ".opentide/configurations/organisation.toml";

/// What [`organisation`] did to `organisation.toml`.
enum Organisation {
    /// The file was created or its name changed.
    Written,
    /// The file already says what `--org` names.
    Unchanged,
    /// The file is not TOML, or not UTF-8: left as it is, with the reason.
    Kept(String),
}

/// Keeps `--org` in `organisation.toml`, the `{uuid, name}` `opentide new`
/// writes into `metadata.organisation`.
///
/// A uuid already in the file stays, so renaming the organisation keeps its
/// identity and a rerun changes nothing; otherwise a fresh UUID v4 is
/// written, which a team replaces with its real one. Every other key and
/// comment of the file, and its line endings, are kept.
///
/// # Errors
///
/// The file cannot be read.
fn organisation(stage: &mut Stage, target: &Path, org: &str) -> Result<Organisation, String> {
    let path = target.join(ORGANISATION_FILE);
    let current = match read_text(stage, &path) {
        Ok(current) => current,
        Err(error) if error == not_utf8(&path) => {
            return Ok(Organisation::Kept(format!(
                "{ORGANISATION_FILE} is not UTF-8"
            )));
        }
        Err(error) => return Err(error),
    };
    let existed = current.is_some();
    let text = current.unwrap_or_default();
    let mut document: toml_edit::DocumentMut = match text.parse() {
        Ok(document) => document,
        Err(error) => {
            return Ok(Organisation::Kept(format!(
                "{ORGANISATION_FILE} is not valid TOML ({})",
                error.message()
            )));
        }
    };
    // A uuid the user wrote stays, as `new` reads it (trimmed). One that is
    // there and is not a UUID is not replaced: the identity is theirs.
    let uuid = match document.get("uuid") {
        None => Some(uuid::Uuid::new_v4().to_string()),
        Some(item)
            if item
                .as_str()
                .is_some_and(|uuid| crate::commands::new::is_uuid(uuid.trim())) =>
        {
            None
        }
        Some(item) => {
            let what = if item.as_str().is_some() {
                "its uuid is not a UUID"
            } else {
                "its uuid is not text"
            };
            return Ok(Organisation::Kept(format!(
                "{what} (setup keeps the value you wrote)"
            )));
        }
    };
    if !existed {
        document.decor_mut().set_prefix(
            "# The organisation `opentide new` writes into metadata.organisation.\n\
             # Replace the uuid with your organisation's.\n",
        );
    }
    if let Some(uuid) = uuid {
        document["uuid"] = toml_edit::value(uuid);
    }
    document["name"] = toml_edit::value(org);
    let written = document.to_string();
    // A key toml_edit adds ends in `\n`: a CRLF file keeps CRLF throughout.
    let written = opentide_core::text::with_newlines_of(written, &text);
    if written == text {
        return Ok(Organisation::Unchanged);
    }
    stage.mkdir(&target.join(OPENTIDE_DIR).join("configurations"));
    stage.write(&path, written);
    Ok(Organisation::Written)
}

/// `setup repo`: the scaffold, the README, `.gitignore`, and the platforms.
///
/// # Errors
///
/// A file cannot be read, or is not UTF-8.
pub fn repo(stage: &mut Stage, target: &Path, options: &RepoOptions) -> Result<StepResult, String> {
    stage.mkdir(target);
    for relative in SCAFFOLD_DIRS {
        let dir = target.join(relative);
        stage.mkdir(&dir);
        if stage.entries(&dir).is_empty() {
            stage.write(&dir.join(".gitkeep"), "");
        }
    }
    let (mut files, mut skipped, mut warnings) = (Vec::new(), Vec::new(), Vec::new());
    let readme_path = target.join("README.md");
    if stage.is_file(&readme_path) {
        skipped.push("README.md".to_owned());
        // `--org` is not ignored: it reaches `organisation.toml` below.
        let ignored: Vec<&str> = [
            ("--name", &options.name),
            ("--description", &options.description),
        ]
        .into_iter()
        .filter(|(_, value)| value.as_deref().is_some_and(|text| !text.is_empty()))
        .map(|(flag, _)| flag)
        .collect();
        if !ignored.is_empty() {
            warnings.push(format!(
                "Left README.md unchanged; ignored {} because the file already exists",
                ignored.join(", ")
            ));
        }
    } else {
        stage.write(&readme_path, readme(target, options));
        files.push("README.md".to_owned());
    }
    let gitignore = target.join(GITIGNORE_PATH);
    let added = if stage.is_file(&gitignore) {
        match append_gitignore_lines(stage, target, &OPENTIDE_IGNORES) {
            Ok(added) => added,
            Err(GitignoreError::NotUtf8) => {
                warnings.push(format!(
                    "Left .gitignore unchanged: it is not UTF-8. Add these lines to it: {}",
                    OPENTIDE_IGNORES.join(", ")
                ));
                Vec::new()
            }
            Err(GitignoreError::Unreadable(error)) => {
                return Err(format!("{}: {error}", gitignore.display()));
            }
        }
    } else {
        let all: Vec<&str> = PYTHON_IGNORES
            .iter()
            .chain(OPENTIDE_IGNORES.iter())
            .copied()
            .collect();
        append_gitignore_lines(stage, target, &all).map_err(|_| not_utf8(&gitignore))?
    };
    if added.is_empty() {
        skipped.push(GITIGNORE_PATH.to_owned());
    } else {
        files.push(GITIGNORE_PATH.to_owned());
    }
    // Without `--org` the file is not touched: a rerun never erases it.
    if let Some(org) = options
        .org
        .as_deref()
        .map(str::trim)
        .filter(|org| !org.is_empty())
    {
        match organisation(stage, target, org)? {
            Organisation::Written => files.push(ORGANISATION_FILE.to_owned()),
            Organisation::Unchanged => skipped.push(ORGANISATION_FILE.to_owned()),
            Organisation::Kept(reason) => warnings.push(format!(
                "Left {ORGANISATION_FILE} unchanged: {reason}, so `opentide new` will not use --org"
            )),
        }
    }
    let name = repo_name(options, target);
    let mut result = StepResult::new([
        ("message", Json::str("Repository scaffold created")),
        ("path", Json::str(shown(target))),
        ("platforms", strings(&options.platforms)),
        ("name", Json::str(name)),
        ("scaffolded", Json::Bool(true)),
        ("files", strings(&files)),
        ("gitignore_added", strings(&added)),
    ]);
    if !skipped.is_empty() {
        result.set("skipped", strings(&skipped));
    }
    if !warnings.is_empty() {
        result.set("warnings", strings(&warnings));
    }
    if !options.platforms.is_empty() {
        repo_platforms(stage, target, &options.platforms, &mut result)?;
    }
    Ok(result)
}

/// `setup repo --platform`: the platforms step, its files under
/// `platform_files` and its warnings (the key changes of a platform file that
/// already exists) added to `result`'s.
fn repo_platforms(
    stage: &mut Stage,
    target: &Path,
    chosen: &[String],
    result: &mut StepResult,
) -> Result<(), String> {
    let step = platforms(stage, target, chosen)?;
    result.set(
        "platform_files",
        Json::Array(step.strings("files").iter().map(Json::str).collect()),
    );
    let mut warnings = result.strings("warnings");
    warnings.extend(step.strings("warnings"));
    if !warnings.is_empty() {
        result.set("warnings", strings(&warnings));
    }
    Ok(())
}

// ---------------------------------------------------------------- mcp

/// An MCP host: its command-line value, the file it reads, its template.
pub const MCP_HOSTS: [(&str, &str, opentide_dataset::TextFn); 4] = [
    ("vscode", ".vscode/mcp.json", || {
        opentide_dataset::text!("src/opentide/data/setup/mcp/vscode.json")
    }),
    ("cursor", ".cursor/mcp.json", || {
        opentide_dataset::text!("src/opentide/data/setup/mcp/cursor.json")
    }),
    ("claude-code", ".mcp.json", || {
        opentide_dataset::text!("src/opentide/data/setup/mcp/claude-code.json")
    }),
    ("generic", "opentide.mcp.json", || {
        opentide_dataset::text!("src/opentide/data/setup/mcp/generic.json")
    }),
];

/// The opentide VS Code extension.
pub const EXTENSION_ID: &str = "opentidehq.opentide";

/// What `setup mcp --vscode` says when the workspace recommends the extension.
pub const EXTENSION_MCP_NOTE: &str = "The opentide VS Code extension (opentidehq.opentide), which .vscode/extensions.json recommends, provides the opentide MCP server to VS Code; .vscode/mcp.json is for teammates without it";

/// Whether `.vscode/extensions.json` recommends the opentide extension.
pub fn recommends_extension(stage: &Stage, target: &Path) -> bool {
    let path = target.join(".vscode/extensions.json");
    let Ok(Some(text)) = read_text(stage, &path) else {
        return false;
    };
    jsonc::parse(&text).is_ok_and(|value| {
        value
            .get("recommendations")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| items.iter().any(|item| item == EXTENSION_ID))
    })
}

/// Writes or merges `host`'s configuration: its path relative to `target`,
/// and the warning for an `opentide` entry the file already had that keeps
/// fields opentide would write otherwise: re-running setup
/// never resets a customised server (its `command`, `args`, `env`).
///
/// # Errors
///
/// The existing file cannot be merged: the reason, for the warning.
pub fn write_mcp_config(
    stage: &mut Stage,
    target: &Path,
    host: &str,
) -> Result<(String, Option<String>), String> {
    let Some((_, relative, template)) = MCP_HOSTS.iter().find(|(name, _, _)| *name == host) else {
        return Err(format!("unknown MCP host {host}"));
    };
    let template = Json::parse(template()).unwrap_or(Json::Null);
    let dest = target.join(relative);
    let mut warning = None;
    let text = if stage.is_file(&dest) {
        let existing = match stage.read(&dest) {
            Ok(Some(bytes)) => String::from_utf8(bytes)
                .map_err(|_| "is not valid JSON (the file is not UTF-8)".to_owned())?,
            Ok(None) => String::new(),
            Err(error) => return Err(format!("is not valid JSON ({error})")),
        };
        let (merged, kept) = jsonc::merge_keeping_entries(&existing, &template)
            .map_err(|error| error.to_string())?;
        if !kept.is_empty() {
            warning = Some(format!(
                "{relative}: kept the opentide server's own {} (opentide writes {}); remove the entry and re-run setup mcp to reset it.",
                kept.join(", "),
                kept_defaults(&template, &kept)
            ));
        }
        merged
    } else {
        crate::json::document_text(&template, true)
    };
    stage.write(&dest, text);
    Ok(((*relative).to_owned(), warning))
}

/// What the template writes for each of `fields` (`command`,
/// `env.OPENTIDE_REPO_ROOT`), in the server entry it holds.
fn kept_defaults(template: &Json, fields: &[String]) -> String {
    let server = match template {
        Json::Object(members) => members.values().find_map(|servers| match servers {
            Json::Object(entries) => entries.values().next(),
            _ => None,
        }),
        _ => None,
    };
    fields
        .iter()
        .map(|field| {
            let mut value = server;
            for part in field.split('.') {
                value = match value {
                    Some(Json::Object(members)) => members.get(part),
                    _ => None,
                };
            }
            let shown = value.map_or_else(|| "nothing".to_owned(), Json::to_compact);
            format!("{field} {shown}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The warning for an MCP configuration left unchanged.
pub fn mcp_config_warning(relative: &str, problem: &str) -> String {
    format!("{relative} {problem}; left unchanged. Add the opentide server to it by hand.")
}

/// Why `opentide mcp start`, which every configuration launches, cannot
/// start here: what [`McpServer::probe`] finds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct McpServer {
    /// What the server needs that this installation cannot satisfy.
    pub missing: Vec<String>,
    /// The command that repairs the installation.
    pub hint: String,
    /// `opentide`, the command every configuration runs, is not on `PATH`.
    pub not_on_path: bool,
}

impl McpServer {
    /// The server `opentide mcp start` runs: this program's own
    /// ([`crate::mcp`]), compiled in with everything it serves, so it starts
    /// wherever this program does and needs nothing installed beside it
    /// (UC-6.0d, #841). What can be missing is the command itself: the
    /// configurations run a bare `opentide`, which a host finds on `PATH`
    /// only, and a virtual environment's is not there until it is activated.
    pub fn probe(env: &Env, cwd: &Path) -> McpServer {
        McpServer {
            not_on_path: command_not_on_path(env, cwd),
            ..McpServer::default()
        }
    }
}

/// `opentide` cannot be found on `env`'s `PATH`.
#[cfg(not(target_os = "wasi"))]
fn command_not_on_path(env: &Env, cwd: &Path) -> bool {
    let path = env.search_path().unwrap_or_default();
    crate::commands::doctor::on_path("opentide", path, cwd).is_none()
}

/// WASI (the VS Code extension): the host's `PATH` is not this program's,
/// so nothing is said about it.
#[cfg(target_os = "wasi")]
fn command_not_on_path(_: &Env, _: &Path) -> bool {
    false
}

/// `setup mcp`: each host's configuration; `server` is what
/// [`McpServer::probe`] found about `opentide mcp start`.
pub fn mcp(
    stage: &mut Stage,
    target: &Path,
    hosts: &[String],
    server: Option<&McpServer>,
) -> StepResult {
    let (mut written, mut skipped, mut warnings) = (Vec::new(), Vec::new(), Vec::new());
    for host in hosts {
        match write_mcp_config(stage, target, host) {
            Ok((relative, kept)) => {
                written.push(relative);
                warnings.extend(kept);
            }
            Err(problem) => {
                let relative = MCP_HOSTS
                    .iter()
                    .find(|(name, _, _)| name == host)
                    .map_or(host.as_str(), |(_, relative, _)| relative);
                skipped.push(relative.to_owned());
                warnings.push(mcp_config_warning(relative, &problem));
            }
        }
    }
    let mut result = StepResult::new([
        ("message", Json::str("MCP configuration generated")),
        ("path", Json::str(shown(target))),
        ("files", strings(&written)),
    ]);
    if !skipped.is_empty() {
        result.set("skipped", strings(&skipped));
    }
    if hosts.iter().any(|host| host == "vscode") && recommends_extension(stage, target) {
        result.set("extension_mcp", Json::Bool(true));
        result.set("detail", Json::str(EXTENSION_MCP_NOTE));
    }
    if hosts.iter().any(|host| host == "generic") {
        result.set(
            "advice",
            Json::str("Copy opentide.mcp.json into your editor MCP settings or run opentide setup mcp with a specific host flag."),
        );
    }
    // Every configuration runs `opentide mcp start`. Say so now rather than
    // leaving the user to debug a server their editor silently fails to start.
    let mut available = true;
    if let Some(server) = server.filter(|server| !server.missing.is_empty()) {
        available = false;
        warnings.push(format!(
            "These configs launch opentide mcp start, which cannot import {} in this environment. Repair it with: {}",
            server.missing.join(", "),
            server.hint
        ));
    }
    if server.is_some_and(|server| server.not_on_path) {
        available = false;
        warnings.push(
            "These configs launch opentide mcp start, but opentide is not on PATH, so the editor cannot start the server. Put opentide on PATH (pipx install opentide, or activate its virtual environment before starting the editor), or set the full path as the server command."
                .to_owned(),
        );
    }
    result.set("mcp_available", Json::Bool(available));
    if !warnings.is_empty() {
        result.set("warnings", strings(&warnings));
    }
    result
}

/// `path` relative to `base` when it is below it.
pub fn relative_to(path: &Path, base: &Path) -> PathBuf {
    path.strip_prefix(base)
        .map_or_else(|_| path.to_path_buf(), Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabling_a_platform_keeps_crlf_and_the_rest_of_the_line_endings() {
        assert_eq!(
            enable_platform_toml("[platform]\r\nenabled = false\r\nx = 1\r\n").unwrap(),
            "[platform]\r\nenabled = true\r\nx = 1\r\n"
        );
        assert_eq!(
            enable_platform_toml("[platform]\r\nx = 1\r\n").unwrap(),
            "[platform]\r\nenabled = true\r\nx = 1\r\n"
        );
        assert_eq!(
            enable_platform_toml("[platform]\nenabled=false # off\n").unwrap(),
            "[platform]\nenabled=true # off\n"
        );
        // Already enabled: no change, so the step skips the file.
        let enabled = "[platform]\nenabled = true\n";
        assert_eq!(enable_platform_toml(enabled).unwrap(), enabled);
        // No `[platform]` table: nothing to enable.
        let other = "[other]\nenabled = false\n";
        assert_eq!(enable_platform_toml(other).unwrap(), other);
        assert!(enable_platform_toml("[platform\n").is_err());
    }

    #[test]
    fn enabling_a_platform_sets_enabled_in_the_platform_table_only() {
        // Another table's `enabled` comes first in the file: it stays false.
        let content = "# Sentinel\n[defaults]\nenabled = false\n\n[platform]\n\
                       name = \"Sentinel\" # shown\nenabled = false\n\n\
                       # [[tenants]]\n[[tenants]]\nname = \"t\"\n";
        assert_eq!(
            enable_platform_toml(content).unwrap(),
            "# Sentinel\n[defaults]\nenabled = false\n\n[platform]\n\
             name = \"Sentinel\" # shown\nenabled = true\n\n\
             # [[tenants]]\n[[tenants]]\nname = \"t\"\n"
        );
        // `[platform]` without `enabled`, after a table that has one.
        assert_eq!(
            enable_platform_toml("[defaults]\nenabled = false\n[platform]\nname = \"x\"\n")
                .unwrap(),
            "[defaults]\nenabled = false\n[platform]\nenabled = true\nname = \"x\"\n"
        );
        // Every bundled template comes out enabled and otherwise unchanged.
        for platform in opentide_schema::platforms::PLATFORMS {
            let Some(file) = platform_file(platform.id) else {
                continue;
            };
            let template =
                opentide_schema::configuration::bundled::text(&format!("platforms/{file}"))
                    .unwrap();
            assert_eq!(
                enable_platform_toml(template).unwrap(),
                template.replacen("enabled = false", "enabled = true", 1),
                "{file}"
            );
        }
    }

    #[test]
    fn gitignore_lines_are_appended_once_in_the_files_line_endings() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(".gitignore"), "\u{feff}/build\r\nnode_modules").unwrap();
        let mut stage = Stage::new();
        let added = append_gitignore_lines(&mut stage, root, &["build/", ".env"]).unwrap();
        assert_eq!(added, [".env"]);
        assert_eq!(
            stage.read(&root.join(".gitignore")).unwrap().unwrap(),
            "\u{feff}/build\r\nnode_modules\r\n.env\r\n".as_bytes()
        );
        assert!(
            append_gitignore_lines(&mut stage, root, &[".env"])
                .unwrap()
                .is_empty()
        );
    }

    /// `setup repo --org` keeps the organisation where `opentide new` reads
    /// it (#1670, smoke B17): a uuid and the name, kept across reruns.
    #[test]
    fn org_is_kept_in_organisation_toml_and_a_rerun_neither_changes_nor_erases_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let file = root.join(ORGANISATION_FILE);
        let options = RepoOptions {
            org: Some("Example Corp".into()),
            ..RepoOptions::default()
        };
        let mut stage = Stage::new();
        let first = repo(&mut stage, root, &options).unwrap();
        assert!(
            first
                .strings("files")
                .contains(&ORGANISATION_FILE.to_owned())
        );
        let text = written(stage, &file);
        let document: toml_edit::DocumentMut = text.parse().unwrap();
        let uuid = document["uuid"].as_str().unwrap().to_owned();
        assert!(crate::commands::new::is_uuid(&uuid), "{text}");
        assert_eq!(document["name"].as_str(), Some("Example Corp"), "{text}");

        // The same `--org` again: the file already says it.
        let mut stage = Stage::new();
        let again = repo(&mut stage, root, &options).unwrap();
        assert!(
            again
                .strings("skipped")
                .contains(&ORGANISATION_FILE.to_owned())
        );
        assert!(
            !again
                .strings("files")
                .contains(&ORGANISATION_FILE.to_owned())
        );
        assert_eq!(written(stage, &file), text);

        // No `--org`: the file is not touched.
        let mut stage = Stage::new();
        repo(&mut stage, root, &RepoOptions::default()).unwrap();
        assert_eq!(written(stage, &file), text);

        // Another name renames the organisation and keeps its uuid, and the
        // README that is already there is not why `--org` is ignored.
        let renamed = RepoOptions {
            org: Some("  Other Corp ".into()),
            ..RepoOptions::default()
        };
        let mut stage = Stage::new();
        std::fs::write(root.join("README.md"), "mine").unwrap();
        let result = repo(&mut stage, root, &renamed).unwrap();
        assert!(
            result.strings("warnings").is_empty(),
            "{:?}",
            result.strings("warnings")
        );
        let text = written(stage, &file);
        let document: toml_edit::DocumentMut = text.parse().unwrap();
        assert_eq!(document["uuid"].as_str(), Some(uuid.as_str()), "{text}");
        assert_eq!(document["name"].as_str(), Some("Other Corp"), "{text}");
    }

    /// A file the user wrote keeps its other keys, its comments and its
    /// line endings; one that is not TOML is left alone with a warning.
    #[test]
    fn organisation_toml_keeps_what_the_user_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let file = root.join(ORGANISATION_FILE);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let mine =
            "# ours\r\nuuid = \"11111111-2222-4333-8444-555555555555\"\r\nname = \"Old\"\r\n";
        std::fs::write(&file, mine).unwrap();
        let mut stage = Stage::new();
        assert!(matches!(
            organisation(&mut stage, root, "New").unwrap(),
            Organisation::Written
        ));
        assert_eq!(
            written(stage, &file),
            "# ours\r\nuuid = \"11111111-2222-4333-8444-555555555555\"\r\nname = \"New\"\r\n"
        );

        std::fs::write(&file, "name = = 1\n").unwrap();
        let mut stage = Stage::new();
        let Organisation::Kept(reason) = organisation(&mut stage, root, "New").unwrap() else {
            panic!("an invalid file is kept");
        };
        assert!(reason.contains("not valid TOML"), "{reason}");
        assert_eq!(written(stage, &file), "name = = 1\n");

        // `new` trims a uuid before it checks it, so setup keeps a padded one
        // as it was written, and only renames.
        std::fs::write(
            &file,
            "uuid = \" 11111111-2222-4333-8444-555555555555 \"\nname = \"Old\"\n",
        )
        .unwrap();
        let mut stage = Stage::new();
        assert!(matches!(
            organisation(&mut stage, root, "New").unwrap(),
            Organisation::Written
        ));
        assert_eq!(
            written(stage, &file),
            "uuid = \" 11111111-2222-4333-8444-555555555555 \"\nname = \"New\"\n"
        );

        // A uuid that is there and is not one (a placeholder, a braced GUID,
        // a number) is never replaced: kept as it is, with the reason.
        for mine in [
            "uuid = \"{uuid}\"\nname = \"Old\"\n",
            "uuid = \"{11111111-2222-4333-8444-555555555555}\"\n",
            "uuid = 7\n",
        ] {
            std::fs::write(&file, mine).unwrap();
            let mut stage = Stage::new();
            let Organisation::Kept(reason) = organisation(&mut stage, root, "New").unwrap() else {
                panic!("{mine:?}: a uuid the user wrote is kept");
            };
            let expected = if mine == "uuid = 7\n" {
                "its uuid is not text"
            } else {
                "its uuid is not a UUID"
            };
            assert!(reason.starts_with(expected), "{mine:?}: {reason}");
            assert_eq!(written(stage, &file), mine);
        }
    }

    #[test]
    fn a_repo_scaffold_keeps_a_folder_with_content_and_an_existing_readme() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("objects/rules")).unwrap();
        std::fs::write(root.join("objects/rules/a.yaml"), "x").unwrap();
        std::fs::write(root.join("README.md"), "mine").unwrap();
        let mut stage = Stage::new();
        let options = RepoOptions {
            name: Some("X".into()),
            platforms: vec!["sentinel".into()],
            ..RepoOptions::default()
        };
        let result = repo(&mut stage, root, &options).unwrap();
        assert!(!stage.is_file(&root.join("objects/rules/.gitkeep")));
        assert!(stage.is_file(&root.join("objects/threats/.gitkeep")));
        assert_eq!(result.strings("skipped"), ["README.md"]);
        assert_eq!(
            result.strings("warnings"),
            ["Left README.md unchanged; ignored --name because the file already exists"]
        );
        assert_eq!(
            result.strings("platform_files"),
            [".opentide/configurations/platforms/sentinel.toml"]
        );
        let toml = String::from_utf8(
            stage
                .read(&root.join(".opentide/configurations/platforms/sentinel.toml"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(toml.contains("enabled = true"), "{toml}");
    }

    #[test]
    fn the_readme_names_the_platforms_and_the_metadata() {
        let options = RepoOptions {
            name: Some("Detections".into()),
            org: Some("Blue".into()),
            description: Some("Ours".into()),
            platforms: vec!["sentinel".into(), "splunk".into()],
        };
        let text = readme(Path::new("/x/ws"), &options);
        assert!(
            text.starts_with("# Detections\n\nOurs\n\n**Organisation:** Blue\n\n## Quick start")
        );
        // A command that runs as written (#1656): `deploy` needs `--strategy`.
        assert!(
            text.contains(
                "opentide deploy --platform splunk --dry-run --strategy PREVIEW --all\n```"
            )
        );
        assert!(text.ends_with("- sentinel\n- splunk\n"));
    }

    #[test]
    fn a_customised_opentide_server_is_kept_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let before = "{\n  \"mcpServers\": {\n    \"opentide\": {\n      \"command\": \"/opt/venv/bin/opentide\",\n      \"args\": [\"--repo\", \"x\", \"mcp\", \"start\"],\n      \"env\": {\"OPENTIDE_LOG\": \"debug\"}\n    }\n  }\n}\n";
        std::fs::write(root.join(".mcp.json"), before).unwrap();
        let mut stage = Stage::new();
        let result = mcp(&mut stage, root, &["claude-code".into()], None);
        assert_eq!(result.strings("files"), [".mcp.json"]);
        let after =
            String::from_utf8(stage.read(&root.join(".mcp.json")).unwrap().unwrap()).unwrap();
        let value = jsonc::parse(&after).unwrap();
        let server = &value["mcpServers"]["opentide"];
        assert_eq!(server["command"], "/opt/venv/bin/opentide", "{after}");
        assert_eq!(
            server["args"],
            serde_json::json!(["--repo", "x", "mcp", "start"]),
            "{after}"
        );
        // The entry's own environment stays; what it lacks is added.
        assert_eq!(server["env"]["OPENTIDE_LOG"], "debug", "{after}");
        assert_eq!(
            server["env"]["OPENTIDE_REPO_ROOT"], "${CLAUDE_PROJECT_DIR}",
            "{after}"
        );
        assert_eq!(
            result.strings("warnings"),
            [
                ".mcp.json: kept the opentide server's own command, args (opentide writes command \"opentide\", args [\"mcp\",\"start\"]); remove the entry and re-run setup mcp to reset it."
            ]
        );
        // A second run changes nothing, and an entry as opentide writes it
        // warns of nothing.
        std::fs::write(root.join(".mcp.json"), &after).unwrap();
        let mut stage = Stage::new();
        mcp(&mut stage, root, &["claude-code".into()], None);
        assert_eq!(
            String::from_utf8(stage.read(&root.join(".mcp.json")).unwrap().unwrap()).unwrap(),
            after
        );
        std::fs::remove_file(root.join(".mcp.json")).unwrap();
        let mut stage = Stage::new();
        mcp(&mut stage, root, &["claude-code".into()], None);
        let fresh = stage.read(&root.join(".mcp.json")).unwrap().unwrap();
        std::fs::write(root.join(".mcp.json"), fresh).unwrap();
        let again = mcp(&mut Stage::new(), root, &["claude-code".into()], None);
        assert!(
            again.get("warnings").is_none(),
            "{:?}",
            again.get("warnings")
        );
    }

    /// `setup vscode --mcp` writes through [`write_mcp_config`] too: a
    /// customised entry is kept, and the warning comes back to the caller.
    #[test]
    fn write_mcp_config_returns_the_kept_entry_warning() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        std::fs::write(
            root.join(".vscode/mcp.json"),
            r#"{"servers": {"opentide": {"command": "/x/opentide", "env": null}}}"#,
        )
        .unwrap();
        let mut stage = Stage::new();
        let (relative, warning) = write_mcp_config(&mut stage, root, "vscode").unwrap();
        assert_eq!(relative, ".vscode/mcp.json");
        let after = jsonc::parse(
            &String::from_utf8(stage.read(&root.join(".vscode/mcp.json")).unwrap().unwrap())
                .unwrap(),
        )
        .unwrap();
        let server = &after["servers"]["opentide"];
        assert_eq!(server["command"], "/x/opentide");
        // `null` is no value: the template's `env` fills it, without a warning.
        assert_eq!(server["env"]["OPENTIDE_REPO_ROOT"], "${workspaceFolder}");
        assert_eq!(
            warning.as_deref(),
            Some(
                ".vscode/mcp.json: kept the opentide server's own command (opentide writes command \"opentide\"); remove the entry and re-run setup mcp to reset it."
            )
        );
    }

    #[test]
    fn an_mcp_file_with_comments_is_merged_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        let before = "{\r\n  // ours\r\n  \"servers\": {\"x\": {}}\r\n}\r\n";
        std::fs::write(root.join(".vscode/mcp.json"), before).unwrap();
        let mut stage = Stage::new();
        let result = mcp(&mut stage, root, &["vscode".into()], None);
        assert_eq!(result.strings("files"), [".vscode/mcp.json"]);
        let after = String::from_utf8(stage.read(&root.join(".vscode/mcp.json")).unwrap().unwrap())
            .unwrap();
        assert!(after.starts_with("{\r\n  // ours\r\n"), "{after}");
        assert!(after.contains("\"opentide\""));
        std::fs::write(root.join(".cursor.json"), "").unwrap();
        std::fs::create_dir_all(root.join(".cursor")).unwrap();
        std::fs::write(root.join(".cursor/mcp.json"), "[]").unwrap();
        let refused = mcp(&mut Stage::new(), root, &["cursor".into()], None);
        assert_eq!(refused.strings("skipped"), [".cursor/mcp.json"]);
        assert_eq!(
            refused.strings("warnings"),
            [
                ".cursor/mcp.json is not a JSON object; left unchanged. Add the opentide server to it by hand."
            ]
        );
    }

    #[test]
    fn an_env_example_without_a_final_newline_gets_one_before_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(".env.example"), "A=1").unwrap();
        let mut stage = Stage::new();
        let result = env(&mut stage, root).unwrap();
        assert_eq!(result.strings("files"), [".env.example", ".gitignore"]);
        assert_eq!(
            stage.read(&root.join(".env.example")).unwrap().unwrap(),
            b"A=1\nOPENTIDE_REPO_ROOT=.\n"
        );
        // A file that ends its last line is not given a blank one.
        std::fs::write(root.join(".env.example"), "A=1\n").unwrap();
        let mut stage = Stage::new();
        env(&mut stage, root).unwrap();
        assert_eq!(
            stage.read(&root.join(".env.example")).unwrap().unwrap(),
            b"A=1\nOPENTIDE_REPO_ROOT=.\n"
        );
        // A CRLF file keeps CRLF, with or without its last line ended.
        for (before, after) in [
            ("A=1\r\n", "A=1\r\nOPENTIDE_REPO_ROOT=.\r\n"),
            ("A=1\r\nB=2", "A=1\r\nB=2\r\nOPENTIDE_REPO_ROOT=.\r\n"),
            ("A=1\r\nB=2\r", "A=1\r\nB=2\r\nOPENTIDE_REPO_ROOT=.\r\n"),
        ] {
            std::fs::write(root.join(".env.example"), before).unwrap();
            let mut stage = Stage::new();
            env(&mut stage, root).unwrap();
            assert_eq!(
                String::from_utf8(stage.read(&root.join(".env.example")).unwrap().unwrap())
                    .unwrap(),
                after
            );
        }
        // One that names the root already is left alone.
        let mut stage = Stage::new();
        std::fs::write(root.join(".env.example"), "OPENTIDE_REPO_ROOT=x").unwrap();
        let kept = env(&mut stage, root).unwrap();
        assert_eq!(kept.strings("skipped")[0], ".env.example");
        assert_eq!(
            kept.text("message"),
            Some("Environment example already present")
        );
    }

    #[test]
    fn only_the_vscode_host_reports_the_extension_server() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        std::fs::write(
            root.join(".vscode/extensions.json"),
            r#"{"recommendations": ["opentidehq.opentide"]}"#,
        )
        .unwrap();
        let cursor = mcp(&mut Stage::new(), root, &["cursor".into()], None);
        assert_eq!(cursor.get("extension_mcp"), None);
        assert_eq!(cursor.get("detail"), None);
        let vscode = mcp(&mut Stage::new(), root, &["vscode".into()], None);
        assert_eq!(vscode.get("extension_mcp"), Some(&Json::Bool(true)));
        assert_eq!(vscode.text("detail"), Some(EXTENSION_MCP_NOTE));
    }

    #[test]
    fn a_server_that_cannot_start_is_reported_unavailable_with_its_repair() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let broken = McpServer {
            missing: vec!["mcp.server.mcpserver".into()],
            hint: "pip install 'mcp>=2.3,<3'".into(),
            not_on_path: false,
        };
        let result = mcp(&mut Stage::new(), root, &["cursor".into()], Some(&broken));
        assert_eq!(result.get("mcp_available"), Some(&Json::Bool(false)));
        assert_eq!(
            result.strings("warnings"),
            [
                "These configs launch opentide mcp start, which cannot import mcp.server.mcpserver in this environment. Repair it with: pip install 'mcp>=2.3,<3'"
            ]
        );
        let fine = McpServer::default();
        for server in [Some(&fine), None] {
            let result = mcp(&mut Stage::new(), root, &["cursor".into()], server);
            assert_eq!(result.get("mcp_available"), Some(&Json::Bool(true)));
            assert_eq!(result.get("warnings"), None);
        }
        // The server is this program's: nothing is ever missing but the
        // command, which is found on PATH.
        let dir = tempfile::tempdir().unwrap();
        let found = dir.path().join(if cfg!(windows) {
            "opentide.exe"
        } else {
            "opentide"
        });
        std::fs::write(&found, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&found, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let on_path = Env::from_pairs([("PATH".to_owned(), dir.path().display().to_string())]);
        assert_eq!(McpServer::probe(&on_path, dir.path()), McpServer::default());
    }

    /// Every configuration runs a bare `opentide`: without one on `PATH`
    /// (a virtual environment not activated), the editor cannot start the
    /// server, and setup says so (#1670, smoke C6).
    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_command_not_on_path_is_reported_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let env = Env::from_pairs([("PATH".to_owned(), empty.display().to_string())]);
        let server = McpServer::probe(&env, dir.path());
        assert!(server.not_on_path);
        let result = mcp(
            &mut Stage::new(),
            dir.path(),
            &["cursor".into()],
            Some(&server),
        );
        assert_eq!(result.get("mcp_available"), Some(&Json::Bool(false)));
        let warnings = result.strings("warnings");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("opentide is not on PATH, so the editor cannot start the server"),
            "{warnings:?}"
        );
        // The configuration is still written.
        assert_eq!(result.strings("files"), [".cursor/mcp.json"]);
    }

    fn written(mut stage: Stage, path: &Path) -> String {
        stage.commit().unwrap();
        std::fs::read_to_string(path).unwrap()
    }

    /// Regenerating a platform file keeps the user's values and comments
    /// (only `enabled` is touched), and names the keys the bundled template
    /// adds and removes, bar the ones the model defaults (OT-7).
    #[test]
    fn a_platform_file_keeps_its_values_and_names_the_key_changes() {
        let relative = ".opentide/configurations/platforms/sentinel.toml";
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let file = target.join(relative);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let chosen = ["sentinel".to_owned()];

        // A file with the template's keys, edited: no warning, nothing lost.
        let template =
            opentide_schema::configuration::bundled::text("platforms/sentinel.toml").unwrap();
        let edited = template
            .replace("name = \"Microsoft Sentinel\"", "name = \"Mine\" # kept")
            .replace("enabled = false", "enabled = true");
        std::fs::write(&file, &edited).unwrap();
        let mut stage = Stage::new();
        let result = platforms(&mut stage, target, &chosen).unwrap();
        assert!(result.strings("warnings").is_empty(), "{result:?}");
        assert_eq!(
            result.strings("skipped"),
            [relative],
            "unchanged: not written"
        );

        // A template-shaped file without `description` (the model defaults
        // it), with tenants in either TOML form: no warning.
        for (before, after) in [
            ("", "\n[[tenants]]\nname = \"t\"\n[tenants.setup]\nx = 1\n"),
            (
                "tenants = [{ name = \"t\", setup = { x = 1 } }]\nmodifiers = [{ name = \"m\" }]\n\n",
                "",
            ),
        ] {
            let text = format!("{before}[platform]\nenabled = true\nname = \"Mine\"\n{after}");
            std::fs::write(&file, &text).unwrap();
            let mut stage = Stage::new();
            let result = platforms(&mut stage, target, &chosen).unwrap();
            assert!(result.strings("warnings").is_empty(), "{text}: {result:?}");
        }

        // A key the template does not have: named, and the user's values and
        // comments are kept (only `enabled` flips).
        let old = "[platform]\nenabled = false # off for now\nname = \"Mine\" # kept\n\
                   legacy_mode = true\n\n[[tenants]]\nname = \"t\"\n[tenants.setup]\nx = 1\n";
        std::fs::write(&file, old).unwrap();
        let mut stage = Stage::new();
        let result = platforms(&mut stage, target, &chosen).unwrap();
        let warnings = result.strings("warnings");
        assert_eq!(
            warnings,
            [format!(
                "{relative} was kept with your values: the new template removes \
                 platform.legacy_mode. Add or delete those keys by hand."
            )]
        );
        assert_eq!(
            written(stage, &file),
            old.replace("enabled = false", "enabled = true")
        );
    }

    /// The diff itself, against a template with a key the model does not
    /// default.
    #[test]
    fn platform_key_changes_names_added_and_removed_keys() {
        let relative = "platforms/x.toml";
        let template = "[platform]\nenabled = false\nname = \"X\"\nregion = \"eu\"\n\n\
                        [platform.options]\nretries = 3\n";
        let only_added = "[platform]\nenabled = true\n";
        assert_eq!(
            platform_key_changes(relative, only_added, template).unwrap(),
            "platforms/x.toml was kept with your values: the new template adds \
             platform.region, platform.options.retries. Add or delete those keys by hand."
        );
        let both = "[platform]\nenabled = true\nregion = \"us\"\nold = 1\n";
        let warning = platform_key_changes(relative, both, template).unwrap();
        assert!(
            warning
                .contains("adds platform.options.retries; the new template removes platform.old"),
            "{warning}"
        );
        // Defaulted keys are never added, and the same keys give no warning.
        let defaulted = "[platform]\nregion = \"eu\"\n[platform.options]\nretries = 1\n";
        assert_eq!(platform_key_changes(relative, defaulted, template), None);
        assert_eq!(platform_key_changes(relative, template, template), None);
        assert_eq!(
            platform_key_changes(relative, "not = [toml", template),
            None
        );
    }

    /// `setup repo --platform` carries the platforms step's warnings.
    #[test]
    fn setup_repo_keeps_the_platform_warnings() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let file = target.join(".opentide/configurations/platforms/sentinel.toml");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "[platform]\nenabled = true\nlegacy_mode = true\n").unwrap();
        let options = RepoOptions {
            platforms: vec!["sentinel".into()],
            ..RepoOptions::default()
        };
        let mut stage = Stage::new();
        let result = repo(&mut stage, target, &options).unwrap();
        assert!(
            result
                .strings("warnings")
                .iter()
                .any(|warning| warning.contains("removes platform.legacy_mode")),
            "{result:?}"
        );
    }

    /// `setup platforms` adds what it enables to the README's platform
    /// list `setup repo` wrote (#1670, smoke B17), keeping its line endings.
    #[test]
    fn enabling_platforms_lists_them_in_the_readme_setup_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let options = RepoOptions {
            platforms: vec!["sentinel".into()],
            ..RepoOptions::default()
        };
        let readme_path = target.join("README.md");
        std::fs::write(&readme_path, readme(target, &options)).unwrap();
        let mut stage = Stage::new();
        let chosen = [
            "splunk".to_owned(),
            "sentinel".to_owned(),
            "elastic".to_owned(),
        ];
        let result = platforms(&mut stage, target, &chosen).unwrap();
        assert!(
            result.strings("updated").contains(&"README.md".to_owned()),
            "{result:?}"
        );
        let text = written(stage, &readme_path);
        assert!(
            text.ends_with("## Platforms\n\n- sentinel\n- splunk\n- elastic\n"),
            "{text}"
        );
        // Nothing new to list: the README is left alone.
        let mut stage = Stage::new();
        let again = platforms(&mut stage, target, &chosen).unwrap();
        assert!(!again.strings("updated").contains(&"README.md".to_owned()));

        // The placeholder line of a README written with no platform goes.
        let none = readme(target, &RepoOptions::default()).replace('\n', "\r\n");
        assert_eq!(
            readme_with_platforms(&none, &["graylog".to_owned()]).unwrap(),
            none.replace(
                "- (configure platforms in .opentide/configurations/)",
                "- graylog"
            )
        );
        // #1946: multi-byte text before the section is kept as it is.
        let accented = "# Détection 😀\n\n## Platforms\n\n- sentinel\n";
        assert_eq!(
            readme_with_platforms(accented, &["splunk".to_owned()]).unwrap(),
            "# Détection 😀\n\n## Platforms\n\n- sentinel\n- splunk\n"
        );
        // A section the user rewrote is not setup's list: left alone.
        for edited in [
            "# X\n\n## Platforms\n\n- sentinel (our main SIEM)\n",
            "# X\n\n## Platforms\n\n- sentinel\n\n## Contact\n\nus\n",
            "# X\n\nNo platform section.\n",
        ] {
            assert_eq!(readme_with_platforms(edited, &["splunk".to_owned()]), None);
        }
    }
}
