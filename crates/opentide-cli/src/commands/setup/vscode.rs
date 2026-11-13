//! `opentide setup vscode` and the `vscode` step of `setup --vscode-setup`
//! (`services/setup/vscode.py`): deprecated, superseded by the opentide VS
//! Code extension. The step runs `generate templates` and `generate schemas`
//! first, recommends the extension in `.vscode/extensions.json`, removes the
//! `yaml.schemas` mappings earlier releases wrote from
//! `.vscode/settings.json`, writes the template snippets and, with `--mcp`,
//! `.vscode/mcp.json`.
//!
//! Every file goes through the [`Stage`], the generated ones included, so
//! `--plan` lists what the run writes and writes nothing. The two JSON files
//! are the user's: an edit changes only the members it names on
//! jsonc-parser's concrete syntax tree ([`jsonc::edit`]), and a file whose
//! edit cannot be made is rewritten whole only when it has no comments to
//! lose; otherwise it is left as it is, with a warning.

use std::path::Path;

use opentide_schema::generate::workspace::{CORE_OBJECT_TYPES, snippets, templates};
use opentide_schema::node::{Node, Value};
use opentide_workspace::Workspace;

use super::Context;
use super::files::{self, EXTENSION_ID, EXTENSION_MCP_NOTE, StepResult, strings};
use super::jsonc::{self, MergeError};
use super::stage::Stage;
use crate::json::Json;
use crate::mode::Mode;

/// What every run says first: the command is on its way out.
pub const DEPRECATION_MESSAGE: &str = "opentide setup vscode is deprecated and will be removed \
     when the opentide VS Code extension ships with a bundled language server and template \
     actions.";

/// `.opentide/` in a workspace.
const OPENTIDE_DIR: &str = files::OPENTIDE_DIR;
const EXTENSIONS: &str = ".vscode/extensions.json";
const SETTINGS: &str = ".vscode/settings.json";

/// What the step does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the command's switches, one field each"
)]
pub struct Options {
    /// Recommend the extension and remove opentide's `yaml.schemas`.
    pub settings: bool,
    /// Write the template snippets.
    pub snippets: bool,
    /// Run `generate templates` and `generate schemas` first.
    pub generate: bool,
    /// Merge into `.vscode/extensions.json` rather than replace it.
    pub merge: bool,
    /// Write `.vscode/mcp.json` as well.
    pub mcp: bool,
}

impl Options {
    /// `setup --vscode-setup`: everything but the MCP configuration.
    pub fn all() -> Options {
        Options {
            settings: true,
            snippets: true,
            generate: true,
            merge: true,
            mcp: false,
        }
    }

    /// `setup vscode`'s switches: `--settings` and `--snippets` each alone,
    /// both when neither is given.
    pub fn from_flags(settings: bool, snippets: bool) -> Options {
        Options {
            settings: settings || !snippets,
            snippets: snippets || !settings,
            ..Options::all()
        }
    }
}

/// What the step did.
#[derive(Clone, Debug)]
pub struct Done {
    /// Its result's members, in the oracle's order.
    pub result: StepResult,
    /// The snippets were asked for and could not be written: the run fails
    /// (exit 1), the files it wrote kept.
    pub failed: bool,
}

/// The deprecation, said once where the step runs, before anything it
/// logs: a log line under `--json` (`vscode_setup_deprecated`), else a
/// `warning:` line on stderr (`emit_vscode_deprecation`).
pub fn deprecation(cx: &Context<'_>) {
    if cx.mode == Mode::Json {
        tracing::warn!(detail = DEPRECATION_MESSAGE, "vscode_setup_deprecated");
        return;
    }
    let line = cx
        .terminal
        .stderr
        .warnings(&[DEPRECATION_MESSAGE.trim_end_matches('.').to_owned()]);
    if let Ok(mut stderr) = cx.stderr.lock() {
        let _ = stderr.write_all(line.as_bytes());
        let _ = stderr.flush();
    }
}

/// Runs the step on the repository at `root` (absolute) into `stage`.
///
/// # Errors
///
/// The workspace's configuration does not resolve, or a generator fails:
/// the message.
pub fn run(
    stage: &mut Stage,
    root: &Path,
    options: Options,
    cx: &Context<'_>,
) -> Result<Done, String> {
    stage.mkdir(root);
    let shown = root.to_string_lossy().into_owned();
    let (_, roots) = crate::commands::placement(Some(&shown), cx.env, cx.cwd);
    let workspace = crate::commands::open(roots)?;
    let mut generated: Vec<String> = Vec::new();
    if options.generate {
        let mut phases = Vec::new();
        if options.snippets {
            phases.push("templates");
        }
        if options.settings {
            phases.push("schemas");
        }
        for phase in phases {
            let outputs =
                crate::commands::generate::phase_outputs(phase, &workspace, root, cx.version)
                    .map_err(|detail| format!("{phase}: {detail}"))?;
            for output in outputs {
                stage.write(&output.path, output.bytes);
            }
            generated.push(phase.to_owned());
        }
    }
    let config = &workspace.configuration().resolved.tree;
    let mut written: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    if options.settings {
        written.extend(write_extensions(stage, root, options.merge, &mut warnings));
        written.extend(write_settings(stage, root, config, &mut warnings));
    }
    let mut snippet_path = None;
    if options.snippets {
        snippet_path = write_snippets(stage, root, &workspace);
        written.extend(snippet_path.clone());
    }
    if options.mcp {
        match files::write_mcp_config(stage, root, "vscode") {
            Ok(relative) => written.push(relative),
            Err(problem) => warnings.push(files::mcp_config_warning(".vscode/mcp.json", &problem)),
        }
    }
    let extension_mcp = options.mcp && files::recommends_extension(stage, root);
    let mut result = StepResult::new([
        ("message", Json::str("VS Code setup complete (deprecated)")),
        ("files", strings(&written)),
        ("generated", strings(&generated)),
        ("deprecated", Json::str(DEPRECATION_MESSAGE)),
        ("status", Json::str("completed")),
    ]);
    if !warnings.is_empty() {
        result.set("warnings", strings(&warnings));
    }
    if extension_mcp {
        result.set("extension_mcp", Json::Bool(true));
        result.set("detail", Json::str(EXTENSION_MCP_NOTE));
    }
    let failed = options.snippets && snippet_path.is_none();
    if failed {
        let message = format!(
            "VS Code snippets were not generated (no templates in {OPENTIDE_DIR}/templates)"
        );
        tracing::error!(detail = message.as_str(), "vscode_snippets_missing");
        result.set("status", Json::str("failed"));
        result.set("message", Json::str(message));
    }
    Ok(Done { result, failed })
}

// ---------------------------------------------------------------- snippets

/// Whether `.opentide/templates/` holds a template (`_templates_ready`).
fn templates_ready(stage: &Stage, root: &Path) -> bool {
    let dir = root.join(OPENTIDE_DIR).join("templates");
    stage.entries(&dir).iter().any(|name| {
        // `glob("*.yaml")`: as written, as on a case-sensitive file system.
        Path::new(name)
            .extension()
            .is_some_and(|extension| extension == "yaml" || extension == "yml")
    })
}

/// Writes the snippets from the templates as they stand
/// (`run_vscode_snippets`); their path, or `None` with a log line when
/// there are no templates to read.
fn write_snippets(stage: &mut Stage, root: &Path, workspace: &Workspace) -> Option<String> {
    if !templates_ready(stage, root) {
        tracing::warn!(
            detail =
                format!("No templates in {OPENTIDE_DIR}/templates — run opentide generate first")
                    .as_str(),
            "vscode_snippets_skipped"
        );
        return None;
    }
    let config = &workspace.configuration().resolved.tree;
    let expected = match templates(config) {
        Ok(expected) => expected,
        Err(error) => {
            tracing::warn!(
                detail = error.to_string().as_str(),
                "vscode_snippets_skipped"
            );
            return None;
        }
    };
    // The snippets quote the templates as they are on disk (or staged).
    let on_disk: Vec<_> = expected
        .into_iter()
        .filter_map(|mut artifact| {
            artifact.text = files::read_text(stage, &root.join(&artifact.path)).ok()??;
            Some(artifact)
        })
        .collect();
    match snippets(config, &on_disk) {
        Ok(snippet) => {
            stage.write(&root.join(&snippet.path), snippet.text);
            Some(snippet.path)
        }
        Err(detail) => {
            tracing::warn!(detail = detail.as_str(), "vscode_snippets_skipped");
            None
        }
    }
}

// ---------------------------------------------------------------- the JSON files

/// A file that cannot be read is left as it is, with a warning and a log
/// line (`_unreadable`).
fn unreadable(path: &Path, error: &str, warnings: &mut Vec<String>, advice: &str) {
    let shown = path.to_string_lossy();
    tracing::warn!(path = shown.as_ref(), error, "vscode_file_unreadable");
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    warnings.push(format!(
        "Could not read .vscode/{name}; left it unchanged. {advice}"
    ));
}

/// The file's text and its value, or why it cannot be read.
fn read_source(stage: &Stage, path: &Path) -> Result<(String, Json), String> {
    let bytes = stage
        .read(path)
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    let text = String::from_utf8(bytes).map_err(|error| error.to_string())?;
    match jsonc::ordered(&text) {
        Some(value) => Ok((text, value)),
        None => Err(jsonc::parse(&text)
            .err()
            .unwrap_or_else(|| "not valid JSON".to_owned())),
    }
}

/// Writes `edited` (the edit of `text`) to `path` when it reads back as
/// `expected`; else `expected` whole in the file's line endings, unless the
/// file has comments that would be lost, which leaves it unchanged with a
/// warning (`_write_edited`). Whether it was written.
fn write_edited(
    stage: &mut Stage,
    path: &Path,
    text: &str,
    edited: Result<String, MergeError>,
    expected: &Json,
    warnings: &mut Vec<String>,
    advice: &str,
) -> bool {
    if let Ok(edited) = edited
        && jsonc::ordered(&edited).as_ref() == Some(expected)
    {
        stage.write(path, edited);
        return true;
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if jsonc::has_comments(text) {
        warnings.push(format!(
            ".vscode/{name} has comments setup cannot keep in this change; left it unchanged. {advice}"
        ));
        return false;
    }
    let bom = if text.starts_with('\u{feff}') {
        "\u{feff}"
    } else {
        ""
    };
    stage.write(
        path,
        format!("{bom}{}", jsonc::dumps(expected, jsonc::newline(text))),
    );
    true
}

/// The members of an object value (none for another value).
fn members(value: &Json) -> Vec<(String, Json)> {
    match value {
        Json::Object(members) => members.clone(),
        _ => Vec::new(),
    }
}

/// `members` with `key` set to `value`, in its place when it is there.
fn with_member(mut members: Vec<(String, Json)>, key: &str, value: Json) -> Json {
    match members.iter_mut().find(|(name, _)| name == key) {
        Some((_, slot)) => *slot = value,
        None => members.push((key.to_owned(), value)),
    }
    Json::Object(members)
}

/// Writes or merges `.vscode/extensions.json` recommending the extension
/// (`write_vscode_extensions`); its path when written.
fn write_extensions(
    stage: &mut Stage,
    root: &Path,
    merge: bool,
    warnings: &mut Vec<String>,
) -> Option<String> {
    let dir = root.join(".vscode");
    stage.mkdir(&dir);
    let path = dir.join("extensions.json");
    let advice =
        format!("Add {EXTENSION_ID} to its recommendations by hand, or re-run with --no-merge.");
    let fresh = Json::object([(
        "recommendations",
        Json::Array(vec![Json::str(EXTENSION_ID)]),
    )]);
    let exists = stage.is_file(&path);
    if !(merge && exists) {
        let newline = if exists {
            files::read_text(stage, &path)
                .ok()
                .flatten()
                .map_or("\n", |text| jsonc::newline(&text))
        } else {
            "\n"
        };
        stage.write(&path, jsonc::dumps(&fresh, newline));
        return Some(EXTENSIONS.to_owned());
    }
    let (text, existing) = match read_source(stage, &path) {
        Ok(read) => read,
        Err(error) => {
            unreadable(&path, &error, warnings, &advice);
            return None;
        }
    };
    let existing = members(&existing);
    let field = |key: &str| {
        existing
            .iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    };
    let (listed, recommendations) = match field("recommendations") {
        None => (true, Vec::new()),
        Some(Json::Array(items)) => (true, items.clone()),
        Some(_) => (false, Vec::new()),
    };
    let unwanted = match field("unwantedRecommendations") {
        Some(Json::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    let id = Json::str(EXTENSION_ID);
    let missing: Vec<Json> = (!recommendations.contains(&id) && !unwanted.contains(&id))
        .then(|| id.clone())
        .into_iter()
        .collect();
    if listed && missing.is_empty() {
        return None;
    }
    let mut all = recommendations;
    all.extend(missing.iter().cloned());
    let expected = with_member(existing.clone(), "recommendations", Json::Array(all));
    let edited = jsonc::edit(&text, |object| {
        let Some(member) = object.get("recommendations") else {
            object.append(
                "recommendations",
                jsonc::input(&Json::Array(missing.clone())),
            );
            return Ok(());
        };
        let array = member
            .array_value()
            .ok_or_else(|| MergeError::MemberNotAnObject("recommendations".into()))?;
        for item in &missing {
            array.append(jsonc::input(item));
        }
        Ok(())
    });
    write_edited(stage, &path, &text, edited, &expected, warnings, &advice)
        .then(|| EXTENSIONS.to_owned())
}

/// Removes the `yaml.schemas` entries opentide wrote from
/// `.vscode/settings.json` (`write_vscode_settings`): the user's own entries
/// and their globs in the router's mapping are kept, an emptied
/// `yaml.schemas` is removed, and the file is never created. Its path when
/// rewritten.
fn write_settings(
    stage: &mut Stage,
    root: &Path,
    config: &Node,
    warnings: &mut Vec<String>,
) -> Option<String> {
    let path = root.join(SETTINGS);
    if !stage.is_file(&path) {
        return None;
    }
    let advice = "Remove opentide's yaml.schemas entries from it by hand, if it has any.";
    let (text, existing) = match read_source(stage, &path) {
        Ok(read) => read,
        Err(error) => {
            unreadable(&path, &error, warnings, advice);
            return None;
        }
    };
    let Json::Object(existing) = existing else {
        return None;
    };
    let Some(Json::Object(schemas)) = existing
        .iter()
        .rev()
        .find(|(name, _)| name == "yaml.schemas")
        .map(|(_, value)| value.clone())
    else {
        return None;
    };
    let mappings = Mappings::of(config);
    let kept: Vec<(String, Json)> = schemas
        .iter()
        .filter_map(|(schema, globs)| {
            mappings
                .without_opentide(schema, globs)
                .map(|rest| (schema.clone(), rest))
        })
        .collect();
    if kept == schemas {
        return None;
    }
    let expected = if kept.is_empty() {
        Json::Object(
            existing
                .iter()
                .filter(|(name, _)| name != "yaml.schemas")
                .cloned()
                .collect(),
        )
    } else {
        with_member(existing.clone(), "yaml.schemas", Json::Object(kept.clone()))
    };
    let edited = jsonc::edit(&text, |object| {
        let member = object
            .get("yaml.schemas")
            .ok_or_else(|| MergeError::MemberNotAnObject("yaml.schemas".into()))?;
        if kept.is_empty() {
            member.remove();
            return Ok(());
        }
        let inner = member
            .object_value()
            .ok_or_else(|| MergeError::MemberNotAnObject("yaml.schemas".into()))?;
        for (schema, globs) in &schemas {
            let Some(entry) = inner.get(schema) else {
                continue;
            };
            match kept.iter().find(|(name, _)| name == schema) {
                None => entry.remove(),
                Some((_, rest)) if rest != globs => entry.set_value(jsonc::input(rest)),
                Some(_) => {}
            }
        }
        Ok(())
    });
    write_edited(stage, &path, &text, edited, &expected, warnings, advice)
        .then(|| SETTINGS.to_owned())
}

/// The `yaml.schemas` mappings earlier releases of `setup vscode` wrote,
/// from the workspace's `paths` configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mappings {
    /// The router schema: `.opentide/schemas/opentide.schema.json` by default.
    router: String,
    /// The object families.
    families: Vec<String>,
    /// Their folders, workspace-relative, without a trailing `/`.
    folders: Vec<String>,
}

impl Mappings {
    /// The mappings of the resolved configuration `config`.
    pub fn of(config: &Node) -> Mappings {
        let paths: Option<&Node> = config.get("paths").map(AsRef::as_ref);
        let at = |keys: &[&str]| -> Option<&Node> {
            let mut node = paths?;
            for key in keys {
                node = node.get(key)?.as_ref();
            }
            Some(node)
        };
        let text =
            |node: Option<&Node>| node.and_then(|node| node.value.as_str().map(str::to_owned));
        let schemas = at(&["artifacts", "schemas"]).or_else(|| at(&["json_schemas"]));
        let router = text(schemas.and_then(|schemas| schemas.get("router").map(AsRef::as_ref)))
            .unwrap_or_else(|| "opentide.schema.json".to_owned());
        let families: Vec<String> = match at(&["objects"]).map(|node| &node.value) {
            Some(Value::Seq(items)) if !items.is_empty() => items
                .iter()
                .filter_map(|item| item.value.as_str().map(str::to_owned))
                .collect(),
            _ => CORE_OBJECT_TYPES
                .iter()
                .map(|&family| family.to_owned())
                .collect(),
        };
        let folders = families
            .iter()
            .map(|family| {
                text(at(&["paths", "objects", family]))
                    .unwrap_or_else(|| format!("objects/{family}s/"))
                    .trim_end_matches('/')
                    .to_owned()
            })
            .collect();
        Mappings {
            router: format!("{OPENTIDE_DIR}/schemas/{router}"),
            families,
            folders,
        }
    }

    /// The glob over the object folders: one under their common parent, or
    /// one per folder when they share none (`_object_glob`).
    fn object_glob(&self) -> Vec<String> {
        let parent = |folder: &str| -> String {
            match folder.rsplit_once('/') {
                Some((parent, _)) if !parent.is_empty() => parent.to_owned(),
                Some(_) => "/".to_owned(),
                None => ".".to_owned(),
            }
        };
        let mut parents: Vec<String> = self.folders.iter().map(|folder| parent(folder)).collect();
        parents.sort();
        parents.dedup();
        if let [parent] = parents.as_slice()
            && parent != "."
        {
            return vec![format!("{parent}/**/*.yaml")];
        }
        self.folders
            .iter()
            .map(|folder| format!("{folder}/**/*.yaml"))
            .collect()
    }

    /// Each folder's own globs, recursive and not.
    fn per_folder(&self) -> Vec<String> {
        self.folders
            .iter()
            .flat_map(|folder| [format!("{folder}/**/*.yaml"), format!("{folder}/*.yaml")])
            .collect()
    }

    /// Whether `schema` mapped to `globs` is a per-folder revision mapping
    /// an earlier release wrote (`_is_stale_revision_mapping`).
    fn stale_revision(&self, schema: &str, globs: &Json) -> bool {
        let schema = schema.strip_prefix("./").unwrap_or(schema);
        let Some(rest) = schema.strip_prefix(&format!("{OPENTIDE_DIR}/schemas/")) else {
            return false;
        };
        let digits = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit());
        let revision = self.families.iter().any(|family| {
            rest.strip_prefix(family.as_str())
                .and_then(|rest| rest.strip_prefix('.'))
                .and_then(|rest| rest.strip_suffix(".schema.json"))
                .and_then(|rest| rest.split_once('.'))
                .is_some_and(|(major, minor)| digits(major) && digits(minor))
        });
        if !revision {
            return false;
        }
        let generated = self.per_folder();
        let values: Vec<&Json> = match globs {
            Json::Str(_) => vec![globs],
            Json::Array(items) => items.iter().collect(),
            _ => return false,
        };
        !values.is_empty()
            && values.iter().all(|value| match value {
                Json::Str(text) => generated.contains(text),
                _ => false,
            })
    }

    /// What of the entry `schema` → `globs` to keep: all of it, the user's
    /// globs of the router's mapping, or `None` (`_without_opentide_mapping`).
    pub fn without_opentide(&self, schema: &str, globs: &Json) -> Option<Json> {
        if schema.strip_prefix("./").unwrap_or(schema) == self.router {
            let mut generated = self.object_glob();
            generated.extend(self.per_folder());
            let values: Vec<&Json> = match globs {
                Json::Str(_) => vec![globs],
                Json::Array(items) => items.iter().collect(),
                _ => return None,
            };
            let ours = |value: &Json| match value {
                Json::Str(text) => {
                    let text = text.strip_prefix("./").unwrap_or(text);
                    generated.iter().any(|glob| glob == text)
                }
                _ => false,
            };
            if !values.is_empty() && !values.iter().any(|value| ours(value)) {
                return Some(globs.clone());
            }
            let theirs: Vec<Json> = values
                .into_iter()
                .filter(|value| !ours(value))
                .cloned()
                .collect();
            return (!theirs.is_empty()).then_some(Json::Array(theirs));
        }
        if self.stale_revision(schema, globs) {
            return None;
        }
        Some(globs.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mappings() -> Mappings {
        Mappings {
            router: ".opentide/schemas/opentide.schema.json".into(),
            families: vec!["threat".into(), "objective".into(), "rule".into()],
            folders: vec![
                "objects/threats".into(),
                "objects/objectives".into(),
                "objects/rules".into(),
            ],
        }
    }

    fn json(text: &str) -> Json {
        Json::parse(text).unwrap()
    }

    #[test]
    fn the_router_mapping_keeps_only_the_users_globs() {
        let m = mappings();
        let router = ".opentide/schemas/opentide.schema.json";
        assert_eq!(
            m.without_opentide(router, &json(r#""objects/**/*.yaml""#)),
            None
        );
        assert_eq!(
            m.without_opentide(
                &format!("./{router}"),
                &json(r#"["./objects/**/*.yaml", "mine/*.yaml"]"#)
            ),
            Some(json(r#"["mine/*.yaml"]"#))
        );
        // A mapping of the router to the user's folders only is theirs, as written.
        assert_eq!(
            m.without_opentide(router, &json(r#""mine/*.yaml""#)),
            Some(json(r#""mine/*.yaml""#))
        );
        assert_eq!(m.without_opentide(router, &json("[]")), None);
        assert_eq!(m.without_opentide(router, &json("3")), None);
    }

    #[test]
    fn a_per_folder_revision_mapping_is_stale_and_another_schema_is_kept() {
        let m = mappings();
        assert_eq!(
            m.without_opentide(
                ".opentide/schemas/rule.1.0.schema.json",
                &json(r#"["objects/rules/**/*.yaml", "objects/rules/*.yaml"]"#)
            ),
            None
        );
        let theirs = json(r#"["custom/*.yaml"]"#);
        assert_eq!(
            m.without_opentide(".opentide/schemas/rule.1.0.schema.json", &theirs),
            Some(theirs.clone())
        );
        assert_eq!(
            m.without_opentide("other.schema.json", &theirs),
            Some(theirs)
        );
        assert!(!m.stale_revision(
            ".opentide/schemas/rule.x.0.schema.json",
            &json(r#""objects/rules/*.yaml""#)
        ));
    }

    #[test]
    fn folders_without_a_common_parent_get_a_glob_each() {
        let mut m = mappings();
        assert_eq!(m.object_glob(), ["objects/**/*.yaml"]);
        m.folders = vec!["threats".into(), "a/rules".into()];
        assert_eq!(m.object_glob(), ["threats/**/*.yaml", "a/rules/**/*.yaml"]);
    }

    #[test]
    fn the_switches_default_to_both_halves() {
        assert_eq!(Options::from_flags(false, false), Options::all());
        let settings = Options::from_flags(true, false);
        assert!(settings.settings && !settings.snippets);
        let snippets = Options::from_flags(false, true);
        assert!(!snippets.settings && snippets.snippets);
    }

    fn extensions(
        before: Option<&str>,
        merge: bool,
    ) -> (Option<String>, Vec<String>, Option<String>) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if let Some(before) = before {
            std::fs::create_dir_all(root.join(".vscode")).unwrap();
            std::fs::write(root.join(EXTENSIONS), before).unwrap();
        }
        let mut stage = Stage::new();
        let mut warnings = Vec::new();
        let written = write_extensions(&mut stage, root, merge, &mut warnings);
        stage.commit().unwrap();
        let after = std::fs::read_to_string(root.join(EXTENSIONS)).ok();
        (written, warnings, after)
    }

    #[test]
    fn a_new_extensions_file_recommends_the_extension() {
        let (written, warnings, after) = extensions(None, true);
        assert_eq!(written.as_deref(), Some(EXTENSIONS));
        assert!(warnings.is_empty());
        assert_eq!(
            after.as_deref(),
            Some("{\n  \"recommendations\": [\n    \"opentidehq.opentide\"\n  ]\n}\n")
        );
    }

    #[test]
    fn a_merge_keeps_comments_crlf_and_the_bom_and_adds_the_id_once() {
        let before = "\u{feff}{\r\n  // the team's\r\n  \"recommendations\": [\r\n    \"a.b\"\r\n  ]\r\n}\r\n";
        let (written, warnings, after) = extensions(Some(before), true);
        assert_eq!(written.as_deref(), Some(EXTENSIONS));
        assert!(warnings.is_empty());
        let after = after.unwrap();
        assert!(
            after.starts_with("\u{feff}{\r\n  // the team's\r\n"),
            "{after:?}"
        );
        assert!(!after.replace("\r\n", "").contains('\n'), "{after:?}");
        let value = jsonc::parse(&after).unwrap();
        assert_eq!(
            value["recommendations"],
            serde_json::json!(["a.b", EXTENSION_ID])
        );
        // Already recommended: nothing to write.
        let (written, _, again) = extensions(Some(&after), true);
        assert_eq!(written, None);
        assert_eq!(again.as_deref(), Some(after.as_str()));
    }

    #[test]
    fn an_unwanted_or_unreadable_file_is_left_alone() {
        let unwanted =
            "{\"unwantedRecommendations\": [\"opentidehq.opentide\"], \"recommendations\": []}";
        let (written, warnings, after) = extensions(Some(unwanted), true);
        assert_eq!(written, None);
        assert!(warnings.is_empty());
        assert_eq!(after.as_deref(), Some(unwanted));
        let broken = "{ not json";
        let (written, warnings, after) = extensions(Some(broken), true);
        assert_eq!(written, None);
        assert_eq!(
            warnings,
            [format!(
                "Could not read .vscode/extensions.json; left it unchanged. Add {EXTENSION_ID} to its recommendations by hand, or re-run with --no-merge."
            )]
        );
        assert_eq!(after.as_deref(), Some(broken));
        // --no-merge replaces it, in its line endings.
        let (written, _, after) = extensions(Some("{\"x\": 1}\r\n"), false);
        assert_eq!(written.as_deref(), Some(EXTENSIONS));
        assert_eq!(
            after.as_deref(),
            Some("{\r\n  \"recommendations\": [\r\n    \"opentidehq.opentide\"\r\n  ]\r\n}\r\n")
        );
    }

    #[test]
    fn recommendations_that_are_no_list_are_rewritten_only_without_comments() {
        let (written, warnings, after) =
            extensions(Some("{\"recommendations\": \"x\", \"é\": 1}"), true);
        assert_eq!(written.as_deref(), Some(EXTENSIONS));
        assert!(warnings.is_empty());
        assert_eq!(
            after.as_deref(),
            Some(
                "{\n  \"recommendations\": [\n    \"opentidehq.opentide\"\n  ],\n  \"\u{e9}\": 1\n}\n"
            )
        );
        let commented = "{\"recommendations\": \"x\" // mine\n}";
        let (written, warnings, after) = extensions(Some(commented), true);
        assert_eq!(written, None);
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].starts_with(".vscode/extensions.json has comments"),
            "{warnings:?}"
        );
        assert_eq!(after.as_deref(), Some(commented));
    }

    fn settings(before: &str) -> (Option<String>, String) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        std::fs::write(root.join(SETTINGS), before).unwrap();
        let config = opentide_schema::node::load("paths: {}\n")
            .unwrap()
            .root()
            .unwrap()
            .clone();
        let mut stage = Stage::new();
        let mut warnings = Vec::new();
        let written = write_settings(&mut stage, root, &config, &mut warnings);
        stage.commit().unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        (
            written,
            std::fs::read_to_string(root.join(SETTINGS)).unwrap(),
        )
    }

    #[test]
    fn opentides_yaml_schemas_go_and_the_rest_stays_byte_for_byte() {
        let before = "{\r\n  // editor\r\n  \"editor.tabSize\": 2,\r\n  \"yaml.schemas\": {\r\n    \".opentide/schemas/opentide.schema.json\": \"objects/**/*.yaml\",\r\n    \"mine.json\": [\"x/*.yaml\"] // keep\r\n  }\r\n}\r\n";
        let (written, after) = settings(before);
        assert_eq!(written.as_deref(), Some(SETTINGS));
        assert!(
            after.contains("// editor") && after.contains("// keep"),
            "{after:?}"
        );
        assert!(!after.contains("opentide.schema.json"), "{after:?}");
        assert!(!after.replace("\r\n", "").contains('\n'), "{after:?}");
        assert_eq!(
            jsonc::parse(&after).unwrap()["yaml.schemas"],
            serde_json::json!({"mine.json": ["x/*.yaml"]})
        );
        // Emptied, yaml.schemas goes; nothing of opentide's, nothing is written.
        let (written, after) = settings(
            "{\"a\": 1, \"yaml.schemas\": {\".opentide/schemas/opentide.schema.json\": [\"objects/**/*.yaml\", \"mine/*.yaml\"]}}",
        );
        assert_eq!(written.as_deref(), Some(SETTINGS));
        assert_eq!(
            jsonc::parse(&after).unwrap(),
            serde_json::json!({"a": 1, "yaml.schemas": {".opentide/schemas/opentide.schema.json": ["mine/*.yaml"]}})
        );
        let (written, after) = settings(
            "{\"a\": 1, \"yaml.schemas\": {\".opentide/schemas/opentide.schema.json\": \"objects/**/*.yaml\"}}",
        );
        assert_eq!(written.as_deref(), Some(SETTINGS));
        assert_eq!(jsonc::parse(&after).unwrap(), serde_json::json!({"a": 1}));
        let untouched = "{\"yaml.schemas\": {\"mine.json\": \"x\"}}";
        assert_eq!(settings(untouched), (None, untouched.to_owned()));
    }
}
