//! What `opentide generate` writes into a workspace from its resolved
//! configuration: the object and platform templates
//! (`template_renderer.py`), the VS Code snippets (`vscode_snippets.py`) and
//! the router schema (`router_schema.py`). Paths are relative to the
//! workspace, `/`-separated; the host writes the files.

use crate::configuration::lint::parse_lint_config;
use crate::node::{Node, Value};
use crate::objects::objective::ObjectiveV1_0;
use crate::objects::platform::{
    CarbonBlackConfig, CrowdstrikeConfig, DefenderConfig, ElasticConfig, HarfangLabConfig,
    PLATFORM_CONFIG_MODELS, SentinelConfig, SentinelOneConfig, SplunkConfig, SysdigConfig,
};
use crate::objects::rule::{RuleV1_0, RuleV1_1};
use crate::objects::threat::ThreatVectorV1_0;
use crate::revisions::{Kind, REVISIONS, SchemaId};

use super::json::{Json, Object};
use super::router::{router, schema_artifact_name, template_artifact_name};
use super::snippets::{core_snippet, platform_snippet};
use super::template::{Options, TemplateError, render};

/// The Tide object families (`CORE_OBJECT_TYPES`).
pub const CORE_OBJECT_TYPES: [&str; 3] = ["threat", "objective", "rule"];

/// Folder under the templates directory that holds the platform templates.
pub const PLATFORM_TEMPLATES_DIR: &str = "platforms";

/// A file to write: its path relative to the workspace, and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// `/`-separated, relative to the workspace.
    pub path: String,
    /// The file's text.
    pub text: String,
}

/// Why the artifacts could not be generated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenerateError {
    /// A template could not be rendered (a bug in a model or the renderer).
    #[error(transparent)]
    Template(#[from] TemplateError),
    /// `lint.toml` cannot be used.
    #[error("{0}")]
    Lint(String),
}

/// The template of a registered object revision, or `None` for an
/// identifier that names none.
pub fn object_template(
    identifier: &str,
    options: &Options,
) -> Result<Option<String>, TemplateError> {
    Ok(Some(match identifier {
        "rule::1.0" => render::<RuleV1_0>(options)?,
        "rule::1.1" => render::<RuleV1_1>(options)?,
        "threat::1.0" => render::<ThreatVectorV1_0>(options)?,
        "objective::1.0" => render::<ObjectiveV1_0>(options)?,
        _ => return Ok(None),
    }))
}

/// A platform block's template, at indent 2, or `None` for a key that is
/// not a platform.
pub fn platform_template(platform: &str) -> Result<Option<String>, TemplateError> {
    let options = Options {
        indent: 2,
        ..Options::default()
    };
    Ok(Some(match platform {
        "sentinel" => render::<SentinelConfig>(&options)?,
        "defender_for_endpoint" => render::<DefenderConfig>(&options)?,
        "splunk" => render::<SplunkConfig>(&options)?,
        "sentinel_one" => render::<SentinelOneConfig>(&options)?,
        "crowdstrike" => render::<CrowdstrikeConfig>(&options)?,
        "harfanglab" => render::<HarfangLabConfig>(&options)?,
        "carbon_black_cloud" => render::<CarbonBlackConfig>(&options)?,
        "elastic" => render::<ElasticConfig>(&options)?,
        "sysdig" => render::<SysdigConfig>(&options)?,
        _ => return Ok(None),
    }))
}

/// The file a platform's template is written to: `<platform>.template.yaml`.
pub fn platform_template_name(platform: &str) -> String {
    format!("{platform}.template.yaml")
}

/// The object revisions of `families`, sorted by their identifier
/// (`identifiers_for_families`).
pub fn identifiers_for_families(families: &[&str]) -> Vec<SchemaId> {
    let mut identifiers: Vec<&'static str> = REVISIONS
        .iter()
        .filter(|revision| revision.in_object_registry())
        .filter(|revision| families.contains(&revision.id().family()))
        .map(|revision| revision.identifier)
        .collect();
    identifiers.sort_unstable();
    identifiers
        .into_iter()
        .filter_map(|identifier| SchemaId::parse(identifier).ok())
        .collect()
}

fn table<'n>(node: Option<&'n Node>, key: &str) -> Option<&'n Node> {
    node.and_then(|node| node.get(key)).map(AsRef::as_ref)
}

fn string<'n>(node: Option<&'n Node>, key: &str) -> Option<&'n str> {
    table(node, key).and_then(|node| node.value.as_str())
}

/// A table's string values in order (`[metaschemas]`, `[artifacts.templates]`).
fn entries(node: Option<&Node>) -> Vec<(String, Option<String>)> {
    match node.map(|node| &node.value) {
        Some(Value::Map(entries)) => entries
            .iter()
            .filter_map(|entry| {
                let key = entry.key.value.as_str()?.to_owned();
                Some((key, entry.value.value.as_str().map(str::to_owned)))
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// `dir` joined with `name`, `/`-separated.
fn join(dir: &str, name: &str) -> String {
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() || dir == "." {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// `a/./b/` as `a/b`: how two configured paths are compared.
fn normal(path: &str) -> String {
    path.split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// The resolved configuration's settings `generate` reads.
struct Settings {
    templates_dir: String,
    snippet_file: String,
    schemas_dir: String,
    metaschemas: Vec<String>,
    templates: Vec<(String, Option<String>)>,
    schema_map: Vec<(String, Option<String>)>,
    object_names: Vec<(String, Option<String>)>,
}

impl Settings {
    fn of(config: &Node) -> Self {
        let paths = table(Some(config), "paths");
        let section = table(paths, "paths");
        let opentide = table(section, "opentide");
        let objects = table(section, "objects");
        let artifacts = table(paths, "artifacts");
        Self {
            templates_dir: string(opentide, "templates")
                .filter(|value| !value.is_empty())
                .unwrap_or(".opentide/templates/")
                .to_owned(),
            schemas_dir: string(opentide, "schemas")
                .filter(|value| !value.is_empty())
                .unwrap_or(".opentide/schemas/")
                .to_owned(),
            snippet_file: string(objects, "snippet_file")
                .filter(|value| !value.is_empty())
                .unwrap_or(".vscode/model-templates.code-snippets")
                .to_owned(),
            metaschemas: entries(table(paths, "metaschemas"))
                .into_iter()
                .map(|(key, _)| key)
                .collect(),
            templates: entries(table(artifacts, "templates")),
            schema_map: entries(table(artifacts, "schemas")),
            object_names: entries(table(table(Some(config), "documentation"), "object_names")),
        }
    }

    fn template_for(&self, family: &str) -> Option<&str> {
        self.templates
            .iter()
            .find(|(key, _)| key == family)
            .and_then(|(_, value)| value.as_deref())
    }
}

/// The templates folder (`[paths.opentide] templates`, `.opentide/templates/`
/// by default), relative to the workspace.
pub fn templates_dir(config: &Node) -> String {
    Settings::of(config).templates_dir
}

/// The schemas folder (`[paths.opentide] schemas`, `.opentide/schemas/` by
/// default), relative to the workspace.
pub fn schemas_dir(config: &Node) -> String {
    Settings::of(config).schemas_dir
}

/// `dir` joined with `name`, `/`-separated (`a/` and `b` are `a/b`; `.` and
/// an empty `dir` are dropped).
pub fn join_path(dir: &str, name: &str) -> String {
    join(dir, name)
}

/// Platforms with a rule block whose merged `[platform] enabled` is `true`,
/// in the configuration's order, each with its display name
/// (`enabled_platforms`, `_entry_name`).
pub fn enabled_platforms(config: &Node) -> Vec<(String, String)> {
    let Some(Value::Map(platforms)) = table(Some(config), "platforms").map(|node| &node.value)
    else {
        return Vec::new();
    };
    let mut enabled = Vec::new();
    for entry in platforms {
        let Some(identifier) = entry.key.value.as_str() else {
            continue;
        };
        if !PLATFORM_CONFIG_MODELS
            .iter()
            .any(|registered| registered.key == identifier)
        {
            continue;
        }
        let section = table(Some(&entry.value), "platform");
        if matches!(
            table(section, "enabled").map(|node| &node.value),
            Some(Value::Bool(true))
        ) {
            let name = string(section, "name")
                .filter(|name| !name.is_empty())
                .unwrap_or(identifier);
            enabled.push((identifier.to_owned(), name.to_owned()));
        }
    }
    enabled
}

/// The `generate templates` phase: every registered revision of each
/// configured family, the family's configured template when it is another
/// file, and every enabled platform's block.
pub fn templates(config: &Node) -> Result<Vec<Artifact>, GenerateError> {
    let settings = Settings::of(config);
    let lint = parse_lint_config(config.get("lint").map(AsRef::as_ref))
        .map_err(|error| GenerateError::Lint(error.0))?;
    let options = Options {
        required_metadata: lint.required_metadata,
        indent: 0,
    };
    let mut artifacts: Vec<Artifact> = Vec::new();
    for family in &settings.metaschemas {
        if !CORE_OBJECT_TYPES.contains(&family.as_str()) {
            continue;
        }
        let Some(configured) = settings.template_for(family) else {
            continue;
        };
        let mut written = Vec::new();
        let ids = identifiers_for_families(&[family.as_str()]);
        for id in &ids {
            let path = join(&settings.templates_dir, &template_artifact_name(id));
            if let Some(text) = object_template(&id.to_string(), &options)? {
                written.push(normal(&path));
                push(&mut artifacts, path, text);
            }
        }
        let configured_path = join(&settings.templates_dir, configured);
        if written.contains(&normal(&configured_path)) {
            continue;
        }
        let pinned = schema_id_from_template_filename(configured)
            .filter(|id| crate::revisions::lookup(id).is_some_and(|r| r.kind == Kind::Object));
        let identifier = match pinned {
            Some(id) => id,
            None => match ids.last() {
                Some(newest) => newest.to_string(),
                None => continue,
            },
        };
        if let Some(text) = object_template(&identifier, &options)? {
            push(&mut artifacts, configured_path, text);
        }
    }
    for (platform, _) in enabled_platforms(config) {
        if let Some(text) = platform_template(&platform)? {
            let dir = join(&settings.templates_dir, PLATFORM_TEMPLATES_DIR);
            push(
                &mut artifacts,
                join(&dir, &platform_template_name(&platform)),
                text,
            );
        }
    }
    Ok(artifacts)
}

/// A later write of the same file replaces the earlier one.
fn push(artifacts: &mut Vec<Artifact>, path: String, text: String) {
    let key = normal(&path);
    artifacts.retain(|artifact| normal(&artifact.path) != key);
    artifacts.push(Artifact { path, text });
}

/// `rule.1.0.template.yaml` as `rule::1.0`; `None` for another name
/// (`_schema_id_from_template_filename`).
pub fn schema_id_from_template_filename(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".template.yaml")?;
    let parts: Vec<&str> = stem.split('.').collect();
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    if parts.len() < 3 || !digits(parts[1]) || !digits(parts[2]) {
        return None;
    }
    let major: u64 = parts[1].parse().ok()?;
    let minor: u64 = parts[2].parse().ok()?;
    Some(format!("{}::{major}.{minor}", parts[0]))
}

/// The `generate snippets` phase, from the templates as `templates` wrote
/// them (`templates`: path and text of each template file there is).
/// `Ok(None)` names the template a snippet needs that is missing.
pub fn snippets(config: &Node, templates: &[Artifact]) -> Result<Artifact, String> {
    let settings = Settings::of(config);
    let find = |path: &str| {
        let key = normal(path);
        templates
            .iter()
            .find(|artifact| normal(&artifact.path) == key)
            .map(|artifact| artifact.text.as_str())
    };
    let mut document = Object::new();
    for family in &settings.metaschemas {
        let Some(file) = settings.template_for(family) else {
            continue;
        };
        let full_name = settings
            .object_names
            .iter()
            .find(|(key, _)| key == family)
            .and_then(|(_, value)| value.clone())
            .unwrap_or_else(|| family.clone());
        let path = join(&settings.templates_dir, file);
        let text = find(&path)
            .ok_or_else(|| format!("Missing core {family} template for snippets: {path}"))?;
        let (title, entry) = core_snippet(family, &full_name, text);
        document.insert(title, entry);
    }
    for (platform, name) in enabled_platforms(config) {
        let dir = join(&settings.templates_dir, PLATFORM_TEMPLATES_DIR);
        let path = join(&dir, &platform_template_name(&platform));
        let text = find(&path)
            .ok_or_else(|| format!("Missing platform {platform} template for snippets: {path}"))?;
        let (title, entry) = platform_snippet(&platform, &name, text);
        document.insert(title, entry);
    }
    Ok(Artifact {
        path: settings.snippet_file,
        text: Json::Object(document).to_text(),
    })
}

/// The router schema, at its configured name in the schemas folder.
pub fn router_artifact(config: &Node) -> Artifact {
    let settings = Settings::of(config);
    let name = settings
        .schema_map
        .iter()
        .find(|(key, _)| key == "router")
        .and_then(|(_, value)| value.clone())
        .unwrap_or_else(|| "opentide.schema.json".to_owned());
    let ids = identifiers_for_families(&CORE_OBJECT_TYPES);
    Artifact {
        path: join(&settings.schemas_dir, &name),
        text: router(&ids).to_text(),
    }
}

/// The schema file of each registered object revision, by its identifier
/// (`schema_artifact_name`): where `generate schemas` writes them.
pub fn schema_paths(config: &Node) -> Vec<(SchemaId, String)> {
    let settings = Settings::of(config);
    identifiers_for_families(&CORE_OBJECT_TYPES)
        .into_iter()
        .map(|id| {
            let name = settings
                .schema_map
                .iter()
                .find(|(key, _)| *key == id.to_string())
                .and_then(|(_, value)| value.clone())
                .unwrap_or_else(|| schema_artifact_name(&id));
            let path = join(&settings.schemas_dir, &name);
            (id, path)
        })
        .collect()
}

/// Where `generate schemas` writes `visibility.toml`'s schema: the
/// `[artifacts.schemas] visibility` name, `visibility.1.0.schema.json` by
/// default, in the schemas folder.
pub fn visibility_schema_path(config: &Node) -> String {
    let settings = Settings::of(config);
    let name = settings
        .schema_map
        .iter()
        .find(|(key, _)| key == "visibility")
        .and_then(|(_, value)| value.clone())
        .unwrap_or_else(|| "visibility.1.0.schema.json".to_owned());
    join(&settings.schemas_dir, &name)
}

/// The JSON Schemas of the `generate schemas` phase but the router
/// ([`router_artifact`]): each registered object revision's editor schema
/// ([`super::schema::revision_schema`]) and `visibility.toml`'s, from the
/// workspace's resolved configuration and vocabularies (UC-1.8b, #900).
pub fn schema_artifacts(sources: &super::schema::Sources) -> Vec<Artifact> {
    let mut artifacts = Vec::new();
    for (id, path) in schema_paths(&sources.config) {
        if let Some(schema) = super::schema::revision_schema(&id.to_string(), sources) {
            push(&mut artifacts, path, super::schema::editor_text(&schema));
        }
    }
    push(
        &mut artifacts,
        visibility_schema_path(&sources.config),
        super::schema::editor_text(&super::schema::visibility_schema()),
    );
    artifacts
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::configuration::lint::LintConfig;
    use crate::configuration::toml::parse;

    fn config(text: &str) -> Node {
        parse(text).unwrap()
    }

    fn rendered(identifier: &str) -> String {
        let options = Options {
            required_metadata: LintConfig::default().required_metadata,
            indent: 0,
        };
        object_template(identifier, &options).unwrap().unwrap()
    }

    fn paths(artifacts: &[Artifact]) -> Vec<&str> {
        artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect()
    }

    const PLATFORMS: &str = r#"
[platforms.sentinel.platform]
enabled = true
name = "Microsoft Sentinel"
[platforms.splunk.platform]
enabled = false
name = "Splunk"
[platforms.elastic.platform]
name = "Elastic"
[platforms.crowdstrike.platform]
enabled = "true"
[platforms.plugin.platform]
enabled = true
[platforms.carbon_black_cloud.platform]
enabled = true
"#;

    #[test]
    fn only_platforms_enabled_with_true_are_generated() {
        let tree = config(PLATFORMS);
        assert_eq!(
            enabled_platforms(&tree),
            [
                ("sentinel".to_owned(), "Microsoft Sentinel".to_owned()),
                (
                    "carbon_black_cloud".to_owned(),
                    "carbon_black_cloud".to_owned()
                ),
            ]
        );
        let artifacts = templates(&tree).unwrap();
        assert_eq!(
            paths(&artifacts),
            [
                ".opentide/templates/platforms/sentinel.template.yaml",
                ".opentide/templates/platforms/carbon_black_cloud.template.yaml",
            ]
        );
        assert_eq!(
            artifacts[0].text,
            platform_template("sentinel").unwrap().unwrap()
        );
        let snippet = snippets(&tree, &artifacts).unwrap();
        assert_eq!(snippet.path, ".vscode/model-templates.code-snippets");
        assert!(
            snippet
                .text
                .contains("Platform configuration : Microsoft Sentinel Template"),
            "{}",
            snippet.text
        );
        assert!(
            snippet
                .text
                .contains("Platform configuration : carbon_black_cloud Template")
        );
        for absent in ["Splunk", "Elastic", "crowdstrike", "plugin"] {
            assert!(!snippet.text.contains(absent), "{absent}: {}", snippet.text);
        }
    }

    #[test]
    fn a_snippet_without_its_template_is_an_error() {
        let tree = config(PLATFORMS);
        assert_eq!(
            snippets(&tree, &[]).unwrap_err(),
            "Missing platform sentinel template for snippets: \
             .opentide/templates/platforms/sentinel.template.yaml"
        );
        let tree = config(
            "[paths.metaschemas]\nrule = \"rule\"\n\
             [paths.artifacts.templates]\nrule = \"rule.template.yaml\"\n",
        );
        assert_eq!(
            snippets(&tree, &[]).unwrap_err(),
            "Missing core rule template for snippets: .opentide/templates/rule.template.yaml"
        );
    }

    fn rule_configured(file: &str) -> Node {
        config(&format!(
            "[paths.metaschemas]\nrule = \"rule\"\n\
             [paths.artifacts.templates]\nrule = \"{file}\"\n"
        ))
    }

    #[test]
    fn a_configured_revision_template_is_not_written_twice() {
        let artifacts = templates(&rule_configured("rule.1.0.template.yaml")).unwrap();
        assert_eq!(
            paths(&artifacts),
            [
                ".opentide/templates/rule.1.0.template.yaml",
                ".opentide/templates/rule.1.1.template.yaml",
            ]
        );
        assert_eq!(artifacts[0].text, rendered("rule::1.0"));
        assert_eq!(artifacts[1].text, rendered("rule::1.1"));
    }

    #[test]
    fn a_configured_template_of_no_revision_is_the_newest_revision() {
        let tree = rule_configured("rule.template.yaml");
        let artifacts = templates(&tree).unwrap();
        assert_eq!(
            paths(&artifacts),
            [
                ".opentide/templates/rule.1.0.template.yaml",
                ".opentide/templates/rule.1.1.template.yaml",
                ".opentide/templates/rule.template.yaml",
            ]
        );
        assert_eq!(artifacts[2].text, rendered("rule::1.1"));
        let snippet = snippets(&tree, &artifacts).unwrap();
        assert!(
            snippet.text.contains("\"rule Template\""),
            "{}",
            snippet.text
        );
    }

    #[test]
    fn a_configured_template_named_for_a_revision_renders_that_revision() {
        // threat's template configured as a rule revision's file name.
        let tree = config(
            "[paths.metaschemas]\nthreat = \"threat\"\n\
             [paths.artifacts.templates]\nthreat = \"rule.1.0.template.yaml\"\n",
        );
        let artifacts = templates(&tree).unwrap();
        assert_eq!(
            paths(&artifacts),
            [
                ".opentide/templates/threat.1.0.template.yaml",
                ".opentide/templates/rule.1.0.template.yaml",
            ]
        );
        assert_eq!(artifacts[1].text, rendered("rule::1.0"));
    }

    #[test]
    fn a_family_without_a_configured_template_writes_none() {
        let tree = config("[paths.metaschemas]\nrule = \"rule\"\nvisibility = \"v\"\n");
        assert!(templates(&tree).unwrap().is_empty());
    }

    #[test]
    fn template_filenames_name_their_revision() {
        assert_eq!(
            schema_id_from_template_filename("rule.1.0.template.yaml").as_deref(),
            Some("rule::1.0")
        );
        assert_eq!(
            schema_id_from_template_filename("rule.01.10.template.yaml").as_deref(),
            Some("rule::1.10")
        );
        assert_eq!(schema_id_from_template_filename("rule.template.yaml"), None);
        assert_eq!(
            schema_id_from_template_filename("rule.x.0.template.yaml"),
            None
        );
        assert_eq!(schema_id_from_template_filename("rule.1.0.yaml"), None);
    }

    #[test]
    fn identifiers_are_the_object_revisions_sorted() {
        let ids: Vec<String> = identifiers_for_families(&CORE_OBJECT_TYPES)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            ids,
            ["objective::1.0", "rule::1.0", "rule::1.1", "threat::1.0"]
        );
    }

    #[test]
    fn paths_join_and_compare_without_dot_segments() {
        assert_eq!(
            join(".opentide/templates/", "a.yaml"),
            ".opentide/templates/a.yaml"
        );
        assert_eq!(join("", "a.yaml"), "a.yaml");
        assert_eq!(
            normal("./.opentide//templates/a.yaml"),
            ".opentide/templates/a.yaml"
        );
    }
}
