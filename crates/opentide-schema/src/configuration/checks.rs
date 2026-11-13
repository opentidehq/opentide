//! The findings of configuration files (`validation/configuration.py`).
//!
//! Client files are partial overrides, so a file is merged onto the layers
//! before it (the bundled file by default) and the model's required keys
//! apply to that merge, never to the file alone. The checks a model cannot
//! state (a status name, an asset name, the file name) run beside it and
//! return the same records.

use std::sync::Arc;

use super::errors::{code_of, describe_error, model_errors};
use super::merge::merge_layers;
use super::models::{
    CarbonBlackCloudConfiguration, CrowdstrikeConfiguration, DefenderForEndpointConfiguration,
    DeploymentConfiguration, DocumentationConfiguration, ElasticConfiguration,
    ExabeamConfiguration, GoogleSecopsConfiguration, HarfangLabConfiguration, PLATFORMS,
    PathsConfiguration, PlatformConfiguration, SentinelConfiguration, SentinelOneConfiguration,
    SplunkConfiguration, SysdigConfiguration, VisibilityConfig,
};
use super::sharing::{SharingIssue, merge_sharing_documents};
use super::{Finding, Severity, bundled, codes, models::TLP_ORDER, repr, toml};
use crate::from_node::{Context, FromNode};
use crate::node::{Node, Value};

/// Router key of a platform file opentide has no dedicated model for.
pub const GENERIC_PLATFORM_FILE: &str = "platforms/*.toml";

/// The configuration files with a model of their own, by file name.
pub const FILE_MODELS: [&str; 5] = [
    "paths.toml",
    "deployment.toml",
    "visibility.toml",
    "documentation.toml",
    "sharing.toml",
];

/// Entries of a configuration folder opentide does not read, and what
/// replaces each.
pub const RETIRED_CONFIGURATIONS: [(&str, &str); 3] = [
    (
        "global.toml",
        "workspace paths and artifact names are set in paths.toml",
    ),
    (
        "schema.toml",
        "template defaults are not configurable, and vocabularies are not extended locally",
    ),
    (
        "systems",
        "platform files live in platforms/<platform>.toml",
    ),
];

/// Bundled files opentide reads that have no model here.
const UNMODELLED_FILES: [&str; 2] = ["resources.toml", "lint.toml"];

const RESPONDERS: &str = "responders";

/// Whether a file name ends in `.toml`, case-sensitively as the oracle
/// reads it (`Deployment.TOML` is not a configuration file).
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "the oracle compares the suffix case-sensitively"
)]
pub(crate) fn is_toml(name: &str) -> bool {
    name.ends_with(".toml")
}

/// The parts of a path, `/` or `\` separated, as `PurePosixPath.parts`: a
/// leading `/` is a part, empty and `.` segments are dropped.
fn parts(path: &str) -> Vec<String> {
    let path = path.replace('\\', "/");
    let mut out = Vec::new();
    if path.starts_with('/') {
        out.push("/".to_owned());
    }
    out.extend(
        path.split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .map(str::to_owned),
    );
    out
}

fn stem(name: &str) -> &str {
    match name.rfind('.') {
        Some(0) | None => name,
        Some(dot) => &name[..dot],
    }
}

/// The router key of a configuration file path, or `None` when it is not
/// one (`configuration_file_key`). `path` may be absolute or relative to
/// `.opentide/configurations/`; only the file name, and the `platforms`
/// folder for a platform file, are read.
pub fn file_key(path: &str) -> Option<String> {
    let parts = parts(path);
    let name = parts.last()?;
    if !is_toml(name) {
        return None;
    }
    let count = parts.len();
    if parts[..count - 1]
        .iter()
        .enumerate()
        .any(|(position, part)| part == ".opentide" && parts[position + 1] == "schemas")
    {
        return None;
    }
    if count >= 2 && parts[count - 2] == "sharing" {
        return None;
    }
    if count >= 2 && parts[count - 2] == "platforms" {
        let identifier = name.strip_suffix(".toml").unwrap_or(name);
        if PLATFORMS.contains(&identifier) {
            return Some(format!("platforms/{identifier}.toml"));
        }
        return Some(GENERIC_PLATFORM_FILE.to_owned());
    }
    FILE_MODELS.contains(&name.as_str()).then(|| name.clone())
}

/// The retired entry `parts` is, or sits in, with what replaces it.
fn retired_entry(parts: &[String]) -> Option<(String, &'static str)> {
    let count = parts.len();
    let last = parts.last()?;
    if let Some((_, replacement)) = RETIRED_CONFIGURATIONS.iter().find(|(name, _)| name == last) {
        return Some((last.clone(), replacement));
    }
    if count >= 2
        && let Some((folder, replacement)) = RETIRED_CONFIGURATIONS
            .iter()
            .find(|(name, _)| *name == parts[count - 2])
        && is_toml(last)
        && (count == 2 || parts[count - 3] == "configurations")
    {
        return Some((format!("{folder}/"), replacement));
    }
    None
}

/// What a check reads besides the file itself (`configuration_file_issues`'
/// keyword arguments).
#[derive(Debug, Clone, Default)]
pub struct Layers<'a> {
    /// The layers before the file; `None` for the bundled file of the same
    /// name.
    pub earlier: Option<Vec<&'a Node>>,
    /// The layers after it (the parent instance's file).
    pub later: Vec<&'a Node>,
    /// The merged `deployment.toml` statuses `sharing.toml` `rule_statuses`
    /// must name; `None` for the bundled ones.
    pub status_names: Option<Vec<String>>,
    /// `configurations/sharing/` exists beside the file.
    pub sharing_directory: bool,
    /// Skip the required-key checks: a layer checked without the layers it
    /// overrides.
    pub partial: bool,
}

fn finding(
    code: &str,
    severity: Severity,
    path: Vec<String>,
    message: String,
    file: &str,
) -> Finding {
    Finding::new(code, severity, path, message, Some(file))
}

/// The status names of a `deployment.toml` document (`_status_names`).
pub fn status_names(deployment: &Node) -> Vec<String> {
    let Some(Value::Seq(statuses)) = deployment.get("statuses").map(|node| &node.value) else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    for entry in statuses {
        if let Some(Value::Str(name)) = entry.get("name").map(|node| &node.value)
            && !names.contains(name)
        {
            names.push(name.clone());
        }
    }
    names
}

/// The statuses of the bundled `deployment.toml`.
pub fn bundled_status_names() -> Vec<String> {
    status_names(&bundled::layer("deployment.toml"))
}

/// The findings of a configuration text (`configuration_text_issues`).
pub fn text_issues(path: &str, text: &str, layers: &Layers<'_>) -> Vec<Finding> {
    match toml::parse(text) {
        Ok(document) => file_issues(path, &document, layers),
        Err(error) => vec![finding(
            codes::CONFIG_PARSE,
            Severity::Error,
            Vec::new(),
            if error.too_deep {
                error.message
            } else {
                format!("Not valid TOML: {}.", error.message.trim_end_matches('.'))
            },
            path,
        )],
    }
}

/// The findings of a parsed configuration file (`configuration_file_issues`).
pub fn file_issues(path: &str, document: &Node, layers: &Layers<'_>) -> Vec<Finding> {
    let parts = parts(path);
    let count = parts.len();
    if count >= 3 && parts[count - 2] == "sharing" && parts[count - 3] == "configurations" {
        return vec![sharing_directory(path)];
    }
    if let Some((name, replacement)) = retired_entry(&parts) {
        return vec![finding(
            codes::RETIRED_CONFIGURATION_FILE,
            Severity::Error,
            Vec::new(),
            format!("{name} is not read by opentide: {replacement}."),
            path,
        )];
    }
    let name = parts.last().map_or("", String::as_str);
    let mut key = file_key(path);
    if key
        .as_deref()
        .is_some_and(|key| key.starts_with("platforms/"))
    {
        key = file_key(&format!("platforms/{}.toml", stem(name)));
    }
    let Some(key) = key else {
        let message = if UNMODELLED_FILES.contains(&name) {
            format!("{name} has no configuration model; it is not checked.")
        } else {
            format!("{name} is not a configuration file opentide reads.")
        };
        return vec![finding(
            codes::NOT_A_CONFIGURATION_FILE,
            Severity::Warning,
            Vec::new(),
            message,
            path,
        )];
    };
    let bundled_layer;
    let earlier: Vec<&Node> = match &layers.earlier {
        Some(earlier) => earlier.clone(),
        None => {
            bundled_layer = bundled::layer(&key);
            vec![&bundled_layer]
        }
    };
    let mut all: Vec<&Node> = earlier.clone();
    all.push(document);
    all.extend(layers.later.iter().copied());

    if key == "sharing.toml" {
        let names = layers
            .status_names
            .clone()
            .unwrap_or_else(bundled_status_names);
        return sharing_issues(
            &all,
            &names,
            &TLP_ORDER.map(str::to_owned),
            layers.sharing_directory,
            layers.partial,
            Some(earlier.len()),
            Some(path),
        );
    }
    let merged = merge_layers(all);
    let mut issues = Vec::new();
    for issue in validate(&key, &merged) {
        if layers.partial && issue.code == codes::MISSING_FIELD {
            continue;
        }
        issues.push(Finding {
            file_path: Some(path.to_owned()),
            ..issue
        });
    }
    issues
}

/// The model of router key `key` over `merged`: its findings (no file), the
/// responders' made warnings, then the cross checks when the model holds.
fn validate(key: &str, merged: &Node) -> Vec<Finding> {
    let (errors, cross) = match key {
        "deployment.toml" => {
            let (errors, model) = convert::<DeploymentConfiguration>(merged);
            let model = model
                .or_else(|| convert::<DeploymentConfiguration>(&without(merged, RESPONDERS)).1);
            (errors, model.map(|model| deployment_cross_issues(&model)))
        }
        "visibility.toml" => {
            let (errors, model) = convert::<VisibilityConfig>(merged);
            (errors, model.map(|model| visibility_cross_issues(&model)))
        }
        "paths.toml" => (convert::<PathsConfiguration>(merged).0, None),
        "documentation.toml" => (convert::<DocumentationConfiguration>(merged).0, None),
        "platforms/sentinel.toml" => (convert::<SentinelConfiguration>(merged).0, None),
        "platforms/splunk.toml" => (convert::<SplunkConfiguration>(merged).0, None),
        "platforms/carbon_black_cloud.toml" => {
            (convert::<CarbonBlackCloudConfiguration>(merged).0, None)
        }
        "platforms/sentinel_one.toml" => (convert::<SentinelOneConfiguration>(merged).0, None),
        "platforms/defender_for_endpoint.toml" => {
            (convert::<DefenderForEndpointConfiguration>(merged).0, None)
        }
        "platforms/crowdstrike.toml" => (convert::<CrowdstrikeConfiguration>(merged).0, None),
        "platforms/harfanglab.toml" => (convert::<HarfangLabConfiguration>(merged).0, None),
        "platforms/elastic.toml" => (convert::<ElasticConfiguration>(merged).0, None),
        "platforms/sysdig.toml" => (convert::<SysdigConfiguration>(merged).0, None),
        "platforms/exabeam.toml" => (convert::<ExabeamConfiguration>(merged).0, None),
        "platforms/google_secops.toml" => (convert::<GoogleSecopsConfiguration>(merged).0, None),
        _ => (convert::<PlatformConfiguration>(merged).0, None),
    };
    let mut issues: Vec<Finding> = errors
        .into_iter()
        .map(|error| {
            let tolerated = key == "deployment.toml"
                && error.path.len() >= 2
                && error.path[0] == RESPONDERS
                && !error.path[1].is_empty()
                && error.path[1].chars().all(|ch| ch.is_ascii_digit());
            Finding::new(
                code_of(error.kind),
                if tolerated {
                    Severity::Warning
                } else {
                    Severity::Error
                },
                error.path,
                describe_error(error.kind, &error.message),
                None,
            )
        })
        .collect();
    issues.extend(cross.into_iter().flatten());
    issues
}

/// The model over `merged`, and its errors placed in it.
fn convert<T: FromNode>(merged: &Node) -> (Vec<super::errors::ModelError>, Option<T>) {
    let mut cx = Context::new();
    let model = T::from_node(merged, &mut cx);
    let errors = cx.into_errors();
    if errors.is_empty() {
        (Vec::new(), model)
    } else {
        (model_errors(&errors, merged), None)
    }
}

/// `merged` without its top-level `key`.
fn without(merged: &Node, key: &str) -> Node {
    let Value::Map(entries) = &merged.value else {
        return merged.clone();
    };
    Node {
        value: Value::Map(
            entries
                .iter()
                .filter(|entry| entry.key.value.as_str() != Some(key))
                .cloned()
                .collect(),
        ),
        start: merged.start,
        end: merged.end,
    }
}

/// `promotion.promotion_target` names a status of the merged file.
pub fn deployment_cross_issues(config: &DeploymentConfiguration) -> Vec<Finding> {
    let target = &config.promotion.promotion_target.0;
    if config.status_names().contains(&target.as_str()) {
        return Vec::new();
    }
    vec![
        Finding::new(
            codes::PROMOTION_TARGET_UNKNOWN,
            Severity::Error,
            vec!["promotion".to_owned(), "promotion_target".to_owned()],
            format!(
                "promotion_target {} is not a [[statuses]] name.",
                repr::quote(target)
            ),
            None,
        )
        .with("value", target.clone()),
    ]
}

/// Log source and detector `assets` name an `[[assets]]` entry: a warning,
/// as the loader logs an unknown asset and goes on.
pub fn visibility_cross_issues(config: &VisibilityConfig) -> Vec<Finding> {
    config
        .unknown_assets()
        .into_iter()
        .map(|(table, index, name, position, asset)| {
            let entry = if table == "logsources" {
                "logsource"
            } else {
                "detector"
            };
            Finding::new(
                codes::ASSET_UNKNOWN,
                Severity::Warning,
                vec![
                    table.to_owned(),
                    index.to_string(),
                    "assets".to_owned(),
                    position.to_string(),
                ],
                format!(
                    "{entry} {} names asset {}, which [[assets]] does not declare.",
                    repr::quote(&name),
                    repr::quote(&asset)
                ),
                None,
            )
            .with("entry", entry)
            .with("name", name)
            .with("asset", asset)
        })
        .collect()
}

fn sharing_directory(path: &str) -> Finding {
    finding(
        codes::SHARING_DIRECTORY,
        Severity::Error,
        Vec::new(),
        "configurations/sharing/ is not a sharing configuration. Use a single sharing.toml \
         file."
            .to_owned(),
        path,
    )
}

/// Every `sharing-config` finding for `layers`, merged by block name in
/// order (`sharing_issues`). With `checked_layer` (the open file's position
/// in `layers`), a field path points into that file; without it, it is
/// `(integration, block name, key)`.
pub fn sharing_issues(
    layers: &[&Node],
    status_names: &[String],
    tlp_names: &[String],
    sharing_directory_found: bool,
    partial: bool,
    checked_layer: Option<usize>,
    file_path: Option<&str>,
) -> Vec<Finding> {
    let mut issues = Vec::new();
    if sharing_directory_found {
        let mut found = sharing_directory(file_path.unwrap_or_default());
        found.file_path = file_path.map(str::to_owned);
        issues.push(found);
    }
    for issue in merge_sharing_documents(layers, status_names, tlp_names) {
        if partial
            && issue.code == codes::MISSING_FIELD
            && issue.field_name.as_deref() != Some("name")
        {
            continue;
        }
        let mut found = Finding::new(
            issue.code,
            issue.severity,
            sharing_field_path(&issue, checked_layer),
            issue.message.clone(),
            file_path,
        );
        if let Some(integration) = &issue.integration {
            found = found.with("integration", integration.clone());
        }
        if let Some(block) = &issue.block {
            found = found.with("block", block.clone());
        }
        if let Some((layer, index)) = issue.location {
            found = found.with("layer", layer).with("index", index);
        }
        issues.push(found);
    }
    issues
}

fn sharing_field_path(issue: &SharingIssue, checked_layer: Option<usize>) -> Vec<String> {
    let Some(checked_layer) = checked_layer else {
        return [&issue.integration, &issue.block, &issue.field_name]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
    };
    if let Some((layer, None)) = issue.location {
        return match &issue.field_name {
            Some(field) if layer == checked_layer => vec![field.clone()],
            _ => Vec::new(),
        };
    }
    let mut candidates: Vec<(usize, usize)> = Vec::new();
    if let Some((layer, Some(index))) = issue.location {
        candidates.push((layer, index));
    }
    candidates.extend(issue.occurrences.iter().rev().copied());
    for (layer, index) in candidates {
        if layer == checked_layer {
            let mut path = vec![
                issue.integration.clone().unwrap_or_default(),
                index.to_string(),
            ];
            if let Some(field) = &issue.field_name {
                path.push(field.clone());
            }
            return path;
        }
    }
    Vec::new()
}

/// What a host knows about the folder an editor buffer sits in, for
/// [`buffer_issues`]: what the language server reads besides the buffer.
#[derive(Debug, Clone, Default)]
pub struct BufferContext {
    /// The parent instance's file of the same name, as text, when one
    /// exists (`<workspace>/../.opentide/configurations/<same path>`).
    pub parent: Option<String>,
    /// For `sharing.toml`: the workspace's `deployment.toml`, as text (an
    /// open buffer of it, else the file).
    pub deployment: Option<String>,
    /// For `sharing.toml`: `configurations/sharing/` exists.
    pub sharing_directory: bool,
}

/// The `.opentide/configurations` folder an absolute `path` sits in, and the
/// path relative to it.
pub fn configurations_directory(path: &str) -> Option<(String, String)> {
    let normal = path.replace('\\', "/");
    let absolute = normal.starts_with('/')
        || normal.as_bytes().get(1) == Some(&b':')
        || normal.starts_with("//");
    if !absolute {
        return None;
    }
    let marker = "/.opentide/configurations/";
    let at = normal.rfind(marker)?;
    let relative = &normal[at + marker.len()..];
    if relative.is_empty() {
        return None;
    }
    Some((
        normal[..at + marker.len() - 1].to_owned(),
        relative.to_owned(),
    ))
}

/// The findings an editor shows for a buffer under
/// `.opentide/configurations/` (`configuration_buffer_issues`): the buffer
/// merged onto the bundled file, then the parent instance's file of the same
/// name, as [`super::resolve`] merges them. A file with no model gets
/// nothing (`not_a_configuration_file` is for the command line).
pub fn buffer_issues(path: &str, text: &str, context: &BufferContext) -> Vec<Finding> {
    let parent = context
        .parent
        .as_deref()
        .and_then(|text| toml::parse(text.trim_start_matches('\u{feff}')).ok());
    let mut layers = Layers::default();
    if let Some(parent) = &parent {
        layers.later.push(parent);
    }
    let relative = configurations_directory(path).map(|(_, relative)| relative);
    if relative.as_deref() == Some("sharing.toml") {
        layers.status_names = context.deployment.as_deref().and_then(|text| {
            let layer = toml::parse(text).ok()?;
            let merged = merge_layers([&bundled::layer("deployment.toml"), &layer]);
            let names = status_names(&merged);
            (!names.is_empty()).then_some(names)
        });
        layers.sharing_directory = context.sharing_directory;
    }
    text_issues(path, text, &layers)
        .into_iter()
        .filter(|issue| issue.code != codes::NOT_A_CONFIGURATION_FILE)
        .collect()
}

/// Every merged configuration document of a resolved workspace, checked as
/// `validate --check configuration` reports them
/// (`workspace_configuration_issues`): each finding's message names the file
/// and key, its context the file. Sharing has its own check; a platform
/// plugin's file is its own.
pub fn workspace_issues(resolved: &Node) -> Vec<Finding> {
    let mut documents: Vec<(String, &Node)> = Vec::new();
    for (key, file_key) in [
        ("paths", "paths.toml"),
        ("deployment", "deployment.toml"),
        ("visibility", "visibility.toml"),
        ("documentation", "documentation.toml"),
    ] {
        if let Some(document) = resolved.get(key) {
            documents.push((file_key.to_owned(), document));
        }
    }
    if let Some(Node {
        value: Value::Map(platforms),
        ..
    }) = resolved.get("platforms").map(Arc::as_ref)
    {
        let mut sorted: Vec<_> = platforms.iter().collect();
        sorted.sort_by_key(|entry| entry.key.value.to_string());
        for entry in sorted {
            let identifier = entry.key.value.to_string();
            if PLATFORMS.contains(&identifier.as_str()) {
                documents.push((format!("platforms/{identifier}.toml"), &entry.value));
            }
        }
    }
    let mut issues = Vec::new();
    for (file_key, document) in documents {
        if !matches!(document.value, Value::Map(_)) {
            issues.push(
                Finding::new(
                    codes::SCHEMA_VALIDATION,
                    Severity::Error,
                    Vec::new(),
                    format!("{file_key}: the file must be a TOML table."),
                    None,
                )
                .with("file", file_key.clone()),
            );
            continue;
        }
        if file_key == "visibility.toml" && matches!(&document.value, Value::Map(e) if e.is_empty())
        {
            continue;
        }
        issues.extend(
            validate(&file_key, document)
                .into_iter()
                .map(|issue| named(issue, &file_key)),
        );
    }
    issues
}

/// The file and key named in the message: a merged document has no single
/// path.
fn named(issue: Finding, file_key: &str) -> Finding {
    let place = if issue.field_path.is_empty() {
        file_key.to_owned()
    } else {
        format!("{file_key}.{}", issue.field_path.join("."))
    };
    Finding {
        message: format!("{place}: {}", issue.message),
        file_path: None,
        ..issue
    }
    .with("file", file_key)
}

/// The findings of `sharing.toml` across the configuration layers, as
/// `validate --check sharing-config` reports them (`load_sharing`). Each
/// layer is `(folder, sharing.toml text if the file exists, whether
/// sharing/ exists)`, bundled first; the file path of every finding is the
/// last `sharing.toml` that exists.
pub fn sharing_config_issues(
    layers: &[(String, Option<String>, bool)],
    status_names: &[String],
) -> Vec<Finding> {
    let mut structural = Vec::new();
    let mut documents = Vec::new();
    let mut source = None;
    for (folder, text, directory) in layers {
        if *directory {
            structural.push(SharingIssue {
                code: codes::SHARING_DIRECTORY,
                message: format!(
                    "{folder}/sharing is not a sharing configuration. Use a single sharing.toml \
                     file."
                ),
                severity: Severity::Error,
                block: None,
                integration: None,
                field_name: None,
                location: None,
                occurrences: Vec::new(),
            });
        }
        let Some(text) = text else {
            continue;
        };
        source = Some(format!("{folder}/sharing.toml"));
        match toml::parse(text) {
            Ok(document) => {
                if matches!(&document.value, Value::Map(entries) if !entries.is_empty()) {
                    documents.push(document);
                }
            }
            Err(error) => structural.push(SharingIssue {
                code: codes::CONFIG_PARSE,
                message: format!("Could not read sharing.toml: {}", error.message),
                severity: Severity::Error,
                block: None,
                integration: None,
                field_name: None,
                location: None,
                occurrences: Vec::new(),
            }),
        }
    }
    let references: Vec<&Node> = documents.iter().collect();
    let merged = merge_sharing_documents(&references, status_names, &bundled::tlp_names());
    structural
        .into_iter()
        .chain(merged)
        .map(|issue| {
            let path = [&issue.integration, &issue.block, &issue.field_name]
                .into_iter()
                .flatten()
                .cloned()
                .collect();
            Finding::new(
                issue.code,
                issue.severity,
                path,
                issue.message,
                source.as_deref(),
            )
        })
        .collect()
}
