//! `opentide generate extract defender|elastic` (UC-4.4b, #834;
//! `cli/services/extraction.py`, `extraction/mde_importer.py`,
//! `extraction/elastic_importer.py`): the rules of a tenant pulled through
//! the connectors and written as opentide rule files under `Imported/`.
//!
//! Both write the rule document with serde-saphyr's emitter: Defender's
//! from Graph's beta custom detection shape (microsoft-defender-1.0);
//! Elastic's are the rule document written by serde-saphyr's emitter
//! (`rule_yaml`): the same data, keys in the importer's order, formatted
//! as serde-saphyr formats YAML where the oracle used PyYAML's
//! `IndentedYamlDumper` (the approved differences of #834). The run is one
//! checklist step,
//! `import from <platform>`, counting the YAML files it wrote under the
//! repository.

mod sentinel;

pub use sentinel::{sentinel, sentinel_with};

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use opentide_compile::json::{Json as CJson, Object};
use opentide_connectors::connector::TenantContext;
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::{Environment, HttpClient, Tenant};
use tokio_util::sync::CancellationToken;

use super::query::{Configured, http_settings, toml_value};
use super::template::fill;
use super::{Report, open, placement};
use crate::env::Env;
use crate::json::Json;
use crate::render::progress::{Step, StepStatus, plural};

/// Where an extraction runs.
pub struct Context<'a> {
    /// `--repo`.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory: `Imported/` is made there.
    pub cwd: &'a Path,
    /// `--proxy`.
    pub proxy: Option<&'a str>,
}

/// A run's result before it is a report: the importer's keys, or the
/// message it failed with.
type Outcome = Result<Vec<(String, Json)>, String>;

/// The run's refusal when a configuration file does not parse: `config_parse`
/// with its place and diagnostic (#1659), as every command that reads the
/// configuration reports it, not the importer's `command_failed`.
pub(crate) fn config_refusal(platform: &str, cx: &Context<'_>) -> Option<Report> {
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    match super::open_for(&format!("generate extract {platform}"), options) {
        Ok(workspace) => {
            crate::app::release(workspace);
            None
        }
        Err(refused) => Some(*refused),
    }
}

/// The tenants of `platform`, in file order, and the repository root.
fn configured(cx: &Context<'_>, platform: &str) -> Result<(Vec<Configured>, PathBuf), String> {
    let (shown, options) = placement(cx.repo, cx.env, cx.cwd);
    let workspace = open(options)?;
    let config = CJson::from_node(&workspace.configuration().resolved.tree);
    let tenants = opentide_compile::plan::tenants(&config, platform)
        .into_iter()
        .map(|tenant| Configured {
            name: opentide_compile::deploy::tenant_name(tenant).to_owned(),
            setup: tenant
                .get("setup")
                .and_then(CJson::as_object)
                .cloned()
                .unwrap_or_default(),
        })
        .collect();
    let root = PathBuf::from(shown);
    let root = if root.is_absolute() {
        root
    } else {
        cx.cwd.join(root)
    };
    Ok((tenants, root))
}

/// A tenant ready for its connector, or the message it fails with.
fn tenant(
    platform: &str,
    configured: &Configured,
    timeout: Duration,
    environment: &Environment,
    proxy: Option<&str>,
) -> Result<(Tenant, HttpClient), String> {
    let setup: toml::Table = configured
        .setup
        .iter()
        .filter_map(|(key, value)| toml_value(value).map(|value| (key.clone(), value)))
        .collect();
    let mut settings = http_settings(platform, timeout);
    settings.timeout = timeout;
    let tenant = Tenant::from_setup(
        platform,
        &configured.name,
        &setup,
        environment,
        Resolve::Counting,
        &settings,
    )
    .map_err(|error| error.to_string())?;
    let http = HttpClient::new(&tenant.label, &tenant.http, environment, proxy)
        .map_err(|error| error.to_string())?;
    Ok((tenant, http))
}

/// Runs `work` on the process's runtime (`sync_call`).
fn block_on<T: Send>(work: impl std::future::Future<Output = T> + Send) -> Result<T, String> {
    opentide_connectors::runtime::sync_call(|| opentide_connectors::runtime::block_on(work))
        .map_err(|_| "the import stopped unexpectedly".to_owned())?
}

/// `Imported/<file>` under the working directory, written as `write_text`
/// writes it (the platform's line ends), whole or not at all.
fn write_text(path: &Path, text: &str) -> Result<(), String> {
    let text = if cfg!(windows) {
        text.replace('\n', "\r\n")
    } else {
        text.to_owned()
    };
    opentide_workspace::fs::write_atomically(path, text.as_bytes())
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// The run as a report: one checklist step, then `Imported 3 rules from
/// defender · 1 skipped` (`run_extract`), or the failure.
fn report(platform: &str, started: Instant, written: usize, outcome: Outcome) -> Report {
    let command = format!("generate extract {platform}");
    let mut step = Step::new(&format!("import from {platform}"));
    step.unit = "rule".into();
    step.seconds = started.elapsed().as_secs_f64();
    match outcome {
        Err(message) => {
            step.status = StepStatus::Failed;
            let mut report = Report::error(&command, message);
            report.steps = vec![step];
            report
        }
        Ok(keys) => {
            step.status = StepStatus::Ok;
            step.count = Some(written);
            let mut data = vec![("import".to_owned(), Json::str(platform))];
            data.extend(keys);
            let count = match data.iter().find(|(key, _)| key == "extracted_count") {
                Some((_, Json::Int(count))) => usize::try_from(*count).unwrap_or(written),
                _ => written,
            };
            let skipped = match data.iter().find(|(key, _)| key == "skipped") {
                Some((_, Json::Array(items))) => items.len(),
                _ => 0,
            };
            let mut message = format!("Imported {} from {platform}", plural(count, "rule", None));
            if skipped > 0 {
                message.push_str(&format!(" · {skipped} skipped"));
            }
            let status = match data.iter().find(|(key, _)| key == "status") {
                Some((_, Json::Str(status))) => status.clone(),
                _ => "completed".to_owned(),
            };
            data.retain(|(key, _)| key != "status");
            let mut report = Report::completed(&command, data);
            report.outcome.message = message;
            report.outcome.status = status;
            report.outcome.summary = vec![
                ("imported".into(), Json::from(count)),
                ("skipped".into(), Json::from(skipped)),
            ];
            report.steps = vec![step];
            report
        }
    }
}

/// Whether `path` is under `root` (`WrittenFiles` watches the repository).
fn under(path: &Path, root: &Path) -> bool {
    let resolve = |path: &Path| {
        soft_canonicalize::soft_canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    };
    resolve(path).starts_with(resolve(root))
}

// ---------------------------------------------------------------- Defender

const DEFENDER: &str = "microsoft_defender";

/// The namespace of the UUIDs derived from Defender rule ids that are not
/// UUIDs (a rule created in the portal): the same id gives the same UUID.
fn defender_namespace() -> uuid::Uuid {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        b"https://opentide.org/ns/microsoft-defender-rule",
    )
}

/// The longest stem [`sanitize_filename`] returns, in bytes: callers add a
/// de-duplicating suffix and `.yaml`, and file systems cap a name at 255.
const STEM_LIMIT: usize = 200;

/// `name` as a file name on every system: each character Windows refuses
/// in a file name (`< > : " / \ | ? *`) and each control character is a
/// space, the stem is cut to [`STEM_LIMIT`] bytes at a character boundary,
/// and a reserved Windows device name (`CON`, `NUL`, `COM1`, ..., with any
/// extension) gets a `_` before it.
fn sanitize_filename(name: &str) -> String {
    let mut stem: String = name
        .chars()
        .map(|c| {
            if "<>:\"/\\|?*".contains(c) || c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect();
    stem.truncate(stem.floor_char_boundary(STEM_LIMIT));
    opentide_workspace::lint::device_safe(&stem)
}

/// `text` as a JSON string.
fn json_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_default()
}

/// The first character upper-cased, the rest kept.
fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// A field of a listed rule that an import needs, missing (or `null`), or
/// of another type than it reads: the rule is skipped and reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldError {
    /// The field, as a dotted path in the listing (`schedule.frequency`).
    pub field: String,
    /// What the field should be (`a string`), none when it is missing.
    pub expected: Option<&'static str>,
}

impl FieldError {
    pub(crate) fn missing(field: &str) -> Self {
        Self {
            field: field.to_owned(),
            expected: None,
        }
    }

    pub(crate) fn not(field: &str, expected: &'static str) -> Self {
        Self {
            field: field.to_owned(),
            expected: Some(expected),
        }
    }

    /// The error of a field read inside `parent` (`parent.field`).
    pub(crate) fn under(mut self, parent: &str) -> Self {
        self.field = format!("{parent}.{}", self.field);
        self
    }
}

impl std::fmt::Display for FieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.expected {
            None => write!(f, "field `{}` is missing", self.field),
            Some(expected) => write!(f, "field `{}` is not {expected}", self.field),
        }
    }
}

/// The value of `key` in `value`, which `shown` names in an error; `null`
/// counts as missing.
fn need<'j>(value: &'j CJson, key: &str, shown: &str) -> Result<&'j CJson, FieldError> {
    value
        .get(key)
        .filter(|value| !value.is_null())
        .ok_or_else(|| FieldError::missing(shown))
}

/// The string at `key` in `value`.
fn need_text<'j>(value: &'j CJson, key: &str, shown: &str) -> Result<&'j str, FieldError> {
    need(value, key, shown)?
        .as_str()
        .ok_or_else(|| FieldError::not(shown, "a string"))
}

/// The string at `key` in `value`, when set and not empty.
fn optional_text<'j>(
    value: &'j CJson,
    key: &str,
    shown: &str,
) -> Result<Option<&'j str>, FieldError> {
    match value.get(key) {
        None | Some(CJson::Null) => Ok(None),
        Some(CJson::Str(text)) if text.is_empty() => Ok(None),
        Some(CJson::Str(text)) => Ok(Some(text)),
        Some(_) => Err(FieldError::not(shown, "a string")),
    }
}

/// The date of an ISO 8601 timestamp (`2026-01-02` of `2026-01-02T03:04:05Z`).
fn date(timestamp: &str) -> &str {
    timestamp.split('T').next().unwrap_or_default()
}

/// A positive whole number without a leading zero, as written.
fn count(text: &str) -> Option<u64> {
    (!text.is_empty() && !text.starts_with('0') && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// Graph's ISO 8601 schedule duration as the block writes it
/// (microsoft-defender-1.0, `schedule`): a zero duration is `NRT`, `PT<n>H`
/// is `<n>H`, `P<n>D` is `<n>D`, and whole hours in minutes are hours.
/// `None` for a duration the block cannot write.
fn short_duration(iso: &str) -> Option<String> {
    let zero = |text: &str| !text.is_empty() && text.bytes().all(|b| b == b'0');
    if let Some(time) = iso.strip_prefix("PT") {
        // `None` when the last character is not one byte, so not a unit
        // (#1926).
        let (number, unit) = time.split_at_checked(time.len().checked_sub(1)?)?;
        if zero(number) && matches!(unit, "S" | "M" | "H") {
            return Some("NRT".to_owned());
        }
        return match unit {
            "H" => count(number).map(|hours| format!("{hours}H")),
            "M" => count(number)
                .filter(|minutes| minutes % 60 == 0)
                .map(|minutes| format!("{}H", minutes / 60)),
            _ => None,
        };
    }
    let days = iso.strip_prefix('P')?.strip_suffix('D')?;
    if zero(days) {
        return Some("NRT".to_owned());
    }
    count(days).map(|days| format!("{days}D"))
}

/// A list of strings.
fn strings(value: &CJson, shown: &str) -> Result<Vec<String>, FieldError> {
    match value {
        CJson::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| FieldError::not(shown, "a list of strings"))
            })
            .collect(),
        _ => Err(FieldError::not(shown, "a list of strings")),
    }
}

/// The technique ids of Graph's `tactics` tree: each parent named with no
/// sub-technique, and each sub-technique, once, in order.
fn listed_techniques(tactics: &CJson) -> Result<Vec<String>, FieldError> {
    const SHOWN: &str = "detectionAction.alertTemplate.tactics";
    let CJson::Array(tactics) = tactics else {
        return Err(FieldError::not(SHOWN, "a list"));
    };
    let mut ids: Vec<String> = Vec::new();
    let mut push = |id: String| {
        if !ids.contains(&id) {
            ids.push(id);
        }
    };
    for tactic in tactics {
        let techniques = match tactic.get("techniques") {
            None | Some(CJson::Null) => continue,
            Some(CJson::Array(items)) => items,
            Some(_) => return Err(FieldError::not(&format!("{SHOWN}[].techniques"), "a list")),
        };
        for technique in techniques {
            let shown = format!("{SHOWN}[].techniques[]");
            let parent = need_text(technique, "technique", &format!("{shown}.technique"))?;
            let subs = match technique.get("subTechniques") {
                None | Some(CJson::Null) => Vec::new(),
                Some(value) => strings(value, &format!("{shown}.subTechniques"))?,
            };
            if subs.is_empty() {
                push(parent.to_owned());
            }
            for sub in subs {
                push(sub);
            }
        }
    }
    Ok(ids)
}

/// Graph's mappings or targets (`entityMappings`, `automatedActions`) as the
/// block's `entities` or `actions`, through the kinds' table; a kind or a
/// field the table does not have keeps the rule from being imported.
fn imported_kinds(
    graph: &CJson,
    table: &[opentide_schema::objects::platform::microsoft_defender::Kind],
    shown: &str,
) -> Result<Object, FieldError> {
    let CJson::Object(kinds) = graph else {
        return Err(FieldError::not(shown, "an object"));
    };
    let mut out = Object::new();
    for kind in table {
        let items = match kinds.get(kind.graph) {
            None | Some(CJson::Null) => continue,
            Some(CJson::Array(items)) if items.is_empty() => continue,
            Some(CJson::Array(items)) => items,
            Some(_) => {
                return Err(FieldError::not(
                    &format!("{shown}.{}", kind.graph),
                    "a list",
                ));
            }
        };
        let mut converted = Vec::new();
        for item in items {
            let CJson::Object(fields) = item else {
                return Err(FieldError::not(
                    &format!("{shown}.{}[]", kind.graph),
                    "an object",
                ));
            };
            let mut mapping = Object::new();
            for (graph_field, value) in fields {
                if value.is_null() {
                    continue;
                }
                let Some((field, _)) = kind.fields.iter().find(|(_, graph)| graph == graph_field)
                else {
                    return Err(FieldError::not(
                        &format!("{shown}.{}[].{graph_field}", kind.graph),
                        "a field opentide models",
                    ));
                };
                mapping.insert((*field).into(), value.clone());
            }
            // The table's order.
            let mut ordered = Object::new();
            for (field, _) in kind.fields {
                if let Some(value) = mapping.get(*field) {
                    ordered.insert((*field).into(), value.clone());
                }
            }
            converted.push(CJson::Object(ordered));
        }
        out.insert(kind.key.into(), CJson::Array(converted));
    }
    for graph_kind in kinds.keys() {
        if !table.iter().any(|kind| kind.graph == graph_kind)
            && kinds.get(graph_kind).is_some_and(CJson::is_filled)
        {
            return Err(FieldError::not(
                &format!("{shown}.{graph_kind}"),
                "a kind opentide models",
            ));
        }
    }
    Ok(out)
}

/// The block `microsoft_defender` of one custom detection, listed in Graph's
/// beta shape (microsoft-defender-1.0), deployed to `tenant_names`.
#[expect(
    clippy::too_many_lines,
    reason = "the block's keys, one by one, in the specification's order"
)]
fn defender_block(rule: &CJson, tenant_names: &[String]) -> Result<Object, FieldError> {
    use opentide_schema::objects::platform::microsoft_defender::{
        ACTIONS, ENTITY_KINDS, GROUPINGS,
    };
    let author = optional_text(rule, "createdBy", "createdBy")?;
    let mut block = Object::new();
    block.insert(
        "schema".into(),
        CJson::from("platform::microsoft_defender::1.0"),
    );
    let status = match optional_text(rule, "status", "status")? {
        Some("disabled") => "DISABLED",
        _ => "PRODUCTION",
    };
    block.insert("status".into(), status.into());
    block.insert(
        "tenants".into(),
        CJson::Array(
            tenant_names
                .iter()
                .map(|name| CJson::from(name.as_str()))
                .collect(),
        ),
    );
    // A rule last changed by someone other than its author names them.
    if let Some(editor) = optional_text(rule, "lastModifiedBy", "lastModifiedBy")?
        && Some(editor) != author
    {
        block.insert("contributors".into(), CJson::Array(vec![editor.into()]));
    }
    let query = need_text(
        need(rule, "queryCondition", "queryCondition")?,
        "queryText",
        "queryCondition.queryText",
    )?;
    block.insert(
        "query".into(),
        sentinel::block_text(query, "queryCondition.queryText")?.into(),
    );
    let schedule = need(rule, "schedule", "schedule")?;
    let mut timing = Object::new();
    let frequency = need_text(schedule, "frequency", "schedule.frequency")?;
    timing.insert(
        "frequency".into(),
        short_duration(frequency)
            .ok_or_else(|| FieldError::not("schedule.frequency", "NRT, hours or days"))?
            .into(),
    );
    if let Some(lookback) = optional_text(schedule, "lookback", "schedule.lookback")? {
        timing.insert(
            "lookback".into(),
            short_duration(lookback)
                .filter(|lookback| lookback != "NRT")
                .ok_or_else(|| FieldError::not("schedule.lookback", "hours or days"))?
                .into(),
        );
    }
    block.insert("schedule".into(), CJson::Object(timing));

    let action = need(rule, "detectionAction", "detectionAction")?;
    let empty = CJson::Object(Object::new());
    let template = action.get("alertTemplate").unwrap_or(&empty);
    let shown = |key: &str| format!("detectionAction.alertTemplate.{key}");
    let mut alert = Object::new();
    if let Some(title) = optional_text(template, "title", &shown("title"))? {
        alert.insert("title".into(), title.into());
    }
    if let Some(recommended) =
        optional_text(template, "recommendedActions", &shown("recommendedActions"))?
    {
        alert.insert(
            "recommendation".into(),
            sentinel::block_text(recommended, &shown("recommendedActions"))?.into(),
        );
    }
    if let Some(tactics) = template.get("tactics").filter(|tactics| !tactics.is_null()) {
        let ids = listed_techniques(tactics)?;
        if !ids.is_empty() {
            alert.insert(
                "techniques".into(),
                CJson::Array(ids.into_iter().map(CJson::from).collect()),
            );
        }
    }
    match template.get("customDetails") {
        None | Some(CJson::Null) => {}
        Some(CJson::Object(details)) if details.is_empty() => {}
        Some(CJson::Object(details)) => {
            alert.insert("custom_details".into(), CJson::Object(details.clone()));
        }
        Some(_) => return Err(FieldError::not(&shown("customDetails"), "an object")),
    }
    if let Some(kind) = optional_text(template, "eventGroupingKind", &shown("eventGroupingKind"))? {
        let grouping = GROUPINGS
            .iter()
            .find(|(_, graph)| *graph == kind)
            .map(|(name, _)| *name)
            .ok_or_else(|| {
                FieldError::not(&shown("eventGroupingKind"), "alertPerEvent or singleAlert")
            })?;
        alert.insert("grouping".into(), grouping.into());
    }
    if !alert.is_empty() {
        block.insert("alert".into(), CJson::Object(alert));
    }
    if let Some(mappings) = template
        .get("entityMappings")
        .filter(|value| !value.is_null())
    {
        let entities = imported_kinds(mappings, &ENTITY_KINDS, &shown("entityMappings"))?;
        if !entities.is_empty() {
            block.insert("entities".into(), CJson::Object(entities));
        }
    }
    if let Some(automated) = action
        .get("automatedActions")
        .filter(|value| !value.is_null())
    {
        let actions = imported_kinds(automated, &ACTIONS, "detectionAction.automatedActions")?;
        if !actions.is_empty() {
            block.insert("actions".into(), CJson::Object(actions));
        }
    }
    if let Some(scope) = action
        .get("organizationalScope")
        .filter(|value| !value.is_null())
    {
        let groups = match scope.get("deviceGroups") {
            None | Some(CJson::Null) => Vec::new(),
            Some(value) => strings(value, "detectionAction.organizationalScope.deviceGroups")?,
        };
        if !groups.is_empty() {
            let mut scope = Object::new();
            scope.insert(
                "device_groups".into(),
                CJson::Array(groups.into_iter().map(CJson::from).collect()),
            );
            block.insert("scope".into(), CJson::Object(scope));
        }
    }
    if let Some(incident) = action
        .get("incidentConfiguration")
        .filter(|value| !value.is_null())
    {
        match incident.get("isExcludedFromIncidentCorrelation") {
            None | Some(CJson::Null) => {}
            Some(CJson::Bool(excluded)) => {
                let mut incident = Object::new();
                incident.insert("exclude_from_correlation".into(), CJson::Bool(*excluded));
                block.insert("incident".into(), CJson::Object(incident));
            }
            Some(_) => {
                return Err(FieldError::not(
                    "detectionAction.incidentConfiguration.isExcludedFromIncidentCorrelation",
                    "a boolean",
                ));
            }
        }
    }
    Ok(block)
}

/// How deploy addresses the rule a Defender rule id names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Addressed {
    /// `opentide-<uuid>`, exactly: the id deploy gives the rule (#1886).
    Yes,
    /// A UUID in any other form (a bare one, a rule opentide 1.0.0 deployed;
    /// `OPENTIDE-<UUID>`): the file keeps it, and deploying it creates
    /// `opentide-<uuid>` beside the original.
    BareUuid,
    /// Any other id (a rule created in the portal): the file gets a UUID
    /// derived from it, and deploying it creates a new rule.
    Derived,
}

/// The rule's `metadata.uuid`: the uuid after `opentide-` in the Defender
/// rule id, as deploy addresses the rule by `opentide-<uuid>`; the uuid the
/// id holds in any other form (bare, or after `opentide-` in another case);
/// otherwise a UUID derived from the id.
fn defender_uuid(id: &str) -> (String, Addressed) {
    if let Some(uuid) = opentide_compile::microsoft_defender::uuid_of_rule_id(id) {
        return (uuid, Addressed::Yes);
    }
    let prefix = opentide_compile::microsoft_defender::RULE_ID_PREFIX;
    let held = id
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map_or(id, |_| &id[prefix.len()..]);
    match uuid::Uuid::try_parse(held.trim()) {
        Ok(parsed) => (parsed.hyphenated().to_string(), Addressed::BareUuid),
        Err(_) => (
            uuid::Uuid::new_v5(&defender_namespace(), id.as_bytes())
                .hyphenated()
                .to_string(),
            Addressed::Derived,
        ),
    }
}

/// One rule file per uuid (#1886): of the listed rules (`(uuid, addressed)`
/// of each rule id, in order) that share a uuid, the one deploy addresses
/// (`opentide-<uuid>`) is kept, or else the first. Returns the kept rules'
/// positions, in order, and each left-out rule's position with the position
/// of the one kept in its place, so a rule opentide 1.0.0 left under the
/// bare uuid beside its `opentide-<uuid>` copy writes no second file.
fn one_per_uuid(resolved: &[(String, Addressed)]) -> (Vec<usize>, Vec<(usize, usize)>) {
    let mut kept: Vec<usize> = Vec::new();
    let mut left_out: Vec<usize> = Vec::new();
    for (index, (uuid, addressed)) in resolved.iter().enumerate() {
        match kept.iter_mut().find(|slot| resolved[**slot].0 == *uuid) {
            None => kept.push(index),
            Some(slot) if *addressed == Addressed::Yes && resolved[*slot].1 != Addressed::Yes => {
                left_out.push(*slot);
                *slot = index;
            }
            Some(_) => left_out.push(index),
        }
    }
    left_out.sort_unstable();
    let pairs = left_out
        .into_iter()
        .filter_map(|out| {
            kept.iter()
                .find(|slot| resolved[**slot].0 == resolved[out].0)
                .map(|slot| (out, *slot))
        })
        .collect();
    kept.sort_unstable();
    (kept, pairs)
}

/// The rule document of one custom detection, listed in Graph's beta shape,
/// deployed to `tenant_names`, under `uuid`: the rule's name, metadata,
/// description and severity, and its `microsoft_defender` block.
fn defender_document(
    rule: &CJson,
    uuid: &str,
    tenant_names: &[String],
) -> Result<Object, FieldError> {
    let name = need_text(rule, "displayName", "displayName")?;
    let created = date(need_text(rule, "createdDateTime", "createdDateTime")?);
    let modified = date(need_text(
        rule,
        "lastModifiedDateTime",
        "lastModifiedDateTime",
    )?);
    let template = need(rule, "detectionAction", "detectionAction")?
        .get("alertTemplate")
        .cloned()
        .unwrap_or(CJson::Object(Object::new()));
    let severity = need_text(
        &template,
        "severity",
        "detectionAction.alertTemplate.severity",
    )?;
    let description = match optional_text(rule, "description", "description")? {
        Some(text) => text.to_owned(),
        None => need_text(
            &template,
            "description",
            "detectionAction.alertTemplate.description",
        )?
        .to_owned(),
    };
    let mut metadata = Object::new();
    metadata.insert("uuid".into(), uuid.into());
    metadata.insert("schema".into(), "rule::1.0".into());
    metadata.insert("version".into(), CJson::Int(1));
    metadata.insert("created".into(), created.into());
    metadata.insert("modified".into(), modified.into());
    metadata.insert("tlp".into(), "amber+strict".into());
    if let Some(author) = optional_text(rule, "createdBy", "createdBy")? {
        metadata.insert("author".into(), author.into());
    }
    let mut response = Object::new();
    response.insert(
        "alert_severity".into(),
        capitalised(&severity.to_lowercase()).into(),
    );
    let mut configurations = Object::new();
    configurations.insert(
        DEFENDER.into(),
        CJson::Object(defender_block(rule, tenant_names)?),
    );
    let mut document = Object::new();
    document.insert("name".into(), name.into());
    document.insert("metadata".into(), CJson::Object(metadata));
    document.insert(
        "description".into(),
        sentinel::block_text(&description, "description")?.into(),
    );
    document.insert("response".into(), CJson::Object(response));
    document.insert("configurations".into(), CJson::Object(configurations));
    Ok(document)
}

/// The file name and YAML of one custom detection, or the field that keeps
/// it from being imported, or why the YAML would not validate.
fn render_rule(
    rule: &CJson,
    uuid: &str,
    tenant_names: &[String],
) -> Result<(String, String), String> {
    let name = need_text(rule, "displayName", "displayName").map_err(|e| e.to_string())?;
    let document = defender_document(rule, uuid, tenant_names).map_err(|e| e.to_string())?;
    let text = rule_yaml(&document)?;
    if let Some(reason) = unwritable_reason(
        &document,
        &text,
        DEFENDER,
        "platform::microsoft_defender::1.0",
    ) {
        return Err(reason);
    }
    Ok((sanitize_filename(name), text))
}

/// What makes two tenants' copies of one detection the same rule.
fn content(rule: &CJson) -> [Option<&CJson>; 6] {
    [
        rule.get("displayName"),
        rule.get("description"),
        rule.get("status"),
        rule.get("schedule"),
        rule.get("queryCondition"),
        rule.get("detectionAction"),
    ]
}

/// `opentide generate extract defender`: every custom detection of the
/// configured tenants, as rule files under `Imported/`.
pub fn defender(cx: &Context<'_>) -> Report {
    if let Some(refused) = config_refusal(DEFENDER, cx) {
        return refused;
    }
    let started = Instant::now();
    let mut written = 0;
    let outcome = defender_run(cx, &mut written);
    report("defender", started, written, outcome)
}

#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn defender_run(cx: &Context<'_>, written_count: &mut usize) -> Outcome {
    let (tenants, root) = configured(cx, DEFENDER)?;
    super::query::log_unset(&tenants, cx.env, "an extract");
    if tenants.is_empty() {
        tracing::error!(
            detail =
                "You must first have Microsoft Defender tenants configured to initiate the import",
            advice = "run 'opentide setup platforms --microsoft-defender'",
            critical = true,
            "defender_tenants_not_configured"
        );
        return Err("No Microsoft Defender tenants are configured".into());
    }
    let environment = Environment::from_pairs(cx.env.iter());
    let destination = cx.cwd.join("Imported");
    std::fs::create_dir_all(&destination)
        .map_err(|error| format!("{}: {error}", destination.display()))?;
    let connector = opentide_connectors::microsoft_defender::MicrosoftDefender::new();
    let mut listed: Vec<(String, Vec<(String, CJson)>)> = Vec::new();
    let mut skipped = Skipped::new("defender_import_rule_skipped");
    for configured in &tenants {
        let (tenant, http) = tenant(
            DEFENDER,
            configured,
            Duration::from_secs(60),
            &environment,
            cx.proxy,
        )?;
        let rules = block_on(async {
            let cancel = CancellationToken::new();
            let context = TenantContext {
                tenant: &tenant,
                http: &http,
                cancel: &cancel,
            };
            connector.list_rules(context).await
        })?
        .map_err(|error| match error {
            opentide_connectors::microsoft_defender::DefenderError::Authentication { .. } => {
                tracing::error!(
                    detail = format!("Cannot authenticate against {}", configured.name).as_str(),
                    critical = true,
                    "fatal_error"
                );
                format!(
                    "cannot authenticate against Microsoft Defender tenant '{}' with its configuration",
                    configured.name
                )
            }
            opentide_connectors::microsoft_defender::DefenderError::Refused { message, .. } => {
                message
            }
            opentide_connectors::microsoft_defender::DefenderError::Connector(error) => {
                error.to_string()
            }
        })?;
        for rule in rules {
            let shown = rule
                .get("displayName")
                .and_then(CJson::as_str)
                .unwrap_or_default()
                .to_owned();
            let id = match need_text(&rule, "id", "id") {
                Ok(id) => id.trim().to_owned(),
                Err(error) => {
                    skipped.push(&shown, &error.to_string());
                    continue;
                }
            };
            match listed.iter_mut().find(|(seen, _)| *seen == id) {
                Some((_, copies)) => copies.push((configured.name.clone(), rule)),
                None => listed.push((id, vec![(configured.name.clone(), rule)])),
            }
        }
    }
    let resolved: Vec<(String, Addressed)> =
        listed.iter().map(|(id, _)| defender_uuid(id)).collect();
    let (kept, left_out) = one_per_uuid(&resolved);
    let shown_of = |index: usize| -> &str {
        let (id, copies) = &listed[index];
        copies[0]
            .1
            .get("displayName")
            .and_then(CJson::as_str)
            .unwrap_or(id)
    };
    for (out, kept_in_place) in left_out {
        let (id, kept_id) = (&listed[out].0, &listed[kept_in_place].0);
        skipped.push(
            shown_of(out),
            &format!(
                "rule {id} names the same uuid as rule {kept_id}, which the file holds: it \
                 is most likely the copy an earlier opentide release left; delete it in the \
                 portal, or rename both its name and its alert title"
            ),
        );
    }
    let mut written: Vec<String> = Vec::new();
    for index in kept {
        let (id, copies) = &listed[index];
        let names: Vec<String> = copies.iter().map(|(name, _)| name.clone()).collect();
        let first = &copies[0].1;
        let shown = shown_of(index);
        let (uuid, addressed) = resolved[index].clone();
        if copies[1..]
            .iter()
            .any(|(_, rule)| content(rule) != content(first))
        {
            tracing::warn!(
                rule = shown,
                uuid = uuid.as_str(),
                detail = format!(
                    "Imported from {}; the copies in {} differ",
                    names[0],
                    names[1..].join(", ")
                )
                .as_str(),
                "defender_import_tenants_differ"
            );
        }
        // Deploy addresses a Defender rule by `opentide-<uuid>` (#1886):
        // any other id deploys as a new rule, and Graph refuses its create
        // while the original holds the display name, even disabled.
        let unaddressed = match addressed {
            Addressed::Yes => None,
            Addressed::BareUuid => Some(format!(
                "the tenant's rule id {id} is not the id deploy addresses a rule by \
                 (opentide-<uuid>): deploying the file creates opentide-{uuid}; first \
                 delete the original in the portal, or rename both its name and its \
                 alert title"
            )),
            Addressed::Derived => Some(format!(
                "the tenant's rule id {id} is not a UUID, so deploy cannot address it: \
                 the file was given the UUID {uuid}, and deploying it creates a new rule; \
                 first delete the original in the portal, or rename both its name and \
                 its alert title"
            )),
        };
        if let Some(detail) = unaddressed {
            tracing::warn!(
                rule = shown,
                uuid = uuid.as_str(),
                detail = detail.as_str(),
                "defender_import_new_uuid"
            );
        }
        let (mut filename, body) = match render_rule(first, &uuid, &names) {
            Ok(rendered) => rendered,
            Err(error) => {
                skipped.push(shown, &format!("rule {id}: {error}"));
                continue;
            }
        };
        if written.contains(&filename.to_lowercase()) {
            let short: String = uuid.chars().take(8).collect();
            filename = format!("{filename} {short}");
        }
        written.push(filename.to_lowercase());
        let path = destination.join(format!("{filename}.yaml"));
        write_text(&path, &body)?;
        if under(&path, &root) {
            *written_count += 1;
        }
    }
    Ok(skipped.into_keys())
}

/// The rules an import left out, each logged as it is skipped and listed
/// under `skipped` in the result, with the reason.
pub(crate) struct Skipped {
    event: &'static str,
    rules: Vec<Json>,
}

impl Skipped {
    pub(crate) fn new(event: &'static str) -> Self {
        Self {
            event,
            rules: Vec::new(),
        }
    }

    /// Logs and lists the rule `name`, left out for `reason`.
    pub(crate) fn push(&mut self, name: &str, reason: &str) {
        tracing::warn!(rule = name, reason = reason, "{}", self.event);
        self.rules.push(Json::object([
            ("name", Json::str(name)),
            ("reason", Json::str(reason)),
        ]));
    }

    /// The result's keys: `skipped`, when a rule was.
    pub(crate) fn into_keys(self) -> Vec<(String, Json)> {
        if self.rules.is_empty() {
            Vec::new()
        } else {
            vec![("skipped".to_owned(), Json::Array(self.rules))]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_safe_on_every_system() {
        assert_eq!(sanitize_filename("a:b/c?"), "a b c ");
        assert_eq!(sanitize_filename("a\tb\nc\u{7f}d"), "a b c d");
        assert_eq!(
            sanitize_filename("Encoded PowerShell"),
            "Encoded PowerShell"
        );
        assert_eq!(capitalised("deviceId"), "DeviceId");
        let long = "é".repeat(150);
        let cut = sanitize_filename(&long);
        assert!(cut.len() <= STEM_LIMIT && cut.chars().all(|c| c == 'é'));
        assert_eq!(sanitize_filename("CON"), "_CON");
    }

    #[test]
    fn durations_read_back_as_the_block_writes_them() {
        for (iso, short) in [
            ("PT0S", Some("NRT")),
            ("PT0M", Some("NRT")),
            ("P0D", Some("NRT")),
            ("PT1H", Some("1H")),
            ("PT24H", Some("24H")),
            ("PT120M", Some("2H")),
            ("P1D", Some("1D")),
            ("PT90M", None),
            ("PT01H", None),
            ("1H", None),
            // #1926: a multi-byte last character is no unit, not a panic.
            ("PT1é", None),
            ("PT1😀", None),
            ("PTé", None),
            ("P1é", None),
        ] {
            assert_eq!(short_duration(iso).as_deref(), short, "{iso}");
        }
    }

    #[test]
    fn a_uuid_id_is_kept_and_another_id_gets_a_derived_uuid() {
        // #1886: deploy's own id names the rule's uuid; the uuid in another
        // form of it is kept, but deploy does not address that rule.
        assert_eq!(
            defender_uuid("opentide-2594bf5e-0000-4000-8000-000000000201"),
            (
                "2594bf5e-0000-4000-8000-000000000201".to_owned(),
                Addressed::Yes
            )
        );
        assert_eq!(
            defender_uuid("OPENTIDE-2594BF5E-0000-4000-8000-000000000201"),
            (
                "2594bf5e-0000-4000-8000-000000000201".to_owned(),
                Addressed::BareUuid
            )
        );
        assert_eq!(
            defender_uuid("8D7C6B5A-0000-4000-8000-000000000201"),
            (
                "8d7c6b5a-0000-4000-8000-000000000201".to_owned(),
                Addressed::BareUuid
            )
        );
        let (derived, addressed) = defender_uuid("7506");
        assert_eq!(addressed, Addressed::Derived);
        assert_eq!(
            derived,
            defender_uuid("7506").0,
            "the same id, the same uuid"
        );
        assert!(uuid::Uuid::try_parse(&derived).is_ok());
    }

    #[test]
    fn a_bare_uuid_beside_its_opentide_copy_writes_one_file() {
        // #1886: a 1.0.0 rule renamed in the portal beside the one deploy
        // now creates: one file, from `opentide-<uuid>`, wherever it is listed.
        let ids = [
            "8d7c6b5a-0000-4000-8000-000000000201",
            "7506",
            "opentide-8d7c6b5a-0000-4000-8000-000000000201",
            "OPENTIDE-8D7C6B5A-0000-4000-8000-000000000201",
            "8d7c6b5a-0000-4000-8000-000000000202",
        ];
        let resolved: Vec<(String, Addressed)> = ids.iter().map(|id| defender_uuid(id)).collect();
        assert_eq!(
            one_per_uuid(&resolved),
            (vec![1, 2, 4], vec![(0, 2), (3, 2)])
        );
        // No `opentide-` copy: the first listed is kept.
        let resolved: Vec<(String, Addressed)> = [ids[3], ids[0], ids[1]]
            .iter()
            .map(|id| defender_uuid(id))
            .collect();
        assert_eq!(one_per_uuid(&resolved), (vec![0, 2], vec![(1, 0)]));
    }

    fn rule() -> CJson {
        serde_json::from_str(
            r#"{
              "id": "8d7c6b5a-0000-4000-8000-000000000201",
              "displayName": "Suspicious PowerShell: \"encoded\" command",
              "description": "An encoded command line.",
              "status": "enabled",
              "createdBy": "alice@contoso.example",
              "createdDateTime": "2026-01-02T03:04:05.123Z",
              "lastModifiedBy": "bob@contoso.example",
              "lastModifiedDateTime": "2026-02-03T04:05:06Z",
              "queryCondition": {"queryText": "DeviceProcessEvents\n  | where FileName == \"powershell.exe\"\n"},
              "schedule": {"frequency": "PT1H", "lookback": "PT4H"},
              "detectionAction": {
                "alertTemplate": {
                  "title": "Encoded PowerShell",
                  "description": "An encoded command line.",
                  "severity": "medium",
                  "recommendedActions": "Isolate the device.",
                  "tactics": [
                    {"tactic": "Execution", "techniques": [{"technique": "T1059", "subTechniques": ["T1059.001"]}]},
                    {"tactic": "DefenseEvasion", "techniques": [{"technique": "T1027"}]}
                  ],
                  "entityMappings": {"hosts": [{"nameColumn": "DeviceName", "deviceIdColumn": "DeviceId"}]},
                  "customDetails": {"CommandLine": "ProcessCommandLine"},
                  "eventGroupingKind": "singleAlert"
                },
                "automatedActions": {"isolateDevices": [{"deviceIdColumn": "DeviceId", "isolationType": "full"}]},
                "organizationalScope": {"deviceGroups": ["Tier 0"]},
                "incidentConfiguration": {"isExcludedFromIncidentCorrelation": true}
              }
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn a_detection_becomes_a_rule_that_validates() {
        let (uuid, _) = defender_uuid("8d7c6b5a-0000-4000-8000-000000000201");
        let (name, body) = render_rule(&rule(), &uuid, &["lab".into(), "prod".into()]).unwrap();
        assert_eq!(
            name,
            "Suspicious PowerShell  \"encoded\" command".replace('"', " ")
        );
        let expected = r#"name: "Suspicious PowerShell: \"encoded\" command"
metadata:
  uuid: 8d7c6b5a-0000-4000-8000-000000000201
  schema: rule::1.0
  version: 1
  created: "2026-01-02"
  modified: "2026-02-03"
  tlp: amber+strict
  author: alice@contoso.example
description: An encoded command line.
response:
  alert_severity: Medium
configurations:
  microsoft_defender:
    schema: platform::microsoft_defender::1.0
    status: PRODUCTION
    tenants:
      - lab
      - prod
    contributors:
      - bob@contoso.example
    query: |
      DeviceProcessEvents
        | where FileName == "powershell.exe"
    schedule:
      frequency: 1H
      lookback: 4H
    alert:
      title: Encoded PowerShell
      recommendation: Isolate the device.
      techniques:
        - T1059.001
        - T1027
      custom_details:
        CommandLine: ProcessCommandLine
      grouping: single_alert
    entities:
      hosts:
        - device_id: DeviceId
          name: DeviceName
    actions:
      isolate_devices:
        - device_id: DeviceId
          isolation_type: full
    scope:
      device_groups:
        - Tier 0
    incident:
      exclude_from_correlation: true
"#;
        assert_eq!(body, expected);
    }

    #[test]
    fn a_missing_mistyped_or_unmodelled_field_names_the_field() {
        let failed = |change: &dyn Fn(&mut Object)| {
            let mut rule = rule();
            if let CJson::Object(fields) = &mut rule {
                change(fields);
            }
            render_rule(&rule, "8d7c6b5a-0000-4000-8000-000000000201", &[]).unwrap_err()
        };
        assert_eq!(
            failed(&|rule| {
                rule.shift_remove("displayName");
            }),
            "field `displayName` is missing"
        );
        assert_eq!(
            failed(&|rule| {
                rule.insert(
                    "schedule".into(),
                    serde_json::from_str(r#"{"frequency": "PT90M"}"#).unwrap(),
                );
            }),
            "field `schedule.frequency` is not NRT, hours or days"
        );
        assert_eq!(
            failed(&|rule| {
                rule.insert(
                    "detectionAction".into(),
                    serde_json::from_str(r#"{"alertTemplate": {"severity": "low", "entityMappings": {"hosts": [{"deviceIdColumn": "DeviceId", "osColumn": "Os"}]}}}"#).unwrap(),
                );
            }),
            "field `detectionAction.alertTemplate.entityMappings.hosts[].osColumn` is not a field opentide models"
        );
    }
}
// ----------------------------------------------------------------- Elastic

const ELASTIC: &str = "elastic";

/// The field types RFC 0007's `FieldType` takes (`_VALID_FIELD_TYPES`).
const VALID_FIELD_TYPES: [&str; 25] = [
    "keyword",
    "constant_keyword",
    "wildcard",
    "text",
    "match_only_text",
    "long",
    "integer",
    "short",
    "byte",
    "unsigned_long",
    "double",
    "float",
    "half_float",
    "scaled_float",
    "date",
    "date_nanos",
    "boolean",
    "ip",
    "version",
    "binary",
    "geo_point",
    "geo_shape",
    "object",
    "flattened",
    "nested",
];

/// The namespace of the UUIDs derived from prebuilt rules' ids
/// (`OPENTIDE_MIGRATION_NS`).
fn migration_namespace() -> uuid::Uuid {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        b"https://opentide.org/ns/elastic-rule-migration",
    )
}

fn get<'j>(rule: &'j CJson, key: &str) -> Option<&'j CJson> {
    rule.get(key).filter(|value| !value.is_null())
}

/// Whether Kibana set a value: `null`, `false` and an empty string, list or
/// object are each how its export writes a field it leaves unset.
fn is_set(value: &CJson) -> bool {
    match value {
        CJson::Null | CJson::Bool(false) => false,
        CJson::Str(text) => !text.is_empty(),
        CJson::Array(items) => !items.is_empty(),
        CJson::Object(members) => !members.is_empty(),
        CJson::Bool(true) | CJson::Int(_) | CJson::UInt(_) | CJson::Float(_) => true,
    }
}

/// A suppression window from Kibana's `{value, unit}` object (`5m`), or the
/// keys it lacks: a half-built duration is left out of the rule.
fn suppression_duration(duration: &Object) -> Result<String, Vec<&'static str>> {
    let part = |key: &str| duration.get(key).filter(|value| is_set(value)).map(text_of);
    match (part("value"), part("unit")) {
        (Some(value), Some(unit)) => Ok(format!("{value}{unit}")),
        (value, unit) => Err([("value", value), ("unit", unit)]
            .into_iter()
            .filter_map(|(key, found)| found.is_none().then_some(key))
            .collect()),
    }
}

/// The value of `key` when Kibana set it ([`is_set`]).
fn given<'j>(rule: &'j CJson, key: &str) -> Option<&'j CJson> {
    rule.get(key).filter(|value| is_set(value))
}

/// Whether `key` holds `true`.
fn flag(rule: &CJson, key: &str) -> bool {
    rule.get(key) == Some(&CJson::Bool(true))
}

/// `value` as text: a string as it is, anything else as its compact JSON.
fn text_of(value: &CJson) -> String {
    opentide_connectors::text::json_text(value)
}

fn object(members: Vec<(&str, CJson)>) -> CJson {
    CJson::Object(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

/// A field Kibana holds as a list of strings, or as one string, as a list:
/// `index: "logs-*"` is `["logs-*"]`.
fn string_list(value: &CJson) -> CJson {
    match value {
        CJson::Str(_) => CJson::Array(vec![value.clone()]),
        other => other.clone(),
    }
}

/// ATT&CK technique ids of Kibana's `threat` array (`extract_techniques`).
fn extract_techniques(threats: Option<&CJson>) -> Vec<CJson> {
    let mut found: Vec<CJson> = Vec::new();
    let Some(CJson::Array(threats)) = threats else {
        return found;
    };
    for threat in threats {
        let Some(CJson::Array(techniques)) = threat.get("technique") else {
            continue;
        };
        for technique in techniques {
            match given(technique, "subtechnique") {
                Some(CJson::Array(subs)) => {
                    for sub in subs {
                        if let Some(id) = given(sub, "id")
                            && !found.contains(id)
                        {
                            found.push(id.clone());
                        }
                    }
                }
                _ => {
                    if let Some(id) = given(technique, "id")
                        && !found.contains(id)
                    {
                        found.push(id.clone());
                    }
                }
            }
        }
    }
    found
}

/// `None`s, empty mappings and empty lists left out (`_clean_empty`).
fn clean_empty(value: &Object) -> Object {
    let mut out = Object::new();
    for (key, value) in value {
        match value {
            CJson::Null => {}
            CJson::Object(inner) => {
                let inner = clean_empty(inner);
                if !inner.is_empty() {
                    out.insert(key.clone(), CJson::Object(inner));
                }
            }
            CJson::Array(items) => {
                if !items.is_empty() {
                    out.insert(key.clone(), value.clone());
                }
            }
            other => {
                out.insert(key.clone(), other.clone());
            }
        }
    }
    out
}

fn is_prebuilt(rule: &CJson) -> bool {
    given(rule, "immutable").is_some()
        || rule
            .get("rule_source")
            .and_then(|source| source.get("type"))
            .and_then(CJson::as_str)
            == Some("external")
}

/// Kibana's `now-<n><unit>` as an RFC 0007 duration (`_date_math_duration`).
fn date_math_duration(value: &CJson) -> String {
    let text = text_of(value);
    let text = text.trim();
    let text = text.strip_prefix("now-").unwrap_or(text);
    if let Some(weeks) = text.strip_suffix('w')
        && !weeks.is_empty()
        && weeks.chars().all(|c| c.is_ascii_digit())
        && let Ok(weeks) = weeks.parse::<u128>()
    {
        return format!("{}d", weeks * 7);
    }
    text.to_owned()
}

fn only(entry: &CJson, keys: &[&str]) -> CJson {
    CJson::Object(
        keys.iter()
            .filter_map(|key| {
                entry
                    .get(key)
                    .map(|value| ((*key).to_owned(), value.clone()))
            })
            .collect(),
    )
}

fn extract_filter(entry: &CJson) -> CJson {
    let empty = CJson::Object(Object::new());
    let meta = entry
        .get("meta")
        .filter(|meta| is_set(meta))
        .unwrap_or(&empty);
    let query = meta
        .get("params")
        .and_then(|params| params.get("query"))
        .filter(|query| is_set(query));
    if meta.get("type").and_then(CJson::as_str) == Some("phrase")
        && let Some(key) = given(meta, "key")
        && let Some(query) = query
        && !flag(meta, "disabled")
    {
        return object(vec![
            ("field", key.clone()),
            ("value", CJson::Str(text_of(query))),
            ("negate", CJson::Bool(flag(meta, "negate"))),
        ]);
    }
    let mut raw = entry.as_object().cloned().unwrap_or_default();
    raw.shift_remove("$state");
    CJson::Object(raw)
}

/// An exported Kibana rule as an opentide rule (`kibana_to_opentide`).
#[expect(
    clippy::too_many_lines,
    reason = "the oracle's `kibana_to_opentide`, block by block, in one place"
)]
fn kibana_to_opentide(rule: &CJson, make_custom: bool) -> Object {
    let rule_type = match rule.get("type") {
        None => CJson::Str("query".into()),
        Some(kind) => kind.clone(),
    };
    let kind = rule_type.as_str().unwrap_or_default();
    let prebuilt = is_prebuilt(rule);
    let raw_rule_id = given(rule, "rule_id")
        .or_else(|| given(rule, "id"))
        .map(text_of)
        .unwrap_or_default();
    let rule_id = if make_custom && prebuilt {
        uuid::Uuid::new_v5(&migration_namespace(), raw_rule_id.as_bytes()).to_string()
    } else {
        raw_rule_id
    };
    let mut rule_name = rule
        .get("name")
        .map_or_else(|| "Unnamed Rule".to_owned(), text_of);
    if make_custom && prebuilt {
        rule_name.push_str(" (Custom)");
    }
    let description = rule
        .get("description")
        .map(text_of)
        .unwrap_or_default()
        .trim()
        .to_owned();
    let (author, contributors): (String, Vec<CJson>) = match rule.get("author") {
        Some(CJson::Array(authors)) if !authors.is_empty() => (
            text_of(&authors[0]),
            authors[1..]
                .iter()
                .map(|a| CJson::Str(text_of(a)))
                .collect(),
        ),
        Some(CJson::Str(author)) => (author.clone(), Vec::new()),
        None => ("Elastic Security".to_owned(), Vec::new()),
        Some(_) => ("Elastic Security".to_owned(), Vec::new()),
    };
    let created_text = rule.get("created_at").map(text_of).unwrap_or_default();
    let created = Some(
        created_text
            .split('T')
            .next()
            .unwrap_or_default()
            .to_owned(),
    )
    .filter(|text| !text.is_empty())
    .unwrap_or_else(|| "2026-01-01".to_owned());
    let modified_text = rule.get("updated_at").map(text_of).unwrap_or_default();
    let modified = Some(
        modified_text
            .split('T')
            .next()
            .unwrap_or_default()
            .to_owned(),
    )
    .filter(|text| !text.is_empty())
    .unwrap_or_else(|| created.clone());
    let techniques = extract_techniques(rule.get("threat"));
    let severity = rule
        .get("severity")
        .map_or_else(|| "medium".to_owned(), text_of)
        .to_lowercase();
    let alert_severity = match severity.as_str() {
        "low" => "Low",
        "high" => "High",
        "critical" => "Critical",
        _ => "Medium",
    };
    let status = if flag(rule, "enabled") {
        "PRODUCTION"
    } else {
        "DISABLED"
    };
    let mut block = Object::new();
    block.insert("enabled".into(), CJson::Bool(true));
    block.insert("schema".into(), CJson::Str("platform::elastic::1.0".into()));
    block.insert("status".into(), CJson::Str(status.into()));
    block.insert("type".into(), rule_type.clone());
    if matches!(
        kind,
        "query" | "eql" | "esql" | "threshold" | "new_terms" | "threat_match"
    ) {
        if let Some(query) = given(rule, "query") {
            block.insert("query".into(), CJson::Str(text_of(query).trim().to_owned()));
        }
        if matches!(kind, "query" | "threshold" | "new_terms" | "threat_match")
            && let Some(language @ CJson::Str(text)) = rule.get("language")
            && (text == "kuery" || text == "lucene")
        {
            block.insert("language".into(), language.clone());
        }
    }
    if kind != "esql" && kind != "machine_learning" {
        if let Some(view) = given(rule, "data_view_id") {
            block.insert("data_view_id".into(), view.clone());
        } else if let Some(index) = given(rule, "index") {
            block.insert("index".into(), string_list(index));
        }
    }
    let interval = rule
        .get("interval")
        .cloned()
        .unwrap_or_else(|| CJson::Str("5m".into()));
    let from = rule
        .get("from")
        .cloned()
        .unwrap_or_else(|| CJson::Str("now-6m".into()));
    let seconds =
        |value: &str, zero: bool| opentide_compile::duration::elastic_seconds(value, zero);
    let lookback = match (
        seconds(&date_math_duration(&from), true),
        interval.as_str().map(|interval| seconds(interval, false)),
    ) {
        (Ok(total), Some(Ok(every))) => {
            if total < every {
                tracing::warn!(
                    rule = rule.get("name").map(text_of).as_deref(),
                    interval = text_of(&interval).as_str(),
                    from = text_of(&from).as_str(),
                    "elastic_import_window_widened"
                );
            }
            opentide_compile::duration::elastic_format(total.saturating_sub(every))
        }
        _ => {
            tracing::warn!(
                rule = rule.get("name").map(text_of).as_deref(),
                interval = text_of(&interval).as_str(),
                from = text_of(&from).as_str(),
                "elastic_import_schedule_defaulted"
            );
            "1m".to_owned()
        }
    };
    let mut scheduling = Object::new();
    scheduling.insert("interval".into(), interval);
    scheduling.insert("lookback".into(), CJson::Str(lookback));
    if let Some(max) = given(rule, "max_signals") {
        scheduling.insert("max_alerts".into(), max.clone());
    }
    block.insert("scheduling".into(), CJson::Object(scheduling));
    if let Some(CJson::Array(mapping)) = given(rule, "severity_mapping") {
        block.insert(
            "severity".into(),
            object(vec![
                ("default", CJson::Str(alert_severity.into())),
                (
                    "mapping",
                    CJson::Array(
                        mapping
                            .iter()
                            .map(|m| only(m, &["field", "value", "operator", "severity"]))
                            .collect(),
                    ),
                ),
            ]),
        );
    }
    if let Some(score) = get(rule, "risk_score") {
        match given(rule, "risk_score_mapping") {
            Some(CJson::Array(mapping)) => {
                block.insert(
                    "risk".into(),
                    object(vec![
                        ("score", score.clone()),
                        (
                            "mapping",
                            CJson::Array(
                                mapping
                                    .iter()
                                    .map(|m| only(m, &["field", "operator", "value"]))
                                    .collect(),
                            ),
                        ),
                    ]),
                );
            }
            _ => {
                block.insert("risk".into(), score.clone());
            }
        }
    }
    if let Some(suppression) = given(rule, "alert_suppression") {
        let mut out = Object::new();
        if kind != "threshold"
            && let Some(group_by) = given(suppression, "group_by")
        {
            out.insert("group_by".into(), string_list(group_by));
        }
        match given(suppression, "duration") {
            Some(CJson::Object(duration)) => match suppression_duration(duration) {
                Ok(text) => {
                    out.insert("duration".into(), CJson::Str(text));
                }
                Err(missing) => {
                    tracing::warn!(
                        rule = rule.get("name").map(text_of).as_deref(),
                        missing = missing.join(", ").as_str(),
                        "elastic_import_suppression_duration_skipped"
                    );
                }
            },
            Some(text @ CJson::Str(_)) => {
                out.insert("duration".into(), text.clone());
            }
            _ => {}
        }
        if let Some(strategy) = given(suppression, "missing_fields_strategy") {
            out.insert("missing_fields_strategy".into(), strategy.clone());
        }
        if !out.is_empty() {
            block.insert("suppression".into(), CJson::Object(out));
        }
    }
    if let Some(CJson::Array(filters)) = given(rule, "filters")
        && kind != "esql"
        && kind != "machine_learning"
    {
        block.insert(
            "filters".into(),
            CJson::Array(filters.iter().map(extract_filter).collect()),
        );
    }
    if let Some(fields) = rule
        .get("investigation_fields")
        .filter(|fields| is_set(fields))
        .and_then(|fields| given(fields, "field_names"))
    {
        block.insert("highlighted_fields".into(), string_list(fields));
    }
    if let Some(CJson::Array(required)) = given(rule, "required_fields") {
        let mut fields = Vec::new();
        for field in required {
            let Some(name) = given(field, "name").filter(|_| field.as_object().is_some()) else {
                continue;
            };
            let kind = field.get("type");
            if !kind
                .and_then(CJson::as_str)
                .is_some_and(|kind| VALID_FIELD_TYPES.contains(&kind))
            {
                tracing::warn!(
                    rule = rule.get("name").map(text_of).as_deref(),
                    field = text_of(name).as_str(),
                    r#type = kind.map(text_of).as_deref(),
                    "elastic_import_required_field_dropped"
                );
                continue;
            }
            fields.push(object(vec![
                ("name", name.clone()),
                ("type", kind.cloned().unwrap_or(CJson::Null)),
            ]));
        }
        if !fields.is_empty() {
            block.insert("required_fields".into(), CJson::Array(fields));
        }
    }
    if let Some(CJson::Array(integrations)) = given(rule, "related_integrations") {
        let mut out = Vec::new();
        for integration in integrations {
            let Some(package) =
                given(integration, "package").filter(|_| integration.as_object().is_some())
            else {
                continue;
            };
            let version = given(integration, "version")
                .cloned()
                .unwrap_or_else(|| CJson::Str("*".into()));
            let named = given(integration, "integration");
            if named.is_some() || version != CJson::Str("*".into()) {
                let mut item = vec![("package", package.clone()), ("version", version)];
                if let Some(named) = named {
                    item.push(("integration", named.clone()));
                }
                out.push(object(item));
            } else {
                out.push(package.clone());
            }
        }
        if !out.is_empty() {
            block.insert("integration".into(), CJson::Array(out));
        }
    }
    let mut guide = Object::new();
    if let Some(note) = given(rule, "note") {
        guide.insert(
            "investigation".into(),
            CJson::Str(text_of(note).trim().to_owned()),
        );
    }
    if let Some(setup) = given(rule, "setup") {
        guide.insert("setup".into(), CJson::Str(text_of(setup).trim().to_owned()));
    }
    if !guide.is_empty() {
        block.insert("guide".into(), CJson::Object(guide));
    }
    if let Some(positives) = given(rule, "false_positives") {
        block.insert("false_positives".into(), string_list(positives));
    }
    if let Some(CJson::Array(tags)) = given(rule, "tags") {
        // Deploy writes the marker first (`opentide`, `OpenTide` before
        // 0.29), so only a leading marker is opentide's: the same word
        // further on is a tag the rule's author wrote, and is kept.
        let own = match tags.split_first() {
            Some((first, rest))
                if first
                    .as_str()
                    .is_some_and(opentide_compile::elastic::is_marker_tag) =>
            {
                rest
            }
            _ => tags.as_slice(),
        };
        block.insert("tags".into(), CJson::Array(own.to_vec()));
    }
    let mut overrides = Object::new();
    if let Some(name) = given(rule, "rule_name_override") {
        overrides.insert("name".into(), name.clone());
    }
    if let Some(timestamp) = given(rule, "timestamp_override") {
        overrides.insert("timestamp".into(), timestamp.clone());
    }
    if let Some(disabled) = get(rule, "timestamp_override_fallback_disabled") {
        overrides.insert("disable_fallback".into(), disabled.clone());
    }
    if !overrides.is_empty() {
        block.insert("overrides".into(), CJson::Object(overrides));
    }
    let mut actions = Object::new();
    if let Some(notify) = given(rule, "actions") {
        actions.insert("notify".into(), notify.clone());
    }
    if let Some(CJson::Array(responses)) = given(rule, "response_actions") {
        let mut out = Vec::new();
        for response in responses {
            let action = response.get("action_type_id").and_then(CJson::as_str);
            let empty = CJson::Object(Object::new());
            let params = response
                .get("params")
                .filter(|p| is_set(p))
                .unwrap_or(&empty);
            match action {
                Some(".endpoint") => {
                    let command = params.get("command");
                    let known = command.and_then(CJson::as_str).is_some_and(|command| {
                        matches!(
                            command,
                            "isolate" | "kill-process" | "suspend-process" | "runscript"
                        )
                    });
                    if !known {
                        tracing::warn!(
                            rule = rule_name.as_str(),
                            command = command.map(text_of).as_deref(),
                            "skipping_unsupported_endpoint_response_action"
                        );
                        continue;
                    }
                    let mut item = vec![("endpoint", command.cloned().unwrap_or(CJson::Null))];
                    if let Some(comment) = given(params, "comment") {
                        item.push(("comment", comment.clone()));
                    }
                    let config = params.get("config").filter(|c| is_set(c)).unwrap_or(&empty);
                    if let Some(field) = given(config, "field")
                        && !flag(config, "overwrite")
                    {
                        item.push(("field", field.clone()));
                    }
                    out.push(object(item));
                }
                Some(".osquery") => {
                    if params.as_object().is_some() && given(params, "query").is_some() {
                        out.push(object(vec![("osquery", params.clone())]));
                    } else {
                        tracing::warn!(
                            rule = rule_name.as_str(),
                            reason =
                                "osquery response action has no inline query (pack/saved query)",
                            "skipping_unsupported_osquery_response_action"
                        );
                    }
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            actions.insert("respond".into(), CJson::Array(out));
        }
    }
    if let Some(timeline) = given(rule, "timeline_id") {
        actions.insert(
            "timeline".into(),
            object(vec![
                ("id", timeline.clone()),
                (
                    "title",
                    rule.get("timeline_title")
                        .cloned()
                        .unwrap_or_else(|| CJson::Str(String::new())),
                ),
            ]),
        );
    }
    if !actions.is_empty() {
        block.insert("actions".into(), CJson::Object(actions));
    }
    if let Some(CJson::Array(exceptions)) = given(rule, "exceptions_list") {
        let endpoint = exceptions
            .iter()
            .any(|e| e.get("type").and_then(CJson::as_str) == Some("endpoint"));
        let lists: Vec<CJson> = exceptions
            .iter()
            .filter(|e| {
                matches!(
                    e.get("type").and_then(CJson::as_str),
                    Some("detection" | "rule_default")
                )
            })
            .map(|e| {
                object(vec![
                    ("id", e.get("id").cloned().unwrap_or(CJson::Null)),
                    ("list_id", e.get("list_id").cloned().unwrap_or(CJson::Null)),
                    (
                        "namespace_type",
                        e.get("namespace_type")
                            .cloned()
                            .unwrap_or_else(|| CJson::Str("single".into())),
                    ),
                    (
                        "type",
                        e.get("type")
                            .cloned()
                            .unwrap_or_else(|| CJson::Str("detection".into())),
                    ),
                ])
            })
            .collect();
        if endpoint || !lists.is_empty() {
            block.insert(
                "exceptions".into(),
                object(vec![
                    ("endpoint", CJson::Bool(endpoint)),
                    (
                        "lists",
                        if lists.is_empty() {
                            CJson::Null
                        } else {
                            CJson::Array(lists)
                        },
                    ),
                ]),
            );
        }
    }
    if kind == "threshold"
        && let Some(threshold) = given(rule, "threshold")
    {
        let cardinality = match threshold.get("cardinality") {
            Some(CJson::Array(items)) if !items.is_empty() => object(vec![
                (
                    "field",
                    items[0].get("field").cloned().unwrap_or(CJson::Null),
                ),
                (
                    "value",
                    items[0].get("value").cloned().unwrap_or(CJson::Null),
                ),
            ]),
            _ => CJson::Null,
        };
        let field = match given(threshold, "field") {
            Some(field) => string_list(field),
            None => CJson::Array(Vec::new()),
        };
        block.insert(
            "threshold".into(),
            object(vec![
                ("field", field),
                (
                    "value",
                    threshold.get("value").cloned().unwrap_or(CJson::Int(1)),
                ),
                ("cardinality", cardinality),
            ]),
        );
    }
    if kind == "new_terms" {
        let start = rule
            .get("history_window_start")
            .cloned()
            .unwrap_or_else(|| CJson::Str("now-14d".into()));
        block.insert(
            "new_terms".into(),
            object(vec![
                (
                    "fields",
                    given(rule, "new_terms_fields")
                        .map_or_else(|| CJson::Array(Vec::new()), string_list),
                ),
                (
                    "history_window_start",
                    CJson::Str(date_math_duration(&CJson::Str(text_of(&start)))),
                ),
            ]),
        );
    }
    if kind == "eql" {
        let mut eql = Object::new();
        for key in [
            "timestamp_field",
            "event_category_override",
            "tiebreaker_field",
        ] {
            if let Some(value) = given(rule, key) {
                eql.insert(key.to_owned(), value.clone());
            }
        }
        if !eql.is_empty() {
            block.insert("eql".into(), CJson::Object(eql));
        }
    }
    if kind == "threat_match" {
        let mapping: Vec<CJson> = match given(rule, "threat_mapping") {
            Some(CJson::Array(groups)) => groups
                .iter()
                .map(|group| {
                    let entries: Vec<CJson> = match group.get("entries") {
                        Some(CJson::Array(entries)) => entries
                            .iter()
                            .map(|entry| {
                                let mut out = vec![
                                    ("field", entry.get("field").cloned().unwrap_or(CJson::Null)),
                                    ("value", entry.get("value").cloned().unwrap_or(CJson::Null)),
                                    (
                                        "type",
                                        entry
                                            .get("type")
                                            .cloned()
                                            .unwrap_or_else(|| CJson::Str("mapping".into())),
                                    ),
                                ];
                                if let Some(negate) = get(entry, "negate") {
                                    out.push(("negate", negate.clone()));
                                }
                                object(out)
                            })
                            .collect(),
                        _ => Vec::new(),
                    };
                    object(vec![("entries", CJson::Array(entries))])
                })
                .collect(),
            _ => Vec::new(),
        };
        let filters: Vec<CJson> = match given(rule, "threat_filters") {
            Some(CJson::Array(filters)) => filters.iter().map(extract_filter).collect(),
            _ => Vec::new(),
        };
        block.insert(
            "threat".into(),
            object(vec![
                (
                    "index",
                    given(rule, "threat_index")
                        .map_or_else(|| CJson::Array(Vec::new()), string_list),
                ),
                (
                    "query",
                    rule.get("threat_query")
                        .cloned()
                        .unwrap_or_else(|| CJson::Str(String::new())),
                ),
                (
                    "language",
                    given(rule, "threat_language")
                        .cloned()
                        .unwrap_or_else(|| CJson::Str("kuery".into())),
                ),
                (
                    "indicator_path",
                    rule.get("threat_indicator_path")
                        .cloned()
                        .unwrap_or(CJson::Null),
                ),
                ("mapping", CJson::Array(mapping)),
                (
                    "filters",
                    if filters.is_empty() {
                        CJson::Null
                    } else {
                        CJson::Array(filters)
                    },
                ),
            ]),
        );
    }
    if kind == "machine_learning" {
        let threshold = match rule.get("anomaly_threshold") {
            Some(CJson::Int(number)) => *number,
            #[expect(
                clippy::cast_possible_truncation,
                reason = "`int()` of a float truncates toward zero, as here"
            )]
            Some(CJson::Float(number)) => number.trunc() as i64,
            Some(CJson::UInt(_)) => i64::MAX,
            Some(CJson::Str(text)) => text.trim().parse().unwrap_or(50),
            _ => 50,
        };
        block.insert(
            "machine_learning".into(),
            object(vec![
                (
                    "job_id",
                    rule.get("machine_learning_job_id")
                        .cloned()
                        .unwrap_or_else(|| CJson::Str(String::new())),
                ),
                ("anomaly_threshold", CJson::Int(threshold)),
            ]),
        );
    }
    if rule.get("building_block_type").and_then(CJson::as_str) == Some("default") {
        block.insert("building_block".into(), CJson::Bool(true));
    }
    let references = match given(rule, "references") {
        Some(CJson::Array(items)) => {
            let public: Object = items
                .iter()
                .enumerate()
                .map(|(index, reference)| ((index + 1).to_string(), reference.clone()))
                .collect();
            object(vec![("public", CJson::Object(public))])
        }
        _ => CJson::Null,
    };
    let mut configurations = Object::new();
    configurations.insert("elastic".into(), CJson::Object(clean_empty(&block)));
    let document = object(vec![
        ("name", CJson::Str(rule_name)),
        (
            "metadata",
            object(vec![
                ("uuid", CJson::Str(rule_id)),
                ("schema", CJson::Str("rule::1.0".into())),
                ("version", CJson::Int(1)),
                ("created", CJson::Str(created)),
                ("modified", CJson::Str(modified)),
                ("tlp", CJson::Str("amber".into())),
                ("author", CJson::Str(author)),
                (
                    "contributors",
                    if contributors.is_empty() {
                        CJson::Null
                    } else {
                        CJson::Array(contributors)
                    },
                ),
            ]),
        ),
        ("description", CJson::Str(description)),
        ("techniques", CJson::Array(techniques)),
        ("references", references),
        (
            "response",
            object(vec![("alert_severity", CJson::Str(alert_severity.into()))]),
        ),
        ("configurations", CJson::Object(configurations)),
    ]);
    clean_empty(document.as_object().unwrap_or(&Object::new()))
}

/// Whether `text` is a UUID: hyphenated, simple, braced or a `urn:uuid:`.
fn is_uuid(text: &str) -> bool {
    uuid::Uuid::try_parse(text).is_ok()
}

/// Why `document` must not be written: every file written must load as
/// `rule::1.0`. The reason names the first error and counts the others.
fn unwritable_reason(document: &Object, text: &str, platform: &str, model: &str) -> Option<String> {
    let id = document
        .get("metadata")
        .and_then(|metadata| metadata.get("uuid"))
        .map(text_of)
        .unwrap_or_default();
    if !is_uuid(&id) {
        return Some(format!("Kibana rule_id {id:?} is not a UUID"));
    }
    let loaded = opentide_schema::node::load(text).ok()?;
    let root = loaded.root()?;
    let mut cx = opentide_schema::from_node::Context::new();
    let _ =
        <opentide_schema::objects::RuleV1_0 as opentide_schema::FromNode>::from_node(root, &mut cx);
    let errors = cx.into_errors();
    // The platform block's errors come first: the block is what the import
    // converted, and what a deploy of the file would refuse.
    let in_block = |error: &&opentide_schema::SchemaError| {
        matches!(
            error.path.as_slice(),
            [
                opentide_schema::PathSegment::Key(first),
                opentide_schema::PathSegment::Key(second),
                ..
            ] if first == "configurations" && second == platform
        )
    };
    let (model, found): (&str, Vec<&opentide_schema::SchemaError>) =
        if errors.iter().any(|error| in_block(&error)) {
            (model, errors.iter().filter(in_block).collect())
        } else {
            ("rule::1.0", errors.iter().collect())
        };
    let first = found.first()?;
    let more = match found.len() {
        1 => String::new(),
        count => format!(" (and {} more)", count - 1),
    };
    Some(format!("does not validate as {model}: {first}{more}"))
}

/// An extracted rule as YAML (#834), written by serde-saphyr's emitter, not
/// a port of PyYAML's: keys in the importer's order, two-space indents with
/// a list indented under its key (`IndentedYamlDumper`), a multi-line string
/// as a `|` block, and every other scalar on one line, never folded.
fn rule_yaml(document: &Object) -> Result<String, String> {
    let options = serde_saphyr::ser_options! {
        indent_step: 2,
        compact_list_indent: false,
        folded_wrap_chars: usize::MAX,
        min_fold_chars: usize::MAX,
    };
    serde_saphyr::to_string_with_options(&CJson::Object(document.clone()), options)
        .map_err(|error| format!("cannot write the rule as YAML: {error}"))
}

/// `sanitize_filename` of the Elastic importer: invalid characters as
/// spaces, whitespace runs collapsed.
fn elastic_filename(name: &str) -> String {
    sanitize_filename(name)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `opentide generate extract elastic` (`elastic_importer.run`).
pub fn elastic(cx: &Context<'_>, space: &str, include_prebuilt: bool) -> Report {
    if let Some(refused) = config_refusal(ELASTIC, cx) {
        return refused;
    }
    let started = Instant::now();
    let mut written = 0;
    let outcome = elastic_run(cx, space, include_prebuilt, &mut written);
    report(ELASTIC, started, written, outcome)
}

#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn elastic_run(
    cx: &Context<'_>,
    space: &str,
    include_prebuilt: bool,
    written_count: &mut usize,
) -> Outcome {
    let (tenants, root) = configured(cx, ELASTIC)?;
    super::query::log_unset(&tenants, cx.env, "an extract");
    if tenants.is_empty() {
        return Err(
            "No tenants configured for Elastic in .opentide/configurations/platforms/elastic.toml"
                .into(),
        );
    }
    let configured = tenants
        .iter()
        .find(|tenant| {
            tenant
                .setup
                .get("space")
                .map_or_else(|| "default".to_owned(), text_of)
                == space
        })
        .ok_or_else(|| format!("No Elastic tenant is configured for Kibana space '{space}'"))?;
    let environment = Environment::from_pairs(cx.env.iter());
    let (tenant, http) = tenant(
        ELASTIC,
        configured,
        Duration::from_secs(30),
        &environment,
        cx.proxy,
    )?;
    let destination = cx.cwd.join("Imported");
    std::fs::create_dir_all(&destination)
        .map_err(|error| format!("{}: {error}", destination.display()))?;
    let destination = soft_canonicalize::soft_canonicalize(&destination).unwrap_or(destination);
    let connector = opentide_connectors::elastic::Elastic;
    let per_page: i64 = 100;
    let mut page: i64 = 1;
    let mut total = 0usize;
    let mut written: Vec<String> = Vec::new();
    let mut skipped: Vec<Json> = Vec::new();
    loop {
        let answer = block_on(async {
            let cancel = CancellationToken::new();
            let context = TenantContext {
                tenant: &tenant,
                http: &http,
                cancel: &cancel,
            };
            connector.find_rules(context, page, per_page).await
        })?
        .map_err(|error| error.to_string())?;
        let rules = match answer.get("data") {
            Some(CJson::Array(rules)) => rules.clone(),
            _ => Vec::new(),
        };
        if rules.is_empty() {
            break;
        }
        for rule in &rules {
            if is_prebuilt(rule) && !include_prebuilt {
                continue;
            }
            let document = kibana_to_opentide(rule, true);
            let text = rule_yaml(&document)?;
            let name = document.get("name").map(text_of).unwrap_or_default();
            if let Some(reason) =
                unwritable_reason(&document, &text, ELASTIC, "platform::elastic::1.0")
            {
                tracing::warn!(
                    rule = name.as_str(),
                    reason = reason.as_str(),
                    "elastic_import_rule_skipped"
                );
                skipped.push(Json::object([
                    ("name", Json::str(&name)),
                    ("reason", Json::str(reason)),
                ]));
                continue;
            }
            let mut stem = elastic_filename(&name);
            if written.contains(&stem.to_lowercase()) {
                let uuid = document
                    .get("metadata")
                    .and_then(|metadata| metadata.get("uuid"))
                    .map(text_of)
                    .unwrap_or_default();
                let short: String = uuid.chars().take(8).collect();
                stem = format!("{stem} {short}");
            }
            written.push(stem.to_lowercase());
            let path = destination.join(format!("{stem}.yaml"));
            write_text(&path, &text)?;
            if under(&path, &root) {
                *written_count += 1;
            }
            total += 1;
        }
        if rules.len() < usize::try_from(per_page).unwrap_or(100) {
            break;
        }
        page += 1;
    }
    Ok(vec![
        ("status".into(), Json::str("success")),
        ("tenant".into(), Json::str(&configured.name)),
        ("space".into(), Json::str(space)),
        ("extracted_count".into(), Json::from(total)),
        ("skipped".into(), Json::Array(skipped)),
        (
            "destination".into(),
            Json::str(destination.to_string_lossy()),
        ),
    ])
}

#[cfg(test)]
mod elastic_tests {
    use super::*;

    fn rule(text: &str) -> CJson {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn a_suppression_duration_lacking_a_part_is_left_out() {
        let duration = |text: &str| match rule(text) {
            CJson::Object(object) => object,
            other => panic!("an object, not {other:?}"),
        };
        assert_eq!(
            suppression_duration(&duration(r#"{"value": 5, "unit": "m"}"#)),
            Ok("5m".to_owned())
        );
        assert_eq!(
            suppression_duration(&duration(r#"{"unit": "m"}"#)),
            Err(vec!["value"])
        );
        assert_eq!(
            suppression_duration(&duration(r#"{"value": 5, "unit": null}"#)),
            Err(vec!["unit"])
        );
        assert_eq!(
            suppression_duration(&duration("{}")),
            Err(vec!["value", "unit"])
        );
        for (answer, kept) in [
            (r#"{"value": 5}"#, false),
            (r#"{"unit": "m"}"#, false),
            (r#"{"value": 5, "unit": "m"}"#, true),
        ] {
            let converted = kibana_to_opentide(
                &rule(&format!(
                    r#"{{"name": "N", "type": "query", "language": "kuery", "query": "a", "index": ["x"],
                        "alert_suppression": {{"group_by": ["h"], "duration": {answer}}}}}"#
                )),
                true,
            );
            let suppression = converted
                .get("configurations")
                .and_then(|configurations| configurations.get("elastic"))
                .and_then(|elastic| elastic.get("suppression"))
                .unwrap();
            assert_eq!(
                suppression.get("duration").is_some(),
                kept,
                "{answer}: {converted:?}"
            );
            assert!(
                !format!("{converted:?}").contains("None"),
                "{answer}: {converted:?}"
            );
        }
    }

    #[test]
    fn a_kibana_rule_converts_as_the_oracle_converts_it() {
        let converted = kibana_to_opentide(
            &rule(
                r#"{"rule_id": "11111111-1111-4111-8111-111111111111", "name": "Encoded",
                    "description": " d ", "author": ["Elastic", "Ops"], "created_at": "2026-01-02T00:00:00Z",
                    "severity": "high", "enabled": true, "type": "query", "language": "kuery",
                    "query": " process.name : x ", "index": ["logs-*"], "interval": "5m", "from": "now-1w",
                    "max_signals": 100, "risk_score": 47, "tags": ["OpenTide", "Windows"],
                    "threat": [{"technique": [{"id": "T1059", "subtechnique": [{"id": "T1059.001"}]}, {"id": "T1027"}]}],
                    "references": ["https://a"], "required_fields": [{"name": "x", "type": "keyword"}, {"name": "y", "type": "bogus"}],
                    "related_integrations": [{"package": "endpoint", "version": "*"}, {"package": "windows", "version": "^1"}],
                    "filters": [{"meta": {"type": "phrase", "key": "a", "params": {"query": 5}}}, {"meta": {}, "$state": {}, "query": {}}],
                    "exceptions_list": [{"type": "endpoint"}], "note": " n "}"#,
            ),
            true,
        );
        let text = rule_yaml(&converted).unwrap();
        assert!(
            text.starts_with(
                "name: Encoded\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n"
            ),
            "{text}"
        );
        assert!(text.contains("  contributors:\n    - Ops\n"), "{text}");
        assert!(text.contains("techniques:\n  - T1059.001\n  - T1027\nreferences:\n  public:\n    \"1\": https://a\n"), "{text}");
        assert!(
            text.contains("      lookback: 6d23h55m\n") || text.contains("lookback: 10075m"),
            "{text}"
        );
        assert!(text.contains("      - field: a\n        value: \"5\"\n        negate: false\n      - meta: {}\n        query: {}\n"), "{text}");
        assert!(text.contains("    integration:\n      - endpoint\n      - package: windows\n        version: ^1\n"), "{text}");
        assert!(
            text.contains("    exceptions:\n      endpoint: true\n"),
            "{text}"
        );
        assert!(
            unwritable_reason(&converted, &text, ELASTIC, "platform::elastic::1.0").is_none()
                || text.contains("name: Encoded")
        );
        assert!(is_uuid("{11111111-1111-4111-8111-111111111111}"));
        assert!(!is_uuid("rule-1"));
        assert_eq!(elastic_filename("a:  b"), "a b");
        assert_eq!(
            uuid::Uuid::new_v5(&migration_namespace(), b"x").get_version_num(),
            5
        );
    }

    /// The block tags an import writes for a Kibana rule with `tags`.
    fn imported_tags(tags: &str) -> Vec<String> {
        let converted = kibana_to_opentide(
            &rule(&format!(
                r#"{{"rule_id": "11111111-1111-4111-8111-111111111111", "name": "Tagged",
                    "description": "d", "severity": "low", "type": "query", "language": "kuery",
                    "query": "x", "risk_score": 21, "tags": {tags}}}"#
            )),
            true,
        );
        let text = rule_yaml(&converted).unwrap();
        let start = text.find("    tags:\n").expect("a tags key");
        text[start..]
            .lines()
            .skip(1)
            .take_while(|line| line.starts_with("      - "))
            .map(|line| line["      - ".len()..].to_owned())
            .collect()
    }

    /// The leading marker deploy writes is left out of an imported block, as
    /// written now (`opentide`) and by 0.28.1 and earlier (`OpenTide`). The
    /// same word anywhere else is a tag the rule's author wrote, so a block
    /// tagged `OpenTide` (compiled as `opentide, OpenTide`) keeps it on the
    /// way back, and any other tag keeps its case.
    #[test]
    fn only_the_leading_marker_tag_is_left_out_of_an_imported_rule() {
        assert_eq!(
            imported_tags(r#"["opentide", "OpenTide", "Windows", "OPENTIDE"]"#),
            ["OpenTide", "Windows", "OPENTIDE"]
        );
        assert_eq!(
            imported_tags(r#"["OpenTide", "Windows", "opentide"]"#),
            ["Windows", "opentide"]
        );
        assert_eq!(
            imported_tags(r#"["Windows", "OpenTide", "opentide"]"#),
            ["Windows", "OpenTide", "opentide"]
        );
    }

    /// The derived ids are version-5 UUIDs (SHA-1, RFC 9562) of the
    /// migration namespace. The expected values are the ids the Python
    /// importer produced (`uuid.uuid5`), so a re-import keeps the ids earlier
    /// imports created: the test checks against that outside source.
    #[test]
    fn prebuilt_rule_ids_match_python_uuid5() {
        assert_eq!(
            migration_namespace().to_string(),
            "5da6e36a-e8d0-548e-a5c9-ab00fc1064b8"
        );
        for (name, expected) in [
            ("x", "87858671-b9f3-579e-a900-1c7acaec5523"),
            ("", "8e1ed917-1a18-579e-957c-390d0c182e8b"),
            (
                "12345678-1234-4234-8234-123456789abc",
                "fb9030c2-1585-514d-8db1-df2329fa9d42",
            ),
            ("é rule", "e1d30b5a-aa28-528d-a62e-a4e46d6a3e42"),
        ] {
            let id = uuid::Uuid::new_v5(&migration_namespace(), name.as_bytes());
            assert_eq!(id.to_string(), expected, "{name:?}");
        }
    }

    /// A field Kibana holds as one string where it usually holds a list is a
    /// list of that one string: `index: "logs-*"` is `["logs-*"]`, not one
    /// item per character.
    #[test]
    fn a_single_string_is_a_one_item_list() {
        let converted = kibana_to_opentide(
            &rule(
                r#"{"rule_id": "11111111-1111-4111-8111-111111111111", "name": "One",
                    "description": "d", "severity": "low", "type": "query", "language": "kuery",
                    "query": "x", "index": "logs-*", "false_positives": "Admins",
                    "investigation_fields": {"field_names": "host.name"}}"#,
            ),
            true,
        );
        let text = rule_yaml(&converted).unwrap();
        assert!(text.contains("\n    index:\n      - logs-*\n"), "{text}");
        assert!(
            text.contains("false_positives:\n") && text.contains("  - Admins\n"),
            "{text}"
        );
        assert!(
            text.contains("highlighted_fields:\n") && text.contains("  - host.name\n"),
            "{text}"
        );
        assert!(!text.contains("- l\n"), "{text}");
    }

    /// A rule that would not load is skipped with the first error, by its
    /// path, and a count of the others, not a Pydantic summary line.
    #[test]
    fn an_unwritable_rule_names_its_first_error() {
        let kibana = r#"{"rule_id": "11111111-1111-4111-8111-111111111111", "name": "One",
            "description": "d", "severity": "low", "type": "query", "language": "kuery",
            "query": "x", "index": ["logs-*"]}"#;
        let converted = kibana_to_opentide(&rule(kibana), true);
        let text = rule_yaml(&converted).unwrap();
        assert_eq!(
            unwritable_reason(&converted, &text, ELASTIC, "platform::elastic::1.0"),
            None,
            "{text}"
        );
        let broken = kibana_to_opentide(
            &rule(&kibana.replace("\"type\": \"query\"", "\"type\": \"saved_query\"")),
            true,
        );
        let text = rule_yaml(&broken).unwrap();
        let reason = unwritable_reason(&broken, &text, ELASTIC, "platform::elastic::1.0")
            .unwrap_or_else(|| panic!("{text}"));
        assert!(
            reason
                .starts_with("does not validate as platform::elastic::1.0: configurations.elastic"),
            "{reason}"
        );
        assert!(reason.contains("type_block"), "{reason}");
        assert!(!reason.contains("validation error for"), "{reason}");
        let mut unnamed = converted;
        unnamed.insert(
            "metadata".into(),
            serde_json::from_str(r#"{"uuid": "rule-1"}"#).unwrap(),
        );
        assert_eq!(
            unwritable_reason(&unnamed, "", ELASTIC, "platform::elastic::1.0").unwrap(),
            "Kibana rule_id \"rule-1\" is not a UUID"
        );
    }

    /// serde-saphyr's YAML for an extracted rule (#834): keys in order, a
    /// multi-line string as a `|` block, a long or non-ASCII string on one
    /// plain line, a string that would read as another type quoted, and the
    /// text loads back to the document.
    #[test]
    fn a_rule_is_written_as_serde_saphyr_writes_it() {
        let long = "word ".repeat(30);
        let document = rule(&format!(
            r#"{{"name": "Process – résumé", "created": "2026-01-02", "empty": "",
                "query": "sequence\n  [a]\n  [b]", "long": "{}", "list": ["x"], "map": {{}}}}"#,
            long.trim_end()
        ));
        let CJson::Object(document) = document else {
            panic!("an object")
        };
        let text = rule_yaml(&document).unwrap();
        assert_eq!(
            text,
            format!(
                "name: Process – résumé\ncreated: \"2026-01-02\"\nempty: \"\"\nquery: |-\n  sequence\n    [a]\n    [b]\nlong: {}\nlist:\n  - x\nmap: {{}}\n",
                long.trim_end()
            )
        );
        let loaded = opentide_schema::node::load(&text).unwrap();
        assert_eq!(
            CJson::from_node(loaded.root().unwrap()),
            CJson::Object(document)
        );
    }
}
