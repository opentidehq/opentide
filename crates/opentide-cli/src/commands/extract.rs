//! `opentide generate extract defender|elastic` (UC-4.4b, #834;
//! `cli/services/extraction.py`, `extraction/mde_importer.py`,
//! `extraction/elastic_importer.py`): the rules of a tenant pulled through
//! the connectors and written as opentide rule files under `Imported/`.
//!
//! Defender's files are the oracle's template filled in, byte for byte;
//! Elastic's are the rule document written by serde-saphyr's emitter
//! ([`rule_yaml`]): the same data, keys in the importer's order, formatted
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
use opentide_connectors::{ConnectorError, Environment, HttpClient, Tenant};
use tokio_util::sync::CancellationToken;

use super::query::{Configured, http_settings, toml_value};
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

/// Runs `work` on a runtime of its own, off this thread.
fn block_on<T: Send>(work: impl std::future::Future<Output = T> + Send) -> Result<T, String> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| opentide_connectors::runtime::block_on(work))
            .join()
            .map_err(|_| "the import stopped unexpectedly".to_owned())?
    })
}

/// `Imported/<file>` under the working directory, written as `write_text`
/// writes it (the platform's line ends).
fn write_text(path: &Path, text: &str) -> Result<(), String> {
    let text = if cfg!(windows) {
        text.replace('\n', "\r\n")
    } else {
        text.to_owned()
    };
    std::fs::write(path, text.as_bytes()).map_err(|error| {
        format!(
            "{}: {}",
            path.display(),
            super::deploy_state::os_error_text(&error, path)
        )
    })
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

const DEFENDER: &str = "defender_for_endpoint";
/// The importer's logger, as its log lines name it.
const DEFENDER_LOGGER: &str = "opentide.extraction.mde_importer";

const TEMPLATE: &str = "\nname: {name}\n#references:\n  #public:\n    #1: \n  #internal:\n    #a: \n\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\n  version: 1\n  created: {created}\n  modified: {modified}\n  tlp: amber+strict\n  author: {author}\n  #contributors:\n    #-\n\ndescription: |\n{description}\n#detection_model: \n\nresponse:\n  alert_severity: {alert_severity}\n  #playbook: https://\n  #responders: \n  #procedure:\n\nconfigurations:\n  defender_for_endpoint: \n    schema: platform::defender_for_endpoint::1.0\n    status: {status}\n    {contributors}\n    tenants:\n      - {tenants}\n    #flags:\n      #-\n    \n    scheduling: {schedule}\n    \n    alert:\n      #title: \n      category: {category}{techniques}\n      #severity: \n      {alert_recommendation}\n    \n    {impacted_entities_flag}impacted_entities:\n      {impacted_device}\n      #mailbox: \n      {impacted_user} \n    \n    #actions:\n    \n      #devices:\n        #isolate_device: \n        #collect_investigation_package: true\n        #run_antivirus_scan: true\n        #initiate_investigation: true\n        #restrict_app_execution: true\n    \n      #files:\n        #allow_block:\n          #action: \n          #column: \n          #groups:\n            #selection: \n            #device_groups:\n              #-\n        #quarantine_file: \n    \n    scope:\n      selection: All\n      #device_groups:\n        #-\n    \n    query: |\n{query}\n";
const NO_CONTRIBUTORS_TEMPLATE: &str = "\n    #contributors:\n      #-\n";
const CONTRIBUTORS_TEMPLATE: &str = "\n    contributors:\n      - {contributor}\n";
const NO_RECOMMENDATION_TEMPLATE: &str = "\n      #recommendation: |\n        #Type Here\n";
const RECOMMENDATION_TEMPLATE: &str = "\n      recommendation: |\n{recommendation}\n";
const TECHNIQUES_TEMPLATE: &str = "\n      techniques:\n        {techniques_list}\n";

/// `str.format` of `template` with `values`, in one pass: a value is never
/// read as a field.
pub(crate) fn format(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                match values.iter().find(|(key, _)| *key == name) {
                    Some((_, value)) => out.push_str(value),
                    None => {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Python's `str.isspace` set, as `strip` uses it.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub(crate) fn strip(text: &str) -> &str {
    text.trim_matches(py_space)
}

/// `str.splitlines()`.
pub(crate) fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        if !matches!(
            c,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            continue;
        }
        lines.push(&text[start..index]);
        let mut end = index + c.len_utf8();
        if c == '\r'
            && let Some((next, '\n')) = chars.peek().copied()
        {
            chars.next();
            end = next + 1;
        }
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// Each non-blank line stripped and indented (`fix_multiline`).
fn fix_multiline(text: &str, indentation: usize) -> String {
    splitlines(text)
        .into_iter()
        .filter(|line| !strip(line).is_empty())
        .map(|line| format!("{}{}", " ".repeat(indentation), strip(line)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A space before each capital but the first character
/// (`add_space_before_uppercase`).
fn space_before_uppercase(text: &str) -> String {
    let mut out = String::new();
    for (index, c) in text.chars().enumerate() {
        if c.is_uppercase() && index > 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// The characters a file name cannot hold, as spaces (`sanitize_filename`).
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if "<>:\"/\\|?*".contains(c) { ' ' } else { c })
        .collect()
}

/// `str.title()`.
fn title(text: &str) -> String {
    let mut out = String::new();
    let mut previous_cased = false;
    for c in text.chars() {
        if c.is_alphabetic() {
            if previous_cased {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            previous_cased = true;
        } else {
            out.push(c);
            previous_cased = false;
        }
    }
    out
}

/// `json.dumps(text, ensure_ascii=False)`.
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

/// What a missing key raises in the importer: `KeyError: 'name'`.
fn key_error(key: &str) -> String {
    format!("KeyError: '{key}'")
}

fn text_at<'j>(rule: &'j CJson, key: &str) -> Result<&'j str, String> {
    match rule.get(key) {
        Some(CJson::Str(text)) => Ok(text),
        Some(_) => Err(format!("AttributeError: '{key}' is not a string")),
        None => Err(key_error(key)),
    }
}

/// The file name and YAML of one custom detection, which targets
/// `tenant_names` (`_render_rule`).
#[expect(
    clippy::too_many_lines,
    reason = "the oracle's `_render_rule`, field by field, in one place"
)]
fn render_rule(rule: &CJson, tenant_names: &[String]) -> Result<(String, String), String> {
    let name = text_at(rule, "displayName")?;
    let uuid = text_at(rule, "detectorId")?;
    let created = text_at(rule, "createdDateTime")?
        .split('T')
        .next()
        .unwrap_or_default();
    let modified = text_at(rule, "lastModifiedDateTime")?
        .split('T')
        .next()
        .unwrap_or_default();
    let action = rule
        .get("detectionAction")
        .ok_or_else(|| key_error("detectionAction"))?;
    let empty = CJson::Object(Object::new());
    let template = action.get("alertTemplate").unwrap_or(&empty);
    let field = |key: &str| template.get(key).filter(|value| !value.is_null());
    let severity = field("severity")
        .and_then(CJson::as_str)
        .ok_or("AttributeError: 'NoneType' object has no attribute 'title'")?;
    let author = text_at(rule, "createdBy")?;
    let mut description = field("description")
        .and_then(CJson::as_str)
        .ok_or("AttributeError: 'NoneType' object has no attribute 'splitlines'")?
        .to_owned();
    let period = rule
        .get("schedule")
        .ok_or_else(|| key_error("schedule"))?
        .get("period")
        .ok_or_else(|| key_error("period"))?;
    let period = match period {
        CJson::Str(text) => text.clone(),
        other => opentide_connectors::python::python_str(other),
    };
    let schedule = if period == "0" {
        "NRT".to_owned()
    } else {
        period
    };
    let category = space_before_uppercase(
        field("category")
            .and_then(CJson::as_str)
            .ok_or("TypeError: 'NoneType' object is not iterable")?,
    );
    let query = rule
        .get("queryCondition")
        .ok_or_else(|| key_error("queryCondition"))?
        .get("queryText")
        .and_then(CJson::as_str)
        .ok_or("AttributeError: 'NoneType' object has no attribute 'splitlines'")?;
    let status = if rule.get("isEnabled").is_some_and(CJson::truthy) {
        "PRODUCTION"
    } else {
        "DISABLED"
    };
    let modified_by = rule
        .get("lastModifiedBy")
        .ok_or_else(|| key_error("lastModifiedBy"))?;
    let contributors = if modified_by.as_str() == Some(author) {
        strip(NO_CONTRIBUTORS_TEMPLATE).to_owned()
    } else {
        let contributor = match modified_by {
            CJson::Str(text) => text.clone(),
            other => opentide_connectors::python::python_str(other),
        };
        strip(&format(
            CONTRIBUTORS_TEMPLATE,
            &[("contributor", &contributor)],
        ))
        .to_owned()
    };
    let mut techniques = String::new();
    if let Some(CJson::Array(items)) = field("mitreTechniques")
        && !items.is_empty()
    {
        let names: Vec<String> = items
            .iter()
            .map(|item| match item {
                CJson::Str(text) => text.clone(),
                other => opentide_connectors::python::python_str(other),
            })
            .collect();
        let list = format!("- {}", names.join("\n        - "));
        format(TECHNIQUES_TEMPLATE, &[("techniques_list", &list)])
            .trim_end_matches(py_space)
            .clone_into(&mut techniques);
    }
    let alert_recommendation = match field("recommendedActions").filter(|value| value.truthy()) {
        None => strip(NO_RECOMMENDATION_TEMPLATE).to_owned(),
        Some(recommended) => {
            let recommended = recommended
                .as_str()
                .ok_or("TypeError: can only concatenate str (not \"list\") to str")?;
            description.push_str("\n\n---\nRecommended Actions : ");
            description.push_str(recommended);
            strip(&format(
                RECOMMENDATION_TEMPLATE,
                &[("recommendation", &fix_multiline(recommended, 8))],
            ))
            .to_owned()
        }
    };
    let mut impacted_device = "#device:".to_owned();
    let mut impacted_user = "#user:".to_owned();
    let mut impacted_entities_flag = "#";
    let assets = match template.get("impactedAssets") {
        Some(CJson::Array(items)) => items,
        Some(_) => return Err("TypeError: 'NoneType' object is not iterable".into()),
        None => return Err(key_error("impactedAssets")),
    };
    for asset in assets {
        let kind = asset
            .get("@odata.type")
            .and_then(CJson::as_str)
            .ok_or_else(|| key_error("@odata.type"))?;
        let identifier = || {
            asset
                .get("identifier")
                .and_then(CJson::as_str)
                .ok_or_else(|| key_error("identifier"))
        };
        if kind.ends_with("impactedDeviceAsset") {
            impacted_device = format!("device: {}", capitalised(identifier()?));
            impacted_entities_flag = "";
        }
        if kind.ends_with("impactedUserAsset") {
            impacted_user = format!("user: {}", capitalised(identifier()?));
            impacted_entities_flag = "";
        }
    }
    let tenants = tenant_names
        .iter()
        .map(|name| json_string(name))
        .collect::<Vec<_>>()
        .join("\n      - ");
    let body = format(
        TEMPLATE,
        &[
            ("name", &json_string(name)),
            ("tenants", &tenants),
            ("uuid", uuid),
            ("created", created),
            ("modified", modified),
            ("alert_severity", &title(severity)),
            ("alert_recommendation", &alert_recommendation),
            ("impacted_device", &impacted_device),
            ("impacted_user", &impacted_user),
            ("impacted_entities_flag", impacted_entities_flag),
            ("author", author),
            ("contributors", &contributors),
            ("description", &fix_multiline(&description, 2)),
            ("schedule", &schedule),
            ("category", &category),
            ("techniques", &techniques),
            ("query", &fix_multiline(query, 6)),
            ("status", status),
        ],
    );
    Ok((sanitize_filename(name), strip(&body).to_owned()))
}

/// What makes two tenants' copies of one detection the same rule (`_content`).
fn content(rule: &CJson) -> [Option<&CJson>; 5] {
    [
        rule.get("displayName"),
        rule.get("isEnabled"),
        rule.get("schedule"),
        rule.get("queryCondition"),
        rule.get("detectionAction"),
    ]
}

/// `opentide generate extract defender` (`_import_defender_rules`).
pub fn defender(cx: &Context<'_>) -> Report {
    let started = Instant::now();
    let mut written = 0;
    let outcome = defender_run(cx, &mut written);
    report("defender", started, written, outcome)
}

fn defender_run(cx: &Context<'_>, written_count: &mut usize) -> Outcome {
    let (tenants, root) = configured(cx, DEFENDER)?;
    super::query::log_unset(&tenants, cx.env);
    if tenants.is_empty() {
        tracing::error!(
            detail = "You must first have Defender for Endpoint tenants configured to initiate the import",
            advice = "run 'opentide setup platforms --defender-for-endpoint'",
            logger = DEFENDER_LOGGER,
            critical = true,
            "defender_tenants_not_configured"
        );
        return Err("No Defender for Endpoint tenants are configured".into());
    }
    let environment = Environment::from_pairs(cx.env.iter());
    let destination = cx.cwd.join("Imported");
    std::fs::create_dir_all(&destination)
        .map_err(|error| format!("{}: {error}", destination.display()))?;
    let connector = opentide_connectors::defender::Defender::new();
    let mut listed: Vec<(String, Vec<(String, CJson)>)> = Vec::new();
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
            opentide_connectors::defender::DefenderError::Authentication { .. } => {
                tracing::error!(
                    detail = format!("Cannot authenticate against {}", configured.name).as_str(),
                    logger = "opentide.platforms.defender_for_endpoint.client",
                    critical = true,
                    "fatal_error"
                );
                "TenantConnectionError: Cannot authenticate with the tenant configuration"
                    .to_owned()
            }
            opentide_connectors::defender::DefenderError::Refused { message, .. } => message,
            opentide_connectors::defender::DefenderError::Connector(error) => {
                connector_message(&error)
            }
        })?;
        for rule in rules {
            let detector = text_at(&rule, "detectorId")?.to_owned();
            let id = rule.get("id").ok_or_else(|| key_error("id"))?;
            let external = match id {
                CJson::Int(number) => super::deploy_state::ExternalId::Int(*number),
                CJson::Str(text) => super::deploy_state::ExternalId::Text(text.clone()),
                other => super::deploy_state::ExternalId::Text(
                    opentide_connectors::python::python_str(other),
                ),
            };
            record_external_id(&root, &detector, &configured.name, &external)?;
            match listed.iter_mut().find(|(seen, _)| *seen == detector) {
                Some((_, copies)) => copies.push((configured.name.clone(), rule)),
                None => listed.push((detector, vec![(configured.name.clone(), rule)])),
            }
        }
    }
    let mut written: Vec<String> = Vec::new();
    for (detector, copies) in &listed {
        let names: Vec<String> = copies.iter().map(|(name, _)| name.clone()).collect();
        let first = &copies[0].1;
        if copies[1..]
            .iter()
            .any(|(_, rule)| content(rule) != content(first))
        {
            let shown = first
                .get("displayName")
                .map(opentide_connectors::python::python_str)
                .unwrap_or_default();
            tracing::warn!(
                rule = shown.as_str(),
                uuid = detector.as_str(),
                logger = DEFENDER_LOGGER,
                detail = format!(
                    "Imported from {}; the copies in {} differ",
                    names[0],
                    names[1..].join(", ")
                )
                .as_str(),
                "defender_import_tenants_differ"
            );
        }
        let (mut filename, body) = render_rule(first, &names)?;
        if written.contains(&filename.to_lowercase()) {
            let short: String = detector.chars().take(8).collect();
            filename = format!("{filename} {short}");
        }
        written.push(filename.to_lowercase());
        let path = destination.join(format!("{filename}.yaml"));
        write_text(&path, &body)?;
        if under(&path, &root) {
            *written_count += 1;
        }
    }
    Ok(Vec::new())
}

/// Binds the tenant's Graph id in the rule's deployment state
/// (`record_external_id`).
fn record_external_id(
    workspace: &Path,
    uuid: &str,
    tenant: &str,
    id: &super::deploy_state::ExternalId,
) -> Result<(), String> {
    let mut shard = super::deploy_state::Shard::load(workspace, uuid)
        .map_err(|error| format!("ValueError: {}", error.message))?;
    shard
        .set(DEFENDER, tenant, id)
        .map_err(|error| format!("ValueError: {}", error.message))?;
    shard.save().map_err(|error| format!("OSError: {error}"))
}

/// A transport failure as the importer's exception reads.
fn connector_message(error: &ConnectorError) -> String {
    let text = error.to_string();
    match error {
        ConnectorError::Timeout { .. } => format!("ReadTimeout: {text}"),
        _ => format!("ConnectionError: {text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_fill_in_one_pass() {
        assert_eq!(
            format("a {x} {y} {z}", &[("x", "{y}"), ("y", "2")]),
            "a {y} 2 {z}"
        );
        assert_eq!(format("a {", &[]), "a {");
        assert_eq!(fix_multiline("  a \n\n\tb\r\n", 2), "  a\n  b");
        assert_eq!(
            space_before_uppercase("SuspiciousActivity"),
            "Suspicious Activity"
        );
        assert_eq!(sanitize_filename("a:b/c?"), "a b c ");
        assert_eq!(title("high"), "High");
        assert_eq!(title("hIGH-risk"), "High-Risk");
        assert_eq!(capitalised("deviceId"), "DeviceId");
        assert_eq!(json_string("a\"é"), "\"a\\\"é\"");
    }

    fn rule() -> CJson {
        serde_json::from_str(
            r##"{"id": "201", "displayName": "Encoded: \"x\"", "isEnabled": true,
                "createdBy": "a@x", "lastModifiedBy": "b@x",
                "createdDateTime": "2026-01-02T03:04:05Z", "lastModifiedDateTime": "2026-02-03T00:00:00Z",
                "detectorId": "d1", "queryCondition": {"queryText": "T\n | take 1"},
                "schedule": {"period": "0"},
                "detectionAction": {"alertTemplate": {"severity": "medium",
                  "description": "Desc", "category": "InitialAccess", "recommendedActions": "Do it",
                  "mitreTechniques": ["T1", "T2"], "impactedAssets": [
                  {"@odata.type": "#microsoft.graph.security.impactedUserAsset", "identifier": "accountUpn"}]}}}"##,
        )
        .unwrap()
    }

    #[test]
    fn a_detection_renders_as_the_oracle_writes_it() {
        let (name, body) = render_rule(&rule(), &["lab".into(), "prod".into()]).unwrap();
        assert_eq!(name, "Encoded  \"x\"".replace('"', " "));
        assert!(
            body.starts_with("name: \"Encoded: \\\"x\\\"\"\n#references:"),
            "{body}"
        );
        assert!(body.contains("    contributors:\n      - b@x\n"), "{body}");
        assert!(
            body.contains("      - \"lab\"\n      - \"prod\"\n"),
            "{body}"
        );
        assert!(body.contains("    scheduling: NRT\n"), "{body}");
        assert!(
            body.contains(
                "category: Initial Access\n      techniques:\n        - T1\n        - T2\n"
            ),
            "{body}"
        );
        assert!(
            body.contains("      recommendation: |\n        Do it\n"),
            "{body}"
        );
        assert!(body.contains("    impacted_entities:\n      #device:\n      #mailbox: \n      user: AccountUpn \n"), "{body}");
        assert!(
            body.contains("  Desc\n  ---\n  Recommended Actions : Do it\n"),
            "{body}"
        );
        assert!(
            body.ends_with("    query: |\n      T\n      | take 1"),
            "{body}"
        );
        let mut missing = rule();
        if let CJson::Object(object) = &mut missing {
            object.shift_remove("detectorId");
        }
        assert_eq!(
            render_rule(&missing, &[]).unwrap_err(),
            "KeyError: 'detectorId'"
        );
    }
}

// ----------------------------------------------------------------- Elastic

const ELASTIC: &str = "elastic";
/// The importer's logger, as its log lines name it.
const ELASTIC_LOGGER: &str = "opentide.extraction.elastic_importer";

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

/// `uuid.uuid5(namespace, name)`.
fn uuid5(namespace: &uuid::Uuid, name: &str) -> uuid::Uuid {
    use sha1::Digest as _;
    let mut hasher = sha1::Sha1::new();
    hasher.update(namespace.as_bytes());
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_sha1_bytes(bytes).into_uuid()
}

/// The namespace of the UUIDs derived from prebuilt rules' ids
/// (`OPENTIDE_MIGRATION_NS`).
fn migration_namespace() -> uuid::Uuid {
    uuid5(
        &uuid::Uuid::NAMESPACE_URL,
        "https://opentide.org/ns/elastic-rule-migration",
    )
}

fn get<'j>(rule: &'j CJson, key: &str) -> Option<&'j CJson> {
    rule.get(key).filter(|value| !value.is_null())
}

fn truthy<'j>(rule: &'j CJson, key: &str) -> Option<&'j CJson> {
    rule.get(key).filter(|value| value.truthy())
}

fn py(value: &CJson) -> String {
    opentide_connectors::python::python_str(value)
}

fn object(members: Vec<(&str, CJson)>) -> CJson {
    CJson::Object(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn list(value: &CJson) -> CJson {
    match value {
        CJson::Array(items) => CJson::Array(items.clone()),
        CJson::Str(text) => CJson::Array(text.chars().map(|c| CJson::Str(c.to_string())).collect()),
        CJson::Object(object) => {
            CJson::Array(object.keys().map(|key| CJson::Str(key.clone())).collect())
        }
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
            match truthy(technique, "subtechnique") {
                Some(CJson::Array(subs)) => {
                    for sub in subs {
                        if let Some(id) = truthy(sub, "id")
                            && !found.contains(id)
                        {
                            found.push(id.clone());
                        }
                    }
                }
                _ => {
                    if let Some(id) = truthy(technique, "id")
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
    truthy(rule, "immutable").is_some()
        || rule
            .get("rule_source")
            .and_then(|source| source.get("type"))
            .and_then(CJson::as_str)
            == Some("external")
}

/// Kibana's `now-<n><unit>` as an RFC 0007 duration (`_date_math_duration`).
fn date_math_duration(value: &CJson) -> String {
    let text = py(value);
    let text = strip(&text);
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
        .filter(|meta| meta.truthy())
        .unwrap_or(&empty);
    let query = meta
        .get("params")
        .and_then(|params| params.get("query"))
        .filter(|query| query.truthy());
    if meta.get("type").and_then(CJson::as_str) == Some("phrase")
        && let Some(key) = truthy(meta, "key")
        && let Some(query) = query
        && !meta.get("disabled").is_some_and(CJson::truthy)
    {
        return object(vec![
            ("field", key.clone()),
            ("value", CJson::Str(py(query))),
            (
                "negate",
                CJson::Bool(meta.get("negate").is_some_and(CJson::truthy)),
            ),
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
    let raw_rule_id = truthy(rule, "rule_id")
        .or_else(|| truthy(rule, "id"))
        .map(py)
        .unwrap_or_default();
    let rule_id = if make_custom && prebuilt {
        uuid5(&migration_namespace(), &raw_rule_id).to_string()
    } else {
        raw_rule_id
    };
    let mut rule_name = rule
        .get("name")
        .map_or_else(|| "Unnamed Rule".to_owned(), py);
    if make_custom && prebuilt {
        rule_name.push_str(" (Custom)");
    }
    let description = strip(&rule.get("description").map(py).unwrap_or_default()).to_owned();
    let (author, contributors): (String, Vec<CJson>) = match rule.get("author") {
        Some(CJson::Array(authors)) if !authors.is_empty() => (
            py(&authors[0]),
            authors[1..].iter().map(|a| CJson::Str(py(a))).collect(),
        ),
        Some(CJson::Str(author)) => (author.clone(), Vec::new()),
        None => ("Elastic Security".to_owned(), Vec::new()),
        Some(_) => ("Elastic Security".to_owned(), Vec::new()),
    };
    let created_text = rule.get("created_at").map(py).unwrap_or_default();
    let created = Some(
        created_text
            .split('T')
            .next()
            .unwrap_or_default()
            .to_owned(),
    )
    .filter(|text| !text.is_empty())
    .unwrap_or_else(|| "2026-01-01".to_owned());
    let modified_text = rule.get("updated_at").map(py).unwrap_or_default();
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
        .map_or_else(|| "medium".to_owned(), py)
        .to_lowercase();
    let alert_severity = match severity.as_str() {
        "low" => "Low",
        "high" => "High",
        "critical" => "Critical",
        _ => "Medium",
    };
    let status = if rule.get("enabled").is_some_and(CJson::truthy) {
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
        if let Some(query) = truthy(rule, "query") {
            block.insert("query".into(), CJson::Str(strip(&py(query)).to_owned()));
        }
        if matches!(kind, "query" | "threshold" | "new_terms" | "threat_match")
            && let Some(language @ CJson::Str(text)) = rule.get("language")
            && (text == "kuery" || text == "lucene")
        {
            block.insert("language".into(), language.clone());
        }
    }
    if kind != "esql" && kind != "machine_learning" {
        if let Some(view) = truthy(rule, "data_view_id") {
            block.insert("data_view_id".into(), view.clone());
        } else if let Some(index) = truthy(rule, "index") {
            block.insert("index".into(), list(index));
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
                    rule = rule.get("name").map(py).as_deref().unwrap_or("None"),
                    interval = py(&interval).as_str(),
                    from = py(&from).as_str(),
                    logger = ELASTIC_LOGGER,
                    "elastic_import_window_widened"
                );
            }
            opentide_compile::duration::elastic_format(total.saturating_sub(every))
        }
        _ => {
            tracing::warn!(
                rule = rule.get("name").map(py).as_deref().unwrap_or("None"),
                interval = py(&interval).as_str(),
                from = py(&from).as_str(),
                logger = ELASTIC_LOGGER,
                "elastic_import_schedule_defaulted"
            );
            "1m".to_owned()
        }
    };
    let mut scheduling = Object::new();
    scheduling.insert("interval".into(), interval);
    scheduling.insert("lookback".into(), CJson::Str(lookback));
    if let Some(max) = truthy(rule, "max_signals") {
        scheduling.insert("max_alerts".into(), max.clone());
    }
    block.insert("scheduling".into(), CJson::Object(scheduling));
    if let Some(CJson::Array(mapping)) = truthy(rule, "severity_mapping") {
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
        match truthy(rule, "risk_score_mapping") {
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
    if let Some(suppression) = truthy(rule, "alert_suppression") {
        let mut out = Object::new();
        if kind != "threshold"
            && let Some(group_by) = truthy(suppression, "group_by")
        {
            out.insert("group_by".into(), list(group_by));
        }
        match truthy(suppression, "duration") {
            Some(CJson::Object(duration)) => {
                let part = |key: &str| duration.get(key).map_or_else(|| "None".to_owned(), py);
                out.insert(
                    "duration".into(),
                    CJson::Str(format!("{}{}", part("value"), part("unit"))),
                );
            }
            Some(text @ CJson::Str(_)) => {
                out.insert("duration".into(), text.clone());
            }
            _ => {}
        }
        if let Some(strategy) = truthy(suppression, "missing_fields_strategy") {
            out.insert("missing_fields_strategy".into(), strategy.clone());
        }
        if !out.is_empty() {
            block.insert("suppression".into(), CJson::Object(out));
        }
    }
    if let Some(CJson::Array(filters)) = truthy(rule, "filters")
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
        .filter(|fields| fields.truthy())
        .and_then(|fields| truthy(fields, "field_names"))
    {
        block.insert("highlighted_fields".into(), list(fields));
    }
    if let Some(CJson::Array(required)) = truthy(rule, "required_fields") {
        let mut fields = Vec::new();
        for field in required {
            let Some(name) = truthy(field, "name").filter(|_| field.as_object().is_some()) else {
                continue;
            };
            let kind = field.get("type");
            if !kind
                .and_then(CJson::as_str)
                .is_some_and(|kind| VALID_FIELD_TYPES.contains(&kind))
            {
                tracing::warn!(
                    rule = rule.get("name").map(py).as_deref().unwrap_or("None"),
                    field = py(name).as_str(),
                    r#type = kind.map_or_else(|| "None".to_owned(), py).as_str(),
                    logger = ELASTIC_LOGGER,
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
    if let Some(CJson::Array(integrations)) = truthy(rule, "related_integrations") {
        let mut out = Vec::new();
        for integration in integrations {
            let Some(package) =
                truthy(integration, "package").filter(|_| integration.as_object().is_some())
            else {
                continue;
            };
            let version = truthy(integration, "version")
                .cloned()
                .unwrap_or_else(|| CJson::Str("*".into()));
            let named = truthy(integration, "integration");
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
    if let Some(note) = truthy(rule, "note") {
        guide.insert(
            "investigation".into(),
            CJson::Str(strip(&py(note)).to_owned()),
        );
    }
    if let Some(setup) = truthy(rule, "setup") {
        guide.insert("setup".into(), CJson::Str(strip(&py(setup)).to_owned()));
    }
    if !guide.is_empty() {
        block.insert("guide".into(), CJson::Object(guide));
    }
    if let Some(positives) = truthy(rule, "false_positives") {
        block.insert("false_positives".into(), list(positives));
    }
    if let Some(CJson::Array(tags)) = truthy(rule, "tags") {
        block.insert(
            "tags".into(),
            CJson::Array(
                tags.iter()
                    .filter(|tag| tag.as_str() != Some("OpenTide"))
                    .cloned()
                    .collect(),
            ),
        );
    }
    let mut overrides = Object::new();
    if let Some(name) = truthy(rule, "rule_name_override") {
        overrides.insert("name".into(), name.clone());
    }
    if let Some(timestamp) = truthy(rule, "timestamp_override") {
        overrides.insert("timestamp".into(), timestamp.clone());
    }
    if let Some(disabled) = get(rule, "timestamp_override_fallback_disabled") {
        overrides.insert("disable_fallback".into(), disabled.clone());
    }
    if !overrides.is_empty() {
        block.insert("overrides".into(), CJson::Object(overrides));
    }
    let mut actions = Object::new();
    if let Some(notify) = truthy(rule, "actions") {
        actions.insert("notify".into(), notify.clone());
    }
    if let Some(CJson::Array(responses)) = truthy(rule, "response_actions") {
        let mut out = Vec::new();
        for response in responses {
            let action = response.get("action_type_id").and_then(CJson::as_str);
            let empty = CJson::Object(Object::new());
            let params = response
                .get("params")
                .filter(|p| p.truthy())
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
                            command = command.map_or_else(|| "None".to_owned(), py).as_str(),
                            logger = ELASTIC_LOGGER,
                            "skipping_unsupported_endpoint_response_action"
                        );
                        continue;
                    }
                    let mut item = vec![("endpoint", command.cloned().unwrap_or(CJson::Null))];
                    if let Some(comment) = truthy(params, "comment") {
                        item.push(("comment", comment.clone()));
                    }
                    let config = params
                        .get("config")
                        .filter(|c| c.truthy())
                        .unwrap_or(&empty);
                    if let Some(field) = truthy(config, "field")
                        && !config.get("overwrite").is_some_and(CJson::truthy)
                    {
                        item.push(("field", field.clone()));
                    }
                    out.push(object(item));
                }
                Some(".osquery") => {
                    if params.as_object().is_some() && truthy(params, "query").is_some() {
                        out.push(object(vec![("osquery", params.clone())]));
                    } else {
                        tracing::warn!(
                            rule = rule_name.as_str(),
                            reason =
                                "osquery response action has no inline query (pack/saved query)",
                            logger = ELASTIC_LOGGER,
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
    if let Some(timeline) = truthy(rule, "timeline_id") {
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
    if let Some(CJson::Array(exceptions)) = truthy(rule, "exceptions_list") {
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
        && let Some(threshold) = truthy(rule, "threshold")
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
        let field = match truthy(threshold, "field") {
            Some(CJson::Str(text)) => CJson::Array(vec![CJson::Str(text.clone())]),
            Some(other) => list(other),
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
                    truthy(rule, "new_terms_fields").map_or_else(|| CJson::Array(Vec::new()), list),
                ),
                (
                    "history_window_start",
                    CJson::Str(date_math_duration(&CJson::Str(py(&start)))),
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
            if let Some(value) = truthy(rule, key) {
                eql.insert(key.to_owned(), value.clone());
            }
        }
        if !eql.is_empty() {
            block.insert("eql".into(), CJson::Object(eql));
        }
    }
    if kind == "threat_match" {
        let mapping: Vec<CJson> = match truthy(rule, "threat_mapping") {
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
        let filters: Vec<CJson> = match truthy(rule, "threat_filters") {
            Some(CJson::Array(filters)) => filters.iter().map(extract_filter).collect(),
            _ => Vec::new(),
        };
        block.insert(
            "threat".into(),
            object(vec![
                (
                    "index",
                    truthy(rule, "threat_index").map_or_else(|| CJson::Array(Vec::new()), list),
                ),
                (
                    "query",
                    rule.get("threat_query")
                        .cloned()
                        .unwrap_or_else(|| CJson::Str(String::new())),
                ),
                (
                    "language",
                    truthy(rule, "threat_language")
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
            Some(CJson::Str(text)) => strip(text).parse().unwrap_or(50),
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
    let references = match truthy(rule, "references") {
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

/// Whether `text` reads as a UUID as `uuid.UUID` reads one.
fn python_uuid(text: &str) -> bool {
    let text = text.replace("urn:", "").replace("uuid:", "");
    let text = text.trim_matches(|c| c == '{' || c == '}').replace('-', "");
    text.len() == 32 && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// Why `document` must not be written (`_unwritable_reason`): every file
/// written must load as `rule::1.0`.
fn unwritable_reason(document: &Object, text: &str) -> Option<String> {
    let id = document
        .get("metadata")
        .and_then(|metadata| metadata.get("uuid"))
        .map(py)
        .unwrap_or_default();
    if !python_uuid(&id) {
        return Some(format!(
            "Kibana rule_id {} is not a UUID",
            opentide_connectors::python::python_string_repr(&id)
        ));
    }
    let loaded = opentide_schema::node::load(text).ok()?;
    let root = loaded.root()?;
    let mut cx = opentide_schema::from_node::Context::new();
    let _ =
        <opentide_schema::objects::RuleV1_0 as opentide_schema::FromNode>::from_node(root, &mut cx);
    let errors = cx.into_errors();
    if errors.is_empty() {
        return None;
    }
    // The platform block is validated first, on its own model
    // (`load_platform_config`): its errors are the ones raised.
    let elastic = |error: &&opentide_schema::SchemaError| {
        matches!(
            error.path.as_slice(),
            [
                opentide_schema::PathSegment::Key(first),
                opentide_schema::PathSegment::Key(second),
                ..
            ] if first == "configurations" && second == ELASTIC
        )
    };
    let in_block = errors.iter().filter(elastic).count();
    let (count, model) = if in_block > 0 {
        (in_block, "ElasticConfig")
    } else {
        (errors.len(), "DetectionRule")
    };
    Some(format!(
        "does not validate as platform::elastic::1.0: {count} validation error{} for {model}",
        if count == 1 { "" } else { "s" }
    ))
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
        .map_err(|error| format!("YAMLError: {error}"))
}

/// `sanitize_filename` of the Elastic importer: invalid characters as
/// spaces, whitespace runs collapsed.
fn elastic_filename(name: &str) -> String {
    sanitize_filename(name)
        .split(py_space)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `opentide generate extract elastic` (`elastic_importer.run`).
pub fn elastic(cx: &Context<'_>, space: &str, include_prebuilt: bool) -> Report {
    let started = Instant::now();
    let mut written = 0;
    let outcome = elastic_run(cx, space, include_prebuilt, &mut written);
    report(ELASTIC, started, written, outcome)
}

fn elastic_run(
    cx: &Context<'_>,
    space: &str,
    include_prebuilt: bool,
    written_count: &mut usize,
) -> Outcome {
    let (tenants, root) = configured(cx, ELASTIC)?;
    super::query::log_unset(&tenants, cx.env);
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
                .map_or_else(|| "default".to_owned(), py)
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
        .map_err(|error| match error {
            opentide_connectors::elastic::FindError::Status(text) => format!("HTTPError: {text}"),
            opentide_connectors::elastic::FindError::Connector(error) => connector_message(&error),
            opentide_connectors::elastic::FindError::NotJson(text) => {
                format!("JSONDecodeError: {text}")
            }
        })?;
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
            let name = document.get("name").map(py).unwrap_or_default();
            if let Some(reason) = unwritable_reason(&document, &text) {
                tracing::warn!(
                    rule = name.as_str(),
                    reason = reason.as_str(),
                    logger = ELASTIC_LOGGER,
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
                    .map(py)
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
        assert!(unwritable_reason(&converted, &text).is_none() || text.contains("name: Encoded"));
        assert!(python_uuid("{11111111-1111-4111-8111-111111111111}"));
        assert!(!python_uuid("rule-1"));
        assert_eq!(elastic_filename("a:  b"), "a b");
        assert_eq!(uuid5(&migration_namespace(), "x").get_version_num(), 5);
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
