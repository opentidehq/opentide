//! HarfangLab: the Sigma rule or YARA file a deploy sends to one tenant
//! (`platforms/harfanglab/deployer.py` `compile_sigma_deployment`,
//! `compile_yara_deployment`, `deploy_mdr`, and the client's
//! `create_or_update_sigma_rule`, `create_or_update_yara_rule` and its
//! deletes). The rule's UUID is its id on the platform: no deployment state.
//!
//! The Sigma rule is written as YAML by serde-saphyr (four-space indents,
//! lists indented under their key, a multi-line string as a `|` block, no
//! folding), not by PyYAML: the text differs where the two emitters quote
//! or lay out a scalar differently, and reads back to the same document.

use crate::Context;
use crate::deploy::{self, Write};
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

/// The platform's key under `configurations`.
pub const PLATFORM: &str = "harfanglab";

/// The platform's display name, in messages.
pub const DISPLAY: &str = "HarfangLab";

/// `global_state` of an opentide `action` (`map_action_to_global_state`).
fn global_state(action: &str) -> &'static str {
    match action {
        "Alert & Block" => "block",
        "Alert, Block & Quarantine" => "quarantine",
        _ => "alert",
    }
}

/// `hl_status` of an opentide `maturity` (`map_maturity_to_hl_status`).
fn hl_status(maturity: &str) -> &'static str {
    match maturity {
        "Stable" => "stable",
        "Testing" => "testing",
        _ => "experimental",
    }
}

/// `rule_confidence_override` of an opentide `confidence` (`map_confidence`).
fn confidence(confidence: &str) -> &'static str {
    match confidence {
        "Weak" => "weak",
        "Strong" => "strong",
        _ => "moderate",
    }
}

/// `rule_level_override` of an alert severity (`map_level`).
fn level(severity: &str) -> &'static str {
    match severity {
        "Informational" => "informational",
        "Low" => "low",
        "High" => "high",
        "Critical" => "critical",
        _ => "medium",
    }
}

/// The YARA score of a severity (`SEVERITY_TO_SCORE`, `SCORE_OVERRIDE_MAP`).
fn score(severity: &str) -> Option<i64> {
    Some(match severity {
        "Informational" => 10,
        "Low" => 30,
        "Medium" => 50,
        "High" => 70,
        "Critical" => 90,
        _ => return None,
    })
}

fn string<'j>(value: Option<&'j Json>, key: &str) -> Option<&'j str> {
    value
        .and_then(|value| value.get(key))
        .and_then(Json::as_str)
}

fn strings(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Array(items)) => items.iter().map(deploy::text).collect(),
        _ => Vec::new(),
    }
}

/// A Sigma rule as YAML: four-space indents, lists indented under their key,
/// a multi-line string as a `|` block, one line per scalar.
pub fn sigma_yaml(rule: &Json) -> Result<String, CompileError> {
    let options = serde_saphyr::ser_options! {
        indent_step: 4,
        compact_list_indent: false,
        folded_wrap_chars: usize::MAX,
        min_fold_chars: usize::MAX,
    };
    serde_saphyr::to_string_with_options(rule, options)
        .map_err(|error| CompileError::failed(DISPLAY, &error.to_string()))
}

/// The settings a Sigma rule and a YARA file share.
struct Common {
    status: &'static str,
    global_state: &'static str,
    confidence: &'static str,
    level: &'static str,
}

fn common(block: &Json, rule: &Rule) -> Common {
    Common {
        status: hl_status(string(Some(block), "maturity").unwrap_or("Experimental")),
        global_state: global_state(string(Some(block), "action").unwrap_or("Alert")),
        confidence: confidence(string(Some(block), "confidence").unwrap_or("Moderate")),
        level: level(rule.alert_severity()),
    }
}

/// The Sigma rule body (`SigmaRule`, `overwrite` true).
fn sigma(
    cx: &Context<'_>,
    rule: &Rule,
    block: &Json,
    sigma: &Json,
    tenant: &Json,
) -> Result<Json, CompileError> {
    let mut settings = common(block, rule);
    let status = string(Some(block), "status").unwrap_or_default();
    let mut enabled = true;
    if deploy::strategy(cx, DISPLAY, status)? == StatusStrategy::Disablement {
        enabled = false;
        settings.global_state = "disabled";
    }
    let mut document = Object::new();
    document.insert("title".into(), rule.name.clone().into());
    document.insert("id".into(), rule.uuid.clone().into());
    if !rule.description().is_empty() {
        document.insert("description".into(), rule.description().into());
    }
    if let Some(author) = deploy::rule_text(rule, &["metadata", "author"]) {
        document.insert("author".into(), author.into());
    }
    document.insert("status".into(), settings.status.into());
    if let Some(tags) = block.get("tags").filter(|tags| tags.truthy()) {
        document.insert("tags".into(), tags.clone());
    }
    let logsource = sigma.get("logsource");
    let mut source = Object::new();
    source.insert(
        "category".into(),
        logsource
            .and_then(|logsource| logsource.get("category"))
            .cloned()
            .unwrap_or(Json::Null),
    );
    source.insert(
        "product".into(),
        logsource
            .and_then(|logsource| logsource.get("product"))
            .cloned()
            .unwrap_or(Json::Null),
    );
    document.insert("logsource".into(), Json::Object(source));
    let mut detection = Object::new();
    if let Some(Json::Array(selections)) = sigma.get("selections") {
        for selection in selections {
            let mut key = vec![
                string(Some(selection), "field")
                    .unwrap_or_default()
                    .to_owned(),
            ];
            key.extend(strings(selection.get("modifiers")));
            let name = string(Some(selection), "name").unwrap_or("selection");
            let entry = detection
                .entry(name.to_owned())
                .or_insert_with(|| Json::Object(Object::new()));
            if let Json::Object(fields) = entry {
                fields.insert(
                    key.join("|"),
                    selection
                        .get("value")
                        .cloned()
                        .unwrap_or(Json::Array(Vec::new())),
                );
            }
        }
    }
    detection.insert(
        "condition".into(),
        sigma.get("condition").cloned().unwrap_or(Json::Null),
    );
    document.insert("detection".into(), Json::Object(detection));
    if let Some(positives) = sigma.get("false_positives").filter(|value| value.truthy()) {
        document.insert("falsepositives".into(), positives.clone());
    }
    document.insert("level".into(), settings.level.into());
    let content = sigma_yaml(&Json::Object(document))?;
    let mut body = Object::new();
    body.insert("name".into(), rule.name.clone().into());
    body.insert("content".into(), content.into());
    body.insert(
        "source_id".into(),
        deploy::setup(tenant, "source_id")
            .cloned()
            .unwrap_or(Json::Null),
    );
    body.insert("enabled".into(), Json::Bool(enabled));
    body.insert("global_state".into(), settings.global_state.into());
    body.insert("hl_status".into(), settings.status.into());
    body.insert(
        "block_on_agent".into(),
        Json::Bool(matches!(settings.global_state, "block" | "quarantine")),
    );
    body.insert(
        "quarantine_on_agent".into(),
        Json::Bool(settings.global_state == "quarantine"),
    );
    body.insert(
        "rule_confidence_override".into(),
        settings.confidence.into(),
    );
    body.insert("rule_level_override".into(), settings.level.into());
    body.insert("overwrite".into(), Json::Bool(true));
    Ok(crate::sentinel_one::without_nulls(Json::Object(body)))
}

/// A string inside a YARA `meta` value (`escape_yara_string`).
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "")
}

/// The YARA rule name of a rule name: lowercase, every character but a
/// letter, a digit or `_` an underscore, and `rule_` before a leading digit.
pub fn yara_name(name: &str) -> String {
    let lowered: String = name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if lowered.chars().next().is_some_and(char::is_numeric) {
        format!("rule_{lowered}")
    } else {
        lowered
    }
}

/// The lines of `text` stripped, each indented eight spaces.
#[expect(
    clippy::str_split_at_newline,
    reason = "the oracle splits at `\\n` alone: a `\\r` stays in the line, as `lines` would not keep it"
)]
fn indented(lines: &mut Vec<String>, text: &str) {
    for line in text.trim().split('\n') {
        lines.push(format!("        {line}"));
    }
}

/// The YARA file body (`YaraRule`, `overwrite` true).
fn yara(rule: &Rule, block: &Json, yara: &Json, tenant: &Json) -> Json {
    let settings = common(block, rule);
    let mut lines: Vec<String> = Vec::new();
    let imports = strings(yara.get("imports"));
    if !imports.is_empty() {
        for module in &imports {
            lines.push(format!("import \"{module}\""));
        }
        lines.push(String::new());
    }
    lines.push(format!("rule {} {{", yara_name(&rule.name)));
    let author = deploy::rule_text(rule, &["metadata", "author"])
        .or_else(|| deploy::rule_text(rule, &["metadata", "organisation", "name"]))
        .unwrap_or_default();
    lines.push("    meta:".into());
    lines.push(format!("        id = \"{}\"", rule.uuid));
    lines.push(format!("        title = \"{}\"", escape(&rule.name)));
    lines.push(format!(
        "        description = \"{}\"",
        escape(rule.description())
    ));
    lines.push(format!("        author = \"{}\"", escape(author)));
    for (key, field) in [("created", "date"), ("modified", "modified")] {
        if let Some(value) = deploy::rule_value(rule, &["metadata", key]).filter(|v| v.truthy()) {
            lines.push(format!("        {field} = \"{}\"", deploy::text(value)));
        }
    }
    if let Some(Json::Object(public)) = deploy::rule_value(rule, &["references", "public"])
        && !public.is_empty()
    {
        let references: Vec<String> = public.values().map(deploy::text).collect();
        lines.push(format!(
            "        references = \"{}\"",
            references.join("\\n")
        ));
    }
    let tags = strings(block.get("tags"));
    if !tags.is_empty() {
        lines.push(format!("        tags = \"{}\"", tags.join(";")));
    }
    let meta = yara.get("meta");
    let os = string(meta, "os").unwrap_or_default();
    let contexts: Vec<String> = strings(meta.and_then(|meta| meta.get("context")))
        .into_iter()
        .map(|context| {
            let file = match os {
                "Windows" => Some("file.pe"),
                "MacOS" => Some("file.macho"),
                "Linux" => Some("file.elf"),
                _ => None,
            };
            match file {
                Some(file) if context == "file" => file.to_owned(),
                _ => context,
            }
        })
        .collect();
    if !contexts.is_empty() {
        lines.push(format!("        context = \"{}\"", contexts.join(",")));
    }
    lines.push(format!("        os = \"{os}\""));
    match meta.and_then(|meta| meta.get("arch")) {
        Some(Json::Array(items)) if !items.is_empty() => {
            let arch: Vec<String> = items.iter().map(deploy::text).collect();
            lines.push(format!("        arch = \"{}\"", arch.join(",")));
        }
        Some(Json::Str(arch)) if !arch.is_empty() => {
            lines.push(format!("        arch = \"{arch}\""));
        }
        _ => {}
    }
    if let Some(classification) = string(meta, "classification").filter(|text| !text.is_empty()) {
        lines.push(format!(
            "        classification = \"{}\"",
            escape(classification)
        ));
    }
    let score = string(meta, "score")
        .filter(|text| !text.is_empty())
        .and_then(score)
        .or_else(|| score(rule.alert_severity()))
        .unwrap_or(50);
    lines.push(format!("        score = {score}"));
    lines.push(format!("        confidence = \"{}\"", settings.confidence));
    lines.push("    strings:".into());
    indented(
        &mut lines,
        string(Some(yara), "strings").unwrap_or_default(),
    );
    lines.push("    condition:".into());
    indented(
        &mut lines,
        string(Some(yara), "condition").unwrap_or_default(),
    );
    lines.push("}".into());
    let mut body = Object::new();
    body.insert("name".into(), rule.name.clone().into());
    body.insert("content".into(), lines.join("\n").into());
    body.insert(
        "source_id".into(),
        deploy::setup(tenant, "source_id")
            .cloned()
            .unwrap_or(Json::Null),
    );
    body.insert("global_state".into(), settings.global_state.into());
    body.insert("hl_status".into(), settings.status.into());
    body.insert(
        "rule_confidence_override".into(),
        settings.confidence.into(),
    );
    body.insert("rule_level_override".into(), settings.level.into());
    body.insert("overwrite".into(), Json::Bool(true));
    Json::Object(body)
}

/// The writes a deploy sends for `rule` to `tenant`: the Sigma rule
/// (`PUT .../SigmaRule/<uuid>/`) or the YARA file (`POST .../YaraFile/`), a
/// delete for a DELETION status, or none when the rule's kind is not the
/// tenant's `type`.
pub fn compile(cx: &Context<'_>, rule: &Rule, tenant: &Json) -> Result<Vec<Write>, CompileError> {
    let Some(block) = rule.block(PLATFORM).filter(|block| block.truthy()) else {
        return Ok(Vec::new());
    };
    let sigma_block = block.get("sigma").filter(|value| !value.is_null());
    let yara_block = block.get("yara").filter(|value| !value.is_null());
    let kind = match (sigma_block, yara_block) {
        (Some(_), _) => "Sigma",
        (None, Some(_)) => "YARA",
        (None, None) => return Ok(Vec::new()),
    };
    if deploy::setup(tenant, "type").and_then(Json::as_str) != Some(kind) {
        return Ok(Vec::new());
    }
    let base = deploy::setup_text(tenant, "url");
    let base = base.trim_end_matches('/');
    let endpoint = if kind == "Sigma" {
        format!("{base}/api/data/threat_intelligence/SigmaRule/")
    } else {
        format!("{base}/api/data/threat_intelligence/YaraFile/")
    };
    let status = string(Some(block), "status").unwrap_or_default();
    if deploy::strategy(cx, DISPLAY, status)? == StatusStrategy::Deletion {
        return Ok(vec![Write::new(
            "DELETE",
            format!("{endpoint}{}/", rule.uuid),
            Json::Null,
        )]);
    }
    Ok(vec![match (sigma_block, yara_block) {
        (Some(sigma_block), _) => Write::new(
            "PUT",
            format!("{endpoint}{}/", rule.uuid),
            sigma(cx, rule, block, sigma_block, tenant)?,
        ),
        (None, Some(yara_block)) => {
            Write::new("POST", endpoint, yara(rule, block, yara_block, tenant))
        }
        (None, None) => return Ok(Vec::new()),
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_names_are_identifiers() {
        assert_eq!(
            yara_name("HarfangLab YARA-Loader"),
            "harfanglab_yara_loader"
        );
        assert_eq!(yara_name("3 Rule: x"), "rule_3_rule__x");
    }

    #[test]
    fn mappings_default_as_the_oracle_does() {
        assert_eq!(global_state("Alert & Block"), "block");
        assert_eq!(global_state("other"), "alert");
        assert_eq!(hl_status("Testing"), "testing");
        assert_eq!(confidence("Weak"), "weak");
        assert_eq!(level("Unknown"), "medium");
        assert_eq!(score("Critical"), Some(90));
        assert_eq!(score("x"), None);
        assert_eq!(escape("a\"b\\c\nd\r"), "a\\\"b\\\\c\\nd");
    }

    /// The YARA content of a rule whose `meta.arch` is written `arch`.
    fn yara_content(arch: &str) -> String {
        let text = format!(
            "name: Loader\nmetadata:\n  uuid: 00000000-0000-4000-8005-000000000699\n\
             description: d\nconfigurations:\n  harfanglab:\n    status: STAGING\n    \
             yara:\n      meta:\n        os: Linux\n        arch: {arch}\n      \
             strings: '$a = \"x\"'\n      condition: $a\n"
        );
        let document = opentide_schema::node::load(&text).unwrap();
        let rule = Rule::new(document.root().unwrap(), None);
        let block = rule.block(PLATFORM).unwrap();
        let body = yara(&rule, block, block.get("yara").unwrap(), &Json::Null);
        body.get("content")
            .and_then(Json::as_str)
            .unwrap()
            .to_owned()
    }

    #[test]
    fn a_yara_architecture_is_written_from_a_list_or_one_string() {
        let os_then = |arch: &str| format!("\n        os = \"Linux\"\n        arch = \"{arch}\"\n");
        let content = yara_content("[x64, arm64]");
        assert!(content.contains(&os_then("x64,arm64")), "{content}");
        // One string, as the oracle's deployer takes it (`isinstance`).
        let content = yara_content("x86");
        assert!(content.contains(&os_then("x86")), "{content}");
        // Empty: no `arch` line.
        let content = yara_content("[]");
        assert!(!content.contains("arch ="), "{content}");
        assert!(
            content.contains("\n        os = \"Linux\"\n        score = 10\n"),
            "{content}"
        );
    }

    #[test]
    fn sigma_lists_indent_under_their_key_and_lines_stay_whole() {
        let rule: Json = serde_json::from_str(
            r#"{"title":"T","tags":["a","b"],"detection":{"s":{"f|contains":["x"]}},"description":"one\ntwo"}"#,
        )
        .unwrap();
        let yaml = sigma_yaml(&rule).unwrap();
        assert!(yaml.contains("tags:\n    - a\n    - b\n"), "{yaml}");
        assert!(
            yaml.contains("    s:\n        f|contains:\n            - x\n"),
            "{yaml}"
        );
        assert!(
            yaml.contains("description: |-\n    one\n    two\n"),
            "{yaml}"
        );
        let long = Json::Str("word ".repeat(40));
        let mut object = Object::new();
        object.insert("description".into(), long);
        assert_eq!(
            sigma_yaml(&Json::Object(object)).unwrap().lines().count(),
            1
        );
    }
}
