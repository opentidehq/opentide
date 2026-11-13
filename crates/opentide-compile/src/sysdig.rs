//! The Sysdig Secure body (`platforms/sysdig/compile.py`, sysdig-1.0): the
//! Falco rule a block deploys, with the block's own macros and lists written
//! in as Falco's rule loader would expand them (`platforms/sysdig/expansion.py`),
//! and the `/api/secure/rules` payload (`api_body`).
//!
//! Falco's loader rules (`resolve_list`, `compile_list_infos`, the value-list
//! passes) are `opentide_core::falco`'s; the scan for the macros a condition
//! uses and `join_lines` are opentide-schema's (`falco_text`), the ones the
//! model's `sysdig_rule_shape` check reads the block with.

use opentide_core::falco::{
    flatten_lists, is_list_comparison, is_python_space, list_inside, normalize_comp, python_strip,
    resolve_list, upsert,
};
use opentide_schema::objects::platform::falco_text::{
    check_position_names, join_lines, substitute_macros,
};

use crate::elastic::rule_techniques;
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;
use crate::{Context, attack};
use opentide_schema::node::{Node, Value};

/// The platform's display name, in a failure's message.
pub const DISPLAY: &str = "Sysdig";

/// The priority of a rule with no `response`, or an unknown severity.
pub const DEFAULT_PRIORITY: &str = "WARNING";

/// The event source of a block that names none.
pub const DEFAULT_SOURCE: &str = "syscall";

/// The maturity tag of a status strategy that is neither released nor in
/// preview.
pub const SANDBOX_TAG: &str = "maturity_sandbox";

/// `response.alert_severity` -> Falco priority (`SEVERITY_PRIORITY`).
fn severity_priority(severity: &str) -> Option<&'static str> {
    Some(match severity {
        "critical" => "CRITICAL",
        "high" => "ERROR",
        "medium" => "WARNING",
        "low" => "NOTICE",
        "informational" => "INFORMATIONAL",
        _ => return None,
    })
}

/// Falco priority -> the API's `priority` value (`API_PRIORITY`).
fn api_priority(priority: &str) -> Option<&'static str> {
    Some(match priority {
        "EMERGENCY" => "emergency",
        "ALERT" => "alert",
        "CRITICAL" => "critical",
        "ERROR" => "error",
        "WARNING" => "warning",
        "NOTICE" => "notice",
        "INFORMATIONAL" => "info",
        "DEBUG" => "debug",
        _ => return None,
    })
}

/// The fields written after the rule name when `output` is omitted
/// (`DEFAULT_OUTPUT_FIELDS`).
fn default_output_fields(source: &str) -> &'static str {
    match source {
        "syscall" => {
            " | evt_type=%evt.type user=%user.name user_uid=%user.uid process=%proc.name \
             proc_exepath=%proc.exepath parent=%proc.pname command=%proc.cmdline \
             terminal=%proc.tty container_id=%container.id container_name=%container.name \
             image=%container.image.repository"
        }
        "k8s_audit" => {
            " | user=%ka.user.name verb=%ka.verb uri=%ka.uri resource=%ka.target.resource \
             namespace=%ka.target.namespace name=%ka.target.name response=%ka.response.code"
        }
        "aws_cloudtrail" => {
            " | user=%ct.user region=%ct.region event=%ct.name source_ip=%ct.srcip \
             account=%ct.user.accountid"
        }
        _ => "",
    }
}

/// The Falco maturity tag of a status strategy (`MATURITY_TAG`).
pub fn maturity_tag(strategy: StatusStrategy) -> &'static str {
    match strategy {
        StatusStrategy::Release | StatusStrategy::Universal => "maturity_stable",
        StatusStrategy::Preview => "maturity_incubating",
        _ => SANDBOX_TAG,
    }
}

/// The Falco rule a block deploys, after derivation and expansion
/// (`FalcoRule`).
#[derive(Debug, Clone, PartialEq)]
pub struct FalcoRule {
    /// The rule's UUID.
    pub uuid: String,
    /// The Falco rule's name: the tuned rule's for a tuning.
    pub name: String,
    /// Whether the block tunes an existing rule (`append_to_rule`).
    pub tuning: bool,
    /// The condition, expanded, on one line.
    pub condition: Option<String>,
    /// The exceptions, comparisons normalised and block lists expanded.
    pub exceptions: Vec<Json>,
    /// The description, on one line.
    pub desc: String,
    /// The output template.
    pub output: String,
    /// The Falco priority.
    pub priority: String,
    /// The event source.
    pub source: String,
    /// The tags.
    pub tags: Vec<String>,
    /// `minimumEngineVersion`.
    pub minimum_engine_version: Option<i64>,
}

/// A value as text: a string as it is, anything else as its JSON. In the
/// block's definitions and exceptions every scalar is already text
/// ([`falco_block`]).
fn item_text(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    }
}

/// The rule's Sysdig block as Falco reads its definitions and exceptions:
/// in `macros`, `lists` and `exceptions`, a scalar that is not a string is
/// its text as written in the file (`1.50`, `True`), which is what Falco's
/// YAML loader makes of a list item or an exception value.
fn falco_block(rule: &Rule) -> Result<Json, CompileError> {
    let json = block_of(rule)?;
    let node = rule
        .node
        .get("configurations")
        .and_then(|configurations| configurations.get("sysdig"));
    let (Some(node), Json::Object(object)) = (node, json) else {
        return Ok(json.clone());
    };
    let mut object = object.clone();
    for key in ["macros", "lists", "exceptions"] {
        if let Some(child) = node.get(key) {
            object.insert(key.into(), falco_json(child));
        }
    }
    Ok(Json::Object(object))
}

/// `node` with every scalar but null as Falco's text.
fn falco_json(node: &Node) -> Json {
    match &node.value {
        Value::Null => Json::Null,
        Value::Seq(items) => Json::Array(items.iter().map(|item| falco_json(item)).collect()),
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|entry| {
                    (
                        opentide_schema::objects::platform::sysdig::item_text(&entry.key),
                        falco_json(&entry.value),
                    )
                })
                .collect(),
        ),
        _ => Json::Str(opentide_schema::objects::platform::sysdig::item_text(node)),
    }
}

/// A null list item or exception value: Falco has no text for it.
fn null_value(place: &str) -> CompileError {
    CompileError::invalid_rule(format!(
        "{place}: a value is null, and Falco reads each value as text: write the text it \
         should match (quote it, \"null\", to match that word)"
    ))
}

/// Why a block's definitions cannot be expanded (`ExpansionError`): the
/// oracle reports it as any other failure, `str(exc)` being the message.
fn expansion_error(message: String) -> CompileError {
    CompileError::failed(DISPLAY, &message)
}

fn list_in_value(name: &str, place: &str) -> CompileError {
    expansion_error(format!(
        "{place}: the block list {name:?} appears in a value where Falco's expansion would \
         not produce a value list"
    ))
}

/// One block's macros and lists, expanded in block order (`Expander`).
struct Expander {
    /// The lists, flattened (`compile_list_infos`), in block order.
    lists: Vec<(String, Vec<String>)>,
    /// The macros, expanded, in block order.
    macros: Vec<(String, String)>,
}

impl Expander {
    fn new(
        macros: &[(String, String)],
        lists: &[(String, Vec<String>)],
    ) -> Result<Self, CompileError> {
        let mut expander = Self {
            lists: flatten_lists(lists),
            macros: Vec::with_capacity(macros.len()),
        };
        let order: Vec<&str> = macros.iter().map(|(name, _)| name.as_str()).collect();
        for (index, (name, condition)) in macros.iter().enumerate() {
            let visible = &order[..index];
            let text = expander.resolve_lists(join_lines(condition));
            let mut later: Vec<String> = Vec::new();
            for used in check_position_names(&text) {
                if order.contains(&used.as_str())
                    && !visible.contains(&used.as_str())
                    && !later.contains(&used)
                {
                    later.push(used);
                }
            }
            if !later.is_empty() {
                return Err(expansion_error(format!(
                    "macro {name:?} uses the block macro {}, which is itself or defined after \
                     it: Falco refuses it as an undefined macro",
                    later
                        .iter()
                        .map(|name| format!("{name:?}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            let written = expander.substitute(&text, visible);
            upsert(&mut expander.macros, name, written);
        }
        Ok(expander)
    }

    /// Every block list resolved in `text`, in block order.
    fn resolve_lists(&self, mut text: String) -> String {
        for (name, items) in &self.lists {
            text = resolve_list(&text, name, items);
        }
        text
    }

    /// `text` with each visible block macro written in, in parentheses.
    fn substitute(&self, text: &str, visible: &[&str]) -> String {
        substitute_macros(text, |name| {
            if !visible.contains(&name) {
                return None;
            }
            self.macros
                .iter()
                .find(|(known, _)| known == name)
                .map(|(_, condition)| format!("({condition})"))
        })
    }

    /// `condition` on one line, with the block's lists and macros written in.
    fn expand(&self, condition: &str) -> String {
        let all: Vec<&str> = self.macros.iter().map(|(name, _)| name.as_str()).collect();
        self.substitute(&self.resolve_lists(join_lines(condition)), &all)
    }

    fn items(&self, name: &str) -> Option<&[String]> {
        self.lists
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, items)| items.as_slice())
    }

    /// `_list_in`: a block list whose name occurs inside a value, not as all
    /// of it.
    fn list_in(&self, value: &Json) -> Option<&str> {
        list_inside(&self.lists, &item_text(value))
    }

    /// `_passes`: a member equal to a list's name becomes its items, one pass
    /// per list in block order.
    fn passes(&self, values: Vec<Json>) -> Vec<Json> {
        let mut out = values;
        for (name, items) in &self.lists {
            let mut current = Vec::with_capacity(out.len());
            for value in out {
                if !matches!(value, Json::Array(_) | Json::Object(_)) && item_text(&value) == *name
                {
                    current.extend(items.iter().cloned().map(Json::Str));
                } else {
                    current.push(value);
                }
            }
            out = current;
        }
        out
    }

    /// `_members`: a value list with block list names expanded.
    fn members(&self, values: Vec<Json>, place: &str) -> Result<Json, CompileError> {
        if values.iter().any(Json::is_null) {
            return Err(null_value(place));
        }
        let out = self.passes(values);
        for value in &out {
            if let Some(name) = self.list_in(value) {
                return Err(list_in_value(name, place));
            }
        }
        Ok(Json::Array(out))
    }

    /// An exception as Sysdig receives it (`exception`).
    fn exception(&self, entry: &Json) -> Result<Json, CompileError> {
        let set = |key: &str| entry.get(key).filter(|value| !value.is_null());
        let name = item_text(set("name").unwrap_or(&Json::Null));
        let fields = set("fields");
        let comps = set("comps");
        let values = set("values");
        let mut out = Object::new();
        out.insert("name".into(), name.clone().into());
        out.insert("fields".into(), fields.cloned().unwrap_or(Json::Null));
        let place = format!("exception {name:?}");
        let as_list = |value: &Json| match value {
            Json::Array(items) => items.clone(),
            other => vec![other.clone()],
        };
        if let Some(Json::Str(_)) = fields {
            if let Some(comps) = comps {
                out.insert(
                    "comps".into(),
                    normalize_comp(&item_text(comps)).to_owned().into(),
                );
            }
            if let Some(values) = values {
                out.insert("values".into(), self.members(as_list(values), &place)?);
            }
            return Ok(Json::Object(out));
        }
        let comp_list: Vec<String> = match comps {
            Some(Json::Array(items)) => items
                .iter()
                .map(|comp| normalize_comp(&item_text(comp)).to_owned())
                .collect(),
            _ => {
                let count = match fields {
                    Some(Json::Array(items)) => items.len(),
                    _ => 0,
                };
                vec!["=".to_owned(); count]
            }
        };
        if comps.is_some() {
            out.insert("comps".into(), comp_list.clone().into());
        }
        let Some(values) = values else {
            return Ok(Json::Object(out));
        };
        let mut rows = Vec::new();
        for row in as_list(values) {
            let Json::Array(row) = row else {
                rows.push(row);
                continue;
            };
            let mut new_row = Vec::new();
            for (comp, item) in comp_list.iter().zip(row) {
                if item.is_null() {
                    return Err(null_value(&place));
                }
                if let Json::Array(items) = item {
                    new_row.push(self.members(items, &place)?);
                    continue;
                }
                if let Some(found) = self.list_in(&item) {
                    return Err(list_in_value(found, &place));
                }
                let text = item_text(&item);
                if self.items(&text).is_none() {
                    new_row.push(item);
                } else if !is_list_comparison(comp) {
                    return Err(list_in_value(&text, &place));
                } else {
                    new_row.push(self.members(vec![item], &place)?);
                }
            }
            rows.push(Json::Array(new_row));
        }
        out.insert("values".into(), Json::Array(rows));
        Ok(Json::Object(out))
    }
}

/// The `name` and `key` entries of a block's `macros` or `lists`, a later
/// entry of the same name replacing the earlier one in place (a dict).
fn definitions(block: &Json, list: &str, key: &str) -> Vec<(String, Json)> {
    let mut out: Vec<(String, Json)> = Vec::new();
    if let Some(Json::Array(entries)) = block.get(list) {
        for entry in entries {
            let name = item_text(entry.get("name").unwrap_or(&Json::Null));
            let value = entry.get(key).cloned().unwrap_or(Json::Null);
            upsert(&mut out, &name, value);
        }
    }
    out
}

/// The text of a field that is set, as Python's `if value:` reads it.
fn text<'a>(block: &'a Json, key: &str) -> Option<&'a str> {
    block
        .get(key)
        .and_then(Json::as_str)
        .filter(|text| !text.is_empty())
}

/// The block's priority, else `response.alert_severity`'s, else `WARNING`
/// (`derive_priority`).
fn derive_priority(rule: &Rule, block: &Json) -> String {
    if let Some(priority) = text(block, "priority") {
        let value = python_strip(priority).to_uppercase();
        return if value == "INFO" {
            "INFORMATIONAL".to_owned()
        } else {
            value
        };
    }
    if rule.response().is_none() {
        return DEFAULT_PRIORITY.to_owned();
    }
    severity_priority(&python_strip(rule.alert_severity()).to_lowercase())
        .unwrap_or(DEFAULT_PRIORITY)
        .to_owned()
}

/// Technique ids, then a `mitre_<tactic>` tag per tactic, in matrix order
/// (`attack_tags`).
pub fn attack_tags(cx: &Context<'_>, techniques: &[String]) -> Vec<String> {
    let mut tactics: Vec<&str> = Vec::new();
    for technique in techniques {
        let Some(name) = cx.attack.name(technique) else {
            continue;
        };
        if attack::non_enterprise(name) {
            continue;
        }
        for stage in cx.attack.stages(technique) {
            if let Some((tactic, _)) = attack::tactic(&stage)
                && !tactics.contains(&tactic)
            {
                tactics.push(tactic);
            }
        }
    }
    let mut tags = techniques.to_vec();
    tags.extend(
        attack::TACTIC_ORDER
            .iter()
            .filter(|(stage, _)| tactics.contains(stage))
            .map(|(stage, _)| format!("mitre_{}", stage.to_lowercase().replace([' ', '-'], "_"))),
    );
    tags
}

fn strings(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Array(items)) => items.iter().map(item_text).collect(),
        _ => Vec::new(),
    }
}

/// The Falco rule `rule`'s Sysdig block deploys under `strategy`, with a
/// tenant's `tenant_tags` (`compile_rule`).
pub fn compile(
    cx: &Context<'_>,
    rule: &Rule,
    strategy: StatusStrategy,
    tenant_tags: &[String],
) -> Result<FalcoRule, CompileError> {
    let block = &falco_block(rule)?;
    let macros: Vec<(String, String)> = definitions(block, "macros", "condition")
        .into_iter()
        .map(|(name, condition)| (name, item_text(&condition)))
        .collect();
    let lists: Vec<(String, Vec<String>)> = definitions(block, "lists", "items")
        .into_iter()
        .map(|(name, items)| {
            let items = match items {
                Json::Array(items) if items.iter().any(Json::is_null) => {
                    return Err(null_value(&format!("list {name:?}")));
                }
                Json::Array(items) => items.iter().map(item_text).collect(),
                _ => Vec::new(),
            };
            Ok((name, items))
        })
        .collect::<Result<_, CompileError>>()?;
    let expander = Expander::new(&macros, &lists)?;
    let condition = text(block, "condition").map(|condition| expander.expand(condition));
    let mut exceptions = Vec::new();
    if let Some(Json::Array(entries)) = block.get("exceptions") {
        for entry in entries {
            exceptions.push(expander.exception(entry)?);
        }
    }
    let minimum_engine_version = match block.get("minimum_engine_version") {
        Some(Json::Int(version)) => Some(*version),
        _ => None,
    };
    if let Some(tuned) = text(block, "append_to_rule") {
        return Ok(FalcoRule {
            uuid: rule.uuid.clone(),
            name: tuned.to_owned(),
            tuning: true,
            condition,
            exceptions,
            desc: String::new(),
            output: String::new(),
            priority: DEFAULT_PRIORITY.to_owned(),
            source: DEFAULT_SOURCE.to_owned(),
            tags: Vec::new(),
            minimum_engine_version,
        });
    }
    let name = text(block, "name").unwrap_or(&rule.name).to_owned();
    let source = text(block, "source").unwrap_or(DEFAULT_SOURCE).to_owned();
    let output = match text(block, "output") {
        Some(output) => join_lines(output),
        None => format!("{name}{}", default_output_fields(&source)),
    };
    let mut tags = strings(block.get("tags"));
    tags.extend(attack_tags(cx, &rule_techniques(cx, rule)));
    tags.push(maturity_tag(strategy).to_owned());
    tags.extend(tenant_tags.iter().cloned());
    let mut unique: Vec<String> = Vec::with_capacity(tags.len());
    for tag in tags {
        if !unique.contains(&tag) {
            unique.push(tag);
        }
    }
    Ok(FalcoRule {
        uuid: rule.uuid.clone(),
        name,
        tuning: false,
        condition,
        exceptions,
        desc: rule
            .description()
            .split(is_python_space)
            .filter(|word| !word.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
        output,
        priority: derive_priority(rule, block),
        source,
        tags: unique,
        minimum_engine_version,
    })
}

/// The rule's Sysdig block, or the error naming the rule (`block_of`).
fn block_of(rule: &Rule) -> Result<&Json, CompileError> {
    rule.block("sysdig").ok_or_else(|| {
        CompileError::failed(
            DISPLAY,
            &format!("Rule {} ({}) has no sysdig block", rule.uuid, rule.name),
        )
    })
}

/// The strategy the block's status maps to (`_strategy`).
pub fn strategy(cx: &Context<'_>, rule: &Rule) -> Result<StatusStrategy, CompileError> {
    let status = block_of(rule)?
        .get("status")
        .map_or_else(|| "null".to_owned(), item_text);
    cx.statuses
        .strategy(&status)
        .map_err(|error| CompileError::failed(DISPLAY, &error.exception_text()))
}

/// The tags a tenant's `setup` adds.
pub fn tenant_tags(tenant: &Json) -> Vec<String> {
    strings(tenant.get("setup").and_then(|setup| setup.get("tags")))
}

/// The body `rule` deploys on `tenant` (none for a dry run), under its
/// block's status (`api_body(SysdigDeploy().compile_deployment(rule, tenant))`).
pub fn compile_body(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: Option<&Json>,
) -> Result<Json, CompileError> {
    let tags = tenant.map(tenant_tags).unwrap_or_default();
    let strategy = strategy(cx, rule)?;
    api_body(&compile(cx, rule, strategy, &tags)?)
}

/// The `/api/secure/rules` payload (`api_body`, sysdig-1.0 "Deploy: api").
pub fn api_body(compiled: &FalcoRule) -> Result<Json, CompileError> {
    let mut details = Object::new();
    details.insert("ruleType".into(), "FALCO".into());
    details.insert("append".into(), Json::Bool(compiled.tuning));
    let condition = |text: &str| {
        let mut condition = Object::new();
        condition.insert("condition".into(), text.into());
        condition.insert("components".into(), Json::Array(Vec::new()));
        Json::Object(condition)
    };
    let mut body = Object::new();
    body.insert("name".into(), compiled.name.clone().into());
    if compiled.tuning {
        if let Some(text) = &compiled.condition {
            details.insert("condition".into(), condition(text));
        }
        if !compiled.exceptions.is_empty() {
            details.insert(
                "exceptions".into(),
                Json::Array(compiled.exceptions.clone()),
            );
        }
        if let Some(version) = compiled.minimum_engine_version {
            details.insert("minimumEngineVersion".into(), Json::Int(version));
        }
        body.insert("description".into(), "".into());
        body.insert("tags".into(), Json::Array(Vec::new()));
        body.insert("details".into(), Json::Object(details));
        return Ok(Json::Object(body));
    }
    let Some(priority) = api_priority(&compiled.priority) else {
        // The oracle's `API_PRIORITY[...]` raises a KeyError.
        return Err(CompileError::failed(
            DISPLAY,
            &format!("{:?}", compiled.priority),
        ));
    };
    details.insert("source".into(), compiled.source.clone().into());
    details.insert(
        "condition".into(),
        condition(compiled.condition.as_deref().unwrap_or_default()),
    );
    details.insert("output".into(), compiled.output.clone().into());
    details.insert("priority".into(), priority.into());
    if !compiled.exceptions.is_empty() {
        details.insert(
            "exceptions".into(),
            Json::Array(compiled.exceptions.clone()),
        );
    }
    if let Some(version) = compiled.minimum_engine_version {
        details.insert("minimumEngineVersion".into(), Json::Int(version));
    }
    body.insert("description".into(), compiled.desc.clone().into());
    body.insert("tags".into(), compiled.tags.clone().into());
    body.insert("details".into(), Json::Object(details));
    Ok(Json::Object(body))
}
