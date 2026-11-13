//! A platform's `[[modifiers]]` applied to a rule for one tenant
//! (`deployment/planning.py` `TideDeployment.modifiers_resolver`): each
//! modifier whose conditions hold rewrites keys of the rule's platform block
//! before the rule is sent there. `validate query --live` checks the queries
//! a deploy sends, so it reads the block as modified.

use opentide_schema::from_node::Model;
use opentide_schema::objects::platform::{
    BitdefenderConfig, CarbonBlackConfig, CrowdstrikeConfig, DefenderConfig, ElasticConfig,
    GoogleSecopsConfig, GraylogConfig, HarfangLabConfig, SentinelConfig, SentinelOneConfig,
    SplunkConfig, SysdigConfig,
};

use crate::json::{Json, Object};

/// The top-level keys of `platform`'s block model, attribute and serialised
/// names (`_typed_platform_config_roots`); empty for a platform it does not
/// know.
pub fn typed_roots(platform: &str) -> Vec<&'static str> {
    let fields: &[(&str, &str)] = match platform {
        "sentinel" => SentinelConfig::FIELDS,
        "defender_for_endpoint" => DefenderConfig::FIELDS,
        "splunk" => SplunkConfig::FIELDS,
        "sentinel_one" => SentinelOneConfig::FIELDS,
        "crowdstrike" => CrowdstrikeConfig::FIELDS,
        "harfanglab" => HarfangLabConfig::FIELDS,
        "carbon_black_cloud" => CarbonBlackConfig::FIELDS,
        "elastic" => ElasticConfig::FIELDS,
        "sysdig" => SysdigConfig::FIELDS,
        "bitdefender" => BitdefenderConfig::FIELDS,
        "google_secops" => GoogleSecopsConfig::FIELDS,
        "graylog" => GraylogConfig::FIELDS,
        _ => &[],
    };
    let mut roots = Vec::with_capacity(fields.len() * 2);
    for (attribute, serialised) in fields {
        roots.push(*attribute);
        roots.push(*serialised);
    }
    roots
}

/// The strings of a list value; nothing for anything else.
fn strings(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether a modifier with `conditions` applies to a rule of `status` and
/// `flags` deployed to `tenant` (`modifier_applies`): every condition it
/// sets holds; one that sets none applies only with `default = true`.
pub fn applies(conditions: Option<&Json>, status: &str, tenant: &str, flags: &[String]) -> bool {
    let statuses = strings(conditions.and_then(|c| c.get("status")));
    let tenants = strings(conditions.and_then(|c| c.get("tenants")));
    let wanted = strings(conditions.and_then(|c| c.get("flags")));
    let mut checks = Vec::new();
    if !statuses.is_empty() {
        checks.push(statuses.iter().any(|item| item == status));
    }
    if !tenants.is_empty() {
        checks.push(tenants.iter().any(|item| item == tenant));
    }
    if !wanted.is_empty() {
        checks.push(flags.iter().any(|flag| wanted.contains(flag)));
    }
    if checks.is_empty() {
        return matches!(
            conditions.and_then(|c| c.get("default")),
            Some(Json::Bool(true))
        );
    }
    checks.into_iter().all(|check| check)
}

/// *data* with each nested mapping spread into dotted keys
/// (`flatten_mapping`): the top-level values that are not mappings first,
/// then the nested values in order. An empty mapping adds no key.
pub fn flatten_mapping(data: &Object) -> Vec<(String, Json)> {
    fn spread(value: &Json, path: &str, flat: &mut Vec<(String, Json)>) {
        match value {
            Json::Object(children) => {
                for (key, child) in children {
                    let next = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    spread(child, &next, flat);
                }
            }
            other => set(flat, path, other.clone()),
        }
    }
    fn set(flat: &mut Vec<(String, Json)>, key: &str, value: Json) {
        match flat.iter_mut().find(|(name, _)| name == key) {
            Some(entry) => entry.1 = value,
            None => flat.push((key.to_owned(), value)),
        }
    }
    let mut flat: Vec<(String, Json)> = data
        .iter()
        .filter(|(_, value)| !matches!(value, Json::Object(_)))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for (key, value) in data {
        if matches!(value, Json::Object(_)) {
            spread(value, key, &mut flat);
        }
    }
    flat
}

/// `{"a.b": value}` as `{"a": {"b": value}}` (`unroll_dot_dict`), with its
/// quirk kept: a segment equal to the last one holds the value itself.
fn unroll(key: &str, value: Json) -> Object {
    let mut parts: Vec<&str> = key.split('.').collect();
    parts.reverse();
    let mut unrolled = Object::new();
    for part in &parts {
        let first = parts.iter().position(|seen| seen == part).unwrap_or(0);
        if first == 0 {
            unrolled.insert((*part).to_owned(), value.clone());
        } else {
            let inner = std::mem::take(&mut unrolled);
            unrolled.insert((*part).to_owned(), Json::Object(inner));
        }
    }
    unrolled
}

/// *base* updated from *update*, mappings merged rather than replaced
/// (`_deep_update`).
fn deep_update(base: &mut Object, update: &Object) {
    for (key, value) in update {
        if let Json::Object(inner) = value {
            let mut merged = match base.get(key) {
                Some(Json::Object(existing)) => existing.clone(),
                _ => Object::new(),
            };
            deep_update(&mut merged, inner);
            base.insert(key.clone(), Json::Object(merged));
        } else {
            base.insert(key.clone(), value.clone());
        }
    }
}

/// The value of the dotted *key* in *block*, as [`flatten_mapping`] spreads it.
fn flattened<'b>(block: &'b Object, key: &str) -> Option<&'b Json> {
    let mut current: &'b Object = block;
    let parts: Vec<&str> = key.split('.').collect();
    for (at, part) in parts.iter().enumerate() {
        let value = current.get(*part)?;
        if at + 1 == parts.len() {
            return (!matches!(value, Json::Object(_))).then_some(value);
        }
        current = value.as_object()?;
    }
    None
}

/// The platform block *block* of a rule with the modifiers of `modifiers`
/// (the platform's `[[modifiers]]`) applied for `tenant` (`modifiers_resolver`).
pub fn apply(modifiers: &[Json], platform: &str, block: &Json, tenant: &str) -> Json {
    let Json::Object(original) = block else {
        return block.clone();
    };
    let status = match original.get("status") {
        Some(Json::Str(text)) => text.clone(),
        Some(other) if !other.is_null() => other.to_compact(),
        _ => String::new(),
    };
    let flags = strings(original.get("flags"));
    let roots = typed_roots(platform);
    let mut raw = original.clone();
    for modifier in modifiers {
        if !applies(modifier.get("conditions"), &status, tenant, &flags) {
            continue;
        }
        let Some(Json::Object(modifications)) = modifier.get("modifications") else {
            continue;
        };
        for (key, value) in flatten_mapping(modifications) {
            let mut value = match &value {
                Json::Str(text) if text == "NONE" || text == "NULL" => Json::Null,
                _ => value,
            };
            if let Json::Str(text) = &value
                && !text.is_empty()
                && text.contains("::")
            {
                let mut parts = text.split("::");
                let operator = parts.next().unwrap_or_default().to_owned();
                let operand = parts.next().unwrap_or_default().to_owned();
                match flattened(&raw, &key) {
                    Some(current) => {
                        let current = match current {
                            Json::Null => String::new(),
                            Json::Str(text) => text.clone(),
                            other => other.to_compact(),
                        };
                        if operator == "prefix" {
                            value = Json::Str(format!("{operand}{current}"));
                        } else if operator == "suffix" {
                            value = Json::Str(format!("{current}{operand}"));
                        }
                    }
                    None => value = Json::Str(operand),
                }
            }
            let update = unroll(&key, value);
            let Some(root) = update.keys().next() else {
                continue;
            };
            if !roots.is_empty() && !roots.contains(&root.as_str()) {
                continue;
            }
            deep_update(&mut raw, &update);
        }
    }
    Json::Object(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn conditions_must_all_hold_and_none_applies_only_by_default() {
        let flags = vec!["noisy".to_owned()];
        let conditions = json(r#"{"status": ["STAGING"], "tenants": ["lab"]}"#);
        assert!(applies(Some(&conditions), "STAGING", "lab", &[]));
        assert!(!applies(Some(&conditions), "STAGING", "prod", &[]));
        let by_flag = json(r#"{"flags": ["noisy"]}"#);
        assert!(applies(Some(&by_flag), "STAGING", "lab", &flags));
        assert!(!applies(Some(&by_flag), "STAGING", "lab", &[]));
        assert!(!applies(Some(&json("{}")), "STAGING", "lab", &[]));
        assert!(applies(
            Some(&json(r#"{"default": true}"#)),
            "STAGING",
            "lab",
            &[]
        ));
    }

    #[test]
    fn modifications_set_prefix_suffix_and_skip_untyped_roots() {
        let modifiers = vec![json(
            r#"{"conditions": {"tenants": ["lab"]}, "modifications": {
                "query": "prefix::// lab\n",
                "scheduling": {"frequency": "1h"},
                "dispatch.latest_time": "now",
                "template": "NONE",
                "trigger": "suffix:: (lab)",
                "severity": "high"
            }}"#,
        )];
        let block = json(
            r#"{"status": "STAGING", "query": "T | take 1", "scheduling": {"lookback": "2h"}}"#,
        );
        let applied = apply(&modifiers, "sentinel", &block, "lab");
        assert_eq!(
            applied.get("query").and_then(Json::as_str),
            Some("// lab\nT | take 1")
        );
        assert_eq!(
            applied.get("scheduling").map(Json::to_compact).as_deref(),
            Some(r#"{"lookback":"2h","frequency":"1h"}"#)
        );
        assert!(applied.get("dispatch").is_none());
        assert_eq!(applied.get("template"), Some(&Json::Null));
        // A key the model does not have is left to the deployer.
        assert!(applied.get("severity").is_none());
        // A prefix or suffix on a key the block lacks sets the operand.
        assert_eq!(
            applied.get("trigger").and_then(Json::as_str),
            Some(" (lab)")
        );
        assert_eq!(apply(&modifiers, "sentinel", &block, "prod"), block);
    }

    #[test]
    fn mappings_flatten_with_the_plain_values_first() {
        let Json::Object(data) = json(r#"{"a": {"b": 1, "c": {}}, "d": 2}"#) else {
            unreachable!()
        };
        let flat = flatten_mapping(&data);
        let keys: Vec<&str> = flat.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["d", "a.b"]);
        assert_eq!(
            Json::Object(unroll("a.b", Json::Int(1))).to_compact(),
            r#"{"a":{"b":1}}"#
        );
        assert_eq!(
            Json::Object(unroll("a.a", Json::Int(1))).to_compact(),
            r#"{"a":1}"#
        );
    }
}
