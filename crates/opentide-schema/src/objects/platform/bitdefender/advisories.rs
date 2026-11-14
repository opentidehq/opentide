//! Bitdefender advisories (bitdefender-1.0, Advisories): warnings that never
//! reject a rule (0.28.0's `platforms/bitdefender/advisories.py`).
//!
//! GravityZone accepts each of these, but the rule then does not do what its
//! author most likely meant. `opentide validate` reports them as warnings,
//! and `opentide lint` with its `queries` check.

use crate::configuration::repr::quote;
use crate::node::{Node, Value};

use super::checks::{CRITERION_FIELD, RELATIONS, unknown_field_paths};
use super::criteria::criteria;

/// `bitdefender_registry_full_hive`.
pub const REGISTRY_FULL_HIVE: &str = "bitdefender_registry_full_hive";
/// `bitdefender_contains_no_wildcard`.
pub const CONTAINS_NO_WILDCARD: &str = "bitdefender_contains_no_wildcard";
/// `bitdefender_severity_collapsed`.
pub const SEVERITY_COLLAPSED: &str = "bitdefender_severity_collapsed";
/// An unknown field on a target outside the spec's table: the constraint
/// code, as a warning.
pub const UNKNOWN_FIELD: &str = CRITERION_FIELD;

/// The advisory codes (`ADVISORY_CODES`).
pub const ADVISORY_CODES: [&str; 3] =
    [REGISTRY_FULL_HIVE, CONTAINS_NO_WILDCARD, SEVERITY_COLLAPSED];

/// One advisory: its code, its path in the rule, and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// The code.
    pub code: &'static str,
    /// The path in the rule (`configurations.bitdefender.detection.criteria.0`).
    pub field_path: Vec<String>,
    /// The message.
    pub message: String,
}

/// What GravityZone sends for an `alert_severity` it has no level for.
fn collapsed(severity: &str) -> Option<&'static str> {
    match severity {
        "critical" => Some("High"),
        "informational" => Some("Low"),
        _ => None,
    }
}

fn block_path(rest: &[&str]) -> Vec<String> {
    ["configurations", "bitdefender"]
        .iter()
        .chain(rest)
        .map(|part| (*part).to_owned())
        .collect()
}

/// `S-<digits>-<digits>(-<digits>)*` then `\` or the end, case-insensitive,
/// at the start of `rest`: `HKEY_USERS\<SID>`, a user's hive.
fn user_sid(rest: &str) -> bool {
    let Some(tail) = rest
        .strip_prefix('S')
        .or_else(|| rest.strip_prefix('s'))
        .and_then(|tail| tail.strip_prefix('-'))
    else {
        return false;
    };
    let mut groups = 0;
    let mut rest = tail;
    loop {
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        if digits == 0 {
            return false;
        }
        groups += 1;
        rest = &rest[digits..];
        match rest.chars().next() {
            None | Some('\\') => return groups >= 2,
            Some('-') => rest = &rest[1..],
            Some(_) => return false,
        }
    }
}

/// The short hive name GravityZone matches for `key`'s full hive name, or
/// `None` (`short_hive`). Compared case-insensitively. `HKEY_USERS\<SID>…`
/// is `HKU`; any other `HKEY_USERS\…` key is `HKLU` (bitdefender-1.0,
/// Advisories).
pub fn short_hive(key: &str) -> Option<String> {
    let (hive, rest) = key.split_once('\\').unwrap_or((key, ""));
    let upper = hive.to_uppercase();
    if upper == "HKEY_USERS" {
        return Some(if user_sid(rest) { "HKU" } else { "HKLU" }.to_owned());
    }
    criteria().registry_hives.get(&upper).cloned()
}

fn get<'n>(node: &'n Node, key: &str) -> Option<&'n Node> {
    node.get(key).map(AsRef::as_ref)
}

fn strings(value: Option<&Node>, relation: &str) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let items: Vec<&Node> = match &value.value {
        Value::Seq(items) if relation == "any" => items.iter().map(AsRef::as_ref).collect(),
        _ => vec![value],
    };
    items
        .into_iter()
        .filter_map(|item| item.value.as_str().map(str::to_owned))
        .collect()
}

fn criteria_advisories(detection: &Node) -> Vec<Advisory> {
    let mut found = Vec::new();
    let Some(Value::Seq(criteria)) = get(detection, "criteria").map(|node| &node.value) else {
        return found;
    };
    for (index, criterion) in criteria.iter().enumerate() {
        let Value::Map(entries) = &criterion.value else {
            continue;
        };
        let field = get(criterion, "field").and_then(|field| field.value.as_str());
        let index = index.to_string();
        for relation in RELATIONS {
            if !entries
                .iter()
                .any(|entry| entry.key.value.as_str() == Some(relation))
            {
                continue;
            }
            let path = block_path(&["detection", "criteria", &index]);
            let values = strings(get(criterion, relation), relation);
            if field == Some("Registry.Key")
                && let Some(hint) = values.iter().find_map(|value| short_hive(value))
            {
                found.push(Advisory {
                    code: REGISTRY_FULL_HIVE,
                    field_path: path.clone(),
                    message: format!(
                        "Registry.Key starts with a full hive name, which GravityZone accepts \
                         and never matches; write {hint}"
                    ),
                });
            }
            if relation == "contains"
                && let Some(first) = values.first()
                && !first.contains(['*', '?'])
            {
                found.push(Advisory {
                    code: CONTAINS_NO_WILDCARD,
                    field_path: path,
                    message: format!(
                        "contains {} has no * or ? wildcard, so GravityZone matches it as \
                         written; write {} for a substring",
                        quote(first),
                        quote(&format!("*{first}*"))
                    ),
                });
            }
        }
    }
    found
}

/// `alert_severity` as text: a string as it is, any other value as YAML
/// writes it (`true`, `1.5`, `null`), as every message writes a value.
fn text(node: &Node) -> String {
    match &node.value {
        Value::Str(text) | Value::Datetime(text) => text.clone(),
        _ => crate::configuration::repr::node(node),
    }
}

/// Every advisory the rule's `bitdefender` block, as authored, earns
/// (`bitdefender_advisories`), on the rule's document.
pub fn advisories(rule: &Node) -> Vec<Advisory> {
    let Some(block) = get(rule, "configurations").and_then(|configurations| {
        get(configurations, "bitdefender").filter(|block| matches!(block.value, Value::Map(_)))
    }) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if let Some(detection) =
        get(block, "detection").filter(|node| matches!(node.value, Value::Map(_)))
    {
        found.extend(criteria_advisories(detection));
        // On a target whose field list the spec does not state, an unknown
        // field is a warning until the catalogue covers it (bitdefender-1.0).
        let target = get(detection, "target")
            .and_then(|target| target.value.as_str())
            .unwrap_or_default();
        found.extend(
            unknown_field_paths(detection)
                .into_iter()
                .map(|index| Advisory {
                    code: UNKNOWN_FIELD,
                    field_path: block_path(&["detection", "criteria", &index.to_string()]),
                    message: format!(
                        "the criteria catalogue lists no such field for target {}; GravityZone may \
                     refuse it",
                        quote(target)
                    ),
                }),
        );
    }
    let severity = get(rule, "response")
        .and_then(|response| get(response, "alert_severity"))
        .filter(|severity| crate::objects::platform::truthy(Some(severity)));
    if let Some(severity) = severity {
        let written = text(severity);
        let level = crate::objects::platform::python_strip(&written).to_lowercase();
        if let Some(collapsed) = collapsed(&level)
            && get(block, "severity").is_none_or(|value| matches!(value.value, Value::Null))
        {
            found.push(Advisory {
                code: SEVERITY_COLLAPSED,
                field_path: block_path(&[]),
                message: format!(
                    "GravityZone has three severities: alert_severity {written} is sent as \
                     {collapsed}; set configurations.bitdefender.severity to choose"
                ),
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use serde_json::{Value as Json, json};

    use super::*;
    use crate::objects::platform::json_node;

    fn rule(criteria: &Json, severity: Option<&str>, response: Option<&Json>) -> Json {
        let mut block = json!({
            "status": "STAGING",
            "detection": {"target": "registry", "criteria": criteria},
        });
        if let Some(severity) = severity {
            block["severity"] = json!(severity);
        }
        let mut rule = json!({"name": "R", "configurations": {"bitdefender": block}});
        if let Some(response) = response {
            rule["response"] = response.clone();
        }
        rule
    }

    fn found(rule: &Json) -> Vec<Advisory> {
        advisories(&json_node(rule))
    }

    fn codes(rule: &Json) -> Vec<&'static str> {
        found(rule)
            .into_iter()
            .map(|advisory| advisory.code)
            .collect()
    }

    #[test]
    fn a_full_hive_name_is_an_advisory_and_a_short_one_is_not() {
        for criterion in [
            json!({"field": "Registry.Key", "is": "HKEY_LOCAL_MACHINE\\Software\\Run"}),
            json!({"field": "Registry.Key", "contains": "hkey_current_user\\Software*"}),
            json!({"field": "Registry.Key", "any": ["HKLM\\Run", "HKEY_USERS\\x"]}),
        ] {
            assert!(
                codes(&rule(&json!([criterion]), None, None)).contains(&REGISTRY_FULL_HIVE),
                "{criterion}"
            );
        }
        let short = json!([{"field": "Registry.Key", "contains": "HKLM\\Software\\*"}]);
        assert!(codes(&rule(&short, None, None)).is_empty());
    }

    #[test]
    fn contains_without_a_wildcard_is_an_advisory() {
        let advisories = found(&rule(
            &json!([{"field": "Registry.Value", "contains": "Run"}]),
            None,
            None,
        ));
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].code, CONTAINS_NO_WILDCARD);
        assert_eq!(
            advisories[0].field_path,
            [
                "configurations",
                "bitdefender",
                "detection",
                "criteria",
                "0"
            ]
        );
        for value in ["*Run*", "Ru?"] {
            let criteria = json!([{"field": "Registry.Value", "contains": value}]);
            assert!(codes(&rule(&criteria, None, None)).is_empty());
        }
    }

    #[test]
    fn a_collapsed_severity_is_an_advisory_on_the_block() {
        for (alert_severity, severity, expected) in [
            ("Critical", None, vec![SEVERITY_COLLAPSED]),
            ("Informational", None, vec![SEVERITY_COLLAPSED]),
            ("Critical", Some("High"), vec![]),
            ("High", None, vec![]),
        ] {
            let response = json!({"alert_severity": alert_severity});
            assert_eq!(
                codes(&rule(&json!([]), severity, Some(&response))),
                expected
            );
        }
        let response = json!({"alert_severity": "Critical"});
        let advisories = found(&rule(&json!([]), None, Some(&response)));
        assert_eq!(advisories[0].field_path, ["configurations", "bitdefender"]);
    }

    #[test]
    fn a_rule_without_a_bitdefender_block_has_none() {
        assert!(found(&json!({"name": "R", "configurations": {"sysdig": {}}})).is_empty());
        assert!(found(&json!({"name": "R"})).is_empty());
    }

    #[test]
    fn the_messages_are_0_28_0s() {
        let criteria = json!([
            {"field": "Registry.Key", "any": ["HKLM\\Run", "HKEY_USERS\\x"]},
            {"field": "Registry.Value", "contains": "it's"}
        ]);
        let response = json!({"alert_severity": " Critical "});
        let messages: Vec<String> = found(&rule(&criteria, None, Some(&response)))
            .into_iter()
            .map(|advisory| advisory.message)
            .collect();
        assert_eq!(
            messages,
            [
                "Registry.Key starts with a full hive name, which GravityZone accepts and never \
                 matches; write HKLU",
                "contains \"it's\" has no * or ? wildcard, so GravityZone matches it as written; \
                 write \"*it's*\" for a substring",
                "GravityZone has three severities: alert_severity  Critical  is sent as High; set \
                 configurations.bitdefender.severity to choose",
            ]
        );
        let open = json!({"configurations": {"bitdefender": {"detection": {
            "target": "email", "criteria": [{"field": "Email.Nope", "is": "x"}]
        }}}});
        assert_eq!(
            found(&open)[0].message,
            "the criteria catalogue lists no such field for target \"email\"; GravityZone may \
             refuse it"
        );
    }

    #[test]
    fn the_hint_names_the_short_hive() {
        for (key, hint) in [
            ("HKEY_LOCAL_MACHINE\\Software", Some("HKLM")),
            ("hkey_current_user\\Software", Some("HKCU")),
            ("HKEY_CLASSES_ROOT\\.exe", Some("HKCR")),
            ("HKEY_CURRENT_CONFIG\\System", Some("HKCC")),
            (
                "HKEY_USERS\\S-1-5-21-1004336348-1177238915-682003330-512\\Software",
                Some("HKU"),
            ),
            ("HKEY_USERS\\.DEFAULT\\Software", Some("HKLU")),
            ("HKLM\\Software", None),
        ] {
            assert_eq!(short_hive(key).as_deref(), hint, "{key}");
            let advisories = found(&rule(
                &json!([{"field": "Registry.Key", "is": key}]),
                None,
                None,
            ));
            match hint {
                None => assert!(advisories.is_empty()),
                Some(hint) => assert!(advisories[0].message.ends_with(&format!("write {hint}"))),
            }
        }
    }

    #[test]
    fn full_hive_names_have_short_ones() {
        assert_eq!(
            short_hive("HKEY_LOCAL_MACHINE\\Software").as_deref(),
            Some("HKLM")
        );
        assert_eq!(short_hive("hkey_current_user\\x").as_deref(), Some("HKCU"));
        assert_eq!(
            short_hive("HKEY_USERS\\S-1-5-21-1-2-3\\Software").as_deref(),
            Some("HKU")
        );
        assert_eq!(short_hive("HKEY_USERS\\s-1-5").as_deref(), Some("HKU"));
        assert_eq!(short_hive("HKEY_USERS\\S-1").as_deref(), Some("HKLU"));
        assert_eq!(short_hive("HKEY_USERS\\.DEFAULT").as_deref(), Some("HKLU"));
        assert_eq!(short_hive("HKEY_USERS").as_deref(), Some("HKLU"));
        assert_eq!(short_hive("HKLM\\Software"), None);
    }
}
