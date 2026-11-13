//! Platform block schema metadata for editor schemas and templates
//! (`models/platform_schema.py`): which keys each block requires besides
//! what its model requires, the titles and `tide.*` keys of the shared
//! properties, and the `schema` identifiers a block offers.

use serde_json::{Value, json};

use crate::objects::platform::{PLATFORM_CONFIG_MODELS, Registered};

/// The keys a platform block requires (`_REQUIRED`), by its key under
/// `configurations`. Not Splunk's `scheduling`: a correlation search has
/// nothing to schedule, so the model, the deployer and the template all leave
/// it optional.
pub fn required(platform: &str) -> &'static [&'static str] {
    match platform {
        "splunk" => &["status", "query"],
        "sentinel" => &["status", "query", "scheduling", "alert"],
        "defender_for_endpoint" => &[
            "status",
            "query",
            "alert",
            "impacted_entities",
            "scheduling",
        ],
        "sentinel_one" => &["status", "condition"],
        "crowdstrike" => &["status", "query", "details", "schedule"],
        "harfanglab" | "elastic" | "sysdig" => &["status"],
        // Carbon Black, and the oracle's default for a model it does not list.
        _ => &["status", "query"],
    }
}

/// `platform_schema_identifiers`: the `schema` identifiers a block accepts,
/// its registered revision.
pub fn schema_identifiers(entry: &Registered) -> Vec<&'static str> {
    vec![entry.schema]
}

/// `platform_root_extras`: the block's root-level schema extras, `required`
/// and `property_extras` (`status`, `contributors`, `tenants` and `schema`),
/// keyed by YAML key. `schema` offers and accepts only the identifiers the
/// model registers, and `null`, which validation accepts too.
pub fn root_extras(entry: &Registered) -> Value {
    let identifiers = schema_identifiers(entry);
    let mut choices: Vec<Value> = identifiers.iter().map(|id| json!(id)).collect();
    choices.push(Value::Null);
    let platform = entry.schema.split("::").nth(1).unwrap_or(entry.key);
    json!({
        "required": required(entry.key),
        "property_extras": {
            "status": {"title": "Status of the use-case", "tide.config.statuses": true},
            "contributors": {"title": "Development Contributors"},
            "tenants": {"title": "Target Tenants", "tide.config.system.tenants": platform},
            "schema": {
                "title": "Schema identifier and version",
                "enum": choices,
                "default": identifiers.last().copied(),
            },
        },
    })
}

/// [`root_extras`] for every block, by key.
pub fn all_root_extras() -> Vec<(&'static str, Value)> {
    PLATFORM_CONFIG_MODELS
        .iter()
        .map(|entry| (entry.key, root_extras(entry)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_root_extras_follow_the_oracle() {
        let extras = all_root_extras();
        assert_eq!(extras.len(), crate::platforms::COUNT);
        let sentinel = &extras[0].1;
        assert_eq!(
            sentinel["required"],
            json!(["status", "query", "scheduling", "alert"])
        );
        assert_eq!(
            sentinel["property_extras"]["schema"],
            json!({
                "title": "Schema identifier and version",
                "enum": ["platform::sentinel::1.0", null],
                "default": "platform::sentinel::1.0",
            })
        );
        assert_eq!(
            sentinel["property_extras"]["tenants"]["tide.config.system.tenants"],
            "sentinel"
        );
        let carbon = extras
            .iter()
            .find(|(key, _)| *key == "carbon_black_cloud")
            .unwrap();
        assert_eq!(carbon.1["required"], json!(["status", "query"]));
        assert_eq!(
            carbon.1["property_extras"]["tenants"]["tide.config.system.tenants"],
            "carbon_black_cloud"
        );
    }
}
