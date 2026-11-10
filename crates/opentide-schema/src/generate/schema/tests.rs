use super::*;

use crate::configuration::toml::parse;
use crate::vocab::Vocabulary;

fn sources(config: &str, objects: &[Vocabulary]) -> Sources {
    let mut vocabularies = Vocabularies::bundled();
    for vocabulary in objects {
        vocabularies.insert(vocabulary.clone());
    }
    Sources {
        config: Arc::new(parse(config).unwrap()),
        vocabularies: Arc::new(vocabularies),
    }
}

fn objectives(entries: &[(&str, &str)]) -> Vocabulary {
    let keys: Vec<toml::Value> = entries
        .iter()
        .map(|(id, name)| {
            let mut entry = toml::Table::new();
            entry.insert("id".to_owned(), (*id).into());
            entry.insert("name".to_owned(), (*name).into());
            entry.insert("description".to_owned(), "Finds it. Then more.".into());
            toml::Value::Table(entry)
        })
        .collect();
    let mut table = toml::Table::new();
    table.insert("name".to_owned(), "Detection Objectives".into());
    table.insert("field".to_owned(), "objective".into());
    table.insert("key".to_owned(), "id".into());
    table.insert("keys".to_owned(), toml::Value::Array(keys));
    Vocabulary::from_table(table, "objective").unwrap()
}

const CONFIG: &str = r#"
[[deployment.statuses]]
name = "DEVELOPMENT"
description = "Being written."
strategy = "INERT"

[[deployment.statuses]]
name = "PRODUCTION"
description = "Live."
strategy = "RELEASE"

[[deployment.responders]]
name = "SOC"
description = "Tier 1."

[platforms.sentinel.platform]
enabled = true
name = "Microsoft Sentinel"
description = "The SIEM."

[[platforms.sentinel.tenants]]
name = "prod"
description = "Production."

[platforms.splunk.platform]
enabled = false

[[visibility.assets]]
name = "dc"
description = "Domain controllers"
criticality = "High"

[[visibility.logsources]]
name = "SecurityEvent"
description = "Windows events"
system = "sentinel"
tenants = ["prod"]
assets = ["dc", "missing"]

[[visibility.logsources]]
name = "SecurityEvent"
description = "The same table"
system = "defender_for_endpoint"
"#;

fn rule(identifier: &str, sources: &Sources) -> Value {
    revision_schema(identifier, sources).unwrap().to_value()
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap_or("<null>"))
        .collect()
}

#[test]
fn every_registered_revision_has_a_schema_and_no_other() {
    let sources = sources("", &[]);
    for identifier in ["rule::1.0", "rule::1.1", "threat::1.0", "objective::1.0"] {
        let schema = rule(identifier, &sources);
        assert_eq!(schema["additionalProperties"], false, "{identifier}");
        assert!(
            !serde_json::to_string(&schema).unwrap().contains("\"tide."),
            "{identifier} keeps a framework keyword"
        );
    }
    assert!(revision_schema("rule::9.9", &sources).is_none());
}

#[test]
fn the_family_requires_its_keys_first_and_keeps_the_models() {
    let schema = rule("threat::1.0", &sources("", &[]));
    let required = strings(&schema["required"]);
    assert_eq!(
        &required[..4],
        ["name", "criticality", "metadata", "threat"]
    );
    assert_eq!(schema["title"], "Threat Vector Schema");
    let schema = rule("rule::1.1", &sources("", &[]));
    let required = strings(&schema["required"]);
    assert_eq!(
        &required[..5],
        [
            "name",
            "metadata",
            "response",
            "description",
            "configurations"
        ]
    );
    assert_eq!(
        required.iter().filter(|key| **key == "name").count(),
        1,
        "{required:?}"
    );
}

#[test]
fn metadata_schema_is_the_revisions_identifier() {
    let schema = rule("rule::1.1", &sources("", &[]));
    let metadata = deref_pointer(&schema, "/properties/metadata");
    let pinned = schema
        .pointer(&format!("{metadata}/properties/schema"))
        .unwrap();
    assert_eq!(pinned["const"], "rule::1.1");
    assert_eq!(pinned["type"], "string");
}

#[test]
fn a_pinned_vocabulary_becomes_an_enum_with_its_texts() {
    let schema = rule("rule::1.1", &sources("", &[]));
    let metadata = deref_pointer(&schema, "/properties/metadata");
    let tlp = schema
        .pointer(&format!("{metadata}/properties/tlp"))
        .unwrap();
    assert_eq!(
        strings(&tlp["enum"]),
        ["clear", "green", "amber", "amber+strict", "red"]
    );
    assert_eq!(tlp["markdownEnumDescriptions"].as_array().unwrap().len(), 5);
    assert_eq!(tlp["enumDescriptions"].as_array().unwrap().len(), 5);
    let markdown = tlp["markdownEnumDescriptions"][0].as_str().unwrap();
    assert!(
        markdown.starts_with("### Clear\n\n**Identifier**: `TLP:CLEAR`"),
        "{markdown}"
    );
    assert!(markdown.contains("_Vocabulary_ : `"), "{markdown}");
}

#[test]
fn a_nullable_field_keeps_null_beside_its_enum() {
    let schema = rule("rule::1.1", &sources("", &[]));
    let severity = &schema["properties"]["severity"];
    let values = strings(&severity["enum"]);
    assert_eq!(values.last(), Some(&"<null>"), "{values:?}");
    assert!(values.contains(&"High"), "{values:?}");
}

#[test]
fn model_vocabularies_offer_search_hints_after_their_values() {
    let objectives = objectives(&[
        ("00000000-0000-4000-8000-000000000001", "Credential access"),
        ("00000000-0000-4000-8000-000000000002", "Lateral movement"),
    ]);
    let schema = rule("rule::1.1", &sources("", &[objectives]));
    let values = strings(&schema["properties"]["detection_model"]["enum"]);
    assert_eq!(
        values,
        [
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000002",
            "00000000-0000-4000-8000-000000000001 #Credential access",
            "00000000-0000-4000-8000-000000000002 #Lateral movement",
            "<null>",
        ]
    );
    let plain = strings(&schema["properties"]["detection_model"]["enumDescriptions"]);
    assert_eq!(plain[0], "Credential access: Finds it.");
}

#[test]
fn an_empty_vocabulary_offers_the_empty_string() {
    let schema = rule("rule::1.1", &sources("", &[objectives(&[])]));
    assert_eq!(
        strings(&schema["properties"]["detection_model"]["enum"]),
        ["", "<null>"]
    );
}

#[test]
fn long_hints_are_abbreviated_unless_the_field_says_not_to() {
    let mut entry = Entry {
        key: "T1".to_owned(),
        name: "Use of a tool and an agent with credentials to escalate privileges".to_owned(),
        version: "1.0".parse().unwrap(),
        removed: None,
        description: String::new(),
        icon: String::new(),
        link: String::new(),
        stages: Vec::new(),
        extra: toml::Table::new(),
    };
    assert_eq!(
        search_hint("T1", &entry, false),
        "T1 #  tool & agent w/ credentials escalate privileges"
    );
    assert_eq!(
        search_hint("T1", &entry, true),
        "T1 #Use of a tool and an agent with credentials to escalate privileges"
    );
    entry.name = "Short".to_owned();
    entry
        .extra
        .insert("alias".to_owned(), toml::Value::Array(vec!["S".into()]));
    assert_eq!(search_hint("T1", &entry, false), "T1 #Short, S");
}

#[test]
fn configurations_offer_each_enabled_platform_with_its_statuses_and_tenants() {
    let schema = rule("rule::1.1", &sources(CONFIG, &[]));
    let configurations = &schema["properties"]["configurations"];
    let platforms: Vec<&String> = configurations["properties"]
        .as_object()
        .unwrap()
        .keys()
        .collect();
    assert_eq!(platforms, ["sentinel"]);
    let sentinel = &configurations["properties"]["sentinel"];
    assert_eq!(sentinel["title"], "Microsoft Sentinel");
    assert_eq!(sentinel["description"], "The SIEM.");
    assert_eq!(sentinel["type"], "object");
    assert_eq!(sentinel["additionalProperties"], false);
    assert_eq!(
        &strings(&sentinel["required"])[..4],
        ["status", "query", "scheduling", "alert"]
    );
    assert_eq!(
        strings(&sentinel["properties"]["status"]["enum"]),
        ["DEVELOPMENT", "PRODUCTION"]
    );
    let status_docs = strings(&sentinel["properties"]["status"]["markdownEnumDescriptions"]);
    assert_eq!(
        status_docs[1],
        "**Strategy**: `RELEASE` - _Deployment from the default branch (also called trunk, or \
         main branch)_\n\nLive."
    );
    let tenants = &sentinel["properties"]["tenants"];
    assert_eq!(strings(&tenants["items"]["enum"]), ["prod"]);
    assert_eq!(tenants["uniqueItems"], true);
    assert_eq!(
        strings(&sentinel["properties"]["schema"]["enum"]),
        ["platform::sentinel::1.0", "<null>"]
    );
    // The definition itself is not narrowed: only the recomposed copy is.
    assert!(
        schema["$defs"]["SentinelConfig"]["properties"]["status"]
            .get("enum")
            .is_none()
    );
}

#[test]
fn no_enabled_platform_recomposes_nothing() {
    let schema = rule("rule::1.1", &sources("", &[]));
    assert_eq!(
        schema["properties"]["configurations"]["properties"],
        json!({})
    );
    assert_eq!(
        schema["properties"]["configurations"]["recomposition"],
        "systems"
    );
}

#[test]
fn responders_constrain_the_field_only_when_configured() {
    let configured = rule("rule::1.1", &sources(CONFIG, &[]));
    let response = deref_pointer(&configured, "/properties/response/anyOf/0");
    let responders = configured
        .pointer(&format!("{response}/properties/responders"))
        .unwrap();
    assert_eq!(strings(&responders["enum"]), ["SOC", "<null>"]);
    let bare = rule("rule::1.1", &sources("", &[]));
    let response = deref_pointer(&bare, "/properties/response/anyOf/0");
    let responders = bare
        .pointer(&format!("{response}/properties/responders"))
        .unwrap();
    assert!(responders.get("enum").is_none(), "{responders}");
}

#[test]
fn signals_name_the_configured_log_sources_bare_and_qualified() {
    let schema = rule("objective::1.0", &sources(CONFIG, &[]));
    let text = serde_json::to_string(&schema).unwrap();
    let start = text.find("\"SecurityEvent\"").unwrap();
    assert!(start > 0);
    let offer = logsources(&parse(CONFIG).unwrap()).unwrap();
    assert_eq!(
        offer.values,
        [
            json!("SecurityEvent"),
            json!("sentinel::SecurityEvent"),
            json!("sentinel::prod::SecurityEvent"),
            json!("defender_for_endpoint::SecurityEvent"),
        ]
    );
    assert!(offer.markdown[0].contains("---\n\n### SecurityEvent"));
    assert!(offer.markdown[0].contains("_Warning_: Asset not found"));
    assert!(offer.markdown[0].contains("_Criticality_: High"));
}

#[test]
fn the_enum_lands_on_the_string_or_array_branch() {
    let keywords: Map<String, Value> = serde_json::from_value(json!({"enum": ["a"]})).unwrap();
    let mut union: Map<String, Value> = serde_json::from_value(json!({
        "anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}},
                  {"type": "array", "items": {"type": "object"}}, {"type": "null"}]
    }))
    .unwrap();
    apply_enum(&mut union, &keywords);
    assert_eq!(
        Value::Object(union),
        json!({"anyOf": [
            {"type": "string", "enum": ["a"]},
            {"type": "array", "items": {"enum": ["a"]}, "uniqueItems": true},
            {"type": "array", "items": {"type": "object"}},
            {"type": "null"},
        ]})
    );
    let mut list: Map<String, Value> =
        serde_json::from_value(json!({"type": ["array", "null"], "items": {"type": "string"}}))
            .unwrap();
    apply_enum(&mut list, &keywords);
    assert_eq!(list["items"], json!({"enum": ["a"]}));
    let mut integer: Map<String, Value> =
        serde_json::from_value(json!({"type": ["integer", "null"]})).unwrap();
    apply_enum(&mut integer, &keywords);
    assert!(integer.get("enum").is_none());
}

#[test]
fn objects_are_closed_unless_they_say_otherwise() {
    let mut schema = Schema::try_from(json!({
        "properties": {
            "open": {"type": "object"},
            "map": {"type": "object", "additionalProperties": {"type": "string"}},
            "any": {"type": "object", "additionalProperties": true},
        }
    }))
    .unwrap();
    CloseObjects.transform(&mut schema);
    let value = schema.to_value();
    assert_eq!(value["properties"]["open"]["additionalProperties"], false);
    assert_eq!(
        value["properties"]["map"]["additionalProperties"],
        json!({"type": "string"})
    );
    assert_eq!(value["properties"]["any"]["additionalProperties"], true);
}

#[test]
fn the_visibility_schema_is_the_configuration_models() {
    let schema = visibility_schema().to_value();
    assert_eq!(schema["title"], "visibility.toml");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(strings(&schema["required"]), ["logsources"]);
    assert_eq!(
        schema["$defs"]["VisibilityLogSource"]["properties"]["columns"]["type"],
        json!(["object", "null"])
    );
}

#[test]
fn the_editor_text_is_annotated() {
    let schema = revision_schema("threat::1.0", &sources("", &[])).unwrap();
    let text = editor_text(&schema);
    assert!(text.ends_with("}\n"));
    assert!(
        text.contains("\"$comment\": \"Generated by opentide"),
        "{}",
        &text[..400]
    );
    assert!(text.is_ascii());
}
