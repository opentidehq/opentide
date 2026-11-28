use super::*;

use crate::configuration::toml::parse;
use crate::vocab::offer::{HINT_ABBREVIATIONS, dropdown, search_hint, search_text, summary_in};
use crate::vocab::{Entry, Vocabulary};

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
system = "microsoft_defender"
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
        description: crate::vocab::Description::default(),
        icon: String::new(),
        link: String::new(),
        stages: Vec::new(),
        extra: toml::Table::new(),
    };
    // Whole words only, and none dropped: `Use` and `to` stay.
    assert_eq!(
        search_hint("T1", &entry, false),
        "T1 #Use of a tool & an agent w/ credentials to escalate privileges"
    );
    entry.name = "User Activity Based Checks used with Andromeda and Usenet sandboxes".to_owned();
    assert_eq!(
        search_hint("T1", &entry, false),
        "T1 #User Activity Based Checks used w/ Andromeda & Usenet sandboxes"
    );
    entry.name = "Use of a tool and an agent with credentials to escalate privileges".to_owned();
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

/// Every search hint of the bundled ATT&CK and actor vocabularies says each
/// word of the entry's name and aliases, whole or as one of
/// [`HINT_ABBREVIATIONS`]: none loses letters (`Bypass User Account Control`
/// once read `Bypass  r Account Control`) and none is dropped.
#[test]
fn no_search_hint_of_the_bundled_vocabularies_loses_letters_from_a_word() {
    let mut checked = 0;
    let mut abbreviated = 0;
    for field in ["att&ck", "actors"] {
        let vocabulary = crate::vocab::bundled::get(field).unwrap();
        for entry in vocabulary.entries.values() {
            let hint = search_hint(&entry.key, entry, false);
            let (value, shown) = hint.split_once(" #").unwrap();
            assert_eq!(value, entry.key, "{hint}");
            let tips = search_text(entry);
            let words: Vec<&str> = tips.split(' ').collect();
            let shown: Vec<&str> = shown.split(' ').collect();
            assert_eq!(
                words.len(),
                shown.len(),
                "a word was dropped: {hint} ({tips})"
            );
            for (word, said) in words.iter().zip(&shown) {
                assert!(
                    word == said || HINT_ABBREVIATIONS.contains(&(*word, *said)),
                    "`{word}` is shown as `{said}`: {hint}"
                );
            }
            checked += 1;
            abbreviated += usize::from(shown != words);
        }
    }
    assert!(checked > 2000, "{checked} entries");
    assert!(abbreviated > 0, "no hint was long enough to abbreviate");
    let attack = crate::vocab::bundled::get("att&ck").unwrap();
    let uac = &attack.entries["T1548.002"];
    assert_eq!(
        search_hint("T1548.002", uac, false),
        "T1548.002 #Abuse Elevation Control Mechanism: Bypass User Account Control"
    );
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
            json!("microsoft_defender::SecurityEvent"),
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
fn a_vocabulary_union_defined_apart_is_written_in_place() {
    let mut schema = json!({
        "properties": {
            "killchain": {"anyOf": [{"$ref": "#/$defs/Killchain"}, {"type": "null"}], "tide.vocab": true},
            "other": {"anyOf": [{"$ref": "#/$defs/Killchain"}, {"type": "null"}]},
            "body": {"anyOf": [{"$ref": "#/$defs/Body"}, {"type": "null"}], "tide.vocab": true},
        },
        "$defs": {
            "Killchain": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
            "Body": {"type": "object", "properties": {"a": {"type": "string"}}},
        },
    });
    let defs = schema["$defs"].clone();
    inline_vocabulary_unions(&mut schema);
    assert_eq!(
        schema["properties"]["killchain"]["anyOf"],
        json!([{"type": "string"}, {"type": "array", "items": {"type": "string"}}, {"type": "null"}])
    );
    // A field without a vocabulary, a model, and the definitions are kept.
    assert_eq!(
        schema["properties"]["other"]["anyOf"][0],
        json!({"$ref": "#/$defs/Killchain"})
    );
    assert_eq!(
        schema["properties"]["body"]["anyOf"][0],
        json!({"$ref": "#/$defs/Body"})
    );
    assert_eq!(schema["$defs"], defs);
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
        text.chars().take(400).collect::<String>()
    );
    // UTF-8 as it is: no `\uXXXX` escape stands for a character past ASCII.
    assert!(!text.contains("\\u00"));
}

#[test]
fn an_all_lower_case_name_is_title_cased_by_english_rules() {
    let vocabulary = objectives(&[
        ("o1", "command and control over it's own channel"),
        ("o2", "already Cased name"),
        ("o3", "o3"),
    ]);
    let heading = |key: &str| -> String {
        let entry = &vocabulary.entries[key];
        dropdown(&vocabulary, entry, &[])
            .lines()
            .next()
            .unwrap()
            .to_owned()
    };
    // Small words stay lower case and an apostrophe starts no word.
    assert_eq!(
        heading("o1"),
        "### Command and Control Over It's Own Channel"
    );
    // A name that has a capital is written as it is.
    assert_eq!(heading("o2"), "### already Cased name");
    assert_eq!(heading("o3"), "### O3");
}

/// The `tide.*` keywords [`ResolveValues`] does not resolve: no object model
/// may carry one, or its schema would silently leave out what the keyword
/// asks for (a model that needs one adds its branch, with a test).
#[test]
fn no_model_carries_a_keyword_the_generator_does_not_resolve() {
    let unresolved = [
        keys::META_DEPRECATION,
        keys::CONFIG_VISIBILITY_DETECTORS,
        keys::CONFIG_PARAMETER_LIST,
        keys::CONFIG_SYSTEMS_ENABLED,
        keys::VOCAB_STAGES,
    ];
    let texts: Vec<(String, String)> = ["rule::1.0", "rule::1.1", "threat::1.0", "objective::1.0"]
        .into_iter()
        .map(|identifier| {
            (
                identifier.to_owned(),
                serde_json::to_string(&revision_model_schema(identifier).unwrap()).unwrap(),
            )
        })
        .collect();
    for (name, text) in &texts {
        // The derived schemas do carry the keywords that are resolved.
        assert!(text.contains("\"tide."), "{name}: no tide keyword at all");
        for keyword in unresolved {
            assert!(
                !text.contains(&format!("\"{keyword}\"")),
                "{name} carries {keyword}, which the generator does not resolve"
            );
        }
    }
}

/// The description summary is worked out once per distinct text: a hit
/// answers what the Markdown clean-up answers, an edited description is
/// worked out afresh, and the cache starts over at its bound.
#[test]
fn a_description_summary_is_kept_by_its_text_and_bounded() {
    use std::collections::HashMap;
    use std::sync::Mutex;

    let cache = Mutex::new(HashMap::new());
    let text = "Runs **commands** through [a shell](https://example.org). And more.";
    let expected =
        super::super::annotate::first_sentence(&super::super::annotate::plain_text(text, true));
    assert_eq!(expected, "Runs commands through a shell.");
    assert_eq!(summary_in(&cache, 2, text), expected);
    assert_eq!(cache.lock().unwrap().get(text), Some(&expected));
    // A hit is the cached answer, not a fresh one.
    cache
        .lock()
        .unwrap()
        .insert(text.to_owned(), "cached".to_owned());
    assert_eq!(summary_in(&cache, 2, text), "cached");
    // Another text is its own entry; the third starts the cache over.
    assert_eq!(summary_in(&cache, 2, "Second. Third."), "Second.");
    assert_eq!(cache.lock().unwrap().len(), 2);
    assert_eq!(summary_in(&cache, 2, "Fourth `x`."), "Fourth x.");
    let kept = cache.lock().unwrap();
    assert_eq!(kept.len(), 1);
    assert!(kept.contains_key("Fourth `x`."));
}

/// The offers `build.rs` makes (`OFFERED` there) are the bundled offers the
/// schemas and the field catalog ask for, no fewer and no more.
#[test]
fn the_build_makes_the_offers_the_catalog_asks_for() {
    use crate::configuration::resolve::{Instance, resolve};
    use crate::vocab::bundled_offers;

    ASKED.with(|asked| asked.borrow_mut().clear());
    let resolved = resolve(&Instance {
        skip_parent: true,
        ..Instance::default()
    })
    .unwrap();
    let sources = Sources {
        config: Arc::new(resolved.tree),
        vocabularies: Arc::new(Vocabularies::bundled()),
    };
    // Both phases that resolve vocabularies: the language server's field catalog
    // and `generate schemas` (each registered revision's editor schema).
    let _ = crate::generate::catalog::fields_catalog("test", &sources);
    let schemas = crate::generate::workspace::schema_artifacts(&sources);
    assert!(!schemas.is_empty());
    let mut asked: Vec<(String, bool)> = ASKED.with(|asked| asked.borrow().clone());
    asked.sort();
    asked.dedup();
    let mut made: Vec<(String, bool)> = bundled_offers::offered()
        .map(|(field, scoped)| (field.to_owned(), scoped))
        .collect();
    made.sort();
    assert_eq!(
        asked, made,
        "an offer the build does not make, or makes for nothing"
    );
}

/// The offer read from what the build made is the offer worked out at run
/// time from the bundled document, for every reference the build makes one of
/// (the bytes of the field catalog, in `tests/catalog.rs`, hold the rest).
#[test]
fn what_the_build_made_is_what_is_worked_out_at_run_time() {
    use crate::vocab::{VocabRef, bundled, bundled_offers};

    let vocabularies = Vocabularies::bundled();
    let mut checked = 0;
    for (reference, scoped) in bundled_offers::offered() {
        let options = VocabOptions {
            scoped,
            no_wrap: false,
        };
        let vocab: VocabRef = reference.parse().unwrap();
        let worked_out = offer_of(&bundled::get(&vocab.field).unwrap(), &vocab, options);
        assert!(!worked_out.values.is_empty(), "{reference}");
        assert_eq!(
            bundled_offer(reference, scoped),
            Some(&worked_out),
            "{reference} (scoped: {scoped})"
        );
        // And through the lookup the schemas use, against the same lookup for a
        // vocabulary the workspace brings (a copy of the bundled document), which
        // is worked out and never read from what the build made.
        let mut brought = Vocabularies::bundled();
        brought.insert((*bundled::get(&vocab.field).unwrap()).clone());
        assert!(!brought.uses_bundled(&vocab.field));
        assert!(vocabularies.uses_bundled(&vocab.field));
        assert_eq!(
            vocabulary_offer(&vocabularies, reference, options),
            vocabulary_offer(&brought, reference, options),
            "{reference} (scoped: {scoped})"
        );
        checked += 1;
    }
    assert_eq!(checked, 16);
}

/// A vocabulary the workspace brings, a data root's vocabularies, a field that
/// asks for unwrapped hints and a reference the build made nothing of are
/// worked out from the vocabularies the workspace has.
#[test]
fn a_vocabulary_of_the_workspace_is_worked_out_not_read() {
    use crate::vocab::bundled_offers;

    let mut replaced = toml::Table::new();
    replaced.insert("name".to_owned(), "Traffic Light Protocol".into());
    replaced.insert("field".to_owned(), "tlp".into());
    replaced.insert("key".to_owned(), "name".into());
    let mut entry = toml::Table::new();
    entry.insert("name".to_owned(), "mine".into());
    replaced.insert("keys".to_owned(), toml::Value::Array(vec![entry.into()]));
    let own = Vocabulary::from_table(replaced, "tlp").unwrap();
    let options = VocabOptions {
        scoped: false,
        no_wrap: false,
    };
    assert!(bundled_offers::offered().any(|offered| offered == ("tlp::1.0", false)));
    let bundled_only = vocabulary_offer(&Vocabularies::bundled(), "tlp::1.0", options);
    assert_eq!(
        bundled_only.values,
        ["clear", "green", "amber", "amber+strict", "red"]
    );
    // A document of the workspace replaces the bundled one.
    let mut vocabularies = Vocabularies::bundled();
    vocabularies.insert(own);
    assert_eq!(
        vocabulary_offer(&vocabularies, "tlp::1.0", options).values,
        ["mine"]
    );
    // A data root's vocabularies are not the bundled ones.
    let (rooted, _) = Vocabularies::from_files([]);
    assert_eq!(vocabulary_offer(&rooted, "tlp::1.0", options).values, [""]);
    // A reference the build made nothing of, and unwrapped hints, are worked out.
    let pin = vocabulary_offer(&Vocabularies::bundled(), "tlp::0.1", options);
    assert_eq!(pin.values, [""]);
    let unwrapped = vocabulary_offer(
        &Vocabularies::bundled(),
        "att&ck::1.2",
        VocabOptions {
            scoped: false,
            no_wrap: true,
        },
    );
    assert_ne!(
        unwrapped,
        vocabulary_offer(&Vocabularies::bundled(), "att&ck::1.2", options)
    );
}
