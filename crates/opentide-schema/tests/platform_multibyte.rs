//! Every platform block with multi-byte text in each of its values (#1946):
//! a rule with a valid block for each built-in platform, one value at a time
//! (and then every value of a block at once) replaced by text whose
//! characters are wider than a byte (`é`, `😀`, a combining accent, CJK, a
//! byte order mark) where a number, a unit or a name was. The models read
//! it through the revision registry (both rule revisions), the block parser
//! and the advisories: a value is accepted or reported with a placed error,
//! and nothing panics. #1926 was a `split_at` on the byte before a
//! multi-byte last character.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the template is valid JSON and YAML"
)]

use opentide_schema::node;
use opentide_schema::objects::platform;
use opentide_schema::revisions;
use proptest::prelude::*;
use serde_json::{Value, json};

/// A rule with a valid block for every built-in platform (the semantic fuzz
/// target's template, `fuzz/seeds/semantic/template.yaml`).
fn template() -> Value {
    json!({
        "name": "Multi-byte template",
        "metadata": {
            "uuid": "8d50f9cf-e13f-4365-93d7-069988cfdd2e",
            "schema": "rule::1.1",
            "version": 1,
            "created": "2026-11-27",
            "modified": "2026-11-27",
            "tlp": "amber",
            "author": "opentide"
        },
        "description": "A rule with a block for every built-in platform.",
        "response": {"alert_severity": "Informational"},
        "configurations": {
            "sentinel": {
                "enabled": true, "status": "STAGING",
                "query": "SecurityEvent | where EventID == 4688",
                "scheduling": {"frequency": "1h", "lookback": "1h"},
                "alert": {"suppression": false, "create_incident": true},
                "grouping": {"event": "SingleAlert", "alert": {"enabled": false}}
            },
            "microsoft_defender": {
                "enabled": true, "status": "STAGING",
                "query": "DeviceProcessEvents | where FileName == \"cmd.exe\"",
                "schedule": {"frequency": "1H"},
                "scope": {"device_groups": ["Servers"]}
            },
            "splunk": {
                "enabled": true, "status": "STAGING",
                "query": "index=main EventCode=4688",
                "scheduling": {"timerange": {"lookback": "1d"}}
            },
            "sentinel_one": {
                "enabled": true, "status": "STAGING",
                "condition": {
                    "type": "Single Event",
                    "single_event": {"query": "EventType = \"Process Creation\""}
                }
            },
            "crowdstrike": {
                "enabled": true, "status": "STAGING",
                "details": {"trigger": "verbose", "outcome": "detection"},
                "schedule": {"frequency": "1h", "lookback": "1h"},
                "query": "#event_simpleName=ProcessRollup2"
            },
            "harfanglab": {
                "enabled": true, "status": "STAGING",
                "sigma": {
                    "logsource": {"category": "process_creation", "product": "windows"},
                    "selections": [{"name": "selection", "field": "Image", "value": "cmd.exe"}],
                    "condition": "selection"
                }
            },
            "carbon_black_cloud": {
                "enabled": true, "status": "STAGING", "query": "process_name:cmd.exe"
            },
            "elastic": {
                "enabled": true, "status": "STAGING", "type": "query",
                "query": "process.name: \"cmd.exe\""
            },
            "sysdig": {
                "enabled": true, "status": "STAGING",
                "condition": "spawned_process and proc.name = \"sh\""
            },
            "bitdefender": {
                "enabled": true, "status": "STAGING", "severity": "Low",
                "detection": {
                    "target": "process",
                    "criteria": [{"field": "Process.Name", "is": "cmd.exe"}]
                }
            },
            "graylog": {
                "enabled": true, "status": "STAGING", "query": "process_name:cmd.exe"
            },
            "exabeam": {
                "enabled": true, "status": "STAGING",
                "sequences": [{"query": "activity_type:\"process-create\""}]
            },
            "google_secops": {
                "enabled": true, "status": "STAGING",
                "events": "$e.metadata.event_type = \"PROCESS_LAUNCH\"",
                "outcome": "$risk_score = 40",
                "condition": "$e"
            }
        }
    })
}

/// Text that ends, starts or is made of characters wider than a byte, in
/// the shapes the models parse: counts with units, names, numbers.
const MULTI_BYTE: &[&str] = &[
    "é",
    "😀",
    "1é",
    "1😀",
    "é1",
    "😀1h",
    "1hé",
    "1h😀",
    "NRTé",
    "9999999999999999é",
    "9999999999999999d😀",
    "e\u{301}",
    "1\u{301}",
    "\u{feff}1h",
    "1\u{2028}h",
    "中文",
    "1中",
    "ÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉÉ",
];

/// The JSON pointer of every scalar under `value`.
fn leaves(value: &Value, pointer: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                leaves(child, &format!("{pointer}/{key}"), out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                leaves(child, &format!("{pointer}/{index}"), out);
            }
        }
        _ => out.push(pointer.to_owned()),
    }
}

/// Each platform with the pointers of its block's scalars.
fn blocks() -> Vec<(String, Vec<String>)> {
    let template = template();
    let configurations = template["configurations"].as_object().unwrap();
    let blocks: Vec<(String, Vec<String>)> = configurations
        .iter()
        .map(|(platform, block)| {
            let mut out = Vec::new();
            leaves(block, &format!("/configurations/{platform}"), &mut out);
            (platform.clone(), out)
        })
        .collect();
    let mut ids: Vec<&str> = opentide_schema::platforms::PLATFORMS
        .iter()
        .map(|platform| platform.id)
        .collect();
    ids.sort_unstable();
    let mut named: Vec<&str> = blocks
        .iter()
        .map(|(platform, _)| platform.as_str())
        .collect();
    named.sort_unstable();
    assert_eq!(named, ids, "a block for every built-in platform");
    blocks
}

/// Reads `rule` as `validate` does, under each rule revision: the registry's
/// models, each block alone, and the advisories. A panic fails the test; an
/// error must say something and lie in the document.
fn read(rule: &Value) {
    for schema in ["rule::1.0", "rule::1.1"] {
        let mut rule = rule.clone();
        rule["metadata"]["schema"] = Value::from(schema);
        let text = serde_json::to_string_pretty(&rule).unwrap();
        let document = node::load(&text).unwrap();
        let lines = text.lines().count();
        if let Ok(read) = revisions::read(&document, "rule")
            && let Err(errors) = read.result
        {
            for error in &errors {
                assert!(!error.message.is_empty(), "{error:?}");
                if let Some(span) = &error.span {
                    assert!(span.line >= 1 && span.line <= lines + 1, "{error:?}");
                    assert!(span.end_column >= span.column, "{error:?}");
                }
            }
        }
        let root = document.root().unwrap();
        if let Some(configurations) = root.get("configurations") {
            for platform in opentide_schema::platforms::PLATFORMS {
                if let Some(block) = configurations.get(platform.id) {
                    let _ = platform::parse_platform_config(platform.id, block);
                }
            }
        }
        for advisory in platform::block_advisories(root, &[]) {
            assert!(!advisory.message.is_empty(), "{advisory:?}");
        }
    }
}

/// The template itself converts under the newest revision: every
/// replacement starts from a valid block.
#[test]
fn the_template_is_a_valid_rule() {
    let text = serde_json::to_string(&template()).unwrap();
    let document = node::load(&text).unwrap();
    let read = revisions::read(&document, "rule").unwrap();
    assert!(read.result.is_ok(), "{:?}", read.result.err());
}

/// #1926's input, through the models: a Defender frequency ending in a
/// multi-byte character is an error at its field, not a panic.
#[test]
fn a_defender_frequency_ending_in_a_multi_byte_character_is_an_error() {
    for frequency in ["1é", "1😀"] {
        let mut rule = template();
        rule["configurations"]["microsoft_defender"]["schedule"]["frequency"] =
            Value::from(frequency);
        let text = serde_json::to_string(&rule).unwrap();
        let document = node::load(&text).unwrap();
        let errors = revisions::read(&document, "rule")
            .unwrap()
            .result
            .unwrap_err();
        let paths: Vec<String> = errors
            .iter()
            .map(|error| {
                error
                    .field_path()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(".")
            })
            .collect();
        assert_eq!(
            paths,
            ["configurations.microsoft_defender.schedule.frequency"],
            "{frequency}"
        );
    }
}

/// Every scalar of every block, one at a time, with each multi-byte value.
#[test]
fn every_value_of_every_block_takes_multi_byte_text_without_a_panic() {
    let template = template();
    let mut count = 0;
    for (_, pointers) in blocks() {
        for pointer in &pointers {
            for text in MULTI_BYTE {
                let mut rule = template.clone();
                *rule.pointer_mut(pointer).unwrap() = Value::from(*text);
                read(&rule);
                count += 1;
            }
        }
    }
    assert!(count > 1000, "{count}");
}

/// Every scalar of a block at once.
#[test]
fn a_block_whose_every_value_is_multi_byte_text_does_not_panic() {
    let template = template();
    for (_, pointers) in blocks() {
        for text in MULTI_BYTE {
            let mut rule = template.clone();
            for pointer in &pointers {
                *rule.pointer_mut(pointer).unwrap() = Value::from(*text);
            }
            read(&rule);
        }
    }
}

/// Text that mixes ASCII digits, units and words with characters wider
/// than a byte, anywhere in it.
fn multi_byte_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[0-9]{0,4}[a-zA-Z]{0,2}[é😀中\u{301}\u{feff}ÿ]{1,3}",
        "[é😀中\u{301}]{1,2}[0-9]{1,4}[smhdHDM]?",
        "[0-9a-zA-Z_.:$ é😀中\u{301}-]{1,12}",
        prop::sample::select(MULTI_BYTE.to_vec()).prop_map(str::to_owned),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any multi-byte text in any scalar of any block.
    #[test]
    fn any_multi_byte_text_in_any_block_value_does_not_panic(
        block in any::<prop::sample::Index>(),
        leaf in any::<prop::sample::Index>(),
        text in multi_byte_text(),
    ) {
        let blocks = blocks();
        let (_, pointers) = block.get(&blocks);
        let pointer = leaf.get(pointers);
        let mut rule = template();
        *rule.pointer_mut(pointer).unwrap() = Value::from(text);
        read(&rule);
    }
}
