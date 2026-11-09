//! Property (UC-1.2, #808): every valid object generated from the models
//! round-trips. It is serialised ([`node::to_yaml`], serde-saphyr) and read
//! back through the YAML 1.2 loader and the structural conversion, which
//! report no error and return an equal value.

#![expect(
    clippy::unwrap_used,
    reason = "helpers of the tests: a strategy that cannot build fails them"
)]

use opentide_schema::from_node::from_document;
use opentide_schema::node;
use opentide_schema::sample::{SampleExample, SampleV1_0, SampleV1_1};
use proptest::prelude::*;

/// Any text, with the shapes a YAML reader takes for something else when
/// unquoted (`true`, `null`, `~`, `017`, `0x1F`, `1e3`, `.inf`, `2026-01-01`,
/// `<<`) and the characters that need escaping or quoting, mixed in.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => any::<String>(),
        2 => "[a-zA-Z0-9 _.:#'\"-]{0,12}",
        2 => prop::sample::select(vec![
            "yes", "No", "on", "OFF", "y", "n", "~", "null", "Null", "", " ", "017", "0o17",
            "true", "True", "FALSE", "12", "-3", "+4", "1.5", "99999999999999999999",
            "0x1F", "1_000", "1:20", "190:20:30.15", "2026-01-01", "2026-01-01 10:00:00",
            ".inf", "-.Inf", ".nan", "1e3", "1.0e+3", "<<", "=", "- a", "a: b", "#c", "&a",
            "*a", "!tag", "|", ">", "'", "\"", "\t", "\u{feff}x", "x\u{85}y", "a\u{2028}b",
            "\r\n", "\u{1F525}", "\u{7f}", "\u{0}",
        ])
        .prop_map(str::to_owned),
    ]
}

fn example() -> impl Strategy<Value = SampleExample> {
    (text(), text(), prop::option::of(text())).prop_map(|(description, link, language)| {
        SampleExample {
            description,
            link,
            language,
        }
    })
}

fn sample_v1_1() -> impl Strategy<Value = SampleV1_1> {
    (
        (text(), text(), text(), text(), text()),
        prop::option::of(any::<i64>()),
        any::<bool>(),
        prop::option::of(prop::collection::vec(example(), 0..3)),
        prop::collection::vec(text(), 0..4),
    )
        .prop_map(
            |((name, uuid, schema_id, description, severity), effort, enabled, examples, tags)| {
                SampleV1_1 {
                    name,
                    uuid,
                    schema_id,
                    description,
                    severity,
                    effort,
                    enabled,
                    examples,
                    tags,
                }
            },
        )
}

fn round_trip<T>(value: &T) -> Result<(), TestCaseError>
where
    T: serde::Serialize + opentide_schema::FromNode + PartialEq + std::fmt::Debug,
{
    let yaml = node::to_yaml(value).unwrap();
    let document = node::load(&yaml)
        .map_err(|error| TestCaseError::fail(format!("{error:?} reading\n{yaml}")))?;
    let read: T = from_document(&document)
        .map_err(|errors| TestCaseError::fail(format!("{errors:#?} reading\n{yaml}")))?;
    prop_assert_eq!(&read, value, "read back from\n{}", yaml);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn every_valid_sample_round_trips(sample in sample_v1_1()) {
        round_trip(&sample)?;
        let older = SampleV1_0 {
            name: sample.name.clone(),
            uuid: sample.uuid.clone(),
            schema_id: sample.schema_id.clone(),
            description: sample.description.clone(),
            severity: sample.severity.clone(),
            effort: sample.effort,
            enabled: sample.enabled,
            examples: sample.examples.clone(),
        };
        round_trip(&older)?;
    }
}

/// Strings a YAML 1.2 reader resolves to another type when they are written
/// plain are quoted, and read back as strings.
#[test]
fn strings_that_look_like_scalars_round_trip() {
    let sample = SampleV1_1 {
        name: "true".to_owned(),
        uuid: "12".to_owned(),
        schema_id: "null".to_owned(),
        description: ".inf".to_owned(),
        severity: "0x1F".to_owned(),
        effort: Some(-1),
        enabled: false,
        examples: None,
        tags: vec![
            "~".to_owned(),
            "1e3".to_owned(),
            String::new(),
            "<<".to_owned(),
        ],
    };
    round_trip(&sample).unwrap();
}
