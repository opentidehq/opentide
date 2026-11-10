//! The registry, `SchemaId` and the dispatch (UC-1.7, #813): unit cases,
//! the corpora, and the property that dispatch is total over identifiers.

use std::collections::BTreeSet;

use proptest::prelude::*;
use serde_json::Value as Json;

use super::*;
use crate::error::ErrorKind;
use crate::node;
use crate::objects::checks;

// --- SchemaId ---------------------------------------------------------------

/// A family, a major and a minor.
type Parts = (&'static str, u32, u32);

#[test]
fn schema_ids_parse_as_schema_version_does() {
    let cases: &[(&str, Result<Parts, SchemaIdError>)] = &[
        ("rule::1.0", Ok(("rule", 1, 0))),
        ("rule::1.1", Ok(("rule", 1, 1))),
        ("objective::1", Ok(("objective", 1, 0))),
        ("  Rule ::2.10", Ok(("rule", 2, 10))),
        ("rule::01.002", Ok(("rule", 1, 2))),
        ("platform::sentinel::1.0", Ok(("platform::sentinel", 1, 0))),
        ("sharing::misp::1.0", Ok(("sharing::misp", 1, 0))),
        ("rule", Err(SchemaIdError::Invalid("rule".into()))),
        ("rule:1.0", Err(SchemaIdError::Invalid("rule:1.0".into()))),
        ("::1.0", Err(SchemaIdError::EmptyFamily)),
        ("  ::1.0", Err(SchemaIdError::EmptyFamily)),
        ("rule::", Err(SchemaIdError::Version(String::new()))),
        ("rule::1.", Err(SchemaIdError::Version("1.".into()))),
        ("rule::.1", Err(SchemaIdError::Version(".1".into()))),
        ("rule::1.0.0", Err(SchemaIdError::Version("1.0.0".into()))),
        ("rule::1.x", Err(SchemaIdError::Version("1.x".into()))),
        ("rule::+1.0", Err(SchemaIdError::Version("+1.0".into()))),
        ("rule::-1.0", Err(SchemaIdError::Version("-1.0".into()))),
        ("rule:: 1.0", Err(SchemaIdError::Version(" 1.0".into()))),
        ("rule::1_0", Err(SchemaIdError::Version("1_0".into()))),
        (
            "rule::\u{661}.0",
            Err(SchemaIdError::Version("\u{661}.0".into())),
        ),
        (
            "rule::4294967296.0",
            Err(SchemaIdError::Version("4294967296.0".into())),
        ),
    ];
    for (text, expected) in cases {
        let parsed = SchemaId::parse(text);
        match expected {
            Ok((family, major, minor)) => {
                let id = parsed.unwrap_or_else(|e| panic!("{text}: {e}"));
                assert_eq!(
                    (id.family(), id.major(), id.minor()),
                    (*family, *major, *minor)
                );
                assert_eq!(id.as_identifier(), format!("{family}::{major}.{minor}"));
                assert_eq!(text.parse::<SchemaId>().unwrap(), id);
            }
            Err(error) => assert_eq!(&parsed.unwrap_err(), error, "{text}"),
        }
    }
    assert_eq!(SchemaId::new(" \t", 1, 0), Err(SchemaIdError::EmptyFamily));
    assert_eq!(
        SchemaId::new("RULE", 1, 0).unwrap().to_string(),
        "rule::1.0"
    );
}

#[test]
fn schema_ids_order_by_family_then_major_then_minor() {
    let ordered = [
        "objective::1.0",
        "rule::1.0",
        "rule::1.2",
        "rule::1.10",
        "rule::2.0",
        "threat::0.9",
    ];
    for pair in ordered.windows(2) {
        let (a, b) = (
            SchemaId::parse(pair[0]).unwrap(),
            SchemaId::parse(pair[1]).unwrap(),
        );
        assert!(a < b, "{a} < {b}");
    }
}

// --- The registry -----------------------------------------------------------

#[test]
fn every_registered_identifier_parses_and_prints_back() {
    for revision in REVISIONS {
        assert_eq!(revision.id().to_string(), revision.identifier);
    }
    let ids: Vec<SchemaId> = REVISIONS.iter().map(Revision::id).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(ids, sorted, "REVISIONS is sorted and holds each once");
}

#[test]
fn the_object_registry_is_the_oracles() {
    let registered: Vec<&str> = REVISIONS
        .iter()
        .filter(|revision| revision.in_object_registry())
        .map(|revision| revision.identifier)
        .collect();
    assert_eq!(registered, checks::REGISTERED);
}

#[test]
fn the_registry_holds_every_platform_block_and_the_misp_block() {
    let platforms: Vec<String> = REVISIONS
        .iter()
        .filter(|revision| revision.kind == Kind::Platform)
        .map(|revision| {
            revision
                .id()
                .family()
                .trim_start_matches("platform::")
                .to_owned()
        })
        .collect();
    let mut expected = crate::objects::RuleConfigurations::PLATFORMS.to_vec();
    expected.sort_unstable();
    assert_eq!(platforms, expected);
    assert_eq!(
        lookup("sharing::misp::1.0").map(|revision| revision.kind),
        Some(Kind::Sharing)
    );
}

#[test]
fn the_newest_revision_of_each_family() {
    let newest_of = |family: &str| newest(family).map(|revision| revision.identifier);
    assert_eq!(newest_of("rule"), Some("rule::1.1"));
    assert_eq!(newest_of(" RULE "), Some("rule::1.1"));
    assert_eq!(newest_of("threat"), Some("threat::1.0"));
    assert_eq!(newest_of("objective"), Some("objective::1.0"));
    assert_eq!(newest_of("visibility"), Some("visibility::1.0"));
    assert_eq!(
        newest_of("platform::sentinel"),
        Some("platform::sentinel::1.0")
    );
    assert_eq!(newest_of("sharing::misp"), Some("sharing::misp::1.0"));
    assert_eq!(newest_of("platform"), None);
    assert_eq!(newest_of("detection"), None);
    let rule: Vec<&str> = revisions_of("rule")
        .iter()
        .map(|revision| revision.identifier)
        .collect();
    assert_eq!(rule, ["rule::1.0", "rule::1.1"]);
    assert_eq!(families().len(), 15 - 1);
}

#[test]
fn lookup_takes_the_identifier_as_written() {
    assert!(lookup("rule::1.1").is_some());
    assert!(lookup("Rule::1.1").is_none());
    assert!(lookup("rule::1").is_none());
    assert!(lookup(" rule::1.1").is_none());
}

// --- Dispatch ---------------------------------------------------------------

/// The object families and a valid document of each registered revision.
const VALID: &[(&str, &str)] = &[
    (
        "objective::1.0",
        "name: Objective\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000003\n  \
         schema: objective::1.0\n  version: 1\n  created: '2026-01-01'\n  modified: '2026-01-02'\n  \
         tlp: clear\nobjective:\n  priority: High\n  type: Threat\n  description: obj\n  \
         composition:\n    strategy: synergetic\n    description: compose\n  signals:\n    \
         - name: Signal\n      uuid: 00000000-0000-4000-8000-000000000099\n      description: sig\n      \
         severity: Medium\n      methodology: analytics\n      entities: [Host::Process]\n      \
         data:\n        availability: Complete\n        requirements: logs\n",
    ),
    (
        "rule::1.0",
        "name: Rule\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n  schema: rule::1.0\n  \
         version: 1\n  created: '2026-01-01'\n  modified: '2026-01-02'\n  tlp: clear\ndescription: d\n",
    ),
    (
        "rule::1.1",
        "name: Rule\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n  schema: rule::1.1\n  \
         version: 1\n  created: '2026-01-01'\n  modified: '2026-01-02'\n  tlp: clear\n  \
         reviewed: '2026-03-01'\ndescription: d\n",
    ),
    (
        "threat::1.0",
        "name: Threat\ncriticality: High\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000002\n  \
         schema: threat::1.0\n  version: 1\n  created: '2026-01-01'\n  modified: '2026-01-02'\n  \
         tlp: clear\nthreat:\n  description: d\n  severity: High\n  impact: [Data Breach]\n  \
         leverage: [Code Execution]\n  viability: Proven\n  terrain: t\n  surface: [Endpoint]\n  \
         mitre_attack: [T1059]\n",
    ),
];

fn family_of(identifier: &str) -> String {
    SchemaId::parse(identifier).unwrap().family().to_owned()
}

#[test]
fn every_object_revision_has_a_struct_and_every_struct_a_revision() {
    let objects: Vec<&str> = REVISIONS
        .iter()
        .filter(|revision| revision.kind == Kind::Object)
        .map(|revision| revision.identifier)
        .collect();
    let valid: Vec<&str> = VALID.iter().map(|(identifier, _)| *identifier).collect();
    assert_eq!(objects, valid);
    for (identifier, text) in VALID {
        let document = node::load(text).unwrap();
        let read = read(&document, &family_of(identifier)).unwrap();
        assert_eq!(
            read.selection,
            Selection::Registered(lookup(identifier).unwrap())
        );
        let object = read
            .result
            .unwrap_or_else(|errors| panic!("{identifier}: {errors:#?}"));
        assert_eq!(object.schema_identifier(), *identifier);
        assert_eq!(object.revision().identifier, *identifier);
    }
}

fn with_schema(identifier: &str, schema: &str) -> String {
    let (_, text) = VALID.iter().find(|(id, _)| *id == identifier).unwrap();
    text.replace(
        &format!("schema: {identifier}\n"),
        &format!("schema: {schema}\n"),
    )
}

#[test]
fn an_unknown_revision_is_checked_against_the_newest_without_the_unknown_key_check() {
    let text = with_schema("rule::1.1", "rule::7.0").replace(
        "description: d\n",
        "description: d\nadded_later: 1\nmetadata_extra: {a: 1}\n",
    );
    let document = node::load(&text).unwrap();
    let read = read(&document, "rule").unwrap();
    assert_eq!(
        read.selection,
        Selection::Unknown {
            written: "rule::7.0".into(),
            newest: lookup("rule::1.1").unwrap(),
        }
    );
    let errors = read.result.unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert_eq!(errors[0].field_path(), ["metadata", "schema"]);
    assert_eq!(errors[0].kind, ErrorKind::InvalidValue("value_error"));
    assert_eq!(
        errors[0].message,
        "Value error, unknown schema identifier: 'rule::7.0'; checked against rule::1.1, the \
         newest rule revision, without the unknown-key check"
    );
    assert_eq!(
        errors[0].context["error"],
        errors[0].message["Value error, ".len()..]
    );
    assert_eq!(errors[0].code(crate::Surface::Object), "schema_validation");
    assert!(errors[0].span.is_some());

    // A registered revision keeps the unknown-key check.
    let text = VALID[2]
        .1
        .replace("description: d\n", "description: d\nadded_later: 1\n");
    let errors = read_errors(&text, "rule");
    assert_eq!(errors, [("added_later".to_owned(), ErrorKind::UnknownKey)]);
}

fn read_errors(text: &str, family: &str) -> Vec<(String, ErrorKind)> {
    let document = node::load(text).unwrap();
    read(&document, family)
        .unwrap()
        .result
        .unwrap_err()
        .iter()
        .map(|error| (error.field_path().join("."), error.kind))
        .collect()
}

#[test]
fn the_loader_refuses_what_is_not_a_revision_of_the_family() {
    let verdict = |schema: &str, family: &str| {
        let text = with_schema("rule::1.1", schema);
        select(&node::load(&text).unwrap(), family)
    };
    assert_eq!(
        verdict("threat::1.0", "rule"),
        Err(Rejection::OtherFamily {
            identifier: "threat::1.0".into(),
            family: "rule".into()
        })
    );
    assert_eq!(
        verdict("rule::1.1", "threat").unwrap_err().to_string(),
        "'rule::1.1' is not a threat schema identifier"
    );
    for (schema, written) in [
        ("platform::sentinel::1.0", "platform::sentinel::1.0"),
        ("sharing::misp::1.0", "sharing::misp::1.0"),
        ("threat::9.0", "threat::9.0"),
        ("rule", "rule"),
        ("rule::1.x", "rule::1.x"),
        ("1.1", "1.1"),
        ("true", "true"),
    ] {
        assert_eq!(
            verdict(schema, "rule"),
            Err(Rejection::Unknown {
                identifier: written.into()
            }),
            "{schema}"
        );
    }
    for schema in ["''", "null", "0", "false", "[]", "{}"] {
        let verdict = verdict(schema, "rule");
        assert_eq!(verdict, Err(Rejection::SchemaMissing), "{schema}");
        assert_eq!(verdict.unwrap_err().code(), "schema_missing");
    }
    assert_eq!(
        verdict("rule::1.1", "visibility"),
        Err(Rejection::NoModel {
            family: "visibility".into()
        })
    );
    assert_eq!(
        verdict("rule::1.1", "detection"),
        Err(Rejection::NoModel {
            family: "detection".into()
        })
    );
    for text in ["", "- a\n", "name: x\n", "metadata:\n", "metadata: 0\n"] {
        assert_eq!(
            select(&node::load(text).unwrap(), "rule"),
            Err(Rejection::SchemaMissing),
            "{text:?}"
        );
    }
    let Err(Rejection::MetadataNotAMapping(error)) =
        select(&node::load("name: x\nmetadata: [1]\n").unwrap(), "rule")
    else {
        panic!("a list is not a mapping")
    };
    assert_eq!(error.kind, ErrorKind::InvalidType("dict_type"));
    assert_eq!(error.field_path(), ["metadata"]);
    assert!(error.span.is_some());
}

/// Every object file of the corpora (`tests/fixtures/tide_corpus` and the VS
/// Code fixture workspace, carried in the oracle's table) dispatches to the
/// revision its `metadata.schema` names, and together they hold every object
/// revision. The values and errors themselves are `objects::table`'s.
#[test]
fn every_revision_in_the_corpora_dispatches_to_its_struct() {
    let table: Json =
        serde_json::from_str(include_str!("../../tests/oracle/objects_table.json")).unwrap();
    let mut seen = BTreeSet::new();
    let mut files = 0;
    for case in table["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if !id.starts_with("file:") {
            continue;
        }
        files += 1;
        let document = node::load(case["yaml"].as_str().unwrap()).unwrap();
        let read = read(&document, case["family"].as_str().unwrap())
            .unwrap_or_else(|rejection| panic!("{id}: {rejection}"));
        let Selection::Registered(revision) = read.selection else {
            panic!("{id}: {:?}", read.selection)
        };
        let written = document
            .root()
            .and_then(|root| root.get("metadata"))
            .and_then(|metadata| metadata.get("schema"))
            .and_then(|schema| schema.value.as_str().map(str::to_owned));
        assert_eq!(Some(revision.identifier.to_owned()), written, "{id}");
        if let Ok(object) = &read.result {
            assert_eq!(object.schema_identifier(), revision.identifier, "{id}");
        }
        assert_eq!(read.result.is_ok(), case.get("value").is_some(), "{id}");
        seen.insert(revision.identifier);
    }
    assert!(files > 10, "{files} corpus files");
    let objects: BTreeSet<&str> = REVISIONS
        .iter()
        .filter(|revision| revision.kind == Kind::Object)
        .map(|revision| revision.identifier)
        .collect();
    assert_eq!(seen, objects, "every object revision is in the corpora");
}

// --- Property: dispatch is total --------------------------------------------

/// What the dispatch must decide for `written` and `family`, from the ADR's
/// table, independently of the implementation.
#[derive(Debug, PartialEq)]
enum Expected {
    Registered(&'static str),
    Unknown(&'static str),
    OtherFamily,
    Refused,
}

fn expected(written: &str, family: &str) -> Expected {
    if let Some(identifier) = checks::REGISTERED.iter().find(|id| **id == written) {
        return if family_of(identifier) == family {
            Expected::Registered(identifier)
        } else {
            Expected::OtherFamily
        };
    }
    match SchemaId::parse(written) {
        Ok(id) if id.family() == family => Expected::Unknown(newest(family).unwrap().identifier),
        _ => Expected::Refused,
    }
}

fn identifier() -> impl Strategy<Value = String> {
    let registered: Vec<String> = REVISIONS
        .iter()
        .map(|revision| revision.identifier.to_owned())
        .collect();
    let family = prop::sample::select(vec![
        "rule",
        "Rule",
        " threat",
        "OBJECTIVE ",
        "objective",
        "visibility",
        "platform::splunk",
        "sharing::misp",
        "detection",
        "",
        " ",
    ]);
    prop_oneof![
        3 => prop::sample::select(registered),
        3 => (family, 0u32..4, 0u32..12)
            .prop_map(|(family, major, minor)| format!("{family}::{major}.{minor}")),
        1 => "[a-z:. 0-9]{1,16}",
        1 => any::<String>().prop_filter("not empty", |text| !text.is_empty()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn revision_dispatch_is_total_over_identifiers(
        written in identifier(),
        family in prop::sample::select(vec!["rule", "threat", "objective"]),
    ) {
        // Valid as every registered revision of its family: the rule has no
        // `reviewed`, which `rule::1.0` refuses.
        let template = match family {
            "rule" => VALID[1],
            "threat" => VALID[3],
            _ => VALID[0],
        };
        // A JSON string is a YAML 1.2 double-quoted scalar.
        let quoted = serde_json::to_string(&written).unwrap();
        let text = template.1.replace(&format!("schema: {}\n", template.0), &format!("schema: {quoted}\n"));
        let document = node::load(&text).unwrap();
        let outcome = read(&document, family);
        match (expected(&written, family), outcome) {
            (Expected::Registered(identifier), Ok(read)) => {
                prop_assert_eq!(read.selection, Selection::Registered(lookup(identifier).unwrap()));
                let object = read.result.unwrap();
                prop_assert_eq!(object.schema_identifier(), identifier);
            }
            (Expected::Unknown(newest), Ok(read)) => {
                prop_assert_eq!(read.selection.revision().identifier, newest);
                let errors = read.result.unwrap_err();
                prop_assert!(errors.iter().all(|error| error.kind != ErrorKind::UnknownKey));
                prop_assert_eq!(errors.len(), 1, "{:?}", errors);
                prop_assert_eq!(errors[0].field_path(), ["metadata", "schema"]);
            }
            (Expected::OtherFamily, Err(Rejection::OtherFamily { identifier, .. }))
            | (Expected::Refused, Err(Rejection::Unknown { identifier })) => {
                prop_assert_eq!(identifier, written);
            }
            (expected, outcome) => prop_assert!(false, "{:?}: expected {:?}, got {:?}", written, expected, outcome),
        }
    }
}
