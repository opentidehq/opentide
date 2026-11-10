//! The migration chain (UC-1.7, #813): the one-step `From` impls, the walk
//! along the chain, `path`, `stamp_schema_identifier`, and the properties of
//! the issue: composing steps equals migrating directly, migration is
//! idempotent on the newest revision, and a valid object migrates to a valid
//! object of the target revision.

use garde::Validate;
use proptest::prelude::*;

use super::*;
use crate::node::{self, Document};
use crate::objects::{ObjectReferences, Organisation, RuleConfigurations, RuleResponse, Version};
use crate::pins::Pins;
use crate::revisions::{self, Kind, REVISIONS, Selection};

/// Any text, with the shapes a YAML reader takes for something else when
/// unquoted mixed in (as `tests/round_trip_property.rs`).
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => any::<String>(),
        3 => "[a-zA-Z0-9 _.:#'\"-]{0,12}",
        1 => prop::sample::select(vec![
            "yes", "No", "on", "~", "null", "", " ", "017", "true", "12", "1.5", "0x1F",
            "2026-01-01", ".inf", "<<", "- a", "a: b", "#c", "\t", "\u{feff}x", "\r\n",
        ])
        .prop_map(str::to_owned),
    ]
}

fn metadata_v1_0() -> impl Strategy<Value = ObjectMetadata> {
    (
        (text(), text(), text(), text()),
        prop_oneof![
            text().prop_map(Version::Str),
            any::<i64>().prop_map(Version::Int)
        ],
        prop::option::of(text()),
        prop::option::of(prop::collection::vec(text(), 0..3)),
        prop::option::of((text(), text()).prop_map(|(uuid, name)| Organisation { uuid, name })),
    )
        .prop_map(
            |((uuid, created, modified, tlp), version, author, contributors, organisation)| {
                ObjectMetadata {
                    uuid,
                    schema_id: RuleV1_0::SCHEMA_IDENTIFIER.to_owned(),
                    version,
                    created,
                    modified,
                    tlp,
                    author,
                    contributors,
                    organisation,
                }
            },
        )
}

fn references() -> impl Strategy<Value = ObjectReferences> {
    (
        prop::option::of(prop::collection::btree_map(any::<i64>(), text(), 0..3)),
        prop::option::of(prop::collection::btree_map(text(), text(), 0..3)),
        prop::option::of(prop::collection::vec(text(), 0..3)),
    )
        .prop_map(|(public, internal, reports)| ObjectReferences {
            public,
            internal: internal.map(|internal| internal.into_iter().collect()),
            reports,
        })
}

fn response() -> impl Strategy<Value = RuleResponse> {
    (text(), prop::option::of(text()), prop::option::of(text())).prop_map(
        |(alert_severity, playbook, responders)| RuleResponse {
            alert_severity,
            playbook,
            responders,
            procedure: None,
        },
    )
}

fn empty_configurations() -> RuleConfigurations {
    RuleConfigurations {
        sentinel: None,
        defender_for_endpoint: None,
        splunk: None,
        sentinel_one: None,
        crowdstrike: None,
        harfanglab: None,
        carbon_black_cloud: None,
        elastic: None,
        sysdig: None,
    }
}

/// A `rule::1.0` object of any content the model accepts. `configurations`
/// is absent or empty: migration copies it whole, and the platform blocks'
/// own content is proved by `objects::platform`'s table.
fn rule_v1_0() -> impl Strategy<Value = RuleV1_0> {
    (
        (text(), metadata_v1_0(), text()),
        (prop::option::of(text()), prop::option::of(text())),
        prop::collection::vec(text(), 0..3),
        prop::option::of(references()),
        prop::option::of(text()),
        prop::option::of(response()),
        any::<bool>(),
    )
        .prop_map(
            |(
                (name, metadata, description),
                (status, severity),
                techniques,
                references,
                detection_model,
                response,
                configured,
            )| RuleV1_0 {
                name,
                metadata,
                description,
                status,
                severity,
                techniques,
                platforms: indexmap::IndexMap::new(),
                references,
                detection_model,
                response,
                configurations: configured.then(empty_configurations),
                file: None,
            },
        )
}

/// A `rule::1.1` object: a migrated `rule::1.0` with any valid `reviewed`.
fn rule_v1_1() -> impl Strategy<Value = RuleV1_1> {
    (
        rule_v1_0(),
        prop::option::of(prop::sample::select(vec![
            "2026-03-01",
            "2026-03-01T10:00:00Z",
            "2026-03-01T10:00:00+02:00",
            "2026-03-01 10:00:00.5-01:30",
        ])),
    )
        .prop_map(|(rule, reviewed)| {
            let mut rule = RuleV1_1::from(rule);
            rule.metadata.reviewed = reviewed.map(str::to_owned);
            rule
        })
}

fn object() -> impl Strategy<Value = TideObject> {
    prop_oneof![
        rule_v1_0().prop_map(|rule| TideObject::RuleV1_0(Box::new(rule))),
        rule_v1_1().prop_map(|rule| TideObject::RuleV1_1(Box::new(rule))),
    ]
}

/// The object written as YAML and read back through the registry.
fn reread(object: &TideObject) -> Result<(Selection, TideObject), TestCaseError> {
    let yaml = node::to_yaml(object).map_err(|error| TestCaseError::fail(error.to_string()))?;
    let document: Document = node::load(&yaml)
        .map_err(|error| TestCaseError::fail(format!("{error:?} reading\n{yaml}")))?;
    let family = object.revision().id().family().to_owned();
    let read = revisions::read(&document, &family)
        .map_err(|rejection| TestCaseError::fail(format!("{rejection} reading\n{yaml}")))?;
    let object = read
        .result
        .map_err(|errors| TestCaseError::fail(format!("{errors:#?} reading\n{yaml}")))?;
    Ok((read.selection, object))
}

fn valid(object: &TideObject) -> Result<(), garde::Report> {
    let pins = Pins::default();
    match object {
        TideObject::RuleV1_0(rule) => rule.validate_with(&pins),
        TideObject::RuleV1_1(rule) => rule.validate_with(&pins),
        TideObject::ThreatV1_0(threat) => threat.validate_with(&pins),
        TideObject::ObjectiveV1_0(objective) => objective.validate_with(&pins),
    }
}

/// Every registered object identifier of the object's family.
fn family_revisions(object: &TideObject) -> Vec<&'static str> {
    revisions::revisions_of(object.revision().id().family())
        .iter()
        .map(|revision| revision.identifier)
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn migration_of_a_valid_object_yields_a_valid_object_of_the_target_revision(object in object()) {
        // The generated object is valid: it reads back as itself.
        let (selection, read) = reread(&object)?;
        prop_assert_eq!(selection.revision(), object.revision());
        prop_assert_eq!(&read, &object);
        prop_assert!(valid(&object).is_ok());
        for target in family_revisions(&object) {
            let Ok(migrated) = object.clone().migrate_to(target) else {
                // Older than the object: a migration never goes backwards.
                prop_assert!(revisions::lookup(target).unwrap().id() < object.revision().id());
                continue;
            };
            prop_assert_eq!(migrated.schema_identifier(), target);
            let (selection, read) = reread(&migrated)?;
            prop_assert_eq!(selection, Selection::Registered(revisions::lookup(target).unwrap()));
            prop_assert_eq!(&read, &migrated);
            prop_assert!(valid(&migrated).is_ok(), "{:?}", valid(&migrated));
        }
    }

    #[test]
    fn migration_steps_composed_equal_migrating_directly(object in object()) {
        let identifiers = family_revisions(&object);
        for (index, middle) in identifiers.iter().enumerate() {
            for target in &identifiers[index..] {
                let Ok(first) = object.clone().migrate_to(middle) else { continue };
                let composed = first.migrate_to(target).unwrap();
                let direct = object.clone().migrate_to(target).unwrap();
                prop_assert_eq!(composed, direct);
            }
        }
        // One step at a time, to the end, is the walk to the newest.
        let newest = revisions::newest(object.revision().id().family()).unwrap();
        let mut stepped = object.clone();
        while let Ok(next) = stepped.clone().step() {
            stepped = next;
        }
        prop_assert_eq!(&stepped, &object.clone().migrate_to(newest.identifier).unwrap());
        prop_assert_eq!(stepped, object.into_newest());
    }

    #[test]
    fn migration_is_idempotent_on_the_newest_revision(object in object()) {
        let newest = object.clone().into_newest();
        prop_assert_eq!(
            newest.schema_identifier(),
            revisions::newest(object.revision().id().family()).unwrap().identifier
        );
        prop_assert_eq!(&newest.clone().into_newest(), &newest);
        prop_assert_eq!(&newest.clone().migrate_to(newest.schema_identifier()).unwrap(), &newest);
        prop_assert_eq!(newest.clone().step(), Err(newest.clone()));
        // Its own revision returns any object as it is.
        prop_assert_eq!(object.clone().migrate_to(object.schema_identifier()).unwrap(), object);
    }
}

// --- Unit cases ---------------------------------------------------------------

const RULE_1_0: &str = "name: Rule\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n  \
                        schema: rule::1.0\n  version: '2.1'\n  created: '2026-01-01'\n  \
                        modified: '2026-01-02'\n  tlp: amber\n  author: A\n  contributors: [B]\n  \
                        organisation: {uuid: o, name: Org}\ndescription: d\nstatus: s\n\
                        severity: High\ntechniques: [T1059]\nplatforms: {splunk: {a: 1}}\n\
                        references: {public: {1: https://x}}\ndetection_model: m\n\
                        response: {alert_severity: Low}\nconfigurations: {splunk: {status: STAGING, query: q}}\n";

fn read_object(text: &str, family: &str) -> TideObject {
    let document = node::load(text).unwrap();
    revisions::read(&document, family).unwrap().result.unwrap()
}

#[test]
fn rule_1_0_migrates_to_rule_1_1_field_for_field() {
    let TideObject::RuleV1_0(source) = read_object(RULE_1_0, "rule") else {
        panic!("rule::1.0")
    };
    let migrated = RuleV1_1::from((*source).clone());
    assert_eq!(migrated.metadata.schema_id, "rule::1.1");
    assert_eq!(migrated.metadata.reviewed, None);
    // The same document, as rule::1.1, reads as the migrated object.
    let TideObject::RuleV1_1(expected) =
        read_object(&RULE_1_0.replace("rule::1.0", "rule::1.1"), "rule")
    else {
        panic!("rule::1.1")
    };
    assert_eq!(migrated, *expected);
    assert_eq!(
        serde_json::to_value(&migrated).unwrap()["metadata"]["schema"],
        "rule::1.1"
    );
}

#[test]
fn every_revision_but_the_newest_has_one_step_to_the_next() {
    let samples = [
        read_object(RULE_1_0, "rule"),
        read_object(&RULE_1_0.replace("rule::1.0", "rule::1.1"), "rule"),
    ];
    for revision in REVISIONS
        .iter()
        .filter(|revision| revision.kind == Kind::Object)
    {
        let family = revisions::revisions_of(revision.id().family());
        let position = family.iter().position(|r| r == &revision).unwrap();
        let Some(sample) = samples
            .iter()
            .find(|sample| sample.schema_identifier() == revision.identifier)
        else {
            // Threat and objective have one revision each: nothing to step.
            assert_eq!(family.len(), 1, "{}", revision.identifier);
            continue;
        };
        match (sample.clone().step(), family.get(position + 1)) {
            (Ok(next), Some(expected)) => assert_eq!(next.schema_identifier(), expected.identifier),
            (Err(same), None) => assert_eq!(&same, sample),
            (step, next) => panic!(
                "{}: {step:?} but the registry's next is {next:?}",
                revision.identifier
            ),
        }
    }
}

#[test]
fn migrate_to_refuses_backwards_across_families_and_unregistered() {
    let newer = read_object(&RULE_1_0.replace("rule::1.0", "rule::1.1"), "rule");
    assert_eq!(
        newer.clone().migrate_to("rule::1.0"),
        Err(MigrationError::Backwards {
            source_id: "rule::1.1".into(),
            target: "rule::1.0".into()
        })
    );
    assert_eq!(
        newer.clone().migrate_to("threat::1.0"),
        Err(MigrationError::CrossFamily {
            source_id: "rule::1.1".into(),
            target: "threat::1.0".into()
        })
    );
    assert_eq!(
        newer.migrate_to("rule::9.0"),
        Err(MigrationError::Unregistered("rule::9.0".into()))
    );
    assert_eq!(
        MigrationError::Unregistered("rule::9.0".into()).to_string(),
        "unknown schema identifier: 'rule::9.0'"
    );
}

#[test]
fn path_lists_the_chain_as_schema_version_chain_does() {
    let ids = |source: &str, target: &str| {
        path(source, target).map(|revisions| {
            revisions
                .iter()
                .map(|revision| revision.identifier)
                .collect::<Vec<_>>()
        })
    };
    assert_eq!(
        ids("rule::1.0", "rule::1.1"),
        Ok(vec!["rule::1.0", "rule::1.1"])
    );
    assert_eq!(ids("rule::1.1", "rule::1.1"), Ok(vec!["rule::1.1"]));
    assert_eq!(ids("threat::1.0", "threat::1.0"), Ok(vec!["threat::1.0"]));
    assert!(matches!(
        ids("rule::1.1", "rule::1.0"),
        Err(MigrationError::Backwards { .. })
    ));
    assert!(matches!(
        ids("rule::1.0", "objective::1.0"),
        Err(MigrationError::CrossFamily { .. })
    ));
    assert_eq!(
        ids("rule::0.9", "rule::1.1"),
        Err(MigrationError::Unregistered("rule::0.9".into()))
    );
}

/// `stamp_schema_identifier`'s cases, each as the oracle's function returns
/// it (`models/migration.py`), written as YAML.
#[test]
fn stamp_schema_identifier_keeps_its_semantics() {
    let cases = [
        // A metadata mapping keeps its keys and their order.
        (
            "name: x\nmetadata: {uuid: u, schema: rule::1.0, version: 1}\nb: 2\n",
            "rule::1.1",
            "name: x\nmetadata: {uuid: u, schema: rule::1.1, version: 1}\nb: 2\n",
        ),
        // `schema` comes last when it was missing.
        (
            "metadata: {uuid: u}\n",
            "rule::1.1",
            "metadata: {uuid: u, schema: rule::1.1}\n",
        ),
        // A metadata that is not a mapping is replaced in place.
        (
            "a: 1\nmetadata: 3\nb: 2\n",
            "rule::1.1",
            "a: 1\nmetadata: {schema: rule::1.1}\nb: 2\n",
        ),
        // A missing metadata is added last.
        (
            "a: 1\n",
            "rule::1.1",
            "a: 1\nmetadata: {schema: rule::1.1}\n",
        ),
        // An empty identifier changes nothing.
        (
            "metadata: {schema: rule::1.0}\n",
            "",
            "metadata: {schema: rule::1.0}\n",
        ),
        // Neither does a root that is not a mapping.
        ("[1, 2]\n", "rule::1.1", "[1, 2]\n"),
    ];
    for (input, schema_id, expected) in cases {
        let input = node::load(input).unwrap();
        let expected = node::load(expected).unwrap();
        let stamped = stamp_schema_identifier(input.root().unwrap(), schema_id);
        assert!(
            crate::objects::Any(std::sync::Arc::new(stamped.clone()))
                == crate::objects::Any(expected.root().unwrap().clone()),
            "{schema_id}: {stamped:#?}"
        );
    }
}
