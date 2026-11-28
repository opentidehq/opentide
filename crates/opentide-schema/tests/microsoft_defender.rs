//! The Microsoft Defender block (microsoft-defender-1.0, RFC 0021) on the
//! specification's fixtures (`tests/fixtures/microsoft_defender`): the valid
//! blocks convert with no finding, each invalid one reports the code its
//! header names, the complete block sets every key the field tables define,
//! every property of the Graph beta snapshot is modelled or listed as not
//! modelled with a reason the snapshot agrees with, and the bundled template
//! carries every key and validates once filled in.
#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test]: a fixture that cannot be read fails the test"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use opentide_schema::FromNode;
use opentide_schema::from_node::Context;
use opentide_schema::node::{self, Node, Value};
use opentide_schema::objects::platform::microsoft_defender::{
    ACTIONS, ADVISORY_CODES, CONSTRAINT_CODES, Duration, ENTITY_IDENTIFIERS, ENTITY_KINDS,
    Evidence, IDENTIFIERS_CHECKED, IMPACTED_ASSET_COLUMNS, MicrosoftDefenderConfig, NOT_MODELLED,
    NotModelled, TEMPLATE, advisories, block_codes, block_findings, entity_kind,
    placeholder_columns,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/microsoft_defender")
}

fn load(text: &str) -> Node {
    let document = node::load(text).unwrap();
    (**document.root().unwrap()).clone()
}

fn load_rule(path: &Path) -> (String, Node) {
    let text = std::fs::read_to_string(path).unwrap();
    let root = load(&text);
    (text, root)
}

fn block(root: &Node) -> &Node {
    root.get("configurations")
        .and_then(|configurations| configurations.get("microsoft_defender"))
        .unwrap()
}

/// The block's value and its errors, each as `(code, path)`.
fn convert(block: &Node) -> (Option<MicrosoftDefenderConfig>, Vec<(String, String)>) {
    let mut cx = Context::new();
    let value = MicrosoftDefenderConfig::from_node(block, &mut cx);
    let errors = cx
        .into_errors()
        .into_iter()
        .map(|error| {
            let path: Vec<String> = error.path.iter().map(ToString::to_string).collect();
            (
                error.kind.pydantic_type().unwrap_or_default().to_owned(),
                path.join("."),
            )
        })
        .collect();
    (value, errors)
}

#[test]
fn the_valid_fixtures_convert_with_no_finding() {
    for name in [
        "microsoft-defender.yaml",
        "microsoft-defender-complete.yaml",
    ] {
        let (_, root) = load_rule(&fixtures().join(name));
        assert_eq!(block_findings(block(&root)), Vec::new(), "{name}");
        let (value, errors) = convert(block(&root));
        assert!(errors.is_empty(), "{name}: {errors:?}");
        assert!(value.is_some(), "{name}");
        assert!(advisories(&root).is_empty(), "{name}: it maps entities");
    }
}

/// The specification writes `unknown_field` for a key the block does not
/// define; the conversion's code for it is `extra_forbidden`, as for every
/// other closed model. The headers' `defender_` prefix is the
/// specification's draft spelling of `microsoft_defender_`.
fn expected_code(text: &str) -> String {
    let named = text
        .lines()
        .take_while(|line| line.starts_with('#'))
        .find_map(|line| line.split_once("Expected").map(|(_, rest)| rest))
        .unwrap()
        .split_once(':')
        .unwrap()
        .1
        .trim()
        .trim_end_matches('.')
        .to_owned();
    match named.as_str() {
        "unknown_field" => "extra_forbidden".to_owned(),
        other if !other.starts_with("microsoft_defender_") => {
            format!("microsoft_{}", other.trim_start_matches("microsoft_"))
        }
        other => other.to_owned(),
    }
}

#[test]
fn each_invalid_fixture_reports_the_code_its_header_names() {
    let mut files: Vec<PathBuf> = std::fs::read_dir(fixtures().join("invalid"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    assert_eq!(files.len(), 4);
    for path in files {
        let (text, root) = load_rule(&path);
        let expected = expected_code(&text);
        let (value, errors) = convert(block(&root));
        assert!(value.is_none(), "{}", path.display());
        let mut codes: BTreeSet<String> = errors.iter().map(|(code, _)| code.clone()).collect();
        // The unknown keys (`scheduling`, `impacted_entities`) stand where
        // the block's own (`schedule`) should be: that one is missing too.
        if expected == "extra_forbidden" {
            codes.remove("missing");
        }
        assert_eq!(
            codes,
            BTreeSet::from([expected.clone()]),
            "{}: {errors:?}",
            path.display()
        );
    }
}

/// A block from `yaml` under the shared keys a block needs.
fn block_of(yaml: &str) -> Node {
    load(&format!(
        "status: STAGING\nquery: DeviceProcessEvents\nschedule:\n  frequency: 1H\n{yaml}"
    ))
}

fn codes_at(yaml: &str) -> Vec<(String, String)> {
    block_findings(&block_of(yaml))
        .into_iter()
        .map(|finding| {
            let path: Vec<String> = finding.path.iter().map(ToString::to_string).collect();
            (finding.code.to_owned(), path.join("."))
        })
        .collect()
}

#[test]
#[expect(clippy::too_many_lines, reason = "one row per constraint, as a table")]
fn each_constraint_is_reported_by_its_code_at_its_path() {
    let cases: [(&str, (&str, &str)); 20] = [
        (
            "schema: platform::microsoft_defender::2.0\n",
            ("microsoft_defender_schema", "schema"),
        ),
        (
            "schedule:\n  frequency: PT1H\n",
            ("microsoft_defender_frequency", "schedule.frequency"),
        ),
        (
            "schedule:\n  frequency: 01H\n",
            ("microsoft_defender_frequency", "schedule.frequency"),
        ),
        (
            "schedule:\n  frequency: 1H\n  lookback: NRT\n",
            ("microsoft_defender_lookback", "schedule.lookback"),
        ),
        (
            "schedule:\n  frequency: 3H\n  lookback: 1H\n",
            ("microsoft_defender_lookback", "schedule.lookback"),
        ),
        (
            "schedule:\n  frequency: 1D\n  lookback: 23H\n",
            ("microsoft_defender_lookback", "schedule.lookback"),
        ),
        (
            "alert:\n  severity: high\n",
            ("microsoft_defender_severity", "alert.severity"),
        ),
        (
            "alert:\n  grouping: singleAlert\n",
            ("microsoft_defender_grouping", "alert.grouping"),
        ),
        (
            "alert:\n  custom_details: [A]\n",
            ("microsoft_defender_custom_details", "alert.custom_details"),
        ),
        (
            "alert:\n  custom_details:\n    A: 1\n",
            (
                "microsoft_defender_custom_details",
                "alert.custom_details.A",
            ),
        ),
        (
            "alert:\n  custom_details:\n    A: ' '\n",
            ("microsoft_defender_column", "alert.custom_details.A"),
        ),
        (
            "entities:\n  devices: [{device_id: DeviceId}]\n",
            ("microsoft_defender_entity_kind", "entities.devices"),
        ),
        (
            "entities:\n  hosts: [{}]\n",
            ("microsoft_defender_entity_mapping", "entities.hosts.0"),
        ),
        (
            "entities:\n  hosts: [{device_id: ''}]\n",
            ("microsoft_defender_column", "entities.hosts.0.device_id"),
        ),
        (
            "entities:\n  registry_values: [{value_name: RegistryValueName}]\n",
            (
                "microsoft_defender_entity_identifier",
                "entities.registry_values.0",
            ),
        ),
        (
            "actions:\n  isolate_device: [{device_id: DeviceId}]\n",
            ("microsoft_defender_action_kind", "actions.isolate_device"),
        ),
        (
            "actions:\n  block_files: []\n",
            ("microsoft_defender_action_target", "actions.block_files"),
        ),
        (
            "actions:\n  block_files: [{sha1: SHA1, device_groups: []}]\n",
            (
                "microsoft_defender_action_target",
                "actions.block_files.0.device_groups",
            ),
        ),
        (
            "actions:\n  isolate_devices: [{device_id: DeviceId, isolation_type: Full}]\n",
            (
                "microsoft_defender_isolation_type",
                "actions.isolate_devices.0.isolation_type",
            ),
        ),
        (
            "scope:\n  device_groups: ['']\n",
            ("microsoft_defender_scope", "scope"),
        ),
    ];
    for (yaml, (code, path)) in cases {
        let found = if yaml.starts_with("schedule:") {
            block_findings(&load(&format!("status: STAGING\nquery: Q\n{yaml}")))
                .into_iter()
                .map(|finding| {
                    let path: Vec<String> = finding.path.iter().map(ToString::to_string).collect();
                    (finding.code.to_owned(), path.join("."))
                })
                .collect()
        } else {
            codes_at(yaml)
        };
        assert_eq!(found, [(code.to_owned(), path.to_owned())], "{yaml}");
        assert!(CONSTRAINT_CODES.contains(&code), "{code}");
    }
    assert_eq!(
        codes_at("incident:\n  exclude_from_correlation: yes please\n"),
        [(
            "microsoft_defender_incident".to_owned(),
            "incident".to_owned()
        )]
    );
    // Every code is reachable by one of the cases above.
    let mut reached: BTreeSet<&str> = cases_codes();
    reached.insert("microsoft_defender_incident");
    assert_eq!(reached, CONSTRAINT_CODES.into_iter().collect());
}

fn cases_codes() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "microsoft_defender_schema",
        "microsoft_defender_frequency",
        "microsoft_defender_lookback",
        "microsoft_defender_severity",
        "microsoft_defender_grouping",
        "microsoft_defender_custom_details",
        "microsoft_defender_column",
        "microsoft_defender_entity_kind",
        "microsoft_defender_entity_mapping",
        "microsoft_defender_entity_identifier",
        "microsoft_defender_action_kind",
        "microsoft_defender_action_target",
        "microsoft_defender_isolation_type",
        "microsoft_defender_scope",
    ])
}

#[test]
fn every_graph_enum_value_but_the_sentinels_is_accepted() {
    for severity in ["Informational", "Low", "Medium", "High", "Critical"] {
        assert_eq!(codes_at(&format!("alert:\n  severity: {severity}\n")), []);
    }
    for grouping in ["alert_per_event", "single_alert"] {
        assert_eq!(codes_at(&format!("alert:\n  grouping: {grouping}\n")), []);
    }
    for isolation in ["full", "selective"] {
        assert_eq!(
            codes_at(&format!(
                "actions:\n  isolate_devices: [{{device_id: D, isolation_type: {isolation}}}]\n"
            )),
            []
        );
    }
    for (frequency, lookback) in [
        ("NRT", None),
        ("1H", Some("1H")),
        ("24H", Some("1D")),
        ("1D", Some("24H")),
        ("12H", Some("30D")),
    ] {
        let lookback = lookback.map_or(String::new(), |lookback| {
            format!("  lookback: {lookback}\n")
        });
        let block = load(&format!(
            "status: STAGING\nquery: Q\nschedule:\n  frequency: {frequency}\n{lookback}"
        ));
        assert_eq!(
            block_codes(&block),
            BTreeSet::new(),
            "{frequency} {lookback}"
        );
    }
}

#[test]
fn durations_parse_and_print_as_graph_takes_them() {
    assert_eq!(
        Duration::parse("NRT").map(Duration::iso8601).as_deref(),
        Some("PT0S")
    );
    assert_eq!(
        Duration::parse("1H").map(Duration::iso8601).as_deref(),
        Some("PT1H")
    );
    assert_eq!(
        Duration::parse("24H").map(Duration::iso8601).as_deref(),
        Some("PT24H")
    );
    assert_eq!(
        Duration::parse("1D").map(Duration::iso8601).as_deref(),
        Some("P1D")
    );
    for bad in [
        "", "H", "0H", "01H", "1h", "1M", "PT1H", "-1H", "1.5H", "NRTH", "1é", "1😀", "é", "😀",
    ] {
        assert_eq!(Duration::parse(bad), None, "{bad}");
    }
    assert_eq!(Duration::parse("1D").and_then(Duration::hours), Some(24));
    assert_eq!(
        Duration::parse(&format!("{}D", u64::MAX)).and_then(Duration::hours),
        None,
        "no overflow"
    );
}

#[test]
fn a_schedule_ending_in_a_multi_byte_character_is_refused_not_a_panic() {
    // #1926: the unit was split off at a byte index inside the last character.
    for frequency in ["1é", "1😀", "é"] {
        let found: Vec<(String, String)> = block_findings(&load(&format!(
            "status: STAGING\nquery: Q\nschedule:\n  frequency: {frequency}\n"
        )))
        .into_iter()
        .map(|finding| {
            let path: Vec<String> = finding.path.iter().map(ToString::to_string).collect();
            (finding.code.to_owned(), path.join("."))
        })
        .collect();
        assert_eq!(
            found,
            [(
                "microsoft_defender_frequency".to_owned(),
                "schedule.frequency".to_owned()
            )],
            "{frequency}"
        );
    }
}

#[test]
fn a_block_that_maps_no_entity_earns_the_advisory() {
    let rule = |entities: &str| {
        load(&format!(
            "configurations:\n  microsoft_defender:\n    status: STAGING\n    query: Q\n{entities}"
        ))
    };
    for entities in ["", "    entities: {}\n", "    entities:\n      hosts: []\n"] {
        let found = advisories(&rule(entities));
        assert_eq!(found.len(), 1, "{entities:?}");
        assert_eq!(found[0].code, "microsoft_defender_no_entities");
    }
    assert!(advisories(&rule("    entities:\n      hosts: [{device_id: D}]\n")).is_empty());
}

/// The identifier table: one row per kind, in the kinds' order, naming only
/// its kind's fields, each row with its source and date; only observed or
/// documented evidence carries a required field.
#[test]
fn the_identifier_table_has_one_sourced_row_per_kind() {
    assert_eq!(
        ENTITY_IDENTIFIERS.map(|row| row.kind),
        ENTITY_KINDS.map(|kind| kind.key)
    );
    for row in ENTITY_IDENTIFIERS {
        let kind = entity_kind(row.kind).unwrap();
        for (field, identifier) in row.required {
            assert!(kind.graph_field(field).is_some(), "{}.{field}", row.kind);
            assert!(!identifier.is_empty(), "{}.{field}", row.kind);
        }
        for identifier in row.asset {
            assert!(!identifier.fields.is_empty(), "{}", row.kind);
            for field in identifier.fields {
                assert!(kind.graph_field(field).is_some(), "{}.{field}", row.kind);
            }
            // Advice, never an error; a column list only where the page
            // names columns.
            assert_eq!(identifier.source.evidence, Evidence::Advised);
            assert_eq!(identifier.source.checked, IDENTIFIERS_CHECKED);
            assert_eq!(
                identifier.columns.is_empty(),
                identifier.source != IMPACTED_ASSET_COLUMNS,
                "{}: {:?}",
                row.kind,
                identifier.fields
            );
        }
        assert_eq!(row.source.checked, IDENTIFIERS_CHECKED, "{}", row.kind);
        assert!(!row.source.reference.is_empty(), "{}", row.kind);
        match row.source.evidence {
            Evidence::Observed | Evidence::Documented => {
                assert!(!row.required.is_empty(), "{}", row.kind);
            }
            Evidence::OneField => {
                assert!(row.required.is_empty(), "{}", row.kind);
                assert_eq!(kind.fields.len(), 1, "{}", row.kind);
            }
            Evidence::Unprobed => {
                assert!(row.required.is_empty(), "{}", row.kind);
                assert!(kind.fields.len() > 1, "{}", row.kind);
            }
            Evidence::Advised => panic!("{}: advice is never a required field", row.kind),
        }
    }
    // The impacted assets with more than one field: the device and the user
    // (a mailbox mapping names its one field, its address).
    let assets: Vec<&str> = ENTITY_IDENTIFIERS
        .iter()
        .filter(|row| !row.asset.is_empty())
        .map(|row| row.kind)
        .collect();
    assert_eq!(assets, ["hosts", "accounts"]);
}

/// The errors of the block mapping `mapping` under the kind `kind`.
fn entity_codes(kind: &str, mapping: &str) -> Vec<(String, String)> {
    codes_at(&format!("entities:\n  {kind}: [{mapping}]\n"))
}

/// A mapping of `fields`, each to a column named after it.
fn mapping_of(fields: &[&str]) -> String {
    let pairs: Vec<String> = fields
        .iter()
        .map(|field| format!("{field}: Column_{field}"))
        .collect();
    format!("{{{}}}", pairs.join(", "))
}

/// For every kind, a valid and an invalid mapping: the mapping with every
/// field is valid, and so is each field alone unless the kind requires
/// another; the invalid one lacks what the kind's rule requires (its
/// required field, or, with none, any field at all).
#[test]
fn every_kind_has_a_valid_and_an_invalid_mapping() {
    for row in ENTITY_IDENTIFIERS {
        let kind = entity_kind(row.kind).unwrap();
        let fields: Vec<&str> = kind.fields.iter().map(|(field, _)| *field).collect();
        assert_eq!(
            entity_codes(row.kind, &mapping_of(&fields)),
            [],
            "{}: every field",
            row.kind
        );
        for field in &fields {
            let alone = entity_codes(row.kind, &mapping_of(&[field]));
            let missing: Vec<(String, String)> = row
                .required
                .iter()
                .filter(|(required, _)| required != field)
                .map(|_| {
                    (
                        "microsoft_defender_entity_identifier".to_owned(),
                        format!("entities.{}.0", row.kind),
                    )
                })
                .collect();
            assert_eq!(alone, missing, "{}.{field} alone", row.kind);
        }
        let invalid = if row.required.is_empty() {
            ("{}".to_owned(), "microsoft_defender_entity_mapping")
        } else {
            let others: Vec<&str> = fields
                .iter()
                .copied()
                .filter(|field| row.required.iter().all(|(required, _)| required != field))
                .collect();
            (mapping_of(&others), "microsoft_defender_entity_identifier")
        };
        let found = entity_codes(row.kind, &invalid.0);
        assert_eq!(
            found,
            [(invalid.1.to_owned(), format!("entities.{}.0", row.kind))],
            "{}: {}",
            row.kind,
            invalid.0
        );
    }
}

/// #1884: the issue's block passes the shape checks and Graph refuses it.
/// The finding is on the mapping, names the missing field, Graph's
/// identifier and its property, and the model rejects the block with it.
#[test]
fn a_registry_value_without_its_key_is_refused_as_graph_refuses_it() {
    let yaml = "entities:\n  accounts:\n    - upn: InitiatingProcessAccountUpn\n  \
                registry_values:\n    - value_name: RegistryValueName   # no key\n";
    let found = block_findings(&block_of(yaml));
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].code, "microsoft_defender_entity_identifier");
    let message = &found[0].message;
    for needle in ["entities.registry_values[0]", "key", "RegKey", "keyColumn"] {
        assert!(message.contains(needle), "{needle}: {message}");
    }
    let (value, errors) = convert(&block_of(yaml));
    assert!(value.is_none());
    assert_eq!(
        errors,
        [(
            "microsoft_defender_entity_identifier".to_owned(),
            "entities.registry_values.0".to_owned()
        )]
    );
    // With its key, the same block converts.
    let keyed = yaml.replace(
        "    - value_name: RegistryValueName   # no key\n",
        "    - key: RegistryKey\n      value_name: RegistryValueName\n",
    );
    assert_eq!(convert(&block_of(&keyed)).1, []);
    // A key with a blank column is the column's finding, not a missing key.
    assert_eq!(
        entity_codes("registry_values", "{key: '', value_name: V}"),
        [(
            "microsoft_defender_column".to_owned(),
            "entities.registry_values.0.key".to_owned()
        )]
    );
    // A mapping with a field its kind lacks is the shape's finding alone.
    assert_eq!(
        entity_codes("registry_values", "{value: V}"),
        [(
            "microsoft_defender_entity_mapping".to_owned(),
            "entities.registry_values.0".to_owned()
        )]
    );
    // Each mapping is judged on its own.
    assert_eq!(
        entity_codes(
            "registry_values",
            "{key: K, value_name: V}, {value_name: V}"
        ),
        [(
            "microsoft_defender_entity_identifier".to_owned(),
            "entities.registry_values.1".to_owned()
        )]
    );
}

/// The impacted-asset advisories of a rule whose block maps `entities`.
fn asset_advisories(entities: &str) -> Vec<(String, String)> {
    let rule = load(&format!(
        "configurations:\n  microsoft_defender:\n    status: STAGING\n    query: Q\n    \
         entities:\n{entities}"
    ));
    advisories(&rule)
        .into_iter()
        .map(|advisory| (advisory.code.to_owned(), advisory.field_path.join(".")))
        .collect()
}

#[test]
fn an_impacted_asset_without_a_strong_identifier_earns_the_advisory() {
    let at = |path: &str| {
        vec![(
            "microsoft_defender_impacted_asset_identifier".to_owned(),
            format!("configurations.microsoft_defender.entities.{path}"),
        )]
    };
    // Weak alone: a user by name, a device by its domain or NetBIOS name.
    for (entities, path) in [
        ("      accounts: [{name: AccountName}]\n", "accounts.0"),
        (
            "      accounts: [{nt_domain: AccountDomain}]\n",
            "accounts.0",
        ),
        (
            "      accounts: [{upn: AccountUpn}, {name: AccountName}]\n",
            "accounts.1",
        ),
        ("      hosts: [{dns_domain: D}]\n", "hosts.0"),
        ("      hosts: [{netbios_name: N}]\n", "hosts.0"),
        ("      hosts: [{nt_domain: D, dns_domain: D}]\n", "hosts.0"),
    ] {
        assert_eq!(asset_advisories(entities), at(path), "{entities}");
    }
    // A column the wizard maps to the asset, or a strong combination of
    // Sentinel's entity reference, identifies it.
    for entities in [
        "      accounts: [{aad_user_id: AccountObjectId}]\n",
        "      accounts: [{sid: AccountSid, name: AccountName}]\n",
        "      accounts: [{upn: InitiatingProcessAccountUpn}]\n",
        "      accounts: [{name: AccountName, nt_domain: AccountDomain}]\n",
        "      accounts: [{name: AccountName, dns_domain: AccountDnsDomain}]\n",
        "      accounts: [{name: AccountName, upn_suffix: AccountUpnSuffix}]\n",
        "      hosts: [{device_id: DeviceId}]\n",
        "      hosts: [{name: DeviceName}]\n",
        "      hosts: [{name: DeviceName, dns_domain: D}]\n",
        "      hosts: [{netbios_name: N, nt_domain: D}]\n",
        "      hosts: [{netbios_name: N, dns_domain: D}]\n",
        // A mailbox has one field, its address; evidence kinds are not
        // impacted assets.
        "      mailboxes: [{primary_address: RecipientEmailAddress}]\n",
        "      ips: [{scope: S}]\n",
        // A mapping a constraint reports earns no advisory.
        "      accounts: [{}]\n",
        "      accounts: [{name: A, device_id: D}]\n",
        "      accounts: [name]\n",
        "      accounts: {name: A}\n",
    ] {
        assert_eq!(asset_advisories(entities), [], "{entities}");
    }
    assert!(ADVISORY_CODES.contains(&"microsoft_defender_impacted_asset_identifier"));
    let rule = load(
        "configurations:\n  microsoft_defender:\n    status: STAGING\n    query: Q\n    \
         entities:\n      accounts: [{name: AccountName}]\n",
    );
    let message = &advisories(&rule)[0].message;
    for needle in [
        "entities.accounts[0]",
        "impacted user",
        "aad_user_id (AccountObjectId)",
        "sid",
        "upn",
        "name + nt_domain",
        "name + upn_suffix",
    ] {
        assert!(message.contains(needle), "{needle}: {message}");
    }
}

/// The advisories of a block that maps a host, with `alert` (YAML at the
/// block's indentation plus two), as `(code, dotted path)`.
fn alert_advisories(alert: &str) -> Vec<(String, String)> {
    let rule = load(&format!(
        "configurations:\n  microsoft_defender:\n    status: STAGING\n    query: Q\n    \
         entities:\n      hosts: [{{device_id: DeviceId}}]\n    alert:\n{alert}"
    ));
    advisories(&rule)
        .into_iter()
        .map(|advisory| (advisory.code.to_owned(), advisory.field_path.join(".")))
        .collect()
}

#[test]
fn custom_details_past_the_documented_limits_earn_the_advisory() {
    let details = |count: usize| -> String {
        let mut out = "      custom_details:\n".to_owned();
        for n in 1..=count {
            out.push_str(&format!("        Detail{n}: Column{n}\n"));
        }
        out
    };
    // Twenty is the documented limit.
    assert_eq!(alert_advisories(&details(20)), []);
    assert_eq!(
        alert_advisories(&details(21)),
        [(
            "microsoft_defender_custom_details_limit".to_owned(),
            "configurations.microsoft_defender.alert.custom_details".to_owned()
        )]
    );
    // Names that fill 4 KB on their own leave no room for a value (written
    // as explicit keys: YAML caps an implicit key at 1024 characters).
    let long = |length: usize| {
        format!(
            "      custom_details:\n        ? {}\n        : A\n        ? {}\n        : B\n",
            "a".repeat(length),
            "b".repeat(length)
        )
    };
    assert_eq!(alert_advisories(&long(2048)), []);
    assert_eq!(
        alert_advisories(&long(2049))
            .into_iter()
            .map(|(code, _)| code)
            .collect::<Vec<_>>(),
        ["microsoft_defender_custom_details_limit"]
    );
    // Not a mapping: the constraint's, not the advisory's.
    assert_eq!(alert_advisories("      custom_details: [A]\n"), []);
}

#[test]
fn more_than_three_columns_in_a_title_or_description_earn_the_advisory() {
    let three = "      title: \"{{A}} on {{B}} by {{C}}, {{A}} again\"\n";
    assert_eq!(alert_advisories(three), []);
    // Braces around anything but a bare identifier are not a column: JSON,
    // prose, and the spaced form, whose substitution is not documented.
    let not_columns = "      description: '{{A}} {{B}} {{C}} {{ D }} {{\"k\": 1}} {{two words}}'\n";
    assert_eq!(alert_advisories(not_columns), []);
    let four = "      title: \"{{A}} {{B}} {{C}} {{D}}\"\n      description: \"{{A}} {{B}} {{C}} \
                {{D}}\"\n";
    assert_eq!(
        alert_advisories(four),
        [
            (
                "microsoft_defender_placeholder_limit".to_owned(),
                "configurations.microsoft_defender.alert.title".to_owned()
            ),
            (
                "microsoft_defender_placeholder_limit".to_owned(),
                "configurations.microsoft_defender.alert.description".to_owned()
            ),
        ]
    );
    assert_eq!(
        placeholder_columns("{{A}} {{ A }} {{}} {{ {x} }} {{B}} {{_c1}} {{1d}} {{a.b}} {{C"),
        ["A", "B", "_c1"]
    );
}

/// The keys of a YAML block, as dotted paths, list items read through.
fn key_paths(node: &Node, prefix: &str, out: &mut BTreeSet<String>) {
    match &node.value {
        Value::Map(entries) => {
            for entry in entries {
                let key = entry.key.value.as_str().unwrap_or_default();
                let path = if prefix.is_empty() {
                    key.to_owned()
                } else {
                    format!("{prefix}.{key}")
                };
                out.insert(path.clone());
                key_paths(&entry.value, &path, out);
            }
        }
        Value::Seq(items) => {
            for item in items {
                key_paths(item, prefix, out);
            }
        }
        _ => {}
    }
}

/// Every key of the block the specification's field tables define.
fn every_key() -> BTreeSet<String> {
    let mut keys: BTreeSet<String> = [
        "enabled",
        "name",
        "schema",
        "status",
        "tenants",
        "flags",
        "contributors",
        "query",
        "schedule",
        "schedule.frequency",
        "schedule.lookback",
        "alert",
        "alert.title",
        "alert.description",
        "alert.severity",
        "alert.recommendation",
        "alert.techniques",
        "alert.custom_details",
        "alert.grouping",
        "entities",
        "actions",
        "scope",
        "scope.device_groups",
        "incident",
        "incident.exclude_from_correlation",
        "exclusions",
        "exclusions.query",
        "exclusions.reason",
        "exclusions.tenant",
        "exclusions.let",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for (section, table) in [("entities", &ENTITY_KINDS[..]), ("actions", &ACTIONS[..])] {
        for kind in table {
            keys.insert(format!("{section}.{}", kind.key));
            for (field, _) in kind.fields {
                keys.insert(format!("{section}.{}.{field}", kind.key));
            }
        }
    }
    keys
}

#[test]
fn the_complete_block_sets_every_key_of_the_field_tables() {
    let (_, root) = load_rule(&fixtures().join("microsoft-defender-complete.yaml"));
    let mut found = BTreeSet::new();
    key_paths(block(&root), "", &mut found);
    // `custom_details` and `let` hold names of the author's choosing.
    found.retain(|path| {
        !path.starts_with("alert.custom_details.") && !path.starts_with("exclusions.let.")
    });
    assert_eq!(found, every_key());
}

/// The template with each commented line uncommented, its marks dropped.
fn uncommented(template: &str) -> String {
    template
        .lines()
        .filter(|line| !line.trim_start().starts_with("# "))
        .map(|line| {
            let line = line.split("  # beta-only").next().unwrap_or(line);
            match line.find('#') {
                Some(at) if line[..at].trim().is_empty() => {
                    format!("{}{}", &line[..at], &line[at + 1..])
                }
                _ => line.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_template_carries_every_key_and_marks_the_beta_ones() {
    // Each placeholder filled in: `...`, an empty list item, and a key with
    // no value and nothing nested under it.
    let uncommented = uncommented(TEMPLATE).replace("...", "DeviceProcessEvents");
    let lines: Vec<&str> = uncommented.lines().collect();
    let indent = |line: &str| line.len() - line.trim_start().len();
    let text = lines
        .iter()
        .enumerate()
        .map(|(at, line)| {
            let trimmed = line.trim_end();
            if trimmed.trim() == "-" {
                return format!("{trimmed} x");
            }
            if !trimmed.ends_with(':') {
                return trimmed.to_owned();
            }
            let nested = lines[at + 1..]
                .iter()
                .find(|next| !next.trim().is_empty())
                .is_some_and(|next| indent(next) > indent(line));
            if nested {
                trimmed.to_owned()
            } else {
                format!("{trimmed} x")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let root = load(&text);
    let mut found = BTreeSet::new();
    key_paths(&root, "", &mut found);
    found.retain(|path| {
        !path.starts_with("alert.custom_details.") && !path.starts_with("exclusions.let.")
    });
    assert_eq!(found, every_key(), "{text}");
    let (value, errors) = convert(&root);
    assert!(errors.is_empty(), "{errors:?}\n{text}");
    assert!(value.is_some());
    // The required keys are live; every optional one is commented out.
    let live: Vec<&str> = TEMPLATE
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(str::trim)
        .collect();
    assert_eq!(
        live,
        [
            "schema: platform::microsoft_defender::1.0",
            "status:",
            "query: |",
            "...",
            "schedule:",
            "frequency: 1H"
        ]
    );
    for beta in ["#lookback:", "#grouping:", "#incident:"] {
        let marked = TEMPLATE
            .lines()
            .find(|line| line.trim_start().starts_with(beta))
            .unwrap();
        assert!(marked.ends_with("# beta-only"), "{marked}");
    }
}

/// The Graph type of each kind's mappings or targets.
fn graph_type(kind: &str) -> &'static str {
    match kind {
        "hosts" => "hostEntityMapping",
        "accounts" => "accountEntityMapping",
        "mailboxes" => "mailboxEntityMapping",
        "files" => "fileEntityMapping",
        "processes" => "processEntityMapping",
        "ips" => "ipEntityMapping",
        "urls" => "urlEntityMapping",
        "dns" => "dnsEntityMapping",
        "registry_values" => "registryValueEntityMapping",
        "mail_messages" => "mailMessageEntityMapping",
        "mail_clusters" => "mailClusterEntityMapping",
        "cloud_applications" => "cloudApplicationEntityMapping",
        "oauth_applications" => "oAuthApplicationEntityMapping",
        "security_groups" => "securityGroupEntityMapping",
        "azure_resources" => "azureResourceEntityMapping",
        "amazon_resources" => "amazonResourceEntityMapping",
        "google_cloud_resources" => "googleCloudResourceEntityMapping",
        "isolate_devices" => "isolateDeviceAction",
        "allow_files" | "block_files" => "fileAction",
        "stop_and_quarantine_files" => "stopAndQuarantineFileAction",
        "disable_users" | "force_user_password_resets" => "accountSidAction",
        "mark_users_as_compromised" => "accountObjectIdAction",
        "soft_delete_emails"
        | "hard_delete_emails"
        | "move_emails_to_deleted_items"
        | "move_emails_to_inbox"
        | "move_emails_to_junk" => "emailAction",
        _ => "deviceAction",
    }
}

/// The Graph properties a key of the block sends, as `type.property`.
fn modelled() -> BTreeSet<String> {
    let mut out: BTreeSet<String> = [
        "detectionRule.queryCondition",
        "detectionRule.schedule",
        "detectionRule.detectionAction",
        "ruleSchedule.frequency",
        "ruleSchedule.lookback",
        "detectionAction.alertTemplate",
        "detectionAction.automatedActions",
        "detectionAction.organizationalScope",
        "detectionAction.incidentConfiguration",
        "alertTemplate.title",
        "alertTemplate.description",
        "alertTemplate.severity",
        "alertTemplate.recommendedActions",
        "alertTemplate.customDetails",
        "alertTemplate.entityMappings",
        "alertTemplate.eventGroupingKind",
        "organizationalScope.deviceGroups",
        "incidentConfiguration.isExcludedFromIncidentCorrelation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for (container, table) in [
        ("entityMappingConfiguration", &ENTITY_KINDS[..]),
        ("automatedActionSet", &ACTIONS[..]),
    ] {
        for kind in table {
            out.insert(format!("{container}.{}", kind.graph));
            for (_, graph) in kind.fields {
                out.insert(format!("{}.{graph}", graph_type(kind.key)));
            }
        }
    }
    out
}

#[test]
fn every_graph_beta_property_is_modelled_or_listed_with_its_reason() {
    let snapshot: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures().join("graph-beta-properties.json")).unwrap(),
    )
    .unwrap();
    let modelled = modelled();
    let mut seen = BTreeSet::new();
    for (type_name, properties) in snapshot["types"].as_object().unwrap() {
        for (property, marks) in properties.as_object().unwrap() {
            let key = format!("{type_name}.{property}");
            seen.insert(key.clone());
            let listed = NOT_MODELLED.iter().find(|(name, _)| *name == key);
            let deprecated = marks["deprecated"].as_bool().unwrap();
            let read_only = marks["readOnly"].as_bool().unwrap();
            match listed {
                None => {
                    assert!(
                        modelled.contains(&key),
                        "{key} is neither modelled nor listed"
                    );
                    assert!(!deprecated && !read_only, "{key} is modelled but {marks}");
                }
                Some((_, reason)) => {
                    assert!(!modelled.contains(&key), "{key} is modelled and listed");
                    match reason {
                        NotModelled::Deprecated => assert!(deprecated, "{key}: {marks}"),
                        NotModelled::ReadOnly => assert!(read_only, "{key}: {marks}"),
                        NotModelled::SetByDeploy => {
                            assert!(!deprecated && !read_only, "{key}: {marks}");
                        }
                    }
                }
            }
        }
    }
    // Nothing modelled or listed is missing from the snapshot.
    for key in modelled.iter().chain(
        NOT_MODELLED
            .iter()
            .map(|(key, _)| (*key).to_owned())
            .collect::<Vec<_>>()
            .iter(),
    ) {
        assert!(seen.contains(key), "{key} is not in the snapshot");
    }
    // The enums: each value but `unknownFutureValue` (and Defender's own
    // `autoDisabled`) is a value the block takes.
    let enums = &snapshot["enums"];
    let values = |name: &str| -> Vec<String> {
        enums[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .filter(|value| value != "unknownFutureValue")
            .collect()
    };
    use opentide_schema::objects::platform::microsoft_defender::{GROUPINGS, ISOLATION_TYPES};
    assert_eq!(
        values("eventGroupingKind"),
        GROUPINGS
            .iter()
            .map(|(_, graph)| (*graph).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(values("isolationType"), ISOLATION_TYPES);
    assert_eq!(
        values("alertTemplate.severity"),
        ["informational", "low", "medium", "high"]
    );
    assert_eq!(
        values("detectionRuleStatus"),
        ["enabled", "disabled", "autoDisabled"]
    );
}
