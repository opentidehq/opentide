//! The revision registry as a dependent crate sees it (UC-1.7, #813): built
//! without `cfg(test)`; rules, with their platform blocks (UC-1.4, #810),
//! threats and objectives are all read.

use opentide_schema::node;
use opentide_schema::revisions::{self, Selection, TideObject};

const THREAT: &str = "name: Threat\ncriticality: High\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000002\n  \
                      schema: threat::1.0\n  version: 1\n  created: '2026-01-01'\n  modified: '2026-01-02'\n  \
                      tlp: clear\nthreat:\n  description: d\n  severity: High\n  impact: [Data Breach]\n  \
                      leverage: [Code Execution]\n  viability: Proven\n  terrain: t\n  surface: [Endpoint]\n  \
                      mitre_attack: [T1059]\n";

const RULE: &str = "name: Rule\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n  schema: rule::1.1\n  \
                    version: 1\n  created: '2026-01-01'\n  modified: '2026-01-02'\n  tlp: clear\ndescription: d\n";

#[test]
fn a_threat_revision_dispatches_to_its_struct() {
    let document = node::load(THREAT).unwrap();
    let read = revisions::read(&document, "threat").unwrap();
    assert_eq!(
        read.selection,
        Selection::Registered(revisions::lookup("threat::1.0").unwrap())
    );
    assert!(matches!(read.result, Ok(TideObject::ThreatV1_0(_))));
}

#[test]
fn an_unknown_threat_revision_is_checked_against_the_newest() {
    let text = THREAT.replace("threat::1.0", "threat::2.0") + "extra: 1\n";
    let document = node::load(&text).unwrap();
    let read = revisions::read(&document, "threat").unwrap();
    assert_eq!(read.selection.revision().identifier, "threat::1.0");
    let errors = read.result.unwrap_err();
    let paths: Vec<String> = errors.iter().map(|e| e.field_path().join(".")).collect();
    assert_eq!(paths, ["metadata.schema"]);
}

#[test]
fn a_rule_revision_dispatches_to_its_struct() {
    let document = node::load(RULE).unwrap();
    assert_eq!(
        revisions::select(&document, "rule"),
        Ok(Selection::Registered(
            revisions::lookup("rule::1.1").unwrap()
        ))
    );
    let read = revisions::read(&document, "rule").unwrap();
    assert!(matches!(read.result, Ok(TideObject::RuleV1_1(_))));
}

#[test]
fn a_splunk_lookback_too_long_for_deploy_fails_the_rule() {
    // #1928: deploy refused it (or, before, wrote a corrupt earliest time)
    // while `validate` passed it.
    let text = RULE.to_owned()
        + "configurations:\n  splunk:\n    status: STAGING\n    query: index=main | head 1\n    \
           scheduling:\n      timerange: {lookback: 9999999999999999d}\n";
    let document = node::load(&text).unwrap();
    let errors = revisions::read(&document, "rule")
        .unwrap()
        .result
        .unwrap_err();
    let found: Vec<(Option<&str>, String, &str)> = errors
        .iter()
        .map(|error| {
            (
                error.kind.pydantic_type(),
                error.field_path().join("."),
                error.message.as_str(),
            )
        })
        .collect();
    assert_eq!(
        found,
        [(
            Some("value_error"),
            "configurations.splunk.scheduling.timerange.lookback".to_owned(),
            "Lookback \"9999999999999999d\" is too long to express in minutes (at \
             most 9223372036854775807 minutes)"
        )]
    );
    let fits = text.replace("9999999999999999d", "6405119470038038d");
    let document = node::load(&fits).unwrap();
    assert!(revisions::read(&document, "rule").unwrap().result.is_ok());
}
