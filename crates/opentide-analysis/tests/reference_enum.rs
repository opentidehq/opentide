//! A reference is checked against the workspace index, never against a list
//! of UUIDs a catalog carries (a workspace catalog from an older opentide
//! enumerated them). Installs a catalog process-wide: a binary of its own.

use opentide_analysis::{
    AnalyzeRequest, Catalog, LanguageId, MemoryWorkspace, analyze, codes, install_catalog,
};

const RULE: &str = "name: Rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\ndetection_model: 00000000-0000-4000-8002-00000000ffff\n";

#[test]
fn a_reference_is_not_checked_against_a_snapshot_of_uuids() {
    install_catalog(&Catalog {
        fields: Some(
            r#"{"opentide": "refs", "fields": [
              {"schema": "rule", "path": "detection_model", "name": "detection_model",
               "type": "string", "ref": "objective",
               "enum": ["00000000-0000-4000-8002-000000000001"]}
            ]}"#
            .into(),
        ),
        deprecations: None,
        visibility: None,
    })
    .expect("install");
    let codes: Vec<String> = analyze(
        &MemoryWorkspace::default(),
        AnalyzeRequest {
            uri: "objects/rules/rule.yaml".into(),
            language: LanguageId::TideYaml,
            text: RULE.into(),
        },
    )
    .diagnostics
    .into_iter()
    .map(|d| d.code)
    .collect();
    assert!(
        !codes.contains(&codes::VOCAB_UNKNOWN.to_string()),
        "{codes:?}"
    );
    install_catalog(&Catalog::default()).expect("reset");
}
