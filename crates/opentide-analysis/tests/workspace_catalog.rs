//! Workspace catalogs replace the bundled ones for the whole process, so this
//! test has a binary of its own.

use opentide_analysis::{
    AnalyzeRequest, Catalog, LanguageId, MemoryWorkspace, analyze, catalog_is_workspace,
    catalog_version, codes, install_catalog,
};

const RULE: &str = "name: House Rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n  tlp: house\n  legacy: yes\n";

fn codes_of(text: &str) -> Vec<String> {
    analyze(
        &MemoryWorkspace::default(),
        AnalyzeRequest {
            uri: "objects/rules/house-rule.yaml".into(),
            language: LanguageId::TideYaml,
            text: text.into(),
        },
    )
    .diagnostics
    .into_iter()
    .map(|d| d.code)
    .collect()
}

#[test]
fn workspace_catalogs_replace_the_bundled_ones() {
    assert!(!catalog_is_workspace());
    assert!(codes_of(RULE).contains(&codes::VOCAB_UNKNOWN.to_string()));

    let fields = r#"{"opentide": "0.19.0", "fields": [
        {"schema": "rule", "path": "metadata", "name": "metadata", "type": "object"},
        {"schema": "rule", "path": "metadata.tlp", "name": "tlp", "type": "string",
         "enum": ["clear", "house"]}]}"#;
    let deprecations = r#"{"fields": [
        {"schema": "rule", "path": "metadata.legacy", "message": "gone in 2.0"}]}"#;
    install_catalog(&Catalog {
        fields: Some(fields.into()),
        deprecations: Some(deprecations.into()),
    })
    .expect("install");
    assert!(catalog_is_workspace());
    assert_eq!(catalog_version(), "0.19.0");
    let found = codes_of(RULE);
    assert!(
        !found.contains(&codes::VOCAB_UNKNOWN.to_string()),
        "{found:?}"
    );
    assert!(
        found.contains(&codes::DEPRECATED_FIELD.to_string()),
        "{found:?}"
    );

    // A part that does not parse changes nothing.
    let err = install_catalog(&Catalog {
        fields: Some("{".into()),
        deprecations: None,
    })
    .unwrap_err();
    assert!(err.starts_with("fields.json"), "{err}");
    assert!(codes_of(RULE).contains(&codes::DEPRECATED_FIELD.to_string()));

    install_catalog(&Catalog::default()).expect("reset");
    assert!(!catalog_is_workspace());
    assert!(codes_of(RULE).contains(&codes::VOCAB_UNKNOWN.to_string()));
}
