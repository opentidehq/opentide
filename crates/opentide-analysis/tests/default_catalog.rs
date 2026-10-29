//! A host's default catalog replaces the bundled one for the whole process,
//! so this test has a binary of its own.

use opentide_analysis::{
    AnalyzeRequest, Catalog, LanguageId, MemoryWorkspace, analyze, catalog_version, codes,
    install_catalog, set_default_catalog,
};

const RULE: &str = "name: House Rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n  tlp: house\n";

fn catalog(version: &str, tlp: &[&str]) -> String {
    let values = tlp
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"{{"opentide": "{version}", "fields": [
          {{"schema": "rule", "path": "metadata", "name": "metadata", "type": "object"}},
          {{"schema": "rule", "path": "metadata.tlp", "name": "tlp", "type": "string", "enum": [{values}]}}
        ]}}"#
    )
}

fn vocab_unknown(text: &str) -> bool {
    has(text, codes::VOCAB_UNKNOWN)
}

fn has(text: &str, code: &str) -> bool {
    analyze(
        &MemoryWorkspace::default(),
        AnalyzeRequest {
            uri: "objects/rules/house-rule.yaml".into(),
            language: LanguageId::TideYaml,
            text: text.into(),
        },
    )
    .diagnostics
    .iter()
    .any(|d| d.code == code)
}

#[test]
fn a_default_catalog_stands_in_for_the_bundled_one_under_workspace_catalogs() {
    let bundled = catalog_version().to_string();
    assert!(vocab_unknown(RULE));

    let host = Catalog {
        fields: Some(catalog("host", &["clear", "house"])),
        deprecations: Some(
            r#"{"opentide": "host", "fields": [{"schema": "rule", "path": "metadata.tlp", "message": "use labels"}]}"#
                .into(),
        ),
        datasets: None,
    };
    set_default_catalog(&host).expect("default");
    assert_eq!(catalog_version(), "host");
    assert!(!vocab_unknown(RULE));
    assert!(has(RULE, codes::DEPRECATED_FIELD));

    // A workspace catalog still wins; resetting it goes back to the default,
    // not to the bundled catalog: what the server's initialize does when a
    // workspace has no catalog.
    let workspace = Catalog {
        fields: Some(catalog("workspace", &["clear"])),
        deprecations: None,
        datasets: None,
    };
    install_catalog(&workspace).expect("workspace");
    assert_eq!(catalog_version(), "workspace");
    assert!(vocab_unknown(RULE));
    install_catalog(&Catalog::default()).expect("reset");
    assert_eq!(catalog_version(), "host");

    // A default that does not parse changes nothing; None is the bundled one.
    assert!(
        set_default_catalog(&Catalog {
            fields: Some("{".into()),
            deprecations: None,
            datasets: None,
        })
        .is_err()
    );
    assert_eq!(catalog_version(), "host");
    set_default_catalog(&Catalog::default()).expect("bundled");
    assert_eq!(catalog_version(), bundled);
    assert!(!has(RULE, codes::DEPRECATED_FIELD));
}
