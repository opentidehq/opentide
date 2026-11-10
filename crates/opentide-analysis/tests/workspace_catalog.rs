//! Workspace catalogs replace the bundled ones for the whole process, so this
//! test has a binary of its own.

use opentide_analysis::{Catalog, catalog_is_workspace, catalog_version, install_catalog};

/// Whether the field catalog in use lets `metadata.tlp` be `house`: what
/// hover, completion and highlighting read (the object checks themselves are
/// `validate`'s, UC-2.6).
fn house_is_a_tlp() -> bool {
    opentide_highlight::tide_field_at("rule", "metadata.tlp")
        .is_some_and(|field| field.enum_values.iter().any(|value| value == "house"))
}

#[test]
fn workspace_catalogs_replace_the_bundled_ones() {
    assert!(!catalog_is_workspace());
    assert!(!house_is_a_tlp());

    let fields = r#"{"opentide": "0.19.0", "fields": [
        {"schema": "rule", "path": "metadata", "name": "metadata", "type": "object"},
        {"schema": "rule", "path": "metadata.tlp", "name": "tlp", "type": "string",
         "enum": ["clear", "house"]}]}"#;
    let deprecations = r#"{"fields": [
        {"schema": "rule", "path": "metadata.legacy", "message": "gone in 2.0"}]}"#;
    install_catalog(&Catalog {
        fields: Some(fields.into()),
        deprecations: Some(deprecations.into()),
        visibility: None,
    })
    .expect("install");
    assert!(catalog_is_workspace());
    assert_eq!(catalog_version(), "0.19.0");
    assert!(house_is_a_tlp());

    // A part that does not parse changes nothing.
    let err = install_catalog(&Catalog {
        fields: Some("{".into()),
        deprecations: None,
        visibility: None,
    })
    .unwrap_err();
    assert!(err.starts_with("fields.json"), "{err}");
    assert!(house_is_a_tlp());

    install_catalog(&Catalog::default()).expect("reset");
    assert!(!catalog_is_workspace());
    assert!(!house_is_a_tlp());
}
