//! The workspace Tide field catalog replaces the bundled one process-wide, so
//! it lives in its own test binary: the crate's unit tests read the bundled
//! catalog on other threads.

use opentide_highlight::{
    install_tide_fields, tide_catalog_is_workspace, tide_catalog_version, tide_field_at,
};

const WORKSPACE: &str = r#"{
  "opentide": "9.9.9",
  "fields": [
    {"schema": "rule", "path": "metadata", "name": "metadata", "type": "object"},
    {"schema": "rule", "path": "metadata.tlp", "name": "tlp", "type": "string",
     "enum": ["clear", "green", "house"]}
  ]
}"#;

#[test]
fn a_workspace_catalog_replaces_the_bundled_one_until_reset() {
    let bundled = tide_catalog_version().to_string();
    assert!(!tide_catalog_is_workspace());
    assert!(
        !tide_field_at("rule", "metadata.tlp")
            .expect("bundled tlp")
            .enum_values
            .iter()
            .any(|value| value == "house")
    );

    install_tide_fields(Some(WORKSPACE)).expect("install");
    assert!(tide_catalog_is_workspace());
    assert_eq!(tide_catalog_version(), "9.9.9");
    let tlp = tide_field_at("rule", "metadata.tlp").expect("workspace tlp");
    assert!(tlp.enum_values.iter().any(|value| value == "house"));
    assert!(tide_field_at("rule", "description").is_none());

    // The same text again reuses the catalog it built.
    install_tide_fields(Some(WORKSPACE)).expect("reinstall");
    assert!(std::ptr::eq(
        tlp,
        tide_field_at("rule", "metadata.tlp").expect("tlp")
    ));

    // A catalog that does not parse, or lists nothing, is refused and keeps
    // the one in use.
    assert!(install_tide_fields(Some("{")).is_err());
    assert!(install_tide_fields(Some(r#"{"opentide": "1", "fields": []}"#)).is_err());
    assert_eq!(tide_catalog_version(), "9.9.9");

    install_tide_fields(None).expect("reset");
    assert!(!tide_catalog_is_workspace());
    assert_eq!(tide_catalog_version(), bundled);
    assert!(tide_field_at("rule", "description").is_some());
}
