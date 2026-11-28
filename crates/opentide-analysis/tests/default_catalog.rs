//! A host's default catalog replaces the bundled one for the whole process,
//! so this test has a binary of its own.

use opentide_analysis::{Catalog, catalog_version, install_catalog, set_default_catalog};

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

/// Whether the field catalog in use lets `metadata.tlp` be `house`: what
/// hover, completion and highlighting read (the object checks themselves are
/// `validate`'s, UC-2.6).
fn house_is_a_tlp() -> bool {
    opentide_highlight::tide_field_at("rule", "metadata.tlp")
        .is_some_and(|field| field.enum_values.iter().any(|value| value == "house"))
}

#[test]
fn a_default_catalog_stands_in_for_the_bundled_one_under_workspace_catalogs() {
    let bundled = catalog_version().to_string();
    assert!(!house_is_a_tlp());

    let host = Catalog {
        fields: Some(catalog("host", &["clear", "house"])),
        deprecations: Some(
            r#"{"opentide": "host", "fields": [{"schema": "rule", "path": "metadata.tlp", "message": "use labels"}]}"#
                .into(),
        ),
        visibility: None,
    };
    set_default_catalog(&host).expect("default");
    assert_eq!(catalog_version(), "host");
    assert!(house_is_a_tlp());

    // A workspace catalog still wins; resetting it goes back to the default,
    // not to the bundled catalog: what the server's initialize does when a
    // workspace has no catalog.
    let workspace = Catalog {
        fields: Some(catalog("workspace", &["clear"])),
        deprecations: None,
        visibility: None,
    };
    install_catalog(&workspace).expect("workspace");
    assert_eq!(catalog_version(), "workspace");
    assert!(!house_is_a_tlp());
    install_catalog(&Catalog::default()).expect("reset");
    assert_eq!(catalog_version(), "host");

    // A default that does not parse changes nothing; None is the bundled one.
    assert!(
        set_default_catalog(&Catalog {
            fields: Some("{".into()),
            deprecations: None,
            visibility: None,
        })
        .is_err()
    );
    assert_eq!(catalog_version(), "host");
    set_default_catalog(&Catalog::default()).expect("bundled");
    assert_eq!(catalog_version(), bundled);
    assert!(!house_is_a_tlp());
}
