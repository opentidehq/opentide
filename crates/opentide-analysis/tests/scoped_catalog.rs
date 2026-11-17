//! `enter_catalog` (#1142): a workspace's catalog for one thread's checks,
//! never installed for the process. The TUI checks its workspace with it.

use opentide_analysis::{Catalog, enter_catalog};

fn fields(version: &str, tlp: &[&str]) -> String {
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

/// What this thread reads: whether `house` is a TLP in its field catalog,
/// whether that catalog is a workspace's, and whether `MyTable_CL` is a
/// declared Sentinel table.
fn seen() -> (bool, bool, bool) {
    let house = opentide_highlight::tide_field_at("rule", "metadata.tlp")
        .is_some_and(|field| field.enum_values.iter().any(|value| value == "house"));
    let declared = opentide_analysis::declared_datasets().declares("sentinel");
    (
        house,
        opentide_highlight::tide_catalog_is_workspace(),
        declared,
    )
}

#[test]
fn a_catalog_entered_on_a_thread_is_that_thread_s_alone_until_it_drops() {
    let before = seen();
    assert_eq!(before, (false, false, false));
    let workspace = Catalog {
        fields: Some(fields("workspace", &["clear", "house"])),
        deprecations: None,
        visibility: Some(
            "[[logsources]]\nname = \"MyTable_CL\"\ndescription = \"x\"\nsystem = \"sentinel\"\n"
                .into(),
        ),
    };
    {
        let _catalog = enter_catalog(&workspace).unwrap();
        assert_eq!(seen(), (true, true, true));
        // Another thread, meanwhile, sees the process's catalog.
        assert_eq!(std::thread::spawn(seen).join().unwrap(), before);
    }
    // Nothing is left behind.
    assert_eq!(seen(), before);

    // A part that does not parse is an error and changes nothing.
    let broken = Catalog {
        fields: Some("{".into()),
        ..workspace.clone()
    };
    assert!(enter_catalog(&broken).is_err());
    assert_eq!(seen(), before);
}
