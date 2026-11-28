//! `visibility.toml` reaches the query checks through `install_catalog`,
//! `install_visibility` and `set_default_catalog`; the workspace's
//! declarations win (#114).

use opentide_analysis::{
    Catalog, Declaration, declared_datasets, install_catalog, install_visibility,
    set_default_catalog,
};

const HOST: &str = r#"[[logsources]]
name = "HostTable"
description = "Test log source."
system = "sentinel"
"#;
const WORKSPACE: &str = r#"[[logsources]]
name = "NTANetAnalytics"
description = "Test log source."
system = "sentinel"
"#;

fn sentinel(name: &str) -> Declaration {
    declared_datasets().status("sentinel", name)
}

// One test: the datasets are process-wide.
#[test]
fn workspace_datasets_win_over_the_hosts_and_a_bad_file_changes_nothing() {
    assert_eq!(sentinel("NTANetAnalytics"), Declaration::Unchecked);

    set_default_catalog(&Catalog {
        visibility: Some(HOST.into()),
        ..Catalog::default()
    })
    .unwrap();
    assert_eq!(sentinel("HostTable"), Declaration::Declared);

    install_catalog(&Catalog {
        visibility: Some(WORKSPACE.into()),
        ..Catalog::default()
    })
    .unwrap();
    assert_eq!(sentinel("NTANetAnalytics"), Declaration::Declared);
    assert_eq!(sentinel("HostTable"), Declaration::Undeclared);

    let err = install_catalog(&Catalog {
        visibility: Some("{ not toml".into()),
        ..Catalog::default()
    })
    .unwrap_err();
    assert!(err.starts_with("visibility.toml:"), "{err}");
    assert_eq!(sentinel("NTANetAnalytics"), Declaration::Declared);

    // An edit applies alone, and keeps the Tide catalogs.
    install_visibility(Some(HOST)).unwrap();
    assert_eq!(sentinel("NTANetAnalytics"), Declaration::Undeclared);
    assert!(install_visibility(Some("[[logsources")).is_err());
    assert_eq!(sentinel("HostTable"), Declaration::Declared);
    install_visibility(Some(WORKSPACE)).unwrap();
    assert_eq!(sentinel("NTANetAnalytics"), Declaration::Declared);
    // A file saved with a byte-order mark parses.
    install_visibility(Some(&format!("\u{feff}{HOST}"))).unwrap();
    assert_eq!(sentinel("HostTable"), Declaration::Declared);
    // The plural lists of opentide 0.20.0 declare nothing.
    install_visibility(Some(
        "[[logsources]]\ndescription = \"x\"\nsystem = \"sentinel\"\ntables = [\"NTANetAnalytics\"]\n",
    ))
    .unwrap();
    assert_eq!(sentinel("NTANetAnalytics"), Declaration::Unchecked);
    install_visibility(Some(WORKSPACE)).unwrap();

    // No workspace datasets: the host's apply again.
    install_catalog(&Catalog::default()).unwrap();
    assert_eq!(sentinel("HostTable"), Declaration::Declared);

    set_default_catalog(&Catalog::default()).unwrap();
    assert_eq!(sentinel("HostTable"), Declaration::Unchecked);
}
