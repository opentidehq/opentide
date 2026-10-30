//! `visibility.toml` reaches the query checks through `install_catalog`,
//! `install_visibility` and `set_default_catalog`; the workspace's
//! declarations win (#114).

use opentide_analysis::{
    Catalog, DatasetKind, Declaration, declared_datasets, install_catalog, install_visibility,
    set_default_catalog,
};

const HOST: &str = r#"[[logsources]]
name = "sentinel datasets"
description = "Test log source."
system = "sentinel"
tables = ["HostTable"]
"#;
const WORKSPACE: &str = r#"[[logsources]]
name = "sentinel datasets"
description = "Test log source."
system = "sentinel"
tables = ["NTANetAnalytics"]
"#;

fn sentinel(name: &str) -> Declaration {
    declared_datasets().status("sentinel", DatasetKind::Tables, name)
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

    // No workspace datasets: the host's apply again.
    install_catalog(&Catalog::default()).unwrap();
    assert_eq!(sentinel("HostTable"), Declaration::Declared);

    set_default_catalog(&Catalog::default()).unwrap();
    assert_eq!(sentinel("HostTable"), Declaration::Unchecked);
}
