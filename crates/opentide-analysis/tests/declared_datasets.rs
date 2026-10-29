//! `datasets.json` reaches the query checks through `install_catalog` and
//! `set_default_catalog`; the workspace's declarations win (#114).

use opentide_analysis::{
    Catalog, DatasetKind, Declaration, declared_datasets, install_catalog, set_default_catalog,
};

const HOST: &str = r#"{"platforms": {"sentinel": {"tables": ["HostTable"]}}}"#;
const WORKSPACE: &str =
    r#"{"opentide": "0.20.0", "platforms": {"sentinel": {"tables": ["NTANetAnalytics"]}}}"#;

fn sentinel(name: &str) -> Declaration {
    declared_datasets().status("sentinel", DatasetKind::Tables, name)
}

// One test: the datasets are process-wide.
#[test]
fn workspace_datasets_win_over_the_hosts_and_a_bad_file_changes_nothing() {
    assert_eq!(sentinel("NTANetAnalytics"), Declaration::Unchecked);

    set_default_catalog(&Catalog {
        datasets: Some(HOST.into()),
        ..Catalog::default()
    })
    .unwrap();
    assert_eq!(sentinel("HostTable"), Declaration::Declared);

    install_catalog(&Catalog {
        datasets: Some(WORKSPACE.into()),
        ..Catalog::default()
    })
    .unwrap();
    assert_eq!(sentinel("NTANetAnalytics"), Declaration::Declared);
    assert_eq!(sentinel("HostTable"), Declaration::Undeclared);

    let err = install_catalog(&Catalog {
        datasets: Some("{ not json".into()),
        ..Catalog::default()
    })
    .unwrap_err();
    assert!(err.starts_with("datasets.json:"), "{err}");
    assert_eq!(sentinel("NTANetAnalytics"), Declaration::Declared);

    // No workspace datasets: the host's apply again.
    install_catalog(&Catalog::default()).unwrap();
    assert_eq!(sentinel("HostTable"), Declaration::Declared);

    set_default_catalog(&Catalog::default()).unwrap();
    assert_eq!(sentinel("HostTable"), Declaration::Unchecked);
}
