//! A host that supplies the catalogs keeps them: `initialize` leaves the
//! workspace's alone. The flag is process-wide, so this test has a binary of
//! its own.

use opentide_analysis::{Catalog, catalog_version, set_default_catalog};
use opentide_lsp::{WORKSPACE_CATALOGS, server::install_workspace_catalog, use_host_catalogs};

const FIELDS: &str = r#"{"opentide": "VERSION", "fields": [
  {"schema": "rule", "path": "name", "name": "name", "type": "string"}
]}"#;

#[test]
fn a_host_that_supplies_the_catalogs_keeps_them() {
    let root = std::env::temp_dir().join(format!("opentide-host-catalogs-{}", std::process::id()));
    let dir = root.join(WORKSPACE_CATALOGS);
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(
        dir.join("fields.json"),
        FIELDS.replace("VERSION", "committed"),
    )
    .expect("write");

    // Without the flag, initialize installs the workspace's catalog.
    install_workspace_catalog(&root);
    assert_eq!(catalog_version(), "committed");

    set_default_catalog(&Catalog {
        fields: Some(FIELDS.replace("VERSION", "host")),
        deprecations: None,
        visibility: None,
    })
    .expect("default");
    install_workspace_catalog(std::path::Path::new(""));
    assert_eq!(catalog_version(), "host");

    use_host_catalogs();
    install_workspace_catalog(&root);
    assert_eq!(catalog_version(), "host");
    let _ = std::fs::remove_dir_all(&root);
}
