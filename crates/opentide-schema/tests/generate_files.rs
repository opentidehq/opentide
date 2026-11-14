//! The generated platform templates against the committed ones
//! (`src/opentide/schemas/data/platform_templates`, which the Python suite
//! keeps equal to its render). They read files, so they live here: the
//! crate's `src` stays I/O-free (`scripts/engine/check-io-free.sh`). What
//! `opentide generate` writes is the CLI's snapshots'.

use std::path::{Path, PathBuf};

use opentide_schema::generate::workspace::platform_template;
use opentide_schema::objects::platform::PLATFORM_CONFIG_MODELS;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn every_platform_template_is_the_committed_one() {
    let dir = repo().join("src/opentide/schemas/data/platform_templates");
    for registered in PLATFORM_CONFIG_MODELS {
        let expected = read(&dir.join(format!("{}.template.yaml", registered.key)));
        let rendered = platform_template(registered.key).unwrap().unwrap();
        assert_eq!(rendered, expected, "{}", registered.key);
    }
    assert_eq!(platform_template("plugin").unwrap(), None);
}
