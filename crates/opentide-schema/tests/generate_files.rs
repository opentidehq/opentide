//! The generated templates against what the oracle writes (UC-1.8, #814):
//! the committed platform templates
//! (`src/opentide/schemas/data/platform_templates`, which the Python suite
//! keeps equal to its render) and the object templates the oracle's
//! `opentide generate` wrote on the tide-corpus fixture, kept in
//! `tests/templates/tide-corpus/` since the recordings were retired (#1142).
//! They read files, so they live here:
//! the crate's `src` stays I/O-free (`scripts/engine/check-io-free.sh`).

use std::path::{Path, PathBuf};

use opentide_schema::generate::template::Options;
use opentide_schema::generate::workspace::{object_template, platform_template};
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

#[test]
fn every_object_template_is_the_oracles_on_the_tide_corpus() {
    // tide-corpus requires lint's default metadata keys.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/templates/tide-corpus");
    for identifier in ["objective::1.0", "rule::1.0", "rule::1.1", "threat::1.0"] {
        let file = format!("{}.template.yaml", identifier.replace("::", "."));
        let expected = read(&dir.join(&file));
        let rendered = object_template(identifier, &Options::default())
            .unwrap()
            .unwrap();
        assert_eq!(rendered, expected, "{identifier}");
    }
    assert_eq!(
        object_template("visibility::1.0", &Options::default()).unwrap(),
        None
    );
}
