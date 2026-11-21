//! The bundled vocabulary and pin documents are the package's data files.

use opentide_schema::pins;
use opentide_schema::vocab::{SUFFIX, bundled};

// The split the build script stores each vocabulary by (`build.rs`, #1743).
#[path = "../src/vocab/split.rs"]
mod split;

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../src/opentide/data");

#[test]
fn the_bundle_is_the_data_directory() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../src/opentide/data/vocabulary"
    );
    let mut on_disk: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(SUFFIX))
        .collect();
    on_disk.sort();
    let compiled: Vec<String> = bundled::FILES
        .iter()
        .map(|(field, _)| format!("{field}{SUFFIX}"))
        .collect();
    assert_eq!(
        compiled, on_disk,
        "add or remove the file in vocab/bundled.rs"
    );
    // What is compiled in is the file, split: the document without its entries' descriptions, and
    // their descriptions.
    for ((field, lean), (_, descriptions)) in bundled::FILES.iter().zip(bundled::DESCRIPTIONS) {
        let path = format!("{dir}/{field}{SUFFIX}");
        let (want_lean, want_descriptions) = split::split(&std::fs::read_to_string(path).unwrap());
        assert_eq!(lean(), want_lean, "{field}");
        assert_eq!(descriptions(), want_descriptions, "{field}");
    }
}

#[test]
fn the_bundled_pins_are_the_data_directory() {
    let mut on_disk: Vec<String> = std::fs::read_dir(format!("{DATA}/pins"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "toml")
        })
        .collect();
    on_disk.sort();
    let compiled: Vec<&str> = pins::FILES.iter().map(|(name, _)| *name).collect();
    assert_eq!(compiled, on_disk, "add or remove the file in pins.rs");
    for (name, text) in pins::FILES {
        assert_eq!(
            text(),
            std::fs::read_to_string(format!("{DATA}/pins/{name}")).unwrap()
        );
    }
}

/// `stakeholders` is retired upstream (opentidehq/specifications#96), as
/// `responders` was in #512: neither the compiled-in set nor the bundled
/// folder carries it, so no workspace reads its one-organisation text.
#[test]
fn the_stakeholders_vocabulary_is_retired() {
    assert!(
        !bundled::FILES
            .iter()
            .any(|(field, _)| *field == "stakeholders"),
        "stakeholders is still compiled in"
    );
    let file = std::path::Path::new(DATA).join(format!("vocabulary/stakeholders{SUFFIX}"));
    assert!(!file.exists(), "{} is still bundled", file.display());
}
