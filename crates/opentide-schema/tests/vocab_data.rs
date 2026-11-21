//! The bundled vocabulary and pin documents are the package's data files.

use opentide_schema::pins;
use opentide_schema::vocab::{SUFFIX, Vocabulary, bundled};

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

/// The bundled document of `field` as the repository holds it.
fn on_disk(field: &str) -> String {
    let path = format!("{DATA}/vocabulary/{field}{SUFFIX}");
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// Every bundled vocabulary read item by item, its descriptions from the compiled-in lines, is field
/// for field the document read whole (ADR 0013, #1071, #1743).
#[test]
fn bundled_vocabularies_read_item_by_item_are_the_whole_documents() {
    for field in bundled::fields() {
        let file = format!("{field}{SUFFIX}");
        let read = bundled::load(field).unwrap().expect("item by item");
        let whole = Vocabulary::from_file(&file, &on_disk(field)).expect("whole");
        assert_eq!(format!("{read:?}"), format!("{whole:?}"), "{file}");
    }
}

/// The alert severity scale's display name names no product
/// (opentidehq/specifications#96).
#[test]
fn the_alert_severity_vocabulary_is_named_alert_severity() {
    let text = on_disk("alert_severity");
    let vocabulary = Vocabulary::from_file("alert_severity.vocab.toml", &text).expect("it parses");
    assert_eq!(vocabulary.metadata.name, "Alert Severity");
    assert!(!text.contains("MDR"), "{text}");
}
