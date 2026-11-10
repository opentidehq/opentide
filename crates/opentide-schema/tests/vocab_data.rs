//! The bundled vocabulary and pin documents are the package's data files.

use opentide_schema::pins;
use opentide_schema::vocab::{SUFFIX, bundled};

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
    for (field, text) in bundled::FILES {
        let path = format!("{dir}/{field}{SUFFIX}");
        assert_eq!(*text, std::fs::read_to_string(path).unwrap());
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
            text,
            std::fs::read_to_string(format!("{DATA}/pins/{name}")).unwrap()
        );
    }
}
