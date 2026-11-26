//! The catalogue `build.rs` stores pre-parsed (#1743) is the TOML file, row for row (ADR 0013:
//! what the engine reads is what `toml` reads from the whole file).

use opentide_datadog::catalog::{Attribute, Catalog};

#[derive(serde::Deserialize)]
struct File {
    reserved: Vec<Attribute>,
    attributes: Vec<Attribute>,
}

#[test]
fn the_stored_catalogs_are_the_whole_files() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../data/catalogs/datadog/attributes.toml"
    ))
    .expect("the catalogue");
    let file: File = toml::from_str(&text).expect("TOML");
    let catalog = Catalog::cached();
    assert_eq!(catalog.reserved, file.reserved);
    assert_eq!(catalog.attributes, file.attributes);
}
