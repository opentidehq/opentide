//! The editor's vocabularies are the one bundled set (UC-1.6, #812).
//!
//! `src/opentide/data/vocabulary` is what opentide-schema compiles in for
//! `opentide validate` and what the upstream sync writes. The editor read a
//! second copy (`data/catalogs/tide/vocabs`) until #812, and it had drifted:
//! 5 of 35 files differed, `actors` by 538 lines. These tests hold every
//! vocabulary the editor offers to that one directory, so a copy cannot
//! come back unnoticed.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vocabulary_dir() -> PathBuf {
    repo().join("src/opentide/data/vocabulary")
}

/// Every `*.vocab.toml` of the bundled directory, by field (the file name
/// without the suffix).
fn on_disk() -> BTreeSet<String> {
    std::fs::read_dir(vocabulary_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|name| name.strip_suffix(".vocab.toml").map(str::to_owned))
        .collect()
}

#[test]
fn the_editor_reads_every_bundled_vocabulary() {
    let compiled: BTreeSet<String> = opentide_tide::bundled_vocabs()
        .values()
        .map(|vocab| vocab.field.clone())
        .collect();
    // A file's field is its name, but for the two that spell a dot
    // differently (`att&ck.groups` is the field `actors`' companion): every
    // file is compiled in, and every vocabulary comes from a file.
    let files = on_disk();
    assert_eq!(files.len(), 35, "{files:?}");
    assert_eq!(compiled.len(), files.len(), "{compiled:?} vs {files:?}");
    for field in &compiled {
        assert!(files.contains(field), "{field} is in no bundled file");
    }
}

#[test]
fn the_editor_reads_the_bundled_file_itself() {
    let actors = opentide_tide::vocab_for_field("actors").unwrap();
    let text = std::fs::read_to_string(vocabulary_dir().join("actors.vocab.toml")).unwrap();
    let document: toml::Value = toml::from_str(&text).unwrap();
    // `actors` is stage-scoped (`[[stages]]`), so a key is written
    // `<stage>::<id>`: every id of the file is one of the editor's keys.
    let keys = document.get("keys").and_then(|k| k.as_array()).unwrap();
    assert!(keys.len() > 1000, "{}", keys.len());
    for key in keys {
        let id = key.get("id").unwrap().as_str().unwrap();
        assert!(
            actors
                .keys
                .iter()
                .any(|k| k.name.ends_with(&format!("::{id}"))),
            "{id} is in the file, not the editor"
        );
    }
    // The MISP galaxy entries the stale copy did not have (it was the
    // ATT&CK 19.2 refresh; the bundled file is 20.0).
    assert!(
        actors
            .keys
            .iter()
            .any(|k| k.name.ends_with("::01219d2a-9038-4a42-9090-2b4e964afb26")),
        "the editor reads an older vocabulary than `validate`"
    );
}

#[test]
fn there_is_no_second_vocabulary_directory() {
    let stale = repo().join("data/catalogs/tide/vocabs");
    assert!(
        !stale.exists(),
        "{} is back: the editor and `validate` read one set of vocabularies (#812)",
        stale.display()
    );
}
