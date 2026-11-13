//! The generated templates against what the oracle writes (UC-1.8, #814):
//! the committed platform templates
//! (`src/opentide/schemas/data/platform_templates`, which the Python suite
//! keeps equal to its render) and the golden recordings of `opentide
//! generate` on the tide-corpus fixture. They read files, so they live here:
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

/// The rule template with each platform block of a platform the recorded
/// oracle lacks (`opentide_schema::platforms::SINCE_ORACLE`) removed. A block
/// is the commented header `  #<id>:` and the lines under it, up to the next
/// `  #<id>:` header at the same two-space indent or the end of the file (the
/// `configurations:` mapping is the template's last key). On a 0.23.0 render
/// no such block is present, so the text is returned unchanged.
fn without_since_oracle_blocks(text: &str) -> String {
    use opentide_schema::platforms::after_oracle;
    let is_platform_header = |line: &str| -> Option<bool> {
        let id = line.strip_prefix("  #")?.strip_suffix(':')?;
        (!id.is_empty() && id.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
            .then(|| after_oracle(id))
    };
    let mut out = String::with_capacity(text.len());
    let mut skipping = false;
    for line in text.split_inclusive('\n') {
        if let Some(drop) = is_platform_header(line.trim_end_matches('\n')) {
            skipping = drop;
        }
        if !skipping {
            out.push_str(line);
        }
    }
    out
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
    let dir = repo()
        .join("tests/golden/cases/generate/agent/tide-corpus/default/files/ws/.opentide/templates");
    for identifier in ["objective::1.0", "rule::1.0", "rule::1.1", "threat::1.0"] {
        let file = format!("{}.template.yaml", identifier.replace("::", "."));
        let expected = read(&dir.join(&file));
        let rendered = object_template(identifier, &Options::default())
            .unwrap()
            .unwrap();
        // The committed template (0.23.0) predates the platforms the train
        // ports onto it; drop their commented blocks from the render before
        // comparing. On this oracle no such block exists, so this is a no-op
        // until a row lands.
        let rendered = without_since_oracle_blocks(&rendered);
        assert_eq!(rendered, expected, "{identifier}");
    }
    assert_eq!(
        object_template("visibility::1.0", &Options::default()).unwrap(),
        None
    );
}
