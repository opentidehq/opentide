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

/// The platforms ported on the catch-up train: built in here, with no
/// committed block in the oracle's (0.23.0) recordings. Their blocks are
/// left out of a template compared with those recordings until the oracle
/// moves (O2).
fn ported(recorded: &str) -> Vec<&'static str> {
    opentide_schema::platforms::PLATFORMS
        .iter()
        .map(|platform| platform.id)
        .filter(|id| !recorded.contains(&format!("\n  #{id}:\n")))
        .collect()
}

/// `template` without the commented block of each platform in `platforms`:
/// its `  #<id>:` line and the deeper lines under it.
fn without_blocks(template: &str, platforms: &[&str]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut skipping = false;
    for line in template.split_inclusive('\n') {
        if platforms
            .iter()
            .any(|id| line.trim_end() == format!("  #{id}:"))
        {
            skipping = true;
            continue;
        }
        if skipping && line.starts_with("    ") {
            continue;
        }
        skipping = false;
        out.push_str(line);
    }
    out
}

#[test]
fn without_blocks_drops_a_platform_block_only() {
    let text =
        "configurations:\n  #sysdig:\n    #a: 1\n  #bitdefender:\n    #b: 2\n      #- \nnext:\n";
    assert_eq!(
        without_blocks(text, &["bitdefender"]),
        "configurations:\n  #sysdig:\n    #a: 1\nnext:\n"
    );
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
        let rendered = if identifier.starts_with("rule::") {
            without_blocks(&rendered, &ported(&expected))
        } else {
            rendered
        };
        assert_eq!(rendered, expected, "{identifier}");
    }
    assert_eq!(
        object_template("visibility::1.0", &Options::default()).unwrap(),
        None
    );
}
