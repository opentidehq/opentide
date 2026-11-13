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

/// The platforms added after the oracle (0.23.0), whose blocks its rule
/// templates do not have (`platforms-since-the-oracle` in
/// `oracle/config_cases.toml`).
const SINCE_THE_ORACLE: &[&str] = &["graylog"];

/// `text` without the commented-out `configurations.<platform>` block of
/// each of `platforms`: its header line at indent 2, and every line after it
/// indented deeper or blank, up to the next line at indent 2 or less.
fn without_blocks(text: &str, platforms: &[&str]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut skipping = false;
    for line in text.split_inclusive('\n') {
        let header = platforms
            .iter()
            .any(|platform| line == format!("  #{platform}:\n"));
        if header {
            skipping = true;
            continue;
        }
        let deeper = line.starts_with("   ") || line.trim().is_empty();
        if skipping && deeper {
            continue;
        }
        skipping = false;
        out.push_str(line);
    }
    out
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
        assert_eq!(
            without_blocks(&rendered, SINCE_THE_ORACLE),
            expected,
            "{identifier}"
        );
        // The blocks left out are the platforms' own templates, indented.
        for platform in SINCE_THE_ORACLE {
            assert!(
                identifier != "rule::1.0" || rendered.contains(&format!("\n  #{platform}:\n")),
                "{identifier}: no {platform} block"
            );
        }
    }
    assert_eq!(
        object_template("visibility::1.0", &Options::default()).unwrap(),
        None
    );
}
