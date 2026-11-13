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

/// The platforms the 0.23.0 recordings predate: the `platforms-after-0.23`
/// difference of `tests/oracle/config_cases.toml`, the one list the oracle
/// tests share until the oracle moves to 0.28.0 (O2).
fn platforms_after_the_oracle() -> Vec<String> {
    let cases: toml::Value = toml::from_str(&read(
        &repo().join("crates/opentide-schema/tests/oracle/config_cases.toml"),
    ))
    .unwrap_or_else(|error| panic!("config_cases.toml: {error}"));
    cases["difference"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|difference| difference["id"].as_str() == Some("platforms-after-0.23"))
        .flat_map(|difference| difference["fields"].as_array().cloned().unwrap_or_default())
        .filter_map(|field| field.as_str().map(str::to_owned))
        .collect()
}

/// `template` without the commented block of each of `platforms` under
/// `configurations:` (`  #<platform>:` up to the next block at that indent).
fn without_blocks(template: &str, platforms: &[String]) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in template.split_inclusive('\n') {
        let block = line
            .strip_prefix("  #")
            .and_then(|rest| rest.trim_end().strip_suffix(':'))
            .filter(|key| !key.is_empty() && !key.contains(' '));
        if let Some(key) = block {
            skipping = platforms.iter().any(|platform| platform == key);
        } else if !line.starts_with("    ") && !line.trim().is_empty() {
            skipping = false;
        }
        if !skipping {
            out.push_str(line);
        }
    }
    out
}

#[test]
fn every_object_template_is_the_oracles_on_the_tide_corpus() {
    let later = platforms_after_the_oracle();
    // tide-corpus requires lint's default metadata keys.
    let dir = repo()
        .join("tests/golden/cases/generate/agent/tide-corpus/default/files/ws/.opentide/templates");
    for identifier in ["objective::1.0", "rule::1.0", "rule::1.1", "threat::1.0"] {
        let file = format!("{}.template.yaml", identifier.replace("::", "."));
        let expected = read(&dir.join(&file));
        let rendered = object_template(identifier, &Options::default())
            .unwrap()
            .unwrap();
        assert_eq!(without_blocks(&rendered, &later), expected, "{identifier}");
    }
    assert_eq!(
        object_template("visibility::1.0", &Options::default()).unwrap(),
        None
    );
}
