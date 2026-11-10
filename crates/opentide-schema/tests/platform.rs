//! The platform blocks on the repository's fixtures (UC-1.4, #810), as the
//! oracle's `tests/test_platforms/test_sysdig_model.py`
//! (`test_fixture_blocks_validate`) and `test_elastic_model.py` read them:
//! every block of `tests/fixtures/sysdig` and `tests/fixtures/elastic`
//! validates, and the invalid Elastic fixture reports the codes its header
//! names.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test]: a fixture that cannot be read fails the test"
)]

use std::path::{Path, PathBuf};

use opentide_schema::node;
use opentide_schema::objects::platform::{self, ParseError, PlatformConfig};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn yaml_files(directory: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    files.sort();
    files
}

fn block_of(path: &Path, platform: &str) -> PlatformConfig {
    let text = std::fs::read_to_string(path).unwrap();
    let document = node::load(&text).unwrap();
    let block = document
        .root()
        .and_then(|root| root.get("configurations"))
        .and_then(|configurations| configurations.get(platform))
        .unwrap_or_else(|| panic!("{}: no configurations.{platform}", path.display()));
    platform::parse_platform_config(platform, block)
        .unwrap_or_else(|error| panic!("{}: {error:?}", path.display()))
}

#[test]
fn every_sysdig_fixture_block_validates() {
    let root = repo().join("tests/fixtures/sysdig");
    let mut files = yaml_files(&root);
    files.extend(yaml_files(&root.join("public")));
    assert!(files.len() >= 7, "{files:?}");
    for path in files {
        assert!(matches!(
            block_of(&path, "sysdig"),
            PlatformConfig::Sysdig(_)
        ));
    }
}

#[test]
fn every_elastic_fixture_rule_validates() {
    let files: Vec<PathBuf> = yaml_files(&repo().join("tests/fixtures/elastic"))
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("rule-"))
        })
        .collect();
    assert!(files.len() >= 8, "{files:?}");
    for path in files {
        assert!(matches!(
            block_of(&path, "elastic"),
            PlatformConfig::Elastic(_)
        ));
    }
}

#[test]
fn the_invalid_elastic_fixture_reports_its_codes() {
    let path = repo().join("tests/fixtures/elastic/invalid.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let expected = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("# expect: "))
        .unwrap();
    let document = node::load(&text).unwrap();
    let block = document.root().unwrap().get("elastic").unwrap();
    let Err(ParseError::Invalid(errors)) = platform::parse_platform_config("elastic", block) else {
        panic!("the invalid fixture validated");
    };
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].message,
        format!("Value error, ElasticConfig validation failed with code(s): {expected}")
    );
}
