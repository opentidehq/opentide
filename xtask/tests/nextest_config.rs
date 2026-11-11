//! `.config/nextest.toml` names only test binaries that exist.
//!
//! nextest refuses a filter whose `binary_id(<crate>::<name>)` matches no
//! binary ("operator didn't match any binary IDs") and fails before running a
//! single test, under every profile. A deleted integration test whose name
//! stays in a filter therefore turns every nextest job red. This test reads
//! each profile's `default-filter` and checks every literal binary id against
//! the workspace's members and their `tests/` targets.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use toml::{Table, Value};

type TestResult = Result<(), Box<dyn Error>>;

fn repository() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
}

fn read_table(path: &Path) -> Result<Table, Box<dyn Error>> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(text.parse::<Table>()?)
}

/// Each workspace member's package name and directory.
fn packages(root: &Path) -> Result<BTreeMap<String, PathBuf>, Box<dyn Error>> {
    let manifest = read_table(&root.join("Cargo.toml"))?;
    let members = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(Value::as_array)
        .ok_or("the root Cargo.toml has no [workspace] members")?;
    let mut packages = BTreeMap::new();
    for member in members.iter().filter_map(Value::as_str) {
        let dir = root.join(member);
        let manifest = read_table(&dir.join("Cargo.toml"))?;
        let name = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{member}/Cargo.toml has no package name"))?;
        packages.insert(name.to_string(), dir);
    }
    Ok(packages)
}

/// Whether `package` (in `dir`) has an integration test binary `name`: a
/// `tests/<name>.rs`, a `tests/<name>/main.rs`, or a `[[test]]` of that name.
fn has_test_binary(dir: &Path, name: &str) -> Result<bool, Box<dyn Error>> {
    if dir.join("tests").join(format!("{name}.rs")).is_file()
        || dir.join("tests").join(name).join("main.rs").is_file()
    {
        return Ok(true);
    }
    let manifest = read_table(&dir.join("Cargo.toml"))?;
    Ok(manifest
        .get("test")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|target| target.get("name").and_then(Value::as_str) == Some(name)))
}

/// The literal `<crate>::<binary>` ids a filter expression names. Regular
/// expressions (`binary_id(/…/)`) and globs are skipped: nextest accepts one
/// that matches nothing only by the same rule, but they name no single file.
fn literal_binary_ids(filter: &str) -> Vec<(String, String)> {
    filter
        .split("binary_id(")
        .skip(1)
        .filter_map(|rest| rest.split_once(')').map(|(id, _)| id.trim()))
        .filter(|id| !id.starts_with('/') && !id.contains(['*', '?', '[']))
        .filter_map(|id| {
            let id = id.trim_start_matches('=');
            id.split_once("::")
                .map(|(package, binary)| (package.to_string(), binary.to_string()))
        })
        .collect()
}

#[test]
fn literal_binary_ids_reads_each_literal_id_and_skips_patterns() {
    let filter = "not (binary_id(a-b::one) | binary_id(/::external_/) | binary_id(c::two*) \
                  | binary_id(=d::three))";
    assert_eq!(
        literal_binary_ids(filter),
        vec![
            ("a-b".to_string(), "one".to_string()),
            ("d".to_string(), "three".to_string()),
        ]
    );
}

#[test]
fn every_binary_id_in_a_nextest_filter_names_an_existing_test_binary() -> TestResult {
    let root = repository();
    let config = read_table(&root.join(".config/nextest.toml"))?;
    let packages = packages(&root)?;
    let profiles = config
        .get("profile")
        .and_then(Value::as_table)
        .ok_or(".config/nextest.toml has no [profile] tables")?;

    let mut checked = 0;
    let mut missing = Vec::new();
    for (profile, settings) in profiles {
        let Some(filter) = settings.get("default-filter").and_then(Value::as_str) else {
            continue;
        };
        for (package, binary) in literal_binary_ids(filter) {
            checked += 1;
            let found = match packages.get(&package) {
                Some(dir) => has_test_binary(dir, &binary)?,
                None => false,
            };
            if !found {
                missing.push(format!(
                    "[profile.{profile}] binary_id({package}::{binary})"
                ));
            }
        }
    }
    assert!(checked > 0, "no literal binary_id in any default-filter");
    assert!(
        missing.is_empty(),
        "nextest refuses a filter that matches no binary; remove or rename:\n{}",
        missing.join("\n")
    );
    Ok(())
}
