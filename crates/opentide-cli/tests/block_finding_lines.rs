//! A finding on a platform block is reported by `validate` and `lint` at the
//! same place: the block's key (#922). `lint` placed it on the line below,
//! where the block's value starts, with no column.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn run(dir: &Path, command: &str) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_opentide-cli"))
        .args(["--json", command])
        .current_dir(dir)
        .env_clear()
        .env("OPENTIDE_OUTPUT", "plain")
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Every finding of `document` (at any depth) on `field_path`: its code and
/// where it points.
fn at(document: &Value, field_path: &[&str]) -> Vec<(String, Vec<Value>)> {
    let mut out = Vec::new();
    let mut stack = vec![document];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(map) => {
                let path: Option<Vec<&str>> = map
                    .get("field_path")
                    .and_then(Value::as_array)
                    .map(|p| p.iter().filter_map(Value::as_str).collect());
                if path.as_deref() == Some(field_path) {
                    let place = ["yaml_line", "line", "column", "end_line", "end_column"]
                        .iter()
                        .map(|key| map.get(*key).cloned().unwrap_or(Value::Null))
                        .collect();
                    let code = map["code"].as_str().unwrap_or_default().to_owned();
                    out.push((code, place));
                }
                stack.extend(map.values());
            }
            Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn validate_and_lint_place_a_block_finding_at_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("objects/rules");
    std::fs::create_dir_all(&rules).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/bitdefender/rule-bitdefender-yara-1.0.yaml");
    std::fs::copy(fixture, rules.join("rule-bitdefender-yara-1.0.yaml")).unwrap();
    let block = ["configurations", "bitdefender"];
    let validate = at(&run(dir.path(), "validate"), &block);
    let lint = at(&run(dir.path(), "lint"), &block);
    let code = "bitdefender_severity_collapsed";
    let place = |found: &[(String, Vec<Value>)]| {
        found
            .iter()
            .find(|(c, _)| c == code)
            .map(|(_, place)| place.clone())
            .unwrap_or_else(|| panic!("no {code} in {found:?}"))
    };
    // `bitdefender:` is line 18, at column 3, of the fixture; its value
    // starts on line 19 (`yaml_line` 18, counted from 0).
    let expected: Vec<Value> = [18, 18, 3, 18, 14].map(Value::from).to_vec();
    assert_eq!(place(&validate), expected, "validate");
    assert_eq!(place(&lint), expected, "lint");
}
