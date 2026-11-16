//! The tree (highlighting, fields, hover) against libsinsp's parser tests:
//! inputs libsinsp accepts parse without an error. The one that does not is a
//! libsinsp lexing quirk the tree keeps from tree-sitter's grammar; it is listed
//! so a regression is visible.

use serde_json::Value;
use std::path::PathBuf;

#[test]
fn the_tree_accepts_what_libsinsp_accepts() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/conformance/libsinsp/parser.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut errors = Vec::new();
    let mut accepted = 0;
    for fx in doc["fixtures"].as_array().unwrap() {
        if fx["verdict"] != "accept" {
            continue;
        }
        accepted += 1;
        let input = fx["input"].as_str().unwrap();
        if opentide_falco::tree_has_error(input) {
            errors.push(input.to_string());
        }
    }
    assert!(accepted >= 370, "{accepted}");
    assert_eq!(
        errors,
        [] as [String; 0],
        "tree errors on libsinsp-accepted inputs"
    );
}
