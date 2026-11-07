//! The tree-sitter grammar (highlighting) against libsinsp's parser tests:
//! inputs libsinsp accepts should highlight without an error node. The few
//! that do not are libsinsp lexing quirks a tokenizer cannot express; they
//! are listed so a regression is visible.

use opentide_core::LanguageId;
use serde_json::Value;
use std::path::PathBuf;

#[test]
fn tree_sitter_accepts_what_libsinsp_accepts() {
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
        let tree = opentide_syntax::parse(LanguageId::Falco, input).unwrap();
        if tree.root_node().has_error() {
            errors.push(input.to_string());
        }
    }
    assert!(accepted >= 370, "{accepted}");
    // libsinsp matches `exists` as a prefix and reads `and` right after it;
    // tree-sitter lexes `existsand` as one word. The engine's verdict comes from
    // the libsinsp port, which accepts it; only highlighting differs.
    assert_eq!(
        errors,
        ["test.op existsand macro"],
        "tree-sitter errors on libsinsp-accepted inputs"
    );
}
