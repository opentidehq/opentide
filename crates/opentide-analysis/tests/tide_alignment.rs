//! The server's semantic token types for the rows of
//! `highlights/test/fixtures/tide-alignment.json` (#1809): the fixture is what
//! the Tide grammar's test (`highlights/test/tide_alignment.test.mjs`) holds
//! the grammar's scopes to, so it must be what the server sends. A key's colon
//! and a list dash get no token.

use opentide_analysis::highlight;
use opentide_core::LanguageId;
use opentide_highlight::{LSP_TOKEN_TYPES, lsp_capture_has_semantic_token, lsp_token_type_index};
use serde_json::Value;

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../highlights/test/fixtures"
);

#[test]
fn the_alignment_fixture_is_what_the_server_sends() {
    let json: Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{DIR}/tide-alignment.json")).expect("json"),
    )
    .expect("json");
    let yaml = std::fs::read_to_string(format!("{DIR}/{}", json["yaml"].as_str().expect("yaml")))
        .expect("yaml");
    let lines: Vec<&str> = yaml.split('\n').collect();
    let result = highlight(LanguageId::TideYaml, &yaml);
    // The tokens over the first `text` of the first line holding `row`.
    let inside = |row: &str, text: &str| -> Vec<&opentide_highlight::HighlightToken> {
        let line = lines.iter().position(|l| l.contains(row)).expect(row);
        let start = lines[line]
            .find(text)
            .unwrap_or_else(|| panic!("{row:?} has no {text:?}"));
        let start = lines[line][..start].chars().count();
        let end = start + text.chars().count();
        result
            .tokens
            .iter()
            .filter(|t| {
                t.range.start.line as usize == line
                    && (t.range.start.character as usize) < end
                    && (t.range.end.character as usize) > start
            })
            .collect()
    };
    for item in json["tokens"].as_array().expect("tokens") {
        let (row, text, ty) = (
            item["row"].as_str().expect("row"),
            item["text"].as_str().expect("text"),
            item["type"].as_str().expect("type"),
        );
        let tokens = inside(row, text);
        assert!(!tokens.is_empty(), "no token in {text:?} on {row:?}");
        for token in tokens {
            assert_eq!(
                LSP_TOKEN_TYPES[lsp_token_type_index(&token.capture) as usize],
                ty,
                "{text:?} on {row:?} is the capture {}",
                token.capture
            );
        }
    }
    for item in json["punctuation"].as_array().expect("punctuation") {
        let (row, text) = (
            item["row"].as_str().expect("row"),
            item["text"].as_str().expect("text"),
        );
        let tokens = inside(row, text);
        assert!(!tokens.is_empty(), "no token {text:?} on {row:?}");
        for token in tokens {
            assert!(
                !lsp_capture_has_semantic_token(&token.capture),
                "{text:?} on {row:?} would be sent as {}",
                token.capture
            );
        }
    }
}
