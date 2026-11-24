//! The Tide grammar's scopes are generated from the semantic-token mapping
//! (#1809): each construct's TextMate scope is under the scopes its token
//! type maps to in the `opentide-yaml` language contribution (copied to
//! `highlights/test/fixtures/semantic-token-scopes.json`), so a theme
//! colours it as it colours the server's token for the same text.

#![expect(
    clippy::expect_used,
    reason = "helpers of a test file: a panic is how a test fails"
)]

use opentide_core::LanguageId;
use opentide_highlight::{
    HighlightSpec, KEY_VALUE_SCOPE, LIST_DASH_SCOPE, LSP_TOKEN_TYPES, LSP_TYPE_SCOPES,
    block_text_scope, capture_base_scope, construct_captures, construct_scope,
    generate_tm_language, lsp_capture_has_semantic_token, lsp_token_type_index, plain_value_scope,
};
use serde_json::Value;
use std::collections::BTreeMap;

/// The extension's table: LSP token type → the scopes it maps to, in order.
fn type_scopes() -> BTreeMap<String, Vec<String>> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../highlights/test/fixtures/semantic-token-scopes.json"
    ))
    .expect("the fixture");
    let json: Value = serde_json::from_str(&text).expect("json");
    json["scopes"]
        .as_object()
        .expect("scopes")
        .iter()
        .map(|(ty, list)| {
            let scopes = list
                .as_array()
                .expect("list")
                .iter()
                .map(|s| s.as_str().expect("scope").to_string())
                .collect();
            (ty.clone(), scopes)
        })
        .collect()
}

/// A theme resolves `scope` like one of `mapped`.
fn under(scope: &str, mapped: &[String]) -> bool {
    mapped
        .iter()
        .any(|m| scope == m || scope.starts_with(&format!("{m}.")))
}

fn lsp_type(capture: &str) -> &'static str {
    LSP_TOKEN_TYPES[lsp_token_type_index(capture) as usize]
}

#[test]
fn every_lsp_type_has_a_base_scope_the_table_maps_it_to() {
    let table = type_scopes();
    for ty in LSP_TOKEN_TYPES {
        let (_, base) = LSP_TYPE_SCOPES
            .iter()
            .find(|(name, _)| name == ty)
            .unwrap_or_else(|| panic!("no base scope for {ty}"));
        let mapped = table
            .get(*ty)
            .unwrap_or_else(|| panic!("no table row for {ty}"));
        assert!(under(base, mapped), "{ty}: {base} is not under {mapped:?}");
    }
}

#[test]
fn a_construct_scope_is_under_the_scopes_of_its_semantic_token_type() {
    let table = type_scopes();
    for capture in construct_captures() {
        let scope = construct_scope(capture).expect("a scope");
        let ty = lsp_type(capture);
        assert!(
            under(&scope, &table[ty]),
            "{capture} ({ty}): {scope} is not under {:?}",
            table[ty]
        );
    }
    for (scope, ty) in [
        (plain_value_scope(), "string"),
        (block_text_scope(), "string"),
    ] {
        assert!(under(&scope, &table[ty]), "{scope}");
    }
}

#[test]
fn the_specs_tide_and_markdown_scopes_are_the_constructs() {
    let spec = HighlightSpec::load().expect("spec");
    for capture in
        construct_captures().filter(|c| c.starts_with("tide.") || c.starts_with("markdown."))
    {
        assert_eq!(
            spec.captures[capture].tm,
            construct_scope(capture).expect("a scope"),
            "highlights/spec.toml [captures.\"{capture}\"].tm"
        );
    }
}

#[test]
fn a_key_colon_and_a_list_dash_have_no_token_and_a_punctuation_scope() {
    for capture in ["punctuation", "punctuation.delimiter", "markdown.list"] {
        assert!(!lsp_capture_has_semantic_token(capture), "{capture}");
        assert_eq!(capture_base_scope(capture), None);
    }
    assert!(KEY_VALUE_SCOPE.starts_with("punctuation.separator.key-value"));
    assert!(LIST_DASH_SCOPE.starts_with("punctuation.definition.list.begin"));
}

/// Every scope the grammar gives a Tide construct is under the scopes of some
/// token type, or is punctuation, an embedded region or a YAML quote.
#[test]
fn every_scope_of_the_generated_grammar_is_a_construct_or_punctuation() {
    let table = type_scopes();
    let spec = HighlightSpec::load().expect("spec");
    let grammar = generate_tm_language(LanguageId::TideYaml, &spec);
    let mut scopes = Vec::new();
    collect(&grammar["patterns"], &mut scopes);
    assert!(scopes.len() > 40, "{}", scopes.len());
    for scope in scopes {
        let free = scope.split(' ').any(|s| {
            s.starts_with("punctuation.")
                || s.starts_with("meta.embedded.")
                || s.starts_with("string.quoted.yaml")
        });
        let known = table.values().any(|mapped| under(&scope, mapped));
        assert!(free || known, "{scope}");
    }
}

fn collect(rule: &Value, out: &mut Vec<String>) {
    match rule {
        Value::Array(rules) => rules.iter().for_each(|r| collect(r, out)),
        Value::Object(map) => {
            for key in ["name", "contentName"] {
                if let Some(scope) = map.get(key).and_then(Value::as_str) {
                    out.push(scope.to_string());
                }
            }
            for key in ["captures", "beginCaptures", "endCaptures"] {
                if let Some(captures) = map.get(key).and_then(Value::as_object) {
                    captures.values().for_each(|c| collect(c, out));
                }
            }
            if let Some(patterns) = map.get("patterns") {
                collect(patterns, out);
            }
        }
        _ => {}
    }
}
