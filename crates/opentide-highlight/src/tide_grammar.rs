//! The Tide YAML grammar's scopes, generated from the language server's
//! semantic-token mapping (`lsp_token_type_index`), so that a rule does not
//! change colour when the server's tokens arrive.
//!
//! A theme colours a semantic token by the TextMate scopes its *type* maps to
//! (`semanticTokenScopes`; the standard defaults, and the editor's own for
//! `opentide-yaml`). The grammar's last scope for a construct must be one
//! of those scopes or below one, whatever the theme, so every scope here is
//! built as `<scope of the token type of the construct's capture>.<suffix>`:
//! [`construct_scope`]. The key colon and the list dash get no semantic token
//! (the server sends none, `lsp_capture_has_semantic_token`), so their
//! scopes are YAML punctuation: [`KEY_VALUE_SCOPE`] and [`LIST_DASH_SCOPE`].
//!
//! What a grammar cannot know stays with the server: the language of an
//! Elastic query (its `type`/`language` is a sibling key), and an enumerated
//! field whose key name is not an enumeration everywhere in the catalog.

use crate::{HighlightSpec, LSP_TOKEN_TYPES, lsp_token_type_index, tide_catalog};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// The TextMate scope each LSP token type resolves to in a default theme
/// (VS Code's `semanticTokenScopes` defaults, which the opentide-yaml
/// language contribution refines with `.tide` scopes under them): the base a
/// construct's scope extends.
pub const LSP_TYPE_SCOPES: &[(&str, &str)] = &[
    ("namespace", "entity.name.namespace"),
    ("type", "entity.name.type"),
    ("class", "entity.name.type.class"),
    ("enum", "entity.name.type.enum"),
    ("interface", "entity.name.type.interface"),
    ("struct", "entity.name.type.struct"),
    ("typeParameter", "entity.name.type.parameter"),
    ("parameter", "variable.parameter"),
    ("variable", "variable.other.readwrite"),
    ("property", "variable.other.property"),
    ("enumMember", "variable.other.enummember"),
    ("event", "variable.other.event"),
    ("function", "entity.name.function"),
    ("method", "entity.name.function.member"),
    ("macro", "entity.name.function.preprocessor"),
    ("keyword", "keyword.control"),
    ("modifier", "storage.modifier"),
    ("comment", "comment"),
    ("string", "string"),
    ("number", "constant.numeric"),
    ("regexp", "variable.other.constant"),
    ("operator", "keyword.operator"),
    ("decorator", "entity.name.decorator"),
];

/// The colon after a key: no semantic token, so a YAML punctuation scope.
pub const KEY_VALUE_SCOPE: &str = "punctuation.separator.key-value.tide";
/// A list dash: no semantic token either.
pub const LIST_DASH_SCOPE: &str = "punctuation.definition.list.begin.tide";

/// The base scope of the semantic token type of `capture`; `None` for a
/// capture the server sends no token for.
pub fn capture_base_scope(capture: &str) -> Option<&'static str> {
    if !crate::lsp_capture_has_semantic_token(capture) {
        return None;
    }
    let lsp_type = LSP_TOKEN_TYPES.get(lsp_token_type_index(capture) as usize)?;
    LSP_TYPE_SCOPES
        .iter()
        .find(|(name, _)| name == lsp_type)
        .map(|(_, scope)| *scope)
}

/// What a Tide construct adds under its type's base scope.
const SUFFIXES: &[(&str, &str)] = &[
    ("tide.property", "tide"),
    ("tide.keyword", "tide"),
    ("tide.schema", "schema.tide"),
    ("tide.uuid", "uuid.tide"),
    ("boolean", "tide"),
    ("constant", "tide"),
    ("markdown.heading", "markdown.tide"),
    ("markdown.emphasis", "emphasis.markdown.tide"),
    ("markdown.strong", "strong.markdown.tide"),
    ("markdown.code", "markdown.tide"),
    ("markdown.link", "link.markdown.tide"),
    ("markdown.quote", "quote.markdown.tide"),
];

/// The captures [`construct_scope`] names: the `tm` of each in
/// `highlights/spec.toml` is the same string (checked by a test).
pub fn construct_captures() -> impl Iterator<Item = &'static str> {
    SUFFIXES.iter().map(|(capture, _)| *capture)
}

/// The grammar scope of a Tide construct of `capture`: the base scope of the
/// capture's semantic token type, then the construct's suffix.
pub fn construct_scope(capture: &str) -> Option<String> {
    let suffix = SUFFIXES.iter().find(|(c, _)| *c == capture)?.1;
    Some(format!("{}.{suffix}", capture_base_scope(capture)?))
}

/// A plain (unquoted) YAML value, which the server colours as a string.
pub fn plain_value_scope() -> String {
    format!(
        "{}.unquoted.plain.tide",
        capture_base_scope("string").unwrap_or("string")
    )
}

/// The text of a block scalar that is no query and no Markdown.
pub fn block_text_scope() -> String {
    format!(
        "{}.unquoted.block.tide",
        capture_base_scope("string").unwrap_or("string")
    )
}

const KEY: &str = r"[A-Za-z0-9_][A-Za-z0-9_.-]*";
/// The end of a value: blanks, then a comment or the end of the line.
const END: &str = r"[ \t]*(?:#.*)?$";
const UUID: &str = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
const SCHEMA: &str = "[A-Za-z][A-Za-z0-9_]*::[0-9.]+";
const TECHNIQUE: &str = "T[0-9]{4}(?:\\.[0-9]{3})?";
const PLAIN_VALUE: &str = r"(\S.*?)(?=[ \t]+#|[ \t]*$)";

/// A plain value starts here: not a quote, a block or flow marker, an
/// anchor, a tag, a comment, nor one of the kinds the server colours
/// otherwise (booleans, numbers, UUIDs, schemas, techniques).
fn not_plain() -> String {
    format!(
        "(?![\"'|>&*!%@`#])(?!(?:true|false){END})(?!-?[0-9]+(?:\\.[0-9]+)?{END})(?!{UUID}{END})(?!{SCHEMA}{END})(?!{TECHNIQUE}{END})"
    )
}

fn name(scope: &str) -> Value {
    json!({ "name": scope })
}

/// `key: value` rules share a head: an optional list dash, the key, the colon.
/// Groups: 2 dash, 4 key, 6 colon; a rule adds its value as group 7 and 8.
fn head(keys: &str) -> String {
    format!(r"^(\s*)(?:(-)(\s+))?({keys})(\s*)(:)")
}

fn head_captures(key_scope: &str) -> serde_json::Map<String, Value> {
    let mut captures = serde_json::Map::new();
    captures.insert("2".into(), name(LIST_DASH_SCOPE));
    captures.insert("4".into(), name(key_scope));
    captures.insert("6".into(), name(KEY_VALUE_SCOPE));
    captures
}

/// The keys every row of the catalog gives `capture`, so that a key name
/// that is a keyword on one path and a property on another is a property.
fn keys_all_rows_have(capture: &str) -> Vec<String> {
    let mut by_name: BTreeMap<&str, bool> = BTreeMap::new();
    for field in &tide_catalog().fields {
        let all = by_name.entry(field.name.as_str()).or_insert(true);
        *all &= field.capture == capture;
    }
    by_name
        .into_iter()
        .filter(|(_, all)| *all)
        .map(|(name, _)| name.to_string())
        .collect()
}

fn alternation(items: &[String]) -> String {
    let mut sorted: Vec<&String> = items.iter().collect();
    sorted.sort_by_key(|item| std::cmp::Reverse(item.len()));
    sorted
        .iter()
        .map(|item| regex::escape(item))
        .collect::<Vec<_>>()
        .join("|")
}

/// The key names whose value is an enumeration on every path that has the
/// key (the catalogue's `enum`), with every value they allow (and their
/// default and constant): the grammar colours a value of the set as the
/// server does, an enumeration member.
fn enumerated_keys() -> BTreeMap<String, BTreeSet<String>> {
    let mut rows: BTreeMap<&str, Vec<&crate::TideField>> = BTreeMap::new();
    for field in &tide_catalog().fields {
        rows.entry(field.name.as_str()).or_default().push(field);
    }
    let mut keys = BTreeMap::new();
    for (key, fields) in rows {
        if !fields.iter().all(|f| !f.enum_values.is_empty()) {
            continue;
        }
        let mut values = BTreeSet::new();
        for field in fields {
            values.extend(field.enum_values.iter().cloned());
            values.extend(field.default_value.iter().cloned());
            values.extend(field.const_value.iter().cloned());
        }
        keys.insert(key.to_string(), values);
    }
    keys
}

/// The keys a query is written under: the embedded regions' keys, `query`
/// (an Elastic query is left to the server) and a Falco `output`.
fn query_keys() -> BTreeSet<&'static str> {
    crate::EMBEDDED_QUERIES
        .iter()
        .flat_map(|(_, keys, _)| keys.iter().copied())
        .chain(["query", "output"])
        .collect()
}

/// The keys whose block scalar is Markdown text: a catalogue field with
/// the `markdown` flag, less the keys an embedded query block is written
/// under (those are the query language's).
fn markdown_keys() -> Vec<String> {
    let queries = query_keys();
    let mut keys = BTreeSet::new();
    for field in &tide_catalog().fields {
        if field.markdown && !queries.contains(field.name.as_str()) {
            keys.insert(field.name.clone());
        }
    }
    keys.into_iter().collect()
}

/// The patterns of Markdown text in a block scalar: what the server's
/// Markdown highlighter marks.
fn markdown_patterns(spec: &HighlightSpec) -> Vec<Value> {
    let scope = |capture: &str| {
        construct_scope(capture).unwrap_or_else(|| {
            spec.captures
                .get(capture)
                .map_or_else(|| capture.to_string(), |m| m.tm.clone())
        })
    };
    let list = spec
        .captures
        .get("markdown.list")
        .map_or("punctuation.definition.list.markdown.tide", |m| {
            m.tm.as_str()
        });
    vec![
        json!({ "name": scope("markdown.heading"), "match": r"^\s*#{1,6}\s+.*$", "comment": "capture:markdown.heading" }),
        json!({ "name": scope("markdown.quote"), "match": r"^\s*>\s?.*$", "comment": "capture:markdown.quote" }),
        json!({ "name": list, "match": r"^\s*(?:[-*+]|\d+\.)\s+", "comment": "capture:markdown.list" }),
        json!({ "name": scope("markdown.code"), "match": r"`[^`]+`", "comment": "capture:markdown.code" }),
        json!({ "name": scope("markdown.strong"), "match": r"\*\*[^*]+\*\*|__[^_]+__", "comment": "capture:markdown.strong" }),
        json!({ "name": scope("markdown.emphasis"), "match": r"(?<![\w*])\*[^*\s][^*]*\*(?![\w*])|(?<![\w_])_[^_\s][^_]*_(?![\w_])", "comment": "capture:markdown.emphasis" }),
        json!({ "name": scope("markdown.link"), "match": r"\[[^\]]+\]\([^)]+\)|<https?://[^>\s]+>", "comment": "capture:markdown.link" }),
    ]
}

/// `key: |` and `key: >`: the text below is not YAML. Markdown text, a
/// query (left to its language) or any other text.
fn block_scalar_rules(spec: &HighlightSpec, property: &str, block_text: &str) -> Vec<Value> {
    let markdown = markdown_keys();
    let mut rules = Vec::new();
    let block = |keys: &str, dash: bool| {
        let (begin, end) = if dash {
            (
                format!(r"^(\s*)(-)(\s)({keys})(\s*)(:)(\s*)[|>][-+0-9]*\s*(?:#.*)?$"),
                r"^(?!\1\s\s\s+\S|\s*$)",
            )
        } else {
            (
                format!(r"^(\s*)({keys})(\s*)(:)(\s*)[|>][-+0-9]*\s*(?:#.*)?$"),
                r"^(?!\1\s+\S|\s*$)",
            )
        };
        let (key_group, colon_group) = if dash { ("4", "6") } else { ("2", "4") };
        let mut captures = serde_json::Map::new();
        if dash {
            captures.insert("2".into(), name(LIST_DASH_SCOPE));
        }
        captures.insert(key_group.into(), name(property));
        captures.insert(colon_group.into(), name(KEY_VALUE_SCOPE));
        (begin, end, captures)
    };
    for dash in [false, true] {
        let suffix = if dash { ":item" } else { "" };
        if !markdown.is_empty() {
            let (begin, end, captures) = block(&alternation(&markdown), dash);
            rules.push(json!({
                "comment": format!("tide:block-scalar:markdown{suffix}"),
                "begin": begin,
                "beginCaptures": captures,
                "contentName": block_text,
                "end": end,
                "patterns": markdown_patterns(spec),
            }));
        }
        let queries: Vec<String> = query_keys().into_iter().map(str::to_string).collect();
        let (begin, end, captures) = block(&alternation(&queries), dash);
        rules.push(json!({
            "comment": format!("tide:block-scalar:query{suffix}"),
            "begin": begin,
            "beginCaptures": captures,
            "end": end,
            "patterns": [],
        }));
        let (begin, end, captures) = block(KEY, dash);
        rules.push(json!({
            "comment": format!("tide:block-scalar{suffix}"),
            "begin": begin,
            "beginCaptures": captures,
            "contentName": block_text,
            "end": end,
            "patterns": [],
        }));
    }

    rules
}

/// The structure rules of the Tide grammar, in order: block scalars, then
/// enumerated values, keys with their values, and list items.
pub(crate) fn structure_rules(spec: &HighlightSpec) -> Vec<Value> {
    let property = construct_scope("tide.property").unwrap_or_default();
    let keyword = construct_scope("tide.keyword").unwrap_or_default();
    let enum_member = construct_scope("boolean").unwrap_or_default();
    let plain = plain_value_scope();
    let block_text = block_text_scope();
    let keyword_keys = keys_all_rows_have("tide.keyword");
    let mut rules = Vec::new();

    rules.extend(block_scalar_rules(spec, &property, &block_text));

    // The value of an enumerated key: `tlp: amber`.
    for (key, values) in enumerated_keys() {
        let values: Vec<String> = values.into_iter().collect();
        let key_scope = if keyword_keys.contains(&key) {
            &keyword
        } else {
            &property
        };
        let mut captures = head_captures(key_scope);
        captures.insert("8".into(), name(&enum_member));
        rules.push(json!({
            "comment": format!("tide:enum:{key}"),
            "match": format!("{}([ \\t]+)({})(?={END})", head(&regex::escape(&key)), alternation(&values)),
            "captures": captures,
        }));
    }
    // A technique id is an enumeration member wherever it stands.
    let mut captures = head_captures(&property);
    captures.insert("8".into(), name(&enum_member));
    rules.push(json!({
        "comment": "tide:technique",
        "match": format!("{}([ \\t]+)({TECHNIQUE})(?={END})", head(KEY)),
        "captures": captures,
    }));
    rules.push(json!({
        "comment": "tide:technique:item",
        "match": format!(r"^(\s*)(-)(\s+)({TECHNIQUE})(?={END})"),
        "captures": { "2": name(LIST_DASH_SCOPE), "4": name(&enum_member) },
    }));

    // Keys that are keywords, then every other key, each with a plain value.
    let value = format!("(?:([ \\t]+){}{PLAIN_VALUE})?", not_plain());
    let value_captures = |captures: &mut serde_json::Map<String, Value>| {
        captures.insert("8".into(), name(&plain));
    };
    if !keyword_keys.is_empty() {
        let mut captures = head_captures(&keyword);
        value_captures(&mut captures);
        rules.push(json!({
            "comment": "capture:tide.keyword",
            "match": format!("{}(?=\\s|$){value}", head(&alternation(&keyword_keys))),
            "captures": captures,
        }));
    }
    let mut captures = head_captures(&property);
    value_captures(&mut captures);
    rules.push(json!({
        "comment": "capture:tide.property",
        "match": format!("{}(?=\\s|$){value}", head(KEY)),
        "captures": captures,
    }));
    // A list item that is a plain value: `- text`.
    rules.push(json!({
        "comment": "tide:sequence-item",
        "match": format!(r"^(\s*)(-)(\s+)(?!{KEY}[ \t]*:(?:\s|$)){}{PLAIN_VALUE}", not_plain()),
        "captures": { "2": name(LIST_DASH_SCOPE), "4": name(&plain) },
    }));
    rules
}
