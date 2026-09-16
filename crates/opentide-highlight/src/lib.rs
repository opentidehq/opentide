//! Frozen HighlightSpec and semantic-token encoding.
//!
//! Capture rename in `highlights/spec.toml` is a **major** (breaking) change.

use opentide_core::{ByteSpan, LanguageId, Range, span_to_range};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const SPEC_TOML: &str = include_str!("../../../highlights/spec.toml");
pub const KQL_HIGHLIGHTS_SCM: &str = include_str!("../../../highlights/queries/kql/highlights.scm");
pub const SPL_HIGHLIGHTS_SCM: &str = include_str!("../../../highlights/queries/spl/highlights.scm");
pub const TIDE_HIGHLIGHTS_SCM: &str =
    include_str!("../../../highlights/queries/tide/highlights.scm");

#[derive(Debug, Error)]
pub enum HighlightError {
    #[error("highlight spec: {0}")]
    Spec(String),
    #[error("unknown capture '{0}' (not in highlights/spec.toml)")]
    UnknownCapture(String),
}

#[derive(Debug, Clone, Deserialize)]
struct SpecFile {
    meta: SpecMeta,
    captures: BTreeMap<String, CaptureMaps>,
}

#[derive(Debug, Clone, Deserialize)]
struct SpecMeta {
    id: String,
    version: String,
    legend: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureMaps {
    pub tm: String,
    pub monaco: String,
    pub helix: String,
}

#[derive(Debug, Clone)]
pub struct HighlightSpec {
    pub id: String,
    pub version: String,
    pub legend: Vec<String>,
    pub captures: BTreeMap<String, CaptureMaps>,
}

impl HighlightSpec {
    pub fn load() -> Result<Self, HighlightError> {
        let file: SpecFile =
            toml::from_str(SPEC_TOML).map_err(|e| HighlightError::Spec(e.to_string()))?;
        if file.meta.legend.is_empty() {
            return Err(HighlightError::Spec("empty legend".into()));
        }
        for name in &file.meta.legend {
            if !file.captures.contains_key(name) {
                return Err(HighlightError::Spec(format!(
                    "legend entry '{name}' has no [captures] maps"
                )));
            }
        }
        Ok(Self {
            id: file.meta.id,
            version: file.meta.version,
            legend: file.meta.legend,
            captures: file.captures,
        })
    }

    pub fn token_index(&self, capture: &str) -> Result<u32, HighlightError> {
        self.legend
            .iter()
            .position(|n| n == capture)
            .map(|i| i as u32)
            .ok_or_else(|| HighlightError::UnknownCapture(capture.to_string()))
    }

    pub fn contains_capture(&self, capture: &str) -> bool {
        self.captures.contains_key(capture)
    }
}

/// Extract `@capture` names from a tree-sitter highlights.scm file.
pub fn scm_captures(scm: &str) -> BTreeSet<String> {
    let re = Regex::new(r"@([A-Za-z][A-Za-z0-9_.]*)").expect("regex");
    re.captures_iter(scm)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

pub fn assert_scm_subset_of_spec(spec: &HighlightSpec, scm: &str) -> Result<(), HighlightError> {
    for capture in scm_captures(scm) {
        if !spec.contains_capture(&capture) {
            return Err(HighlightError::UnknownCapture(capture));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighlightToken {
    pub span: ByteSpan,
    pub range: Range,
    pub capture: String,
    pub token_type: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighlightResult {
    pub language_id: String,
    pub tokens: Vec<HighlightToken>,
    pub legend: Vec<String>,
}

/// LSP semantic tokens (delta-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTokens {
    pub data: Vec<u32>,
    pub legend: Vec<String>,
}

/// Standard LSP / VS Code semantic token types. Capture names such as
/// `operator.pipe` are **not** styled by default themes, so encoding uses
/// this legend instead of `HighlightSpec.legend`.
pub const LSP_TOKEN_TYPES: &[&str] = &[
    "namespace",
    "type",
    "class",
    "enum",
    "interface",
    "struct",
    "typeParameter",
    "parameter",
    "variable",
    "property",
    "enumMember",
    "event",
    "function",
    "method",
    "macro",
    "keyword",
    "modifier",
    "comment",
    "string",
    "number",
    "regexp",
    "operator",
    "decorator",
];

pub fn lsp_token_type_index(capture: &str) -> u32 {
    let name = match capture {
        "comment" => "comment",
        "keyword" | "tide.keyword" => "keyword",
        "operator"
        | "operator.pipe"
        | "punctuation"
        | "punctuation.bracket"
        | "punctuation.delimiter" => "operator",
        "function" | "function.builtin" => "function",
        "type" | "tide.schema" => "type",
        "variable" => "variable",
        "property" | "tide.property" => "property",
        "string" => "string",
        "number" | "tide.uuid" => "number",
        "boolean" | "constant" => "enumMember",
        "error" => "macro",
        _ => "variable",
    };
    LSP_TOKEN_TYPES.iter().position(|n| *n == name).unwrap_or(8) as u32
}

pub fn encode_semantic_tokens(tokens: &[HighlightToken]) -> Vec<u32> {
    encode_semantic_tokens_with(tokens, |t| t.token_type)
}

/// Encode using the standard LSP legend so VS Code / Monaco actually color
/// pipes, builtins, Tide keys, and punctuation.
pub fn encode_lsp_semantic_tokens(tokens: &[HighlightToken]) -> Vec<u32> {
    encode_semantic_tokens_with(tokens, |t| lsp_token_type_index(&t.capture))
}

fn encode_semantic_tokens_with(
    tokens: &[HighlightToken],
    token_type: impl Fn(&HighlightToken) -> u32,
) -> Vec<u32> {
    let mut data = Vec::with_capacity(tokens.len() * 5);
    let mut prev_line = 0u32;
    let mut prev_char = 0u32;
    for token in tokens {
        let line = token.range.start.line;
        let character = token.range.start.character;
        let delta_line = line.saturating_sub(prev_line);
        let delta_char = if delta_line == 0 {
            character.saturating_sub(prev_char)
        } else {
            character
        };
        let length = token
            .range
            .end
            .character
            .saturating_sub(token.range.start.character)
            .max(1);
        data.extend_from_slice(&[delta_line, delta_char, length, token_type(token), 0]);
        prev_line = line;
        prev_char = character;
    }
    data
}

/// High-contrast HTML for `opentide-lsp highlight --html` and tests.
pub fn tokens_to_html(source: &str, tokens: &[HighlightToken]) -> String {
    let mut html = String::from(
        r#"<!doctype html><meta charset=utf-8>
<title>OpenTide highlight</title>
<style>
body{font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#1e1e1e;color:#d4d4d4;padding:24px;margin:0}
pre{margin:0;white-space:pre-wrap}
.keyword{color:#c586c0;font-weight:700}
.function,.function-builtin{color:#dcdcaa;font-weight:600}
.string{color:#ce9178}
.number{color:#b5cea8}
.comment{color:#6a9955;font-style:italic}
.type{color:#4ec9b0;font-weight:700}
.property{color:#9cdcfe}
.operator{color:#d7ba7d;font-weight:600}
.operator-pipe{color:#ff79c6;font-weight:800}
.error{color:#f44747;text-decoration:underline}
.boolean,.constant{color:#569cd6;font-weight:600}
.punctuation,.punctuation-bracket,.punctuation-delimiter{color:#c8c8c8}
.tide-keyword{color:#c586c0;font-weight:700}
.tide-property{color:#9cdcfe}
.tide-uuid{color:#b5cea8}
.tide-schema{color:#4ec9b0}
.variable{color:#9cdcfe}
</style><pre>"#,
    );
    let mut last = 0usize;
    let mut ordered = tokens.to_vec();
    ordered.sort_by_key(|t| (t.span.start, t.span.end));
    for t in &ordered {
        if t.span.start < last {
            continue;
        }
        let start = t.span.start.min(source.len());
        let end = t.span.end.min(source.len());
        html.push_str(&html_escape(&source[last..start]));
        let class = t.capture.replace('.', "-");
        html.push_str(&format!("<span class=\"{class}\">"));
        html.push_str(&html_escape(&source[start..end]));
        html.push_str("</span>");
        last = end;
    }
    html.push_str(&html_escape(&source[last..]));
    html.push_str("</pre>");
    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn tokens_from_spans(
    spec: &HighlightSpec,
    source: &str,
    spans: &[(ByteSpan, &str)],
) -> Result<Vec<HighlightToken>, HighlightError> {
    let mut out = Vec::with_capacity(spans.len());
    for (span, capture) in spans {
        let token_type = spec.token_index(capture)?;
        out.push(HighlightToken {
            span: *span,
            range: span_to_range(source, *span),
            capture: (*capture).to_string(),
            token_type,
        });
    }
    out.sort_by_key(|t| (t.span.start, t.token_type));
    Ok(out)
}

/// Generate TextMate / Monaco / Helix maps from the frozen spec.
pub fn generate_tm_language(language: LanguageId, spec: &HighlightSpec) -> serde_json::Value {
    let scm = match language {
        LanguageId::Kql => KQL_HIGHLIGHTS_SCM,
        LanguageId::Spl => SPL_HIGHLIGHTS_SCM,
        LanguageId::TideYaml => TIDE_HIGHLIGHTS_SCM,
    };
    let mut patterns: Vec<serde_json::Value> = Vec::new();
    let comment_tm = spec
        .captures
        .get("comment")
        .map(|m| m.tm.as_str())
        .unwrap_or("comment");
    let string_tm = spec
        .captures
        .get("string")
        .map(|m| m.tm.as_str())
        .unwrap_or("string");
    let number_tm = spec
        .captures
        .get("number")
        .map(|m| m.tm.as_str())
        .unwrap_or("constant.numeric");
    let comment_match = if language == LanguageId::TideYaml {
        "(?m)^\\s*#.*$"
    } else {
        "//.*$|```[^`]*```"
    };
    patterns.push(serde_json::json!({
        "name": comment_tm,
        "match": comment_match,
        "comment": "capture:comment",
    }));
    patterns.push(serde_json::json!({
        "name": string_tm,
        "match": "\"(\\\\.|[^\"\\\\])*\"|'(\\\\.|[^'\\\\])*'",
        "comment": "capture:string",
    }));
    patterns.push(serde_json::json!({
        "name": number_tm,
        "match": "\\b[0-9]+(\\.[0-9]+)?\\b",
        "comment": "capture:number",
    }));
    if language == LanguageId::TideYaml {
        if let Some(maps) = spec.captures.get("tide.keyword") {
            patterns.push(serde_json::json!({
                "name": maps.tm,
                "match": "(?m)^\\s*(name|metadata|description|status|severity|techniques|detection_model|response|configurations|objective|threat|composition|criticality|references|procedure)\\s*:",
                "comment": "capture:tide.keyword",
            }));
        }
        if let Some(maps) = spec.captures.get("tide.property") {
            patterns.push(serde_json::json!({
                "name": maps.tm,
                "match": "(?m)^\\s*(uuid|schema|version|created|modified|tlp|author|organisation|query|search|enabled)\\s*:",
                "comment": "capture:tide.property",
            }));
        }
        if let Some(maps) = spec.captures.get("tide.uuid") {
            patterns.push(serde_json::json!({
                "name": maps.tm,
                "match": "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                "comment": "capture:tide.uuid",
            }));
        }
        if let Some(maps) = spec.captures.get("tide.schema") {
            patterns.push(serde_json::json!({
                "name": maps.tm,
                "match": "\\b[A-Za-z][A-Za-z0-9_]*::[0-9.]+",
                "comment": "capture:tide.schema",
            }));
        }
        if let Some(maps) = spec.captures.get("boolean") {
            patterns.push(serde_json::json!({
                "name": maps.tm,
                "match": "(?<![A-Za-z0-9_])(?:true|false)(?![A-Za-z0-9_])",
                "comment": "capture:boolean",
            }));
        }
    }
    let mut by_capture: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let re = Regex::new(r#""([^"\\]+)"\s+@([A-Za-z0-9_.]+)"#).expect("regex");
    for cap in re.captures_iter(scm) {
        by_capture
            .entry(cap[2].to_string())
            .or_default()
            .insert(cap[1].to_string());
    }
    for (capture, tokens) in &by_capture {
        let Some(maps) = spec.captures.get(capture) else {
            continue;
        };
        let mut words = Vec::new();
        let mut punct = Vec::new();
        for token in tokens {
            if token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                words.push(regex::escape(token));
            } else {
                punct.push(regex::escape(token));
            }
        }
        if !words.is_empty() {
            patterns.push(serde_json::json!({
                "name": maps.tm,
                "match": format!("(?i)(?<![A-Za-z0-9_])(?:{})(?![A-Za-z0-9_])", words.join("|")),
                "comment": format!("capture:{capture}"),
            }));
        }
        for p in punct {
            patterns.push(serde_json::json!({
                "name": maps.tm,
                "match": p,
                "comment": format!("capture:{capture}"),
            }));
        }
    }
    serde_json::json!({
        "scopeName": format!("source.{}", language.as_str()),
        "name": format!("OpenTide {}", language),
        "patterns": patterns,
        "opentideHighlightSpec": spec.version,
    })
}

pub fn generate_monaco(spec: &HighlightSpec) -> serde_json::Value {
    let token_map: BTreeMap<&String, &String> =
        spec.captures.iter().map(|(k, v)| (k, &v.monaco)).collect();
    serde_json::json!({
        "tokenLegend": spec.legend,
        "tokenMap": token_map,
    })
}

pub fn generate_helix(spec: &HighlightSpec) -> String {
    let mut out = String::from("# Generated from highlights/spec.toml — do not edit.\n");
    for (name, maps) in &spec.captures {
        out.push_str(&format!("\"{name}\" = \"{}\"\n", maps.helix));
    }
    out
}

pub fn generated_artifacts_stale(
    spec: &HighlightSpec,
    tm: &str,
    monaco: &str,
    helix: &str,
) -> Result<(), String> {
    generated_artifacts_stale_for(spec, LanguageId::Kql, tm, monaco, helix)
}

pub fn generated_artifacts_stale_for(
    spec: &HighlightSpec,
    language: LanguageId,
    tm: &str,
    monaco: &str,
    helix: &str,
) -> Result<(), String> {
    let expected_tm = serde_json::to_string_pretty(&generate_tm_language(language, spec))
        .map_err(|e| e.to_string())?;
    let expected_monaco =
        serde_json::to_string_pretty(&generate_monaco(spec)).map_err(|e| e.to_string())?;
    let expected_helix = generate_helix(spec);
    if tm.trim() != expected_tm.trim() {
        return Err(format!(
            "generated {language} tmLanguage is stale; run opentide-lsp generate-highlights"
        ));
    }
    if monaco.trim() != expected_monaco.trim() {
        return Err("generated monaco map is stale; run opentide-lsp generate-highlights".into());
    }
    if helix.trim() != expected_helix.trim() {
        return Err("generated helix map is stale; run opentide-lsp generate-highlights".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_loads_and_legend_matches_captures() {
        let spec = HighlightSpec::load().expect("spec");
        assert!(spec.legend.contains(&"keyword".to_string()));
        assert!(spec.contains_capture("tide.keyword"));
        assert!(spec.token_index("keyword").is_ok());
    }

    #[test]
    fn scm_captures_are_subset_of_spec() {
        let spec = HighlightSpec::load().unwrap();
        assert_scm_subset_of_spec(&spec, KQL_HIGHLIGHTS_SCM).unwrap();
        assert_scm_subset_of_spec(&spec, SPL_HIGHLIGHTS_SCM).unwrap();
        assert_scm_subset_of_spec(&spec, TIDE_HIGHLIGHTS_SCM).unwrap();
    }

    #[test]
    fn unknown_scm_capture_fails() {
        let spec = HighlightSpec::load().unwrap();
        let err = assert_scm_subset_of_spec(&spec, "(identifier) @not_a_real_capture").unwrap_err();
        match err {
            HighlightError::UnknownCapture(name) => assert_eq!(name, "not_a_real_capture"),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn semantic_token_encoding_is_delta() {
        let spec = HighlightSpec::load().unwrap();
        let src = "where x";
        let tokens = tokens_from_spans(
            &spec,
            src,
            &[
                (ByteSpan::new(0, 5), "keyword"),
                (ByteSpan::new(6, 7), "variable"),
            ],
        )
        .unwrap();
        let data = encode_semantic_tokens(&tokens);
        assert_eq!(data.len(), 10);
        assert_eq!(data[0], 0);
        assert_eq!(data[5], 0); // same line
    }

    #[test]
    fn lsp_legend_maps_dotted_captures_to_standard_types() {
        assert_eq!(
            LSP_TOKEN_TYPES[lsp_token_type_index("keyword") as usize],
            "keyword"
        );
        assert_eq!(
            LSP_TOKEN_TYPES[lsp_token_type_index("operator.pipe") as usize],
            "operator"
        );
        assert_eq!(
            LSP_TOKEN_TYPES[lsp_token_type_index("function.builtin") as usize],
            "function"
        );
        assert_eq!(
            LSP_TOKEN_TYPES[lsp_token_type_index("tide.keyword") as usize],
            "keyword"
        );
    }

    #[test]
    fn html_stylesheet_colors_keywords_and_pipes() {
        let spec = HighlightSpec::load().unwrap();
        let src = "SecurityEvent | where x == 1";
        let tokens = tokens_from_spans(
            &spec,
            src,
            &[
                (ByteSpan::new(0, 13), "type"),
                (ByteSpan::new(14, 15), "operator.pipe"),
                (ByteSpan::new(16, 21), "keyword"),
            ],
        )
        .unwrap();
        let html = tokens_to_html(src, &tokens);
        assert!(html.contains("class=\"keyword\""));
        assert!(html.contains("class=\"operator-pipe\""));
        assert!(html.contains("#c586c0"));
        assert!(html.contains("#ff79c6"));
    }
}

#[cfg(test)]
mod tm_language_stub_bug {
    #[test]
    fn generated_kql_tm_language_has_executable_match_rules() {
        let tm = include_str!("../../../highlights/generated/kql.tmLanguage.json");
        let v: serde_json::Value = serde_json::from_str(tm).expect("json");
        let patterns = v["patterns"].as_array().expect("patterns");
        let has_match = patterns
            .iter()
            .any(|p| p.get("match").is_some() || p.get("begin").is_some());
        assert!(
            has_match,
            "kql.tmLanguage.json patterns are name-only stubs with no match/begin — TextMate-only editors render uncolored source"
        );
    }

    #[test]
    fn generated_tide_tm_language_does_not_over_escape_whitespace() {
        let spec = crate::HighlightSpec::load().unwrap();
        let tm = crate::generate_tm_language(opentide_core::LanguageId::TideYaml, &spec);
        let patterns = tm["patterns"].as_array().unwrap();
        let key = patterns
            .iter()
            .find(|p| p["comment"] == "capture:tide.keyword")
            .unwrap();
        let m = key["match"].as_str().unwrap();
        assert!(
            m.contains(r"^\s*"),
            "expected real whitespace class, got {m}"
        );
        assert!(
            !m.contains(r"\\s"),
            "over-escaped whitespace in Tide TextMate match: {m}"
        );
        assert!(
            patterns.iter().any(|p| p["comment"] == "capture:tide.uuid"
                && p["match"].as_str().unwrap().contains("8}-")),
            "{tm}"
        );
        assert_eq!(tm["patterns"][0]["match"], "(?m)^\\s*#.*$");
    }
}
