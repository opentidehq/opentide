//! Shared I/O-free types for the opentide language server.
//!
//! Names use `opentide`, never `otide`.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Language identifier advertised to editors and WASM hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LanguageId {
    #[serde(rename = "kql", alias = "opentide-kql")]
    Kql,
    #[serde(rename = "spl", alias = "opentide-spl")]
    Spl,
    #[serde(rename = "opentide-yaml", alias = "yaml", alias = "tide")]
    TideYaml,
    /// Elasticsearch ES|QL (Elastic Security `esql` rules).
    #[serde(rename = "esql", alias = "opentide-esql")]
    Esql,
    /// Elasticsearch Event Query Language (Elastic Security `eql` rules).
    #[serde(rename = "eql", alias = "opentide-eql")]
    Eql,
    /// Kibana Query Language. Kibana's API calls it `kuery`; `KQL` stays Kusto.
    #[serde(rename = "kuery", alias = "opentide-kuery")]
    Kuery,
    /// Lucene query string syntax (Elastic `language: lucene`).
    #[serde(rename = "lucene", alias = "opentide-lucene")]
    Lucene,
}

impl LanguageId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kql => "kql",
            Self::Spl => "spl",
            Self::TideYaml => "opentide-yaml",
            Self::Esql => "esql",
            Self::Eql => "eql",
            Self::Kuery => "kuery",
            Self::Lucene => "lucene",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "kql" | "opentide-kql" | "KQL" | "kusto" => Some(Self::Kql),
            "spl" | "opentide-spl" | "SPL" => Some(Self::Spl),
            "opentide-yaml" | "yaml" | "tide" | "tide-yaml" => Some(Self::TideYaml),
            "esql" | "opentide-esql" | "ES|QL" | "es|ql" | "ESQL" => Some(Self::Esql),
            "eql" | "opentide-eql" | "EQL" => Some(Self::Eql),
            "kuery" | "opentide-kuery" | "kibana-kql" => Some(Self::Kuery),
            "lucene" | "opentide-lucene" | "Lucene" => Some(Self::Lucene),
            _ => None,
        }
    }

    /// Language of a raw query file, from its extension. Anything else is
    /// Tide YAML or unknown, which the caller decides.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension {
            "kql" => Some(Self::Kql),
            "spl" => Some(Self::Spl),
            "esql" => Some(Self::Esql),
            "eql" => Some(Self::Eql),
            "kuery" => Some(Self::Kuery),
            "lucene" => Some(Self::Lucene),
            _ => None,
        }
    }

    /// Query languages with a tree-sitter grammar and an engine.
    pub const QUERY_LANGUAGES: [Self; 6] = [
        Self::Kql,
        Self::Spl,
        Self::Esql,
        Self::Eql,
        Self::Kuery,
        Self::Lucene,
    ];
}

impl fmt::Display for LanguageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Zero-based UTF-16-friendly line/character position (LSP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

impl Position {
    pub fn new(line: u32, character: u32) -> Self {
        Self { line, character }
    }
}

/// Half-open range in a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub fn new(start: Position, end: Position) -> Self {
        Self { start, end }
    }

    pub fn point(line: u32, character: u32) -> Self {
        let p = Position::new(line, character);
        Self { start: p, end: p }
    }

    pub fn contains(&self, position: Position) -> bool {
        (position.line > self.start.line
            || (position.line == self.start.line && position.character >= self.start.character))
            && (position.line < self.end.line
                || (position.line == self.end.line && position.character <= self.end.character))
    }
}

/// Byte span in the original source (UTF-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

/// Convert a UTF-8 byte offset to an LSP position.
pub fn offset_to_position(source: &str, offset: usize) -> Position {
    let offset = offset.min(source.len());
    let mut line = 0u32;
    let mut last_line_start = 0usize;
    for (idx, ch) in source.char_indices() {
        if idx >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            last_line_start = idx + 1;
        }
    }
    let slice = &source[last_line_start..offset];
    Position {
        line,
        character: utf16_len(slice),
    }
}

/// Convert an LSP position (UTF-16 columns) to a UTF-8 byte offset, the
/// inverse of [`offset_to_position`]. A column past the end of its line
/// clamps to the line end; a line past the end of the text gives its length.
pub fn position_to_offset(source: &str, position: Position) -> usize {
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in source.char_indices() {
        if line == position.line && (col >= position.character || ch == '\n') {
            return idx;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += ch.len_utf16() as u32;
        }
    }
    source.len()
}

pub fn span_to_range(source: &str, span: ByteSpan) -> Range {
    Range {
        start: offset_to_position(source, span.start),
        end: offset_to_position(source, span.end),
    }
}

/// Line starts of a text, for many offset-to-position conversions: each is a
/// binary search instead of [`offset_to_position`]'s scan from the start, so
/// converting every token of a large query stays linear.
pub struct LineIndex<'a> {
    source: &'a str,
    starts: Vec<usize>,
    /// Lines that are pure ASCII, where a column is a byte distance.
    ascii: Vec<bool>,
}

impl<'a> LineIndex<'a> {
    pub fn new(source: &'a str) -> Self {
        let mut starts = vec![0];
        starts.extend(source.match_indices('\n').map(|(i, _)| i + 1));
        let ascii = (0..starts.len())
            .map(|line| {
                let end = starts.get(line + 1).copied().unwrap_or(source.len());
                source[starts[line]..end].is_ascii()
            })
            .collect();
        Self {
            source,
            starts,
            ascii,
        }
    }

    /// Same result as [`offset_to_position`].
    pub fn position(&self, offset: usize) -> Position {
        let offset = offset.min(self.source.len());
        let line = self.starts.partition_point(|&start| start <= offset) - 1;
        let start = self.starts[line];
        let character = if self.ascii[line] {
            (offset - start) as u32
        } else {
            utf16_len(&self.source[start..offset])
        };
        Position {
            line: line as u32,
            character,
        }
    }

    /// Same result as [`span_to_range`].
    pub fn range(&self, span: ByteSpan) -> Range {
        Range {
            start: self.position(span.start),
            end: self.position(span.end),
        }
    }
}

fn utf16_len(s: &str) -> u32 {
    s.chars()
        .map(|c| if c.len_utf16() == 2 { 2 } else { 1 })
        .sum()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Information,
    Hint,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Information => "information",
            Self::Hint => "hint",
        }
    }
}

/// Machine-stable diagnostic. CLI Pydantic issues map onto `{code, field_path, severity}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    pub range: Range,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_path: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionItem {
    pub label: String,
    pub detail: Option<String>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
}

impl CompletionItem {
    pub fn new(label: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: None,
            kind: kind.into(),
            documentation: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_docs(mut self, documentation: impl Into<String>) -> Self {
        self.documentation = Some(documentation.into());
        self
    }
}

/// LSP `textDocument/signatureHelp` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHelp {
    pub signatures: Vec<SignatureInformation>,
    pub active_signature: u32,
    pub active_parameter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureInformation {
    pub label: String,
    pub documentation: Option<String>,
    pub parameters: Vec<ParameterInformation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterInformation {
    pub label: String,
    pub documentation: Option<String>,
}

impl Diagnostic {
    pub fn error(code: impl Into<String>, message: impl Into<String>, range: Range) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Error,
            message: message.into(),
            range,
            field_path: None,
            suggestion: None,
            object_uuid: None,
            object_type: None,
        }
    }

    pub fn warning(code: impl Into<String>, message: impl Into<String>, range: Range) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Warning,
            message: message.into(),
            range,
            field_path: None,
            suggestion: None,
            object_uuid: None,
            object_type: None,
        }
    }

    pub fn with_field_path(mut self, path: Vec<String>) -> Self {
        self.field_path = Some(path);
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}

/// Well-known diagnostic codes. Extra query diagnostics are allowed.
pub mod codes {
    pub const SCHEMA_VALIDATION: &str = "schema_validation";
    pub const VOCAB_UNKNOWN: &str = "vocab_unknown";
    pub const INVALID_UUID: &str = "invalid_uuid";
    pub const DUPLICATE_ID: &str = "duplicate_id";
    pub const INVALID_REF: &str = "invalid_ref";
    pub const CHAINING_RELATION_UNKNOWN: &str = "chaining_relation_unknown";
    pub const DEPRECATED_FIELD: &str = "deprecated_field";
    pub const KQL_CONTROL_COMMAND_UNSUPPORTED: &str = "kql_control_command_unsupported";
    pub const KQL_UNKNOWN_OPERATOR: &str = "kql_unknown_operator";
    pub const KQL_UNKNOWN_FUNCTION: &str = "kql_unknown_function";
    pub const KQL_DEPRECATED_FUNCTION: &str = "kql_deprecated_function";
    pub const KQL_UNKNOWN_TABLE: &str = "kql_unknown_table";
    pub const KQL_RENDER_NOT_VALID: &str = "kql_render_not_valid";
    pub const KQL_PARSE_ERROR: &str = "kql_parse_error";
    pub const KQL_WHERE_NOT_FIRST: &str = "kql_where_not_first";
    pub const KQL_UNSCOPED_SEARCH: &str = "kql_unscoped_search";
    pub const KQL_UNSCOPED_UNION: &str = "kql_unscoped_union";
    pub const KQL_WILDCARD_TABLE: &str = "kql_wildcard_table";
    pub const KQL_JOIN_SUMMARIZE_BEFORE_PROJECT: &str = "kql_join_summarize_before_project";
    pub const SPL_UNKNOWN_COMMAND: &str = "spl_unknown_command";
    pub const SPL_PARSE_ERROR: &str = "spl_parse_error";
    pub const SPL_WILDCARD: &str = "spl_wildcard";
    pub const SPL_LEADING_NOT: &str = "spl_leading_not";
    pub const SPL_SUBSEARCH_TRUNCATION: &str = "spl_subsearch_truncation";
    pub const ESQL_PARSE_ERROR: &str = "esql_parse_error";
    pub const ESQL_UNKNOWN_COMMAND: &str = "esql_unknown_command";
    pub const ESQL_UNKNOWN_FUNCTION: &str = "esql_unknown_function";
    pub const ESQL_UNAVAILABLE: &str = "esql_unavailable";
    pub const ESQL_METADATA_ID: &str = "esql_metadata_id";
    pub const EQL_PARSE_ERROR: &str = "eql_parse_error";
    pub const EQL_UNKNOWN_FUNCTION: &str = "eql_unknown_function";
    pub const EQL_UNSUPPORTED: &str = "eql_unsupported";
    pub const EQL_MAXSPAN_UNIT: &str = "eql_maxspan_unit";
    pub const EQL_MAXSPAN_WINDOW: &str = "eql_maxspan_window";
    pub const EQL_MAXSPAN_LOOKBACK: &str = "eql_maxspan_lookback";
    pub const EQL_FUNCTION_ARITY: &str = "eql_function_arity";
    pub const EQL_CASE_SENSITIVE: &str = "eql_case_sensitive";
    pub const EQL_LITERAL_WILDCARD: &str = "eql_literal_wildcard";
    pub const EQL_NESTED_COMMENT: &str = "eql_nested_comment";
    pub const EQL_EXPRESSION_DEPTH: &str = "eql_expression_depth";
    pub const EQL_ARGUMENT_TYPE: &str = "eql_argument_type";
    pub const EQL_FIELD_COMPARISON: &str = "eql_field_comparison";
    pub const EQL_RUNS_IGNORED: &str = "eql_runs_ignored";
    pub const EQL_UNTIL_TERM: &str = "eql_until_term";
    pub const EQL_REGEX: &str = "eql_regex";
    pub const EQL_MAXSPAN_MISSING: &str = "eql_maxspan_missing";
    pub const KUERY_PARSE_ERROR: &str = "kuery_parse_error";
    pub const KUERY_LUCENE_SYNTAX: &str = "kuery_lucene_syntax";
    pub const KUERY_ESCAPE: &str = "kuery_escape";
    pub const KUERY_QUOTED_WILDCARD: &str = "kuery_quoted_wildcard";
    pub const LUCENE_PARSE_ERROR: &str = "lucene_parse_error";
    pub const LUCENE_LOWERCASE_OPERATOR: &str = "lucene_lowercase_operator";
    pub const LUCENE_MIXED_OPERATORS: &str = "lucene_mixed_operators";
    pub const LUCENE_ESCAPE: &str = "lucene_escape";
    pub const LUCENE_KUERY_SYNTAX: &str = "lucene_kuery_syntax";
    pub const LUCENE_REGEXP: &str = "lucene_regexp";
    pub const LUCENE_FUZZY: &str = "lucene_fuzzy";
    pub const LUCENE_RANGE_OPERATOR: &str = "lucene_range_operator";
    pub const LUCENE_UNESCAPED_SLASH: &str = "lucene_unescaped_slash";
    pub const LUCENE_BARE_TERM: &str = "lucene_bare_term";
    pub const LUCENE_LOOKS_LIKE_KUERY: &str = "lucene_looks_like_kuery";
    pub const LUCENE_ELASTICSEARCH_ONLY: &str = "lucene_elasticsearch_only";
    pub const KUERY_QUESTION_MARK: &str = "kuery_question_mark";
    pub const KUERY_FREE_TEXT: &str = "kuery_free_text";
    pub const KUERY_LOOKS_LIKE_LUCENE: &str = "kuery_looks_like_lucene";
    pub const KUERY_RANGE_TYPE: &str = "kuery_range_type";
    // elastic-1.0 Advisories on the block itself (specifications#57).
    pub const LOOKBACK_ZERO: &str = "lookback_zero";
    pub const LOOKBACK_LONG: &str = "lookback_long";
    pub const THRESHOLD_LOOKBACK: &str = "threshold_lookback";
    pub const RISK_BAND: &str = "risk_band";
    pub const TECHNIQUE_NOT_ENTERPRISE: &str = "technique_not_enterprise";
    pub const CROWDSTRIKE_UNSUPPORTED: &str = "crowdstrike_unsupported";
    pub const FILENAME_SLUG: &str = "filename_slug";
    pub const MISSING_AUTHOR: &str = "missing_author";
    pub const MISSING_ORGANISATION: &str = "missing_organisation";
    pub const DEFENDER_OUTPUT_COLUMNS: &str = "defender_output_columns";
    /// `::type` names no Elasticsearch release can cast to.
    pub const ESQL_UNKNOWN_TYPE: &str = "esql_unknown_type";
    pub const ESQL_GROUP_BY_COLUMN: &str = "esql_group_by_column";
    pub const EQL_NOT_BOOLEAN: &str = "eql_not_boolean";
    pub const ESQL_PATTERN: &str = "esql_pattern";
    pub const ESQL_EXPRESSION_DEPTH: &str = "esql_expression_depth";
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("{0}")]
    Message(String),
}

#[cfg(test)]
mod tests {
    #[test]
    fn line_index_matches_offset_to_position() {
        let text = "ab\n\u{1F600}c\r\n\nd é";
        let index = LineIndex::new(text);
        for (offset, _) in text
            .char_indices()
            .chain([(text.len(), ' '), (text.len() + 5, ' ')])
        {
            assert_eq!(
                index.position(offset),
                offset_to_position(text, offset),
                "{offset}"
            );
        }
    }

    use super::*;

    #[test]
    fn no_otide_in_crate_name() {
        assert!(
            !env!("CARGO_PKG_NAME").contains("otide")
                || env!("CARGO_PKG_NAME").starts_with("opentide")
        );
        assert!(env!("CARGO_PKG_NAME").starts_with("opentide"));
    }

    #[test]
    fn language_id_roundtrip() {
        for id in LanguageId::QUERY_LANGUAGES
            .into_iter()
            .chain([LanguageId::TideYaml])
        {
            assert_eq!(LanguageId::parse(id.as_str()), Some(id));
        }
        assert_eq!(LanguageId::parse("kusto"), Some(LanguageId::Kql));
        // `KQL` is Kusto. Kibana's language is `kuery`.
        assert_eq!(LanguageId::parse("KQL"), Some(LanguageId::Kql));
        assert_eq!(LanguageId::parse("kibana-kql"), Some(LanguageId::Kuery));
        assert_eq!(LanguageId::parse("sql"), None);
        assert_eq!(LanguageId::parse("esql"), Some(LanguageId::Esql));
        assert_eq!(LanguageId::from_extension("sql"), None);
        assert_eq!(LanguageId::from_extension("eql"), Some(LanguageId::Eql));
    }

    #[test]
    fn offset_to_position_handles_newlines() {
        let src = "abc\néé";
        let pos = offset_to_position(src, src.len());
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 2);
    }

    #[test]
    fn range_contains_inclusive_end() {
        let range = Range::new(Position::new(0, 1), Position::new(0, 4));
        assert!(range.contains(Position::new(0, 1)));
        assert!(range.contains(Position::new(0, 4)));
        assert!(!range.contains(Position::new(0, 0)));
    }
}
