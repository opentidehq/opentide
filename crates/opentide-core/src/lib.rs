//! Shared I/O-free types for the OpenTide language server.
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
}

impl LanguageId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kql => "kql",
            Self::Spl => "spl",
            Self::TideYaml => "opentide-yaml",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "kql" | "opentide-kql" | "KQL" | "kusto" => Some(Self::Kql),
            "spl" | "opentide-spl" | "SPL" => Some(Self::Spl),
            "opentide-yaml" | "yaml" | "tide" | "tide-yaml" => Some(Self::TideYaml),
            _ => None,
        }
    }
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

pub fn span_to_range(source: &str, span: ByteSpan) -> Range {
    Range {
        start: offset_to_position(source, span.start),
        end: offset_to_position(source, span.end),
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
    pub const KQL_UNKNOWN_TABLE: &str = "kql_unknown_table";
    pub const KQL_RENDER_NOT_VALID: &str = "kql_render_not_valid";
    pub const KQL_PARSE_ERROR: &str = "kql_parse_error";
    pub const SPL_UNKNOWN_COMMAND: &str = "spl_unknown_command";
    pub const SPL_PARSE_ERROR: &str = "spl_parse_error";
    pub const CROWDSTRIKE_UNSUPPORTED: &str = "crowdstrike_unsupported";
    pub const FILENAME_SLUG: &str = "filename_slug";
    pub const MISSING_AUTHOR: &str = "missing_author";
    pub const MISSING_ORGANISATION: &str = "missing_organisation";
    pub const DEFENDER_OUTPUT_COLUMNS: &str = "defender_output_columns";
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("{0}")]
    Message(String),
}

#[cfg(test)]
mod tests {
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
        for id in [LanguageId::Kql, LanguageId::Spl, LanguageId::TideYaml] {
            assert_eq!(LanguageId::parse(id.as_str()), Some(id));
        }
        assert_eq!(LanguageId::parse("kusto"), Some(LanguageId::Kql));
        assert_eq!(LanguageId::parse("sql"), None);
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
