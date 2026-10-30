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
    pub const KQL_DEPRECATED_OPERATOR: &str = "kql_deprecated_operator";
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
    /// A field the templates ask for and validation does not require.
    pub const RECOMMENDED_FIELD_MISSING: &str = "recommended_field_missing";
    pub const DEFENDER_OUTPUT_COLUMNS: &str = "defender_output_columns";
    /// `::type` names no Elasticsearch release can cast to.
    pub const ESQL_UNKNOWN_TYPE: &str = "esql_unknown_type";
    pub const ESQL_GROUP_BY_COLUMN: &str = "esql_group_by_column";
    pub const EQL_NOT_BOOLEAN: &str = "eql_not_boolean";
    pub const ESQL_PATTERN: &str = "esql_pattern";
    pub const ESQL_EXPRESSION_DEPTH: &str = "esql_expression_depth";

    /// Every code above, in declaration order.
    pub const ALL: &[&str] = &[
        SCHEMA_VALIDATION,
        VOCAB_UNKNOWN,
        INVALID_UUID,
        DUPLICATE_ID,
        INVALID_REF,
        CHAINING_RELATION_UNKNOWN,
        DEPRECATED_FIELD,
        KQL_CONTROL_COMMAND_UNSUPPORTED,
        KQL_UNKNOWN_OPERATOR,
        KQL_UNKNOWN_FUNCTION,
        KQL_DEPRECATED_FUNCTION,
        KQL_DEPRECATED_OPERATOR,
        KQL_UNKNOWN_TABLE,
        KQL_RENDER_NOT_VALID,
        KQL_PARSE_ERROR,
        KQL_WHERE_NOT_FIRST,
        KQL_UNSCOPED_SEARCH,
        KQL_UNSCOPED_UNION,
        KQL_WILDCARD_TABLE,
        KQL_JOIN_SUMMARIZE_BEFORE_PROJECT,
        SPL_UNKNOWN_COMMAND,
        SPL_PARSE_ERROR,
        SPL_WILDCARD,
        SPL_LEADING_NOT,
        SPL_SUBSEARCH_TRUNCATION,
        ESQL_PARSE_ERROR,
        ESQL_UNKNOWN_COMMAND,
        ESQL_UNKNOWN_FUNCTION,
        ESQL_UNAVAILABLE,
        ESQL_METADATA_ID,
        EQL_PARSE_ERROR,
        EQL_UNKNOWN_FUNCTION,
        EQL_UNSUPPORTED,
        EQL_MAXSPAN_UNIT,
        EQL_MAXSPAN_WINDOW,
        EQL_MAXSPAN_LOOKBACK,
        EQL_FUNCTION_ARITY,
        EQL_CASE_SENSITIVE,
        EQL_LITERAL_WILDCARD,
        EQL_NESTED_COMMENT,
        EQL_EXPRESSION_DEPTH,
        EQL_ARGUMENT_TYPE,
        EQL_FIELD_COMPARISON,
        EQL_RUNS_IGNORED,
        EQL_UNTIL_TERM,
        EQL_REGEX,
        EQL_MAXSPAN_MISSING,
        KUERY_PARSE_ERROR,
        KUERY_LUCENE_SYNTAX,
        KUERY_ESCAPE,
        KUERY_QUOTED_WILDCARD,
        LUCENE_PARSE_ERROR,
        LUCENE_LOWERCASE_OPERATOR,
        LUCENE_MIXED_OPERATORS,
        LUCENE_ESCAPE,
        LUCENE_KUERY_SYNTAX,
        LUCENE_REGEXP,
        LUCENE_FUZZY,
        LUCENE_RANGE_OPERATOR,
        LUCENE_UNESCAPED_SLASH,
        LUCENE_BARE_TERM,
        LUCENE_LOOKS_LIKE_KUERY,
        LUCENE_ELASTICSEARCH_ONLY,
        KUERY_QUESTION_MARK,
        KUERY_FREE_TEXT,
        KUERY_LOOKS_LIKE_LUCENE,
        KUERY_RANGE_TYPE,
        LOOKBACK_ZERO,
        LOOKBACK_LONG,
        THRESHOLD_LOOKBACK,
        RISK_BAND,
        TECHNIQUE_NOT_ENTERPRISE,
        CROWDSTRIKE_UNSUPPORTED,
        FILENAME_SLUG,
        MISSING_AUTHOR,
        MISSING_ORGANISATION,
        RECOMMENDED_FIELD_MISSING,
        DEFENDER_OUTPUT_COLUMNS,
        ESQL_UNKNOWN_TYPE,
        ESQL_GROUP_BY_COLUMN,
        EQL_NOT_BOOLEAN,
        ESQL_PATTERN,
        ESQL_EXPRESSION_DEPTH,
    ];

    /// One sentence on what a code means, for hosts that explain a diagnostic
    /// (`opentide explain <code>`). `None` for a code this engine does not emit.
    pub fn describe(code: &str) -> Option<&'static str> {
        Some(match code {
            SCHEMA_VALIDATION => {
                "A Tide object does not match its schema: a required field is missing, or a value has the wrong shape."
            }
            VOCAB_UNKNOWN => "A value is not in the vocabulary its field draws from.",
            INVALID_UUID => "An object id is not a version 4 UUID.",
            DUPLICATE_ID => "Two object files carry the same UUID.",
            INVALID_REF => "A reference names an object the workspace does not have.",
            CHAINING_RELATION_UNKNOWN => {
                "A threat chaining relation is not in the chaining_relations vocabulary."
            }
            DEPRECATED_FIELD => "The field is deprecated in its schema revision.",
            KQL_CONTROL_COMMAND_UNSUPPORTED => {
                "A KQL control command (.show, .create, ...) is not a detection query; rules cannot run it."
            }
            KQL_UNKNOWN_OPERATOR => "The KQL tabular operator is not one Kusto knows.",
            KQL_UNKNOWN_FUNCTION => "The KQL function is not in the Kusto function catalog.",
            KQL_DEPRECATED_FUNCTION => {
                "The KQL function is a deprecated alias; Microsoft Learn names its replacement."
            }
            KQL_DEPRECATED_OPERATOR => {
                "The KQL scalar operator is a legacy spelling (containscs); use the current name (contains_cs)."
            }
            KQL_UNKNOWN_TABLE => {
                "The table is not in the platform's KQL schema (Sentinel or Defender)."
            }
            KQL_RENDER_NOT_VALID => "render draws a chart; it has no effect in a detection rule.",
            KQL_PARSE_ERROR => "The KQL query does not parse.",
            KQL_WHERE_NOT_FIRST => {
                "A filter comes after a more expensive operator; filtering first scans fewer rows."
            }
            KQL_UNSCOPED_SEARCH => "search without a table scans every table in the workspace.",
            KQL_UNSCOPED_UNION => "union * or an unscoped union reads every table.",
            KQL_WILDCARD_TABLE => "A wildcard table name reads every matching table.",
            KQL_JOIN_SUMMARIZE_BEFORE_PROJECT => {
                "join or summarize runs before project, so it carries every column."
            }
            SPL_UNKNOWN_COMMAND => "The SPL command is not in the Splunk Search Reference.",
            SPL_PARSE_ERROR => "The SPL search does not parse.",
            SPL_WILDCARD => {
                "A leading or mid-token wildcard cannot use the index and scans every event."
            }
            SPL_LEADING_NOT => {
                "A search that starts with NOT scans every event before excluding any."
            }
            SPL_SUBSEARCH_TRUNCATION => {
                "A subsearch is silently truncated at its result or time limit."
            }
            ESQL_PARSE_ERROR => "The ES|QL query does not parse.",
            ESQL_UNKNOWN_COMMAND => "The ES|QL command is not one Elasticsearch knows.",
            ESQL_UNKNOWN_FUNCTION => {
                "The ES|QL function is not in the Elasticsearch function catalog."
            }
            ESQL_UNAVAILABLE => {
                "The command, function or form is missing or in preview on a targeted stack version."
            }
            ESQL_METADATA_ID => {
                "A non-aggregating ES|QL rule query has no METADATA _id, so alerts cannot be deduplicated."
            }
            EQL_PARSE_ERROR => "The EQL query does not parse.",
            EQL_UNKNOWN_FUNCTION => {
                "The EQL function is not in the Elasticsearch function catalog."
            }
            EQL_UNSUPPORTED => {
                "Elasticsearch EQL does not support this construct (pipes, relationships, ...)."
            }
            EQL_MAXSPAN_UNIT => "A sequence maxspan uses a unit Elasticsearch does not accept.",
            EQL_MAXSPAN_WINDOW => {
                "A sequence maxspan is longer than the rule's interval plus lookback, so the rule cannot see whole sequences."
            }
            EQL_MAXSPAN_LOOKBACK => "A sequence maxspan is longer than the rule's lookback.",
            EQL_FUNCTION_ARITY => "An EQL function is called with the wrong number of arguments.",
            EQL_CASE_SENSITIVE => {
                "The comparison is case-sensitive; the case-insensitive form may be meant."
            }
            EQL_LITERAL_WILDCARD => {
                "A wildcard character is compared literally; use : or like for a pattern."
            }
            EQL_NESTED_COMMENT => {
                "Elasticsearch nests /* */ comments; the comment ends later than it looks."
            }
            EQL_EXPRESSION_DEPTH => "The expression nests deeper than Elasticsearch accepts.",
            EQL_ARGUMENT_TYPE => "A literal has a type the EQL verifier rejects in this position.",
            EQL_FIELD_COMPARISON => {
                "Both sides of a comparison read fields, which EQL does not support."
            }
            EQL_RUNS_IGNORED => "A decimal runs count is truncated by Elasticsearch.",
            EQL_UNTIL_TERM => "runs or a missing-event term ![ ] is not allowed on until.",
            EQL_REGEX => "The regular expression trips a Lucene RegExp pitfall.",
            EQL_MAXSPAN_MISSING => {
                "A sequence has no maxspan, so partial sequences are held until they expire."
            }
            KUERY_PARSE_ERROR => "The Kibana KQL (kuery) query does not parse.",
            KUERY_LUCENE_SYNTAX => "Lucene syntax inside a Kibana KQL (kuery) query.",
            KUERY_ESCAPE => "A character needs escaping in Kibana KQL (kuery).",
            KUERY_QUOTED_WILDCARD => {
                "A wildcard inside quotes is a literal * in Kibana KQL (kuery)."
            }
            LUCENE_PARSE_ERROR => "The Lucene query does not parse.",
            LUCENE_LOWERCASE_OPERATOR => {
                "Lucene operators are upper case; lowercase and/or/not are search terms."
            }
            LUCENE_MIXED_OPERATORS => {
                "AND and OR mixed without parentheses do not bind as they read."
            }
            LUCENE_ESCAPE => "A character needs escaping in Lucene.",
            LUCENE_KUERY_SYNTAX => "Kibana KQL (kuery) syntax inside a Lucene query.",
            LUCENE_REGEXP => {
                "The /regexp/ body is rejected by, or too costly for, Lucene's RegExp."
            }
            LUCENE_FUZZY => "Elasticsearch accepts only 0, 1, 2 or AUTO as a fuzziness.",
            LUCENE_RANGE_OPERATOR => {
                "f:> 10 searches f for the text >; the value must follow the operator."
            }
            LUCENE_UNESCAPED_SLASH => "An unescaped / starts a regular expression.",
            LUCENE_BARE_TERM => "A term with no field searches every field.",
            LUCENE_LOOKS_LIKE_KUERY => {
                "The query reads like Kibana KQL (kuery); language: kuery may be meant."
            }
            LUCENE_ELASTICSEARCH_ONLY => {
                "The syntax works in Elasticsearch but not in Carbon Black Cloud."
            }
            KUERY_QUESTION_MARK => {
                "? is a literal in Kibana KQL (kuery), not a single-character wildcard."
            }
            KUERY_FREE_TEXT => "A value with no field searches every field.",
            KUERY_LOOKS_LIKE_LUCENE => {
                "The query reads like Lucene; language: lucene may be meant."
            }
            KUERY_RANGE_TYPE => "A range compares a value of the wrong type.",
            LOOKBACK_ZERO => {
                "The Elastic rule's lookback is zero, so events that arrive late are missed."
            }
            LOOKBACK_LONG => {
                "The Elastic rule's lookback exceeds an hour; it is added to the interval, not the whole window."
            }
            THRESHOLD_LOOKBACK => {
                "A threshold rule's lookback exceeds its interval, so windows overlap and alerts repeat."
            }
            RISK_BAND => "The risk score is outside the band of the rule's severity.",
            TECHNIQUE_NOT_ENTERPRISE => {
                "The ATT&CK technique is not in the Enterprise matrix that Elastic maps."
            }
            CROWDSTRIKE_UNSUPPORTED => {
                "CrowdStrike queries are not validated; the engine never fakes it."
            }
            FILENAME_SLUG => "The file name is not the slug of the object's name.",
            MISSING_AUTHOR => "The recommended metadata.author field is missing.",
            MISSING_ORGANISATION => "The recommended metadata.organisation field is missing.",
            RECOMMENDED_FIELD_MISSING => {
                "A field the templates ask for is missing; opentide validate accepts the object without it."
            }
            DEFENDER_OUTPUT_COLUMNS => {
                "A Defender custom detection must return the columns Defender requires."
            }
            ESQL_UNKNOWN_TYPE => {
                "The ::type cast names a type no Elasticsearch release can cast to."
            }
            ESQL_GROUP_BY_COLUMN => {
                "A suppression group_by field is not a column the ES|QL query returns."
            }
            EQL_NOT_BOOLEAN => "A string or number literal is used as a condition.",
            ESQL_PATTERN => "A LIKE or RLIKE pattern escapes or matches differently than it reads.",
            ESQL_EXPRESSION_DEPTH => "The expression nests deeper than Elasticsearch accepts.",
            _ => return None,
        })
    }
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
    fn every_code_is_listed_and_described() {
        let source = include_str!("lib.rs");
        let module =
            &source[source.find("pub mod codes").unwrap()..source.find("pub const ALL").unwrap()];
        let declared = module.matches("pub const ").count();
        assert_eq!(
            declared,
            codes::ALL.len(),
            "codes::ALL must list every code"
        );
        let mut seen = std::collections::BTreeSet::new();
        for code in codes::ALL {
            assert!(seen.insert(*code), "{code} listed twice");
            let text = codes::describe(code).unwrap_or_else(|| panic!("{code} has no description"));
            assert!(
                text.ends_with('.'),
                "{code}: one sentence ending in a period"
            );
        }
        assert_eq!(codes::describe("not_a_code"), None);
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
