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
    /// A configuration TOML file under `.opentide/configurations/`. The host
    /// checks it (opentide's models); the engine places the findings. Not an
    /// alias of `toml`: only those files are this language.
    #[serde(rename = "opentide-config")]
    Config,
    /// Falco rule conditions (Sysdig Secure `configurations.sysdig`).
    #[serde(rename = "falco", alias = "opentide-falco")]
    Falco,
    /// CrowdStrike Query Language: Falcon LogScale and Next-Gen SIEM
    /// (`configurations.crowdstrike`). Not Cassandra's CQL.
    #[serde(rename = "cql", alias = "opentide-cql")]
    Cql,
    /// YARA signatures as libyara 4.5 compiles them, with YARA-X 1.x as a
    /// second opinion (yara-1.0; HarfangLab and Bitdefender `yara` blocks).
    #[serde(rename = "yara", alias = "opentide-yara")]
    Yara,
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
            Self::Config => "opentide-config",
            Self::Falco => "falco",
            Self::Cql => "cql",
            Self::Yara => "yara",
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
            "opentide-config" => Some(Self::Config),
            "falco" | "opentide-falco" | "Falco" => Some(Self::Falco),
            "cql" | "opentide-cql" | "CQL" | "logscale" | "crowdstrike" => Some(Self::Cql),
            "yara" | "opentide-yara" | "YARA" => Some(Self::Yara),
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
            "falco" => Some(Self::Falco),
            "cql" => Some(Self::Cql),
            "yar" | "yara" => Some(Self::Yara),
            _ => None,
        }
    }

    /// Query languages with a tree-sitter grammar and an engine.
    pub const QUERY_LANGUAGES: [Self; 9] = [
        Self::Kql,
        Self::Spl,
        Self::Esql,
        Self::Eql,
        Self::Kuery,
        Self::Lucene,
        Self::Falco,
        Self::Cql,
        Self::Yara,
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

/// The text of a document without its leading UTF-8 byte-order mark
/// (U+FEFF, `EF BB BF`), if it has one. Some Windows editors save files with
/// one; an editor neither shows it nor counts it as a column, so a document's
/// offsets and positions are those of the text after it.
pub fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// [`strip_bom`], with `offset` (a byte offset into `text`) moved onto the
/// text it returns. An offset inside the mark is the start of the text.
/// Where the run of characters `keep` accepts that ends `text` starts: the
/// byte after the last character it rejects, or 0. Always a char boundary,
/// whatever the rejected character's width (#182: `rfind(...) + 1` landed
/// inside `é`).
pub fn word_start(text: &str, keep: impl Fn(char) -> bool) -> usize {
    text.char_indices()
        .rev()
        .find(|(_, c)| !keep(*c))
        .map_or(0, |(i, c)| i + c.len_utf8())
}

pub fn strip_bom_at(text: &str, offset: usize) -> (&str, usize) {
    let stripped = strip_bom(text);
    let shift = text.len() - stripped.len();
    (stripped, offset.saturating_sub(shift))
}

/// Convert a UTF-8 byte offset to an LSP position. An offset inside a
/// multi-byte character counts from that character's start: a span that ends
/// mid-character gives a slightly short range, never a panic.
pub fn offset_to_position(source: &str, offset: usize) -> Position {
    let mut offset = offset.min(source.len());
    while !source.is_char_boundary(offset) {
        offset -= 1;
    }
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
        let mut offset = offset.min(self.source.len());
        while !self.source.is_char_boundary(offset) {
            offset -= 1;
        }
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

    /// A severity named the way hosts name it (`error`, `warning`,
    /// `information` or `info`, `hint`), case-insensitively.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warning" | "warn" => Some(Self::Warning),
            "information" | "info" => Some(Self::Information),
            "hint" => Some(Self::Hint),
            _ => None,
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

pub mod datasets;

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
    /// `==`, `<>`, `=>`, `=<`, `!~` or `=~` in a search clause.
    pub const SPL_SEARCH_OPERATOR: &str = "spl_search_operator";
    /// A command Splunk parses with no arguments, where it does nothing,
    /// returns no results or fails at run time.
    pub const SPL_EMPTY_COMMAND: &str = "spl_empty_command";
    /// A trailing `|` with no command, which Splunk ignores.
    pub const SPL_EMPTY_STAGE: &str = "spl_empty_stage";
    /// The query starts with a command name but no `|`, so Splunk searches
    /// for the word.
    pub const SPL_COMMAND_WITHOUT_PIPE: &str = "spl_command_without_pipe";
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
    pub const FILENAME_SLUG: &str = "filename_slug";
    pub const FILENAME_PATTERN: &str = "filename_pattern";
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
    // Dataset knowledge (#110): known schemas, then visibility.toml, then warn.
    pub const KQL_TABLE_NOT_DECLARED: &str = "kql_table_not_declared";
    pub const KQL_UNKNOWN_COLUMN: &str = "kql_unknown_column";
    pub const KQL_TYPE_MISMATCH: &str = "kql_type_mismatch";
    pub const SPL_UNKNOWN_DATAMODEL: &str = "spl_unknown_datamodel";
    pub const SPL_UNKNOWN_DATAMODEL_FIELD: &str = "spl_unknown_datamodel_field";
    pub const SPL_DATASET_NOT_DECLARED: &str = "spl_dataset_not_declared";
    pub const ECS_TYPE_MISMATCH: &str = "ecs_type_mismatch";
    pub const ECS_UNKNOWN_FIELD: &str = "ecs_unknown_field";
    pub const ELASTIC_DATASET_NOT_DECLARED: &str = "elastic_dataset_not_declared";
    /// A Carbon Black Cloud query field one edit or two from a catalog field
    /// (#162).
    pub const CBC_UNKNOWN_FIELD: &str = "cbc_unknown_field";
    /// The host's configuration checker failed on a configuration file.
    pub const CONFIG_CHECK_FAILED: &str = "config_check_failed";
    // Falco conditions (sysdig-1.0, "Falco language").
    pub const FALCO_PARSE_ERROR: &str = "falco_parse_error";
    pub const FALCO_UNKNOWN_FIELD: &str = "falco_unknown_field";
    pub const FALCO_UNKNOWN_MACRO: &str = "falco_unknown_macro";
    pub const FALCO_UNKNOWN_LIST: &str = "falco_unknown_list";
    pub const FALCO_MISPLACED_LIST: &str = "falco_misplaced_list";
    pub const FALCO_FIELD_ARGUMENT: &str = "falco_field_argument";
    pub const FALCO_OPERATOR_TYPE: &str = "falco_operator_type";
    pub const FALCO_VALUE_TYPE: &str = "falco_value_type";
    pub const FALCO_TRANSFORMER: &str = "falco_transformer";
    pub const FALCO_RHS_FIELD: &str = "falco_rhs_field";
    pub const FALCO_INVALID_REGEX: &str = "falco_invalid_regex";
    pub const FALCO_REGEX_SIMPLE: &str = "falco_regex_simple";
    pub const FALCO_FIELD_AS_VALUE: &str = "falco_field_as_value";
    pub const FALCO_TRANSFORMER_AS_VALUE: &str = "falco_transformer_as_value";
    pub const FALCO_DEPRECATED_FIELD: &str = "falco_deprecated_field";
    pub const FALCO_UNSAFE_NA_CHECK: &str = "falco_unsafe_na_check";
    pub const FALCO_NO_EVTTYPE: &str = "falco_no_evttype";
    pub const FALCO_OUTPUT_SYNTAX: &str = "falco_output_syntax";
    pub const FALCO_NEWER_SYNTAX: &str = "falco_newer_syntax";
    pub const FALCO_EXCEPTION: &str = "falco_exception";
    pub const FALCO_UNKNOWN_EVENT: &str = "falco_unknown_event";
    pub const FALCO_UNKNOWN_SOURCE: &str = "falco_unknown_source";
    pub const FALCO_APPEND_CONDITION: &str = "falco_append_condition";
    pub const FALCO_UNKNOWN_RULE: &str = "falco_unknown_rule";
    // Sysdig block constraint codes (sysdig-1.0, Constraints), as opentide names them.
    pub const SYSDIG_RULE_SHAPE: &str = "sysdig_rule_shape";
    pub const SYSDIG_TUNING_KEYS: &str = "sysdig_tuning_keys";
    pub const SYSDIG_PRIORITY: &str = "sysdig_priority";
    pub const SYSDIG_SOURCE: &str = "sysdig_source";
    pub const SYSDIG_EXCEPTION_SHAPE: &str = "sysdig_exception_shape";
    pub const SYSDIG_DEFINITION_NAME: &str = "sysdig_definition_name";
    pub const SYSDIG_DEFINITION_DUPLICATE: &str = "sysdig_definition_duplicate";
    pub const SYSDIG_DEFINITION_ORDER: &str = "sysdig_definition_order";
    pub const SYSDIG_LIST_IN_VALUE: &str = "sysdig_list_in_value";
    pub const SYSDIG_LIST_SELF_REFERENCE: &str = "sysdig_list_self_reference";

    // CrowdStrike Query Language (Falcon LogScale, Next-Gen SIEM).
    pub const CQL_PARSE_ERROR: &str = "cql_parse_error";
    pub const CQL_UNKNOWN_FUNCTION: &str = "cql_unknown_function";
    pub const CQL_REMOVED_FUNCTION: &str = "cql_removed_function";
    pub const CQL_DEPRECATED_FUNCTION: &str = "cql_deprecated_function";
    pub const CQL_UNKNOWN_PARAMETER: &str = "cql_unknown_parameter";
    pub const CQL_DUPLICATE_PARAMETER: &str = "cql_duplicate_parameter";
    pub const CQL_UNNAMED_ARGUMENT: &str = "cql_unnamed_argument";
    pub const CQL_MISSING_PARAMETER: &str = "cql_missing_parameter";
    pub const CQL_PARAMETER_VALUE: &str = "cql_parameter_value";
    pub const CQL_REGEX_FLAG: &str = "cql_regex_flag";
    pub const CQL_STRING_ESCAPE: &str = "cql_string_escape";
    pub const CQL_FREE_TEXT_AFTER_AGGREGATE: &str = "cql_free_text_after_aggregate";
    pub const CQL_ASSIGNMENT_AS: &str = "cql_assignment_as";
    pub const CQL_LINK_OUTSIDE_CORRELATE: &str = "cql_link_outside_correlate";
    pub const CQL_UNKNOWN_EVENT: &str = "cql_unknown_event";
    pub const CQL_EVENT_FUNCTION_AFTER_AGGREGATE: &str = "cql_event_function_after_aggregate";
    pub const CQL_CORRELATE_PLACEMENT: &str = "cql_correlate_placement";
    pub const CQL_MATCH_GUARD: &str = "cql_match_guard";
    pub const CQL_REGEX_GROUP_UNDER_OR: &str = "cql_regex_group_under_or";
    pub const CQL_CORRELATE_AGGREGATE: &str = "cql_correlate_aggregate";

    // YARA (yara-1.0, #165). Errors are what libyara 4.5 refuses; the
    // warnings are yara_x_incompatible through yara_meta_missing.
    pub const YARA_PARSE_ERROR: &str = "yara_parse_error";
    pub const YARA_INCLUDE: &str = "yara_include";
    pub const YARA_SIGNATURE_ALIAS: &str = "yara_signature_alias";
    pub const YARA_EMPTY_SIGNATURE: &str = "yara_empty_signature";
    pub const YARA_DUPLICATE_RULE: &str = "yara_duplicate_rule";
    pub const YARA_DUPLICATE_STRING: &str = "yara_duplicate_string";
    pub const YARA_DUPLICATE_TAG: &str = "yara_duplicate_tag";
    pub const YARA_UNDEFINED_STRING: &str = "yara_undefined_string";
    pub const YARA_UNREFERENCED_STRING: &str = "yara_unreferenced_string";
    pub const YARA_UNDEFINED_IDENTIFIER: &str = "yara_undefined_identifier";
    pub const YARA_RULE_IDENTIFIER_CONFLICT: &str = "yara_rule_identifier_conflict";
    pub const YARA_UNKNOWN_MODULE: &str = "yara_unknown_module";
    pub const YARA_MODULE_NOT_IMPORTED: &str = "yara_module_not_imported";
    pub const YARA_UNKNOWN_MODULE_MEMBER: &str = "yara_unknown_module_member";
    pub const YARA_TYPE: &str = "yara_type";
    pub const YARA_REGEXP: &str = "yara_regexp";
    pub const YARA_HEX_STRING: &str = "yara_hex_string";
    pub const YARA_STRING_MODIFIER: &str = "yara_string_modifier";
    pub const YARA_NUMBER_OUT_OF_RANGE: &str = "yara_number_out_of_range";
    pub const YARA_X_INCOMPATIBLE: &str = "yara_x_incompatible";
    pub const YARA_SLOW_PATTERN: &str = "yara_slow_pattern";
    pub const YARA_ENTRYPOINT_DEPRECATED: &str = "yara_entrypoint_deprecated";
    pub const YARA_SUSPICIOUS_EXPRESSION: &str = "yara_suspicious_expression";
    pub const YARA_MODULE_UNCONFIRMED: &str = "yara_module_unconfirmed";
    pub const YARA_META_MISSING: &str = "yara_meta_missing";
    // The YARA profiles of harfanglab-1.0 (1.2) and bitdefender-1.0.
    pub const HARFANGLAB_RULE_KIND: &str = "harfanglab_rule_kind";
    pub const HARFANGLAB_YARA_FORM: &str = "harfanglab_yara_form";
    pub const HARFANGLAB_YARA_SECTION_HEADER: &str = "harfanglab_yara_section_header";
    pub const HARFANGLAB_YARA_IMPORT: &str = "harfanglab_yara_import";
    pub const HARFANGLAB_YARA_RULE_NAME: &str = "harfanglab_yara_rule_name";
    pub const HARFANGLAB_YARA_CONTEXT: &str = "harfanglab_yara_context";
    pub const BITDEFENDER_YARA_ASCII: &str = "bitdefender_yara_ascii";
    pub const BITDEFENDER_YARA_SIZE: &str = "bitdefender_yara_size";

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
        SPL_SEARCH_OPERATOR,
        SPL_EMPTY_COMMAND,
        SPL_EMPTY_STAGE,
        SPL_COMMAND_WITHOUT_PIPE,
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
        FILENAME_SLUG,
        FILENAME_PATTERN,
        MISSING_AUTHOR,
        MISSING_ORGANISATION,
        RECOMMENDED_FIELD_MISSING,
        DEFENDER_OUTPUT_COLUMNS,
        ESQL_UNKNOWN_TYPE,
        ESQL_GROUP_BY_COLUMN,
        EQL_NOT_BOOLEAN,
        ESQL_PATTERN,
        ESQL_EXPRESSION_DEPTH,
        KQL_TABLE_NOT_DECLARED,
        KQL_UNKNOWN_COLUMN,
        KQL_TYPE_MISMATCH,
        SPL_UNKNOWN_DATAMODEL,
        SPL_UNKNOWN_DATAMODEL_FIELD,
        SPL_DATASET_NOT_DECLARED,
        ECS_TYPE_MISMATCH,
        ECS_UNKNOWN_FIELD,
        ELASTIC_DATASET_NOT_DECLARED,
        CBC_UNKNOWN_FIELD,
        CONFIG_CHECK_FAILED,
        FALCO_PARSE_ERROR,
        FALCO_UNKNOWN_FIELD,
        FALCO_UNKNOWN_MACRO,
        FALCO_UNKNOWN_LIST,
        FALCO_MISPLACED_LIST,
        FALCO_FIELD_ARGUMENT,
        FALCO_OPERATOR_TYPE,
        FALCO_VALUE_TYPE,
        FALCO_TRANSFORMER,
        FALCO_RHS_FIELD,
        FALCO_INVALID_REGEX,
        FALCO_REGEX_SIMPLE,
        FALCO_FIELD_AS_VALUE,
        FALCO_TRANSFORMER_AS_VALUE,
        FALCO_DEPRECATED_FIELD,
        FALCO_UNSAFE_NA_CHECK,
        FALCO_NO_EVTTYPE,
        FALCO_OUTPUT_SYNTAX,
        FALCO_NEWER_SYNTAX,
        FALCO_EXCEPTION,
        FALCO_UNKNOWN_EVENT,
        FALCO_UNKNOWN_SOURCE,
        FALCO_APPEND_CONDITION,
        FALCO_UNKNOWN_RULE,
        SYSDIG_RULE_SHAPE,
        SYSDIG_TUNING_KEYS,
        SYSDIG_PRIORITY,
        SYSDIG_SOURCE,
        SYSDIG_EXCEPTION_SHAPE,
        SYSDIG_DEFINITION_NAME,
        SYSDIG_DEFINITION_DUPLICATE,
        SYSDIG_DEFINITION_ORDER,
        SYSDIG_LIST_IN_VALUE,
        SYSDIG_LIST_SELF_REFERENCE,
        CQL_PARSE_ERROR,
        CQL_UNKNOWN_FUNCTION,
        CQL_REMOVED_FUNCTION,
        CQL_DEPRECATED_FUNCTION,
        CQL_UNKNOWN_PARAMETER,
        CQL_DUPLICATE_PARAMETER,
        CQL_UNNAMED_ARGUMENT,
        CQL_MISSING_PARAMETER,
        CQL_PARAMETER_VALUE,
        CQL_REGEX_FLAG,
        CQL_STRING_ESCAPE,
        CQL_FREE_TEXT_AFTER_AGGREGATE,
        CQL_ASSIGNMENT_AS,
        CQL_LINK_OUTSIDE_CORRELATE,
        CQL_UNKNOWN_EVENT,
        CQL_EVENT_FUNCTION_AFTER_AGGREGATE,
        CQL_CORRELATE_PLACEMENT,
        CQL_MATCH_GUARD,
        CQL_REGEX_GROUP_UNDER_OR,
        CQL_CORRELATE_AGGREGATE,
        YARA_PARSE_ERROR,
        YARA_INCLUDE,
        YARA_SIGNATURE_ALIAS,
        YARA_EMPTY_SIGNATURE,
        YARA_DUPLICATE_RULE,
        YARA_DUPLICATE_STRING,
        YARA_DUPLICATE_TAG,
        YARA_UNDEFINED_STRING,
        YARA_UNREFERENCED_STRING,
        YARA_UNDEFINED_IDENTIFIER,
        YARA_RULE_IDENTIFIER_CONFLICT,
        YARA_UNKNOWN_MODULE,
        YARA_MODULE_NOT_IMPORTED,
        YARA_UNKNOWN_MODULE_MEMBER,
        YARA_TYPE,
        YARA_REGEXP,
        YARA_HEX_STRING,
        YARA_STRING_MODIFIER,
        YARA_NUMBER_OUT_OF_RANGE,
        YARA_X_INCOMPATIBLE,
        YARA_SLOW_PATTERN,
        YARA_ENTRYPOINT_DEPRECATED,
        YARA_SUSPICIOUS_EXPRESSION,
        YARA_MODULE_UNCONFIRMED,
        YARA_META_MISSING,
        HARFANGLAB_RULE_KIND,
        HARFANGLAB_YARA_FORM,
        HARFANGLAB_YARA_SECTION_HEADER,
        HARFANGLAB_YARA_IMPORT,
        HARFANGLAB_YARA_RULE_NAME,
        HARFANGLAB_YARA_CONTEXT,
        BITDEFENDER_YARA_ASCII,
        BITDEFENDER_YARA_SIZE,
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
                "The table is neither one the engine knows for the platform nor one the workspace declares in visibility.toml: a warning under Sentinel, whose workspaces hold tables no catalog lists; an error under Defender's advanced hunting schema. Declaring it in visibility.toml makes it known."
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
            SPL_UNKNOWN_COMMAND => {
                "The SPL command is not in the Splunk Search Reference or a catalogued app such as MLTK: a warning, since an app on the search head can add commands, or an error when the name is one edit from a known command."
            }
            SPL_PARSE_ERROR => "The SPL search does not parse.",
            SPL_WILDCARD => {
                "A leading or mid-token wildcard in a base search that nothing else narrows (no index, sourcetype, source, host, TERM() or macro) cannot use the index and scans every event."
            }
            SPL_LEADING_NOT => {
                "A base search that starts with NOT scans every event before excluding any."
            }
            SPL_SUBSEARCH_TRUNCATION => {
                "A subsearch is silently truncated at its result or time limit."
            }
            SPL_EMPTY_COMMAND => {
                "A command with no arguments: Splunk runs it, but it does nothing, returns no results, or fails at run time."
            }
            SPL_EMPTY_STAGE => "A trailing | with no command; Splunk ignores it.",
            SPL_COMMAND_WITHOUT_PIPE => {
                "The query starts with a command name but no |, so Splunk searches for the word instead of running the command."
            }
            SPL_SEARCH_OPERATOR => {
                "A search clause compares with an operator search does not have (`==`, `<>`, `=>`, `=<`, `!~`): Splunk accepts it but the comparison never matches, or `=~`, which compares with a value that starts with `~`."
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
            FILENAME_SLUG => {
                "The file name is not the one lint.toml's [filenames] style derives from the object's name."
            }
            FILENAME_PATTERN => {
                "The file name does not match the pattern lint.toml's [filenames] sets."
            }
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
            KQL_TABLE_NOT_DECLARED => {
                "The engine knows the table, but the workspace, which declares its tables for the platform in visibility.toml, does not declare it."
            }
            KQL_UNKNOWN_COLUMN => {
                "The column is not in the documented schema of the table or ASIM parser it comes from, or in the columns visibility.toml declares for the table."
            }
            KQL_TYPE_MISMATCH => {
                "The operator cannot apply to the column's documented or declared type."
            }
            SPL_UNKNOWN_DATAMODEL => "The CIM data model or dataset is not one Splunk CIM defines.",
            SPL_UNKNOWN_DATAMODEL_FIELD => {
                "The field is not in the CIM data model the search reads."
            }
            SPL_DATASET_NOT_DECLARED => {
                "The sourcetype is not one the workspace's Splunk log sources name in visibility.toml."
            }
            ECS_TYPE_MISMATCH => {
                "The operation cannot apply to the field's type, from ECS or from the columns visibility.toml declares for the index."
            }
            ECS_UNKNOWN_FIELD => {
                "The field is not in the Elastic Common Schema, on indices that use it, nor declared for the index in visibility.toml; ECS allows custom fields."
            }
            CBC_UNKNOWN_FIELD => {
                "A field in a Carbon Black Cloud query is a near miss of a process search field."
            }
            ELASTIC_DATASET_NOT_DECLARED => {
                "The index pattern is not one the workspace's elastic log sources name, or cover, in visibility.toml."
            }
            CONFIG_CHECK_FAILED => {
                "opentide could not check this configuration file; the message says why. Its other findings are missing."
            }
            FALCO_PARSE_ERROR => "The Falco condition does not parse.",
            FALCO_UNKNOWN_FIELD => {
                "The field is not one Falco or its plugins define for the rule's event source; a plugin the engine does not know may add it."
            }
            FALCO_UNKNOWN_MACRO => {
                "The name is not a macro of the block or of the Falco default rules; the tenant may define it, as Sysdig does for its managed macros."
            }
            FALCO_UNKNOWN_LIST => {
                "The name after a list operator, without parentheses, is not a list of the block or of the Falco default rules, so it is compared as a single value."
            }
            FALCO_MISPLACED_LIST => {
                "A list is used where its expansion breaks the condition: as a macro, or as a single value; a list belongs inside a value list, `in (name)`."
            }
            FALCO_FIELD_ARGUMENT => {
                "A known Falco field is used with an argument it refuses, or without one it requires (libsinsp's field rules: `proc.aname[N]` takes an index, `evt.arg.NAME` an event argument)."
            }
            FALCO_OPERATOR_TYPE => {
                "The operator does not apply to the field's type (libsinsp `flt_is_comparable`); Falco refuses to load the rule."
            }
            FALCO_VALUE_TYPE => {
                "The value cannot be parsed as the field's type (a number, `true` or `false`, an IP address or network, a hex string for `bcontains`); Falco refuses to load the rule."
            }
            FALCO_TRANSFORMER => {
                "A field transformer cannot apply here: the field's type, a field that refuses transformers, or the arguments of `join`, `concat`, or `getopt`."
            }
            FALCO_RHS_FIELD => {
                "A field cannot be compared with another field here (`val(...)` or a transformer on the right): not with `pmatch` or `regex`, not on networks, not on fields that refuse it, and only between fields of the same type."
            }
            FALCO_INVALID_REGEX => "The `regex` pattern does not compile.",
            FALCO_REGEX_SIMPLE => {
                "A `regex` check a plain operator (`=`, `contains`, `startswith`, `endswith`) could make, which libsinsp warns about: regex is the slowest check."
            }
            FALCO_FIELD_AS_VALUE => {
                "A constant value that is a field name: compare with `val(field)` to read the field."
            }
            FALCO_TRANSFORMER_AS_VALUE => {
                "A constant value that looks like a transformer call, compared as text."
            }
            FALCO_DEPRECATED_FIELD => {
                "A field Falco deprecates (`evt.dir`, `evt.latency`): it no longer carries the value it used to."
            }
            FALCO_UNSAFE_NA_CHECK => {
                "A `ka.` or `jevt.` field compared with `<NA>`, which Falco warns about: the field may hold that text."
            }
            FALCO_NO_EVTTYPE => {
                "The rule cannot be narrowed to a few event types (`evt.type`), so it runs on every event; Falco and Sysdig warn about the performance penalty."
            }
            FALCO_OUTPUT_SYNTAX => {
                "The output template does not format: a `%` at the end, a length with no field, or a token that is no field or transformer."
            }
            FALCO_NEWER_SYNTAX => {
                "Syntax that only recent libsinsp releases parse (operator modifiers, `join`, `concat`, `getopt`, transformer arguments); an older Falco or Sysdig agent refuses the rule."
            }
            FALCO_EXCEPTION => {
                "A rule exception Falco refuses: comparison operators, field and value counts, or a value the field's type cannot hold."
            }
            FALCO_UNKNOWN_EVENT => {
                "The event type is not in the driver's event table nor a syscall name; libsinsp refuses it."
            }
            FALCO_UNKNOWN_SOURCE => {
                "The event source is not one Falco or its published plugins define, so its fields are not checked."
            }
            SYSDIG_RULE_SHAPE => {
                "A Sysdig block is a new rule with a non-blank `condition`, or a tuning (`append_to_rule`) that appends a condition, exceptions, or both."
            }
            SYSDIG_TUNING_KEYS => {
                "A tuning (`append_to_rule`) inherits `output`, `priority`, `policies`, `source`, and `name` from the rule it tunes, so it must not set them."
            }
            SYSDIG_PRIORITY => {
                "`priority` is not one of Falco's eight priorities (or `INFO`), compared case-insensitively."
            }
            SYSDIG_SOURCE => "`source` is not an event source name (`[a-z][a-z0-9_]*`).",
            SYSDIG_EXCEPTION_SHAPE => {
                "An exception's fields, comps, and values do not have a shape Falco's rule loader accepts (`validate_exception_info`)."
            }
            SYSDIG_DEFINITION_NAME => {
                "A block macro or list name is not `[A-Za-z_][A-Za-z0-9_]*`, or is a Falco operator or keyword."
            }
            SYSDIG_DEFINITION_DUPLICATE => {
                "A name is defined more than once across the block's macros and lists."
            }
            SYSDIG_DEFINITION_ORDER => {
                "A block macro uses itself or a macro defined after it: Falco gives a macro no view of itself or later macros, and refuses it as an undefined macro."
            }
            SYSDIG_LIST_SELF_REFERENCE => {
                "A block list names itself: Falco keeps the name as a literal item, which on Sysdig resolves against a tenant list of that name, not this one."
            }
            SYSDIG_LIST_IN_VALUE => {
                "A block list name appears in an exception value where Falco's expansion would not produce a value list."
            }
            FALCO_UNKNOWN_RULE => {
                "A tuning (`append_to_rule`) names a rule the Falco default rules do not define: Falco refuses the append, and on Sysdig the tenant must have that rule."
            }
            FALCO_APPEND_CONDITION => {
                "A tuning's condition is appended to the tuned rule's condition and must start with `and` or `or`; a new rule's condition must not."
            }
            CQL_PARSE_ERROR => "The CrowdStrike Query Language (CQL) query does not parse.",
            CQL_UNKNOWN_FUNCTION => {
                "No CQL function has this name; function names are matched without regard to case."
            }
            CQL_REMOVED_FUNCTION => {
                "The CQL function was removed from LogScale and Next-Gen SIEM no longer runs it."
            }
            CQL_DEPRECATED_FUNCTION => "CrowdStrike's reference marks the CQL function deprecated.",
            CQL_UNKNOWN_PARAMETER => "The CQL function has no parameter with this name.",
            CQL_DUPLICATE_PARAMETER => "A CQL function parameter is given more than once.",
            CQL_UNNAMED_ARGUMENT => {
                "A CQL function gets an argument without a name that it cannot take: a second one, or one when every parameter needs its name."
            }
            CQL_MISSING_PARAMETER => "A CQL function call leaves out a required parameter.",
            CQL_PARAMETER_VALUE => {
                "A literal CQL argument is not one of the parameter's allowed values, or is outside its bounds."
            }
            CQL_REGEX_FLAG => "A CQL regex literal has a flag other than d, g, i, m or F.",
            CQL_STRING_ESCAPE => {
                "A CQL string has an escape LogScale does not translate; it keeps the backslash and the character."
            }
            CQL_FREE_TEXT_AFTER_AGGREGATE => {
                "A CQL free-text filter comes after the first aggregate function, which LogScale refuses since 1.190."
            }
            CQL_ASSIGNMENT_AS => {
                "A CQL assignment names the output field and the function's as= parameter names it again."
            }
            CQL_LINK_OUTSIDE_CORRELATE => {
                "The CQL link operator <=> appears outside the queries of correlate(), the only place it links fields."
            }
            CQL_UNKNOWN_EVENT => {
                "The #event_simpleName value is not a Falcon sensor event the engine knows."
            }
            CQL_CORRELATE_AGGREGATE => {
                "A Next-Gen SIEM correlation rule combines correlate() with another aggregate function, which CrowdStrike does not allow."
            }
            CQL_EVENT_FUNCTION_AFTER_AGGREGATE => {
                "A CQL eventSize(), eventInternals() or eventFieldCount() call comes after the first aggregate function, which LogScale refuses since 1.190."
            }
            CQL_CORRELATE_PLACEMENT => {
                "CQL correlate() stands where its reference forbids: after an aggregate or a source function, inside another function's arguments, or with an aggregate in its queries."
            }
            CQL_MATCH_GUARD => {
                "A CQL match guard is an aggregate function; a guard must be a filter."
            }
            CQL_REGEX_GROUP_UNDER_OR => {
                "A CQL regex with named groups is an operand of or, where LogScale extracts none of its fields."
            }
            YARA_PARSE_ERROR => "The YARA signature does not parse as libyara 4.5 reads it.",
            YARA_INCLUDE => {
                "A YARA signature uses an include directive, which no platform resolves: each API takes one text with no file system behind it."
            }
            YARA_SIGNATURE_ALIAS => {
                "A YARA signature is a YAML alias instead of text written out in its own block."
            }
            YARA_EMPTY_SIGNATURE => {
                "The YARA signature has no rule, or only private or global rules."
            }
            YARA_DUPLICATE_RULE => "Two YARA rules in one signature have the same name.",
            YARA_DUPLICATE_STRING => "Two strings of one YARA rule have the same identifier.",
            YARA_DUPLICATE_TAG => "A YARA rule repeats a tag.",
            YARA_UNDEFINED_STRING => {
                "A YARA condition names a string ($id, #id, @id, !id or $prefix*) that the rule does not define."
            }
            YARA_UNREFERENCED_STRING => {
                "A YARA string is never used in the condition, which libyara refuses unless the condition uses them."
            }
            YARA_UNDEFINED_IDENTIFIER => {
                "A YARA identifier is neither a rule defined earlier in the signature nor an imported module, or is used as libyara refuses: a module field called as a function, a module function named without a call, or a loop variable a loop already binds."
            }
            YARA_RULE_IDENTIFIER_CONFLICT => {
                "A YARA rule is named like a keyword, or matches a rule wildcard an earlier condition uses; a rule named like an imported module is yara_x_incompatible."
            }
            YARA_UNKNOWN_MODULE => "A YARA import names a module libyara does not ship.",
            YARA_MODULE_NOT_IMPORTED => {
                "A YARA module field or function is used without importing its module."
            }
            YARA_UNKNOWN_MODULE_MEMBER => {
                "The YARA module has no such field or function, or the function takes other arguments."
            }
            YARA_TYPE => "A YARA operator or function is applied to a value of the wrong type.",
            YARA_REGEXP => "A YARA regular expression is invalid.",
            YARA_HEX_STRING => {
                "A YARA hex string is invalid: an odd number of nibbles, a bad jump, or unbalanced alternatives."
            }
            YARA_STRING_MODIFIER => {
                "libyara refuses this combination of YARA string modifiers, or an xor or base64 argument is out of range."
            }
            YARA_NUMBER_OUT_OF_RANGE => {
                "A YARA integer, size suffix, jump bound or string index is outside the range libyara accepts."
            }
            YARA_X_INCOMPATIBLE => "libyara 4.5 compiles this YARA but YARA-X 1.x refuses it.",
            YARA_SLOW_PATTERN => {
                "libyara warns that this YARA string or loop may slow scanning down."
            }
            YARA_ENTRYPOINT_DEPRECATED => {
                "entrypoint is deprecated in libyara and refused by YARA-X; use pe.entry_point or elf.entry_point."
            }
            YARA_SUSPICIOUS_EXPRESSION => {
                "A YARA condition is invariant, unsatisfiable or not boolean, or compares an integer with a boolean."
            }
            YARA_MODULE_UNCONFIRMED => {
                "The YARA module is known but not confirmed on the platform's agents."
            }
            YARA_META_MISSING => {
                "A non-private YARA rule lacks a meta key the platform profile recommends."
            }
            HARFANGLAB_RULE_KIND => {
                "A HarfangLab block sets both sigma and yara; a block is one kind."
            }
            HARFANGLAB_YARA_FORM => {
                "A HarfangLab yara object sets signature together with decomposed keys (meta, strings, condition or imports)."
            }
            HARFANGLAB_YARA_SECTION_HEADER => {
                "A decomposed HarfangLab YARA fragment contains a strings:, condition: or rule header, which deploy writes itself."
            }
            HARFANGLAB_YARA_IMPORT => {
                "A decomposed HarfangLab YARA imports entry is not a module the YARA language knows."
            }
            HARFANGLAB_YARA_RULE_NAME => {
                "The YARA rule name deploy derives from the rule name is a YARA keyword or keeps a character other than an ASCII letter, digit or underscore."
            }
            HARFANGLAB_YARA_CONTEXT => {
                "A HarfangLab YARA rule's meta context is not a comma-joined list, without blanks, of file, memory, file.pe, file.elf and file.macho."
            }
            BITDEFENDER_YARA_ASCII => {
                "A Bitdefender YARA signature holds a character that is not ASCII."
            }
            BITDEFENDER_YARA_SIZE => {
                "A Bitdefender YARA signature is longer than 30,000 characters."
            }
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
    use super::word_start;

    /// #182: the character before the word may be wider than a byte.
    #[test]
    fn word_start_is_a_char_boundary_after_a_wide_character() {
        let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
        assert_eq!(word_start("a b", word), 2);
        assert_eq!(word_start("abc", word), 0);
        let text = "wehrE\u{59a}ndsWith";
        assert_eq!(&text[word_start(text, word)..], "ndsWith");
        let text = "x 日本name";
        assert_eq!(&text[word_start(text, word)..], "name");
        assert_eq!(word_start("😀", word), "😀".len());
    }
    use super::*;

    /// #180: a span that ends inside a multi-byte character gave a panic.
    #[test]
    fn an_offset_inside_a_character_counts_from_its_start() {
        let src = "a\\é日😀";
        for offset in 0..=src.len() + 2 {
            let position = offset_to_position(src, offset);
            assert_eq!(LineIndex::new(src).position(offset), position, "{offset}");
        }
        // Byte 3 is inside `é` (bytes 2..4): its column is `é`'s start, 2.
        assert_eq!(offset_to_position(src, 3), Position::new(0, 2));
        let _ = span_to_range(src, ByteSpan::new(1, 4));
    }

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
        assert_eq!(LanguageId::from_extension("falco"), Some(LanguageId::Falco));
        assert_eq!(LanguageId::parse("falco"), Some(LanguageId::Falco));
        assert_eq!(LanguageId::parse("cql"), Some(LanguageId::Cql));
        assert_eq!(LanguageId::parse("yara"), Some(LanguageId::Yara));
        assert_eq!(
            LanguageId::parse(LanguageId::Yara.as_str()),
            Some(LanguageId::Yara)
        );
        assert_eq!(LanguageId::from_extension("yar"), Some(LanguageId::Yara));
        assert_eq!(LanguageId::from_extension("yara"), Some(LanguageId::Yara));
        assert_eq!(LanguageId::parse("logscale"), Some(LanguageId::Cql));
        assert_eq!(LanguageId::from_extension("cql"), Some(LanguageId::Cql));
    }

    #[test]
    fn a_byte_order_mark_is_not_text() {
        let src = "\u{feff}a: é😀";
        assert_eq!(strip_bom(src), "a: é😀");
        assert_eq!(strip_bom("a: 1"), "a: 1");
        // Only one leading mark is a byte-order mark.
        assert_eq!(strip_bom("\u{feff}\u{feff}a"), "\u{feff}a");
        assert_eq!(strip_bom("a\u{feff}"), "a\u{feff}");
        assert_eq!(strip_bom_at(src, 4), ("a: é😀", 1));
        assert_eq!(strip_bom_at(src, 1), ("a: é😀", 0));
        assert_eq!(strip_bom_at("a: 1", 2), ("a: 1", 2));
        let stripped = strip_bom(src);
        assert_eq!(
            offset_to_position(stripped, stripped.len()),
            Position::new(0, 6)
        );
    }

    #[test]
    fn offset_to_position_handles_newlines() {
        let src = "abc\néé";
        let pos = offset_to_position(src, src.len());
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 2);
    }

    /// Diagnostic ranges leave the process as UTF-16 code units. `é` is one
    /// unit (two UTF-8 bytes); an emoji outside the BMP is two units.
    #[test]
    fn offset_to_position_counts_utf16_for_accent_and_emoji() {
        let src = "aé😀";
        assert_eq!(offset_to_position(src, 0), Position::new(0, 0));
        assert_eq!(offset_to_position(src, 1), Position::new(0, 1));
        assert_eq!(offset_to_position(src, 1 + "é".len()), Position::new(0, 2));
        assert_eq!(offset_to_position(src, src.len()), Position::new(0, 4));

        let emoji_start = 1 + "é".len();
        let range = span_to_range(src, ByteSpan::new(emoji_start, src.len()));
        assert_eq!(range.start, Position::new(0, 2));
        assert_eq!(range.end, Position::new(0, 4));
        assert_eq!(range.end.character - range.start.character, 2);
    }

    #[test]
    fn offset_to_position_emoji_on_the_next_line() {
        let src = "a\n😀b";
        let after_emoji = "a\n😀".len();
        assert_eq!(offset_to_position(src, after_emoji), Position::new(1, 2));
        assert_eq!(offset_to_position(src, src.len()), Position::new(1, 3));
    }

    #[test]
    fn range_contains_inclusive_end() {
        let range = Range::new(Position::new(0, 1), Position::new(0, 4));
        assert!(range.contains(Position::new(0, 1)));
        assert!(range.contains(Position::new(0, 4)));
        assert!(!range.contains(Position::new(0, 0)));
    }
}
