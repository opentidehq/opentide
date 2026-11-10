//! The one finding type (UC-2.2, #817; plan §3 invariant 3): what `validate`,
//! the SDK, MCP and the language server report, serialised exactly as an
//! entry of `validate --json`'s `report.issues` and `report.warnings`.
//!
//! The JSON keys, in order: `code`, `severity`, `object_uuid`,
//! `object_type`, `file_path`, `yaml_line`, `field_path`, `message`,
//! `suggestion`, `context` (the validation issue, `validation/issues.py`),
//! then `path`, `line`, `column`, `end_line`, `end_column`, `help`, `fix`,
//! `explain` (the place and the step, `cli/ui/diagnostics.py` `annotate`).
//!
//! Positions are 1-based; columns count Unicode code points; a span runs
//! from (`line`, `column`) up to (`end_line`, `end_column`), `end_column`
//! exclusive and on `end_line` (`docs/cli/diagnostics.md`). `yaml_line` is
//! the 0-based line of the value as the oracle's JSON writes it (a block's
//! first child), kept for consumers that read it.
//!
//! What only the code frames read (the label under the underline, further
//! notes such as `also: <file>:<line>:<column>` for a duplicate UUID) is
//! carried beside the JSON fields and never serialised: the JSON stays the
//! contract it is today.

use std::fmt;
use std::path::PathBuf;

use indexmap::IndexMap;
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

/// How much a finding matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    /// Fails the run.
    Error,
    /// Fails it under `--strict`, unless its code is exempt.
    Warning,
}

impl Severity {
    /// `error` or `warning`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A value of a finding's `context`: JSON whose mappings keep the order they
/// were written in (`serde_json::Value` sorts them unless a feature that
/// would change every crate's maps is on).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContextValue {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(serde_json::Number),
    /// A string.
    String(String),
    /// A list.
    List(Vec<ContextValue>),
    /// A mapping, in order.
    Map(IndexMap<String, ContextValue>),
}

impl ContextValue {
    /// The string, when this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }
}

impl From<&str> for ContextValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for ContextValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<bool> for ContextValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<Vec<String>> for ContextValue {
    fn from(value: Vec<String>) -> Self {
        Self::List(value.into_iter().map(Self::String).collect())
    }
}

impl From<serde_json::Value> for ContextValue {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(flag) => Self::Bool(flag),
            serde_json::Value::Number(number) => Self::Number(number),
            serde_json::Value::String(text) => Self::String(text),
            serde_json::Value::Array(items) => {
                Self::List(items.into_iter().map(Self::from).collect())
            }
            serde_json::Value::Object(map) => Self::Map(
                map.into_iter()
                    .map(|(key, value)| (key, Self::from(value)))
                    .collect(),
            ),
        }
    }
}

/// A finding's `context`, in the order its keys were set.
pub type Context = IndexMap<String, ContextValue>;

/// Replace the text from (`line`, `column`) up to (`end_line`, `end_column`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextEdit {
    /// 1-based.
    pub line: usize,
    /// 1-based, code points.
    pub column: usize,
    /// The line `end_column` is on.
    pub end_line: usize,
    /// Exclusive, on `end_line`.
    pub end_column: usize,
    /// The new text.
    pub replacement: String,
}

/// Edits that resolve a finding; `safe` ones `validate --fix` applies
/// without review.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fix {
    /// Whether the fix is certainly what the author meant.
    pub safe: bool,
    /// The edits, in order.
    pub edits: Vec<TextEdit>,
}

/// One finding.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Diagnostic {
    /// The stable code, with its `opentide explain` page.
    pub code: String,
    /// Its severity.
    pub severity: Severity,
    /// The object the finding is about; empty when none is.
    #[serde(default)]
    pub object_uuid: String,
    /// The object's family (`rule`), `configuration`, or empty.
    #[serde(default)]
    pub object_type: String,
    /// The file, absolute, when one is at fault.
    #[serde(default)]
    pub file_path: Option<PathBuf>,
    /// The value's line from 0, as the oracle's JSON writes it.
    #[serde(default)]
    pub yaml_line: Option<usize>,
    /// The field at fault, keys and list indexes as strings.
    #[serde(default)]
    pub field_path: Vec<String>,
    /// One sentence.
    pub message: String,
    /// What the value most likely meant, or the step to take.
    #[serde(default)]
    pub suggestion: Option<String>,
    /// Facts a consumer may read (`value`, `vocab`, `original`, ...).
    #[serde(default)]
    pub context: Context,
    /// [`Self::file_path`] relative to the workspace, `/`-separated.
    #[serde(default)]
    pub path: Option<String>,
    /// 1-based.
    #[serde(default)]
    pub line: Option<usize>,
    /// 1-based, code points.
    #[serde(default)]
    pub column: Option<usize>,
    /// The line `end_column` is on.
    #[serde(default)]
    pub end_line: Option<usize>,
    /// Exclusive, on `end_line`.
    #[serde(default)]
    pub end_column: Option<usize>,
    /// The step to take.
    #[serde(default)]
    pub help: Option<String>,
    /// Edits that resolve it.
    #[serde(default)]
    pub fix: Option<Fix>,
    /// A few words under the frame's underline (`not in tlp::1.0`); not in
    /// the JSON.
    #[serde(skip)]
    pub label: Option<String>,
    /// Further `(label, text)` lines of the frame (`also`, `expected`); not
    /// in the JSON.
    #[serde(skip)]
    pub notes: Vec<(String, String)>,
}

impl Diagnostic {
    /// A finding with no object, file or place.
    pub fn new(code: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity,
            object_uuid: String::new(),
            object_type: String::new(),
            file_path: None,
            yaml_line: None,
            field_path: Vec::new(),
            message: message.into(),
            suggestion: None,
            context: Context::new(),
            path: None,
            line: None,
            column: None,
            end_line: None,
            end_column: None,
            help: None,
            fix: None,
            label: None,
            notes: Vec::new(),
        }
    }

    /// An error.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Error, message)
    }

    /// A warning.
    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Warning, message)
    }

    /// The finding about object `uuid` of `family`.
    #[must_use]
    pub fn object(mut self, uuid: impl Into<String>, family: impl Into<String>) -> Self {
        self.object_uuid = uuid.into();
        self.object_type = family.into();
        self
    }

    /// The finding in `file`.
    #[must_use]
    pub fn file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file_path = Some(file.into());
        self
    }

    /// The finding at `field_path`.
    #[must_use]
    pub fn at<S: Into<String>>(mut self, field_path: impl IntoIterator<Item = S>) -> Self {
        self.field_path = field_path.into_iter().map(Into::into).collect();
        self
    }

    /// The finding with `suggestion`.
    #[must_use]
    pub fn suggest(mut self, suggestion: Option<String>) -> Self {
        self.suggestion = suggestion;
        self
    }

    /// The finding with `key` set in its context.
    #[must_use]
    pub fn with(mut self, key: &str, value: impl Into<ContextValue>) -> Self {
        self.context.insert(key.to_owned(), value.into());
        self
    }

    /// `opentide explain <code>`.
    pub fn explain(&self) -> String {
        format!("opentide explain {}", self.code)
    }

    /// Whether this is an error.
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }

    /// `context.value`, when it is a string: the value the finding is about.
    pub fn value(&self) -> Option<&str> {
        self.context.get("value").and_then(ContextValue::as_str)
    }
}

impl Serialize for Diagnostic {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("Diagnostic", 18)?;
        out.serialize_field("code", &self.code)?;
        out.serialize_field("severity", &self.severity)?;
        out.serialize_field("object_uuid", &self.object_uuid)?;
        out.serialize_field("object_type", &self.object_type)?;
        out.serialize_field(
            "file_path",
            &self
                .file_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
        )?;
        out.serialize_field("yaml_line", &self.yaml_line)?;
        out.serialize_field("field_path", &self.field_path)?;
        out.serialize_field("message", &self.message)?;
        out.serialize_field("suggestion", &self.suggestion)?;
        out.serialize_field("context", &self.context)?;
        out.serialize_field("path", &self.path)?;
        out.serialize_field("line", &self.line)?;
        out.serialize_field("column", &self.column)?;
        out.serialize_field("end_line", &self.end_line)?;
        out.serialize_field("end_column", &self.end_column)?;
        out.serialize_field("help", &self.help)?;
        out.serialize_field("fix", &self.fix)?;
        out.serialize_field("explain", &self.explain())?;
        out.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_written_in_the_cli_order_with_explain_from_the_code() {
        let diagnostic = Diagnostic::error("invalid_uuid", "UUID 'x' is not a valid UUIDv4")
            .object("x", "rule")
            .at(["metadata", "uuid"])
            .with("name", "A rule");
        let text = serde_json::to_string(&diagnostic).unwrap();
        assert_eq!(
            text,
            r#"{"code":"invalid_uuid","severity":"error","object_uuid":"x","object_type":"rule","file_path":null,"yaml_line":null,"field_path":["metadata","uuid"],"message":"UUID 'x' is not a valid UUIDv4","suggestion":null,"context":{"name":"A rule"},"path":null,"line":null,"column":null,"end_line":null,"end_column":null,"help":null,"fix":null,"explain":"opentide explain invalid_uuid"}"#
        );
    }

    #[test]
    fn context_mappings_keep_their_order() {
        let mut original = IndexMap::new();
        original.insert("name".to_owned(), ContextValue::from("b"));
        original.insert("file_name".to_owned(), ContextValue::from("a"));
        let diagnostic = Diagnostic::error("duplicate_id", "m")
            .with("value", "u")
            .with("original", ContextValue::Map(original));
        let text = serde_json::to_string(&diagnostic.context).unwrap();
        assert_eq!(
            text,
            r#"{"value":"u","original":{"name":"b","file_name":"a"}}"#
        );
        let back: Context = serde_json::from_str(&text).unwrap();
        assert_eq!(back, diagnostic.context);
    }

    #[test]
    fn a_fix_is_written_with_its_edits() {
        let mut diagnostic = Diagnostic::warning("vocab_unknown", "m");
        diagnostic.fix = Some(Fix {
            safe: true,
            edits: vec![TextEdit {
                line: 3,
                column: 6,
                end_line: 3,
                end_column: 11,
                replacement: "amber".to_owned(),
            }],
        });
        let value: serde_json::Value = serde_json::to_value(&diagnostic).unwrap();
        assert_eq!(
            value["fix"],
            serde_json::json!({"safe": true, "edits": [{"line": 3, "column": 6, "end_line": 3, "end_column": 11, "replacement": "amber"}]})
        );
        assert_eq!(value["severity"], "warning");
    }
}
