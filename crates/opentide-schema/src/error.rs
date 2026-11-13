//! Typed schema errors and the stable codes they map to (ADR 0001, "Errors").
//!
//! Every error the model reports is a [`SchemaError`]: a [`ErrorKind`], the
//! path of the value it is about and a message. The kind names Pydantic's
//! error type ([`ErrorKind::pydantic_type`]), so a recording of the oracle and
//! a Rust result compare kind for kind, and maps to the diagnostic code the CLI
//! prints today ([`SchemaError::code`]). No new code is minted here: the codes
//! are the ones `src/opentide/validation` emits at the frozen tag.

use std::collections::BTreeMap;
use std::fmt;

use crate::node::Span;

/// The CLI's codes for schema errors. `schema_validation` is the engine's
/// already ([`opentide_core::codes::SCHEMA_VALIDATION`]). The others are
/// created by the Python CLI; the language server only relays three of them
/// from the host's configuration checker. `opentide_core::codes::ALL` lists
/// the codes the engine itself emits, each with a description
/// (`codes::describe`), so each of the others moves there with the Rust port
/// that emits it (UC-2.2, #817; UC-1.5, #811).
pub mod codes {
    pub use opentide_core::codes::SCHEMA_VALIDATION;
    /// An object file that is not YAML (`loading/`).
    pub const YAML_PARSE: &str = "yaml_parse";
    /// A configuration file that is not TOML (`validation/configuration.py`).
    pub const CONFIG_PARSE: &str = "config_parse";
    /// A required configuration key is missing (`validation/configuration.py`).
    pub const MISSING_FIELD: &str = "missing_field";
    /// A configuration key the model does not declare (`validation/configuration.py`).
    pub const UNKNOWN_KEY: &str = "unknown_key";
    /// An object with no `metadata.schema` (`loading/object_loader.py`
    /// `SchemaMissingError.code`).
    pub const SCHEMA_MISSING: &str = "schema_missing";
}

/// Where a model is read from. The same Pydantic error maps to a different
/// diagnostic code for an object file than for a configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Surface {
    /// A Tide object (`objects/**/*.yaml`): `validation/errors.py`
    /// (`issues_from_pydantic`) reports every Pydantic error as
    /// `schema_validation`.
    Object,
    /// A configuration file (`configurations/*.toml`):
    /// `validation/configuration.py` maps `missing` to `missing_field`,
    /// `extra_forbidden` to `unknown_key`, and every other error to
    /// `schema_validation`.
    Configuration,
}

/// The kind of a schema error, one per Pydantic error type the model raises.
///
/// The structural conversion (UC-1.2, #808, [`crate::from_node`]) reports
/// `Missing`, `UnknownKey`, and `InvalidType` / `InvalidValue` with Pydantic's
/// type (`string_type`, `int_parsing`, `model_type`, `invalid_key`,
/// `literal_error`, `enum`, `vocab_list_type`, …), and `Limit` when it stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The document does not parse: `yaml_parse` for an object file,
    /// `config_parse` for a configuration file.
    Syntax,
    /// A required key is absent. Pydantic `missing`.
    Missing,
    /// A key the model does not declare, on a closed model
    /// (`extra="forbid"`). Pydantic `extra_forbidden`.
    UnknownKey,
    /// A value of the wrong type, with Pydantic's exact type: `string_type`,
    /// `int_type`, `list_type`, `model_type`, …
    InvalidType(&'static str),
    /// A value of the right type that a constraint or a custom validator
    /// rejects, with Pydantic's exact type: `value_error`, `literal_error`,
    /// `greater_than_equal`, …
    InvalidValue(&'static str),
    /// A platform block's constraint, typed by its code
    /// (`graylog_schedule`): one finding of a block's named check
    /// ([`crate::objects::platform::NamedCheck`]), at the path its
    /// specification fixes. The oracle raises it as a `PydanticCustomError`
    /// whose type is the code, and `validate` reports it under that code.
    Constraint(&'static str),
    /// The conversion stopped: the document produced more work than
    /// [`crate::from_node::BUDGET`] allows (a tree of aliases nested to
    /// billions of nodes). Not a Pydantic error; the oracle would keep going.
    Limit,
}

impl ErrorKind {
    /// Pydantic's error type for this kind, as `ValidationError.errors()`
    /// reports it in `type` (the differential runner compares on it), or
    /// `None` for [`ErrorKind::Syntax`]: the loader reports that before
    /// Pydantic runs.
    pub const fn pydantic_type(self) -> Option<&'static str> {
        match self {
            Self::Syntax | Self::Limit => None,
            Self::Missing => Some("missing"),
            Self::UnknownKey => Some("extra_forbidden"),
            Self::InvalidType(pydantic)
            | Self::InvalidValue(pydantic)
            | Self::Constraint(pydantic) => Some(pydantic),
        }
    }
}

/// One step of the path to the value an error is about: a key or a list
/// index, as Pydantic's `loc` holds them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathSegment {
    /// A mapping key (the serialised name, `schema`, not `schema_id`).
    Key(String),
    /// A position in a sequence, from 0.
    Index(usize),
}

impl fmt::Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(key) => f.write_str(key),
            Self::Index(index) => write!(f, "{index}"),
        }
    }
}

/// A schema error: what is wrong, where, and the message Pydantic would print.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {message}", display_path(path))]
pub struct SchemaError {
    /// What is wrong.
    pub kind: ErrorKind,
    /// The path from the document root to the value, empty for the document.
    pub path: Vec<PathSegment>,
    /// The message, in Pydantic's wording where Pydantic reports the error.
    pub message: String,
    /// Where the CLI points for it (`SourceFiles.span`), when the error came
    /// from a document: [`crate::node::Document::span`].
    pub span: Option<Span>,
    /// The finding's `yaml_line` (0-based, `attach_yaml_lines`):
    /// [`crate::node::Document::yaml_line`].
    pub yaml_line: Option<usize>,
    /// Pydantic's `input`, when it is a string (`validation/errors.py` reads
    /// only string inputs: references, vocabulary values).
    pub input: Option<String>,
    /// Pydantic's `ctx`, each value as `str()` gives it (`class_name`,
    /// `expected`, `field`, `value`, `error`).
    pub context: BTreeMap<String, String>,
}

impl SchemaError {
    /// An error of `kind` at `path`.
    pub fn new(kind: ErrorKind, path: Vec<PathSegment>, message: impl Into<String>) -> Self {
        Self {
            kind,
            path,
            message: message.into(),
            span: None,
            yaml_line: None,
            input: None,
            context: BTreeMap::new(),
        }
    }

    /// The diagnostic code the CLI prints for this error on `surface`: one of
    /// `yaml_parse`, `config_parse`, `schema_validation`, `missing_field` and
    /// `unknown_key`, as `loading/`, `validation/errors.py` and
    /// `validation/configuration.py` choose them, or a platform constraint's
    /// own code ([`ErrorKind::Constraint`]).
    pub const fn code(&self, surface: Surface) -> &'static str {
        match (self.kind, surface) {
            (ErrorKind::Syntax, Surface::Object) => codes::YAML_PARSE,
            (ErrorKind::Syntax, Surface::Configuration) => codes::CONFIG_PARSE,
            (ErrorKind::Missing, Surface::Configuration) => codes::MISSING_FIELD,
            (ErrorKind::UnknownKey, Surface::Configuration) => codes::UNKNOWN_KEY,
            (ErrorKind::Constraint(code), _) => code,
            _ => codes::SCHEMA_VALIDATION,
        }
    }

    /// The path as the CLI's `field_path` tuple: keys and indexes as strings.
    pub fn field_path(&self) -> Vec<String> {
        self.path.iter().map(ToString::to_string).collect()
    }
}

fn display_path(path: &[PathSegment]) -> String {
    if path.is_empty() {
        return "<document>".to_owned();
    }
    path.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(kind: ErrorKind) -> SchemaError {
        SchemaError::new(
            kind,
            vec![PathSegment::Key("examples".into()), PathSegment::Index(0)],
            "m",
        )
    }

    #[test]
    fn object_errors_are_schema_validation_except_syntax() {
        assert_eq!(at(ErrorKind::Syntax).code(Surface::Object), "yaml_parse");
        for kind in [
            ErrorKind::Missing,
            ErrorKind::UnknownKey,
            ErrorKind::InvalidType("string_type"),
            ErrorKind::InvalidValue("value_error"),
        ] {
            assert_eq!(at(kind).code(Surface::Object), "schema_validation");
        }
    }

    #[test]
    fn a_constraint_is_reported_under_its_code() {
        let error = at(ErrorKind::Constraint("graylog_schedule"));
        assert_eq!(error.code(Surface::Object), "graylog_schedule");
        assert_eq!(error.code(Surface::Configuration), "graylog_schedule");
        assert_eq!(
            ErrorKind::Constraint("graylog_schedule").pydantic_type(),
            Some("graylog_schedule")
        );
    }

    #[test]
    fn configuration_errors_follow_configuration_py() {
        let codes = [
            (ErrorKind::Syntax, "config_parse"),
            (ErrorKind::Missing, "missing_field"),
            (ErrorKind::UnknownKey, "unknown_key"),
            (ErrorKind::InvalidType("int_type"), "schema_validation"),
            (
                ErrorKind::InvalidValue("literal_error"),
                "schema_validation",
            ),
        ];
        for (kind, code) in codes {
            assert_eq!(at(kind).code(Surface::Configuration), code, "{kind:?}");
        }
    }

    #[test]
    fn pydantic_types_are_pydantics() {
        assert_eq!(ErrorKind::Syntax.pydantic_type(), None);
        assert_eq!(ErrorKind::Limit.pydantic_type(), None);
        assert_eq!(ErrorKind::Missing.pydantic_type(), Some("missing"));
        assert_eq!(
            ErrorKind::UnknownKey.pydantic_type(),
            Some("extra_forbidden")
        );
        assert_eq!(
            ErrorKind::InvalidType("list_type").pydantic_type(),
            Some("list_type")
        );
        assert_eq!(
            ErrorKind::InvalidValue("value_error").pydantic_type(),
            Some("value_error")
        );
    }

    #[test]
    fn field_path_and_display() {
        let error = at(ErrorKind::Missing);
        assert_eq!(error.field_path(), ["examples", "0"]);
        assert_eq!(error.to_string(), "examples.0: m");
        let root = SchemaError::new(ErrorKind::Syntax, vec![], "bad");
        assert_eq!(root.to_string(), "<document>: bad");
    }
}
