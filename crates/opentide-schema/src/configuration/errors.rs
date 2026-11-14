//! A model's errors as configuration findings (`model_errors` and
//! `describe_error`).

use crate::error::SchemaError;

/// One error, placed in the input: the key path (indexes as decimal strings),
/// the error type and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError {
    /// The key path.
    pub path: Vec<String>,
    /// The error type (`missing`, `extra_forbidden`, `string_type`, ...).
    pub kind: &'static str,
    /// The message.
    pub message: String,
}

/// `(key path, error type, message)` per error of `errors`, in the order the
/// conversion reported them (the document's).
pub fn model_errors(errors: &[SchemaError]) -> Vec<ModelError> {
    errors
        .iter()
        .map(|error| ModelError {
            path: error.field_path(),
            kind: error.kind.pydantic_type().unwrap_or(""),
            message: error.message.clone(),
        })
        .collect()
}

/// The message a configuration error shows: plain words for a key,
/// Pydantic's otherwise.
pub fn describe_error(kind: &str, message: &str) -> String {
    match kind {
        "extra_forbidden" => "unknown key".to_owned(),
        "missing" => "required key is missing".to_owned(),
        _ if message.is_empty() => "invalid value".to_owned(),
        _ => message.to_owned(),
    }
}

/// The finding code of an error type: `missing_field`, `unknown_key`, or
/// `schema_validation`.
pub fn code_of(kind: &str) -> &'static str {
    match kind {
        "missing" => super::codes::MISSING_FIELD,
        "extra_forbidden" => super::codes::UNKNOWN_KEY,
        _ => super::codes::SCHEMA_VALIDATION,
    }
}
