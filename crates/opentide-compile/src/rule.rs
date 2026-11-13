//! A rule as the compilers read it: its document as ordered JSON, with the
//! few fields every compiler needs, and the error a compiler gives for a rule
//! it cannot compile (`deployment/preview.py` `compile_diagnostic`).

use std::fmt;

use crate::json::Json;

/// A rule a compiler reads.
#[derive(Debug, Clone)]
pub struct Rule {
    /// The document.
    pub data: Json,
    /// The document as read, for a compiler that needs a scalar as written
    /// (Falco reads list items and exception values as text).
    pub node: std::sync::Arc<opentide_schema::node::Node>,
    /// `metadata.uuid`, written as the oracle's `UUID` writes it.
    pub uuid: String,
    /// `name`.
    pub name: String,
    /// The file it was read from, when it was read from one.
    pub file: Option<String>,
}

impl Rule {
    /// The rule `root` holds.
    pub fn new(root: &opentide_schema::node::Node, file: Option<String>) -> Self {
        let data = Json::from_node(root);
        let uuid = data
            .get("metadata")
            .and_then(|metadata| metadata.get("uuid"))
            .map(|uuid| match uuid {
                Json::Str(text) => canonical_uuid(text),
                other => other.to_compact(),
            })
            .unwrap_or_default();
        let name = data
            .get("name")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_owned();
        Self {
            data,
            node: std::sync::Arc::new(root.clone()),
            uuid,
            name,
            file,
        }
    }

    /// The platform block of `platform`, if the rule has one that is set.
    pub fn block(&self, platform: &str) -> Option<&Json> {
        self.data
            .get("configurations")
            .and_then(|configurations| configurations.get(platform))
            .filter(|block| !block.is_null())
    }

    /// `response`, unless absent or empty (an empty `response:` reads as `null`).
    pub fn response(&self) -> Option<&Json> {
        self.data
            .get("response")
            .filter(|response| !response.is_null())
    }

    /// `response.alert_severity`, or its default (`alert_severity`).
    pub fn alert_severity(&self) -> &str {
        self.response()
            .and_then(|response| response.get("alert_severity"))
            .and_then(Json::as_str)
            .unwrap_or(opentide_schema::objects::response::DEFAULT_ALERT_SEVERITY)
    }

    /// `description`.
    pub fn description(&self) -> &str {
        self.data
            .get("description")
            .and_then(Json::as_str)
            .unwrap_or_default()
    }
}

/// A UUID as Python's `uuid.UUID` writes it: lowercase, hyphenated. Text that
/// is not a UUID stays as written.
pub fn canonical_uuid(text: &str) -> String {
    let trimmed = text.trim();
    let bare = trimmed
        .strip_prefix("urn:uuid:")
        .unwrap_or(trimmed)
        .trim_start_matches('{')
        .trim_end_matches('}');
    let hex: String = bare.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return text.to_owned();
    }
    let hex = hex.to_ascii_lowercase();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The codes a compile failure carries, each with its `opentide explain` page
/// (`src/opentide/data/diagnostics/compile_*.md`).
pub mod codes {
    /// A setting the platform needs is missing.
    pub const COMPILE_MISSING_FIELD: &str = "compile_missing_field";
    /// A setting has a value the platform cannot take.
    pub const COMPILE_INVALID_VALUE: &str = "compile_invalid_value";
    /// A block the rule needs is empty.
    pub const COMPILE_EMPTY_BLOCK: &str = "compile_empty_block";
    /// The rule's data does not hold together (a duration that cannot be read).
    pub const COMPILE_INVALID_RULE: &str = "compile_invalid_rule";
    /// Any other failure.
    pub const COMPILE_FAILED: &str = "compile_failed";
}

/// A rule a platform cannot compile: a stable code, the reason alone, and
/// what to do (`code`, `reason`, `hint`), with the field at fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    /// `compile_missing_field`, `compile_invalid_value`, `compile_empty_block`,
    /// `compile_invalid_rule` or `compile_failed`.
    pub code: &'static str,
    /// The reason, in the reader's words.
    pub reason: String,
    /// What to do, when known.
    pub hint: Option<String>,
    /// The key at fault, from the rule's root.
    pub field: Vec<String>,
}

impl CompileError {
    /// An error with its code, reason and hint.
    pub fn new(code: &'static str, reason: impl Into<String>, hint: Option<&str>) -> Self {
        Self {
            code,
            reason: reason.into(),
            hint: hint.map(str::to_owned),
            field: Vec::new(),
        }
    }

    /// The same error, at `field`.
    pub fn at(mut self, field: &[&str]) -> Self {
        self.field = field.iter().map(|part| (*part).to_owned()).collect();
        self
    }

    /// A rule the data model refuses (`TideRuleDataModelErrors` without a code).
    pub fn invalid_rule(text: impl Into<String>) -> Self {
        Self::new(codes::COMPILE_INVALID_RULE, text, None)
    }

    /// Any other failure, described for `platform` (its display name).
    pub fn failed(platform: &str, text: &str) -> Self {
        let text = text.trim();
        Self::new(
            codes::COMPILE_FAILED,
            format!(
                "{platform} cannot compile this rule: {}",
                if text.is_empty() {
                    "no detail given"
                } else {
                    text
                }
            ),
            None,
        )
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.hint {
            Some(hint) => write!(f, "{}; {hint}", self.reason),
            None => f.write_str(&self.reason),
        }
    }
}

impl std::error::Error for CompileError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_written_as_python_writes_them() {
        assert_eq!(
            canonical_uuid("0000000A-0000-4000-8003-00000000000B"),
            "0000000a-0000-4000-8003-00000000000b"
        );
        assert_eq!(
            canonical_uuid("{0000000a00004000800300000000000b}"),
            "0000000a-0000-4000-8003-00000000000b"
        );
        assert_eq!(canonical_uuid("not-a-uuid"), "not-a-uuid");
    }

    #[test]
    fn errors_read_with_their_hint() {
        let error = CompileError::new("compile_missing_field", "x is missing", Some("set x"));
        assert_eq!(error.to_string(), "x is missing; set x");
        assert_eq!(
            CompileError::failed("Sentinel", " ").reason,
            "Sentinel cannot compile this rule: no detail given"
        );
    }
}
