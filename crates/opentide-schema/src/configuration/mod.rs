//! The configuration TOML files under `.opentide/configurations/` (UC-1.5,
//! #811): their models, their layering and their checks.
//!
//! - [`toml`]: a file read with the `toml_edit` crate (TOML 1.0) into the
//!   same node tree an object file is read into ([`crate::node`]), every node
//!   with its position;
//! - [`models`]: one model per file, the oracle's Pydantic models field for
//!   field, converted with `#[derive(FromNode)]` so every error of a file is
//!   reported at once, with Pydantic's error type and message;
//! - [`resolve`]: the layering of `core/files.py` `resolve_configurations`
//!   (bundled defaults, then the workspace, then the parent instance; tables
//!   merge, every other value replaces), done once per run;
//! - [`checks`]: `validation/configuration.py`: the findings of one file, as
//!   an editor buffer holds it ([`checks::text_issues`],
//!   [`checks::buffer_issues`]), and of a resolved workspace
//!   ([`checks::workspace_issues`]);
//! - [`sharing`]: `sharing.toml`, merged block by block (`sharing/config.py`);
//! - [`lint`]: `lint.toml`, checked as `core/lint_config.py` checks it.
//!
//! `$NAME` placeholders stay strings: resolving them is the connectors' work
//! (UC-4.1, #829).
//!
//! The module is I/O-free: a host reads the files and hands their text over.
//! The bundled defaults are compiled in ([`bundled`]).

pub mod bundled;
pub mod checks;
pub mod errors;
pub mod lint;
pub mod merge;
pub mod models;
pub mod repr;
pub mod resolve;
pub mod sharing;
pub mod toml;
pub mod types;

use std::collections::BTreeMap;

pub use opentide_core::Severity;
use serde::Serialize;

/// The codes configuration findings carry, as `validation/configuration.py`
/// and `sharing/config.py` emit them.
pub mod codes {
    pub use crate::error::codes::{CONFIG_PARSE, MISSING_FIELD, SCHEMA_VALIDATION, UNKNOWN_KEY};
    /// `promotion.promotion_target` names no `[[statuses]]` entry.
    pub const PROMOTION_TARGET_UNKNOWN: &str = "promotion_target_unknown";
    /// A log source or detector names an asset `[[assets]]` does not declare.
    pub const ASSET_UNKNOWN: &str = "asset_unknown";
    /// A `.toml` file opentide does not read.
    pub const NOT_A_CONFIGURATION_FILE: &str = "not_a_configuration_file";
    /// A file or folder opentide no longer reads (`global.toml`, `systems/`).
    pub const RETIRED_CONFIGURATION_FILE: &str = "retired_configuration_file";
    /// `configurations/sharing/` instead of one `sharing.toml`.
    pub const SHARING_DIRECTORY: &str = "sharing_directory";
    /// A `sharing.toml` top-level array of another connector.
    pub const UNKNOWN_CONNECTOR: &str = "unknown_connector";
    /// Two blocks of one `sharing.toml` layer share a name.
    pub const DUPLICATE_NAME: &str = "duplicate_name";
    /// A `[[misp]]` block name that is not 1 to 64 of `[a-z0-9_-]`.
    pub const NAME_INVALID: &str = "name_invalid";
    /// A `[[misp]]` url that is not http(s).
    pub const URL_INVALID: &str = "url_invalid";
    /// A `[[misp]]` `max_tlp` that is not a tlp name.
    pub const MAX_TLP_UNKNOWN: &str = "max_tlp_unknown";
    /// A `[[misp]]` `organisation_uuid` that is not a hex UUID.
    pub const ORGANISATION_UUID_INVALID: &str = "organisation_uuid_invalid";
    /// A `[[misp]]` `object_types` entry that is not an object family.
    pub const OBJECT_TYPE_UNKNOWN: &str = "object_type_unknown";
    /// A `[[misp]]` `rule_statuses` entry that is not a `deployment.toml` status.
    pub const RULE_STATUS_UNKNOWN: &str = "rule_status_unknown";
    /// A `[[misp]]` `api_key` written as a literal instead of `${NAME}`.
    pub const API_KEY_LITERAL: &str = "api_key_literal";
    /// Any other invalid `[[misp]]` value.
    pub const INVALID_VALUE: &str = "invalid_value";
}

/// One configuration finding: `ValidationIssue` with `object_type`
/// `configuration`, as the oracle builds it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// The diagnostic code ([`codes`]).
    pub code: String,
    /// `error` or `warning`.
    pub severity: Severity,
    /// The key path in the file (or, for a workspace finding, in the merged
    /// document); list indexes as decimal strings. Empty for the whole file.
    pub field_path: Vec<String>,
    /// What is wrong. Never repeats a value: tenant `setup` tables hold
    /// credentials.
    pub message: String,
    /// The file, when the finding names one.
    pub file_path: Option<String>,
    /// Extra facts (`file`, `value`, `integration`, `block`, `layer`, ...).
    pub context: BTreeMap<String, serde_json::Value>,
}

impl Finding {
    /// A finding with no context.
    pub fn new(
        code: &str,
        severity: Severity,
        field_path: Vec<String>,
        message: impl Into<String>,
        file_path: Option<&str>,
    ) -> Self {
        Self {
            code: code.to_owned(),
            severity,
            field_path,
            message: message.into(),
            file_path: file_path.map(str::to_owned),
            context: BTreeMap::new(),
        }
    }

    /// The finding with `key` set in its context.
    #[must_use]
    pub fn with(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.context.insert(key.to_owned(), value.into());
        self
    }
}
