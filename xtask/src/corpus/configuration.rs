//! `corpus faults --check --engine rust --only configuration` (UC-1.5,
//! #811): the fault kinds whose findings are about configuration files,
//! checked against the oracle finding for finding (code, severity, field
//! path, message), or, when resolution stops the run, the failure's code
//! and message.
//!
//! The Rust engine's `validate` comes with UC-2.x. Until then this runner
//! resolves each fault workspace's configuration with
//! `opentide_schema::configuration::resolve` and reports what `validate`
//! reports for it: `checks::workspace_issues` (the `configuration` check), or
//! `checks::sharing_config_issues` for `validate --check sharing-config`.
//!
//! This module computes; [`super::cli`] writes the workspaces, reads their
//! folders and runs the oracle.

use opentide_schema::configuration::Finding;
use opentide_schema::configuration::checks;
use opentide_schema::configuration::resolve::{Folder, Instance, ResolveError, resolve};
use serde_json::{Value as Json, json};

/// The configuration fault kinds of `tests/corpora/faults.toml`, each with
/// what it exercises. The `config-enum-*` kinds and `platform-not-enabled`
/// are findings on rules (UC-2.x), not on configuration files.
pub const CONFIGURATION: &[(&str, &str)] = &[
    (
        "config-unknown-key-platform",
        "an unknown key in [platform]",
    ),
    ("config-missing-field-tenant", "a tenant without its name"),
    (
        "config-schema-validation-platform",
        "a platform name that is not a string",
    ),
    (
        "config-promotion-target-unknown",
        "a promotion target no status has",
    ),
    (
        "config-unknown-key-deployment",
        "five unknown keys in deployment.toml",
    ),
    ("config-retired-file", "global.toml stops every command"),
    (
        "config-parse-visibility",
        "visibility.toml that is not TOML",
    ),
    (
        "gap-extra-configuration-file",
        "a .toml opentide does not read",
    ),
    (
        "config-asset-unknown",
        "log sources naming undeclared assets",
    ),
    ("sharing-api-key-literal", "literal MISP keys"),
    ("sharing-duplicate-name", "five blocks of one name"),
    ("sharing-name-invalid", "block names that are not slugs"),
    (
        "sharing-max-tlp-unknown",
        "a max_tlp that is not a tlp name",
    ),
    ("sharing-url-invalid", "ftp URLs"),
    (
        "sharing-invalid-value",
        "a verify_ssl that is not a boolean",
    ),
    (
        "sharing-object-type-unknown",
        "an object type that is not a family",
    ),
    (
        "sharing-organisation-uuid-invalid",
        "organisation UUIDs that are not UUIDs",
    ),
    (
        "sharing-rule-status-unknown",
        "rule statuses deployment.toml lacks",
    ),
    ("sharing-unknown-key", "unknown block keys"),
    ("sharing-missing-field", "blocks missing required keys"),
    ("sharing-unknown-connector", "another connector's array"),
    (
        "gap-sharing-dollar-variable",
        "$NAME is a literal key in sharing.toml",
    ),
    ("sharing-config-parse", "sharing.toml that is not TOML"),
    ("sharing-directory", "configurations/sharing/"),
];

/// The group `--only` names.
pub const GROUP: &str = "configuration";

/// An intended difference on one fault kind: the fields compared are only
/// `code` and `severity` (the message is the TOML crate's).
#[derive(Debug, Clone, Copy)]
pub struct Approved {
    /// The fault kind.
    pub kind: &'static str,
    /// Why.
    pub reason: &'static str,
    /// The bold lead of the CHANGELOG.md entry.
    pub changelog: &'static str,
}

/// The intended differences (`crates/opentide-schema/tests/oracle/config_cases.toml`
/// lists them case by case).
pub const APPROVED: &[Approved] = &[
    Approved {
        kind: "config-parse-visibility",
        reason: "a file that is not TOML is refused by the toml_edit crate, with its own \
                 words and position",
        changelog: "**Configuration files are read as TOML 1.0**",
    },
    Approved {
        kind: "sharing-config-parse",
        reason: "a file that is not TOML is refused by the toml_edit crate, with its own \
                 words",
        changelog: "**Configuration files are read as TOML 1.0**",
    },
];

/// The approved difference for `kind`, if any.
pub fn approved(kind: &str) -> Option<&'static Approved> {
    APPROVED.iter().find(|approved| approved.kind == kind)
}

/// Whether the command is `validate --check sharing-config`.
pub fn is_sharing(command: &[String]) -> bool {
    command.iter().any(|word| word == "sharing-config")
}

fn finding_json(finding: &Finding) -> Json {
    json!({
        "code": finding.code,
        "severity": finding.severity.as_str(),
        "field_path": finding.field_path,
        "message": finding.message,
    })
}

/// What the Rust engine reports for a workspace: `workspace` and `parent`
/// are its configuration folders (their `path` as the oracle prints it in a
/// failure, relative to the workspace), `sharing` the same folders by their
/// absolute path for the sharing messages.
pub fn rust_findings(
    command: &[String],
    workspace: Option<&Folder>,
    parent: Option<&Folder>,
    sharing: &[(String, Option<String>, bool)],
) -> Vec<Json> {
    let resolved = match resolve(&Instance {
        workspace,
        overlay: None,
        parent,
        // The oracle runs without OPENTIDE_TIDE_WORKSPACE.
        skip_parent: false,
    }) {
        Ok(resolved) => resolved,
        Err(error) => {
            let message = match &error {
                ResolveError::Parse {
                    path,
                    message,
                    line,
                    column,
                } => {
                    let place = match (line, column) {
                        (Some(line), Some(column)) => format!(":{line}:{column}"),
                        (Some(line), None) => format!(":{line}"),
                        _ => String::new(),
                    };
                    format!("{path}{place}: {message}")
                }
                ResolveError::Retired { path, message } => format!("{path}: {message}"),
                ResolveError::Proxy(message) => message.clone(),
            };
            return vec![json!({ "code": error.code(), "message": message })];
        }
    };
    let mut found: Vec<Json> = if is_sharing(command) {
        let statuses = resolved
            .get("deployment")
            .map(checks::status_names)
            .unwrap_or_default();
        checks::sharing_config_issues(sharing, &statuses)
            .iter()
            .map(finding_json)
            .collect()
    } else {
        resolved.issues().iter().map(finding_json).collect()
    };
    found.sort_by_key(ToString::to_string);
    found
}

/// The oracle's configuration findings in its `--json` document: the
/// failure when resolution stopped the run, else the report's configuration
/// issues and warnings (every one, for `--check sharing-config`).
pub fn oracle_findings(document: &Json, sharing: bool) -> Vec<Json> {
    if document.get("report").is_none()
        && let Some(failure) = document.get("failure")
        && matches!(
            failure.get("code").and_then(Json::as_str),
            Some("config_parse" | "retired_configuration_file")
        )
    {
        return vec![json!({ "code": failure["code"], "message": failure["message"] })];
    }
    let report = document.get("report");
    let mut found: Vec<Json> = ["issues", "warnings"]
        .iter()
        .filter_map(|key| {
            report
                .and_then(|report| report.get(*key))
                .and_then(Json::as_array)
        })
        .flatten()
        .filter(|item| {
            sharing || item.get("object_type").and_then(Json::as_str) == Some("configuration")
        })
        .map(|item| {
            json!({
                "code": item["code"],
                "severity": item["severity"],
                "field_path": item["field_path"],
                "message": item["message"],
            })
        })
        .collect();
    found.sort_by_key(ToString::to_string);
    found
}

/// The bold lead of the CHANGELOG.md entry for [`quoting_only`].
pub const QUOTING_CHANGELOG: &str = "**Messages quote values the same way everywhere**";

/// `messages-quote-values` (`config_cases.toml`): the findings differ only
/// in the quote characters around the values their messages name.
pub fn quoting_only(oracle: &[Json], rust: &[Json]) -> bool {
    let unquoted = |findings: &[Json]| {
        let mut all: Vec<Json> = findings.iter().map(crate::lint::unquoted_json).collect();
        all.sort_by_key(ToString::to_string);
        all
    };
    oracle != rust && unquoted(oracle) == unquoted(rust)
}

/// Only the codes and severities of `findings`, for an approved difference.
pub fn codes_only(findings: &[Json]) -> Vec<Json> {
    findings
        .iter()
        .map(|finding| json!({ "code": finding["code"], "severity": finding.get("severity") }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_that_differ_only_in_their_quotes_are_the_quoting_difference() {
        let finding = |message: &str| json!({"code": "duplicate_name", "message": message});
        let oracle = [finding("Name 'circl' is used by more than one block")];
        let rust = [finding(r#"Name "circl" is used by more than one block"#)];
        assert!(quoting_only(&oracle, &rust));
        assert!(!quoting_only(&oracle, &oracle));
        let other = [finding(r#"Name "misp" is used by more than one block"#)];
        assert!(!quoting_only(&oracle, &other));
    }

    #[test]
    fn every_configuration_kind_is_in_the_catalogue() {
        let catalogue = super::super::faults::Catalogue::parse(include_str!(
            "../../../tests/corpora/faults.toml"
        ))
        .unwrap();
        for (id, _) in CONFIGURATION {
            assert!(catalogue.kind(id).is_some(), "{id}");
        }
        for approved in APPROVED {
            assert!(CONFIGURATION.iter().any(|(id, _)| *id == approved.kind));
        }
    }

    #[test]
    fn a_resolution_error_is_the_failure() {
        let workspace = Folder {
            path: ".opentide/configurations".to_owned(),
            files: vec![("global.toml".to_owned(), String::new())],
            folders: Vec::new(),
        };
        let found = rust_findings(&["validate".to_owned()], Some(&workspace), None, &[]);
        assert_eq!(
            found,
            [json!({
                "code": "retired_configuration_file",
                "message": ".opentide/configurations/global.toml: global.toml is not read by \
                            opentide: workspace paths and artifact names are set in paths.toml.",
            })]
        );
        let document = json!({"failure": {"code": "retired_configuration_file", "message": "m"}});
        assert_eq!(
            oracle_findings(&document, false),
            [json!({"code": "retired_configuration_file", "message": "m"})]
        );
    }

    #[test]
    fn the_report_gives_configuration_findings_only() {
        let document = json!({"report": {"issues": [
            {"code": "unknown_key", "severity": "error", "field_path": ["x"], "message": "m",
             "object_type": "configuration"},
            {"code": "invalid_uuid", "severity": "error", "field_path": [], "message": "n",
             "object_type": "rule"},
        ], "warnings": []}});
        assert_eq!(oracle_findings(&document, false).len(), 1);
        assert_eq!(oracle_findings(&document, true).len(), 2);
    }
}
