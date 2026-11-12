//! `sharing.toml`, loaded as `sharing/config.py` `load_sharing` loads it: the
//! bundled file, the workspace's, then the fixture overlay or the parent
//! instance's, merged block by block by `opentide-schema`
//! ([`merge_sharing`]); each block's `api_key` resolved from the environment
//! (`${NAME}` only: anything else is a literal, reported and still used).

use opentide_schema::configuration::Severity;
use opentide_schema::configuration::checks::{bundled_status_names, status_names};
use opentide_schema::configuration::sharing::{MispBlock, SharingIssue, merge_sharing};
use opentide_schema::configuration::{bundled, toml};
use opentide_schema::node::{Node, Value};
use opentide_workspace::Workspace;
use regex::Regex;
use std::sync::OnceLock;

use crate::env::Env;

/// The one sharing integration.
pub const INTEGRATION_MISP: &str = "misp";

/// One destination, its key resolved (`MispBlock`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The block's name.
    pub name: String,
    /// The instance's URL.
    pub url: String,
    /// The highest TLP shared.
    pub max_tlp: String,
    /// The resolved secret; `None` when unset. Never printed.
    pub api_key: Option<String>,
    /// `enabled`.
    pub enabled: bool,
    /// `object_types`.
    pub object_types: Vec<String>,
    /// `rule_statuses`.
    pub rule_statuses: Vec<String>,
    /// `organisation_uuid`.
    pub organisation_uuid: Option<String>,
    /// `publish`.
    pub publish: bool,
    /// `verify_ssl`.
    pub verify_ssl: bool,
}

impl Block {
    /// The secret for the client, `None` when unset (`resolved_api_key`).
    pub fn resolved_api_key(&self) -> Option<&str> {
        self.api_key.as_deref().filter(|key| !key.is_empty())
    }

    /// A block from the merged model, its key resolved from `env`.
    fn resolve(block: MispBlock, env: &Env) -> Self {
        let api_key = match block.api_key.as_deref() {
            None | Some("") => None,
            Some(written) => match api_key_pattern().captures(written) {
                // A `${NAME}` reference: the variable's value, unset when empty.
                Some(captures) => captures
                    .get(1)
                    .and_then(|name| env.get(name.as_str()))
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned),
                // A literal (reported as `api_key_literal`) is the key.
                None => Some(written.to_owned()),
            },
        };
        Self {
            name: block.name,
            url: block.url,
            max_tlp: block.max_tlp,
            api_key,
            enabled: block.enabled,
            object_types: block.object_types,
            rule_statuses: block.rule_statuses,
            organisation_uuid: block.organisation_uuid,
            publish: block.publish,
            verify_ssl: block.verify_ssl,
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "a literal pattern, compiled once; it cannot fail"
)]
fn api_key_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^\$\{([A-Z][A-Z0-9_]*)\}$").expect("a valid pattern"))
}

/// The merged configuration and its findings (`SharingConfig`).
#[derive(Clone, Debug, Default)]
pub struct Sharing {
    /// The destinations; empty when a finding is an error.
    pub blocks: Vec<Block>,
    /// Every finding, structural ones first.
    pub issues: Vec<SharingIssue>,
}

impl Sharing {
    /// The errors.
    pub fn errors(&self) -> Vec<&SharingIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.severity == Severity::Error)
            .collect()
    }

    /// The warnings' messages.
    pub fn warnings(&self) -> Vec<String> {
        self.issues
            .iter()
            .filter(|issue| issue.severity == Severity::Warning)
            .map(|issue| issue.message.clone())
            .collect()
    }

    /// Every resolved key, to redact from the output.
    pub fn secrets(&self) -> Vec<String> {
        self.blocks
            .iter()
            .filter_map(|block| block.api_key.clone())
            .filter(|key| !key.is_empty())
            .collect()
    }
}

fn structural(code: &'static str, message: String) -> SharingIssue {
    SharingIssue {
        code,
        message,
        severity: Severity::Error,
        block: None,
        integration: None,
        field_name: None,
        location: None,
        occurrences: Vec::new(),
    }
}

/// Loads the workspace's sharing configuration (`load_sharing`).
pub fn load(workspace: &Workspace, env: &Env) -> Sharing {
    let fs = workspace.fs().as_ref();
    let mut issues = Vec::new();
    let mut documents: Vec<Node> = Vec::new();
    // The bundled folder holds no `sharing/` and its file always parses.
    if let Some(text) = bundled::text("sharing.toml")
        && let Ok(document) = toml::parse(text)
        && matches!(&document.value, Value::Map(entries) if !entries.is_empty())
    {
        documents.push(document);
    }
    for folder in &workspace.configuration().folders {
        let directory = folder.join("sharing");
        if fs.is_dir(&directory) {
            issues.push(structural(
                "sharing_directory",
                format!(
                    "{} is not a sharing configuration. Use a single sharing.toml file.",
                    directory.display()
                ),
            ));
        }
        let file = folder.join("sharing.toml");
        if !fs.is_file(&file) {
            continue;
        }
        let parsed = fs
            .read(&file)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(|text| toml::parse(&text));
        match parsed {
            Some(Ok(document)) => {
                if matches!(&document.value, Value::Map(entries) if !entries.is_empty()) {
                    documents.push(document);
                }
            }
            // `tomllib` names its error's class; a file that does not read
            // as UTF-8 text is a `UnicodeDecodeError`.
            Some(Err(_)) => issues.push(structural(
                "config_parse",
                "Could not read sharing.toml: TOMLDecodeError".to_owned(),
            )),
            None => issues.push(structural(
                "config_parse",
                "Could not read sharing.toml: UnicodeDecodeError".to_owned(),
            )),
        }
    }
    let statuses = workspace
        .configuration()
        .resolved
        .get("deployment")
        .map(status_names)
        .unwrap_or_else(bundled_status_names);
    let layers: Vec<&Node> = documents.iter().collect();
    let merged = merge_sharing(&layers, &statuses, &bundled::tlp_names());
    issues.extend(merged.issues);
    let failed = issues.iter().any(|issue| issue.severity == Severity::Error);
    let blocks = if failed {
        Vec::new()
    } else {
        merged
            .blocks
            .into_iter()
            .map(|block| Block::resolve(block, env))
            .collect()
    };
    Sharing { blocks, issues }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(key: Option<&str>) -> MispBlock {
        MispBlock {
            name: "misp-prod".into(),
            url: "https://misp.example".into(),
            max_tlp: "amber".into(),
            api_key: key.map(str::to_owned),
            enabled: true,
            object_types: vec!["rule".into()],
            rule_statuses: vec!["PRODUCTION".into()],
            organisation_uuid: None,
            publish: false,
            verify_ssl: true,
        }
    }

    #[test]
    fn keys_resolve_from_the_environment_or_stay_literal() {
        let env = Env::from_pairs([("MISP_KEY", "s3cret"), ("EMPTY", "")]);
        let resolved = Block::resolve(block(Some("${MISP_KEY}")), &env);
        assert_eq!(resolved.resolved_api_key(), Some("s3cret"));
        assert_eq!(Block::resolve(block(Some("${EMPTY}")), &env).api_key, None);
        assert_eq!(Block::resolve(block(Some("${UNSET}")), &env).api_key, None);
        assert_eq!(
            Block::resolve(block(Some(" ${MISP_KEY}")), &env)
                .api_key
                .as_deref(),
            Some(" ${MISP_KEY}"),
            "whitespace makes a literal"
        );
        assert_eq!(Block::resolve(block(None), &env).resolved_api_key(), None);
        let sharing = Sharing {
            blocks: vec![resolved],
            issues: Vec::new(),
        };
        assert_eq!(sharing.secrets(), ["s3cret"]);
        assert!(sharing.errors().is_empty());
    }
}
