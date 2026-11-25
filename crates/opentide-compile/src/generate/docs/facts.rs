//! Where a rule deploys (`documentation/facts/deployment.py`): per platform
//! block, its status, the runs that act on it, and the tenants they reach.
//!
//! A page shows what `opentide deploy` would do with the rule, not what its
//! YAML merely says. For each block:
//!
//! - the **status**, and the strategy `deployment.toml` maps it to;
//! - the **runs** that act on it (`PREVIEW` from pull requests, `RELEASE`
//!   from the default branch), by [`crate::strategy::deploys`];
//! - the **tenants** those runs reach, by the planner's own rule
//!   ([`crate::plan::tenant_skip_reason`]): a block that lists `tenants`
//!   reaches only those, otherwise every tenant that is not `manual`; and
//!   only a tenant that accepts one of the runs;
//! - the **remote id** each tenant holds, from the rule's deployment state
//!   shard ([`crate::plan::state_ids`]).
//!
//! The configuration and the state are read once into an [`Environment`],
//! so rendering stays pure and a test builds one by hand. Credentials are
//! never resolved: targeting reads `name`, `description`, `strategies` and
//! `manual` only.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use indexmap::IndexMap;
use opentide_workspace::FileSystem;

use super::platforms::platform_label;
use crate::json::Json;
use crate::strategy::{DEPLOYABLE, StatusStrategy, deploys};

/// One `[[statuses]]` entry of `deployment.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusDefinition {
    /// `name`.
    pub name: String,
    /// `description`.
    pub description: String,
    /// `strategy`.
    pub strategy: StatusStrategy,
}

/// A configured tenant, as far as targeting goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantInfo {
    /// `name`.
    pub name: String,
    /// `description`.
    pub description: String,
    /// The run strategies it accepts.
    pub strategies: Vec<StatusStrategy>,
    /// Reached only by rules whose block lists it.
    pub manual: bool,
}

/// The workspace configuration and state a rule page reads.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    /// Every configured status, in file order.
    pub statuses: Vec<StatusDefinition>,
    /// The platforms the workspace enables; `None` when unknown.
    pub enabled: Option<BTreeSet<String>>,
    /// Each platform's tenants; a platform that is not here, or `None`,
    /// has tenants that cannot be read.
    pub tenants: HashMap<String, Option<Vec<TenantInfo>>>,
    /// `platform -> tenant -> remote id`, by rule UUID.
    pub states: HashMap<String, IndexMap<String, IndexMap<String, String>>>,
    /// `[deployment] default_responders`.
    pub default_responders: String,
}

impl Environment {
    /// The environment of a resolved configuration (its tree as JSON), the
    /// enabled platforms given, and the deployment state of `rules` under
    /// `workspace`.
    pub fn read<'u>(
        config: &Json,
        enabled: &[String],
        fs: &dyn FileSystem,
        workspace: &Path,
        rules: impl IntoIterator<Item = &'u str>,
    ) -> Self {
        let deployment = config.get("deployment");
        let statuses = deployment
            .and_then(|deployment| deployment.get("statuses"))
            .and_then(|statuses| match statuses {
                Json::Array(items) => Some(items.as_slice()),
                _ => None,
            })
            .unwrap_or_default()
            .iter()
            .filter_map(|entry| {
                let name = entry.get("name")?.as_str()?;
                let strategy = StatusStrategy::from_name(entry.get("strategy")?.as_str()?)?;
                Some(StatusDefinition {
                    name: name.to_owned(),
                    description: entry
                        .get("description")
                        .and_then(Json::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    strategy,
                })
            })
            .collect();
        let tenants = config
            .get("platforms")
            .and_then(Json::as_object)
            .into_iter()
            .flatten()
            .map(|(platform, table)| (platform.clone(), read_tenants(table)))
            .collect();
        let states = rules
            .into_iter()
            .filter_map(|uuid| {
                crate::plan::state_ids(fs, workspace, uuid).map(|ids| (uuid.to_owned(), ids))
            })
            .collect();
        Self {
            statuses,
            enabled: Some(enabled.iter().cloned().collect()),
            tenants,
            states,
            default_responders: deployment
                .and_then(|deployment| deployment.get("default_responders"))
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned(),
        }
    }

    /// Whether the workspace enables `platform`; `None` when unknown.
    pub fn platform_enabled(&self, platform: &str) -> Option<bool> {
        self.enabled
            .as_ref()
            .map(|enabled| enabled.contains(platform))
    }

    /// The configured tenants of `platform`; `None` when they cannot be read.
    pub fn tenants(&self, platform: &str) -> Option<&[TenantInfo]> {
        self.tenants.get(platform)?.as_deref()
    }

    /// The remote ids of a rule, by platform then tenant.
    pub fn remote_ids(&self, uuid: &str) -> Option<&IndexMap<String, IndexMap<String, String>>> {
        self.states.get(uuid)
    }
}

/// The targeting keys of a platform's `[[tenants]]`; `None` when they are
/// malformed (validate reports those, and the page says the tenants are
/// unknown).
fn read_tenants(table: &Json) -> Option<Vec<TenantInfo>> {
    let entries = match table.get("tenants") {
        None | Some(Json::Null) => return Some(Vec::new()),
        Some(Json::Array(entries)) => entries,
        Some(_) => return None,
    };
    let mut tenants = Vec::new();
    for entry in entries {
        let name = entry.as_object()?.get("name")?.as_str()?;
        let strategies = match entry.get("strategies") {
            None => DEPLOYABLE.to_vec(),
            Some(Json::Str(one)) => strategies(&[one.as_str()])?,
            Some(Json::Array(items)) => {
                let names: Option<Vec<&str>> = items.iter().map(Json::as_str).collect();
                strategies(&names?)?
            }
            Some(_) => return None,
        };
        tenants.push(TenantInfo {
            name: name.to_owned(),
            description: match entry.get("description") {
                Some(Json::Str(text)) => text.clone(),
                Some(Json::Null) | None => String::new(),
                Some(other) => other.to_compact(),
            },
            strategies,
            manual: matches!(entry.get("manual"), Some(Json::Bool(true))),
        });
    }
    Some(tenants)
}

/// A tenant's `strategies`: deployable strategy names, comma-separated or
/// listed, in [`DEPLOYABLE`] order; `None` when one is not.
fn strategies(values: &[&str]) -> Option<Vec<StatusStrategy>> {
    let mut chosen = Vec::new();
    for value in values {
        for part in value.split(',') {
            let name = part.trim().to_uppercase();
            if name.is_empty() {
                continue;
            }
            let strategy = StatusStrategy::from_name(&name).filter(|s| DEPLOYABLE.contains(s))?;
            chosen.push(strategy);
        }
    }
    Some(
        DEPLOYABLE
            .into_iter()
            .filter(|strategy| chosen.contains(strategy))
            .collect(),
    )
}

/// How a block's tenants were chosen: it lists them, every tenant that is
/// not manual, the platform configures none, or its tenants cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantScope {
    /// The block lists its tenants.
    Listed,
    /// Every tenant that is not manual.
    All,
    /// The platform configures no tenant.
    None,
    /// The platform's tenants cannot be read.
    Unknown,
}

/// One tenant a block reaches, and the runs that reach it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantTarget {
    /// The tenant.
    pub name: String,
    /// Its description.
    pub description: String,
    /// The runs that deploy the block there.
    pub runs: Vec<StatusStrategy>,
    /// The rule's id there, from the state.
    pub remote_id: String,
    /// The run strategies the tenant accepts; empty when unknown.
    pub accepts: Vec<StatusStrategy>,
}

/// Everything a page says about one platform block's deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformDeployment {
    /// The platform's key.
    pub platform: String,
    /// Its label.
    pub label: String,
    /// The block's `enabled`.
    pub enabled: bool,
    /// The block's `status`.
    pub status: String,
    /// The status's definition; `None` when `deployment.toml` has none.
    pub definition: Option<StatusDefinition>,
    /// The runs that act on the block, whatever the tenants accept.
    pub runs: Vec<StatusStrategy>,
    /// How its tenants were chosen.
    pub scope: TenantScope,
    /// The candidate tenants.
    pub targets: Vec<TenantTarget>,
    /// Tenants the block lists that the platform does not configure.
    pub unknown_tenants: Vec<String>,
    /// Whether the workspace enables the platform; `None` when unknown.
    pub platform_enabled: Option<bool>,
    /// Remote ids held for tenants the block no longer reaches.
    pub orphaned_ids: IndexMap<String, String>,
}

impl PlatformDeployment {
    /// The tenants at least one run deploys to.
    pub fn reached(&self) -> impl Iterator<Item = &TenantTarget> {
        self.targets.iter().filter(|target| !target.runs.is_empty())
    }
}

/// A platform block as deployment reads it: the block's JSON.
pub struct Block<'b> {
    /// The platform's key.
    pub platform: &'b str,
    /// The block as the model holds it.
    pub json: &'b Json,
}

/// One [`PlatformDeployment`] per block, in the order given (the model's).
pub fn rule_deployments(
    uuid: &str,
    blocks: &[Block<'_>],
    environment: &Environment,
) -> Vec<PlatformDeployment> {
    let definitions: HashMap<&str, &StatusDefinition> = environment
        .statuses
        .iter()
        .map(|status| (status.name.as_str(), status))
        .collect();
    let empty = IndexMap::new();
    let remote = environment.remote_ids(uuid);
    blocks
        .iter()
        .map(|block| {
            let status = match block.json.get("status") {
                Some(Json::Str(text)) => text.clone(),
                Some(Json::Null) | None => String::new(),
                Some(other) => other.to_compact(),
            };
            let definition = definitions
                .get(status.as_str())
                .map(|found| (*found).clone());
            let enabled = environment.platform_enabled(block.platform);
            // A platform the workspace does not enable is never deployed to.
            let runs = match &definition {
                Some(definition) if enabled != Some(false) => DEPLOYABLE
                    .into_iter()
                    .filter(|run| deploys(definition.strategy, *run))
                    .collect(),
                _ => Vec::new(),
            };
            let listed: Vec<String> = match block.json.get("tenants") {
                Some(Json::Array(items)) => items
                    .iter()
                    .map(|item| match item {
                        Json::Str(text) => text.clone(),
                        other => other.to_compact(),
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let deployment = PlatformDeployment {
                platform: block.platform.to_owned(),
                label: platform_label(block.platform),
                enabled: matches!(block.json.get("enabled"), Some(Json::Bool(true))),
                status,
                definition,
                runs,
                scope: TenantScope::Unknown,
                targets: Vec::new(),
                unknown_tenants: Vec::new(),
                platform_enabled: enabled,
                orphaned_ids: IndexMap::new(),
            };
            let remote = remote
                .and_then(|remote| remote.get(block.platform))
                .unwrap_or(&empty);
            with_tenants(
                deployment,
                &listed,
                environment.tenants(block.platform),
                remote,
            )
        })
        .collect()
}

fn with_tenants(
    mut deployment: PlatformDeployment,
    listed: &[String],
    tenants: Option<&[TenantInfo]>,
    remote: &IndexMap<String, String>,
) -> PlatformDeployment {
    let Some(tenants) = tenants else {
        deployment.scope = if listed.is_empty() {
            TenantScope::Unknown
        } else {
            TenantScope::Listed
        };
        deployment.targets = listed
            .iter()
            .map(|name| TenantTarget {
                name: name.clone(),
                remote_id: remote.get(name).cloned().unwrap_or_default(),
                ..TenantTarget::default()
            })
            .collect();
        deployment.orphaned_ids = remote
            .iter()
            .filter(|(name, _)| !listed.contains(name))
            .map(|(name, id)| (name.clone(), id.clone()))
            .collect();
        return deployment;
    };
    if tenants.is_empty() {
        deployment.scope = TenantScope::None;
        deployment.unknown_tenants = listed.to_vec();
        deployment.orphaned_ids.clone_from(remote);
        return deployment;
    }
    deployment.targets = tenants
        .iter()
        .filter(|tenant| {
            crate::plan::tenant_skip_reason(&tenant.name, tenant.manual, listed).is_none()
        })
        .map(|tenant| TenantTarget {
            name: tenant.name.clone(),
            description: tenant.description.clone(),
            runs: deployment
                .runs
                .iter()
                .copied()
                .filter(|run| tenant.strategies.contains(run))
                .collect(),
            remote_id: remote.get(&tenant.name).cloned().unwrap_or_default(),
            accepts: tenant.strategies.clone(),
        })
        .collect();
    deployment.scope = if listed.is_empty() {
        TenantScope::All
    } else {
        TenantScope::Listed
    };
    deployment.unknown_tenants = listed
        .iter()
        .filter(|name| !tenants.iter().any(|tenant| &tenant.name == *name))
        .cloned()
        .collect();
    let names: Vec<&str> = deployment
        .targets
        .iter()
        .map(|target| target.name.as_str())
        .collect();
    deployment.orphaned_ids = remote
        .iter()
        .filter(|(name, _)| !names.contains(&name.as_str()))
        .map(|(name, id)| (name.clone(), id.clone()))
        .collect();
    deployment
}

#[cfg(test)]
mod tests {
    use super::*;
    use StatusStrategy::{Deletion, Preview, Release, Universal};

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap()
    }

    fn status(name: &str, strategy: StatusStrategy) -> StatusDefinition {
        StatusDefinition {
            name: name.to_owned(),
            description: format!("{name} description"),
            strategy,
        }
    }

    fn tenant(name: &str, strategies: &[StatusStrategy], manual: bool) -> TenantInfo {
        TenantInfo {
            name: name.to_owned(),
            description: String::new(),
            strategies: strategies.to_vec(),
            manual,
        }
    }

    fn environment() -> Environment {
        let mut environment = Environment {
            statuses: vec![
                status("STAGING", Preview),
                status("PRODUCTION", Release),
                status("ALWAYS", Universal),
                status("RETIRED", Deletion),
            ],
            enabled: Some(["sentinel".to_owned(), "splunk".to_owned()].into()),
            ..Environment::default()
        };
        environment.tenants.insert(
            "sentinel".into(),
            Some(vec![
                tenant("prod", &[Release], false),
                tenant("lab", &[Preview, Release], false),
                tenant("vip", &[Preview, Release], true),
            ]),
        );
        environment
            .tenants
            .insert("splunk".into(), Some(Vec::new()));
        environment.states.insert(
            "u".into(),
            [(
                "sentinel".to_owned(),
                [("lab", "1"), ("gone", "9")]
                    .into_iter()
                    .map(|(a, b)| (a.to_owned(), b.to_owned()))
                    .collect(),
            )]
            .into_iter()
            .collect(),
        );
        environment
    }

    fn deploy(platform: &str, block: &str) -> PlatformDeployment {
        let block = json(block);
        rule_deployments(
            "u",
            &[Block {
                platform,
                json: &block,
            }],
            &environment(),
        )
        .remove(0)
    }

    #[test]
    fn every_tenant_that_is_not_manual_and_its_runs() {
        let found = deploy("sentinel", r#"{"enabled": true, "status": "ALWAYS"}"#);
        assert_eq!(found.label, "Microsoft Sentinel");
        assert_eq!(found.scope, TenantScope::All);
        assert_eq!(found.runs, [Preview, Release]);
        let targets: Vec<(&str, &[StatusStrategy], &str)> = found
            .targets
            .iter()
            .map(|t| (t.name.as_str(), t.runs.as_slice(), t.remote_id.as_str()))
            .collect();
        assert_eq!(
            targets,
            [
                ("prod", &[Release][..], ""),
                ("lab", &[Preview, Release][..], "1")
            ]
        );
        assert_eq!(found.orphaned_ids.keys().collect::<Vec<_>>(), ["gone"]);
    }

    #[test]
    fn a_listed_tenant_and_one_that_is_not_configured() {
        let found = deploy(
            "sentinel",
            r#"{"enabled": true, "status": "STAGING", "tenants": ["vip", "nope"]}"#,
        );
        assert_eq!(found.scope, TenantScope::Listed);
        assert_eq!(found.targets.len(), 1);
        assert_eq!(found.targets[0].runs, [Preview]);
        assert_eq!(found.unknown_tenants, ["nope"]);
        assert_eq!(found.reached().count(), 1);
    }

    #[test]
    fn unknown_statuses_disabled_platforms_and_no_tenants() {
        let found = deploy("sentinel", r#"{"status": "DRAFT"}"#);
        assert!(found.definition.is_none());
        assert!(found.runs.is_empty());
        assert!(!found.enabled);
        let found = deploy("elastic", r#"{"status": "STAGING", "tenants": ["a"]}"#);
        assert_eq!(found.platform_enabled, Some(false));
        assert!(found.runs.is_empty());
        assert_eq!(found.scope, TenantScope::Listed);
        let found = deploy("elastic", r#"{"status": "STAGING"}"#);
        assert_eq!(found.scope, TenantScope::Unknown);
        let found = deploy("splunk", r#"{"status": "RETIRED", "tenants": ["x"]}"#);
        assert_eq!(found.scope, TenantScope::None);
        assert_eq!(found.runs, [Release]);
        assert_eq!(found.unknown_tenants, ["x"]);
    }

    #[test]
    fn tenants_read_from_the_configuration() {
        let config = json(
            r#"{"deployment": {"default_responders": "soc", "statuses": [
                    {"name": "STAGING", "description": "Staged", "strategy": "PREVIEW"},
                    {"name": "BAD", "strategy": "NOPE"}]},
                "platforms": {
                    "sentinel": {"tenants": [
                        {"name": "a", "strategies": "release", "manual": true, "description": "A"},
                        {"name": "b", "strategies": ["PREVIEW, RELEASE"]}]},
                    "splunk": {"platform": {"enabled": true}},
                    "elastic": {"tenants": [{"name": "c", "strategies": ["DEBUG"]}]},
                    "sysdig": {"tenants": [{"description": "no name"}]},
                    "crowdstrike": {"tenants": {"name": "x"}}}}"#,
        );
        let fs = opentide_workspace::OsFs;
        let environment = Environment::read(
            &config,
            &["sentinel".to_owned()],
            &fs,
            Path::new("/nonexistent"),
            ["u"],
        );
        assert_eq!(
            environment.statuses,
            [StatusDefinition {
                name: "STAGING".into(),
                description: "Staged".into(),
                strategy: Preview
            }]
        );
        assert_eq!(environment.default_responders, "soc");
        assert_eq!(environment.platform_enabled("sentinel"), Some(true));
        assert_eq!(environment.platform_enabled("splunk"), Some(false));
        let sentinel = environment.tenants("sentinel").unwrap();
        assert_eq!(sentinel[0].strategies, [Release]);
        assert!(sentinel[0].manual);
        assert_eq!(sentinel[0].description, "A");
        assert_eq!(sentinel[1].strategies, [Preview, Release]);
        assert_eq!(environment.tenants("splunk"), Some(&[][..]));
        assert_eq!(environment.tenants("elastic"), None);
        assert_eq!(environment.tenants("sysdig"), None);
        assert_eq!(environment.tenants("crowdstrike"), None);
        assert_eq!(environment.tenants("harfanglab"), None);
        assert!(environment.remote_ids("u").is_none());
    }
}
