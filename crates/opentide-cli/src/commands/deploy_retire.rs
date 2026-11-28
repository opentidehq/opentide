//! The rules `opentide deploy` deployed whose file is gone (#1713): found,
//! warned about, and with `--prune` retired from the tenants that hold them.
//!
//! Two kinds of evidence say a rule was deployed and its file deleted, and
//! nothing else does:
//!
//! - **The run's diff** (a change-detection run): the rule files the run's
//!   commits deleted from the rules folder, read as the diff's base commit
//!   held them, so the rule's UUID, name and platform blocks are known.
//! - **Deployment state** (`.opentide/states/deployment/`): the shards of the
//!   platforms that keep vendor ids. A change-detection run reads the shards
//!   of the deleted files' rules; an `--all` run reads every shard, and a
//!   shard whose rule is in no file is an orphan.
//!
//! A UUID that any rule of the workspace still holds (a file moved or
//! renamed) is never retired. A platform that keeps ids retires only the
//! tenants and ids its shard records, and forgets them once retired; the
//! others (Sentinel, Microsoft Defender, Splunk, Elastic, HarfangLab) retire from the deleted
//! file alone, on the tenants its blocks reached, as the same blocks would
//! retire with a status that maps to `DELETION` (Microsoft Defender by
//! `opentide-<uuid>`, the id it deployed the rule under). Carbon Black Cloud cannot
//! retire a report without the rule, so its rows say so.

use std::collections::HashSet;
use std::path::Path;

use opentide_compile::Json as CJson;
use opentide_compile::plan::{self, Change};
use opentide_compile::strategy::{DEPLOYABLE, StatusStrategy};
use opentide_schema::platforms::{PlatformId, PlatformKey};
use opentide_workspace::Workspace;

use super::deploy_state;
use crate::env::Env;

/// The reason a Carbon Black Cloud row carries: its connector retires a
/// report from the rule's own query and watchlist, which a deleted file no
/// longer gives.
pub const CARBON_BLACK_UNSUPPORTED: &str = "retiring a deleted rule is not supported on \
     carbon_black_cloud: remove its report from the watchlist by hand";

/// Which rules the run reads, and so which evidence it has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The files the run's commits changed: deletions are in the diff.
    Changes,
    /// `--all`: every rule file, and every deployment state shard.
    All,
    /// `--uuid` or `--file`: the named rules only; nothing is retired.
    Selected,
}

/// A rule deployed earlier whose file is gone.
#[derive(Clone, Debug)]
struct Orphan {
    uuid: String,
    name: String,
    /// The deleted file's `description`.
    description: String,
    /// The deleted file's `configurations`, when the diff gave it.
    blocks: Option<CJson>,
    /// Its deployment state shard, when it has one.
    shard: Option<deploy_state::Shard>,
}

/// What retiring a rule on one tenant sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// A delete of `rule_id` with `body`; `state`: the id is a shard's, to
    /// forget once deleted.
    Delete {
        /// The id the platform knows the rule by.
        rule_id: String,
        /// What the platform reads beside the id (Splunk's description,
        /// HarfangLab's kind); empty for most.
        body: Vec<u8>,
        /// Whether the id comes from deployment state.
        state: bool,
    },
    /// The platform cannot retire it: why.
    Unsupported(String),
}

/// One rule to retire on one tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retirement {
    /// The platform's identifier (`splunk`).
    pub platform: String,
    /// The tenant's name in the platform's configuration.
    pub tenant: String,
    /// The rule's canonical UUID.
    pub uuid: String,
    /// Its name, as its file last had it (its UUID when unknown).
    pub name: String,
    /// Its block's status as its file last had it; empty when unknown.
    pub status: String,
    /// What is sent.
    pub request: Request,
}

impl Retirement {
    /// The plan's row.
    pub fn change(&self) -> Change {
        Change {
            platform: self.platform.clone(),
            tenant: Some(self.tenant.clone()),
            uuid: self.uuid.clone(),
            name: self.name.clone(),
            status: self.status.clone(),
            action: "delete",
            fails: false,
            retired: true,
        }
    }
}

/// What the search found.
#[derive(Clone, Debug, Default)]
pub struct Found {
    /// The rules to retire, platform by platform, tenant by tenant.
    pub retirements: Vec<Retirement>,
    /// What the run should say: what was found and not retired, and why.
    pub warnings: Vec<String>,
    /// Without `--prune`: what `--prune` would retire, sent nowhere.
    pub retirable: Vec<Retirement>,
}

impl Found {
    /// The `retirable` list `--json` carries without `--prune` (#1713):
    /// each rule a `RELEASE` run with `--prune` would retire, on each tenant.
    pub fn retirable_json(&self) -> Option<CJson> {
        if self.retirable.is_empty() {
            return None;
        }
        Some(CJson::Array(
            self.retirable
                .iter()
                .map(|retirement| {
                    let mut row = opentide_compile::json::Object::new();
                    row.insert("platform".into(), retirement.platform.clone().into());
                    row.insert("tenant".into(), retirement.tenant.clone().into());
                    row.insert("uuid".into(), retirement.uuid.clone().into());
                    row.insert("name".into(), retirement.name.clone().into());
                    row.insert("status".into(), retirement.status.clone().into());
                    row.insert("action".into(), "delete".into());
                    if let Request::Unsupported(reason) = &retirement.request {
                        row.insert("unsupported".into(), reason.clone().into());
                    }
                    CJson::Object(row)
                })
                .collect(),
        ))
    }
}

impl Found {
    /// The platforms the retirements are on, in order.
    pub fn platforms(&self) -> Vec<String> {
        let mut platforms: Vec<String> = Vec::new();
        for retirement in &self.retirements {
            if !platforms.contains(&retirement.platform) {
                platforms.push(retirement.platform.clone());
            }
        }
        platforms
    }

    /// The retirements on `platform`.
    pub fn on<'a>(&'a self, platform: &'a str) -> impl Iterator<Item = &'a Retirement> + 'a {
        self.retirements
            .iter()
            .filter(move |retirement| retirement.platform == platform)
    }
}

/// What the search reads.
pub struct Search<'a> {
    /// The workspace, as the run reads it.
    pub workspace: &'a Workspace,
    /// The resolved configuration and statuses.
    pub owned: &'a opentide_compile::Owned,
    /// The environment (CI's variables pick the diff).
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// Which rules the run reads.
    pub mode: Mode,
    /// `--platform`.
    pub platform: Option<&'a str>,
    /// `--prune`: the warnings name what will be retired, not how to.
    pub prune: bool,
}

/// The rules deployed earlier whose file is gone, and what retiring each on
/// each tenant sends.
pub fn find(search: &Search<'_>) -> Found {
    let mut found = Found::default();
    if search.mode == Mode::Selected {
        return found;
    }
    let workspace = search.workspace;
    let root = workspace.root().to_path_buf();
    let index = workspace.index();
    let present: HashSet<String> = index
        .rules()
        .map(|object| opentide_compile::rule::canonical_uuid(&object.uuid))
        .collect();
    let orphans = match search.mode {
        Mode::Changes => deleted_orphans(search, &present, &mut found.warnings),
        Mode::All => {
            if present.is_empty() {
                // An empty or misplaced rules folder would make every shard
                // an orphan: never prune from nothing.
                let shards = deploy_state::recorded_uuids(&root);
                if !shards.is_empty() {
                    found.warnings.push(format!(
                        "the workspace holds no rule, so the {} in .opentide/states/deployment/ \
                         {} not checked for deleted rules: nothing is retired",
                        plan::plural(shards.len(), "deployment state shard"),
                        if shards.len() == 1 { "was" } else { "were" }
                    ));
                }
                return found;
            }
            state_orphans(&root, &present)
        }
        Mode::Selected => Vec::new(),
    };
    if orphans.is_empty() {
        return found;
    }
    // A rule file that does not load holds a UUID the index does not: its
    // rule would look deleted.
    if !index.load_errors.is_empty() {
        found.warnings.push(format!(
            "{} deployed earlier {} no rule file, but {} could not be read, so deploy cannot \
             tell a deleted rule from an unreadable one: nothing is retired; fix the files \
             (opentide validate shows where)",
            plan::plural(orphans.len(), "rule"),
            if orphans.len() == 1 { "has" } else { "have" },
            plan::plural(index.load_errors.len(), "object file"),
        ));
        return found;
    }
    let enabled = plan::enabled_with(&search.owned.config, &crate::plugins::plugin_ids());
    for orphan in &orphans {
        retire_orphan(search, &enabled, orphan, &mut found);
    }
    if !search.prune && !found.retirements.is_empty() {
        let mut rules: Vec<String> = Vec::new();
        for retirement in &found.retirements {
            // A rule known only from deployment state has no name.
            let label = if retirement.name == retirement.uuid {
                retirement.uuid.clone()
            } else {
                format!("{} ({})", retirement.name, retirement.uuid)
            };
            if !rules.contains(&label) {
                rules.push(label);
            }
        }
        found.warnings.push(format!(
            "{} deployed earlier {} no rule file any more and {} not retired from {}: {}; a \
             --strategy RELEASE run with --prune retires {}",
            plan::plural(rules.len(), "rule"),
            if rules.len() == 1 { "has" } else { "have" },
            if rules.len() == 1 { "is" } else { "are" },
            plan::plural(
                found
                    .retirements
                    .iter()
                    .map(|r| (&r.platform, &r.tenant))
                    .collect::<HashSet<_>>()
                    .len(),
                "tenant"
            ),
            rules.join(", "),
            if rules.len() == 1 { "it" } else { "them" }
        ));
        found.retirable = std::mem::take(&mut found.retirements);
    }
    found
}

/// The rule files the run's diff deleted whose rule no file holds now.
fn deleted_orphans(
    search: &Search<'_>,
    present: &HashSet<String>,
    warnings: &mut Vec<String>,
) -> Vec<Orphan> {
    let workspace = search.workspace;
    let root = workspace.root().to_path_buf();
    let (_, folder) = opentide_compile::dry_run::rules_folder(workspace);
    let lookup = |name: &str| search.env.get(name).map(str::to_owned);
    let source = opentide_compile::git::diff_source(&lookup);
    let deleted = match opentide_compile::git::deleted_paths(&root, search.cwd, &lookup, source) {
        Ok(deleted) => deleted,
        Err(error) => {
            warnings.push(format!(
                "cannot tell which rule files the run deleted, so none is retired: {}",
                error.message()
            ));
            return Vec::new();
        }
    };
    let paths: Vec<String> = deleted.iter().map(|file| file.path.clone()).collect();
    let (top, _) = opentide_compile::git::split_rule_paths(&paths, &folder);
    let mut orphans: Vec<Orphan> = Vec::new();
    for file in deleted.iter().filter(|file| top.contains(&file.path)) {
        let data = opentide_schema::node::load_bytes(&file.content)
            .ok()
            .and_then(|document| document.root().map(|root| CJson::from_node(root)));
        let uuid = data
            .as_ref()
            .and_then(|data| data.get("metadata"))
            .and_then(|metadata| metadata.get("uuid"))
            .and_then(CJson::as_str)
            .and_then(deploy_state::canonical);
        let Some(uuid) = uuid else {
            warnings.push(format!(
                "{} was deleted, but its last version names no rule UUID, so its rule cannot be \
                 retired: remove it from the tenants by hand",
                file.path
            ));
            continue;
        };
        if present.contains(&uuid) || orphans.iter().any(|orphan| orphan.uuid == uuid) {
            continue;
        }
        let text = |key: &str| {
            data.as_ref()
                .and_then(|data| data.get(key))
                .and_then(CJson::as_str)
                .map(str::to_owned)
        };
        let shard = deploy_state::Shard::load(&root, &uuid)
            .ok()
            .filter(|shard| shard.exists);
        orphans.push(Orphan {
            name: text("name").unwrap_or_else(|| uuid.clone()),
            description: text("description").unwrap_or_default(),
            blocks: data
                .as_ref()
                .and_then(|data| data.get("configurations"))
                .cloned(),
            uuid,
            shard,
        });
    }
    orphans
}

/// The deployment state shards whose rule no file holds.
fn state_orphans(root: &Path, present: &HashSet<String>) -> Vec<Orphan> {
    deploy_state::recorded_uuids(root)
        .into_iter()
        .filter(|uuid| !present.contains(uuid))
        .filter_map(|uuid| {
            let shard = deploy_state::Shard::load(root, &uuid).ok()?;
            Some(Orphan {
                name: uuid.clone(),
                description: String::new(),
                blocks: None,
                uuid,
                shard: Some(shard),
            })
        })
        .collect()
}

/// Each tenant `orphan` is on, and what retiring it there sends.
fn retire_orphan(search: &Search<'_>, enabled: &[String], orphan: &Orphan, found: &mut Found) {
    let config = &search.owned.config;
    let mut platforms: Vec<String> = Vec::new();
    if let Some(shard) = &orphan.shard {
        platforms.extend(shard.platforms.keys().cloned());
    }
    if let Some(CJson::Object(blocks)) = &orphan.blocks {
        for (platform, _) in blocks {
            if !platforms.contains(platform) {
                platforms.push(platform.clone());
            }
        }
    }
    for platform in platforms {
        if search.platform.is_some_and(|only| only != platform) || !enabled.contains(&platform) {
            continue;
        }
        let tables = plan::tenants(config, &PlatformKey::new(&platform));
        let block = orphan
            .blocks
            .as_ref()
            .and_then(|blocks| blocks.get(&platform))
            .filter(|block| !block.is_null());
        let status = block
            .and_then(|block| block.get("status"))
            .and_then(CJson::as_str)
            .unwrap_or_default()
            .to_owned();
        let row = |tenant: &str, request: Request| Retirement {
            platform: platform.clone(),
            tenant: tenant.to_owned(),
            uuid: orphan.uuid.clone(),
            name: orphan.name.clone(),
            status: status.clone(),
            request,
        };
        if opentide_workspace::state::stores_ids(&platform) {
            // Deployment state is the only proof: its tenants and ids alone.
            let Some(recorded) = orphan
                .shard
                .as_ref()
                .and_then(|shard| shard.platforms.get(&platform))
            else {
                continue;
            };
            for (tenant, id) in recorded {
                let configured = tables
                    .iter()
                    .any(|table| opentide_compile::deploy::tenant_name(table).trim() == tenant);
                if !configured {
                    found.warnings.push(format!(
                        "rule {} has no file and deployment state records it on {platform} \
                         tenant {tenant:?}, which is no longer configured: remove it there by \
                         hand",
                        orphan.uuid
                    ));
                    continue;
                }
                found.retirements.push(row(
                    tenant,
                    Request::Delete {
                        rule_id: id.clone(),
                        body: Vec::new(),
                        state: true,
                    },
                ));
            }
            continue;
        }
        // No state: the deleted file's block says where it went.
        let Some(block) = block else {
            continue;
        };
        let Ok(strategy) = search.owned.statuses.strategy(&status) else {
            continue;
        };
        // Never deployed (`INERT`), or already retired (`DELETION`).
        if matches!(strategy, StatusStrategy::Inert | StatusStrategy::Deletion) {
            continue;
        }
        let tenants: Vec<plan::Tenant> =
            tables.iter().map(|t| plan::Tenant::from_json(t)).collect();
        for tenant in plan::rule_tenants(&tenants, block, strategy, &DEPLOYABLE, false) {
            let table = tables
                .iter()
                .find(|table| opentide_compile::deploy::tenant_name(table) == tenant.name);
            let request = stateless_request(&platform, orphan, block, table.copied());
            found.retirements.push(row(&tenant.name, request));
        }
    }
}

/// What retiring `orphan` sends to a platform that keeps no state.
fn stateless_request(
    platform: &str,
    orphan: &Orphan,
    block: &CJson,
    table: Option<&CJson>,
) -> Request {
    let delete = |rule_id: String, body: Vec<u8>| Request::Delete {
        rule_id,
        body,
        state: false,
    };
    match PlatformId::parse(platform) {
        Some(PlatformId::Splunk) => {
            // The saved search's name, and the line naming the rule: the
            // connector deletes every saved search of the app that ends with
            // it, so an earlier name's copy goes too (#1657).
            let mut name = orphan.name.trim().to_owned();
            let correlation = match block.get("correlation_search") {
                Some(CJson::Bool(set)) => *set,
                _ => table.is_some_and(|table| {
                    opentide_compile::splunk::enterprise_security(table).unwrap_or(false)
                }),
            };
            if correlation {
                name.push_str(" - Rule");
            }
            let mut body = opentide_compile::json::Object::new();
            body.insert(
                "description".into(),
                opentide_compile::splunk::described(&orphan.description, &orphan.uuid).into(),
            );
            delete(name, CJson::Object(body).to_compact().into_bytes())
        }
        Some(PlatformId::Harfanglab) => {
            let kind = if block.get("sigma").is_some_and(|value| !value.is_null()) {
                opentide_compile::harfanglab::Kind::Sigma
            } else if block.get("yara").is_some_and(|value| !value.is_null()) {
                opentide_compile::harfanglab::Kind::Yara
            } else {
                return Request::Unsupported(
                    "the deleted rule's harfanglab block is neither a sigma nor a yara rule".into(),
                );
            };
            let body = opentide_compile::harfanglab::request_body(kind, None);
            delete(orphan.uuid.clone(), body.to_compact().into_bytes())
        }
        Some(PlatformId::CarbonBlackCloud) => Request::Unsupported(CARBON_BLACK_UNSUPPORTED.into()),
        // The Defender rule id opentide gives the rule, `opentide-<uuid>`
        // (#1886): a retirement deletes only a rule opentide manages.
        Some(PlatformId::MicrosoftDefender) => delete(
            opentide_compile::microsoft_defender::rule_id_of(&orphan.uuid),
            Vec::new(),
        ),
        _ => delete(orphan.uuid.clone(), Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn orphan(name: &str, description: &str) -> Orphan {
        Orphan {
            uuid: "00000000-0000-4000-8003-000000000001".into(),
            name: name.into(),
            description: description.into(),
            blocks: None,
            shard: None,
        }
    }

    fn json(text: &str) -> CJson {
        CJson::parse(text).unwrap_or(CJson::Null)
    }

    #[test]
    fn a_splunk_retirement_names_the_saved_search_and_marks_the_rule() {
        let block = json(r#"{"status": "PRODUCTION"}"#);
        let table = json(r#"{"name": "es", "setup": {"enterprise_security": true}}"#);
        let request = stateless_request("splunk", &orphan(" Gone ", "Old."), &block, Some(&table));
        let Request::Delete {
            rule_id,
            body,
            state,
        } = request
        else {
            panic!("a delete")
        };
        assert_eq!(rule_id, "Gone - Rule");
        assert!(!state);
        assert_eq!(
            String::from_utf8(body).unwrap_or_default(),
            r#"{"description":"Old.\n\nopentide rule 00000000-0000-4000-8003-000000000001"}"#
        );
    }

    #[test]
    fn a_harfanglab_retirement_names_its_kind() {
        let block = json(r#"{"status": "PRODUCTION", "yara": {"rule": "x"}}"#);
        let request = stateless_request("harfanglab", &orphan("Gone", ""), &block, None);
        assert_eq!(
            request,
            Request::Delete {
                rule_id: "00000000-0000-4000-8003-000000000001".into(),
                body: br#"{"kind":"YARA"}"#.to_vec(),
                state: false,
            }
        );
    }

    #[test]
    fn carbon_black_says_it_cannot_retire_a_deleted_rule() {
        let block = json(r#"{"status": "PRODUCTION"}"#);
        assert_eq!(
            stateless_request("carbon_black_cloud", &orphan("Gone", ""), &block, None),
            Request::Unsupported(CARBON_BLACK_UNSUPPORTED.into())
        );
    }

    #[test]
    fn microsoft_defender_retires_the_opentide_rule_id() {
        // #1886: Graph refuses an id that begins with a digit, so the rule
        // was deployed as `opentide-<uuid>`, and is retired by that id.
        let block = json(r#"{"status": "PRODUCTION"}"#);
        assert_eq!(
            stateless_request("microsoft_defender", &orphan("Gone", ""), &block, None),
            Request::Delete {
                rule_id: "opentide-00000000-0000-4000-8003-000000000001".into(),
                body: Vec::new(),
                state: false,
            }
        );
    }

    #[test]
    fn sentinel_and_elastic_delete_by_the_rules_uuid() {
        let block = json(r#"{"status": "PRODUCTION"}"#);
        for platform in ["sentinel", "elastic"] {
            assert_eq!(
                stateless_request(platform, &orphan("Gone", ""), &block, None),
                Request::Delete {
                    rule_id: "00000000-0000-4000-8003-000000000001".into(),
                    body: Vec::new(),
                    state: false,
                }
            );
        }
    }
}
