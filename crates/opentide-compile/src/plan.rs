//! The deploy plan: which rule goes to which platform and tenant, and what
//! that does there (`deployment/utils.py` `make_deploy_plan`,
//! `deployment/planning.py` `tenants_resolver`, `platforms/enabled.py`,
//! `cli/services/deploy_plan.py`).

use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use opentide_schema::node::{Node, Value};
use opentide_workspace::FileSystem;

use crate::json::{Json, Object};
use crate::rule::canonical_uuid;
use crate::strategy::{RunStrategies, StatusError, StatusStrategy, Statuses, deploys};

/// The platforms, in the order the plan visits a configuration's tables.
pub const PLATFORMS: [&str; 9] = [
    "sentinel",
    "defender_for_endpoint",
    "splunk",
    "sentinel_one",
    "crowdstrike",
    "harfanglab",
    "carbon_black_cloud",
    "elastic",
    "sysdig",
];

/// Platforms whose deployer addresses a rule by a vendor id kept in
/// `.opentide/states/deployment/` (`STATE_PLATFORMS`).
pub const STATE_PLATFORMS: [&str; 4] = [
    "crowdstrike",
    "defender_for_endpoint",
    "sentinel_one",
    "sysdig",
];

/// Where nested rule files are explained.
pub const NESTED_RULES_ISSUE: &str = "https://github.com/opentidehq/opentide/issues/312";

/// Nested files named in the warning before the rest are counted.
const NESTED_SHOWN: usize = 5;

/// `1 rule`, `2 rules` (`plural`).
pub fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// The rule files a run reads, and those in subfolders it skips (#312).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    /// Files directly in the rules folder.
    pub files: Vec<PathBuf>,
    /// Files in subfolders, as `<rules folder>/<path>`.
    pub nested: Vec<String>,
}

/// Every `.yaml` and `.yml` file under `rules`, sorted as Python sorts paths
/// (component by component), split by depth (`local_rule_scope`). `folder`
/// is the rules folder as the workspace spells it (`objects/rules`).
pub fn local_scope(fs: &dyn FileSystem, rules: &Path, folder: &str) -> Scope {
    let mut found: Vec<(Vec<String>, PathBuf)> = Vec::new();
    walk(fs, rules, &mut Vec::new(), &mut found, 0);
    found.sort_by(|a, b| a.0.cmp(&b.0));
    let mut scope = Scope::default();
    for (parts, path) in found {
        if parts.len() == 1 {
            scope.files.push(path);
        } else {
            scope.nested.push(format!("{folder}/{}", parts.join("/")));
        }
    }
    scope
}

/// Folders deeper than this are not read: a link cycle ends here.
const MAX_DEPTH: usize = 64;

fn walk(
    fs: &dyn FileSystem,
    dir: &Path,
    parts: &mut Vec<String>,
    found: &mut Vec<(Vec<String>, PathBuf)>,
    depth: usize,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = fs.read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = dir.join(&entry.name);
        let name = entry.name.clone();
        if fs.is_dir(&path) {
            parts.push(name);
            walk(fs, &path, parts, found, depth + 1);
            parts.pop();
        } else if fs.is_file(&path)
            && Path::new(&name)
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        {
            let mut all = parts.clone();
            all.push(name);
            found.push((all, path));
        }
    }
}

/// The warning for rule files in subfolders (`_nested_rules_warning`).
pub fn nested_warning(nested: &[String], folder: &str) -> String {
    let mut names = nested
        .iter()
        .take(NESTED_SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if nested.len() > NESTED_SHOWN {
        names.push_str(&format!(", +{} more", nested.len() - NESTED_SHOWN));
    }
    format!(
        "{} rule file(s) in subfolders of {folder} are not deployed (deploy reads only files \
         directly in {folder}; see {NESTED_RULES_ISSUE}): {names}",
        nested.len()
    )
}

/// Python's `repr` of a list of strings (`['a', 'b']`), as a log field
/// prints it.
fn python_list(items: &[String]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|item| crate::strategy::python_repr(item))
        .collect();
    format!("[{}]", quoted.join(", "))
}

/// The platforms the configuration enables, in [`PLATFORMS`] order
/// (`enabled_systems`).
pub fn enabled(config: &Json) -> Vec<String> {
    PLATFORMS
        .iter()
        .filter(|platform| {
            matches!(
                config
                    .get("platforms")
                    .and_then(|platforms| platforms.get(platform))
                    .and_then(|table| table.get("platform"))
                    .and_then(|block| block.get("enabled")),
                Some(Json::Bool(true))
            )
        })
        .map(|platform| (*platform).to_owned())
        .collect()
}

/// The platforms the configuration enables: the built-in ones
/// ([`enabled`]), then each of *plugins* (the platform plugins the run can
/// reach, UC-4.5b) whose `[platform] enabled` is true, in *plugins*' order.
pub fn enabled_with(config: &Json, plugins: &[String]) -> Vec<String> {
    let mut platforms = enabled(config);
    platforms.extend(
        plugins
            .iter()
            .filter(|plugin| !PLATFORMS.contains(&plugin.as_str()))
            .filter(|plugin| {
                matches!(
                    config
                        .get("platforms")
                        .and_then(|platforms| platforms.get(plugin))
                        .and_then(|table| table.get("platform"))
                        .and_then(|block| block.get("enabled")),
                    Some(Json::Bool(true))
                )
            })
            .cloned(),
    );
    platforms
}

/// A platform's configured tenants, as the file holds them.
pub fn tenants<'c>(config: &'c Json, platform: &str) -> Vec<&'c Json> {
    match config
        .get("platforms")
        .and_then(|platforms| platforms.get(platform))
        .and_then(|table| table.get("tenants"))
    {
        Some(Json::Array(items)) => items
            .iter()
            .filter(|item| item.as_object().is_some())
            .collect(),
        _ => Vec::new(),
    }
}

/// A rule block a run left out because no run strategy deploys its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The rule's name.
    pub rule: String,
    /// Its UUID.
    pub uuid: String,
    /// The platform.
    pub platform: String,
    /// The block's status.
    pub status: String,
    /// The strategy the status maps to.
    pub strategy: String,
}

impl Skipped {
    /// The entry of the result's `skipped` list.
    pub fn to_json(&self) -> Json {
        let mut entry = Object::new();
        entry.insert("rule".into(), self.rule.clone().into());
        entry.insert("uuid".into(), self.uuid.clone().into());
        entry.insert("platform".into(), self.platform.clone().into());
        entry.insert("status".into(), self.status.clone().into());
        entry.insert("strategy".into(), self.strategy.clone().into());
        Json::Object(entry)
    }
}

/// Why a plan could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// A rule file is not one mapping: the CLI points at it.
    ObjectFile {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        problem: String,
    },
    /// Any other failure, with the message the run reports.
    Failed(String),
}

/// The rules a run deploys, per platform (`make_deploy_plan`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Selection {
    /// Rule UUIDs per platform, platforms in the order rules name them.
    pub platforms: IndexMap<String, Vec<String>>,
    /// Blocks no run strategy deploys.
    pub skipped: Vec<Skipped>,
    /// Warnings the run prints before its own.
    pub warnings: Vec<String>,
    /// Rules refused for carrying vendor ids (`external_id_in_rule`): the run fails.
    pub refused: Vec<String>,
}

/// What [`select`] is asked.
#[derive(Debug, Clone)]
pub struct SelectOptions<'a> {
    /// The run's strategies.
    pub runs: &'a [StatusStrategy],
    /// `--wide`: every block, whatever its status.
    pub wide: bool,
    /// Keep `DISABLEMENT` and `DELETION` blocks.
    pub keep_deprecated: bool,
    /// The enabled platforms.
    pub enabled: &'a [String],
    /// The rules folder as the workspace spells it, for the nested warning.
    pub folder: &'a str,
    /// Log what the plan leaves out as warnings, as `make_deploy_plan` does
    /// when its caller passes no list to report through (`validate query
    /// --live`): `--wide`, the subfolder files, a block no run strategy
    /// deploys, a rule with vendor ids. A block of a disabled platform is
    /// logged for every caller, as `make_deploy_plan` logs it.
    pub log: bool,
}

/// The legacy vendor-id keys a rule still carries on its blocks.
fn legacy_keys(rule: &Json) -> Vec<(String, String)> {
    let Some(Json::Object(configurations)) = rule.get("configurations") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (platform, block) in configurations {
        let Json::Object(block) = block else {
            continue;
        };
        for key in block.keys() {
            if key == "rule_id" || key == "rule_id_bundle" || key.starts_with("rule_id::") {
                found.push((platform.clone(), key.clone()));
            }
        }
    }
    found
}

/// What `opentide deploy migrate-state` says to do.
pub const MIGRATE_ADVICE: &str =
    "run 'opentide deploy migrate-state' and commit .opentide/states/deployment/";

/// The rule's UUID as the oracle reads a raw document (`object_uuid`).
fn object_uuid(rule: &Json) -> Option<String> {
    let text = |value: &Json| match value {
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    };
    if let Some(top) = rule.get("uuid").filter(|value| value.truthy()) {
        return Some(text(top));
    }
    rule.get("metadata")
        .and_then(|metadata| metadata.get("uuid"))
        .filter(|value| value.truthy())
        .map(text)
}

/// The rule files of `scope`, read with `read`, selected for the run.
pub fn select(
    statuses: &Statuses,
    scope: &Scope,
    read: &dyn Fn(&Path) -> Result<Node, String>,
    options: &SelectOptions<'_>,
) -> Result<Selection, PlanError> {
    let mut selection = Selection::default();
    let run_names = {
        let names: Vec<&str> = options.runs.iter().map(|run| run.name()).collect();
        if names.is_empty() {
            "none".to_owned()
        } else {
            names.join(", ")
        }
    };
    if options.log && options.wide {
        tracing::warn!(
            detail = "Assembling plan without status filtering.",
            logger = "opentide.deployment.utils",
            "wide_scope_enabled"
        );
    }
    if !scope.nested.is_empty() {
        if options.log {
            tracing::warn!(
                count = scope.nested.len(),
                files = python_list(&scope.nested).as_str(),
                issue = NESTED_RULES_ISSUE,
                logger = "opentide.deployment.utils",
                "deploy_nested_rules_skipped"
            );
        }
        selection
            .warnings
            .push(nested_warning(&scope.nested, options.folder));
    }
    for path in &scope.files {
        let root = read(path).map_err(|problem| PlanError::ObjectFile {
            path: path.clone(),
            problem,
        })?;
        if !matches!(root.value, Value::Map(_)) {
            return Err(PlanError::ObjectFile {
                path: path.clone(),
                problem: format!(
                    "the file holds a {}, not one mapping of keys",
                    root.value.type_name()
                ),
            });
        }
        let data = Json::from_node(&root);
        let name = match data.get("name") {
            Some(Json::Str(name)) => name.clone(),
            Some(other) => other.to_compact(),
            None => return Err(PlanError::Failed("'name'".to_owned())),
        };
        let uuid = object_uuid(&data).ok_or_else(|| PlanError::Failed("'uuid'".to_owned()))?;
        let mut chosen: Vec<String> = Vec::new();
        if let Some(Json::Object(configurations)) = data.get("configurations") {
            for (platform, block) in configurations {
                let status = block
                    .get("status")
                    .filter(|status| status.truthy())
                    .map(|status| match status {
                        Json::Str(text) => text.clone(),
                        other => other.to_compact(),
                    })
                    .ok_or_else(|| {
                        // The oracle's `get_platform_status` logs it, then raises.
                        let detail = format!(
                            "Rule {} ({uuid}) has no 'status' in its {platform} configuration \
                             block. Add a status, e.g. 'status: STAGING', then re-run 'opentide \
                             validate'.",
                            crate::strategy::python_repr(&name)
                        );
                        tracing::error!(
                            detail = detail.as_str(),
                            system = platform.as_str(),
                            rule = name.as_str(),
                            uuid = uuid.as_str(),
                            "platform_status_missing"
                        );
                        PlanError::Failed(crate::strategy::python_repr(&format!(
                            "{} ({uuid}): configurations.{platform}.status is required for \
                             deployment",
                            crate::strategy::python_repr(&name)
                        )))
                    })?;
                if !options.enabled.iter().any(|known| known == platform) {
                    // Logged whatever `log` says: `make_deploy_plan` logs it
                    // for every caller, a deploy too.
                    tracing::warn!(
                        system = platform.to_uppercase().as_str(),
                        rule = name.as_str(),
                        advice = format!(
                            "enable it with 'opentide setup platforms --{}'",
                            platform.replace('_', "-")
                        )
                        .as_str(),
                        logger = "opentide.deployment.utils",
                        "system_disabled_for_deploy"
                    );
                    continue;
                }
                let strategy = statuses.strategy(&status).map_err(|error| {
                    PlanError::Failed(match error {
                        StatusError::Invalid(message) => message,
                        StatusError::Unknown(_) => error.exception_text(),
                    })
                })?;
                if !options.keep_deprecated
                    && matches!(
                        strategy,
                        StatusStrategy::Deletion | StatusStrategy::Disablement
                    )
                {
                    continue;
                }
                if options.wide || options.runs.iter().any(|run| deploys(strategy, *run)) {
                    chosen.push(platform.clone());
                } else {
                    if options.log {
                        let deployed: Vec<&str> = crate::strategy::deployed_by(strategy)
                            .iter()
                            .map(|run| run.name())
                            .collect();
                        let deployed = if deployed.is_empty() {
                            "no run".to_owned()
                        } else {
                            deployed.join(", ")
                        };
                        tracing::warn!(
                            system = platform.to_uppercase().as_str(),
                            status = status.as_str(),
                            strategy = strategy.name(),
                            run_strategies = run_names.as_str(),
                            deployed_by = deployed.as_str(),
                            rule = name.as_str(),
                            logger = "opentide.deployment.utils",
                            "rule_skipped_for_strategy"
                        );
                    }
                    selection.skipped.push(Skipped {
                        rule: name.clone(),
                        uuid: uuid.clone(),
                        platform: platform.clone(),
                        status: status.clone(),
                        strategy: strategy.name().to_owned(),
                    });
                }
            }
        }
        if !chosen.is_empty() {
            let legacy = legacy_keys(&data);
            if !legacy.is_empty() {
                let keys: Vec<String> = legacy
                    .iter()
                    .map(|(platform, key)| format!("configurations.{platform}.{key}"))
                    .collect();
                if options.log {
                    let detail = format!(
                        "rule {uuid} still carries vendor ids on the rule ({}); deploy reads \
                         them only from .opentide/states/deployment/",
                        keys.join(", ")
                    );
                    tracing::error!(
                        detail = detail.as_str(),
                        code = "external_id_in_rule",
                        uuid = uuid.as_str(),
                        platform = "*",
                        tenant = "",
                        advice = MIGRATE_ADVICE,
                        logger = "opentide.deployment.external_ids",
                        "external_id_in_rule"
                    );
                }
                selection.warnings.push(format!(
                    "external_id_in_rule: rule {uuid} still carries vendor ids on the rule ({}); \
                     deploy reads them only from .opentide/states/deployment/ -- {} was not \
                     deployed to any platform",
                    keys.join(", "),
                    path.display()
                ));
                selection.refused.push(uuid);
                continue;
            }
        }
        for platform in chosen {
            selection
                .platforms
                .entry(platform)
                .or_default()
                .push(uuid.clone());
        }
    }
    if !selection.refused.is_empty() && selection.platforms.is_empty() {
        return Err(PlanError::Failed(format!(
            "external_id_in_rule: {} rule(s) still carry vendor rule ids ({}) and nothing else \
             is left to deploy. Run 'opentide deploy migrate-state' and commit the result.",
            selection.refused.len(),
            selection.refused.join(", ")
        )));
    }
    Ok(selection)
}

/// A configured tenant as the plan reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    /// `name`.
    pub name: String,
    /// `strategies`: every deployable one when unset.
    pub strategies: RunStrategies,
    /// `manual`.
    pub manual: bool,
}

impl Tenant {
    /// The tenant a configuration table describes.
    pub fn from_json(tenant: &Json) -> Self {
        let name = match tenant.get("name") {
            Some(Json::Str(name)) => name.clone(),
            Some(other) => other.to_compact(),
            None => String::new(),
        };
        let strategies = match tenant.get("strategies") {
            Some(Json::Array(items)) => crate::strategy::DEPLOYABLE
                .into_iter()
                .filter(|strategy| {
                    items.iter().any(|item| {
                        item.as_str()
                            .is_some_and(|text| text.trim().eq_ignore_ascii_case(strategy.name()))
                    })
                })
                .collect(),
            _ => crate::strategy::DEPLOYABLE.to_vec(),
        };
        let manual = matches!(tenant.get("manual"), Some(Json::Bool(true)));
        Self {
            name,
            strategies,
            manual,
        }
    }

    /// Whether a run with `runs` deploys a `rule` rule here (`accepts`).
    pub fn accepts(&self, rule: StatusStrategy, runs: &[StatusStrategy]) -> bool {
        runs.iter()
            .filter(|run| self.strategies.contains(run))
            .any(|run| deploys(rule, *run))
    }
}

/// Why a rule block does not select a tenant, or `None` when it does
/// (`tenant_skip_reason`): a block that lists `tenants` selects only those;
/// otherwise every tenant that is not `manual`. The planner and the
/// documentation's Deployment section both read it here, so a page never
/// says a rule reaches a tenant that deploy skips.
pub fn tenant_skip_reason(name: &str, manual: bool, listed: &[String]) -> Option<&'static str> {
    if !listed.is_empty() {
        return (!listed.iter().any(|item| item == name)).then_some("not listed by the rule");
    }
    manual.then_some("manual tenant: only rules that list it under tenants reach it")
}

/// The tenants a rule's block reaches (`tenants_resolver`): those listed by
/// the block when it lists any, else every tenant that is not `manual`, each
/// when it accepts a run strategy that deploys the block's status.
pub fn rule_tenants<'t>(
    tenants: &'t [Tenant],
    block: &Json,
    strategy: StatusStrategy,
    runs: &[StatusStrategy],
    wide: bool,
) -> Vec<&'t Tenant> {
    let listed: Vec<String> = match block.get("tenants") {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    tenants
        .iter()
        .filter(|tenant| tenant_skip_reason(&tenant.name, tenant.manual, &listed).is_none())
        .filter(|tenant| {
            if wide {
                runs.iter().any(|run| tenant.strategies.contains(run))
            } else {
                tenant.accepts(strategy, runs)
            }
        })
        .collect()
}

/// One rule on one tenant (`PlannedChange`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The platform.
    pub platform: String,
    /// The tenant; `None` when the platform has none.
    pub tenant: Option<String>,
    /// The rule's UUID.
    pub uuid: String,
    /// Its name.
    pub name: String,
    /// The block's status.
    pub status: String,
    /// `create`, `update`, `upsert`, `disable` or `delete`.
    pub action: &'static str,
    /// A dry run could not compile it.
    pub fails: bool,
}

/// The actions, in tally order, with their words in a plan.
pub const ACTIONS: [(&str, &str); 5] = [
    ("create", "to create"),
    ("update", "to update"),
    ("upsert", "to create or update"),
    ("disable", "to disable"),
    ("delete", "to delete"),
];

impl Change {
    /// The entry of the result's `changes` list.
    pub fn to_json(&self) -> Json {
        let mut row = Object::new();
        row.insert("platform".into(), self.platform.clone().into());
        row.insert(
            "tenant".into(),
            self.tenant.clone().map_or(Json::Null, Json::Str),
        );
        row.insert("uuid".into(), self.uuid.clone().into());
        row.insert("name".into(), self.name.clone().into());
        row.insert("status".into(), self.status.clone().into());
        row.insert("action".into(), self.action.into());
        if self.fails {
            row.insert("fails".into(), Json::Bool(true));
        }
        Json::Object(row)
    }
}

/// The external id the deployment state holds for a rule on a tenant: `None`
/// when the shard is absent or cannot be used.
pub fn state_id(
    fs: &dyn FileSystem,
    workspace: &Path,
    uuid: &str,
    platform: &str,
    tenant: &str,
) -> Option<String> {
    state_ids(fs, workspace, uuid)?
        .get(platform)?
        .get(tenant.trim())
        .filter(|id| !id.is_empty())
        .cloned()
}

/// Every external id the deployment state holds for a rule, by platform
/// then tenant, in the shard's order: `None` when the shard is absent or
/// cannot be used (another spelling of it exists, its schema or UUID is
/// not the rule's, a platform stores no ids, an id is not text, a tenant
/// key is blank or padded).
pub fn state_ids(
    fs: &dyn FileSystem,
    workspace: &Path,
    uuid: &str,
) -> Option<IndexMap<String, IndexMap<String, String>>> {
    let canonical = canonical_uuid(uuid);
    let dir = workspace.join(".opentide/states/deployment");
    let names: Vec<String> = fs
        .read_dir(&dir)
        .ok()?
        .into_iter()
        .map(|entry| entry.name.clone())
        .collect();
    let file = format!("{canonical}.json");
    // Another spelling of the same rule's shard makes the state unusable.
    let variants = names.iter().any(|name| {
        let stem = name
            .len()
            .checked_sub(5)
            .filter(|at| name.is_char_boundary(*at))
            .filter(|at| name[*at..].eq_ignore_ascii_case(".json"))
            .map(|at| &name[..at]);
        name != &file && stem.is_some_and(|stem| canonical_uuid(stem) == canonical)
    });
    if variants || !names.contains(&file) {
        return None;
    }
    let bytes = fs.read(&dir.join(&file)).ok()?;
    let payload: Json = serde_json::from_slice(&bytes).ok()?;
    if payload.get("schema")?.as_str()? != "deployment.state::1.0"
        || payload.get("object_uuid")?.as_str()? != canonical
    {
        return None;
    }
    let mut found = IndexMap::new();
    for (name, tenants) in payload.get("platforms")?.as_object()? {
        if !opentide_workspace::state::stores_ids(name) {
            return None;
        }
        let mut ids = IndexMap::new();
        for (key, id) in tenants.as_object()? {
            let id = id.as_str()?;
            if key.trim().is_empty() || key.trim() != key {
                return None;
            }
            ids.insert(key.clone(), id.to_owned());
        }
        found.insert(name.clone(), ids);
    }
    Some(found)
}

/// What a change does (`_action`).
pub fn action(
    statuses: &Statuses,
    platform: &str,
    has_tenant: bool,
    status: &str,
    known: &dyn Fn() -> Option<String>,
) -> &'static str {
    match statuses.strategy(status) {
        Ok(StatusStrategy::Deletion) => return "delete",
        Ok(StatusStrategy::Disablement) => return "disable",
        _ => {}
    }
    // A platform plugin records the ids its platform gives, as the built-in
    // platforms of `STATE_PLATFORMS` do (UC-4.5b).
    if !opentide_workspace::state::stores_ids(platform) {
        return "upsert";
    }
    if !has_tenant {
        return "create";
    }
    if known().is_some() {
        "update"
    } else {
        "create"
    }
}

/// Changes per action, every action present; a change that would fail counts
/// under none.
pub fn tally(changes: &[Change]) -> IndexMap<&'static str, usize> {
    ACTIONS
        .iter()
        .map(|(action, _)| {
            (
                *action,
                changes
                    .iter()
                    .filter(|change| !change.fails && change.action == *action)
                    .count(),
            )
        })
        .collect()
}

/// `Plan: 1 to create, 0 to update, 0 to disable, 0 to delete` (`plan_message`).
pub fn message(changes: &[Change]) -> String {
    let counts = tally(changes);
    let mut parts: Vec<String> = ACTIONS
        .iter()
        .filter(|(action, _)| *action != "upsert" || counts[action] > 0)
        .map(|(action, words)| format!("{} {words}", counts[action]))
        .collect();
    let failing = changes.iter().filter(|change| change.fails).count();
    if failing > 0 {
        parts.push(format!("{failing} would fail"));
    }
    format!("Plan: {}", parts.join(", "))
}

/// The plan's JSON `summary` (`plan_summary`).
pub fn summary(changes: &[Change], platforms: usize, tenants: usize) -> Json {
    let mut out = Object::new();
    for (action, count) in tally(changes) {
        out.insert(action.into(), Json::Int(as_int(count)));
    }
    out.insert("platforms".into(), Json::Int(as_int(platforms)));
    out.insert("tenants".into(), Json::Int(as_int(tenants)));
    let failing = changes.iter().filter(|change| change.fails).count();
    if failing > 0 {
        out.insert("fail".into(), Json::Int(as_int(failing)));
    }
    Json::Object(out)
}

/// `1 platform, 0 tenants` (`plan_scope`).
pub fn scope_text(platforms: usize, tenants: usize) -> String {
    format!(
        "{}, {}",
        plural(platforms, "platform"),
        plural(tenants, "tenant")
    )
}

fn as_int(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// The variable a configuration value names when it is `$NAME` or `${NAME}`
/// as a whole (`env_reference`).
pub fn env_reference(value: &str) -> Option<&str> {
    let name = value.strip_prefix('$')?;
    let name = match name.strip_prefix('{') {
        Some(braced) => braced.strip_suffix('}')?,
        None => name,
    };
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(name)
}

/// The unset variables the tenants' `setup` of `platforms` name, in the order
/// the oracle reads them, each once.
pub fn unset_variables(
    config: &Json,
    platforms: &[&str],
    is_set: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for platform in platforms {
        for tenant in tenants(config, platform) {
            let Some(Json::Object(setup)) = tenant.get("setup") else {
                continue;
            };
            for value in setup.values() {
                if let Some(name) = value.as_str().and_then(env_reference)
                    && !is_set(name)
                    && !names.iter().any(|known| known == name)
                {
                    names.push(name.to_owned());
                }
            }
        }
    }
    names
}

/// `a real deploy would need $A and $B, which are unset`
/// (`unset_variables_warning`), counting past three.
pub fn unset_warning(names: &[String]) -> String {
    let shown: Vec<String> = names.iter().map(|name| format!("${name}")).collect();
    if shown.len() > 3 {
        return format!(
            "a real deploy would need {} variables that are unset: {} and {} more; opentide \
             doctor lists them by tenant",
            shown.len(),
            shown[..3].join(", "),
            shown.len() - 3
        );
    }
    let listed = match shown.as_slice() {
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
        [] => String::new(),
    };
    let which = if shown.len() == 1 {
        "which is unset"
    } else {
        "which are unset"
    };
    format!("a real deploy would need {listed}, {which}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use StatusStrategy::{Deletion, Preview, Release, Universal};

    fn json(yaml: &str) -> Json {
        Json::from_node(opentide_schema::node::load(yaml).unwrap().root().unwrap())
    }

    #[test]
    fn tenants_are_skipped_as_the_oracle_skips_them() {
        let listed = ["a".to_owned()];
        assert_eq!(tenant_skip_reason("a", true, &listed), None);
        assert_eq!(
            tenant_skip_reason("b", false, &listed),
            Some("not listed by the rule")
        );
        assert_eq!(
            tenant_skip_reason("m", true, &[]),
            Some("manual tenant: only rules that list it under tenants reach it")
        );
        assert_eq!(tenant_skip_reason("m", false, &[]), None);
    }

    #[test]
    fn tenants_take_the_rules_their_strategies_deploy() {
        let preview = Tenant::from_json(&json("{name: p, strategies: [preview]}"));
        let release = Tenant::from_json(&json("{name: r, strategies: [' RELEASE ']}"));
        let manual = Tenant::from_json(&json("{name: m, manual: true}"));
        assert_eq!(manual.strategies, vec![Preview, Release]);
        let all = [preview, release, manual];
        let names = |found: Vec<&Tenant>| found.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
        let block = json("{status: X}");
        assert_eq!(
            names(rule_tenants(&all, &block, Preview, &[Preview], false)),
            ["p"]
        );
        assert_eq!(
            names(rule_tenants(
                &all,
                &block,
                Universal,
                &[Preview, Release],
                false
            )),
            ["p", "r"]
        );
        assert_eq!(
            names(rule_tenants(&all, &block, Deletion, &[Release], false)),
            ["r"]
        );
        let listed = json("{status: X, tenants: [m]}");
        assert_eq!(
            names(rule_tenants(&all, &listed, Preview, &[Preview], false)),
            ["m"]
        );
    }

    #[test]
    fn messages_are_the_oracles() {
        let change = |action: &'static str, fails: bool| Change {
            platform: "sentinel".into(),
            tenant: None,
            uuid: "u".into(),
            name: "n".into(),
            status: "S".into(),
            action,
            fails,
        };
        let changes = [
            change("create", false),
            change("upsert", false),
            change("upsert", true),
        ];
        assert_eq!(
            message(&changes),
            "Plan: 1 to create, 0 to update, 1 to create or update, 0 to disable, 0 to delete, 1 \
             would fail"
        );
        assert_eq!(
            summary(&changes, 2, 1).to_compact(),
            r#"{"create":1,"update":0,"upsert":1,"disable":0,"delete":0,"platforms":2,"tenants":1,"fail":1}"#
        );
        assert_eq!(
            message(&[]),
            "Plan: 0 to create, 0 to update, 0 to disable, 0 to delete"
        );
        assert_eq!(scope_text(1, 0), "1 platform, 0 tenants");
    }

    #[test]
    fn unset_variables_are_named_once() {
        assert_eq!(env_reference("$A_1"), Some("A_1"));
        assert_eq!(env_reference("${B}"), Some("B"));
        assert_eq!(env_reference("$uP3r-S3cret!"), None);
        assert_eq!(env_reference("$1"), None);
        assert_eq!(
            unset_warning(&["A".into(), "B".into()]),
            "a real deploy would need $A and $B, which are unset"
        );
        assert_eq!(
            unset_warning(&["A".into()]),
            "a real deploy would need $A, which is unset"
        );
        assert_eq!(
            unset_warning(&["A".into(), "B".into(), "C".into(), "D".into()]),
            "a real deploy would need 4 variables that are unset: $A, $B, $C and 1 more; \
             opentide doctor lists them by tenant"
        );
    }

    #[test]
    fn the_state_is_read_only_from_the_one_canonical_shard() {
        let fs = opentide_workspace::MemoryFs::new();
        let uuid = "0000000a-0000-4000-8000-00000000000b";
        let shard = format!(
            "{{\"schema\": \"deployment.state::1.0\", \"object_uuid\": \"{uuid}\", \
             \"platforms\": {{\"crowdstrike\": {{\"t\": \"42\"}}}}}}"
        );
        let dir = "/ws/.opentide/states/deployment";
        fs.write(format!("{dir}/{uuid}.json"), shard.clone());
        fs.write(format!("{dir}/\u{212a}é.json"), "{}");
        let root = Path::new("/ws");
        assert_eq!(
            state_id(&fs, root, uuid, "crowdstrike", "t").as_deref(),
            Some("42")
        );
        assert_eq!(state_id(&fs, root, uuid, "crowdstrike", "other"), None);
        assert_eq!(state_id(&fs, root, uuid, "sentinel_one", "t"), None);
        // Another spelling of the same rule's shard makes the state unusable.
        fs.write(format!("{dir}/{}.JSON", uuid.to_uppercase()), shard);
        assert_eq!(state_id(&fs, root, uuid, "crowdstrike", "t"), None);
    }

    #[test]
    fn a_plugins_platform_is_planned_when_enabled_and_its_id_read_from_state() {
        let config: Json = serde_json::from_str(
            r#"{"platforms": {"acme": {"platform": {"enabled": true}}, "other": {"platform": {"enabled": false}}, "sentinel": {"platform": {"enabled": true}}}}"#,
        )
        .unwrap();
        let plugins = ["other".to_owned(), "acme".to_owned(), "sentinel".to_owned()];
        assert_eq!(enabled_with(&config, &plugins), ["sentinel", "acme"]);
        assert_eq!(enabled(&config), ["sentinel"]);
        let fs = opentide_workspace::MemoryFs::new();
        let uuid = "0000000a-0000-4000-8000-00000000000b";
        fs.write(
            format!("/ws/.opentide/states/deployment/{uuid}.json"),
            format!(
                "{{\"schema\": \"deployment.state::1.0\", \"object_uuid\": \"{uuid}\", \
                 \"platforms\": {{\"acme\": {{\"lab\": \"acme-rule-17\"}}}}}}"
            ),
        );
        assert_eq!(
            state_id(&fs, Path::new("/ws"), uuid, "acme", "lab").as_deref(),
            Some("acme-rule-17")
        );
    }

    #[test]
    fn nested_files_are_named_up_to_five() {
        let nested: Vec<String> = (0..7)
            .map(|n| format!("objects/rules/x/{n}.yaml"))
            .collect();
        let warning = nested_warning(&nested, "objects/rules");
        assert!(warning.starts_with("7 rule file(s) in subfolders of objects/rules"));
        assert!(warning.ends_with("objects/rules/x/4.yaml, +2 more"));
    }
}
