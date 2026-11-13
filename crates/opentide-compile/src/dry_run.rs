//! `deploy --dry-run`'s result (`cli/services/deploy.py` `run_deploy` with
//! `dry_run`): the plan, every planned change, the tenants each rule reaches,
//! and each rule's payload, with the warnings a real run would hit.
//!
//! The keys are the command's result payload, in the oracle's order; the
//! CLI wraps them in its envelope. Nothing is sent and nothing is written.

use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use opentide_schema::node::Node;
use opentide_workspace::{FileSystem, Workspace};

use crate::json::{Json, Object};
use crate::plan::{self, Change, PlanError, Scope, SelectOptions, Tenant};
use crate::preview;
use crate::rule::Rule;
use crate::strategy::{self, RunStrategies, StatusStrategy};
use crate::{Context, Owned};

/// What the run was asked.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// `--strategy` values, as typed.
    pub strategies: Vec<String>,
    /// `--all`.
    pub all: bool,
    /// `--uuid` values.
    pub uuids: Vec<String>,
    /// `--file` values.
    pub files: Vec<String>,
    /// `--platform`.
    pub platform: Option<String>,
    /// `--wide`.
    pub wide: bool,
    /// `--keep-deprecated` / `--drop-deprecated`; `None` when neither.
    pub keep_deprecated: Option<bool>,
    /// `DEPLOYMENT_PLAN`, when set.
    pub removed_plan: Option<String>,
    /// The working directory: where relative `--file` values start and
    /// paths are shown from.
    pub cwd: PathBuf,
    /// The platform plugins the run can reach (UC-4.5b, #835): planned as a
    /// built-in platform is when the configuration enables them, each change
    /// a create or an update from deployment state.
    pub plugins: Vec<String>,
}

/// The rule files the run changed, when it reads neither `--all` nor a
/// selection: the git baseline's answer (`modified_rule_scope`), with the
/// warning a checkout without commits gives. `rules` is the rules folder,
/// `folder` as the workspace spells it.
pub type ChangedScope<'a> = &'a dyn Fn(&Path, &str) -> Result<(Scope, Option<String>), String>;

/// The changed rule files from the git baseline ([`crate::git`]), for the
/// environment `env`.
pub fn git_scope(
    workspace: &Path,
    cwd: &Path,
    env: crate::git::Env<'_>,
    rules: &Path,
    folder: &str,
) -> Result<(Scope, Option<String>), String> {
    let source = crate::git::diff_source(env);
    let changed =
        crate::git::changed_paths(workspace, cwd, env, source).map_err(|error| error.message())?;
    let (top, nested) = crate::git::split_rule_paths(&changed, folder);
    let files = top
        .iter()
        .filter_map(|path| Path::new(path).file_name().map(|name| rules.join(name)))
        .collect();
    let scope = Scope { files, nested };
    let warning = if scope.files.is_empty() && scope.nested.is_empty() {
        crate::git::no_commits_warning(
            workspace,
            env,
            "commit the rules, or pass --all to read every rule file",
        )
    } else {
        None
    };
    Ok((scope, warning))
}

/// A failure the CLI reports with a code and an exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    /// `failure.code`.
    pub code: &'static str,
    /// The option at fault.
    pub argument: Option<&'static str>,
    /// The closest valid value.
    pub suggestion: Option<String>,
}

/// The run's result.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The payload's keys, in order (`deployed`, `dry_run`, `plan`, ...).
    pub payload: Object,
    /// The process exit code.
    pub exit_code: i32,
    /// The counts behind the outcome (`_summary`).
    pub summary: Option<Json>,
    /// `_outcome_kind`: `plan` for a plan.
    pub outcome_kind: Option<&'static str>,
    /// `_outcome`: the outcome line, when the run sets it.
    pub outcome_line: Option<String>,
    /// A usage failure (exit 2).
    pub usage: Option<Usage>,
}

impl Outcome {
    fn failed(message: impl Into<String>, exit_code: i32) -> Self {
        let mut payload = Object::new();
        payload.insert("status".into(), "failed".into());
        payload.insert("message".into(), message.into().into());
        Self {
            payload,
            exit_code,
            summary: None,
            outcome_kind: None,
            outcome_line: None,
            usage: None,
        }
    }

    fn usage(message: String, usage: Usage) -> Self {
        let mut outcome = Self::failed(message, 2);
        outcome.usage = Some(usage);
        outcome
    }
}

/// The CLI's answer when `--strategy` is missing.
pub const STRATEGY_REQUIRED: &str = "Pass --strategy: PREVIEW deploys the rules whose status maps \
     to PREVIEW (the pull or merge request job), RELEASE deploys and retires the rules whose \
     status maps to RELEASE, DISABLEMENT or DELETION (the default-branch job). Rules whose status \
     maps to UNIVERSAL are deployed by both. See 'opentide deploy --help'.";

/// Nothing matched the run's strategies.
pub const NO_RULES_MATCHED: &str = "No rule this run read has a status that maps to its strategies";

/// The deployable strategy closest to the first `--strategy` value that is
/// not one (`strategy_suggestion`).
pub fn strategy_suggestion(values: &[String]) -> Option<String> {
    let names: Vec<&str> = strategy::DEPLOYABLE.iter().map(|s| s.name()).collect();
    for raw in values {
        for part in raw.split(',') {
            let value = part.trim();
            if !value.is_empty() && !names.contains(&value.to_uppercase().as_str()) {
                return opentide_core::suggest::closest(value, names.iter().copied())
                    .map(str::to_owned);
            }
        }
    }
    None
}

/// The rules folder, and as the workspace spells it (`rules_folder_in_repo`).
pub fn rules_folder(workspace: &Workspace) -> (PathBuf, String) {
    let folder = workspace
        .configuration()
        .folder("rule")
        .map(Path::to_path_buf)
        .unwrap_or_else(|| workspace.root().join("objects/rules"));
    let spelled = folder
        .strip_prefix(workspace.root())
        .map(opentide_workspace::index::posix)
        .unwrap_or_else(|_| opentide_workspace::index::posix(&folder));
    (folder, spelled)
}

/// The rule files `--file` and `--uuid` (`request.files`, `request.uuids`)
/// select among `local`'s, and each value that selects none
/// (`_selected_rule_scope`); `deploy` and `validate query` share it.
pub fn selected_scope(
    fs: &dyn FileSystem,
    workspace: &Workspace,
    local: &Scope,
    request: &Request,
    cwd: &Path,
) -> (Scope, Vec<String>) {
    let mut targets: Vec<(String, String, Vec<PathBuf>)> = Vec::new();
    let mut sorted_files = request.files.clone();
    sorted_files.sort();
    for target in &sorted_files {
        let raw = target.trim();
        let as_path = Path::new(raw);
        let name = as_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let bare = raw.is_empty() || raw == "." || (name == raw && !as_path.is_absolute());
        let resolved = if bare {
            Vec::new()
        } else if as_path.is_absolute() {
            vec![fs.resolve(as_path)]
        } else {
            vec![
                fs.resolve(&cwd.join(as_path)),
                fs.resolve(&workspace.root().join(as_path)),
            ]
        };
        targets.push((
            target.clone(),
            if bare { raw.to_owned() } else { name },
            resolved,
        ));
    }
    let wanted: IndexMap<String, String> = request
        .uuids
        .iter()
        .map(|uuid| (uuid.trim().to_lowercase(), uuid.clone()))
        .collect();
    let file_names: Vec<&str> = targets
        .iter()
        .filter(|(_, _, resolved)| resolved.is_empty())
        .map(|(_, name, _)| name.as_str())
        .collect();
    let file_paths: Vec<&PathBuf> = targets.iter().flat_map(|(_, _, paths)| paths).collect();
    let mut found: Vec<String> = Vec::new();
    let mut selected = Scope::default();
    for path in &local.files {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut chosen = !request.files.is_empty()
            && (file_paths.contains(&&fs.resolve(path)) || file_names.contains(&name.as_str()));
        if !wanted.is_empty() {
            let uuid = fs
                .read(path)
                .ok()
                .and_then(|bytes| opentide_schema::node::load_bytes(&bytes).ok())
                .and_then(|document| document.root().map(|root| Json::from_node(root)))
                .and_then(|data| {
                    data.get("uuid")
                        .filter(|value| value.truthy())
                        .or_else(|| data.get("metadata").and_then(|m| m.get("uuid")))
                        .and_then(Json::as_str)
                        .map(|uuid| uuid.trim().to_lowercase())
                })
                .unwrap_or_default();
            if wanted.contains_key(&uuid) {
                found.push(uuid);
                chosen = true;
            }
        }
        if chosen {
            selected.files.push(path.clone());
        }
    }
    let mut unmatched: Vec<String> = targets
        .iter()
        .filter(|(_, name, resolved)| {
            !local.files.iter().any(|path| {
                if resolved.is_empty() {
                    path.file_name()
                        .is_some_and(|own| own.to_string_lossy() == name.as_str())
                } else {
                    resolved.contains(&fs.resolve(path))
                }
            })
        })
        .map(|(raw, _, _)| raw.clone())
        .collect();
    unmatched.extend(
        wanted
            .iter()
            .filter(|(key, _)| !found.contains(key))
            .map(|(_, raw)| raw.clone()),
    );
    (selected, unmatched)
}

/// A platform's configuration path, as the advice names it (`platform_config_path`).
fn config_path(fs: &dyn FileSystem, workspace: &Workspace, platform: &str) -> String {
    let candidate = workspace
        .root()
        .join(".opentide/configurations/platforms")
        .join(format!("{platform}.toml"));
    if fs.is_file(&candidate) {
        return format!(".opentide/configurations/platforms/{platform}.toml");
    }
    format!(".opentide/configurations/platforms/{platform}.toml")
}

/// Runs a dry run. `changed` answers the rule files the run changed;
/// `is_set` whether an environment variable is set.
pub fn run(
    workspace: &Workspace,
    owned: &Owned,
    request: &Request,
    changed: ChangedScope<'_>,
    is_set: &dyn Fn(&str) -> bool,
) -> Outcome {
    let fs = workspace.fs().as_ref();
    if let Some(value) = request
        .removed_plan
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        return Outcome::usage(
            strategy::removed_plan_message(Some(value), false),
            Usage {
                code: "usage_invalid_value",
                argument: None,
                suggestion: None,
            },
        );
    }
    if request.strategies.is_empty() {
        return Outcome::usage(
            STRATEGY_REQUIRED.to_owned(),
            Usage {
                code: "usage_missing_option",
                argument: Some("--strategy"),
                suggestion: None,
            },
        );
    }
    let runs: RunStrategies =
        match strategy::parse_strategies(&request.strategies, &owned.statuses, "--strategy") {
            Ok(runs) => runs,
            Err(message) => {
                return Outcome::usage(
                    message,
                    Usage {
                        code: "usage_invalid_choice",
                        argument: Some("--strategy"),
                        suggestion: strategy_suggestion(&request.strategies),
                    },
                );
            }
        };
    let (rules_dir, folder) = rules_folder(workspace);
    let local = plan::local_scope(fs, &rules_dir, &folder);
    let selecting = !request.uuids.is_empty() || !request.files.is_empty();
    let mut no_commits: Option<String> = None;
    let scope = if selecting {
        let (scope, unmatched) = selected_scope(fs, workspace, &local, request, &request.cwd);
        if !unmatched.is_empty() {
            let mut outcome = Outcome::failed(
                format!(
                    "No rule file directly in {folder} matched: {}",
                    unmatched.join(", ")
                ),
                1,
            );
            outcome.payload.insert("scope".into(), "selected".into());
            outcome.payload.insert("unmatched".into(), unmatched.into());
            outcome.payload.insert("dry_run".into(), Json::Bool(true));
            return outcome;
        }
        scope
    } else if request.all {
        local
    } else {
        match changed(&rules_dir, &folder) {
            Ok((scope, warning)) => {
                no_commits = warning;
                scope
            }
            Err(message) => {
                let mut outcome = Outcome::failed(message, 1);
                let mut own = Vec::new();
                let mut warnings = Vec::new();
                finish_failure(
                    &mut outcome,
                    workspace,
                    &request.cwd,
                    &mut warnings,
                    &mut own,
                );
                return outcome;
            }
        }
    };
    let enabled = plan::enabled_with(
        &Json::from_node(&workspace.configuration().resolved.tree),
        &request.plugins,
    );
    let read = |path: &Path| -> Result<Node, String> {
        let bytes = fs.read(path).map_err(|error| error.to_string())?;
        let document =
            opentide_schema::node::load_bytes(&bytes).map_err(|error| error.to_string())?;
        document
            .root()
            .map(|root| (**root).clone())
            .ok_or_else(|| "the file is empty".to_owned())
    };
    let keep_deprecated = request.keep_deprecated.unwrap_or(!request.all);
    let selection = plan::select(
        &owned.statuses,
        &scope,
        &read,
        &SelectOptions {
            runs: &runs,
            wide: request.wide,
            keep_deprecated,
            enabled: &enabled,
            folder: &folder,
            log: false,
        },
    );
    let mut selection = match selection {
        Ok(selection) => selection,
        Err(PlanError::ObjectFile { path, problem }) => {
            return Outcome::failed(format!("{}: {problem}", path.display()), 1);
        }
        Err(PlanError::Failed(message)) => {
            let mut outcome = Outcome::failed(message, 1);
            if selecting {
                // `run_deploy` names a selection's scope on a failed plan too.
                outcome.payload.insert("scope".into(), "selected".into());
            }
            let mut warnings: Vec<String> = no_commits.into_iter().collect();
            if !scope.nested.is_empty() {
                warnings.push(plan::nested_warning(&scope.nested, &folder));
            }
            finish_failure(
                &mut outcome,
                workspace,
                &request.cwd,
                &mut warnings,
                &mut Vec::new(),
            );
            return outcome;
        }
    };
    if let Some(warning) = no_commits {
        selection.warnings.insert(0, warning);
    }
    let config = Json::from_node(&workspace.configuration().resolved.tree);
    let index = workspace.index();
    let cx: Context<'_> = owned.context(index);
    let run_names: Vec<String> = runs.iter().map(|run| run.name().to_owned()).collect();
    let mut warnings = selection.warnings.clone();
    let failed_before = !selection.refused.is_empty();
    let mut deployment = selection.platforms.clone();
    if let Some(platform) = &request.platform {
        match deployment.shift_remove(platform) {
            Some(uuids) => {
                deployment = IndexMap::from([(platform.clone(), uuids)]);
            }
            None => {
                return nothing(
                    "No rules to deploy for this platform",
                    failed_before,
                    Some(("platform", Json::from(platform.as_str()))),
                    &selection,
                    &mut warnings,
                    &runs,
                    &owned.statuses,
                    workspace,
                    &config,
                    is_set,
                    &request.cwd,
                );
            }
        }
    }
    if deployment.is_empty() {
        return nothing(
            NO_RULES_MATCHED,
            failed_before,
            Some(("strategies", Json::from(run_names.clone()))),
            &selection,
            &mut warnings,
            &runs,
            &owned.statuses,
            workspace,
            &config,
            is_set,
            &request.cwd,
        );
    }
    let plan_payload: Object = deployment
        .iter()
        .map(|(platform, uuids)| (platform.clone(), Json::from(uuids.clone())))
        .collect();
    let tenantless: Vec<&String> = deployment
        .keys()
        .filter(|platform| plan::tenants(&config, platform).is_empty())
        .collect();
    let missing: Object = tenantless
        .iter()
        .map(|platform| {
            (
                (*platform).clone(),
                Json::from(config_path(fs, workspace, platform)),
            )
        })
        .collect();
    let advice = tenantless
        .iter()
        .map(|platform| {
            format!(
                "add (or uncomment) a [[tenants]] entry in {}",
                config_path(fs, workspace, platform)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    // Tenants each rule reaches, per platform with tenants.
    let mut targets: IndexMap<String, IndexMap<String, Vec<String>>> = IndexMap::new();
    for (platform, uuids) in &deployment {
        if tenantless.contains(&platform) {
            continue;
        }
        let tenants: Vec<Tenant> = plan::tenants(&config, platform)
            .into_iter()
            .map(Tenant::from_json)
            .collect();
        let mut per_tenant: IndexMap<String, Vec<String>> = IndexMap::new();
        for uuid in uuids {
            let Some(rule) = index.get("rule", uuid).and_then(|object| object.root()) else {
                continue;
            };
            let block = Json::from_node(rule)
                .get("configurations")
                .and_then(|configurations| configurations.get(platform))
                .cloned()
                .unwrap_or(Json::Null);
            let status = block
                .get("status")
                .and_then(Json::as_str)
                .unwrap_or_default();
            let Ok(strategy) = owned.statuses.strategy(status) else {
                continue;
            };
            for tenant in plan::rule_tenants(&tenants, &block, strategy, &runs, request.wide) {
                per_tenant
                    .entry(tenant.name.clone())
                    .or_default()
                    .push(crate::rule::canonical_uuid(uuid));
            }
        }
        targets.insert(platform.clone(), per_tenant);
    }
    let workspace_root = workspace.root().to_path_buf();
    let mut planned: Vec<Change> = Vec::new();
    for (platform, uuids) in &deployment {
        let tenants = targets.get(platform).filter(|tenants| !tenants.is_empty());
        let pairs: Vec<(Option<String>, String)> = match tenants {
            Some(tenants) => tenants
                .iter()
                .flat_map(|(tenant, ids)| ids.iter().map(|id| (Some(tenant.clone()), id.clone())))
                .collect(),
            None => uuids.iter().map(|uuid| (None, uuid.clone())).collect(),
        };
        for (tenant, uuid) in pairs {
            let data = index
                .get("rule", &uuid)
                .and_then(|object| object.root())
                .map(Json::from_node);
            let name = data
                .as_ref()
                .and_then(|data| data.get("name"))
                .and_then(Json::as_str)
                .unwrap_or(&uuid)
                .to_owned();
            let status = data
                .as_ref()
                .and_then(|data| data.get("configurations"))
                .and_then(|configurations| configurations.get(platform))
                .and_then(|block| block.get("status"))
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned();
            let known = || match &tenant {
                Some(tenant) => plan::state_id(fs, &workspace_root, &uuid, platform, tenant),
                None => None,
            };
            let action = plan::action(&owned.statuses, platform, tenant.is_some(), &status, &known);
            planned.push(Change {
                platform: platform.clone(),
                tenant,
                uuid,
                name,
                status,
                action,
                fails: false,
            });
        }
    }
    let tenant_count: usize = targets.values().map(IndexMap::len).sum();
    let mut payloads = Object::new();
    let mut deployed: Vec<String> = Vec::new();
    let mut failing: Vec<(String, String)> = Vec::new();
    let mut diagnostics: Vec<Json> = Vec::new();
    for (platform, uuids) in &deployment {
        let mut entries = Vec::new();
        for uuid in uuids {
            let Some(object) = index.get("rule", uuid) else {
                continue;
            };
            let Some(root) = object.root() else {
                continue;
            };
            let rule = Rule::new(root, Some(object.path.to_string_lossy().into_owned()));
            // The tenants this run sends the rule to.
            let reached: Vec<&str> = targets
                .get(platform)
                .into_iter()
                .flatten()
                .filter(|(_, sent)| sent.contains(uuid))
                .map(|(tenant, _)| tenant.as_str())
                .collect();
            let entry = preview::preview_on(&cx, platform, &rule, &reached);
            if entry.get("status").and_then(Json::as_str) == Some("failed") {
                failing.push((platform.clone(), rule.uuid.clone()));
                diagnostics.push(diagnostic(platform, &entry, workspace.root()));
            }
            entries.push(entry);
        }
        payloads.insert(platform.clone(), Json::Array(entries));
        if !tenantless.contains(&platform) {
            deployed.push(platform.clone());
        }
    }
    for change in &mut planned {
        if failing
            .iter()
            .any(|(platform, uuid)| *platform == change.platform && *uuid == change.uuid)
        {
            change.fails = true;
        }
    }
    let failed = failed_before || !diagnostics.is_empty();
    let mut payload = Object::new();
    payload.insert("message".into(), plan::message(&planned).into());
    payload.insert(
        "status".into(),
        if failed { "failed" } else { "completed" }.into(),
    );
    payload.insert("deployed".into(), deployed.into());
    payload.insert("dry_run".into(), Json::Bool(true));
    payload.insert("plan".into(), Json::Object(plan_payload));
    payload.insert(
        "changes".into(),
        Json::Array(planned.iter().map(Change::to_json).collect()),
    );
    if !diagnostics.is_empty() {
        let count = diagnostics.len();
        payload.insert("diagnostics".into(), Json::Array(diagnostics));
        payload.insert(
            "error".into(),
            format!("{} would fail to deploy", plan::plural(count, "rule")).into(),
        );
    }
    let mut own_warnings: Vec<String> = tenantless
        .iter()
        .map(|platform| {
            format!(
                "{platform} has no tenants configured in {}, so a real deploy would stop",
                config_path(fs, workspace, platform)
            )
        })
        .collect();
    if !own_warnings.is_empty() {
        payload.insert("warnings".into(), own_warnings.clone().into());
    }
    payload.insert("strategies".into(), run_names.into());
    payload.insert("payloads".into(), Json::Object(payloads));
    payload.insert(
        "tenants".into(),
        Json::Object(
            targets
                .iter()
                .map(|(platform, tenants)| {
                    (
                        platform.clone(),
                        Json::Object(
                            tenants
                                .iter()
                                .map(|(tenant, ids)| (tenant.clone(), Json::from(ids.clone())))
                                .collect(),
                        ),
                    )
                })
                .collect(),
        ),
    );
    if !missing.is_empty() {
        payload.insert("missing_tenants".into(), Json::Object(missing));
        payload.insert("advice".into(), advice.into());
    }
    let mut outcome = Outcome {
        payload,
        exit_code: i32::from(failed),
        summary: Some(plan::summary(&planned, deployment.len(), tenant_count)),
        outcome_kind: Some("plan"),
        outcome_line: None,
        usage: None,
    };
    finish(
        &mut outcome,
        selecting,
        &mut warnings,
        &mut own_warnings,
        &selection,
        &runs,
        &owned.statuses,
        workspace,
        &config,
        &deployment.keys().map(String::as_str).collect::<Vec<_>>(),
        is_set,
        &request.cwd,
    );
    outcome
}

/// A compile failure as the plan's diagnostic (`compile_diagnostics`).
fn diagnostic(platform: &str, entry: &Json, root: &Path) -> Json {
    let file = entry.get("file").cloned().unwrap_or(Json::Null);
    let path = file
        .as_str()
        .and_then(|file| {
            Path::new(file)
                .strip_prefix(root)
                .ok()
                .map(opentide_workspace::index::posix)
        })
        .map_or(Json::Null, Json::Str);
    let mut out = Object::new();
    out.insert(
        "code".into(),
        entry
            .get("code")
            .filter(|code| code.truthy())
            .cloned()
            .unwrap_or_else(|| crate::rule::codes::COMPILE_FAILED.into()),
    );
    out.insert("severity".into(), "error".into());
    out.insert(
        "message".into(),
        entry.get("error").cloned().unwrap_or(Json::Null),
    );
    out.insert(
        "help".into(),
        entry.get("help").cloned().unwrap_or(Json::Null),
    );
    out.insert("path".into(), path);
    out.insert("file_path".into(), file);
    out.insert("platform".into(), platform.into());
    out.insert(
        "uuid".into(),
        entry.get("uuid").cloned().unwrap_or(Json::Null),
    );
    out.insert(
        "name".into(),
        entry.get("name").cloned().unwrap_or(Json::Null),
    );
    Json::Object(out)
}

/// A run that planned nothing (`_nothing_to_deploy`).
#[expect(
    clippy::too_many_arguments,
    reason = "the oracle's run state, passed through once"
)]
fn nothing(
    message: &str,
    failed: bool,
    field: Option<(&str, Json)>,
    selection: &plan::Selection,
    warnings: &mut Vec<String>,
    runs: &[StatusStrategy],
    statuses: &strategy::Statuses,
    workspace: &Workspace,
    config: &Json,
    is_set: &dyn Fn(&str) -> bool,
    cwd: &Path,
) -> Outcome {
    let mut payload = Object::new();
    if let Some((key, value)) = field {
        payload.insert(key.into(), value);
    }
    payload.insert(
        "status".into(),
        if failed { "failed" } else { "skipped" }.into(),
    );
    payload.insert(
        "message".into(),
        if failed {
            format!("{message}; planning reported rule errors")
        } else {
            message.to_owned()
        }
        .into(),
    );
    payload.insert("deployed".into(), Json::Array(Vec::new()));
    payload.insert("dry_run".into(), Json::Bool(true));
    payload.insert("plan".into(), Json::Object(Object::new()));
    payload.insert("payloads".into(), Json::Object(Object::new()));
    let mut outcome = Outcome {
        payload,
        exit_code: i32::from(failed),
        summary: None,
        outcome_kind: None,
        outcome_line: None,
        usage: None,
    };
    let mut own = Vec::new();
    finish(
        &mut outcome,
        false,
        warnings,
        &mut own,
        selection,
        runs,
        statuses,
        workspace,
        config,
        &[],
        is_set,
        cwd,
    );
    outcome
}

/// What `run_deploy` adds after the plan: the selection's scope, the
/// warnings before the plan's own, and the blocks a status kept out.
#[expect(
    clippy::too_many_arguments,
    reason = "the oracle's run state, passed through once"
)]
fn finish(
    outcome: &mut Outcome,
    selecting: bool,
    plan_warnings: &mut Vec<String>,
    own_warnings: &mut Vec<String>,
    selection: &plan::Selection,
    runs: &[StatusStrategy],
    statuses: &strategy::Statuses,
    workspace: &Workspace,
    config: &Json,
    platforms: &[&str],
    is_set: &dyn Fn(&str) -> bool,
    cwd: &Path,
) {
    if selecting && !outcome.payload.contains_key("scope") {
        outcome.payload.insert("scope".into(), "selected".into());
    }
    let unread = unread_files(workspace, cwd);
    if !unread.is_empty() {
        plan_warnings.push(format!(
            "{} could not be read: {}; opentide validate shows where",
            plan::plural(unread.len(), "object file"),
            unread.join(", ")
        ));
    }
    let with_tenants: Vec<&str> = platforms
        .iter()
        .copied()
        .filter(|platform| !plan::tenants(config, platform).is_empty())
        .collect();
    let unset = plan::unset_variables(config, &with_tenants, is_set);
    if !unset.is_empty() {
        plan_warnings.push(plan::unset_warning(&unset));
    }
    if !plan_warnings.is_empty() {
        let mut all = plan_warnings.clone();
        all.append(own_warnings);
        outcome.payload.insert("warnings".into(), all.into());
    }
    if !selection.skipped.is_empty() {
        report_skipped(outcome, &selection.skipped, runs, statuses);
    }
}

/// The warnings a failed plan still reports (`run_deploy` after `_deploy`).
fn finish_failure(
    outcome: &mut Outcome,
    workspace: &Workspace,
    cwd: &Path,
    plan_warnings: &mut Vec<String>,
    own: &mut Vec<String>,
) {
    let unread = unread_files(workspace, cwd);
    if !unread.is_empty() {
        plan_warnings.push(format!(
            "{} could not be read: {}; opentide validate shows where",
            plan::plural(unread.len(), "object file"),
            unread.join(", ")
        ));
    }
    if !plan_warnings.is_empty() {
        let mut all = plan_warnings.clone();
        all.append(own);
        outcome.payload.insert("warnings".into(), all.into());
    }
}

/// Object files the index could not read, shown from the working directory
/// when inside it, else from the workspace.
pub fn unread_files(workspace: &Workspace, cwd: &Path) -> Vec<String> {
    let root = workspace.root().to_path_buf();
    workspace
        .index()
        .load_errors
        .iter()
        .map(|error| {
            let path = &error.path;
            path.strip_prefix(cwd)
                .or_else(|_| path.strip_prefix(&root))
                .map(opentide_workspace::index::posix)
                .unwrap_or_else(|_| path.display().to_string())
        })
        .collect()
}

/// Counts the blocks a status kept out of the plan (`_report_skipped`).
fn report_skipped(
    outcome: &mut Outcome,
    skipped: &[plan::Skipped],
    runs: &[StatusStrategy],
    statuses: &strategy::Statuses,
) {
    let mut rules: Vec<&str> = Vec::new();
    for entry in skipped {
        if !rules.contains(&entry.uuid.as_str()) {
            rules.push(&entry.uuid);
        }
    }
    let mut counts: IndexMap<&str, usize> = IndexMap::new();
    for entry in skipped {
        *counts.entry(entry.status.as_str()).or_default() += 1;
    }
    let in_status = if counts.len() == 1 {
        format!(
            "{} in {}",
            plan::plural(rules.len(), "rule"),
            counts.keys().next().copied().unwrap_or_default()
        )
    } else {
        // Counter.most_common: by count, ties in first-seen order.
        let mut ordered: Vec<(&str, usize)> = counts.into_iter().collect();
        ordered.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        let listed: Vec<String> = ordered
            .iter()
            .map(|(status, count)| format!("{count} in {status}"))
            .collect();
        format!(
            "{} left out: {}",
            plan::plural(rules.len(), "rule"),
            listed.join(", ")
        )
    };
    let run_names = if runs.is_empty() {
        "this run".to_owned()
    } else {
        runs.iter()
            .map(|run| run.name())
            .collect::<Vec<_>>()
            .join(" or ")
    };
    outcome.payload.insert(
        "skipped".into(),
        Json::Array(skipped.iter().map(plan::Skipped::to_json).collect()),
    );
    let mut summary = outcome
        .summary
        .as_ref()
        .and_then(Json::as_object)
        .cloned()
        .unwrap_or_default();
    summary.insert(
        "skipped".into(),
        Json::Int(i64::try_from(rules.len()).unwrap_or(i64::MAX)),
    );
    outcome.summary = Some(Json::Object(summary));
    let deployable = statuses.deployed_by(runs);
    let listed = match deployable.as_slice() {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    };
    let advice = if listed.is_empty() {
        format!("no configured status deploys with {run_names}")
    } else {
        format!("set a platform block's status to {listed} for {run_names} to deploy it")
    };
    let skipped_run = outcome.payload.get("status").and_then(Json::as_str) == Some("skipped");
    let planned = outcome.payload.get("plan").is_some_and(Json::truthy);
    if skipped_run && !planned {
        outcome.outcome_line = Some(format!(
            "No rule has a status {run_names} deploys · {in_status}"
        ));
        outcome
            .payload
            .entry("advice".to_owned())
            .or_insert_with(|| advice.into());
    } else {
        outcome
            .payload
            .entry("detail".to_owned())
            .or_insert_with(|| format!("not in the plan: {in_status}; {advice}").into());
    }
}
