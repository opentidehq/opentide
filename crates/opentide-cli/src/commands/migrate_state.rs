//! `deploy migrate-state` (UC-4.4, #834; `cli/services/migrate_state.py`):
//! move vendor rule ids off rules into deployment state (RFC 0010 §3).
//!
//! Defender for Endpoint, SentinelOne and CrowdStrike ids found on a rule are
//! written to `.opentide/states/deployment/<uuid>.json` first, durably
//! ([`deploy_state`]), and only then removed from the YAML. A crash between
//! the two leaves both copies; they agree, so the next run strips the YAML
//! and succeeds.
//!
//! The YAML edit deletes whole lines located from the parsed node marks: the
//! `rule_id::<tenant>` line, or the `rule_id` / `rule_id_bundle` key and every
//! line of its mapping. Nothing else is rewritten, so comments, key order and
//! whitespace survive. The edited text is parsed again and must equal the
//! original document minus those keys, or the rule is left alone.
//!
//! Every other platform addresses its rules without a vendor id, so its keys
//! are removed and reported as `external_id_unused`, not copied into a shard.
//! The command never calls a vendor API.
//!
//! Exit codes: `0` after a migration, a clean second run, or
//! `external_id_unused` warnings only; `1` when any rule fails or git ignores
//! the deployment state folder.

use std::path::{Path, PathBuf};

use opentide_schema::configuration::merge::to_json;
use opentide_schema::node::{self, Node, Value};
use opentide_workspace::{OsFs, root};

use super::deploy_state::{self, ExternalId, Shard, StateError};
use super::{Report, counted, placement};
use crate::env::Env;
use crate::envelope::Failure;
use crate::json::Json;

/// The command's path.
pub const COMMAND: &str = "deploy migrate-state";
/// The Python module whose events this port logs.
const LOGGER: &str = "opentide.cli.services.migrate_state";
/// Platforms whose ids move into shards (`MIGRATED_PLATFORMS`).
const MIGRATED_PLATFORMS: [&str; 3] = ["crowdstrike", "defender_for_endpoint", "sentinel_one"];
/// Platform-block keys that used to carry the vendor id on the rule.
const LEGACY_MAP_KEYS: [&str; 2] = ["rule_id", "rule_id_bundle"];
/// The prefix of a one-tenant id key (`rule_id::<tenant>`).
const LEGACY_TENANT_PREFIX: &str = "rule_id::";

/// What a run that edited rules tells the reader to do next.
pub const COMMIT_ADVICE: &str = "Commit the edited rules together with every new or changed file \
under .opentide/states/deployment/. A deploy from a checkout that has the stripped rules but not \
the shards creates a second remote rule.";

/// `rule_id`, `rule_id_bundle` or `rule_id::<tenant>`.
fn is_legacy_key(key: &str) -> bool {
    LEGACY_MAP_KEYS.contains(&key) || key.starts_with(LEGACY_TENANT_PREFIX)
}

fn migrated_platform(platform: &str) -> bool {
    MIGRATED_PLATFORMS.contains(&platform)
}

/// One vendor id found on a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    platform: String,
    tenant: String,
    stored: String,
}

impl Binding {
    fn json(&self) -> Json {
        Json::object([
            ("platform", Json::str(&self.platform)),
            ("tenant", Json::str(&self.tenant)),
            ("external_id", Json::str(&self.stored)),
        ])
    }
}

/// Everything one rule file needs moved, or why it cannot be.
#[derive(Debug, Default)]
struct RuleIds {
    object_uuid: Option<String>,
    bindings: Vec<Binding>,
    /// Zero-based first and last line of each key to remove.
    spans: Vec<(usize, usize)>,
    removed: Vec<(String, String)>,
    errors: Vec<(&'static str, String)>,
}

impl RuleIds {
    fn fail(&mut self, code: &'static str, message: String) {
        self.errors.push((code, message));
    }

    fn shard_bindings(&self) -> impl Iterator<Item = &Binding> {
        self.bindings
            .iter()
            .filter(|binding| migrated_platform(&binding.platform))
    }
}

/// A node as a message shows it: the JSON of the value the YAML holds
/// (`"x"`, `1.5`, `null`, `true`, `[1, "x"]` without spaces).
fn node_repr(node: &Node) -> String {
    opentide_compile::json::Json::from_node(node).to_compact()
}

/// The node as a vendor id: a string or an integer (`normalise_external_id`
/// refuses anything else, a boolean included).
fn external_id(node: &Node) -> Option<ExternalId> {
    match &node.value {
        Value::Int(integer) => Some(ExternalId::Int(*integer)),
        Value::Str(text) => Some(ExternalId::Text(text.clone())),
        _ => None,
    }
}

/// The text as characters, for the marks (offsets in code points).
struct Source {
    chars: Vec<char>,
}

impl Source {
    /// Whether the collection that starts at `node.start` is written in flow
    /// style (`[a, b]`, `{a: 1}`), after its anchor and tag if any.
    fn is_flow(&self, node: &Node) -> bool {
        let mut index = node.start.index;
        loop {
            match self.chars.get(index) {
                Some('&' | '!') => {
                    while self.chars.get(index).is_some_and(|c| !c.is_whitespace()) {
                        index += 1;
                    }
                    while self.chars.get(index).is_some_and(|c| c.is_whitespace()) {
                        index += 1;
                    }
                }
                Some('[' | '{') => return true,
                _ => return false,
            }
        }
    }

    /// The zero-based last line `node` occupies (`_last_line`).
    fn last_line(&self, node: &Node) -> usize {
        let (start, end) = (
            node.start.line.saturating_sub(1),
            node.end.line.saturating_sub(1),
        );
        match &node.value {
            Value::Seq(items) if !items.is_empty() && !self.is_flow(node) => items
                .iter()
                .map(|item| self.last_line(item))
                .max()
                .unwrap_or(end),
            Value::Map(entries) if !entries.is_empty() && !self.is_flow(node) => entries
                .iter()
                .flat_map(|entry| [self.last_line(&entry.key), self.last_line(&entry.value)])
                .max()
                .unwrap_or(end),
            Value::Seq(_) | Value::Map(_) => end,
            _ if end > start && self.at_line_start(node.end.index) => end - 1,
            _ => end,
        }
    }

    /// Whether only indentation comes before `index` on its line. PyYAML
    /// ends a block scalar at the start of the next token's line, where
    /// saphyr ends it at that token: either way the scalar's last line is
    /// the one before.
    fn at_line_start(&self, index: usize) -> bool {
        let mut at = index;
        while at > 0 {
            match self.chars.get(at - 1) {
                Some(' ') => at -= 1,
                Some('\n') | None => return true,
                Some(_) => return false,
            }
        }
        true
    }
}

/// The rule files under `rules_dir`, `*.yaml` and `*.yml` at any depth, in
/// path order; a linked folder is not entered (`Path.rglob`).
fn rule_files(rules_dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![rules_dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let linked = entry.file_type().is_ok_and(|kind| kind.is_symlink());
            if path.is_dir() {
                if !linked {
                    pending.push(path);
                }
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if (name.ends_with(".yaml") || name.ends_with(".yml")) && path.is_file() {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Binds one tenant's id (`_bind`).
fn bind(
    rule: &mut RuleIds,
    platform: &str,
    tenant: Option<&str>,
    tenant_repr: &str,
    id: &Node,
    seen: &mut Vec<(String, String)>,
) {
    let Some(tenant) = tenant.filter(|tenant| !tenant.trim().is_empty()) else {
        rule.fail(
            "external_id_shape",
            format!("{platform}: tenant name {tenant_repr} is empty or not a string"),
        );
        return;
    };
    let tenant = tenant.trim();
    let normalised = match external_id(id) {
        Some(value) => deploy_state::normalise_external_id(platform, &value),
        None => Err(StateError {
            code: "external_id_shape",
            message: format!(
                "{platform} external id {} is not a string or an integer",
                node_repr(id)
            ),
        }),
    };
    let stored = match normalised {
        Ok(stored) => stored,
        Err(error) => {
            rule.fail(
                error.code,
                format!("{platform} tenant {tenant:?}: {}", error.message),
            );
            return;
        }
    };
    let key = (platform.to_owned(), tenant.to_owned());
    if seen.contains(&key) {
        rule.fail(
            "external_id_conflict",
            format!("{platform} tenant {tenant:?} is mapped more than once on the rule"),
        );
        return;
    }
    seen.push(key);
    rule.bindings.push(Binding {
        platform: platform.to_owned(),
        tenant: tenant.to_owned(),
        stored,
    });
}

/// Every legacy key under `configurations` (`_collect`).
fn collect(rule: &mut RuleIds, source: &Source, root: &Node) {
    let Some(configurations) = root.get("configurations") else {
        return;
    };
    let Value::Map(blocks) = &configurations.value else {
        return;
    };
    let mut seen = Vec::new();
    for block_entry in blocks {
        let Value::Map(keys) = &block_entry.value.value else {
            continue;
        };
        let platform = block_entry.key.value.to_string();
        for entry in keys {
            let Some(key) = entry.key.value.as_str().filter(|key| is_legacy_key(key)) else {
                continue;
            };
            rule.removed.push((platform.clone(), key.to_owned()));
            rule.spans.push((
                entry.key.start.line.saturating_sub(1),
                source.last_line(&entry.value),
            ));
            if LEGACY_MAP_KEYS.contains(&key) {
                let Value::Map(tenants) = &entry.value.value else {
                    rule.fail(
                        "external_id_shape",
                        format!("configurations.{platform}.{key} is not a mapping of tenant to id"),
                    );
                    continue;
                };
                for tenant in tenants {
                    if matches!(tenant.value.value, Value::Seq(_) | Value::Map(_)) {
                        rule.fail(
                            "external_id_shape",
                            format!("configurations.{platform}.{key}: the id is not a scalar"),
                        );
                        continue;
                    }
                    bind(
                        rule,
                        &platform,
                        tenant.key.value.as_str(),
                        &node_repr(&tenant.key),
                        &tenant.value,
                        &mut seen,
                    );
                }
            } else {
                if matches!(entry.value.value, Value::Seq(_) | Value::Map(_)) {
                    rule.fail(
                        "external_id_shape",
                        format!("configurations.{platform}.{key}: the id is not a scalar"),
                    );
                    continue;
                }
                let tenant = &key[LEGACY_TENANT_PREFIX.len()..];
                bind(
                    rule,
                    &platform,
                    Some(tenant),
                    &format!("{tenant:?}"),
                    &entry.value,
                    &mut seen,
                );
            }
        }
    }
}

/// `text` without the lines of `spans`; lines split after each LF, so a
/// CRLF line keeps its CR (`_strip_lines`).
fn strip_lines(text: &str, spans: &[(usize, usize)]) -> String {
    text.split_inclusive('\n')
        .enumerate()
        .filter(|(number, _)| {
            !spans
                .iter()
                .any(|(start, end)| start <= number && number <= end)
        })
        .map(|(_, line)| line)
        .collect()
}

/// The document as plain values, with every legacy key removed from the
/// platform blocks when `strip` (`_expected_document`).
fn plain(document: &node::Document, strip: bool) -> serde_json::Value {
    let Some(root) = document.root() else {
        return serde_json::Value::Null;
    };
    let mut value = to_json(root);
    if strip && let Some(serde_json::Value::Object(blocks)) = value.get_mut("configurations") {
        for block in blocks.values_mut() {
            if let serde_json::Value::Object(keys) = block {
                keys.retain(|key, _| !is_legacy_key(key));
            }
        }
    }
    value
}

/// Line breaks the edit cannot split: a lone CR, NEL, LS and PS.
fn unsupported_breaks(text: &str) -> bool {
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' if chars.peek() != Some(&'\n') => return true,
            '\u{85}' | '\u{2028}' | '\u{2029}' => return true,
            _ => {}
        }
    }
    false
}

/// Finds the ids in one file and computes its edited text (`_plan_rule`).
fn plan_rule(path: &Path) -> (RuleIds, Option<String>) {
    let mut rule = RuleIds::default();
    let text = match std::fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) => {
                rule.fail(
                    "yaml_parse",
                    format!("cannot read {}: {error}", path.display()),
                );
                return (rule, None);
            }
        },
        Err(error) => {
            rule.fail(
                "yaml_parse",
                format!(
                    "cannot read {}: {}",
                    path.display(),
                    deploy_state::os_error_text(&error, path)
                ),
            );
            return (rule, None);
        }
    };
    if !text.contains("rule_id") {
        return (rule, None);
    }
    let document = match node::load_keeping_repeated_keys(&text) {
        Ok(document) => document,
        Err(error) => {
            rule.fail(
                "yaml_parse",
                format!("cannot parse {}: {error}", path.display()),
            );
            return (rule, None);
        }
    };
    let Some(root) = document.root() else {
        return (rule, None);
    };
    let source = Source {
        chars: document.source().chars().collect(),
    };
    collect(&mut rule, &source, root);
    if rule.removed.is_empty() {
        return (rule, None);
    }
    let raw_uuid = root
        .get("metadata")
        .and_then(|metadata| metadata.get("uuid"))
        .filter(|uuid| !matches!(uuid.value, Value::Seq(_) | Value::Map(_)));
    if rule.shard_bindings().next().is_some() {
        let canonical = raw_uuid.and_then(|uuid| match &uuid.value {
            Value::Str(text) => deploy_state::canonical(text),
            Value::Int(integer) => deploy_state::canonical(&integer.to_string()),
            _ => None,
        });
        match canonical {
            Some(uuid) => rule.object_uuid = Some(uuid),
            None => {
                let shown = raw_uuid.map_or_else(|| "null".to_owned(), |uuid| node_repr(uuid));
                rule.fail(
                    "invalid_uuid",
                    format!("metadata.uuid {shown} is not a UUID"),
                );
            }
        }
    } else if let Some(uuid) = raw_uuid.filter(|uuid| uuid.value != Value::Null) {
        rule.object_uuid = Some(match &uuid.value {
            Value::Str(text) => text.clone(),
            other => other.to_string(),
        });
    }
    if !rule.errors.is_empty() {
        return (rule, None);
    }
    if unsupported_breaks(&text) {
        rule.fail(
            "external_id_shape",
            "the file uses line breaks other than LF or CRLF; remove the keys by hand".to_owned(),
        );
        return (rule, None);
    }
    let edited = strip_lines(&text, &rule.spans);
    let same = match node::load_keeping_repeated_keys(&edited) {
        Ok(reparsed) => plain(&reparsed, false) == plain(&document, true),
        Err(_) => false,
    };
    if !same {
        let keys: Vec<String> = rule
            .removed
            .iter()
            .map(|(platform, key)| format!("configurations.{platform}.{key}"))
            .collect();
        rule.fail(
            "external_id_shape",
            format!(
                "{} cannot be removed without rewriting other content (flow-style block?); \
                 remove the keys by hand",
                keys.join(", ")
            ),
        );
        return (rule, None);
    }
    (rule, Some(edited))
}

/// Loads the shard and refuses ids that disagree with it (`_check_shard`).
fn check_shard(rule: &mut RuleIds, workspace: &Path) -> Option<Shard> {
    let uuid = rule.object_uuid.clone()?;
    rule.shard_bindings().next()?;
    let shard = match Shard::load(workspace, &uuid) {
        Ok(shard) => shard,
        Err(error) => {
            rule.fail(error.code, error.message);
            return None;
        }
    };
    let conflicts: Vec<String> = rule
        .shard_bindings()
        .filter_map(|binding| {
            let existing = shard.get(&binding.platform, &binding.tenant)?;
            (existing != binding.stored).then(|| {
                format!(
                    "{} tenant {:?} is {:?} on the rule but {existing:?} in {}",
                    binding.platform,
                    binding.tenant,
                    binding.stored,
                    shard.path.display()
                )
            })
        })
        .collect();
    for message in conflicts {
        rule.fail("external_id_conflict", message);
    }
    Some(shard)
}

/// `path` relative to `workspace`, with `/` (`_display`).
fn display(path: &Path, workspace: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let base = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    match resolved.strip_prefix(&base) {
        Ok(relative) => relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
        Err(_) => path.display().to_string(),
    }
}

fn optional(text: Option<&String>) -> Json {
    text.map_or(Json::Null, Json::str)
}

fn shown(text: Option<&String>) -> String {
    text.cloned().unwrap_or_else(|| "null".to_owned())
}

/// Where the rules are: `paths.toml`'s rule folder, else `objects/rules`.
fn rules_dir(roots: &root::Roots) -> PathBuf {
    opentide_workspace::config::load(&OsFs, roots)
        .ok()
        .and_then(|config| config.folder("rule").map(Path::to_path_buf))
        .unwrap_or_else(|| roots.workspace.join("objects").join("rules"))
}

/// Runs `deploy migrate-state`.
pub fn run(repo: Option<&str>, env: &Env, cwd: &Path) -> Report {
    let (_, options) = placement(repo, env, cwd);
    let roots = root::resolve(&OsFs, &options);
    let workspace = roots.workspace.clone();
    let rules = rules_dir(&roots);
    migrate(&workspace, &rules)
}

/// Moves every vendor id under `rules_dir` into shards (`run_migrate_state`).
pub fn migrate(workspace: &Path, rules_dir: &Path) -> Report {
    if let Some(rule) = opentide_compile::git::state_ignore(workspace) {
        return refused(&rule);
    }
    let mut migrated: Vec<Json> = Vec::new();
    let mut unused: Vec<(Json, String)> = Vec::new();
    let mut errors: Vec<(String, String, Option<String>, String)> = Vec::new();
    let mut shards_written = 0usize;
    let mut ids = 0usize;

    for path in rule_files(rules_dir) {
        let (mut rule, edited) = plan_rule(&path);
        let shard = if edited.is_some() {
            check_shard(&mut rule, workspace)
        } else {
            None
        };
        let relative = display(&path, workspace);
        if !rule.errors.is_empty() {
            for (code, message) in &rule.errors {
                tracing::error!(
                    detail = message.as_str(),
                    file = relative.as_str(),
                    uuid = shown(rule.object_uuid.as_ref()).as_str(),
                    logger = LOGGER,
                    "{code}"
                );
                errors.push((
                    (*code).to_owned(),
                    relative.clone(),
                    rule.object_uuid.clone(),
                    message.clone(),
                ));
            }
            continue;
        }
        let Some(edited) = edited else {
            continue;
        };
        for binding in &rule.bindings {
            if migrated_platform(&binding.platform) {
                continue;
            }
            tracing::warn!(
                platform = binding.platform.as_str(),
                tenant = binding.tenant.as_str(),
                value = binding.stored.as_str(),
                file = relative.as_str(),
                logger = LOGGER,
                "external_id_unused"
            );
            let mut members = vec![
                ("file".to_owned(), Json::str(&relative)),
                ("uuid".to_owned(), optional(rule.object_uuid.as_ref())),
            ];
            if let Json::Object(binding) = binding.json() {
                members.extend(binding);
            }
            unused.push((
                Json::Object(members),
                format!(
                    "external_id_unused: {} tenant {} id {} removed from {relative} (never read \
                     by its deployer; not stored)",
                    binding.platform, binding.tenant, binding.stored
                ),
            ));
        }
        let shard_bindings: Vec<&Binding> = rule.shard_bindings().collect();
        let written = write(shard, &shard_bindings, &path, &edited, workspace);
        let shard_file = match written {
            Ok((shard_file, changed)) => {
                if changed {
                    shards_written += 1;
                }
                shard_file
            }
            Err(detail) => {
                let message = format!("could not write the migration for {relative}: {detail}");
                tracing::error!(
                    detail = message.as_str(),
                    logger = LOGGER,
                    "deployment_state_write_failed"
                );
                errors.push((
                    "deployment_state_write_failed".to_owned(),
                    relative.clone(),
                    rule.object_uuid.clone(),
                    message,
                ));
                continue;
            }
        };
        tracing::info!(
            file = relative.as_str(),
            shard = shown(shard_file.as_ref()).as_str(),
            logger = LOGGER,
            "external_ids_migrated"
        );
        ids += shard_bindings.len();
        migrated.push(Json::object([
            ("file", Json::str(&relative)),
            ("uuid", optional(rule.object_uuid.as_ref())),
            ("shard", optional(shard_file.as_ref())),
            (
                "bindings",
                Json::Array(
                    shard_bindings
                        .iter()
                        .map(|binding| binding.json())
                        .collect(),
                ),
            ),
            (
                "removed",
                Json::Array(
                    rule.removed
                        .iter()
                        .map(|(platform, key)| {
                            Json::str(format!("configurations.{platform}.{key}"))
                        })
                        .collect(),
                ),
            ),
        ]));
    }
    outcome(migrated, unused, &errors, shards_written, ids)
}

/// Writes the shard, when an id changed, then the stripped rule; the shard's
/// path shown, and whether it was written.
fn write(
    shard: Option<Shard>,
    bindings: &[&Binding],
    path: &Path,
    edited: &str,
    workspace: &Path,
) -> Result<(Option<String>, bool), String> {
    let mut shard_file = None;
    let mut changed = false;
    if let Some(mut shard) = shard
        && !bindings.is_empty()
    {
        for binding in bindings {
            if shard.get(&binding.platform, &binding.tenant) != Some(binding.stored.as_str()) {
                shard
                    .set(
                        &binding.platform,
                        &binding.tenant,
                        &ExternalId::Text(binding.stored.clone()),
                    )
                    .map_err(|error| error.to_string())?;
                changed = true;
            }
        }
        if changed {
            shard
                .save()
                .map_err(|error| deploy_state::os_error_text(&error, &shard.path))?;
        }
        shard_file = Some(display(&shard.path, workspace));
    }
    deploy_state::write_durable(path, edited)
        .map_err(|error| deploy_state::os_error_text(&error, path))?;
    Ok((shard_file, changed))
}

/// The run's report from what it did.
fn outcome(
    migrated: Vec<Json>,
    unused: Vec<(Json, String)>,
    errors: &[(String, String, Option<String>, String)],
    shards_written: usize,
    ids: usize,
) -> Report {
    let rules = migrated.len();
    let (unused, warnings): (Vec<Json>, Vec<String>) = unused.into_iter().unzip();
    let int = |count: usize| Json::Int(i64::try_from(count).unwrap_or(i64::MAX));
    let error_items: Vec<Json> = errors
        .iter()
        .map(|(code, file, uuid, message)| {
            Json::object([
                ("code", Json::str(code)),
                ("file", Json::str(file)),
                ("uuid", optional(uuid.as_ref())),
                ("message", Json::str(message)),
            ])
        })
        .collect();
    let mut data = vec![
        ("migrated".to_owned(), Json::Array(migrated)),
        ("unused".to_owned(), Json::Array(unused)),
        ("errors".to_owned(), Json::Array(error_items)),
        ("shards_written".to_owned(), int(shards_written)),
        ("rules_edited".to_owned(), int(rules)),
    ];
    let mut report = Report::completed(COMMAND, Vec::new());
    report.outcome.summary = vec![
        ("ids".to_owned(), int(ids)),
        ("rules".to_owned(), int(rules)),
        ("shards".to_owned(), int(shards_written)),
    ];
    if !errors.is_empty() {
        let detail: Vec<String> = errors
            .iter()
            .map(|(code, file, _, message)| format!("{code}: {file}: {message}"))
            .collect();
        data.push(("detail".to_owned(), Json::str(detail.join("; "))));
        let message = format!(
            "{} rule file(s) could not be migrated; {rules} migrated. Fix them and re-run",
            errors.len()
        );
        failed(&mut report, message, 1);
    } else if rules > 0 {
        data.push(("advice".to_owned(), Json::str(COMMIT_ADVICE)));
        report.outcome.message = format!(
            "Moved {} to .opentide/states/deployment/ · {} edited, {} written",
            counted(ids, "vendor id"),
            counted(rules, "rule"),
            counted(shards_written, "shard")
        );
    } else {
        "No vendor rule ids left on rules".clone_into(&mut report.outcome.message);
    }
    report.outcome.data = data;
    report.warnings = warnings;
    report
}

/// Marks `report` failed with `message`, `command_failed`.
fn failed(report: &mut Report, message: String, exit_code: i32) {
    "failed".clone_into(&mut report.outcome.status);
    report.outcome.message.clone_from(&message);
    report.outcome.exit_code = exit_code;
    report.outcome.failure = Some(Failure::new(super::COMMAND_FAILED, message));
}

/// The refusal while git ignores the deployment state folder.
fn refused(rule: &deploy_state::IgnoreRule) -> Report {
    let message = format!(
        "deployment_state_ignored: {}",
        deploy_state::ignored_message(rule)
    );
    let mut report = Report::completed(COMMAND, Vec::new());
    report.outcome.data = vec![
        ("code".to_owned(), Json::str("deployment_state_ignored")),
        (
            "ignore".to_owned(),
            Json::object([
                ("pattern", Json::str(&rule.pattern)),
                ("source", optional(rule.source.as_ref())),
                (
                    "line",
                    rule.line.map_or(Json::Null, |line| {
                        Json::Int(i64::try_from(line).unwrap_or(i64::MAX))
                    }),
                ),
            ]),
        ),
        (
            "advice".to_owned(),
            Json::str(
                "Edit .gitignore so it ignores .opentide/states/sharing.jsonl only, then re-run",
            ),
        ),
        ("migrated".to_owned(), Json::Array(Vec::new())),
        ("unused".to_owned(), Json::Array(Vec::new())),
        ("errors".to_owned(), Json::Array(Vec::new())),
    ];
    failed(&mut report, message, 1);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "0b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b";

    fn workspace(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".opentide")).unwrap();
        for (path, text) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    fn rules(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("objects").join("rules")
    }

    fn data<'r>(report: &'r Report, key: &str) -> &'r Json {
        &report
            .outcome
            .data
            .iter()
            .find(|(name, _)| name == key)
            .unwrap_or_else(|| panic!("no {key}"))
            .1
    }

    fn rule(configurations: &str) -> String {
        format!(
            "name: Rule\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.1\n# keep me\nconfigurations:\n{configurations}detection_model: x\n"
        )
    }

    #[test]
    fn ids_move_into_the_shard_and_off_the_rule() {
        let text = rule(
            "  defender_for_endpoint:\n    rule_id::prod: 12345\n    rule_id_bundle:\n      lab: '678'\n    query: q\n  sentinel:\n    rule_id::soc: abc\n    query: |\n      x\n",
        );
        let dir = workspace(&[("objects/rules/r.yaml", &text)]);
        let report = migrate(dir.path(), &rules(&dir));
        assert_eq!(report.outcome.exit_code, 0, "{report:?}");
        assert_eq!(
            report.outcome.message,
            "Moved 2 vendor ids to .opentide/states/deployment/ · 1 rule edited, 1 shard written"
        );
        assert_eq!(
            report.warnings,
            [
                "external_id_unused: sentinel tenant soc id abc removed from objects/rules/r.yaml \
              (never read by its deployer; not stored)"
            ]
        );
        let edited = std::fs::read_to_string(dir.path().join("objects/rules/r.yaml")).unwrap();
        assert_eq!(
            edited,
            rule("  defender_for_endpoint:\n    query: q\n  sentinel:\n    query: |\n      x\n")
        );
        let shard = Shard::load(dir.path(), UUID).unwrap();
        assert_eq!(shard.get("defender_for_endpoint", "prod"), Some("12345"));
        assert_eq!(shard.get("defender_for_endpoint", "lab"), Some("678"));
        assert_eq!(data(&report, "shards_written"), &Json::Int(1));
        // A second run finds nothing left.
        let again = migrate(dir.path(), &rules(&dir));
        assert_eq!(again.outcome.message, "No vendor rule ids left on rules");
        assert_eq!(again.outcome.exit_code, 0);
    }

    #[test]
    fn crlf_and_a_byte_order_mark_survive() {
        let text = format!(
            "\u{feff}{}",
            rule("  crowdstrike:\n    rule_id::us: abc\n    query: q\n").replace('\n', "\r\n")
        );
        let dir = workspace(&[("objects/rules/r.yml", &text)]);
        let report = migrate(dir.path(), &rules(&dir));
        assert_eq!(report.outcome.exit_code, 0, "{report:?}");
        let edited = std::fs::read_to_string(dir.path().join("objects/rules/r.yml")).unwrap();
        assert_eq!(
            edited,
            format!(
                "\u{feff}{}",
                rule("  crowdstrike:\n    query: q\n").replace('\n', "\r\n")
            )
        );
    }

    #[test]
    fn a_bad_id_fails_the_rule_and_leaves_it_alone() {
        let text = rule("  sentinel_one:\n    rule_id::lab: \"007\"\n    query: q\n");
        let dir = workspace(&[("objects/rules/r.yaml", &text)]);
        let report = migrate(dir.path(), &rules(&dir));
        assert_eq!(report.outcome.exit_code, 1);
        assert_eq!(report.outcome.status, "failed");
        assert_eq!(
            report.outcome.message,
            "1 rule file(s) could not be migrated; 0 migrated. Fix them and re-run"
        );
        assert_eq!(
            data(&report, "detail"),
            &Json::str(
                "external_id_shape: objects/rules/r.yaml: sentinel_one tenant \"lab\": sentinel_one \
                 external id \"007\" is not a canonical decimal integer (no sign, no leading zeroes)"
            )
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("objects/rules/r.yaml")).unwrap(),
            text
        );
    }

    #[test]
    fn shapes_that_cannot_be_migrated_are_errors() {
        let cases = [
            (
                "  crowdstrike:\n    rule_id: [a]\n",
                "external_id_shape",
                "configurations.crowdstrike.rule_id is not a mapping of tenant to id",
            ),
            (
                "  crowdstrike:\n    rule_id:\n      us: [a]\n",
                "external_id_shape",
                "configurations.crowdstrike.rule_id: the id is not a scalar",
            ),
            (
                "  crowdstrike:\n    rule_id::us: {a: 1}\n",
                "external_id_shape",
                "configurations.crowdstrike.rule_id::us: the id is not a scalar",
            ),
            (
                "  crowdstrike:\n    rule_id::: abc\n",
                "external_id_shape",
                "crowdstrike: tenant name \"\" is empty or not a string",
            ),
            (
                "  crowdstrike:\n    rule_id:\n      1: abc\n",
                "external_id_shape",
                "crowdstrike: tenant name 1 is empty or not a string",
            ),
            (
                "  crowdstrike:\n    rule_id::us: true\n",
                "external_id_shape",
                "crowdstrike tenant \"us\": crowdstrike external id true is not a string or an integer",
            ),
            (
                "  crowdstrike:\n    rule_id::us: a\n    rule_id:\n      us: b\n",
                "external_id_conflict",
                "crowdstrike tenant \"us\" is mapped more than once on the rule",
            ),
            (
                "  crowdstrike: {rule_id::us: a, query: q}\n",
                "external_id_shape",
                "configurations.crowdstrike.rule_id::us cannot be removed without rewriting other \
                 content (flow-style block?); remove the keys by hand",
            ),
        ];
        for (configurations, code, message) in cases {
            let dir = workspace(&[("objects/rules/r.yaml", &rule(configurations))]);
            let report = migrate(dir.path(), &rules(&dir));
            assert_eq!(report.outcome.exit_code, 1, "{configurations}");
            let Json::Array(errors) = data(&report, "errors") else {
                panic!("errors")
            };
            let Json::Object(first) = &errors[0] else {
                panic!("an error is an object")
            };
            assert_eq!(first[0].1, Json::str(code), "{configurations}");
            assert_eq!(first[3].1, Json::str(message), "{configurations}");
        }
    }

    #[test]
    fn a_rule_without_a_uuid_cannot_name_a_shard() {
        let text = "name: R\nconfigurations:\n  crowdstrike:\n    rule_id::us: a\n";
        let dir = workspace(&[("objects/rules/r.yaml", text)]);
        let report = migrate(dir.path(), &rules(&dir));
        assert!(
            report
                .outcome
                .data
                .iter()
                .any(|(key, value)| key == "detail"
                    && value
                        == &Json::str(
                            "invalid_uuid: objects/rules/r.yaml: metadata.uuid null is not a UUID"
                        ))
        );
        // Another platform's id needs no shard: it is dropped and reported.
        let text = "name: R\nmetadata:\n  uuid: 7\nconfigurations:\n  splunk:\n    rule_id::us: a\n    query: q\n";
        let dir = workspace(&[("objects/rules/r.yaml", text)]);
        let report = migrate(dir.path(), &rules(&dir));
        assert_eq!(report.outcome.exit_code, 0);
        let Json::Array(unused) = data(&report, "unused") else {
            panic!("unused")
        };
        let Json::Object(first) = &unused[0] else {
            panic!("an object")
        };
        assert_eq!(first[1].1, Json::str("7"));
        assert_eq!(data(&report, "shards_written"), &Json::Int(0));
    }

    #[test]
    fn an_id_that_disagrees_with_the_shard_is_a_conflict() {
        let shard = format!(
            "{{\"schema\": \"deployment.state::1.0\", \"object_uuid\": \"{UUID}\", \"platforms\": {{\"crowdstrike\": {{\"us\": \"old\"}}}}}}"
        );
        let dir = workspace(&[
            (
                "objects/rules/r.yaml",
                &rule("  crowdstrike:\n    rule_id::us: new\n    query: q\n"),
            ),
            (&format!(".opentide/states/deployment/{UUID}.json"), &shard),
        ]);
        let report = migrate(dir.path(), &rules(&dir));
        assert_eq!(report.outcome.exit_code, 1);
        let Json::Str(detail) = data(&report, "detail") else {
            panic!("detail")
        };
        assert!(
            detail.starts_with(
                "external_id_conflict: objects/rules/r.yaml: crowdstrike tenant \"us\" is \"new\" \
                 on the rule but \"old\" in "
            ),
            "{detail}"
        );
        // The same id is no conflict, and the shard is not written again.
        let dir = workspace(&[
            (
                "objects/rules/r.yaml",
                &rule("  crowdstrike:\n    rule_id::us: old\n    query: q\n"),
            ),
            (&format!(".opentide/states/deployment/{UUID}.json"), &shard),
        ]);
        let report = migrate(dir.path(), &rules(&dir));
        assert_eq!(report.outcome.exit_code, 0, "{report:?}");
        assert_eq!(data(&report, "shards_written"), &Json::Int(0));
    }

    #[test]
    fn unreadable_and_unparseable_files_are_errors() {
        let dir = workspace(&[
            ("objects/rules/a.yaml", "rule_id: [unclosed\n"),
            ("objects/rules/b.yaml", "name: plain\n"),
            ("objects/rules/c.yaml", "# rule_id only in a comment\n"),
        ]);
        std::fs::write(dir.path().join("objects/rules/d.yaml"), b"rule_id: \xff\n").unwrap();
        let report = migrate(dir.path(), &rules(&dir));
        let Json::Array(errors) = data(&report, "errors") else {
            panic!("errors")
        };
        assert_eq!(errors.len(), 2);
        assert_eq!(report.outcome.exit_code, 1);
    }

    #[test]
    fn lone_carriage_returns_are_refused() {
        let text = rule("  crowdstrike:\n    rule_id::us: a\n    query: q\n")
            .replace("# keep me\n", "# keep\rme\n");
        let dir = workspace(&[("objects/rules/r.yaml", &text)]);
        let report = migrate(dir.path(), &rules(&dir));
        assert_eq!(report.outcome.exit_code, 1);
        assert!(unsupported_breaks("a\u{2028}b"));
        assert!(!unsupported_breaks("a\r\nb\n"));
    }

    #[test]
    fn a_missing_rules_folder_is_a_clean_run() {
        let dir = workspace(&[]);
        let report = migrate(dir.path(), &rules(&dir));
        assert_eq!(report.outcome.message, "No vendor rule ids left on rules");
        assert_eq!(report.outcome.exit_code, 0);
    }

    #[test]
    fn a_gitignored_state_folder_is_refused() {
        let dir = workspace(&[
            (
                "objects/rules/r.yaml",
                &rule("  crowdstrike:\n    rule_id::us: a\n"),
            ),
            (".gitignore", ".opentide/states/\n"),
        ]);
        let git = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status();
        if !git.is_ok_and(|status| status.success()) {
            return;
        }
        let report = migrate(dir.path(), &rules(&dir));
        assert_eq!(report.outcome.exit_code, 1);
        assert_eq!(
            data(&report, "code"),
            &Json::str("deployment_state_ignored")
        );
        assert!(
            report
                .outcome
                .message
                .starts_with("deployment_state_ignored: git ignores .opentide/states/deployment/")
        );
    }

    #[test]
    fn last_lines_follow_pyyaml_marks() {
        let text = "a:\n  b: |\n    x\n    y\n\n  c: [1,\n    2]\n  d:\n    - 1\n    - 2\n  e: !!str &x v\n";
        let document = node::load(text).unwrap();
        let source = Source {
            chars: document.source().chars().collect(),
        };
        let root = document.root().unwrap();
        let a = root.get("a").unwrap();
        // PyYAML ends `b` at the start of `c`'s line: the blank line goes too.
        assert_eq!(source.last_line(a.get("b").unwrap()), 4);
        assert_eq!(source.last_line(a.get("c").unwrap()), 6);
        assert_eq!(source.last_line(a.get("d").unwrap()), 9);
        assert_eq!(source.last_line(a.get("e").unwrap()), 10);
        assert!(source.is_flow(a.get("c").unwrap()));
        assert!(!source.is_flow(a.get("e").unwrap()));
    }

    #[test]
    fn values_print_as_the_json_they_hold() {
        let document = node::load("a: [1, null, 1.5, x, {k: false}]\nb: 2024-01-01\n").unwrap();
        let root = document.root().unwrap();
        assert_eq!(
            node_repr(root.get("a").unwrap()),
            r#"[1,null,1.5,"x",{"k":false}]"#
        );
        assert_eq!(node_repr(root.get("b").unwrap()), r#""2024-01-01""#);
    }
}
