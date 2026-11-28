//! `opentide deploy replay-state <state_commit>` (RFC 0010, #548): replays
//! one commit's deployment-state changes onto the current checkout.
//!
//! The production write-back the generated CI pipelines run falls back to
//! pushing the deployment state alone when its rule files conflict with a
//! concurrent merge. Copying this run's `.opentide/states/deployment/` over
//! the tip would revert shards other runs updated and resurrect shards that
//! were deleted, so only what *state_commit* changed relative to its parent is
//! applied, per platform and tenant:
//!
//! - a binding this run added or changed is set on the tip's shard;
//! - a binding this run removed is removed from it, and a shard left with no
//!   binding is deleted;
//! - every binding this run did not touch keeps the tip's value.
//!
//! When a concurrent run changed the same binding to a different id, this
//! run's id is kept (the newest record of what this run created) and both ids
//! are printed as `deployment_state_conflict`, so the duplicate can be
//! cleaned up.

use std::collections::BTreeSet;
use std::path::Path;

use indexmap::IndexMap;
use opentide_compile::git::GitError;

use super::deploy_state::{Shard, StateError};
use super::result::{ExitCode, Status};
use super::{Report, counted};
use crate::env::Env;
use crate::envelope::Failure;
use crate::json::Json;

/// The deployment-state folder, relative to the repository root.
pub const DEPLOYMENT_STATES: &str = ".opentide/states/deployment";

/// What the replay changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Replayed {
    /// Shards written, by path relative to the root.
    pub written: Vec<String>,
    /// Shards removed (no binding left).
    pub removed: Vec<String>,
    /// One `deployment_state_conflict` line per binding a concurrent run changed too.
    pub conflicts: Vec<String>,
}

/// Why the replay could not run.
#[derive(Debug)]
pub enum ReplayError {
    /// Git failed: its words.
    Git(String),
    /// A shard does not read.
    State(StateError),
    /// A file could not be written.
    Io(std::io::Error),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Git(message) => f.write_str(message),
            Self::State(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

/// A shard as one side of the commit held it, written into *scratch* to be
/// read with the shard's own checks; an empty state where it held nothing.
fn state_at(bytes: Option<&[u8]>, path: &str, scratch: &Path) -> Result<Shard, ReplayError> {
    let name = Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = name.strip_suffix(".json").unwrap_or(&name).to_owned();
    let target = scratch.join(&name);
    match bytes {
        Some(bytes) => {
            std::fs::create_dir_all(scratch).map_err(ReplayError::Io)?;
            std::fs::write(&target, bytes).map_err(ReplayError::Io)?;
            Shard::from_file(&target, None).map_err(ReplayError::State)
        }
        None => Ok(empty(target, stem)),
    }
}

fn empty(path: std::path::PathBuf, object_uuid: String) -> Shard {
    Shard {
        path,
        object_uuid,
        platforms: IndexMap::new(),
        extra: serde_json::Map::new(),
        exists: false,
    }
}

/// Every `(platform, tenant)` binding of *shard*, with its id.
fn bindings(shard: &Shard) -> IndexMap<(String, String), String> {
    shard
        .platforms
        .iter()
        .flat_map(|(platform, tenants)| {
            tenants
                .iter()
                .map(move |(tenant, id)| ((platform.clone(), tenant.clone()), id.clone()))
        })
        .collect()
}

/// An optional id as the conflict line prints it: quoted, or `null`.
fn shown(value: Option<&String>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| format!("{value:?}"))
}

/// A private folder under the system's temporary directory, removed when dropped.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> std::io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "opentide-replay-state-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Applies *state_commit*'s deployment-state delta to the working tree at *root*.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "a shard is named <uuid>.json in lower case; git lists the paths as committed"
)]
pub fn replay(root: &Path, env: &Env, state_commit: &str) -> Result<Replayed, ReplayError> {
    // The checkout is the one git would find with the run's environment
    // (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_CEILING_DIRECTORIES`).
    let lookup = |name: &str| env.get(name).map(std::ffi::OsString::from);
    let changes =
        opentide_compile::git::commit_changes(root, &lookup, state_commit, DEPLOYMENT_STATES)
            .map_err(|error| {
                ReplayError::Git(match error {
                    GitError::MissingCheckout(searched) => format!(
                        "no git checkout was found from {}",
                        dunce::simplified(&searched).display()
                    ),
                    other => other.message(),
                })
            })?;
    let scratch = Scratch::new().map_err(ReplayError::Io)?;
    let mut result = Replayed::default();
    for change in changes
        .iter()
        .filter(|change| change.path.ends_with(".json"))
    {
        let path = change.path.as_str();
        let base = bindings(&state_at(
            change.before.as_deref(),
            path,
            &scratch.path().join("base"),
        )?);
        let ours_state = state_at(change.after.as_deref(), path, &scratch.path().join("ours"))?;
        let ours = bindings(&ours_state);
        let tip_path = root.join(path);
        let stem = Path::new(path)
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut tip = if tip_path.is_file() {
            Shard::from_file(&tip_path, None).map_err(ReplayError::State)?
        } else {
            empty(tip_path.clone(), stem)
        };
        let tip_bindings = bindings(&tip);
        let keys: BTreeSet<&(String, String)> = base.keys().chain(ours.keys()).collect();
        for key in keys {
            if base.get(key) == ours.get(key) {
                continue;
            }
            let (platform, tenant) = key;
            let theirs = tip_bindings.get(key);
            if theirs != base.get(key) && theirs != ours.get(key) {
                result.conflicts.push(format!(
                    "deployment_state_conflict {path} {platform}/{tenant}: kept {}, the default \
                     branch had {}",
                    shown(ours.get(key)),
                    shown(theirs)
                ));
            }
            match ours.get(key) {
                Some(id) => {
                    tip.platforms
                        .entry(platform.clone())
                        .or_default()
                        .insert(tenant.clone(), id.clone());
                }
                None => {
                    tip.remove(platform, tenant);
                }
            }
        }
        for (key, value) in &ours_state.extra {
            tip.extra
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
        if let Some(parent) = tip.path.parent() {
            std::fs::create_dir_all(parent).map_err(ReplayError::Io)?;
        }
        tip.save().map_err(ReplayError::Io)?;
        if tip.platforms.is_empty() {
            result.removed.push(path.to_owned());
        } else {
            result.written.push(path.to_owned());
        }
    }
    Ok(result)
}

/// The command's name in its `--json` document.
pub const COMMAND: &str = "deploy replay-state";

/// Runs the command from *cwd*, the repository root. The shards written and
/// removed are the document's `written` and `removed`; each binding a
/// concurrent run changed too is a `deployment_state_conflict` line in
/// `conflicts` and `warnings`, so the CI log shows both ids.
pub fn report(cwd: &Path, env: &Env, state_commit: &str) -> Report {
    let paths = |paths: &[String]| Json::Array(paths.iter().map(Json::str).collect());
    match replay(cwd, env, state_commit) {
        Ok(result) => {
            let mut report = Report::completed(
                COMMAND,
                [
                    ("state_commit".to_owned(), Json::str(state_commit)),
                    ("written".to_owned(), paths(&result.written)),
                    ("removed".to_owned(), paths(&result.removed)),
                    ("conflicts".to_owned(), paths(&result.conflicts)),
                ],
            );
            let count = |count: usize| Json::Int(i64::try_from(count).unwrap_or(i64::MAX));
            report.outcome.summary = vec![
                ("written".to_owned(), count(result.written.len())),
                ("removed".to_owned(), count(result.removed.len())),
                ("conflicts".to_owned(), count(result.conflicts.len())),
            ];
            report.outcome.message = format!(
                "Replayed deployment state · {} written, {} removed, {} conflicting",
                counted(result.written.len(), "shard"),
                result.removed.len(),
                result.conflicts.len()
            );
            report.warnings = result.conflicts;
            report
        }
        Err(error) => {
            let message = format!("Could not replay {state_commit}: {error}");
            let mut report = Report::completed(
                COMMAND,
                [("state_commit".to_owned(), Json::str(state_commit))],
            );
            report.outcome.status = Status::Failed;
            report.outcome.message.clone_from(&message);
            report.outcome.exit_code = ExitCode::Failure;
            report.outcome.failure = Some(Failure::new(super::COMMAND_FAILED, message));
            report
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    const UUID: &str = "00000000-0000-4000-8003-000000000001";

    fn git_in(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    /// A run's environment without git's variables (a hook running the
    /// tests exports `GIT_DIR`).
    fn no_env() -> Env {
        Env::from_pairs(Vec::<(String, String)>::new())
    }

    /// The run's `GIT_DIR` and `GIT_WORK_TREE` name the checkout, as they
    /// did for the `git` program: a run from outside it replays its commit.
    #[test]
    fn the_runs_git_dir_names_the_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("dépôt");
        let elsewhere = dir.path().join("ailleurs");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        git_in(&root, &["init", "-q"]);
        write(&root, &shard("{\"crowdstrike\": {\"lab\": \"1\"}}"));
        git_in(&root, &["add", "-A"]);
        git_in(&root, &["commit", "-qm", "base"]);
        write(&root, &shard("{\"crowdstrike\": {\"lab\": \"2\"}}"));
        git_in(&root, &["commit", "-qam", "ours"]);
        let env = Env::from_pairs([
            ("GIT_DIR", root.join(".git").to_string_lossy().into_owned()),
            ("GIT_WORK_TREE", root.to_string_lossy().into_owned()),
        ]);
        let result = replay(&elsewhere, &env, "HEAD").unwrap();
        assert_eq!(result.written.len(), 1, "{result:?}");
        // Without them, the folder is no checkout.
        let error = replay(&elsewhere, &no_env(), "HEAD").unwrap_err();
        assert!(error.to_string().contains("no git checkout"), "{error}");
    }

    fn shard(platforms: &str) -> String {
        format!(
            "{{\n  \"object_uuid\": \"{UUID}\",\n  \"platforms\": {platforms},\n  \"schema\": \"deployment.state::1.0\"\n}}\n"
        )
    }

    fn write(dir: &Path, text: &str) {
        let path = dir.join(DEPLOYMENT_STATES).join(format!("{UUID}.json"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// This run added `soc` and changed nothing else; a concurrent run had
    /// given `lab` another id: `soc` is set, `lab` keeps the tip's.
    #[test]
    fn only_the_commits_delta_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git_in(root, &["init", "-q"]);
        write(root, &shard("{\"crowdstrike\": {\"lab\": \"1\"}}"));
        git_in(root, &["add", "-A"]);
        git_in(root, &["commit", "-qm", "base"]);
        write(
            root,
            &shard("{\"crowdstrike\": {\"lab\": \"1\", \"soc\": \"2\"}}"),
        );
        git_in(root, &["commit", "-qam", "ours"]);
        // The tip, as a concurrent merge left it.
        write(root, &shard("{\"crowdstrike\": {\"lab\": \"9\"}}"));
        let result = replay(root, &no_env(), "HEAD").unwrap();
        assert_eq!(result.written.len(), 1);
        assert!(result.conflicts.is_empty(), "{:?}", result.conflicts);
        let text =
            std::fs::read_to_string(root.join(DEPLOYMENT_STATES).join(format!("{UUID}.json")))
                .unwrap();
        assert!(text.contains("\"lab\": \"9\""), "{text}");
        assert!(text.contains("\"soc\": \"2\""), "{text}");
    }

    /// The same binding changed both ways: this run's id is kept, and the
    /// conflict names both; a binding removed leaves no shard.
    #[test]
    fn a_conflict_keeps_this_runs_id_and_an_emptied_shard_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git_in(root, &["init", "-q"]);
        write(root, &shard("{\"crowdstrike\": {\"lab\": \"1\"}}"));
        git_in(root, &["add", "-A"]);
        git_in(root, &["commit", "-qm", "base"]);
        write(root, &shard("{\"crowdstrike\": {\"lab\": \"2\"}}"));
        git_in(root, &["commit", "-qam", "ours"]);
        write(root, &shard("{\"crowdstrike\": {\"lab\": \"3\"}}"));
        let result = replay(root, &no_env(), "HEAD").unwrap();
        assert_eq!(
            result.conflicts,
            [format!(
                "deployment_state_conflict {DEPLOYMENT_STATES}/{UUID}.json crowdstrike/lab: kept \
                 \"2\", the default branch had \"3\""
            )]
        );
        // Now a run that removed the binding, from a tip that holds this run's id.
        git_in(root, &["checkout", "--", "."]);
        let path = root.join(DEPLOYMENT_STATES).join(format!("{UUID}.json"));
        std::fs::remove_file(&path).unwrap();
        git_in(root, &["commit", "-qam", "removed"]);
        write(root, &shard("{\"crowdstrike\": {\"lab\": \"2\"}}"));
        let result = replay(root, &no_env(), "HEAD").unwrap();
        assert_eq!(result.removed.len(), 1);
        assert!(!path.exists());
        let report = report(root, &no_env(), "HEAD~1");
        assert_eq!(report.outcome.exit_code, ExitCode::Success);
        assert!(
            report
                .outcome
                .message
                .starts_with("Replayed deployment state · "),
            "{}",
            report.outcome.message
        );
        let failed = super::report(root, &no_env(), "no-such-commit");
        assert_eq!(failed.outcome.exit_code, ExitCode::Failure);
        assert_eq!(failed.outcome.status, Status::Failed);
    }
}
