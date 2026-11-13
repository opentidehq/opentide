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
//! cleaned up. The Python implementation was `opentide.ci.state_replay`
//! (UC-6.2, #841 ports it); its output is the same.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use indexmap::IndexMap;

use super::deploy_state::{Shard, StateError};
use crate::env::Env;

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

fn git(root: &Path, env: &Env, args: &[&str]) -> Result<Vec<u8>, ReplayError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .env_clear()
        .envs(env.iter())
        .stdin(Stdio::null())
        .output()
        .map_err(|error| ReplayError::Git(format!("git {}: {error}", args.join(" "))))?;
    if !output.status.success() {
        return Err(ReplayError::Git(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

/// The shard *path* holds at *revision*, written into *scratch* to be read
/// with the shard's own checks; an empty state where it has none.
fn state_at(
    root: &Path,
    env: &Env,
    revision: &str,
    path: &str,
    scratch: &Path,
) -> Result<Shard, ReplayError> {
    let name = Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = name.strip_suffix(".json").unwrap_or(&name).to_owned();
    let target = scratch.join(&name);
    match git(root, env, &["show", &format!("{revision}:{path}")]) {
        Ok(bytes) => {
            std::fs::create_dir_all(scratch).map_err(ReplayError::Io)?;
            std::fs::write(&target, bytes).map_err(ReplayError::Io)?;
            Shard::from_file(&target, None).map_err(ReplayError::State)
        }
        Err(_) => Ok(empty(target, stem)),
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
    let parent = format!("{state_commit}^");
    let changed = git(
        root,
        env,
        &[
            "diff",
            "--name-only",
            "--no-renames",
            &parent,
            state_commit,
            "--",
            DEPLOYMENT_STATES,
        ],
    )?;
    let changed = String::from_utf8_lossy(&changed).into_owned();
    let scratch = Scratch::new().map_err(ReplayError::Io)?;
    let mut result = Replayed::default();
    for path in changed.lines().filter(|line| line.ends_with(".json")) {
        let base = bindings(&state_at(
            root,
            env,
            &parent,
            path,
            &scratch.path().join("base"),
        )?);
        let ours_state = state_at(root, env, state_commit, path, &scratch.path().join("ours"))?;
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

/// Runs the command from *cwd*, the repository root: the conflicts on
/// stderr, the summary on stdout; the exit code.
pub fn run(
    cwd: &Path,
    env: &Env,
    state_commit: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> std::io::Result<i32> {
    match replay(cwd, env, state_commit) {
        Ok(result) => {
            for line in &result.conflicts {
                writeln!(err, "{line}")?;
            }
            writeln!(
                out,
                "Replayed deployment state: {} written, {} removed, {} conflicting",
                result.written.len(),
                result.removed.len(),
                result.conflicts.len()
            )?;
            Ok(0)
        }
        Err(error) => {
            writeln!(err, "error: {error}")?;
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "00000000-0000-4000-8003-000000000001";

    fn git_in(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
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

    fn env() -> Env {
        Env::from_pairs(
            std::env::vars()
                .chain([
                    ("GIT_CONFIG_GLOBAL".to_owned(), "/dev/null".to_owned()),
                    ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
                ])
                .collect::<Vec<_>>(),
        )
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
        let result = replay(root, &env(), "HEAD").unwrap();
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
        let result = replay(root, &env(), "HEAD").unwrap();
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
        let result = replay(root, &env(), "HEAD").unwrap();
        assert_eq!(result.removed.len(), 1);
        assert!(!path.exists());
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(run(root, &env(), "HEAD~1", &mut out, &mut err).unwrap(), 0);
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with("Replayed deployment state: ")
        );
    }
}
