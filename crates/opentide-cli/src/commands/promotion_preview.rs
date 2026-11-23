//! A preview of the status promotion a `RELEASE` push will make (#1653,
//! smoke E13 and E15): `deploy --dry-run` and `validate query --live
//! --changed` on a push read the workspace as the push's deploy will after
//! its `status promotion` step, the promoted files read from memory over
//! the disk, so the plan and the live check see the promoted status and the
//! tenants it routes the rules to. Nothing is written.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::Owned;
use opentide_compile::strategy::StatusStrategy;
use opentide_workspace::fs::{DirEntry, EntryKind, FileSystem, Stamp};
use opentide_workspace::{OsFs, RootOptions, Workspace};

use super::deploy_promote::{self, Promotion};
use crate::env::Env;

/// The disk, with some files' bytes replaced by others held in memory.
#[derive(Debug, Default)]
pub struct Overlay {
    files: HashMap<PathBuf, Vec<u8>>,
}

impl Overlay {
    /// The disk with `files` (path, bytes) read from memory.
    pub fn new(files: impl IntoIterator<Item = (PathBuf, Vec<u8>)>) -> Self {
        Self {
            files: files
                .into_iter()
                .map(|(path, bytes)| (OsFs.resolve(&path), bytes))
                .collect(),
        }
    }

    fn held(&self, path: &Path) -> Option<&Vec<u8>> {
        self.files.get(&OsFs.resolve(path))
    }
}

impl FileSystem for Overlay {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        match self.held(path) {
            Some(bytes) => Ok(bytes.clone()),
            None => OsFs.read(path),
        }
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        OsFs.kind(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        OsFs.read_dir(path)
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        OsFs.resolve(path)
    }

    fn stamp(&self, path: &Path) -> io::Result<Stamp> {
        match self.held(path) {
            Some(bytes) => Ok(Stamp::of_bytes(bytes)),
            None => OsFs.stamp(path),
        }
    }
}

/// Whether the run is one that could promote before it deploys: a `RELEASE`
/// run on a push in CI that reads the push's changes (no `--all`, `--uuid`
/// or `--file`), as `deploy` decides (`deploy_send::promotes`).
fn candidate(
    runs: &[StatusStrategy],
    reads_changes: bool,
    env: &Env,
) -> Option<opentide_compile::git::Ci> {
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    let ci = opentide_compile::git::ci(&lookup);
    (runs.contains(&StatusStrategy::Release)
        && reads_changes
        && ci != opentide_compile::git::Ci::Local
        && !opentide_compile::git::is_change_request(ci, &lookup))
    .then_some(ci)
}

/// Whether a run with `runs` would promote before it deploys: a `RELEASE`
/// push in CI that reads its changes and is to the default branch. A push to
/// another branch, a tag, or a default branch the CI environment does not
/// say promotes nothing.
pub fn applies(runs: &[StatusStrategy], reads_changes: bool, env: &Env) -> bool {
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    candidate(runs, reads_changes, env)
        .is_some_and(|ci| opentide_compile::git::default_branch_push(ci, &lookup) == Some(true))
}

/// The warnings of a run that could promote: promotion skipped for a branch
/// the CI environment does not say (with how to fix it), and an
/// `OPENTIDE_DEFAULT_BRANCH` that disagrees with the one GitHub's event names.
/// Empty when promotion is off (`enabled` false), the run is not a candidate,
/// or all is as it should be.
pub fn warnings(
    runs: &[StatusStrategy],
    reads_changes: bool,
    env: &Env,
    enabled: bool,
) -> Vec<String> {
    use opentide_compile::git::{
        DEFAULT_BRANCH_ENV, default_branch, default_branch_push, platform_default_branch,
        pushed_branch, pushed_branch_variable,
    };
    let mut found = Vec::new();
    if !enabled {
        return found;
    }
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    let Some(ci) = candidate(runs, reads_changes, env) else {
        return found;
    };
    if default_branch_push(ci, &lookup).is_none() {
        let mut cause = Vec::new();
        if pushed_branch(ci, &lookup).is_none() {
            cause.push(format!(
                "the branch this push is to could not be determined; set {} to it",
                pushed_branch_variable(ci)
            ));
        }
        if default_branch(ci, &lookup).is_none() {
            cause.push(format!(
                "the repository's default branch could not be determined; set \
                 {DEFAULT_BRANCH_ENV} to its name, or regenerate the pipeline (`opentide setup ci`)"
            ));
        }
        found.push(format!(
            "status promotion skipped: {}",
            cause.join("; and ")
        ));
    }
    // A renamed default branch leaves the variable stale: the push to the
    // branch GitHub says is the default would then promote nothing.
    if let (Some(set_to), Some(platform), Some(pushed)) = (
        env.get(DEFAULT_BRANCH_ENV).filter(|name| !name.is_empty()),
        platform_default_branch(ci, &lookup),
        pushed_branch(ci, &lookup).flatten(),
    ) && set_to.strip_prefix("refs/heads/").unwrap_or(set_to) != platform
        && pushed == platform
    {
        found.push(format!(
            "{DEFAULT_BRANCH_ENV} is `{set_to}`, but the repository's default branch is \
             `{platform}` and this push is to it, so its statuses are not promoted: update \
             {DEFAULT_BRANCH_ENV} (or regenerate the pipeline)"
        ));
    }
    found
}

/// What the push's deploy will do at its status promotion, as a preview
/// reads it.
pub enum Preview {
    /// The promotion rewrites no file.
    Nothing,
    /// The workspace as the deploy will read it after promoting, the files
    /// it rewrites, the canonical UUIDs of their rules, and the target.
    Promoted {
        /// The workspace, the promoted files read from memory.
        workspace: Box<Workspace>,
        /// The files the promotion rewrites.
        files: Vec<PathBuf>,
        /// Their rules' canonical UUIDs.
        uuids: Vec<String>,
        /// The status they are promoted to.
        target: String,
    },
    /// The promotion would stop the run: what it says.
    Stops(String),
}

/// The workspace as the push's deploy will read it after promoting
/// `changed` (every rule file of `local` instead when `debug`), opened with
/// `options`.
///
/// # Errors
///
/// The workspace does not open through the overlay.
pub fn promoted_workspace(
    owned: &Owned,
    options: RootOptions,
    changed: &[PathBuf],
    local: &[PathBuf],
    debug: bool,
) -> Result<Preview, String> {
    let settings = opentide_compile::promotion::Settings::new(&owned.config, &owned.statuses);
    let promotion = Promotion {
        settings: &settings,
        changed,
        local,
        debug,
    };
    let planned = match deploy_promote::preview(&promotion) {
        Ok(planned) => planned,
        Err(stop) => return Ok(Preview::Stops(deploy_promote::stop_text(&stop))),
    };
    if planned.is_empty() {
        return Ok(Preview::Nothing);
    }
    let files = planned.iter().map(|(path, _, _)| path.clone()).collect();
    let uuids = planned
        .iter()
        .filter_map(|(_, _, uuid)| uuid.clone())
        .collect();
    let target = settings.target.clone().unwrap_or_default();
    let workspace = Workspace::open(
        Arc::new(Overlay::new(
            planned.into_iter().map(|(path, bytes, _)| (path, bytes)),
        )),
        opentide_workspace::Options { roots: options },
    )
    .map_err(|error| error.to_string())?;
    Ok(Preview::Promoted {
        workspace: Box::new(workspace),
        files,
        uuids,
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_overlay_reads_its_files_from_memory_and_the_rest_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let held = dir.path().join("held.yaml");
        let other = dir.path().join("other.yaml");
        std::fs::write(&held, "status: STAGING\n").unwrap();
        std::fs::write(&other, "status: STAGING\n").unwrap();
        let overlay = Overlay::new([(held.clone(), b"status: PRODUCTION\n".to_vec())]);
        assert_eq!(overlay.read(&held).unwrap(), b"status: PRODUCTION\n");
        assert_eq!(overlay.read(&other).unwrap(), b"status: STAGING\n");
        assert_eq!(
            overlay.stamp(&held).unwrap(),
            Stamp::of_bytes(b"status: PRODUCTION\n")
        );
        assert!(!overlay.shared());
        assert_eq!(overlay.read_dir(dir.path()).unwrap().len(), 2);
        // Nothing reached the disk.
        assert_eq!(std::fs::read(&held).unwrap(), b"status: STAGING\n");
    }

    fn github(reference: &str, extra: &[(&str, &str)]) -> Env {
        let mut pairs = vec![
            ("GITHUB_ACTIONS".to_owned(), "true".to_owned()),
            ("GITHUB_EVENT_NAME".to_owned(), "push".to_owned()),
            ("GITHUB_REF".to_owned(), reference.to_owned()),
            (
                opentide_compile::git::DEFAULT_BRANCH_ENV.to_owned(),
                "main".to_owned(),
            ),
        ];
        pairs.extend(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        Env::from_pairs(pairs)
    }

    #[test]
    fn only_a_release_push_to_the_default_branch_that_reads_its_changes_promotes() {
        let push = github("refs/heads/main", &[]);
        let feature = github("refs/heads/feature/foo", &[]);
        let tag = github("refs/tags/v1", &[]);
        let request = github("refs/heads/main", &[("GITHUB_EVENT_NAME", "pull_request")]);
        let local = Env::from_pairs(Vec::<(String, String)>::new());
        let release = [StatusStrategy::Release];
        assert!(applies(&release, true, &push));
        assert!(!applies(&release, false, &push));
        assert!(!applies(&[StatusStrategy::Preview], true, &push));
        assert!(!applies(&release, true, &feature));
        assert!(!applies(&release, true, &tag));
        assert!(!applies(&release, true, &request));
        assert!(!applies(&release, true, &local));
        // A known other branch is no warning; only an unknown one is.
        assert!(warnings(&release, true, &feature, true).is_empty());
        assert!(warnings(&release, true, &push, true).is_empty());
    }

    #[test]
    fn an_unknown_default_branch_skips_the_promotion_with_a_warning() {
        let release = [StatusStrategy::Release];
        let azure = Env::from_pairs([
            ("TF_BUILD".to_owned(), "True".to_owned()),
            ("BUILD_REASON".to_owned(), "IndividualCI".to_owned()),
            (
                "BUILD_SOURCEBRANCH".to_owned(),
                "refs/heads/main".to_owned(),
            ),
        ]);
        assert!(!applies(&release, true, &azure));
        let found = warnings(&release, true, &azure, true);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("set OPENTIDE_DEFAULT_BRANCH"),
            "{found:?}"
        );
        assert!(!found[0].contains("BUILD_SOURCEBRANCH"), "{found:?}");
        // Promotion off: nothing is said.
        assert!(warnings(&release, true, &azure, false).is_empty());
        // Not a promoting run: nothing to warn about.
        assert!(warnings(&release, false, &azure, true).is_empty());
        assert!(warnings(&[StatusStrategy::Preview], true, &azure, true).is_empty());
    }

    #[test]
    fn an_unknown_pushed_branch_names_the_variable_that_carries_it() {
        let release = [StatusStrategy::Release];
        // Generic CI is read as GitLab: `CI_COMMIT_BRANCH` is the variable.
        let generic = Env::from_pairs([
            ("CI".to_owned(), "true".to_owned()),
            (
                opentide_compile::git::DEFAULT_BRANCH_ENV.to_owned(),
                "main".to_owned(),
            ),
        ]);
        let found = warnings(&release, true, &generic, true);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("CI_COMMIT_BRANCH"), "{found:?}");
        assert!(
            !found[0].contains("set OPENTIDE_DEFAULT_BRANCH"),
            "{found:?}"
        );
        // Neither known: both are asked for.
        let bare = Env::from_pairs([("CI".to_owned(), "true".to_owned())]);
        let found = warnings(&release, true, &bare, true);
        assert!(found[0].contains("CI_COMMIT_BRANCH"), "{found:?}");
        assert!(
            found[0].contains("set OPENTIDE_DEFAULT_BRANCH"),
            "{found:?}"
        );
        let azure = Env::from_pairs([
            ("TF_BUILD".to_owned(), "True".to_owned()),
            ("BUILD_REASON".to_owned(), "IndividualCI".to_owned()),
        ]);
        assert!(warnings(&release, true, &azure, true)[0].contains("BUILD_SOURCEBRANCH"));
    }

    #[test]
    fn a_default_branch_variable_that_differs_from_githubs_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let event = dir.path().join("event.json");
        std::fs::write(&event, r#"{"repository":{"default_branch":"trunk"}}"#).unwrap();
        let path = event.to_str().unwrap();
        let release = [StatusStrategy::Release];
        // The variable says `main`; GitHub says `trunk`, and the push is to it.
        let stale = github("refs/heads/trunk", &[("GITHUB_EVENT_PATH", path)]);
        assert!(!applies(&release, true, &stale));
        let found = warnings(&release, true, &stale, true);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("`main`") && found[0].contains("`trunk`"),
            "{found:?}"
        );
        // A push to another branch, or a variable that agrees, says nothing.
        let other = github("refs/heads/feature/x", &[("GITHUB_EVENT_PATH", path)]);
        assert!(warnings(&release, true, &other, true).is_empty());
        std::fs::write(&event, r#"{"repository":{"default_branch":"main"}}"#).unwrap();
        let agree = github("refs/heads/main", &[("GITHUB_EVENT_PATH", path)]);
        assert!(warnings(&release, true, &agree, true).is_empty());
    }
}
