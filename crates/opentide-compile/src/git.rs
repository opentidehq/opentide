//! The git baseline: the rule files a run changed, read with gitoxide's
//! crates (`gix-discover`, `gix-ref`, `gix-odb`, `gix-diff`,
//! `gix-revision`), the git implementation in Rust, without the `git` program.
//! `gix-discover` finds the checkout and its git directory (linked worktrees
//! included); `gix-revision`'s rev-spec parser reads the revisions a run
//! names, resolved against the reference store and the object database.
//!
//! The diff is the run's commits: a pull or merge request against its target
//! branch, a push against the branch's previous tip, outside CI the last
//! commit against its first parent. A repository's first commit, which has no
//! parent, added every file it holds. Added, renamed and modified files count;
//! deleted ones do not (there is nothing left to deploy), but
//! [`deleted_paths`] lists them with their old content, for retirement (#1713). Paths are relative
//! to the git top level, as git writes them, non-ASCII paths included.
//!
//! This module and [`crate::plan::state_id`] are the crate's only reads: the
//! repository's objects, through gix, and the CI event file.

use std::path::{Path, PathBuf};

use gix_error::ErrorExt as _;
use gix_error::bstr::{BStr, ByteSlice as _};
use gix_hash::ObjectId;
use gix_object::{Find as _, FindExt as _};
use gix_ref::file::ReferenceExt as _;
use gix_revision::spec::parse::delegate;

/// Which commits the changed files come from (`DiffSource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSource {
    /// The pull or merge request, against its target branch.
    ChangeRequest,
    /// The pushed commits, against the branch's previous tip.
    Push,
    /// The last commit, against its first parent.
    LastCommit,
}

/// The CI platform a run is on (`CIEnvironment`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ci {
    /// Azure Pipelines (`TF_BUILD`).
    Azure,
    /// GitHub Actions (`GITHUB_ACTIONS`).
    GitHub,
    /// GitLab CI (`CI`).
    GitLab,
    /// Not CI.
    Local,
}

/// The environment, as the baseline reads it.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn set(env: Env<'_>, name: &str) -> Option<String> {
    env(name).filter(|value| !value.is_empty())
}

/// The CI platform `env` describes.
pub fn ci(env: Env<'_>) -> Ci {
    if set(env, "TF_BUILD").is_some() {
        Ci::Azure
    } else if set(env, "GITHUB_ACTIONS").is_some() {
        Ci::GitHub
    } else if set(env, "CI").is_some() {
        Ci::GitLab
    } else {
        Ci::Local
    }
}

/// Whether the run is for a pull or merge request (`is_change_request`).
pub fn is_change_request(ci: Ci, env: Env<'_>) -> bool {
    let (name, values): (&str, &[&str]) = match ci {
        Ci::Azure => ("BUILD_REASON", &["PullRequest"]),
        Ci::GitHub => (
            "GITHUB_EVENT_NAME",
            &["pull_request", "pull_request_target"],
        ),
        Ci::GitLab => ("CI_PIPELINE_SOURCE", &["merge_request_event"]),
        Ci::Local => return false,
    };
    env(name).is_some_and(|value| values.contains(&value.as_str()))
}

/// The variable that names the default branch on every CI platform, and
/// the only source on Azure Pipelines, which has no predefined one.
pub const DEFAULT_BRANCH_ENV: &str = "OPENTIDE_DEFAULT_BRANCH";

/// The branch a ref names: `refs/heads/<name>`, or a bare name.
fn branch_name(reference: &str) -> &str {
    reference.strip_prefix("refs/heads/").unwrap_or(reference)
}

/// The branch a push is to: `Some(Some(name))`, `Some(None)` for a ref that
/// is not a branch (a tag), `None` when the environment does not say.
pub fn pushed_branch(ci: Ci, env: Env<'_>) -> Option<Option<String>> {
    match ci {
        Ci::GitHub => set(env, "GITHUB_REF")
            .map(|reference| reference.strip_prefix("refs/heads/").map(str::to_owned)),
        Ci::GitLab => match set(env, "CI_COMMIT_BRANCH") {
            Some(branch) => Some(Some(branch)),
            None => set(env, "CI_COMMIT_TAG").map(|_| None),
        },
        Ci::Azure => set(env, "BUILD_SOURCEBRANCH")
            .map(|reference| reference.strip_prefix("refs/heads/").map(str::to_owned)),
        Ci::Local => None,
    }
}

/// Whether the run is a push to the repository's default branch, which is
/// when a `RELEASE` run promotes statuses.
///
/// `Some(false)` is a push to another branch or a tag, `None` a run whose
/// default branch (or pushed ref) the environment does not say. The default
/// branch is `OPENTIDE_DEFAULT_BRANCH` when set, on every platform; else
/// GitHub's event payload (`repository.default_branch`) and GitLab's
/// `CI_DEFAULT_BRANCH`. Azure Pipelines has no predefined variable.
pub fn default_branch_push(ci: Ci, env: Env<'_>) -> Option<bool> {
    let pushed = pushed_branch(ci, env)?;
    let Some(pushed) = pushed else {
        return Some(false);
    };
    let default = default_branch(ci, env)?;
    Some(pushed == default)
}

/// The variable that names the pushed ref on `ci`.
pub fn pushed_branch_variable(ci: Ci) -> &'static str {
    match ci {
        Ci::GitHub => "GITHUB_REF",
        Ci::GitLab | Ci::Local => "CI_COMMIT_BRANCH",
        Ci::Azure => "BUILD_SOURCEBRANCH",
    }
}

/// The repository's default branch: `OPENTIDE_DEFAULT_BRANCH` when set, else
/// the platform's own (GitHub's event payload, GitLab's `CI_DEFAULT_BRANCH`).
pub fn default_branch(ci: Ci, env: Env<'_>) -> Option<String> {
    set(env, DEFAULT_BRANCH_ENV)
        .or_else(|| platform_default_branch(ci, env))
        .map(|name| branch_name(&name).to_owned())
}

/// The default branch the CI platform itself names, whatever
/// `OPENTIDE_DEFAULT_BRANCH` says.
pub fn platform_default_branch(ci: Ci, env: Env<'_>) -> Option<String> {
    match ci {
        Ci::GitHub => event(env)?
            .get("repository")?
            .get("default_branch")?
            .as_str()
            .filter(|name| !name.is_empty())
            .map(str::to_owned),
        Ci::GitLab => set(env, "CI_DEFAULT_BRANCH"),
        Ci::Azure | Ci::Local => None,
    }
}

/// The run's diff source (`run_diff_source`).
pub fn diff_source(env: Env<'_>) -> DiffSource {
    let ci = ci(env);
    if ci == Ci::Local {
        DiffSource::LastCommit
    } else if is_change_request(ci, env) {
        DiffSource::ChangeRequest
    } else {
        DiffSource::Push
    }
}

/// Why the changed files could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    /// No checkout holds the workspace: the run must pass `--all`.
    MissingCheckout(PathBuf),
    /// Any other failure, with the message the run reports.
    Failed(String),
    /// `OPENTIDE_PUSH_BASE` names no usable commit: a usage error (exit 2).
    PushBase(String),
}

impl GitError {
    /// The message the run reports (`missing_checkout_message`).
    pub fn message(&self) -> String {
        match self {
            Self::MissingCheckout(searched) => format!(
                "deploy reads the rule files the last commit, push or pull request changed, \
                 which needs a git checkout; no .git was found from {}. Run inside the \
                 repository, or pass --all to read every rule file.",
                dunce::simplified(searched).display()
            ),
            Self::Failed(message) | Self::PushBase(message) => message.clone(),
        }
    }

    /// The exit code of a run this failure stops: `2` for a wrong
    /// `OPENTIDE_PUSH_BASE`, else `1`.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::PushBase(_) => 2,
            Self::MissingCheckout(_) | Self::Failed(_) => 1,
        }
    }
}

/// The checkout at or above `start`: its work tree and its git directory
/// (for a linked worktree, the worktree's own one). A bare repository is no
/// checkout. Discovery crosses file systems (`cross_fs`), so a checkout
/// above a mount point is still found. The
/// environment steers it as it steers git (#2049): `GIT_DIR`,
/// `GIT_WORK_TREE` and `GIT_CEILING_DIRECTORIES`, a relative path read
/// against `start`, the directory opentide ran git in.
fn discover(start: &Path) -> Option<(PathBuf, PathBuf)> {
    discover_with(start, &|name| std::env::var_os(name))
}

/// The environment discovery reads: a variable's raw value, which a path
/// need not spell in UTF-8. A caller with its own environment (the command
/// line's, which a test injects) passes it rather than the process's.
pub type OsEnv<'a> = &'a dyn Fn(&str) -> Option<std::ffi::OsString>;

/// A variable git reads as a path, made absolute against `start`; unset and
/// empty are the same.
fn env_path(env: OsEnv<'_>, name: &str, start: &Path) -> Option<PathBuf> {
    let value = env(name).filter(|value| !value.is_empty())?;
    Some(absolute(&start.join(value)))
}

/// `path`, absolute against the working directory (as written when that
/// cannot be read).
fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The checkout at or above `start`, as [`worktree`] finds it, reading
/// `GIT_DIR`, `GIT_WORK_TREE` and `GIT_CEILING_DIRECTORIES` from `env`
/// rather than the process: its work tree and its git directory (for a
/// linked worktree, the worktree's own one). `None` when there is no
/// checkout, or the repository is bare.
#[must_use]
pub fn discover_with(start: &Path, env: OsEnv<'_>) -> Option<(PathBuf, PathBuf)> {
    let work_tree = env_path(env, "GIT_WORK_TREE", start);
    if let Some(git_dir) = env_path(env, "GIT_DIR", start) {
        return named_repository(start, git_dir, work_tree);
    }
    let ceilings = env("GIT_CEILING_DIRECTORIES")
        .map(|dirs| ceiling_dirs(&dirs))
        .unwrap_or_default();
    let options = gix_discover::upwards::Options {
        cross_fs: true,
        dot_git_only: true,
        ceiling_dirs: ceilings.clone(),
        // git ignores the ceilings that are not above `start` rather than
        // failing.
        match_ceiling_dir_or_error: false,
        ..Default::default()
    };
    let (path, _trust) = gix_discover::upwards_opts(start, options).ok()?;
    let (git_dir, work_dir) = path.into_repository_and_work_tree_directories();
    // gix stops at a ceiling after looking in it; git stops below it, unless
    // the ceiling is `start` itself.
    if !ceilings.is_empty() {
        let found = work_dir
            .as_deref()
            .or_else(|| git_dir.parent())
            .and_then(|dir| gix_path::realpath(dir).ok());
        let start = gix_path::realpath(start).ok();
        if found.is_some_and(|found| Some(&found) != start.as_ref() && ceilings.contains(&found)) {
            return None;
        }
    }
    // `GIT_WORK_TREE` names the work tree of the repository found.
    Some((work_tree.or(work_dir)?, git_dir))
}

/// The repository `GIT_DIR` names, without a search: a file there is a
/// gitfile (`gitdir: <path>`). Its work tree is `GIT_WORK_TREE`, else none
/// in a bare repository (`core.bare`), else `core.worktree`, else `start`,
/// the directory git runs in. `core.worktree` is read only here: git also
/// applies it to a git directory found by the search (run inside the git
/// directory, say), a layout opentide does not follow.
fn named_repository(
    start: &Path,
    git_dir: PathBuf,
    work_tree: Option<PathBuf>,
) -> Option<(PathBuf, PathBuf)> {
    let git_dir = if git_dir.is_file() {
        gix_discover::path::from_gitdir_file(&git_dir).ok()?
    } else {
        git_dir
    };
    gix_discover::is_git(&git_dir).ok()?;
    if let Some(work_tree) = work_tree {
        return Some((work_tree, git_dir));
    }
    let config = config(&git_dir);
    // git reads `core.bare` first: a bare repository has no work tree, even
    // with `core.worktree` set.
    let bare = config
        .as_ref()
        .and_then(|config| config.boolean("core.bare").ok().flatten())
        .unwrap_or(false);
    if bare {
        return None;
    }
    if let Some(configured) = config
        .as_ref()
        .and_then(|config| config.path("core.worktree"))
    {
        let configured = gix_path::from_bstr(configured.value.as_bstr()).ok()?;
        return Some((absolute(&git_dir.join(configured)), git_dir));
    }
    Some((absolute(start), git_dir))
}

/// `GIT_CEILING_DIRECTORIES` as git reads it: absolute paths separated as in
/// `PATH`, relative ones skipped; those before an empty entry have their
/// symbolic links resolved, those after it are taken as written.
fn ceiling_dirs(value: &std::ffi::OsStr) -> Vec<PathBuf> {
    let mut resolve = true;
    let mut dirs = Vec::new();
    for dir in std::env::split_paths(value) {
        if dir.as_os_str().is_empty() {
            resolve = false;
        } else if dir.is_absolute() {
            let resolved = resolve.then(|| gix_path::realpath(&dir).ok()).flatten();
            dirs.push(resolved.unwrap_or(dir));
        }
    }
    dirs
}

/// The work tree of the checkout at or above `start`.
pub fn worktree(start: &Path) -> Option<PathBuf> {
    discover(start).map(|(work_dir, _)| work_dir)
}

/// [`worktree`], reading the environment from `env` (see [`discover_with`]).
#[must_use]
pub fn worktree_with(start: &Path, env: OsEnv<'_>) -> Option<PathBuf> {
    discover_with(start, env).map(|(work_dir, _)| work_dir)
}

fn failed(message: impl Into<String>) -> GitError {
    GitError::Failed(message.into())
}

/// A repository: its references and its objects.
struct Repo {
    /// The git directory (for a linked worktree, the worktree's own one),
    /// whose configuration names a branch's upstream.
    git_dir: PathBuf,
    refs: gix_ref::file::Store,
    odb: gix_odb::Handle,
    /// Whether the clone is shallow (git's `shallow` file): it then names
    /// parents it does not hold.
    shallow: bool,
}

/// Opens the checkout at or above `start`.
fn open(start: &Path) -> Result<Repo, GitError> {
    open_with(start, &|name| std::env::var_os(name))
}

/// [`open`], discovering the checkout with the environment `env`.
fn open_with(start: &Path, env: OsEnv<'_>) -> Result<Repo, GitError> {
    let (top, git_dir) =
        discover_with(start, env).ok_or_else(|| GitError::MissingCheckout(start.to_path_buf()))?;
    // A linked worktree's git directory names the repository it shares.
    let common =
        match gix_discover::path::from_plain_file_relative_to_file(&git_dir.join("commondir")) {
            Some(Ok(common)) => common,
            Some(Err(error)) => {
                return Err(failed(format!(
                    "Could not open the git repository at {}: {error}",
                    top.display()
                )));
            }
            None => git_dir.clone(),
        };
    let kind = gix_hash::Kind::Sha1;
    let refs = if common == git_dir {
        gix_ref::file::Store::at(git_dir.clone(), kind)
    } else {
        gix_ref::file::Store::for_linked_worktree(git_dir.clone(), common.clone(), kind)
    };
    let odb = gix_odb::at(common.join("objects"), kind).map_err(|error| {
        failed(format!(
            "Could not open the git repository at {}: {error}",
            top.display()
        ))
    })?;
    let shallow = common.join("shallow").is_file();
    Ok(Repo {
        git_dir,
        refs,
        odb,
        shallow,
    })
}

/// A commit's tree and parents.
struct Commit {
    tree: ObjectId,
    parents: Vec<ObjectId>,
}

impl Repo {
    fn commit(&self, id: ObjectId) -> Option<Commit> {
        let mut buf = Vec::new();
        let commit = self.odb.find_commit(&id, &mut buf).ok()?;
        Some(Commit {
            tree: commit.tree(),
            parents: commit.parents().collect(),
        })
    }

    /// The commit `name` (a reference) points at, symbolic references
    /// followed and annotated tags peeled.
    fn reference(&self, name: &str) -> Option<ObjectId> {
        let mut reference = self.refs.try_find(name).ok()??;
        let id = reference.peel_to_id(&self.refs, &self.odb).ok()?;
        self.commit(id).map(|_| id)
    }
}

/// An error for the rev-spec parser.
fn refused(message: String) -> gix_error::Error {
    gix_error::Message::new(message).raise()
}

/// Resolves the revisions `gix_revision::spec::parse` reads, as git does:
/// references (partial names searched as git does: `refs/`, tags, heads,
/// remotes), object ids and their prefixes, parent and ancestor steps,
/// reflog entries (`HEAD@{1}`, `main@{yesterday}`), the branches checked out
/// before (`@{-1}`), a branch's upstream (`@{u}`) and message searches
/// (`:/fix`, `HEAD^{/fix}`). What names no single commit is refused: ranges,
/// paths (`HEAD:file`, `:file`), trees and blobs; and `@{push}`, whose
/// branch depends on the push configuration. Without `every_form`, the
/// forms that name no commit a CI run diffs (reflogs, earlier branches,
/// upstreams, message searches) are refused as well.
struct Resolve<'r> {
    repo: &'r Repo,
    /// Whether reflogs, earlier branches, upstreams and message searches
    /// are read (`deploy replay-state`'s commit, which a person may type).
    every_form: bool,
    current: Option<ObjectId>,
    /// The reference the revision named last (`HEAD`, `refs/heads/main`),
    /// whose reflog and upstream `@{...}` reads.
    current_ref: Option<gix_ref::FullName>,
    /// Why the revision was refused, in words a person reads.
    refusal: Option<String>,
}

impl Resolve<'_> {
    /// `id` with its annotated tags peeled, when that is a commit.
    fn peel_to_commit(&self, mut id: ObjectId) -> Option<ObjectId> {
        let mut buf = Vec::new();
        loop {
            let data = self.repo.odb.try_find(&id, &mut buf).ok()??;
            match data.kind {
                gix_object::Kind::Commit => return Some(id),
                gix_object::Kind::Tag => {
                    id = gix_object::TagRefIter::from_bytes(data.data, gix_hash::Kind::Sha1)
                        .target_id()
                        .ok()?;
                }
                _ => return None,
            }
        }
    }

    fn current(&self) -> Result<ObjectId, gix_error::Error> {
        self.current
            .ok_or_else(|| refused("no revision to start from".to_owned()))
    }

    /// Refuses the revision, remembering `message` for the person.
    fn refuse(&mut self, message: String) -> gix_error::Error {
        self.refusal = Some(message.clone());
        refused(message)
    }

    fn unsupported(&mut self, what: &str) -> Result<(), gix_error::Error> {
        Err(self.refuse(what.to_owned()))
    }

    /// Refuses `what` unless every form is read.
    fn every_form(&mut self, what: &str) -> Result<(), gix_error::Error> {
        if self.every_form {
            Ok(())
        } else {
            self.unsupported(&format!("{what} names no commit a run diffs"))
        }
    }

    /// The reference `@{...}` applies to: the one named last, else the
    /// branch `HEAD` is on (`HEAD` itself when detached).
    fn anchor_ref(&self) -> Option<gix_ref::FullName> {
        if let Some(name) = &self.current_ref {
            return Some(name.clone());
        }
        let head = self.repo.refs.try_find("HEAD").ok()??;
        Some(match head.target {
            gix_ref::Target::Symbolic(name) => name,
            gix_ref::Target::Object(_) => head.name,
        })
    }

    /// The reflog of `name`, newest entry first. The file is read whole, so
    /// a line of any length (a long commit subject) is read.
    fn reflog_lines(&self, name: &gix_ref::FullName) -> Result<Vec<gix_ref::log::Line>, String> {
        let mut buf = Vec::new();
        let lines = self
            .repo
            .refs
            .reflog_iter(name.as_ref(), &mut buf)
            .map_err(|error| format!("could not read the reflog of {name}: {error}"))?
            .ok_or_else(|| format!("{name} has no reflog"))?;
        let mut lines = lines
            .map(|line| line.map(gix_ref::log::Line::from))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("could not read the reflog of {name}: {error}"))?;
        lines.reverse();
        Ok(lines)
    }

    /// The commit `@{n}` or `@{<date>}` names in `lines` (newest first), as
    /// git reads it: the n-th entry's new value; for a date, the newest
    /// entry at or before it, else the oldest entry's previous value.
    fn reflog_entry(
        lines: &[gix_ref::log::Line],
        name: &gix_ref::FullName,
        query: delegate::ReflogLookup,
    ) -> Result<ObjectId, String> {
        match query {
            delegate::ReflogLookup::Entry(n) => {
                if let Some(line) = lines.get(n) {
                    return Ok(line.new_oid);
                }
                // One past the oldest entry is the value before it.
                match lines.last() {
                    Some(oldest) if n == lines.len() && !oldest.previous_oid.is_null() => {
                        Ok(oldest.previous_oid)
                    }
                    _ => Err(format!(
                        "the reflog of {name} has only {} entries",
                        lines.len()
                    )),
                }
            }
            delegate::ReflogLookup::Date(time) => {
                if let Some(line) = lines
                    .iter()
                    .find(|line| line.signature.time.seconds <= time.seconds)
                {
                    return Ok(line.new_oid);
                }
                let oldest = lines
                    .last()
                    .ok_or_else(|| format!("the reflog of {name} is empty"))?;
                Ok(if oldest.previous_oid.is_null() {
                    oldest.new_oid
                } else {
                    oldest.previous_oid
                })
            }
        }
    }

    /// The `n`-th branch (or commit) `HEAD` was checked out from, newest
    /// first, as `checkout: moving from <from> to <to>` reflog lines name it.
    fn checked_out_before(&self, n: usize) -> Result<String, String> {
        let head = gix_ref::FullName::try_from("HEAD")
            .map_err(|error| format!("HEAD is not a reference name: {error}"))?;
        let lines = self.reflog_lines(&head)?;
        lines
            .iter()
            .filter_map(|line| {
                let rest = line.message.strip_prefix(b"checkout: moving from ")?;
                let to = rest.rfind(b" to ")?;
                rest.get(..to)?.to_str().ok().map(str::to_owned)
            })
            .nth(n.saturating_sub(1))
            .ok_or_else(|| format!("HEAD's reflog names fewer than {n} checked-out branches"))
    }

    /// The commits reachable from `tips`, newest committer date first
    /// (git's order for `:/`), the first whose message `regex` matches (or,
    /// `negated`, does not match).
    fn search_messages(
        &self,
        tips: Vec<ObjectId>,
        regex: &regex::bytes::Regex,
        negated: bool,
    ) -> Option<ObjectId> {
        let mut seen: std::collections::HashSet<ObjectId> = tips.iter().copied().collect();
        let mut queue = std::collections::BinaryHeap::new();
        let mut buf = Vec::new();
        for tip in tips {
            if let Ok(commit) = self.repo.odb.find_commit(&tip, &mut buf) {
                queue.push((commit.time().map_or(0, |time| time.seconds), tip));
            }
        }
        while let Some((_, id)) = queue.pop() {
            let Ok(commit) = self.repo.odb.find_commit(&id, &mut buf) else {
                continue;
            };
            if regex.is_match(commit.message) != negated {
                return Some(id);
            }
            let parents: Vec<ObjectId> = commit.parents().collect();
            for parent in parents {
                if seen.insert(parent) {
                    let mut parent_buf = Vec::new();
                    // A shallow clone names parents it does not hold.
                    if let Ok(found) = self.repo.odb.find_commit(&parent, &mut parent_buf) {
                        queue.push((found.time().map_or(0, |time| time.seconds), parent));
                    }
                }
            }
        }
        None
    }

    /// Every commit a reference or `HEAD` points at, `:/`'s starting points.
    fn every_tip(&self) -> Vec<ObjectId> {
        let mut tips = Vec::new();
        let mut add = |mut reference: gix_ref::Reference| {
            if let Ok(id) = reference.peel_to_id(&self.repo.refs, &self.repo.odb)
                && let Some(commit) = self.peel_to_commit(id)
            {
                tips.push(commit);
            }
        };
        if let Ok(Some(head)) = self.repo.refs.try_find("HEAD") {
            add(head);
        }
        if let Ok(platform) = self.repo.refs.iter()
            && let Ok(all) = platform.all()
        {
            for reference in all.flatten() {
                add(reference);
            }
        }
        tips.sort();
        tips.dedup();
        tips
    }
}

impl delegate::Revision for Resolve<'_> {
    fn find_ref(&mut self, name: &BStr) -> Result<(), gix_error::Error> {
        let found = self
            .repo
            .refs
            .try_find(name)
            .map_err(|error| refused(format!("reference {name}: {error}")))?
            .ok_or_else(|| refused(format!("no reference {name}")))?;
        let mut found = found;
        let full_name = found.name.clone();
        let id = found
            .peel_to_id(&self.repo.refs, &self.repo.odb)
            .map_err(|error| refused(format!("reference {name}: {error}")))?;
        self.current = Some(id);
        self.current_ref = Some(full_name);
        Ok(())
    }

    fn disambiguate_prefix(
        &mut self,
        prefix: gix_hash::Prefix,
        _hint: Option<delegate::PrefixHint<'_>>,
    ) -> Result<(), gix_error::Error> {
        match self.repo.odb.lookup_prefix(prefix, None) {
            Ok(Some(Ok(id))) => {
                self.current = Some(id);
                self.current_ref = None;
                Ok(())
            }
            Ok(Some(Err(()))) => Err(refused(format!("{prefix} is ambiguous"))),
            Ok(None) => Err(refused(format!("no object {prefix}"))),
            Err(error) => Err(refused(format!("{prefix}: {error}"))),
        }
    }

    fn reflog(&mut self, query: delegate::ReflogLookup) -> Result<(), gix_error::Error> {
        self.every_form("a reflog entry")?;
        let name = self
            .anchor_ref()
            .ok_or_else(|| self.refuse("HEAD names no reference".to_owned()))?;
        let found = self
            .reflog_lines(&name)
            .and_then(|lines| Self::reflog_entry(&lines, &name, query));
        match found {
            Ok(id) => {
                self.current = Some(id);
                self.current_ref = None;
                Ok(())
            }
            Err(message) => Err(self.refuse(message)),
        }
    }

    fn nth_checked_out_branch(&mut self, branch_no: usize) -> Result<(), gix_error::Error> {
        self.every_form("a checked-out branch")?;
        let before = self
            .checked_out_before(branch_no)
            .map_err(|message| self.refuse(message))?;
        // A detached checkout is named by its commit id.
        if let Ok(id) = ObjectId::from_hex(before.as_bytes()) {
            self.current = Some(id);
            self.current_ref = None;
            return Ok(());
        }
        let branch = format!("refs/heads/{before}");
        self.find_ref(branch.as_bytes().as_bstr())
            .or_else(|_| self.find_ref(before.as_bytes().as_bstr()))
            .map_err(|_| {
                self.refuse(format!(
                    "the branch checked out before, {before}, no longer exists"
                ))
            })
    }

    fn sibling_branch(&mut self, kind: delegate::SiblingBranch) -> Result<(), gix_error::Error> {
        self.every_form("an upstream branch")?;
        if matches!(kind, delegate::SiblingBranch::Push) {
            return self.unsupported(
                "@{push} is not supported: the branch a push goes to depends on the push \
                 configuration; name the remote branch instead (origin/<branch>)",
            );
        }
        let branch = self
            .anchor_ref()
            .and_then(|name| {
                // `HEAD@{u}` is the upstream of the branch HEAD is on.
                if name.as_bstr() == "HEAD" {
                    return current_branch(self.repo);
                }
                name.as_bstr()
                    .to_str()
                    .ok()?
                    .strip_prefix("refs/heads/")
                    .map(str::to_owned)
            })
            .ok_or_else(|| self.refuse("@{upstream} needs a branch".to_owned()))?;
        let upstream = upstream_ref(&self.repo.git_dir, &branch)
            .ok_or_else(|| self.refuse(format!("branch {branch} has no upstream")))?;
        let upstream = upstream.map_err(|merge| {
            self.refuse(format!(
                "the upstream of {branch}, {merge}, is fetched by none of its remote's refspecs"
            ))
        })?;
        self.find_ref(upstream.as_bytes().as_bstr()).map_err(|_| {
            self.refuse(format!(
                "the upstream of {branch}, {upstream}, is not in the checkout"
            ))
        })
    }
}

impl delegate::Navigate for Resolve<'_> {
    fn traverse(&mut self, kind: delegate::Traversal) -> Result<(), gix_error::Error> {
        let mut id = self.current()?;
        let (steps, parent) = match kind {
            delegate::Traversal::NthParent(n) => (1, n.saturating_sub(1)),
            delegate::Traversal::NthAncestor(n) => (n, 0),
        };
        for _ in 0..steps {
            let commit = self
                .peel_to_commit(id)
                .and_then(|commit| self.repo.commit(commit))
                .ok_or_else(|| refused(format!("no commit {id}")))?;
            id = *commit
                .parents
                .get(parent)
                .ok_or_else(|| refused(format!("commit {id} has no such parent")))?;
        }
        self.current = Some(id);
        Ok(())
    }

    fn peel_until(&mut self, kind: delegate::PeelTo<'_>) -> Result<(), gix_error::Error> {
        let id = self.current()?;
        match kind {
            delegate::PeelTo::ObjectKind(gix_object::Kind::Commit)
            | delegate::PeelTo::RecursiveTagObject => {
                self.current = Some(
                    self.peel_to_commit(id)
                        .ok_or_else(|| refused(format!("{id} is not a commit")))?,
                );
                Ok(())
            }
            delegate::PeelTo::ValidObject => {
                let mut buf = Vec::new();
                match self.repo.odb.try_find(&id, &mut buf) {
                    Ok(Some(_)) => Ok(()),
                    _ => Err(refused(format!("no object {id}"))),
                }
            }
            delegate::PeelTo::Path(_) => {
                self.unsupported("a file in a commit (<rev>:<path>) is not a commit")
            }
            delegate::PeelTo::ObjectKind(_) => {
                self.unsupported("a tree, blob or tag object is not a commit")
            }
        }
    }

    fn find(&mut self, regex: &BStr, negated: bool) -> Result<(), gix_error::Error> {
        self.every_form("a message search")?;
        let pattern = regex
            .to_str()
            .map_err(|_| self.refuse(format!("the message search {regex} is not UTF-8")))?;
        let compiled = regex::bytes::Regex::new(pattern).map_err(|error| {
            self.refuse(format!(
                "the message search {pattern} is not a regular expression: {error}"
            ))
        })?;
        // `<rev>^{/text}` searches from `<rev>`; `:/text` from every reference.
        let tips = match self.current {
            Some(id) => self.peel_to_commit(id).into_iter().collect(),
            None => self.every_tip(),
        };
        match self.search_messages(tips, &compiled, negated) {
            Some(id) => {
                self.current = Some(id);
                self.current_ref = None;
                Ok(())
            }
            None => Err(self.refuse(format!("no commit's message matches {pattern}"))),
        }
    }

    fn index_lookup(&mut self, _path: &BStr, _stage: u8) -> Result<(), gix_error::Error> {
        self.unsupported("a file in the index (:<path>) is not a commit")
    }
}

impl delegate::Kind for Resolve<'_> {
    fn kind(&mut self, _kind: gix_revision::spec::Kind) -> Result<(), gix_error::Error> {
        self.unsupported("a range (a..b, a...b, ^a) names more than one commit")
    }
}

impl gix_revision::spec::parse::Delegate for Resolve<'_> {
    fn done(&mut self) -> Result<(), gix_error::Error> {
        Ok(())
    }
}

/// The commit `rev` names, as `git rev-parse` reads it (see [`Resolve`]);
/// an annotated tag peeled.
fn commit_id(repo: &Repo, rev: &str) -> Option<ObjectId> {
    resolve_commit(repo, rev, false).ok()
}

/// [`commit_id`], reading every form when `every_form`, or why `rev` names
/// no commit, when opentide knows (`None` for a revision that names
/// nothing).
fn resolve_commit(repo: &Repo, rev: &str, every_form: bool) -> Result<ObjectId, Option<String>> {
    let mut resolve = Resolve {
        repo,
        every_form,
        current: None,
        current_ref: None,
        refusal: None,
    };
    if gix_revision::spec::parse(rev.as_bytes().as_bstr(), &mut resolve).is_err() {
        return Err(resolve.refusal);
    }
    let id = resolve.current.ok_or(None)?;
    resolve
        .peel_to_commit(id)
        .ok_or_else(|| Some(format!("{id} is not a commit")))
}

fn has_commit(repo: &Repo, id: &str) -> bool {
    ObjectId::from_hex(id.as_bytes()).is_ok_and(|id| repo.commit(id).is_some())
}

fn parents(repo: &Repo, id: ObjectId) -> Option<Vec<ObjectId>> {
    repo.commit(id).map(|commit| commit.parents)
}

/// HEAD's first parent when the checkout holds it:
/// `None` for the first commit; an error when a shallow clone names a parent
/// it does not hold, which must not read as an empty diff.
fn production_base(repo: &Repo, head: ObjectId) -> Result<Option<ObjectId>, GitError> {
    let parents =
        parents(repo, head).ok_or_else(|| failed(format!("Could not find git commit {head}")))?;
    let Some(parent) = parents.first().copied() else {
        return Ok(None);
    };
    if repo.commit(parent).is_none() {
        return Err(missing_parent(repo, parent));
    }
    Ok(Some(parent))
}

/// The failure of a parent the checkout names but does not hold: in a
/// shallow clone, what to fetch.
fn missing_parent(repo: &Repo, parent: ObjectId) -> GitError {
    if repo.shallow {
        failed(format!(
            "Could not find git commit {parent}: {SHALLOW_HINT}"
        ))
    } else {
        failed(format!("Could not find git commit {parent}"))
    }
}

/// Why a shallow clone cannot compute a diff, and what to fetch.
const SHALLOW_HINT: &str = "the checkout is shallow, so it does not hold the commits the diff \
                            needs. Check out the full history (`fetch-depth: 0` in GitHub \
                            Actions, `GIT_DEPTH: \"0\"` on GitLab, `fetchDepth: 0` on Azure \
                            Pipelines)";

/// The first parent of the merge commit a request run builds, when `merge`
/// has two parents, the first is in the checkout, and the second is `head`
/// when given.
fn merge_first_parent(repo: &Repo, merge: Option<&str>, head: Option<&str>) -> Option<ObjectId> {
    let merge = ObjectId::from_hex(merge?.as_bytes()).ok()?;
    let found = parents(repo, merge)?;
    let [first, second] = found.as_slice() else {
        return None;
    };
    if head.is_some_and(|head| ObjectId::from_hex(head.as_bytes()).ok() != Some(*second)) {
        return None;
    }
    repo.commit(*first).map(|_| *first)
}

fn event(env: Env<'_>) -> Option<serde_json::Value> {
    let path = set(env, "GITHUB_EVENT_PATH")?;
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Where a push's diff starts, from what the CI platform says the branch
/// held before the push (#1683).
enum PushBefore {
    /// The branch's tip before the push, a commit the checkout holds.
    Commit(String),
    /// All zeros: the push created the branch, so every file it holds is new.
    Created,
    /// Nothing usable: the run reads its last commit, and says why.
    Unknown(String),
}

/// Whether a commit id is all zeros, as a push that created its branch
/// names the commit before it.
fn all_zeros(sha: &str) -> bool {
    sha.trim_matches('0').is_empty()
}

/// The branch tip before a GitHub push: the push
/// event's `before`.
fn github_push_before(repo: &Repo, env: Env<'_>) -> PushBefore {
    let Some(before) = event(env).and_then(|event| {
        event
            .get("before")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }) else {
        return PushBefore::Unknown("the run names no push event with a `before` commit".into());
    };
    if all_zeros(&before) {
        PushBefore::Created
    } else if has_commit(repo, &before) {
        PushBefore::Commit(before)
    } else {
        PushBefore::Unknown(format!(
            "the push event's `before` commit {before} is not in this checkout"
        ))
    }
}

/// The branch tip before a GitLab push: `CI_COMMIT_BEFORE_SHA`. GitLab
/// sets it to all zeros on a branch's first push, and also on a pipeline no
/// push started (`CI_PIPELINE_SOURCE` `web`, `schedule`, `api`, ...), which
/// is not a new branch. A commit the checkout does not hold (a force push
/// replaced it) is no base either.
fn gitlab_push_before(repo: &Repo, env: Env<'_>) -> PushBefore {
    match set(env, "CI_COMMIT_BEFORE_SHA") {
        Some(before) if all_zeros(&before) => match set(env, "CI_PIPELINE_SOURCE") {
            None => PushBefore::Created,
            Some(source) if source == "push" => PushBefore::Created,
            Some(source) => PushBefore::Unknown(format!(
                "a `{source}` pipeline names no commit before it (CI_COMMIT_BEFORE_SHA is all zeros)"
            )),
        },
        Some(before) if commit_id(repo, &before).is_some() => PushBefore::Commit(before),
        Some(before) => PushBefore::Unknown(format!(
            "CI_COMMIT_BEFORE_SHA {before} is not in this checkout"
        )),
        None => PushBefore::Unknown("CI_COMMIT_BEFORE_SHA is not set".into()),
    }
}

/// The variable that names the commit a push's diff starts at, on any
/// provider (#1683): for Azure Pipelines, which names none itself.
pub const PUSH_BASE_VARIABLE: &str = "OPENTIDE_PUSH_BASE";

/// How the note of a push that read only its last commit begins, for a host
/// that shows it as the CI run's warning.
pub const LAST_COMMIT_ONLY_PREFIX: &str = "This push's diff starts at its last commit's parent";

/// The commit `OPENTIDE_PUSH_BASE` names, when it is set: a commit of the
/// checkout that is an ancestor of HEAD, else an error.
fn push_base_override(repo: &Repo, env: Env<'_>) -> Result<Option<ObjectId>, GitError> {
    let Some(value) = set(env, PUSH_BASE_VARIABLE) else {
        return Ok(None);
    };
    let base = commit_id(repo, &value).ok_or_else(|| {
        GitError::PushBase(if repo.shallow {
            format!(
                "{PUSH_BASE_VARIABLE}={value} is not a commit of this checkout: the checkout is \
                 shallow, so it does not hold it. Check out the full history (`fetchDepth: 0` on \
                 Azure Pipelines, `fetch-depth: 0` in GitHub Actions, `GIT_DEPTH: \"0\"` on GitLab)"
            )
        } else {
            format!(
                "{PUSH_BASE_VARIABLE}={value} is not a commit of this checkout: name a commit id \
                 the checkout holds"
            )
        })
    })?;
    let head = head_commit(repo)
        .ok_or_else(|| failed("The git repository has no commits yet".to_owned()))?;
    if merge_base(repo, base, head) != Some(base) {
        return Err(GitError::PushBase(format!(
            "{PUSH_BASE_VARIABLE}={value} is not an ancestor of HEAD ({head}): name a commit \
             the checked-out commit descends from"
        )));
    }
    Ok(Some(base))
}

/// What a push run that read only its last commit says: the commits before
/// it in the same push are not in the diff.
fn last_commit_only(why: &str) -> String {
    format!(
        "{LAST_COMMIT_ONLY_PREFIX}: {why}. Rules that earlier \
         commits of the same push changed are not in it; pass --all to deploy every rule file"
    )
}

/// A pull request's base and head commits from the event.
fn github_request_shas(repo: &Repo, env: Env<'_>) -> Option<(String, String)> {
    let event = event(env)?;
    let request = event.get("pull_request")?;
    let base = request.get("base")?.get("sha")?.as_str()?.to_owned();
    let head = request.get("head")?.get("sha")?.as_str()?.to_owned();
    (has_commit(repo, &base) && has_commit(repo, &head)).then_some((base, head))
}

fn merge_base(repo: &Repo, a: ObjectId, b: ObjectId) -> Option<ObjectId> {
    let mut graph = gix_revwalk::Graph::new(&repo.odb, None);
    let bases = gix_revision::merge_base(a, &[b], &mut graph).ok()??;
    Some(*bases.first())
}

/// The request's base and head from `origin/<target>` and `origin/<source>`,
/// as the checkout holds them. Nothing is fetched (this crate reads no
/// network), so the checkout must already hold both branches.
fn origin_request(
    repo: &Repo,
    source: &str,
    target: &str,
) -> Result<(ObjectId, ObjectId), GitError> {
    let source = format!("origin/{}", source.trim_start_matches("refs/heads/"));
    let target = format!("origin/{target}");
    let target_id = commit_id(repo, &target)
        .ok_or_else(|| failed(format!("Could not find git ref {target}")))?;
    let source_id = commit_id(repo, &source)
        .ok_or_else(|| failed(format!("Could not find git ref {source}")))?;
    let base = merge_base(repo, target_id, source_id).ok_or_else(|| {
        failed(
            "You may not have a sufficient Checkout Depth configuration | If you run very old Pull \
             Requests, this setting may need to be increased, or reopen a PR",
        )
    })?;
    Ok((base, source_id))
}

/// The paths added, renamed or modified from `base` to `head`, relative to
/// the git top level, sorted. With no `base` (`head` is a root commit, the
/// first of a repository), every file of `head` is added.
fn changed_between(
    repo: &Repo,
    base: Option<ObjectId>,
    head: ObjectId,
) -> Result<Vec<String>, GitError> {
    let mut paths: Vec<String> = tree_changes(repo, base, head)?
        .into_iter()
        .filter_map(|change| match change {
            gix_diff::tree::recorder::Change::Addition {
                entry_mode, path, ..
            }
            | gix_diff::tree::recorder::Change::Modification {
                entry_mode, path, ..
            } if !entry_mode.is_tree() => Some(String::from_utf8_lossy(&path).into_owned()),
            _ => None,
        })
        .collect();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// The files deleted from `base` to `head`, each with the content `base`
/// held, sorted by path. With no `base`, nothing was deleted.
fn deleted_between(
    repo: &Repo,
    base: Option<ObjectId>,
    head: ObjectId,
) -> Result<Vec<Deleted>, GitError> {
    if base.is_none() {
        return Ok(Vec::new());
    }
    let mut deleted = Vec::new();
    for change in tree_changes(repo, base, head)? {
        let gix_diff::tree::recorder::Change::Deletion {
            entry_mode,
            oid,
            path,
            ..
        } = change
        else {
            continue;
        };
        if entry_mode.is_tree() {
            continue;
        }
        let mut buf = Vec::new();
        let blob = repo
            .odb
            .find_blob(&oid, &mut buf)
            .map_err(|error| failed(format!("Could not find git object {oid}: {error}")))?;
        deleted.push(Deleted {
            path: String::from_utf8_lossy(&path).into_owned(),
            content: blob.data.to_vec(),
        });
    }
    deleted.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(deleted)
}

/// A file a commit changed against its first parent, with its content on
/// each side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitChange {
    /// Its path, relative to the git top level.
    pub path: String,
    /// What the parent held; `None` when the commit added it.
    pub before: Option<Vec<u8>>,
    /// What the commit holds; `None` when the commit deleted it.
    pub after: Option<Vec<u8>>,
}

/// The files under `folder` (relative to `start`) that the commit `rev`
/// changed against its first parent, sorted by path, as `git diff
/// --no-renames <rev>^ <rev> -- <folder>` lists them, each with what `git
/// show` prints of it on either side. `rev` is read as `git rev-parse` reads
/// it, except what names no single commit (a range, a path, `@{push}`). The
/// checkout is found with `env` (`GIT_DIR`, `GIT_WORK_TREE`,
/// `GIT_CEILING_DIRECTORIES`; see [`discover_with`]). A root commit has no
/// parent to compare with, and an object the checkout cannot read is an
/// error, not an empty side.
pub fn commit_changes(
    start: &Path,
    env: OsEnv<'_>,
    rev: &str,
    folder: &str,
) -> Result<Vec<CommitChange>, GitError> {
    let (top, _) =
        discover_with(start, env).ok_or_else(|| GitError::MissingCheckout(start.to_path_buf()))?;
    let repo = open_with(start, env)?;
    let head = resolve_commit(&repo, rev, true).map_err(|reason| {
        failed(match reason {
            Some(reason) => format!("Could not find git commit {rev}: {reason}"),
            None => format!("Could not find git commit {rev}"),
        })
    })?;
    let parents = parents(&repo, head).ok_or_else(|| missing_parent(&repo, head))?;
    let Some(parent) = parents.first().copied() else {
        return Err(failed(format!(
            "Commit {rev} has no parent to compare with"
        )));
    };
    if repo.commit(parent).is_none() {
        return Err(missing_parent(&repo, parent));
    }
    let scope = pathspec_scope(start, &top, folder);
    let within = |path: &str| {
        scope.is_empty()
            || path
                .strip_prefix(scope.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    let blob = |oid: ObjectId| -> Result<Vec<u8>, GitError> {
        let mut buf = Vec::new();
        repo.odb
            .find_blob(&oid, &mut buf)
            .map(|blob| blob.data.to_vec())
            .map_err(|error| failed(format!("Could not find git object {oid}: {error}")))
    };
    let mut changes: std::collections::BTreeMap<String, CommitChange> =
        std::collections::BTreeMap::new();
    for change in tree_changes(&repo, Some(parent), head)? {
        use gix_diff::tree::recorder::Change;
        // A file's side, or none where the entry is a folder (a file that
        // became a folder, or the reverse, is a deletion and an addition).
        let side = |mode: gix_object::tree::EntryMode, oid: ObjectId| {
            if mode.is_tree() || mode.is_commit() {
                Ok(None)
            } else {
                blob(oid).map(Some)
            }
        };
        let (path, before, after) = match change {
            Change::Addition {
                entry_mode,
                oid,
                path,
                ..
            } => (path, None, side(entry_mode, oid)?),
            Change::Deletion {
                entry_mode,
                oid,
                path,
                ..
            } => (path, side(entry_mode, oid)?, None),
            Change::Modification {
                previous_entry_mode,
                previous_oid,
                entry_mode,
                oid,
                path,
            } => (
                path,
                side(previous_entry_mode, previous_oid)?,
                side(entry_mode, oid)?,
            ),
        };
        if before.is_none() && after.is_none() {
            continue;
        }
        let path = String::from_utf8_lossy(&path).into_owned();
        if !within(&path) {
            continue;
        }
        let entry = changes.entry(path.clone()).or_insert(CommitChange {
            path,
            before: None,
            after: None,
        });
        if before.is_some() {
            entry.before = before;
        }
        if after.is_some() {
            entry.after = after;
        }
    }
    Ok(changes.into_values().collect())
}

/// `folder`, a pathspec relative to `start`, as a path from the top level
/// `top` (`/`-separated, empty for the whole tree).
fn pathspec_scope(start: &Path, top: &Path, folder: &str) -> String {
    let below = match (gix_path::realpath(start), gix_path::realpath(top)) {
        (Ok(start), Ok(top)) => start
            .strip_prefix(&top)
            .ok()
            .map(|relative| {
                relative
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let parts: Vec<&str> = below
        .iter()
        .map(String::as_str)
        .chain(folder.split('/'))
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    parts.join("/")
}

/// Every change of a file or folder from `base` to `head`, as gix records
/// them (no rename tracking: a rename is a deletion and an addition).
fn tree_changes(
    repo: &Repo,
    base: Option<ObjectId>,
    head: ObjectId,
) -> Result<Vec<gix_diff::tree::recorder::Change>, GitError> {
    let tree = |id: ObjectId| -> Result<Vec<u8>, GitError> {
        let commit = repo
            .commit(id)
            .ok_or_else(|| failed(format!("Could not find git commit {id}")))?;
        let mut buf = Vec::new();
        repo.odb
            .find_tree_iter(&commit.tree, &mut buf)
            .map_err(|error| {
                failed(format!(
                    "Could not find git object {}: {error}",
                    commit.tree
                ))
            })?;
        Ok(buf)
    };
    // The empty tree: no entry, so each of `head`'s files is an addition.
    let old = match base {
        Some(base) => tree(base)?,
        None => Vec::new(),
    };
    let new = tree(head)?;
    let mut recorder = gix_diff::tree::Recorder::default();
    gix_diff::tree(
        gix_object::TreeRefIter::from_bytes(&old, gix_hash::Kind::Sha1),
        gix_object::TreeRefIter::from_bytes(&new, gix_hash::Kind::Sha1),
        gix_diff::tree::State::default(),
        &repo.odb,
        &mut recorder,
    )
    .map_err(|error| failed(format!("Could not find git object: {error}")))?;
    Ok(recorder.records)
}

/// A file the run's commits deleted, with the content it had before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deleted {
    /// Its path, relative to the git top level.
    pub path: String,
    /// What the base commit held.
    pub content: Vec<u8>,
}

/// The commits a run's diff spans: `base` (none for a root commit or a
/// push that created its branch) to `head`.
struct Range {
    repo: Repo,
    base: Option<ObjectId>,
    head: ObjectId,
    note: Option<String>,
}

/// The commit HEAD names, if any.
fn head_commit(repo: &Repo) -> Option<ObjectId> {
    repo.reference("HEAD")
}

/// The files the run's commits changed (`diff_calculation`), from the git
/// top level. `workspace` is the detection workspace; `cwd` the working
/// directory a CI run without its checkout variable searches from.
pub fn changed_paths(
    workspace: &Path,
    cwd: &Path,
    env: Env<'_>,
    source: DiffSource,
) -> Result<Vec<String>, GitError> {
    changed_paths_noted(workspace, cwd, env, source).map(|(paths, _)| paths)
}

/// [`changed_paths`], with what the run should say when a push's diff could
/// start only at its last commit's parent (#1683): the platform named no
/// commit the branch held before the push (Azure Pipelines never does), or
/// the checkout does not hold it, so earlier commits of the same push are
/// not in the diff. A push that created its branch (an all-zero `before`)
/// reads every file of the run's commit.
pub fn changed_paths_noted(
    workspace: &Path,
    cwd: &Path,
    env: Env<'_>,
    source: DiffSource,
) -> Result<(Vec<String>, Option<String>), GitError> {
    match diff_range(workspace, cwd, env, source)? {
        Some(range) => Ok((
            changed_between(&range.repo, range.base, range.head)?,
            range.note,
        )),
        None => Ok((Vec::new(), None)),
    }
}

/// The rule files [`changed_paths_noted`]'s diff deleted, each with the
/// content its base held, so a deploy can retire the rule (#1713). The diff
/// is the same one: a base it cannot find (a shallow checkout, a missing
/// commit) is the same error, never an empty list, and a push that created
/// its branch, or a repository's first commit, deleted nothing.
pub fn deleted_paths(
    workspace: &Path,
    cwd: &Path,
    env: Env<'_>,
    source: DiffSource,
) -> Result<Vec<Deleted>, GitError> {
    match diff_range(workspace, cwd, env, source)? {
        Some(range) => deleted_between(&range.repo, range.base, range.head),
        None => Ok(Vec::new()),
    }
}

/// The commits the run's diff spans; `None` for a local checkout with no
/// commit yet.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn diff_range(
    workspace: &Path,
    cwd: &Path,
    env: Env<'_>,
    source: DiffSource,
) -> Result<Option<Range>, GitError> {
    let platform = ci(env);
    let mut note = None;
    if source == DiffSource::LastCommit || platform == Ci::Local {
        if source == DiffSource::ChangeRequest {
            return Err(failed("A pull or merge request diff needs a CI run"));
        }
        let repo = open(workspace)?;
        let Some(head) = head_commit(&repo) else {
            return Ok(None);
        };
        // A root commit (no parent) added every file it holds.
        let base = production_base(&repo, head)?;
        return Ok(Some(Range {
            repo,
            base,
            head,
            note: None,
        }));
    }
    let variable = match platform {
        Ci::GitHub => "GITHUB_WORKSPACE",
        Ci::GitLab => "CI_PROJECT_DIR",
        Ci::Azure => "BUILD_SOURCESDIRECTORY",
        Ci::Local => "",
    };
    let searched = set(env, variable).map_or_else(|| cwd.to_path_buf(), |dir| cwd.join(dir));
    let repo = open(&searched)?;
    let head = head_commit(&repo);
    let (tip_name, mut latest) = match platform {
        Ci::GitHub => ("GITHUB_SHA", set(env, "GITHUB_SHA")),
        Ci::GitLab => ("CI_COMMIT_SHA", set(env, "CI_COMMIT_SHA")),
        _ => ("BUILD_SOURCEVERSION", set(env, "BUILD_SOURCEVERSION")),
    };
    // A push diffs from HEAD's first parent when its event names no base: a
    // checkout without a commit has none, which a CI run never is.
    let first_parent = || -> Result<Option<ObjectId>, GitError> {
        match head {
            Some(head) => production_base(&repo, head),
            None => Err(no_commits_yet(&searched)),
        }
    };
    let pushed_base = if source == DiffSource::Push {
        push_base_override(&repo, env)?.map(|base| base.to_string())
    } else {
        None
    };
    let base: Option<String> = match (platform, source) {
        (_, DiffSource::LastCommit) | (Ci::Local, _) => None,
        (_, DiffSource::Push) if pushed_base.is_some() => pushed_base,
        (Ci::GitHub, DiffSource::Push) => match github_push_before(&repo, env) {
            PushBefore::Commit(before) => Some(before),
            PushBefore::Created => {
                return whole_tree(repo, latest.as_deref(), tip_name).map(Some);
            }
            PushBefore::Unknown(why) => match first_parent()? {
                Some(base) => {
                    note = Some(last_commit_only(&why));
                    Some(base.to_string())
                }
                None => return root_changes(repo, latest.as_deref(), tip_name).map(Some),
            },
        },
        (Ci::GitHub, DiffSource::ChangeRequest) => {
            let (Some(source_branch), Some(target_branch)) =
                (set(env, "GITHUB_HEAD_REF"), set(env, "GITHUB_BASE_REF"))
            else {
                return Err(failed(
                    "Expected to find GITHUB_HEAD_REF and GITHUB_BASE_REF | Ensure this is running \
                     in a Pull Request pipeline",
                ));
            };
            let target_run = env("GITHUB_EVENT_NAME").as_deref() == Some("pull_request_target");
            let merge_parent = if target_run {
                None
            } else {
                merge_first_parent(&repo, latest.as_deref(), None)
            };
            let request = if target_run {
                github_request_shas(&repo, env)
            } else {
                None
            };
            let request_base = request.as_ref().and_then(|(base, head)| {
                merge_base(
                    &repo,
                    ObjectId::from_hex(base.as_bytes()).ok()?,
                    ObjectId::from_hex(head.as_bytes()).ok()?,
                )
            });
            if let Some(parent) = merge_parent {
                Some(parent.to_string())
            } else if let (Some((_, head)), Some(base)) = (&request, request_base) {
                latest = Some(head.clone());
                Some(base.to_string())
            } else {
                let (base, source) = origin_request(&repo, &source_branch, &target_branch)?;
                latest = Some(source.to_string());
                Some(base.to_string())
            }
        }
        (Ci::GitLab, DiffSource::Push) => match gitlab_push_before(&repo, env) {
            PushBefore::Commit(before) => Some(before),
            PushBefore::Created => {
                return whole_tree(repo, latest.as_deref(), tip_name).map(Some);
            }
            PushBefore::Unknown(why) => match first_parent()? {
                Some(base) => {
                    note = Some(last_commit_only(&why));
                    Some(base.to_string())
                }
                None => return root_changes(repo, latest.as_deref(), tip_name).map(Some),
            },
        },
        (Ci::GitLab, DiffSource::ChangeRequest) => {
            let mut base = set(env, "CI_MERGE_REQUEST_DIFF_BASE_SHA");
            if matches!(
                env("CI_MERGE_REQUEST_EVENT_TYPE").as_deref(),
                Some("merged_result" | "merge_train")
            ) {
                let source_head = set(env, "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA");
                if let Some(parent) =
                    merge_first_parent(&repo, latest.as_deref(), source_head.as_deref())
                {
                    base = Some(parent.to_string());
                } else if let Some(source_head) = source_head {
                    latest = Some(source_head);
                }
            }
            base
        }
        // Azure Pipelines names no commit the branch held before the push.
        (Ci::Azure, DiffSource::Push) => match first_parent()? {
            Some(base) => {
                note = Some(last_commit_only(
                    "Azure Pipelines does not name the commit the branch held before the push \
                     (the diff is exact for a one-commit push, and for a merge a pull request \
                     completed on the target branch; set OPENTIDE_PUSH_BASE, or build every \
                     commit with a branch policy, for the rest)",
                ));
                Some(base.to_string())
            }
            None => return root_changes(repo, latest.as_deref(), tip_name).map(Some),
        },
        (Ci::Azure, DiffSource::ChangeRequest) => {
            let (Some(source_branch), Some(target_branch)) = (
                set(env, "SYSTEM_PULLREQUEST_SOURCEBRANCH"),
                set(env, "SYSTEM_PULLREQUEST_TARGETBRANCHNAME"),
            ) else {
                return Err(failed(
                    "Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and \
                     SYSTEM_PULLREQUEST_TARGETBRANCHNAME | Ensure this is running in a Pull Request \
                     pipeline",
                ));
            };
            let head = set(env, "SYSTEM_PULLREQUEST_SOURCECOMMITID");
            if let Some(parent) = merge_first_parent(&repo, latest.as_deref(), head.as_deref()) {
                Some(parent.to_string())
            } else {
                let (base, source) = origin_request(&repo, &source_branch, &target_branch)?;
                latest = Some(source.to_string());
                Some(base.to_string())
            }
        }
    };
    let source_commit = base
        .as_deref()
        .and_then(|base| commit_id(&repo, base))
        .ok_or_else(|| failed("No Source Commit Found"))?;
    let latest = latest.ok_or_else(|| {
        failed(format!(
            "{tip_name} is required to compute the changed rules"
        ))
    })?;
    let latest = commit_id(&repo, &latest)
        .ok_or_else(|| failed(format!("Could not find git commit {latest}")))?;
    Ok(Some(Range {
        repo,
        base: Some(source_commit),
        head: latest,
        note,
    }))
}

/// A push that created its branch (an all-zero `before`): every file
/// `latest`, the run's commit named by `tip_name`, holds.
fn whole_tree(repo: Repo, latest: Option<&str>, tip_name: &str) -> Result<Range, GitError> {
    let latest = latest.ok_or_else(|| {
        failed(format!(
            "{tip_name} is required to compute the changed rules"
        ))
    })?;
    let commit = commit_id(&repo, latest)
        .ok_or_else(|| failed(format!("Could not find git commit {latest}")))?;
    Ok(Range {
        repo,
        base: None,
        head: commit,
        note: None,
    })
}

/// A push whose HEAD has no parent: the files `latest`, the run's commit
/// named by `tip_name`, changed against its own first parent, or, when it
/// has none (the repository's first commit), every file it holds.
fn root_changes(repo: Repo, latest: Option<&str>, tip_name: &str) -> Result<Range, GitError> {
    let latest = latest.ok_or_else(|| {
        failed(format!(
            "{tip_name} is required to compute the changed rules"
        ))
    })?;
    let commit = commit_id(&repo, latest)
        .ok_or_else(|| failed(format!("Could not find git commit {latest}")))?;
    let base = production_base(&repo, commit)?;
    Ok(Range {
        repo,
        base,
        head: commit,
        note: None,
    })
}

/// The failure of a CI checkout at `searched` whose HEAD names no commit.
fn no_commits_yet(searched: &Path) -> GitError {
    let top = discover(searched).map_or_else(|| searched.to_path_buf(), |(top, _)| top);
    failed(format!(
        "The git repository at {} has no commits yet",
        dunce::simplified(&top).display()
    ))
}

// --- the push's diff up to HEAD (`changed_through_head`) -------------------

/// What an object id or a reference names: 40 hex digits are an object id;
/// anything else, or an id the store does not hold, is a reference's exact
/// name, symbolic references followed and annotated tags peeled. `None` when neither finds an object.
fn exact_object(repo: &Repo, name: &str) -> Option<ObjectId> {
    let mut buf = Vec::new();
    if name.len() == 40
        && let Ok(id) = ObjectId::from_hex(name.as_bytes())
        && matches!(repo.odb.try_find(&id, &mut buf), Ok(Some(_)))
    {
        return Some(id);
    }
    let mut reference = repo.refs.try_find(name).ok()??;
    // Only the exact name counts: a partial name the store finds under
    // `refs/` (`main` for `refs/heads/main`) names nothing here.
    if reference.name.as_bstr() != name.as_bytes().as_bstr() {
        return None;
    }
    reference.peel_to_id(&repo.refs, &repo.odb).ok()
}

/// Whether `id` is a commit the checkout holds.
fn is_commit(repo: &Repo, id: ObjectId) -> bool {
    repo.commit(id).is_some()
}

/// The commit an object id or a reference's exact name holds; `Could not
/// find git commit <text>` when nothing is found, and `Object <text> is not
/// a commit` for a tag, tree or blob.
fn dulwich_commit(repo: &Repo, text: &str) -> Result<ObjectId, GitError> {
    match exact_object(repo, text) {
        Some(id) if is_commit(repo, id) => Ok(id),
        Some(_) => Err(failed(format!("Object {text} is not a commit"))),
        None => Err(failed(format!("Could not find git commit {text}"))),
    }
}

/// The reference name tried first for `rev`: `refs/...` as written,
/// `origin/<branch>` under `refs/remotes/`, `HEAD`, and anything else as a
/// branch.
fn normalized_ref(rev: &str) -> String {
    if rev.starts_with("refs/") || rev == "HEAD" {
        rev.to_owned()
    } else if rev.starts_with("origin/") {
        format!("refs/remotes/{rev}")
    } else {
        format!("refs/heads/{rev}")
    }
}

/// The commit `--since` names: a full commit id, a reference's exact name, or
/// a branch, `origin/<branch>` or `refs/...` name, an annotated tag peeled.
/// Short ids and revision syntax (`HEAD~1`) are not read: unless a reference
/// has that exact name, they fail with `Could not find git commit <rev>`.
fn since_commit(repo: &Repo, rev: &str) -> Result<ObjectId, GitError> {
    if let Some(id) = exact_object(repo, rev).filter(|id| is_commit(repo, *id)) {
        return Ok(id);
    }
    let normalized = normalized_ref(rev);
    let id = [normalized.as_str(), rev]
        .into_iter()
        .find_map(|name| {
            let mut reference = repo.refs.try_find(name).ok()??;
            (reference.name.as_bstr() == name.as_bytes().as_bstr())
                .then(|| reference.peel_to_id(&repo.refs, &repo.odb).ok())
                .flatten()
        })
        .ok_or_else(|| failed(format!("Could not find git commit {rev}")))?;
    if is_commit(repo, id) {
        Ok(id)
    } else {
        Err(failed(format!("Object {id} is not a commit")))
    }
}

/// The variable naming the commit that triggered a CI run
/// (`TRIGGER_SHA_VARIABLES`).
fn trigger_variable(ci: Ci) -> &'static str {
    match ci {
        Ci::GitHub => "GITHUB_SHA",
        Ci::GitLab => "CI_COMMIT_SHA",
        Ci::Azure => "BUILD_SOURCEVERSION",
        Ci::Local => "",
    }
}

/// Where the triggering push's diff starts: on GitLab
/// `CI_COMMIT_BEFORE_SHA` unless it is unset or all zeros, else the
/// triggering commit's first parent; `None` when that commit is the first.
fn push_baseline(repo: &Repo, ci: Ci, env: Env<'_>) -> Result<Option<ObjectId>, GitError> {
    let variable = trigger_variable(ci);
    let trigger = set(env, variable).ok_or_else(|| {
        failed(format!(
            "{variable} is required to compute the changed objects"
        ))
    })?;
    if let Some(base) = push_base_override(repo, env)? {
        return Ok(Some(base));
    }
    if ci == Ci::GitLab
        && let Some(before) =
            set(env, "CI_COMMIT_BEFORE_SHA").filter(|sha| !sha.trim_matches('0').is_empty())
    {
        return dulwich_commit(repo, &before).map(Some);
    }
    let commit = dulwich_commit(repo, &trigger)?;
    let Some(parent) = parents(repo, commit).and_then(|parents| parents.first().copied()) else {
        return Ok(None);
    };
    // A shallow clone names the parent without holding it: that fails here.
    dulwich_commit(repo, &parent.to_string()).map(Some)
}

/// The paths a push changed, up to the checkout's HEAD rather than the
/// pushed commit (`changed_through_head`), for a job that runs after the
/// production deploy and checks out the default branch's tip. The diff starts
/// where the triggering push's starts (`push_baseline`), or at `since`, a
/// commit id or reference, which also works outside CI; it ends at HEAD.
/// Added, renamed and modified files count, from the git top level.
///
/// Outside CI the checkout holds `workspace`; in CI it is found from the
/// platform's checkout variable (`GITHUB_WORKSPACE`, `CI_PROJECT_DIR`,
/// `BUILD_SOURCESDIRECTORY`), else from `cwd`. A missing checkout is
/// [`GitError::MissingCheckout`] with the folder searched.
pub fn changed_through_head(
    workspace: &Path,
    cwd: &Path,
    env: Env<'_>,
    since: Option<&str>,
) -> Result<Vec<String>, GitError> {
    let platform = ci(env);
    let (repo, top) = if platform == Ci::Local {
        if since.is_none() {
            return Err(failed(
                "Outside CI, --since must name the commit to diff from",
            ));
        }
        let top = discover(workspace)
            .map(|(top, _)| top)
            .ok_or_else(|| GitError::MissingCheckout(workspace.to_path_buf()))?;
        (open(workspace)?, top)
    } else {
        let variable = match platform {
            Ci::GitHub => "GITHUB_WORKSPACE",
            Ci::GitLab => "CI_PROJECT_DIR",
            _ => "BUILD_SOURCESDIRECTORY",
        };
        let searched = set(env, variable).map_or_else(|| cwd.to_path_buf(), |dir| cwd.join(dir));
        let top = discover(&searched)
            .map(|(top, _)| top)
            .ok_or_else(|| GitError::MissingCheckout(searched.clone()))?;
        (open(&searched)?, top)
    };
    let head = head_commit(&repo).ok_or_else(|| {
        failed(format!(
            "The git repository at {} has no commits yet",
            dunce::simplified(&top).display()
        ))
    })?;
    let base = match since {
        Some(since) => Some(since_commit(&repo, since)?),
        None => push_baseline(&repo, platform, env)?,
    };
    // No base: HEAD is the repository's first commit, which added every file.
    changed_between(&repo, base, head)
}

/// Splits changed paths into the rule files directly in `folder` (the rules
/// folder, workspace-relative) and those in its subfolders: a path matches
/// when `folder` is one of its whole leading components, at the top level or
/// below it.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "a rule file is `*.yaml` or `*.yml`, case-sensitive: `rule.YAML` is not one"
)]
pub fn split_rule_paths(changed: &[String], folder: &str) -> (Vec<String>, Vec<String>) {
    let folder = folder.trim_matches('/');
    let mut top = Vec::new();
    let mut nested = Vec::new();
    for path in changed {
        if path.is_empty() || !(path.ends_with(".yaml") || path.ends_with(".yml")) {
            continue;
        }
        let rest = if let Some(rest) = path.strip_prefix(&format!("{folder}/")) {
            Some(rest)
        } else {
            path.split_once(&format!("/{folder}/"))
                .map(|(_, rest)| rest)
        };
        let Some(rest) = rest else {
            continue;
        };
        if rest.is_empty() {
            continue;
        }
        if rest.contains('/') {
            nested.push(path.clone());
        } else {
            top.push(path.clone());
        }
    }
    nested.sort();
    (top, nested)
}

/// Why a run outside CI read no changed file: HEAD names no commit yet
/// (`no_commits_warning`). `None` in CI, outside a checkout, or once HEAD
/// names a commit.
pub fn no_commits_warning(workspace: &Path, env: Env<'_>, advice: &str) -> Option<String> {
    if ci(env) != Ci::Local {
        return None;
    }
    let repo = open(workspace).ok()?;
    if head_commit(&repo).is_some() {
        return None;
    }
    Some(format!(
        "HEAD names no commit yet (a new repository or an orphan branch), so no file has changed: \
         {advice}"
    ))
}

/// `folder` and, when `recursive`, every folder below it, for the
/// uncommitted-files note (a hidden folder is left out).
fn folders_below(folder: &Path, recursive: bool, into: &mut Vec<PathBuf>) {
    into.push(folder.to_path_buf());
    if !recursive {
        return;
    }
    let Ok(entries) = std::fs::read_dir(folder) else {
        return;
    };
    let mut below: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && !entry.file_name().to_string_lossy().starts_with('.')
        })
        .map(|entry| entry.path())
        .collect();
    below.sort();
    for path in below {
        folders_below(&path, true, into);
    }
}

/// How many uncommitted object files a note names.
const UNCOMMITTED_SHOWN: usize = 3;

/// The note of a run outside CI that reads the last commit (`--changed`,
/// deploy's default scope) while object files in the work tree or the index
/// differ from HEAD or are untracked, and the scope leaves them out (F-05):
/// the command reads files from disk, so a file the scope names is read as
/// it is now, and is not in the note. `folders` are the folders the scope can
/// hold files of (the YAML files directly in each count, and below it when
/// `recursive`); `in_scope` are the files the scope names. A file deleted
/// from disk cannot be passed to `--file` and is not named. `None` in CI,
/// outside a checkout, before HEAD names a commit, or when every such file is
/// committed or in scope.
pub fn uncommitted_warning(
    workspace: &Path,
    env: Env<'_>,
    folders: &[PathBuf],
    recursive: bool,
    in_scope: &[PathBuf],
) -> Option<String> {
    if ci(env) != Ci::Local || folders.is_empty() {
        return None;
    }
    let repo = open(workspace).ok()?;
    head_commit(&repo)?;
    let mut all = Vec::new();
    for folder in folders {
        folders_below(folder, recursive, &mut all);
    }
    let keep = |name: &str| {
        Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
    };
    let dirty = changed_in_folders_against(workspace, &all, &keep, &|repo, _| {
        head_commit(repo).ok_or_else(|| failed(NO_GIT_MESSAGE))
    })
    .ok()?;
    let real = |path: &Path| dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let in_scope: Vec<PathBuf> = in_scope.iter().map(|path| real(path)).collect();
    let left_out: Vec<&ChangedFile> = dirty
        .iter()
        .filter(|file| file.absolute.is_file() && !in_scope.contains(&real(&file.absolute)))
        .collect();
    if left_out.is_empty() {
        return None;
    }
    let shown: Vec<&str> = left_out
        .iter()
        .take(UNCOMMITTED_SHOWN)
        .map(|file| file.relative.as_str())
        .collect();
    let more = left_out.len().saturating_sub(UNCOMMITTED_SHOWN);
    let names = if more == 0 {
        shown.join(", ")
    } else {
        format!("{} and {more} more", shown.join(", "))
    };
    let (count, verb) = if left_out.len() == 1 {
        ("1 uncommitted object file".to_owned(), "is")
    } else {
        (
            format!("{} uncommitted object files", left_out.len()),
            "are",
        )
    };
    Some(format!(
        "{count} {verb} not in scope ({names}); commit them or pass --file"
    ))
}

// --- the default-branch baseline ---------------------------------------------

/// The message of a run that needs a commit to compare with.
pub const NO_GIT_MESSAGE: &str =
    "changed-object discovery requires a git repository with at least one commit";

/// Default-branch names tried as `origin/<name>`, then `<name>`.
pub const DEFAULT_BRANCH_NAMES: [&str; 3] = ["development", "main", "master"];

/// The configuration of the repository `git_dir` belongs to.
fn config(git_dir: &Path) -> Option<gix_config::File> {
    let common =
        match gix_discover::path::from_plain_file_relative_to_file(&git_dir.join("commondir")) {
            Some(Ok(common)) => common,
            _ => git_dir.to_path_buf(),
        };
    gix_config::File::from_path_no_includes(common.join("config"), gix_config::Source::Local).ok()
}

/// What `opentide doctor` reports of a checkout, read with gix rather than
/// the `git` program (the WASI build, which cannot run one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkout {
    /// Its work tree.
    pub top: PathBuf,
    /// The branch `origin/HEAD` names, when it is set.
    pub default_branch: Option<String>,
    /// Whether it has an `origin` remote.
    pub has_origin: bool,
    /// The branch HEAD is on; `None` when HEAD is detached.
    pub current_branch: Option<String>,
}

/// The checkout at or above `start`, or `None` when there is none (or it
/// cannot be opened).
pub fn checkout(start: &Path) -> Option<Checkout> {
    let (top, _) = discover(start)?;
    let repo = open(start).ok()?;
    Some(Checkout {
        top,
        default_branch: remote_default_branch(&repo),
        has_origin: origin_url(start).is_some(),
        current_branch: current_branch(&repo),
    })
}

/// The URL of the `origin` remote of the checkout at or above `start`.
pub fn origin_url(start: &Path) -> Option<String> {
    let (_, git_dir) = discover(start)?;
    let url = config(&git_dir)?.string("remote.origin.url")?;
    Some(String::from_utf8_lossy(&url).into_owned())
}

/// Whether `start` is in a git checkout (`git rev-parse --git-dir`).
pub fn in_repository(start: &Path) -> bool {
    discover(start).is_some()
}

/// The local branches of the checkout at or above `start`, loose and
/// packed, sorted by name as `git for-each-ref refs/heads/` lists them;
/// empty outside a checkout.
pub fn local_branches(start: &Path) -> Vec<String> {
    let Ok(repo) = open(start) else {
        return Vec::new();
    };
    let Ok(platform) = repo.refs.iter() else {
        return Vec::new();
    };
    let Ok(prefix) = <&gix_path::RelativePath>::try_from("refs/heads/") else {
        return Vec::new();
    };
    let Ok(references) = platform.prefixed(prefix) else {
        return Vec::new();
    };
    let mut names: Vec<String> = references
        .filter_map(Result::ok)
        .filter_map(|reference| {
            reference
                .name
                .as_bstr()
                .to_str()
                .ok()?
                .strip_prefix("refs/heads/")
                .map(str::to_owned)
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The value `git config --get <key>` prints from `start`: the last one set
/// in the system, global and, in a checkout, repository configuration, then
/// in the `GIT_CONFIG_COUNT` overrides. The files are found through `env`
/// (`HOME`, `XDG_CONFIG_HOME`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_NOSYSTEM`,
/// `GIT_CONFIG_SYSTEM`), as git finds them in its own environment. Includes
/// are followed; conditional ones (`includeIf`) are not.
pub fn config_value(start: &Path, key: &str, env: Env<'_>) -> Option<String> {
    if let Some(value) = config_override(key, env) {
        return Some(value);
    }
    let mut var = |name: &str| env(name).map(std::ffi::OsString::from);
    let mut metas: Vec<gix_config::file::Metadata> = [
        gix_config::Source::GitInstallation,
        gix_config::Source::System,
        gix_config::Source::Git,
        gix_config::Source::User,
    ]
    .into_iter()
    .filter_map(|source| {
        let path = source.storage_location(&mut var)?;
        path.is_file()
            .then(|| gix_config::file::Metadata::from(source).at(path))
    })
    .collect();
    if let Some((_, git_dir)) = discover(start) {
        let common = match gix_discover::path::from_plain_file_relative_to_file(
            &git_dir.join("commondir"),
        ) {
            Some(Ok(common)) => common,
            _ => git_dir.clone(),
        };
        metas.push(
            gix_config::file::Metadata::from(gix_config::Source::Local).at(common.join("config")),
        );
    }
    metas.retain(|meta| meta.path.as_deref().is_some_and(Path::is_file));
    let home = env("HOME").map(PathBuf::from);
    let options = gix_config::file::init::Options {
        includes: gix_config::file::includes::Options::follow_without_conditional(home.as_deref()),
        ..Default::default()
    };
    let config = gix_config::File::from_paths_metadata(metas, options).ok()??;
    let value = config.string(key)?;
    Some(String::from_utf8_lossy(&value).into_owned())
}

/// The last `GIT_CONFIG_KEY_<n>` naming `key` among the first
/// `GIT_CONFIG_COUNT`, with its value: section and name compared without
/// case, as git compares them.
fn config_override(key: &str, env: Env<'_>) -> Option<String> {
    let count: usize = env("GIT_CONFIG_COUNT")?.trim().parse().ok()?;
    let normal = |key: &str| -> String {
        let mut parts: Vec<String> = key.split('.').map(str::to_owned).collect();
        let last = parts.len().saturating_sub(1);
        for (index, part) in parts.iter_mut().enumerate() {
            if index == 0 || index == last {
                *part = part.to_ascii_lowercase();
            }
        }
        parts.join(".")
    };
    let wanted = normal(key);
    (0..count).rev().find_map(|index| {
        let name = env(&format!("GIT_CONFIG_KEY_{index}"))?;
        (normal(&name) == wanted)
            .then(|| env(&format!("GIT_CONFIG_VALUE_{index}")))
            .flatten()
    })
}

/// A file changed against the baseline: where it is, and its bytes at the
/// baseline, when the baseline has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    /// Its path from the git top level, `/`-separated.
    pub relative: String,
    /// Where it is (or was) on disk.
    pub absolute: PathBuf,
    /// Its content at the baseline.
    pub baseline: Option<Vec<u8>>,
}

/// The name of the branch HEAD is on, if any.
fn current_branch(repo: &Repo) -> Option<String> {
    let head = repo.refs.try_find("HEAD").ok()??;
    match head.target {
        gix_ref::Target::Symbolic(name) => name
            .as_bstr()
            .to_str()
            .ok()?
            .strip_prefix("refs/heads/")
            .map(str::to_owned),
        gix_ref::Target::Object(_) => None,
    }
}

/// The branch `origin/HEAD` names.
fn remote_default_branch(repo: &Repo) -> Option<String> {
    let reference = repo.refs.try_find("refs/remotes/origin/HEAD").ok()??;
    match reference.target {
        gix_ref::Target::Symbolic(name) => name
            .as_bstr()
            .to_str()
            .ok()?
            .strip_prefix("refs/remotes/origin/")
            .map(str::to_owned),
        gix_ref::Target::Object(_) => None,
    }
}

/// The upstream `branch` tracks (`@{upstream}`): `origin/<branch>` for a
/// remote's branch, the local branch for `remote = .`, and whether it is the
/// branch's own copy.
fn upstream(git_dir: &Path, branch: &str) -> Option<(String, bool)> {
    let config = config(git_dir)?;
    let remote = config.string(format!("branch.{branch}.remote").as_str())?;
    let merge = config.string(format!("branch.{branch}.merge").as_str())?;
    let remote = remote.to_str().ok()?;
    let merge = merge.to_str().ok()?;
    let name = merge.strip_prefix("refs/heads/")?;
    let own = merge == format!("refs/heads/{branch}");
    if remote == "." {
        Some((name.to_owned(), own))
    } else {
        Some((format!("{remote}/{name}"), own))
    }
}

/// The reference `<branch>@{upstream}` names, as git maps it: with
/// `branch.<b>.remote = .` the merge reference itself; otherwise the merge
/// reference mapped through the first of the remote's fetch refspecs that
/// matches it. `None` when the branch has no upstream; `Err(merge)` when no
/// refspec fetches it.
fn upstream_ref(git_dir: &Path, branch: &str) -> Option<Result<String, String>> {
    let config = config(git_dir)?;
    let remote = config.string(format!("branch.{branch}.remote").as_str())?;
    let merge = config.string(format!("branch.{branch}.merge").as_str())?;
    let remote = remote.to_str().ok()?;
    let merge = merge.to_str().ok()?.to_owned();
    if remote == "." {
        return Some(Ok(merge));
    }
    let specs = config
        .strings(format!("remote.{remote}.fetch").as_str())
        .unwrap_or_default();
    let mapped = specs.iter().find_map(|spec| {
        let spec = spec.to_str().ok()?;
        if spec.starts_with('^') {
            return None;
        }
        let (source, destination) = spec.trim_start_matches('+').split_once(':')?;
        match (source.split_once('*'), destination.split_once('*')) {
            (Some((prefix, suffix)), Some((to_prefix, to_suffix))) => {
                let middle = merge.strip_prefix(prefix)?.strip_suffix(suffix)?;
                Some(format!("{to_prefix}{middle}{to_suffix}"))
            }
            (None, None) if source == merge && !destination.is_empty() => {
                Some(destination.to_owned())
            }
            _ => None,
        }
    });
    Some(mapped.ok_or(merge))
}

/// The baseline refs to try, most specific first (`candidate_refs`), and
/// the last resort apart: a non-default branch's own upstream, tried after
/// every other.
fn candidate_refs(repo: &Repo, git_dir: &Path) -> (Vec<String>, Option<String>) {
    let head_branch = current_branch(repo);
    let remote_default = remote_default_branch(repo);
    let tracked = head_branch
        .as_deref()
        .and_then(|branch| upstream(git_dir, branch));
    let mut candidates: Vec<String> = Vec::new();
    let mut last_resort = None;
    if let (Some((upstream, own)), Some(branch)) = (&tracked, &head_branch) {
        let is_default = match &remote_default {
            Some(default) => branch == default,
            None => DEFAULT_BRANCH_NAMES.contains(&branch.as_str()),
        };
        if !own || is_default {
            candidates.push(upstream.clone());
        } else {
            last_resort = Some(upstream.clone());
        }
    }
    if let Some(default) = &remote_default {
        candidates.push(format!("origin/{default}"));
    }
    candidates.extend(
        DEFAULT_BRANCH_NAMES
            .iter()
            .map(|name| format!("origin/{name}")),
    );
    candidates.extend(DEFAULT_BRANCH_NAMES.iter().map(|name| (*name).to_owned()));
    let mut ordered: Vec<String> = Vec::new();
    for candidate in candidates {
        if Some(&candidate) == head_branch.as_ref() || ordered.contains(&candidate) {
            continue;
        }
        ordered.push(candidate);
    }
    let last_resort = last_resort.filter(|candidate| {
        Some(candidate) != head_branch.as_ref() && !ordered.contains(candidate)
    });
    (ordered, last_resort)
}

/// The commit the work is compared with (`resolve_baseline`): HEAD's merge
/// base with the first candidate ref that has one, else HEAD itself.
///
/// A merge base the walk cannot finish (a commit it needs is not in the
/// clone) is an error, and so is none at all in a shallow clone, whose walk
/// stops where its history does: it says to fetch more history, never
/// compares with HEAD instead (#1931). So is a shallow clone that holds no
/// candidate but the branch's own upstream (`actions/checkout`'s default:
/// one commit of one ref); a full clone compares with that upstream, else
/// HEAD.
fn baseline(repo: &Repo, git_dir: &Path) -> Result<ObjectId, GitError> {
    let head = head_commit(repo).ok_or_else(|| failed(NO_GIT_MESSAGE))?;
    let (candidates, last_resort) = candidate_refs(repo, git_dir);
    if repo.shallow
        && !candidates
            .iter()
            .any(|candidate| commit_id(repo, candidate).is_some())
    {
        return Err(failed(format!(
            "Could not find a default branch to compare HEAD with: {SHALLOW_HINT}"
        )));
    }
    for candidate in candidates.into_iter().chain(last_resort) {
        let Some(id) = commit_id(repo, &candidate) else {
            continue;
        };
        let mut graph = gix_revwalk::Graph::new(&repo.odb, None);
        match gix_revision::merge_base(head, &[id], &mut graph) {
            Ok(Some(bases)) => return Ok(*bases.first()),
            Ok(None) if repo.shallow => {
                return Err(failed(format!(
                    "Could not find the merge base of HEAD and {candidate}: {SHALLOW_HINT}"
                )));
            }
            Ok(None) => {}
            Err(error) => {
                let why = if repo.shallow {
                    SHALLOW_HINT.to_owned()
                } else {
                    error.to_string()
                };
                return Err(failed(format!(
                    "Could not find the merge base of HEAD and {candidate}: {why}"
                )));
            }
        }
    }
    Ok(head)
}

/// The entries of the tree at `path` (`/`-separated, from the top level) in
/// the commit `id`: name, object and whether it is a blob. A name that is not
/// UTF-8 is left out; a folder the commit does not hold has no entries.
///
/// # Errors
///
/// The commit, or a tree on the way, cannot be read (#1931): an empty list
/// would read as every file added, or every committed file deleted.
fn tree_entries(
    repo: &Repo,
    id: ObjectId,
    path: &str,
) -> Result<Vec<(String, ObjectId, bool)>, GitError> {
    let commit = repo.commit(id).ok_or_else(|| missing_parent(repo, id))?;
    let unreadable = |tree: &ObjectId, error: &dyn std::fmt::Display| {
        failed(format!("Could not find git object {tree}: {error}"))
    };
    let mut tree = commit.tree;
    let mut buf = Vec::new();
    for part in path.split('/').filter(|part| !part.is_empty()) {
        let iter = repo
            .odb
            .find_tree_iter(&tree, &mut buf)
            .map_err(|error| unreadable(&tree, &error))?;
        let mut next = None;
        for entry in iter {
            let entry = entry.map_err(|error| unreadable(&tree, &error))?;
            if entry.filename == part.as_bytes().as_bstr() && entry.mode.is_tree() {
                next = Some(entry.oid.to_owned());
                break;
            }
        }
        match next {
            Some(oid) => tree = oid,
            None => return Ok(Vec::new()),
        }
    }
    let iter = repo
        .odb
        .find_tree_iter(&tree, &mut buf)
        .map_err(|error| unreadable(&tree, &error))?;
    let mut entries = Vec::new();
    for entry in iter {
        let entry = entry.map_err(|error| unreadable(&tree, &error))?;
        // A name that is not UTF-8 is left out, as on disk.
        let Ok(name) = std::str::from_utf8(entry.filename) else {
            tracing::warn!("git_path_not_utf8");
            continue;
        };
        entries.push((name.to_owned(), entry.oid.to_owned(), entry.mode.is_blob()));
    }
    Ok(entries)
}

/// The repository's configuration as git reads it for the work tree: the
/// installation's, system, global and local files, then the environment's
/// overrides.
fn full_config(git_dir: &Path) -> Option<gix_config::File> {
    let common =
        match gix_discover::path::from_plain_file_relative_to_file(&git_dir.join("commondir")) {
            Some(Ok(common)) => common,
            _ => git_dir.to_path_buf(),
        };
    gix_config::File::from_git_dir(common).ok()
}

/// A path setting (`core.excludesFile`), `~` expanded; else the XDG default
/// (`$XDG_CONFIG_HOME/git/<default>`), as git falls back to it.
fn config_path(config: Option<&gix_config::File>, key: &str, default: &str) -> Option<PathBuf> {
    let configured = config.and_then(|config| config.path(key)).and_then(|path| {
        let home = gix_path::env::home_dir();
        path.interpolate(gix_config::path::interpolate::Context {
            home_dir: home.as_deref(),
            ..Default::default()
        })
        .ok()
    });
    configured.or_else(|| gix_path::env::xdg_config(default, &mut |name| std::env::var_os(name)))
}

/// The work tree as `git diff <baseline>` and `git ls-files --others
/// --exclude-standard` read it: the index says which files are tracked; an
/// untracked file counts unless an exclude file ignores it; a file's content
/// is what git would store for it, through the clean filters its attributes
/// and the configuration choose (`core.autocrlf`, `core.eol`, `text`, `eol`,
/// `ident`, `working-tree-encoding`, `filter.<driver>.clean`).
struct WorkTree {
    index: gix_index::File,
    stack: gix_worktree::Stack,
    pipeline: gix_filter::Pipeline,
}

impl WorkTree {
    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
    fn open(top: &Path, git_dir: &Path) -> Self {
        let common = match gix_discover::path::from_plain_file_relative_to_file(
            &git_dir.join("commondir"),
        ) {
            Some(Ok(common)) => common,
            _ => git_dir.to_path_buf(),
        };
        let kind = gix_hash::Kind::Sha1;
        // No index (nothing staged yet) reads as an empty one, as git reads it.
        let index = gix_index::File::at(
            git_dir.join("index"),
            kind,
            false,
            gix_index::decode::Options::default(),
        )
        .unwrap_or_else(|_| {
            gix_index::File::from_state(gix_index::State::new(kind), git_dir.join("index"))
        });
        let config = full_config(git_dir);
        let config = config.as_ref();
        let flag = |key: &str| {
            config
                .and_then(|config| config.boolean(key).ok().flatten())
                .unwrap_or(false)
        };
        let setting = |key: &str| {
            config
                .and_then(|config| config.string(key))
                .map(|value| value.to_str_lossy().to_lowercase())
        };
        let mut buf = Vec::new();
        let ignore_globals = gix_ignore::Search::from_git_dir(
            &common,
            config_path(config, "core.excludesFile", "ignore"),
            &mut buf,
            gix_ignore::search::Ignore::default(),
        )
        .unwrap_or_default();
        let ignore = gix_worktree::stack::state::Ignore::new(
            gix_ignore::Search::default(),
            ignore_globals,
            None,
            gix_worktree::stack::state::ignore::Source::WorktreeThenIdMappingIfNotSkipped,
            gix_ignore::search::Ignore::default(),
        );
        let mut collection = gix_attributes::search::MetadataCollection::default();
        let attribute_globals = gix_attributes::Search::new_globals(
            config_path(config, "core.attributesFile", "attributes"),
            &mut buf,
            &mut collection,
        )
        .unwrap_or_default();
        let attributes = gix_worktree::stack::state::Attributes::new(
            attribute_globals,
            Some(common.join("info").join("attributes")),
            gix_worktree::stack::state::attributes::Source::WorktreeThenIdMapping,
            collection,
        );
        let stack = gix_worktree::Stack::from_state_and_ignore_case(
            top,
            flag("core.ignoreCase"),
            gix_worktree::stack::State::for_add(attributes, ignore),
            &index,
            index.path_backing(),
        );
        let auto_crlf = match setting("core.autocrlf").as_deref() {
            Some("input") => gix_filter::eol::AutoCrlf::Input,
            _ if flag("core.autocrlf") => gix_filter::eol::AutoCrlf::Enabled,
            _ => gix_filter::eol::AutoCrlf::Disabled,
        };
        let eol = match setting("core.eol").as_deref() {
            Some("lf") => Some(gix_filter::eol::Mode::Lf),
            Some("crlf") => Some(gix_filter::eol::Mode::CrLf),
            _ => None,
        };
        let drivers = config
            .and_then(|config| config.sections_by_name("filter"))
            .into_iter()
            .flatten()
            .filter_map(|section| {
                let name = section.header().subsection_name()?.to_owned();
                let body = section.body();
                Some(gix_filter::Driver {
                    name,
                    clean: body.value("clean"),
                    smudge: body.value("smudge"),
                    process: body.value("process"),
                    required: body.value("required").is_some_and(|value| {
                        gix_config::Boolean::try_from(value.as_bstr()).is_ok_and(|b| b.0)
                    }),
                })
            })
            .collect();
        let pipeline = gix_filter::Pipeline::new(
            gix_command::Context {
                git_dir: Some(git_dir.to_path_buf()),
                worktree_dir: Some(top.to_path_buf()),
                ..Default::default()
            },
            kind,
            gix_filter::pipeline::Options {
                drivers,
                eol_config: gix_filter::eol::Configuration { auto_crlf, eol },
                crlf_roundtrip_check: gix_filter::pipeline::CrlfRoundTripCheck::Skip,
                ..Default::default()
            },
        );
        Self {
            index,
            stack,
            pipeline,
        }
    }

    /// The object the index holds for `relative`, at stage 0 or "ours".
    fn tracked(&self, relative: &str) -> Option<ObjectId> {
        self.index
            .entry_by_path(relative.as_bytes().as_bstr())
            .map(|entry| entry.id)
    }

    /// Whether an exclude file ignores the untracked file `relative`.
    fn ignored(&mut self, relative: &str, odb: &gix_odb::Handle) -> bool {
        self.stack
            .at_entry(
                relative.as_bytes().as_bstr(),
                Some(gix_index::entry::Mode::FILE),
                odb,
            )
            .is_ok_and(|platform| platform.is_excluded())
    }

    /// The object id git would store for `bytes` at `relative`, through the
    /// clean filters; `None` when a filter fails.
    fn stored_id(
        &mut self,
        relative: &str,
        bytes: &[u8],
        odb: &gix_odb::Handle,
    ) -> Option<ObjectId> {
        let in_index = self.tracked(relative);
        let stack = &mut self.stack;
        let mut attributes = |path: &BStr, out: &mut gix_attributes::search::Outcome| {
            if let Ok(platform) = stack.at_entry(path, Some(gix_index::entry::Mode::FILE), odb) {
                platform.matching_attributes(out);
            }
        };
        let mut index_object = |buf: &mut Vec<u8>| match in_index {
            Some(id) => odb.try_find(&id, buf).map(|found| found.map(|_| ())),
            None => Ok(None),
        };
        let outcome = self
            .pipeline
            .convert_to_git(
                bytes,
                Path::new(relative),
                &mut attributes,
                &mut index_object,
            )
            .ok()?;
        let hash = |data: &[u8]| {
            gix_object::compute_hash(gix_hash::Kind::Sha1, gix_object::Kind::Blob, data).ok()
        };
        match outcome {
            gix_filter::pipeline::convert::ToGitOutcome::Unchanged(_) => hash(bytes),
            gix_filter::pipeline::convert::ToGitOutcome::Buffer(data) => hash(data),
            gix_filter::pipeline::convert::ToGitOutcome::Process(mut read) => {
                let mut data = Vec::new();
                std::io::Read::read_to_end(&mut read, &mut data).ok()?;
                hash(&data)
            }
        }
    }
}

/// The files directly in each of `folders` that differ from the default
/// branch's baseline, as `git diff <baseline>` and `git ls-files --others
/// --exclude-standard` report them (`changed_paths` read for the object
/// folders only): a tracked file whose content, through the clean filters,
/// is not the baseline's; one deleted or no longer in the index; an
/// untracked file no exclude file ignores. `keep` picks the file names that
/// count. Sorted by path.
///
/// # Errors
///
/// No checkout holds `workspace`, or HEAD names no commit:
/// [`NO_GIT_MESSAGE`].
pub fn changed_in_folders(
    workspace: &Path,
    folders: &[PathBuf],
    keep: &dyn Fn(&str) -> bool,
) -> Result<Vec<ChangedFile>, GitError> {
    changed_in_folders_against(workspace, folders, keep, &|repo, git_dir| {
        baseline(repo, git_dir)
    })
}

/// [`changed_in_folders`] against the commit `base_of` picks.
fn changed_in_folders_against(
    workspace: &Path,
    folders: &[PathBuf],
    keep: &dyn Fn(&str) -> bool,
    base_of: &dyn Fn(&Repo, &Path) -> Result<ObjectId, GitError>,
) -> Result<Vec<ChangedFile>, GitError> {
    let (top, git_dir) = discover(workspace).ok_or_else(|| failed(NO_GIT_MESSAGE))?;
    let repo = open(workspace).map_err(|_| failed(NO_GIT_MESSAGE))?;
    let base = base_of(&repo, &git_dir)?;
    let top = dunce::canonicalize(&top).unwrap_or(top);
    let mut work = WorkTree::open(&top, &git_dir);
    let mut changed = Vec::new();
    for folder in folders {
        let Ok(real) = dunce::canonicalize(folder) else {
            continue;
        };
        let Ok(relative) = real.strip_prefix(&top) else {
            continue;
        };
        let prefix: String = relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let path_of = |name: &str| {
            if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            }
        };
        let committed: std::collections::BTreeMap<String, ObjectId> =
            tree_entries(&repo, base, &prefix)?
                .into_iter()
                .filter(|(name, _, blob)| *blob && keep(name))
                .map(|(name, id, _)| (name, id))
                .collect();
        let mut on_disk: std::collections::BTreeMap<String, Vec<u8>> =
            std::collections::BTreeMap::new();
        // A folder or file that cannot be read is the run's failure: left
        // out, its committed files would read as deleted (#1931). One gone
        // between the listing and the read is deleted.
        let unreadable = |path: &Path, error: &std::io::Error| {
            failed(format!("Could not read {}: {error}", path.display()))
        };
        let entries = match std::fs::read_dir(&real) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(unreadable(&real, &error)),
        };
        for entry in entries.into_iter().flatten() {
            let entry = entry.map_err(|error| unreadable(&real, &error))?;
            // Files are compared by UTF-8 name: one whose name is not UTF-8
            // is left out, with a `git_path_not_utf8` warning.
            let Ok(name) = entry.file_name().into_string() else {
                tracing::warn!("git_path_not_utf8");
                continue;
            };
            if !keep(&name) || !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            match std::fs::read(entry.path()) {
                Ok(bytes) => {
                    on_disk.insert(name, bytes);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(unreadable(&entry.path(), &error)),
            }
        }
        let mut names: Vec<&String> = committed.keys().chain(on_disk.keys()).collect();
        names.sort();
        names.dedup();
        for name in names {
            let relative = path_of(name);
            let before = committed.get(name);
            let tracked = work.tracked(&relative).is_some();
            let differs = match on_disk.get(name) {
                // Deleted from the work tree: a change only if the baseline had it.
                None => before.is_some(),
                Some(_) if !tracked && work.ignored(&relative, &repo.odb) => {
                    // Ignored and untracked: `git ls-files --exclude-standard`
                    // skips it; `git diff` still reports a baseline file the
                    // index no longer holds.
                    before.is_some()
                }
                // Untracked, or no longer in the index: the baseline's file
                // reads as deleted, and the one on disk as new.
                Some(_) if !tracked => true,
                Some(bytes) => before.is_none_or(|id| {
                    work.stored_id(&relative, bytes, &repo.odb)
                        .is_none_or(|stored| stored != *id)
                }),
            };
            if !differs {
                continue;
            }
            // A committed file whose text cannot be read is not a new file.
            let baseline = match before {
                None => None,
                Some(id) => {
                    let mut buf = Vec::new();
                    let blob = repo.odb.find_blob(id, &mut buf).map_err(|error| {
                        failed(format!("Could not find git object {id}: {error}"))
                    })?;
                    Some(blob.data.to_vec())
                }
            };
            changed.push(ChangedFile {
                absolute: top.join(&relative),
                relative,
                baseline,
            });
        }
    }
    changed.sort_by(|a, b| a.relative.cmp(&b.relative));
    changed.dedup_by(|a, b| a.relative == b.relative);
    Ok(changed)
}

/// The git ignore rule that hides `.opentide/states/deployment/` from git
/// (its shards must be committed, so a deploy refuses to run under it, and
/// so does a state migration): its pattern, and the file and line it is on
/// when it is in the work tree's `.gitignore` files or the repository's
/// `info/exclude`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreRule {
    /// The pattern, as written.
    pub pattern: String,
    /// The file it is in, relative to the git top level.
    pub source: Option<String>,
    /// Its line in that file.
    pub line: Option<usize>,
}

impl IgnoreRule {
    /// `<source>:<line>: <pattern>`, or the pattern alone (`describe`).
    pub fn describe(&self) -> String {
        match (&self.source, self.line) {
            (Some(source), Some(line)) => format!("{source}:{line}: {}", self.pattern),
            _ => self.pattern.clone(),
        }
    }
}

/// The pattern that decides whether a path is ignored.
struct Decided {
    excluded: bool,
    pattern: String,
    source: Option<PathBuf>,
    line: usize,
}

/// The folder deploy keeps its state in, and a shard inside it, relative to
/// the workspace (`deployment_state_ignore`'s probes).
const STATE_PROBES: [&str; 4] = [
    ".opentide/",
    ".opentide/states/",
    ".opentide/states/deployment/",
    ".opentide/states/deployment/00000000-0000-4000-8000-000000000000.json",
];

/// The ignore rule that hides `.opentide/states/deployment/` of the
/// workspace at `workspace` from git, with git's own ignore semantics
/// (`deployment_state_ignore`): the `.gitignore` files of the work tree, the
/// repository's `info/exclude` and `core.excludesFile`; a folder ignored
/// above the shards hides them too. `None` when git keeps them. Outside a
/// checkout, the workspace's `.gitignore` files alone are read.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
pub fn state_ignore(workspace: &Path) -> Option<IgnoreRule> {
    let root = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let top = root
        .ancestors()
        .find(|candidate| candidate.join(".git").exists())
        .map_or_else(|| root.clone(), Path::to_path_buf);
    let mut buf = Vec::new();
    let globals = if top.join(".git").exists() {
        discover(&top)
            .map(|(_, git_dir)| {
                let common = match gix_discover::path::from_plain_file_relative_to_file(
                    &git_dir.join("commondir"),
                ) {
                    Some(Ok(common)) => common,
                    _ => git_dir.clone(),
                };
                let config = full_config(&git_dir);
                gix_ignore::Search::from_git_dir(
                    &common,
                    config_path(config.as_ref(), "core.excludesFile", "ignore"),
                    &mut buf,
                    gix_ignore::search::Ignore::default(),
                )
                .unwrap_or_default()
            })
            .unwrap_or_default()
    } else {
        gix_ignore::Search::default()
    };
    let ignore = gix_worktree::stack::state::Ignore::new(
        gix_ignore::Search::default(),
        globals,
        None,
        gix_worktree::stack::state::ignore::Source::WorktreeThenIdMappingIfNotSkipped,
        gix_ignore::search::Ignore::default(),
    );
    // No index: the ignore files are read from the work tree.
    let index = gix_index::State::new(gix_hash::Kind::Sha1);
    let mut stack = gix_worktree::Stack::from_state_and_ignore_case(
        &top,
        false,
        gix_worktree::stack::State::IgnoreStack(ignore),
        &index,
        index.path_backing(),
    );
    let prefix = root
        .strip_prefix(&top)
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}/")
    };
    let chain: Vec<String> = STATE_PROBES
        .iter()
        .map(|probe| format!("{prefix}{probe}"))
        .collect();
    // Each probe's deciding pattern: whether it excludes, its text, its
    // file and its line.
    let mut matched = |path: &str| -> Option<Decided> {
        let directory = path.ends_with('/');
        let relative = path.trim_end_matches('/');
        let mode = if directory {
            gix_index::entry::Mode::DIR
        } else {
            gix_index::entry::Mode::FILE
        };
        let platform = stack
            .at_path(Path::new(relative), Some(mode), &gix_object::find::Never)
            .ok()?;
        let found = platform.matching_exclude_pattern()?;
        Some(Decided {
            excluded: !found.pattern.is_negative(),
            pattern: found.pattern.to_string(),
            source: found.source.map(Path::to_path_buf),
            line: found.sequence_number,
        })
    };
    let ignored = |found: &Option<Decided>| found.as_ref().is_some_and(|found| found.excluded);
    let results: Vec<_> = chain.iter().map(|path| matched(path)).collect();
    if !(ignored(&results[2]) || ignored(&results[3])) {
        return None;
    }
    for found in &results {
        if !ignored(found) {
            continue;
        }
        let Some(Decided {
            pattern,
            source,
            line,
            ..
        }) = found
        else {
            continue;
        };
        let written = source
            .as_ref()
            .and_then(|source| std::fs::read_to_string(source).ok())
            .and_then(|text| {
                text.lines()
                    .nth(line.saturating_sub(1))
                    .map(|text| text.trim().to_owned())
            })
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| pattern.clone());
        // Named only when the file is the work tree's or `info/exclude`;
        // `core.excludesFile` is outside both.
        let located = source.as_ref().and_then(|source| {
            // `top` is canonical, which on Windows is a verbatim path
            // (`\\?\C:\...`); `info/exclude` comes by the git dir
            // discovery found, which is not: compare both simplified.
            let relative = dunce::simplified(source)
                .strip_prefix(dunce::simplified(&top))
                .ok()?;
            let text = relative.to_string_lossy().replace('\\', "/");
            (text.ends_with(".gitignore") || text == ".git/info/exclude").then_some(text)
        });
        return Some(IgnoreRule {
            pattern: written,
            line: located.as_ref().map(|_| *line),
            source: located,
        });
    }
    Some(IgnoreRule {
        pattern: ".opentide/states/deployment/".to_owned(),
        source: None,
        line: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    /// `git init` in `dir`, with `args` (`--bare`).
    fn git_init(dir: &Path, args: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        let status = std::process::Command::new("git")
            .arg("init")
            .arg("-q")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", dir)
            // A hook running the tests exports these (a linked worktree's
            // `GIT_DIR`): `git init --bare` would then rewrite that
            // repository rather than create one here.
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_CEILING_DIRECTORIES")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_NAMESPACE")
            .env_remove("GIT_PREFIX")
            .status()
            .expect("git runs");
        assert!(status.success());
    }

    /// `git config <key> <value>` in the repository at `git_dir`.
    fn git_config(git_dir: &Path, key: &str, value: &Path) {
        let status = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(git_dir)
            .args(["config", key])
            .arg(value)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_COMMON_DIR")
            .status()
            .expect("git runs");
        assert!(status.success());
    }

    fn os_lookup(pairs: &[(&str, &Path)]) -> impl Fn(&str) -> Option<std::ffi::OsString> + use<> {
        let pairs: Vec<(String, PathBuf)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.to_path_buf()))
            .collect();
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone().into_os_string())
        }
    }

    #[test]
    fn git_dir_and_git_work_tree_name_a_bare_repository_and_its_work_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let bare = root.join("dépôt.git");
        git_init(&bare, &["--bare"]);
        let work_tree = root.join("arbre 😀");
        let sub = work_tree.join("rules");
        std::fs::create_dir_all(&sub).unwrap();
        // Discovery alone finds nothing: the work tree has no `.git`.
        assert_eq!(discover_with(&sub, &os_lookup(&[])), None);
        let env = os_lookup(&[("GIT_DIR", &bare), ("GIT_WORK_TREE", &work_tree)]);
        assert_eq!(
            discover_with(&sub, &env),
            Some((work_tree.clone(), bare.clone()))
        );
        // Relative paths are read against the directory git runs in.
        let relative = os_lookup(&[
            ("GIT_DIR", Path::new("../../dépôt.git")),
            ("GIT_WORK_TREE", Path::new("..")),
        ]);
        let (top, git_dir) = discover_with(&sub, &relative).unwrap();
        assert_eq!(top.canonicalize().unwrap(), work_tree);
        assert_eq!(git_dir.canonicalize().unwrap(), bare);
        // A bare repository without `GIT_WORK_TREE` has no work tree.
        assert_eq!(discover_with(&sub, &os_lookup(&[("GIT_DIR", &bare)])), None);
        // `core.bare` wins over `core.worktree`, as in git.
        git_config(&bare, "core.worktree", &work_tree);
        assert_eq!(discover_with(&sub, &os_lookup(&[("GIT_DIR", &bare)])), None);
        git_config(&bare, "core.bare", Path::new("false"));
        assert_eq!(
            discover_with(&sub, &os_lookup(&[("GIT_DIR", &bare)])),
            Some((work_tree.clone(), bare.clone()))
        );
        // `GIT_DIR` naming no repository finds none, without a search.
        let missing = os_lookup(&[("GIT_DIR", &root.join("missing"))]);
        assert_eq!(discover_with(&sub, &missing), None);
    }

    #[test]
    fn git_dir_alone_makes_the_running_directory_the_work_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let repo = root.join("repo");
        git_init(&repo, &[]);
        let elsewhere = root.join("ailleurs");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let git_dir = repo.join(".git");
        let env = os_lookup(&[("GIT_DIR", &git_dir)]);
        assert_eq!(
            discover_with(&elsewhere, &env),
            Some((elsewhere.clone(), git_dir.clone()))
        );
        // `GIT_WORK_TREE` alone names the work tree of the repository found.
        let env = os_lookup(&[("GIT_WORK_TREE", &elsewhere)]);
        assert_eq!(discover_with(&repo, &env), Some((elsewhere, git_dir)));
        // An empty variable is unset.
        let env = os_lookup(&[("GIT_DIR", Path::new("")), ("GIT_WORK_TREE", Path::new(""))]);
        assert_eq!(
            discover_with(&repo, &env),
            Some((repo.clone(), repo.join(".git")))
        );
    }

    #[test]
    fn a_ceiling_directory_stops_the_search_above_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let repo = root.join("dépôt");
        git_init(&repo, &[]);
        let deep = repo.join("a").join("b");
        std::fs::create_dir_all(&deep).unwrap();
        let found = Some((repo.clone(), repo.join(".git")));
        assert_eq!(discover_with(&deep, &os_lookup(&[])), found);
        // A ceiling between the start and the repository hides it, and so
        // does the repository's own top level, which git does not enter.
        for ceiling in [repo.join("a"), repo.clone()] {
            let env = os_lookup(&[("GIT_CEILING_DIRECTORIES", &ceiling)]);
            assert_eq!(discover_with(&deep, &env), None, "{}", ceiling.display());
        }
        // The start itself is searched even when it is a ceiling.
        let env = os_lookup(&[("GIT_CEILING_DIRECTORIES", &repo)]);
        assert_eq!(discover_with(&repo, &env), found);
        // A ceiling that is not above the start, or a relative one, is
        // ignored rather than an error.
        let joined = std::env::join_paths([root.join("autre"), PathBuf::from("a")]).unwrap();
        let env = |name: &str| (name == "GIT_CEILING_DIRECTORIES").then(|| joined.clone());
        assert_eq!(discover_with(&deep, &env), found);
    }

    #[test]
    fn a_github_push_promotes_only_on_the_default_branch() {
        let dir = tempfile::tempdir().unwrap();
        let event = dir.path().join("event.json");
        std::fs::write(&event, r#"{"repository":{"default_branch":"main"}}"#).unwrap();
        let path = event.to_str().unwrap();
        let on = |reference: &str| {
            default_branch_push(
                Ci::GitHub,
                &lookup(&[("GITHUB_REF", reference), ("GITHUB_EVENT_PATH", path)]),
            )
        };
        assert_eq!(on("refs/heads/main"), Some(true));
        assert_eq!(on("refs/heads/feature/foo"), Some(false));
        assert_eq!(on("refs/tags/main"), Some(false));
        // No event file: the default branch is unknown.
        let no_event = lookup(&[("GITHUB_REF", "refs/heads/main")]);
        assert_eq!(default_branch_push(Ci::GitHub, &no_event), None);
        // The override wins, and a tag stays false under it.
        let over = |reference: &str| {
            default_branch_push(
                Ci::GitHub,
                &lookup(&[
                    ("GITHUB_REF", reference),
                    ("GITHUB_EVENT_PATH", path),
                    (DEFAULT_BRANCH_ENV, "release"),
                ]),
            )
        };
        assert_eq!(over("refs/heads/release"), Some(true));
        assert_eq!(over("refs/heads/main"), Some(false));
        assert_eq!(over("refs/tags/release"), Some(false));
        let only = lookup(&[
            ("GITHUB_REF", "refs/heads/trunk"),
            (DEFAULT_BRANCH_ENV, "trunk"),
        ]);
        assert_eq!(default_branch_push(Ci::GitHub, &only), Some(true));
    }

    #[test]
    fn the_variable_naming_the_pushed_branch_depends_on_the_platform() {
        assert_eq!(pushed_branch_variable(Ci::GitHub), "GITHUB_REF");
        assert_eq!(pushed_branch_variable(Ci::GitLab), "CI_COMMIT_BRANCH");
        assert_eq!(pushed_branch_variable(Ci::Azure), "BUILD_SOURCEBRANCH");
        // Bare `CI=true` is read as GitLab.
        assert_eq!(pushed_branch(Ci::GitLab, &lookup(&[("CI", "true")])), None);
    }

    #[test]
    fn a_gitlab_push_promotes_only_on_the_default_branch() {
        let on = |pairs: &[(&str, &str)]| default_branch_push(Ci::GitLab, &lookup(pairs));
        let default = ("CI_DEFAULT_BRANCH", "main");
        assert_eq!(on(&[("CI_COMMIT_BRANCH", "main"), default]), Some(true));
        assert_eq!(on(&[("CI_COMMIT_BRANCH", "dev"), default]), Some(false));
        // A tag pipeline has no CI_COMMIT_BRANCH.
        assert_eq!(on(&[("CI_COMMIT_TAG", "v1"), default]), Some(false));
        assert_eq!(on(&[("CI_COMMIT_BRANCH", "main")]), None);
        assert_eq!(on(&[default]), None);
        let over = [
            ("CI_COMMIT_BRANCH", "dev"),
            default,
            (DEFAULT_BRANCH_ENV, "dev"),
        ];
        assert_eq!(on(&over), Some(true));
    }

    #[test]
    fn an_azure_push_needs_the_default_branch_variable() {
        let on = |pairs: &[(&str, &str)]| default_branch_push(Ci::Azure, &lookup(pairs));
        let branch = ("BUILD_SOURCEBRANCH", "refs/heads/main");
        assert_eq!(on(&[branch]), None);
        assert_eq!(on(&[branch, (DEFAULT_BRANCH_ENV, "main")]), Some(true));
        assert_eq!(
            on(&[
                ("BUILD_SOURCEBRANCH", "refs/heads/feature/x"),
                (DEFAULT_BRANCH_ENV, "main")
            ]),
            Some(false)
        );
        assert_eq!(
            on(&[
                ("BUILD_SOURCEBRANCH", "refs/tags/v1"),
                (DEFAULT_BRANCH_ENV, "main")
            ]),
            Some(false)
        );
        assert_eq!(default_branch_push(Ci::Local, &lookup(&[])), None);
    }

    #[test]
    fn rule_paths_split_by_depth() {
        let changed = strings(&[
            "objects/rules/a.yaml",
            "ws/objects/rules/b.yml",
            "objects/rules/sub/c.yaml",
            "objects/rules/a.txt",
            "xobjects/rules/d.yaml",
            "objects/threats/t.yaml",
            "objects/rules/é.yaml",
        ]);
        let (top, nested) = split_rule_paths(&changed, "objects/rules");
        assert_eq!(
            top,
            [
                "objects/rules/a.yaml",
                "ws/objects/rules/b.yml",
                "objects/rules/é.yaml"
            ]
        );
        assert_eq!(nested, ["objects/rules/sub/c.yaml"]);
    }

    #[test]
    fn the_ci_platform_and_source_come_from_the_environment() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let github_pr = env(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_EVENT_NAME", "pull_request"),
        ]);
        assert_eq!(ci(&github_pr), Ci::GitHub);
        assert_eq!(diff_source(&github_pr), DiffSource::ChangeRequest);
        let gitlab_push = env(&[("CI", "true")]);
        assert_eq!(diff_source(&gitlab_push), DiffSource::Push);
        let azure = env(&[("TF_BUILD", "True"), ("GITHUB_ACTIONS", "true")]);
        assert_eq!(ci(&azure), Ci::Azure);
        let local = env(&[]);
        assert_eq!(diff_source(&local), DiffSource::LastCommit);
    }

    #[test]
    fn a_missing_checkout_says_what_to_do() {
        assert_eq!(
            GitError::MissingCheckout(PathBuf::from("/w")).message(),
            "deploy reads the rule files the last commit, push or pull request changed, which \
             needs a git checkout; no .git was found from /w. Run inside the repository, or pass \
             --all to read every rule file."
        );
    }

    #[test]
    fn a_missing_checkout_names_the_path_without_a_verbatim_prefix() {
        let dir = tempfile::tempdir().unwrap();
        // `\\?\C:\...` on Windows, as `std::fs::canonicalize` answers there.
        let verbatim = std::fs::canonicalize(dir.path()).unwrap();
        let message = GitError::MissingCheckout(verbatim).message();
        assert!(!message.contains(r"\\?\"), "{message}");
        let plain = dunce::canonicalize(dir.path()).unwrap();
        assert!(
            message.contains(&format!("no .git was found from {}.", plain.display())),
            "{message}"
        );
    }

    #[test]
    fn deployment_state_hidden_by_an_ignore_file_is_named_with_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // No checkout: the workspace's own `.gitignore` files are read.
        assert_eq!(state_ignore(root), None);
        std::fs::write(root.join(".gitignore"), "target/\n.opentide/states/\n").unwrap();
        let rule = state_ignore(root).unwrap();
        assert_eq!(rule.pattern, ".opentide/states/");
        assert_eq!(rule.source.as_deref(), Some(".gitignore"));
        assert_eq!(rule.line, Some(2));
        assert_eq!(rule.describe(), ".gitignore:2: .opentide/states/");
        // A negation for the shards keeps them.
        std::fs::write(
            root.join(".gitignore"),
            ".opentide/states/*\n!.opentide/states/deployment/\n",
        )
        .unwrap();
        assert_eq!(state_ignore(root), None);
        // The shards themselves.
        std::fs::write(root.join(".gitignore"), "*.json\n").unwrap();
        let rule = state_ignore(root).unwrap();
        assert_eq!(rule.pattern, "*.json");
        // In a checkout, `info/exclude` counts too.
        std::fs::write(root.join(".gitignore"), "").unwrap();
        std::fs::create_dir_all(root.join(".git/info")).unwrap();
        std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::create_dir_all(root.join(".git/objects")).unwrap();
        std::fs::create_dir_all(root.join(".git/refs/heads")).unwrap();
        std::fs::write(root.join(".git/info/exclude"), ".opentide/\n").unwrap();
        let rule = state_ignore(root).unwrap();
        assert_eq!(rule.pattern, ".opentide/");
        assert_eq!(rule.source.as_deref(), Some(".git/info/exclude"));
        assert_eq!(
            IgnoreRule {
                pattern: "x/".into(),
                source: None,
                line: None
            }
            .describe(),
            "x/"
        );
    }

    #[test]
    fn rule_paths_with_multi_byte_folders() {
        // #1946: the folder is split off, never sliced by byte.
        let changed = vec![
            "é/objects/rules/😀.yaml".to_owned(),
            "😀/objects/rules/é/x.yml".to_owned(),
            "é/objects/rulesé/x.yaml".to_owned(),
        ];
        let (top, nested) = split_rule_paths(&changed, "objects/rules");
        assert_eq!(top, ["é/objects/rules/😀.yaml"]);
        assert_eq!(nested, ["😀/objects/rules/é/x.yml"]);
    }
}
