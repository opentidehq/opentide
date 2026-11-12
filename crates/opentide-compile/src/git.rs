//! The git baseline: the rule files a run changed (`deployment/git_repo.py`
//! `diff_calculation`, `split_changed_rule_paths`, `deployment/ci.py`), read
//! with gitoxide's crates (`gix-discover`, `gix-ref`, `gix-odb`, `gix-diff`,
//! `gix-revision`), the git implementation in Rust, without the `git` program.
//! `gix-discover` finds the checkout and its git directory (linked worktrees
//! included); `gix-revision`'s rev-spec parser reads the revisions a run
//! names, resolved against the reference store and the object database.
//!
//! The diff is the run's commits: a pull or merge request against its target
//! branch, a push against the branch's previous tip, outside CI the last
//! commit against its first parent. Added, renamed and modified files count;
//! deleted ones do not (there is nothing left to deploy). Paths are relative
//! to the git top level, as git writes them, non-ASCII paths included.
//!
//! This module and [`crate::plan::state_id`] are the crate's only reads: the
//! repository's objects, through gix, and the CI event file.

use std::path::{Path, PathBuf};

use gix_error::bstr::{BStr, ByteSlice as _};
use gix_error::{ErrorExt as _, Exn};
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
            Self::Failed(message) => message.clone(),
        }
    }
}

/// The checkout at or above `start`: its work tree and its git directory
/// (for a linked worktree, the worktree's own one). A bare repository is no
/// checkout. Discovery crosses file systems, as the oracle's did.
fn discover(start: &Path) -> Option<(PathBuf, PathBuf)> {
    let options = gix_discover::upwards::Options {
        cross_fs: true,
        dot_git_only: true,
        ..Default::default()
    };
    let (path, _trust) = gix_discover::upwards_opts(start, options).ok()?;
    let (git_dir, work_dir) = path.into_repository_and_work_tree_directories();
    Some((work_dir?, git_dir))
}

/// The work tree of the checkout at or above `start`.
pub fn worktree(start: &Path) -> Option<PathBuf> {
    discover(start).map(|(work_dir, _)| work_dir)
}

fn failed(message: impl Into<String>) -> GitError {
    GitError::Failed(message.into())
}

/// A repository: its references and its objects.
struct Repo {
    refs: gix_ref::file::Store,
    odb: gix_odb::Handle,
}

/// Opens the checkout at or above `start`.
fn open(start: &Path) -> Result<Repo, GitError> {
    let (top, git_dir) =
        discover(start).ok_or_else(|| GitError::MissingCheckout(start.to_path_buf()))?;
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
        gix_ref::file::Store::at(git_dir, kind)
    } else {
        gix_ref::file::Store::for_linked_worktree(git_dir, common.clone(), kind)
    };
    let odb = gix_odb::at(common.join("objects"), kind).map_err(|error| {
        failed(format!(
            "Could not open the git repository at {}: {error}",
            top.display()
        ))
    })?;
    Ok(Repo { refs, odb })
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
fn refused(message: String) -> Exn {
    gix_error::Message::new(message).raise().erased()
}

/// Resolves the revisions `gix_revision::spec::parse` reads: references
/// (partial names searched as git does: `refs/`, tags, heads, remotes),
/// object ids and their prefixes, and parent and ancestor steps. Reflogs,
/// upstreams, message searches, index paths and ranges name no commit a run
/// diffs and are refused.
struct Resolve<'r> {
    repo: &'r Repo,
    current: Option<ObjectId>,
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

    fn current(&self) -> Result<ObjectId, Exn> {
        self.current
            .ok_or_else(|| refused("no revision to start from".to_owned()))
    }

    fn unsupported(what: &str) -> Result<(), Exn> {
        Err(refused(format!("{what} names no commit a run diffs")))
    }
}

impl delegate::Revision for Resolve<'_> {
    fn find_ref(&mut self, name: &BStr) -> Result<(), Exn> {
        let found = self
            .repo
            .refs
            .try_find(name)
            .map_err(|error| refused(format!("reference {name}: {error}")))?
            .ok_or_else(|| refused(format!("no reference {name}")))?;
        let mut found = found;
        let id = found
            .peel_to_id(&self.repo.refs, &self.repo.odb)
            .map_err(|error| refused(format!("reference {name}: {error}")))?;
        self.current = Some(id);
        Ok(())
    }

    fn disambiguate_prefix(
        &mut self,
        prefix: gix_hash::Prefix,
        _hint: Option<delegate::PrefixHint<'_>>,
    ) -> Result<(), Exn> {
        match self.repo.odb.lookup_prefix(prefix, None) {
            Ok(Some(Ok(id))) => {
                self.current = Some(id);
                Ok(())
            }
            Ok(Some(Err(()))) => Err(refused(format!("{prefix} is ambiguous"))),
            Ok(None) => Err(refused(format!("no object {prefix}"))),
            Err(error) => Err(refused(format!("{prefix}: {error}"))),
        }
    }

    fn reflog(&mut self, _query: delegate::ReflogLookup) -> Result<(), Exn> {
        Self::unsupported("a reflog entry")
    }

    fn nth_checked_out_branch(&mut self, _branch_no: usize) -> Result<(), Exn> {
        Self::unsupported("a checked-out branch")
    }

    fn sibling_branch(&mut self, _kind: delegate::SiblingBranch) -> Result<(), Exn> {
        Self::unsupported("an upstream branch")
    }
}

impl delegate::Navigate for Resolve<'_> {
    fn traverse(&mut self, kind: delegate::Traversal) -> Result<(), Exn> {
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

    fn peel_until(&mut self, kind: delegate::PeelTo<'_>) -> Result<(), Exn> {
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
            _ => Self::unsupported("a tree, blob or path"),
        }
    }

    fn find(&mut self, _regex: &BStr, _negated: bool) -> Result<(), Exn> {
        Self::unsupported("a message search")
    }

    fn index_lookup(&mut self, _path: &BStr, _stage: u8) -> Result<(), Exn> {
        Self::unsupported("an index path")
    }
}

impl delegate::Kind for Resolve<'_> {
    fn kind(&mut self, _kind: gix_revision::spec::Kind) -> Result<(), Exn> {
        Self::unsupported("a range")
    }
}

impl gix_revision::spec::parse::Delegate for Resolve<'_> {
    fn done(&mut self) -> Result<(), Exn> {
        Ok(())
    }
}

/// The commit `rev` names, as `git rev-parse` reads it: an object id, a
/// reference (`origin/main`, `refs/...`), a parent step; an annotated tag
/// peeled.
fn commit_id(repo: &Repo, rev: &str) -> Option<ObjectId> {
    let mut resolve = Resolve {
        repo,
        current: None,
    };
    gix_revision::spec::parse(rev.as_bytes().as_bstr(), &mut resolve).ok()?;
    let id = resolve.current?;
    resolve.peel_to_commit(id)
}

fn has_commit(repo: &Repo, id: &str) -> bool {
    ObjectId::from_hex(id.as_bytes()).is_ok_and(|id| repo.commit(id).is_some())
}

fn parents(repo: &Repo, id: ObjectId) -> Option<Vec<ObjectId>> {
    repo.commit(id).map(|commit| commit.parents)
}

/// HEAD's first parent when the checkout holds it (`_production_base`):
/// `None` for the first commit; an error when a shallow clone names a parent
/// it does not hold, which must not read as an empty diff.
fn production_base(repo: &Repo, head: ObjectId) -> Result<Option<ObjectId>, GitError> {
    let parents =
        parents(repo, head).ok_or_else(|| failed(format!("Could not find git commit {head}")))?;
    let Some(parent) = parents.first().copied() else {
        return Ok(None);
    };
    if repo.commit(parent).is_none() {
        return Err(failed(format!("Could not find git commit {parent}")));
    }
    Ok(Some(parent))
}

/// The first parent of the merge commit a request run builds, when `merge`
/// has two parents, the first is in the checkout, and the second is `head`
/// when given (`_merge_first_parent`).
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

/// The branch tip before a GitHub push (`_github_push_before`).
fn github_push_before(repo: &Repo, env: Env<'_>) -> Option<String> {
    let before = event(env)?.get("before")?.as_str()?.to_owned();
    if before.trim_matches('0').is_empty() || !has_commit(repo, &before) {
        return None;
    }
    Some(before)
}

/// A pull request's base and head commits from the event (`_github_event_request_shas`).
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
/// as the checkout holds them. The oracle fetched `origin` first; this
/// compile reads no network, so a checkout must hold both branches.
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
/// the git top level, sorted.
fn changed_between(repo: &Repo, base: ObjectId, head: ObjectId) -> Result<Vec<String>, GitError> {
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
    let (old, new) = (tree(base)?, tree(head)?);
    let mut recorder = gix_diff::tree::Recorder::default();
    gix_diff::tree(
        gix_object::TreeRefIter::from_bytes(&old, gix_hash::Kind::Sha1),
        gix_object::TreeRefIter::from_bytes(&new, gix_hash::Kind::Sha1),
        gix_diff::tree::State::default(),
        &repo.odb,
        &mut recorder,
    )
    .map_err(|error| failed(format!("Could not find git object: {error}")))?;
    let mut paths: Vec<String> = recorder
        .records
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
    let platform = ci(env);
    if source == DiffSource::LastCommit || platform == Ci::Local {
        if source == DiffSource::ChangeRequest {
            return Err(failed("A pull or merge request diff needs a CI run"));
        }
        let repo = open(workspace)?;
        let Some(head) = head_commit(&repo) else {
            return Ok(Vec::new());
        };
        return match production_base(&repo, head)? {
            None => Ok(Vec::new()),
            Some(base) => changed_between(&repo, base, head),
        };
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
    let first_parent = || -> Result<Option<ObjectId>, GitError> {
        match head {
            Some(head) => production_base(&repo, head),
            None => Ok(None),
        }
    };
    let base: Option<String> = match (platform, source) {
        (_, DiffSource::LastCommit) | (Ci::Local, _) => None,
        (Ci::GitHub, DiffSource::Push) => match github_push_before(&repo, env) {
            Some(before) => Some(before),
            None => match first_parent()? {
                Some(base) => Some(base.to_string()),
                None => return Ok(Vec::new()),
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
        (Ci::GitLab, DiffSource::Push) => {
            match set(env, "CI_COMMIT_BEFORE_SHA").filter(|sha| !sha.trim_matches('0').is_empty()) {
                Some(before) => Some(before),
                None => match first_parent()? {
                    Some(base) => Some(base.to_string()),
                    None => return Ok(Vec::new()),
                },
            }
        }
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
        (Ci::Azure, DiffSource::Push) => match first_parent()? {
            Some(base) => Some(base.to_string()),
            None => return Ok(Vec::new()),
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
    changed_between(&repo, source_commit, latest)
}

/// Splits changed paths into the rule files directly in `folder` (the rules
/// folder, workspace-relative) and those in its subfolders
/// (`split_changed_rule_paths`): a path matches when `folder` is one of its
/// whole leading components, at the top level or below it.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "the oracle's pattern is case-sensitive: `rule.YAML` is not a rule file"
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
            path.find(&format!("/{folder}/"))
                .map(|at| &path[at + folder.len() + 2..])
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

// --- the default-branch baseline (`core/git_baseline.py`) ---------------------

/// The message of a run that needs a commit to compare with
/// (`NO_GIT_MESSAGE`).
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

/// The URL of the `origin` remote of the checkout at or above `start`.
pub fn origin_url(start: &Path) -> Option<String> {
    let (_, git_dir) = discover(start)?;
    let url = config(&git_dir)?.string("remote.origin.url")?;
    Some(String::from_utf8_lossy(&url).into_owned())
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

/// The baseline refs to try, most specific first (`candidate_refs`).
fn candidate_refs(repo: &Repo, git_dir: &Path) -> Vec<String> {
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
    candidates.extend(last_resort);
    let mut ordered: Vec<String> = Vec::new();
    for candidate in candidates {
        if Some(&candidate) == head_branch.as_ref() || ordered.contains(&candidate) {
            continue;
        }
        ordered.push(candidate);
    }
    ordered
}

/// The commit the work is compared with (`resolve_baseline`): HEAD's merge
/// base with the first candidate ref that has one, else HEAD itself.
fn baseline(repo: &Repo, git_dir: &Path) -> Result<ObjectId, GitError> {
    let head = head_commit(repo).ok_or_else(|| failed(NO_GIT_MESSAGE))?;
    for candidate in candidate_refs(repo, git_dir) {
        if let Some(id) = commit_id(repo, &candidate)
            && let Some(base) = merge_base(repo, head, id)
        {
            return Ok(base);
        }
    }
    Ok(head)
}

/// The entries of the tree at `path` (`/`-separated, from the top level) in
/// the commit `id`: name, object and whether it is a blob.
fn tree_entries(repo: &Repo, id: ObjectId, path: &str) -> Vec<(String, ObjectId, bool)> {
    let Some(commit) = repo.commit(id) else {
        return Vec::new();
    };
    let mut tree = commit.tree;
    let mut buf = Vec::new();
    for part in path.split('/').filter(|part| !part.is_empty()) {
        let Ok(iter) = repo.odb.find_tree_iter(&tree, &mut buf) else {
            return Vec::new();
        };
        let next = iter
            .filter_map(Result::ok)
            .find(|entry| entry.filename == part.as_bytes().as_bstr() && entry.mode.is_tree());
        match next {
            Some(entry) => tree = entry.oid.to_owned(),
            None => return Vec::new(),
        }
    }
    let Ok(iter) = repo.odb.find_tree_iter(&tree, &mut buf) else {
        return Vec::new();
    };
    iter.filter_map(Result::ok)
        .map(|entry| {
            (
                String::from_utf8_lossy(entry.filename).into_owned(),
                entry.oid.to_owned(),
                entry.mode.is_blob(),
            )
        })
        .collect()
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
            gix_filter::pipeline::Options {
                drivers,
                eol_config: gix_filter::eol::Configuration { auto_crlf, eol },
                crlf_roundtrip_check: gix_filter::pipeline::CrlfRoundTripCheck::Skip,
                object_hash: kind,
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
    let (top, git_dir) = discover(workspace).ok_or_else(|| failed(NO_GIT_MESSAGE))?;
    let repo = open(workspace).map_err(|_| failed(NO_GIT_MESSAGE))?;
    let base = baseline(&repo, &git_dir)?;
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
            tree_entries(&repo, base, &prefix)
                .into_iter()
                .filter(|(name, _, blob)| *blob && keep(name))
                .map(|(name, id, _)| (name, id))
                .collect();
        let mut on_disk: std::collections::BTreeMap<String, Vec<u8>> =
            std::collections::BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(&real) {
            for entry in entries.filter_map(Result::ok) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !keep(&name) || !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    on_disk.insert(name, bytes);
                }
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
            let baseline = before.and_then(|id| {
                let mut buf = Vec::new();
                repo.odb
                    .find_blob(id, &mut buf)
                    .ok()
                    .map(|blob| blob.data.to_vec())
            });
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
/// (`states/deployment.py` `IgnoreRule`): its pattern, and the file and
/// line it is on when it is in the work tree's `.gitignore` files or the
/// repository's `info/exclude`.
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
        // Named only when the file is the work tree's or `info/exclude`
        // (`_locate_pattern`); `core.excludesFile` is outside both.
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
}
