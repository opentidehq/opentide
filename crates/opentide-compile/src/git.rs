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
}
