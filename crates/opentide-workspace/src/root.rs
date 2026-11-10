//! Where the workspace is (`core/root.py`, `registry/discovery.py`).
//!
//! The order: `--repo`, else `OPENTIDE_REPO_ROOT`, else the nearest
//! ancestor of the working directory holding `.opentide/` or an `objects/`
//! catalogue, stopping at the git top level, else the git top level, else the
//! working directory. `OPENTIDE_TIDE_WORKSPACE` names the workspace itself
//! and wins over all of them.

use std::path::{Path, PathBuf};

use crate::fs::FileSystem;

/// The `.opentide` folder's name.
pub const OPENTIDE_DIR: &str = ".opentide";

/// What the host knows about where it runs: the flags and environment
/// variables that place the workspace, and the working directory. The crate
/// reads no environment of its own; [`RootOptions::from_env`] is the
/// process's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootOptions {
    /// `--repo`, which wins over [`Self::repo_root_env`].
    pub repo: Option<PathBuf>,
    /// `OPENTIDE_REPO_ROOT`.
    pub repo_root_env: Option<PathBuf>,
    /// `OPENTIDE_TIDE_WORKSPACE`: the workspace itself. Generation sets it;
    /// it also makes the configuration skip the parent instance.
    pub tide_workspace_env: Option<PathBuf>,
    /// The working directory: where relative paths start and the search for a
    /// workspace begins.
    pub cwd: PathBuf,
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

impl RootOptions {
    /// The options of this process: `repo` (a `--repo` flag), its
    /// `OPENTIDE_REPO_ROOT` and `OPENTIDE_TIDE_WORKSPACE` (empty counts as
    /// unset, as in Python) and its working directory.
    ///
    /// # Errors
    ///
    /// The working directory cannot be read.
    pub fn from_env(repo: Option<PathBuf>) -> std::io::Result<Self> {
        Ok(Self {
            repo,
            repo_root_env: env_path("OPENTIDE_REPO_ROOT"),
            tide_workspace_env: env_path("OPENTIDE_TIDE_WORKSPACE"),
            cwd: std::env::current_dir()?,
        })
    }

    /// `path` taken from the working directory when it is relative.
    pub fn absolute(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        }
    }
}

/// Where a run's workspace is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roots {
    /// The repository root (`get_repo_root`): `--repo` or
    /// `OPENTIDE_REPO_ROOT` as given (made absolute), else the nearest
    /// workspace root.
    pub repo: PathBuf,
    /// The detection workspace (`discover_workspace`), resolved.
    pub workspace: PathBuf,
    /// Whether `OPENTIDE_TIDE_WORKSPACE` placed it.
    pub tide_workspace: bool,
}

/// The git work tree root at or above `path`: the first that holds `.git`
/// (a folder, or a file in a linked worktree).
pub fn git_root(fs: &dyn FileSystem, path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|candidate| {
            fs.kind(&candidate.join(".git"))
                .is_ok_and(|kind| kind != crate::fs::EntryKind::Other)
        })
        .map(Path::to_path_buf)
}

/// Whether `path` holds `.opentide/` or an `objects/` catalogue. `.git/objects`
/// is git's object store and an `objects/` holding `__init__.py` is Python
/// source: neither is a catalogue.
pub fn is_workspace_root(fs: &dyn FileSystem, path: &Path) -> bool {
    if path
        .components()
        .any(|component| component.as_os_str() == ".git")
    {
        return false;
    }
    if fs.is_dir(&path.join(OPENTIDE_DIR)) {
        return true;
    }
    let objects = path.join("objects");
    fs.is_dir(&objects) && !fs.is_file(&objects.join("__init__.py"))
}

/// The nearest ancestor of `start` that is a workspace root, not looking above
/// the enclosing git work tree; without one, the git root, or `start`
/// outside git.
pub fn find_workspace_root(fs: &dyn FileSystem, start: &Path) -> PathBuf {
    let path = fs.resolve(start);
    let git = git_root(fs, &path);
    for candidate in path.ancestors() {
        if is_workspace_root(fs, candidate) {
            return candidate.to_path_buf();
        }
        if git.as_deref() == Some(candidate) {
            break;
        }
    }
    git.unwrap_or(path)
}

/// Resolves the repository root and the workspace from `options`.
pub fn resolve(fs: &dyn FileSystem, options: &RootOptions) -> Roots {
    let repo = match options.repo.as_ref().or(options.repo_root_env.as_ref()) {
        Some(repo) => options.absolute(repo),
        None => find_workspace_root(fs, &options.cwd),
    };
    if let Some(workspace) = &options.tide_workspace_env {
        return Roots {
            workspace: fs.resolve(&options.absolute(workspace)),
            repo,
            tide_workspace: true,
        };
    }
    let fixture = repo.join("tests/fixtures/generation/tide_workspace");
    let workspace = if fs.is_dir(&repo.join("objects")) {
        fs.resolve(&repo)
    } else if fs.is_dir(&fixture) {
        // The opentide checkout itself: the generation fixture, as in Python.
        fs.resolve(&fixture)
    } else {
        fs.resolve(&repo)
    };
    Roots {
        repo,
        workspace,
        tide_workspace: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;

    fn options(cwd: &str) -> RootOptions {
        RootOptions {
            cwd: PathBuf::from(cwd),
            ..RootOptions::default()
        }
    }

    #[test]
    fn the_nearest_marker_wins_and_the_walk_stops_at_git() {
        let fs = MemoryFs::new();
        fs.create_dir("/repo/.git");
        fs.create_dir("/repo/team/.opentide");
        fs.create_dir("/repo/team/sub/deeper");
        fs.create_dir("/.opentide");
        assert_eq!(
            find_workspace_root(&fs, Path::new("/repo/team/sub/deeper")),
            PathBuf::from("/repo/team")
        );
        // Above the git root nothing counts, even a marker.
        fs.create_dir("/repo/other");
        assert_eq!(
            find_workspace_root(&fs, Path::new("/repo/other")),
            PathBuf::from("/repo")
        );
        // Outside git the walk goes to the top: the marker at `/` counts.
        fs.create_dir("/loose/dir");
        assert_eq!(
            find_workspace_root(&fs, Path::new("/loose/dir")),
            PathBuf::from("/")
        );
        // Outside git and without a marker, the start itself.
        let bare = MemoryFs::new();
        bare.create_dir("/loose/dir");
        assert_eq!(
            find_workspace_root(&bare, Path::new("/loose/dir")),
            PathBuf::from("/loose/dir")
        );
    }

    #[test]
    fn git_objects_and_python_packages_are_not_catalogues() {
        let fs = MemoryFs::new();
        fs.create_dir("/r/.git/objects");
        fs.write("/py/objects/__init__.py", "");
        fs.create_dir("/cat/objects");
        assert!(!is_workspace_root(&fs, Path::new("/r/.git")));
        assert!(!is_workspace_root(&fs, Path::new("/py")));
        assert!(is_workspace_root(&fs, Path::new("/cat")));
        fs.write("/wt/.git", "gitdir: elsewhere\n");
        assert_eq!(
            git_root(&fs, Path::new("/wt/a/b")),
            Some(PathBuf::from("/wt"))
        );
    }

    #[test]
    fn repo_flag_beats_the_environment_and_tide_workspace_beats_both() {
        let fs = MemoryFs::new();
        fs.create_dir("/flag/objects");
        fs.create_dir("/env/objects");
        fs.create_dir("/tide");
        let mut opts = options("/cwd");
        opts.repo = Some(PathBuf::from("/flag"));
        opts.repo_root_env = Some(PathBuf::from("/env"));
        assert_eq!(resolve(&fs, &opts).workspace, PathBuf::from("/flag"));
        opts.repo = None;
        assert_eq!(resolve(&fs, &opts).workspace, PathBuf::from("/env"));
        opts.tide_workspace_env = Some(PathBuf::from("../tide"));
        let roots = resolve(&fs, &opts);
        assert_eq!(roots.workspace, PathBuf::from("/tide"));
        assert_eq!(roots.repo, PathBuf::from("/env"));
        assert!(roots.tide_workspace);
    }

    #[test]
    fn a_repo_without_objects_falls_back_to_the_generation_fixture() {
        let fs = MemoryFs::new();
        fs.create_dir("/checkout/.git");
        fs.create_dir("/checkout/tests/fixtures/generation/tide_workspace");
        let roots = resolve(&fs, &options("/checkout/src"));
        assert_eq!(roots.repo, PathBuf::from("/checkout"));
        assert_eq!(
            roots.workspace,
            PathBuf::from("/checkout/tests/fixtures/generation/tide_workspace")
        );
        let fs = MemoryFs::new();
        fs.create_dir("/plain/.git");
        assert_eq!(
            resolve(&fs, &options("/plain")).workspace,
            PathBuf::from("/plain")
        );
    }

    #[test]
    fn relative_paths_start_at_the_working_directory() {
        let opts = options("/here");
        assert_eq!(opts.absolute(Path::new("ws")), PathBuf::from("/here/ws"));
        assert_eq!(opts.absolute(Path::new("/abs")), PathBuf::from("/abs"));
        let fs = MemoryFs::new();
        fs.create_dir("/here/ws/objects");
        let mut opts = opts;
        opts.repo = Some(PathBuf::from("ws"));
        assert_eq!(resolve(&fs, &opts).workspace, PathBuf::from("/here/ws"));
    }
}
