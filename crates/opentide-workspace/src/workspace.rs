//! A loaded workspace: its roots, its configuration (resolved once), each
//! object file read and parsed once (in parallel), and the index; and the
//! invalidation the language server and `serve` drive.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;

use crate::config::{self, ConfigError, Configuration};
use crate::discover;
use crate::fs::FileSystem;
use crate::index::{self, FamilyScan, Index};
use crate::load::{self, Parsed};
use crate::root::{self, RootOptions, Roots};

/// How a workspace is opened.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Where the workspace is ([`RootOptions`]); its working directory is also
    /// where messages show paths from.
    pub roots: RootOptions,
}

/// Why a workspace could not be opened: its configuration stops every
/// command.
pub type OpenError = ConfigError;

/// What loading did, counted: the instrumentation of issue #816.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Object files read.
    pub file_reads: usize,
    /// Object files parsed.
    pub parses: usize,
    /// Configuration resolutions.
    pub config_resolutions: usize,
    /// Configuration files read.
    pub config_files_read: usize,
}

/// What a change did to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeKind {
    /// Its content changed.
    Changed,
    /// It was created.
    Created,
    /// It was deleted.
    Deleted,
}

/// A changed path. A rename is the deletion of the old path and the
/// creation of the new one ([`Change::renamed`]). A path may name a folder:
/// everything under it counts as changed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Change {
    /// The path, absolute or from the working directory.
    pub path: PathBuf,
    /// What happened to it.
    pub kind: ChangeKind,
}

impl Change {
    /// `path`'s content changed.
    pub fn changed(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: ChangeKind::Changed,
        }
    }

    /// `path` was created.
    pub fn created(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: ChangeKind::Created,
        }
    }

    /// `path` was deleted.
    pub fn deleted(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: ChangeKind::Deleted,
        }
    }

    /// `from` was renamed to `to`.
    pub fn renamed(from: impl Into<PathBuf>, to: impl Into<PathBuf>) -> [Self; 2] {
        [Self::deleted(from), Self::created(to)]
    }
}

/// What an invalidation did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Invalidation {
    /// The workspace was loaded again from scratch: a path outside it (it may
    /// be a file the configuration points at) or one that contains it, as
    /// `serve`'s `invalidate` drops every snapshot for a path that matches
    /// none.
    pub full: bool,
    /// The configuration was resolved again: a path in a configuration
    /// folder changed.
    pub configuration: bool,
    /// The object files read and parsed again.
    pub reparsed: Vec<PathBuf>,
    /// The UUIDs whose object, signal or references changed, removed ones
    /// included.
    pub affected: BTreeSet<String>,
}

/// A loaded workspace.
pub struct Workspace {
    fs: Arc<dyn FileSystem>,
    options: Options,
    roots: Roots,
    config: Arc<Configuration>,
    parsed: HashMap<PathBuf, Arc<Parsed>>,
    index: Arc<Index>,
    stats: Stats,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workspace")
            .field("roots", &self.roots)
            .field("objects", &self.index.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

fn scan_all(fs: &dyn FileSystem, config: &Configuration) -> Vec<FamilyScan> {
    config
        .object_folders
        .iter()
        .map(|folder| FamilyScan {
            family: folder.family.clone(),
            folder: folder.path.clone(),
            scan: match &folder.path {
                Some(path) => discover::scan(fs, path),
                None => Err(discover::FolderProblem::Missing),
            },
        })
        .collect()
}

fn listed(scans: &[FamilyScan]) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    scans
        .iter()
        .filter_map(|scan| scan.scan.as_ref().ok())
        .flat_map(|scan| scan.files.iter())
        .filter(|path| seen.insert((*path).clone()))
        .cloned()
        .collect()
}

/// Reads and parses `paths` in parallel, each exactly once.
fn read_and_parse(fs: &dyn FileSystem, paths: &[PathBuf]) -> Vec<(PathBuf, Arc<Parsed>)> {
    paths
        .par_iter()
        .map(|path| {
            let parsed = match fs.read(path) {
                Ok(bytes) => load::parse(&bytes),
                Err(error) => load::unreadable(&error),
            };
            (path.clone(), Arc::new(parsed))
        })
        .collect()
}

impl Workspace {
    /// Opens the workspace `options` place, reading through `fs`.
    ///
    /// # Errors
    ///
    /// The configuration does not resolve ([`ConfigError`]).
    pub fn open(fs: Arc<dyn FileSystem>, options: Options) -> Result<Self, OpenError> {
        let roots = root::resolve(fs.as_ref(), &options.roots);
        let config = config::load(fs.as_ref(), &roots)?;
        let mut workspace = Self {
            stats: Stats {
                config_resolutions: 1,
                config_files_read: config.files_read,
                ..Stats::default()
            },
            fs,
            options,
            roots,
            config: Arc::new(config),
            parsed: HashMap::new(),
            index: Arc::new(Index::default()),
        };
        workspace.refresh(&HashSet::new());
        Ok(workspace)
    }

    /// Opens the workspace this process is in, on disk ([`crate::OsFs`]):
    /// `repo` is the `--repo` flag.
    ///
    /// # Errors
    ///
    /// The working directory cannot be read, or the configuration does not
    /// resolve.
    pub fn open_os(
        repo: Option<PathBuf>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let roots = RootOptions::from_env(repo)?;
        Ok(Self::open(Arc::new(crate::fs::OsFs), Options { roots })?)
    }

    /// Lists the object folders, parses what the cache does not hold (and
    /// what `stale` names), drops what is no longer listed, and assembles the
    /// index.
    fn refresh(&mut self, stale: &HashSet<PathBuf>) -> Vec<PathBuf> {
        let scans = scan_all(self.fs.as_ref(), &self.config);
        let files = listed(&scans);
        let keep: HashSet<&PathBuf> = files.iter().collect();
        self.parsed
            .retain(|path, _| keep.contains(path) && !stale.contains(path));
        let missing: Vec<PathBuf> = files
            .iter()
            .filter(|path| !self.parsed.contains_key(*path))
            .cloned()
            .collect();
        let fresh = read_and_parse(self.fs.as_ref(), &missing);
        self.stats.file_reads += fresh.len();
        self.stats.parses += fresh.len();
        self.parsed.extend(fresh);
        // Messages show paths from the working directory, both resolved, as
        // `_shown_path` compares them (links, `\\?\` on Windows, `/private`).
        let display_base = self.fs.resolve(&self.options.roots.cwd);
        self.index = Arc::new(index::assemble(
            &self.config.families,
            &scans,
            &self.parsed,
            &display_base,
        ));
        missing
    }

    /// The roots.
    pub fn roots(&self) -> &Roots {
        &self.roots
    }

    /// The workspace's folder.
    pub fn root(&self) -> &Path {
        &self.roots.workspace
    }

    /// The configuration, resolved once and shared.
    pub fn configuration(&self) -> &Arc<Configuration> {
        &self.config
    }

    /// The index.
    pub fn index(&self) -> &Arc<Index> {
        &self.index
    }

    /// What loading has done so far.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The filesystem.
    pub fn fs(&self) -> &Arc<dyn FileSystem> {
        &self.fs
    }

    /// Takes `changes` into account. A path inside the workspace re-reads and
    /// re-parses only the files it names (or holds, for a folder); a path in
    /// a configuration folder resolves the configuration again; any other
    /// path, or one that contains the workspace, loads everything again, as
    /// `serve`'s `invalidate` drops every snapshot for a path that matches
    /// none (vscode-extension `docs/CONTRACTS.md`). The index is assembled
    /// again from the parses either way, and equals a full load's.
    ///
    /// # Errors
    ///
    /// The configuration no longer resolves; the workspace is then unchanged.
    pub fn invalidate(&mut self, changes: &[Change]) -> Result<Invalidation, OpenError> {
        let root = self.roots.workspace.clone();
        let paths: Vec<PathBuf> = changes
            .iter()
            .map(|change| self.fs.resolve(&self.options.roots.absolute(&change.path)))
            .collect();
        if paths.is_empty() {
            return Ok(Invalidation::default());
        }
        let touches =
            |folder: &Path, path: &Path| path.starts_with(folder) || folder.starts_with(path);
        let configuration = paths.iter().any(|path| {
            self.config
                .folders
                .iter()
                .any(|folder| touches(folder, path))
        });
        let full = paths.iter().any(|path| {
            let configuration_only = self
                .config
                .folders
                .iter()
                .any(|folder| path.starts_with(folder));
            !configuration_only && (!path.starts_with(&root) || path == &root)
        });
        let before = Arc::clone(&self.index);
        if full {
            let fresh = Self::open(Arc::clone(&self.fs), self.options.clone())?;
            let stats = Stats {
                file_reads: self.stats.file_reads + fresh.stats.file_reads,
                parses: self.stats.parses + fresh.stats.parses,
                config_resolutions: self.stats.config_resolutions + 1,
                config_files_read: self.stats.config_files_read + fresh.stats.config_files_read,
            };
            let reparsed = {
                let mut files: Vec<PathBuf> = fresh.parsed.keys().cloned().collect();
                files.sort();
                files
            };
            *self = fresh;
            self.stats = stats;
            return Ok(Invalidation {
                full: true,
                configuration: true,
                reparsed,
                affected: affected(&before, &self.index),
            });
        }
        if configuration {
            let config = config::load(self.fs.as_ref(), &self.roots)?;
            self.stats.config_resolutions += 1;
            self.stats.config_files_read += config.files_read;
            self.config = Arc::new(config);
        }
        let stale: HashSet<PathBuf> = self
            .parsed
            .keys()
            .filter(|cached| paths.iter().any(|path| cached.starts_with(path)))
            .cloned()
            .collect();
        let mut reparsed = self.refresh(&stale);
        reparsed.sort();
        Ok(Invalidation {
            full: false,
            configuration,
            reparsed,
            affected: affected(&before, &self.index),
        })
    }
}

/// The UUIDs whose object (file, document), signal or references differ
/// between `before` and `after`.
fn affected(before: &Index, after: &Index) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let objects = |index: &Index| -> HashMap<(String, String), (PathBuf, usize)> {
        index
            .objects
            .iter()
            .flat_map(|(family, objects)| {
                objects.values().map(move |object| {
                    (
                        (family.clone(), object.uuid.clone()),
                        (object.path.clone(), Arc::as_ptr(&object.document).addr()),
                    )
                })
            })
            .collect()
    };
    let (old, new) = (objects(before), objects(after));
    for (key, value) in &old {
        if new.get(key) != Some(value) {
            out.insert(key.1.clone());
        }
    }
    for key in new.keys() {
        if !old.contains_key(key) {
            out.insert(key.1.clone());
        }
    }
    let signals = |index: &Index| -> HashMap<String, (String, usize)> {
        index
            .signals
            .values()
            .map(|signal| {
                (
                    signal.uuid.clone(),
                    (signal.owner.clone(), Arc::as_ptr(&signal.node).addr()),
                )
            })
            .collect()
    };
    let (old, new) = (signals(before), signals(after));
    for uuid in old.keys().chain(new.keys()) {
        if old.get(uuid) != new.get(uuid) {
            out.insert(uuid.clone());
        }
    }
    let references = |index: &Index| -> HashSet<crate::index::Reference> {
        index.references.iter().cloned().collect()
    };
    let (old, new) = (references(before), references(after));
    for reference in old.symmetric_difference(&new) {
        out.insert(reference.from.clone());
        out.insert(reference.target.clone());
    }
    out
}
