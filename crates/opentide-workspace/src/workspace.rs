//! A loaded workspace: its roots, its configuration (resolved once), each
//! object file read and parsed once (in parallel), and the index; and the
//! invalidation the language server and `serve` drive.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;

use crate::config::{self, ConfigError, Configuration};
use crate::discover;
use crate::fs::{self, FileSystem};
use crate::index::{self, FamilyScan, Index};
use crate::load::{self, Parsed};
use crate::root::{self, RootOptions, Roots};

/// How a workspace is opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag for each thing an invalidation can change"
)]
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
    /// The UUIDs whose object, signal, references or duplicate findings
    /// may have changed, removed ones included: those of the objects in the
    /// files read again, the objects that reference or are referenced by
    /// them, and the signals they own.
    pub affected: BTreeSet<String>,
    /// The files whose cached parse was dropped: read again, new, or gone.
    /// Every one of the other object files is the document it was.
    pub changed: Vec<PathBuf>,
    /// What other objects' checks read of the objects in `changed` is not what
    /// it was: an object's UUID, family or name, a signal, or a UUID another
    /// file now shares. When it is not, an edit changes the findings of
    /// the files in `changed` alone, but for the cross-rule checks
    /// ([`cross_changed`](Self::cross_changed)).
    pub identity_changed: bool,
    /// The platform blocks the cross-rule checks compare (Graylog titles,
    /// Exabeam and Google SecOps names) are not what they were in a rule of
    /// `changed`: the findings of other rules may change too.
    pub cross_changed: bool,
}

/// A loaded workspace. A clone shares the parses and the index, and is
/// cheap: a [`crate::session::Session`] hands out one per run.
#[derive(Clone)]
pub struct Workspace {
    fs: Arc<dyn FileSystem>,
    options: Options,
    roots: Roots,
    config: Arc<Configuration>,
    parsed: HashMap<PathBuf, Arc<Parsed>>,
    /// Each object file that is a symbolic link, and what it resolves to.
    links: HashMap<PathBuf, PathBuf>,
    /// The object folders as last listed: an edit of a file already listed
    /// lists nothing again.
    scans: Arc<Vec<FamilyScan>>,
    /// What [`Workspace::editor_lint`] keeps between runs.
    pub(crate) lint_records: Arc<crate::lint::RecordCache>,
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
    ///
    /// While a host keeps workspaces warm ([`crate::session::activate`],
    /// `opentide serve`), a workspace on the disk comes from the session,
    /// brought up to date.
    pub fn open(fs: Arc<dyn FileSystem>, options: Options) -> Result<Self, OpenError> {
        if let Some(opened) = crate::session::open_global(&fs, &options) {
            return opened;
        }
        Self::open_observed(fs, options, |_, _| {})
    }

    /// Opens the workspace without a session; `resolved` sees the
    /// configuration once it resolves, before any object file is read.
    pub(crate) fn open_observed(
        fs: Arc<dyn FileSystem>,
        options: Options,
        resolved: impl FnOnce(&dyn FileSystem, &Configuration),
    ) -> Result<Self, OpenError> {
        let roots = root::resolve(fs.as_ref(), &options.roots);
        let config = config::load(fs.as_ref(), &roots)?;
        resolved(fs.as_ref(), &config);
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
            links: HashMap::new(),
            scans: Arc::new(Vec::new()),
            lint_records: Arc::default(),
            index: Arc::new(Index::default()),
        };
        workspace.refresh(&HashSet::new(), true);
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

    /// Lists the object folders (unless `rescan` is false: the listing
    /// is the last one), parses what the cache does not hold (and what
    /// `stale` names), drops what is no longer listed, and assembles the
    /// index.
    fn refresh(&mut self, stale: &HashSet<PathBuf>, rescan: bool) -> Vec<PathBuf> {
        if rescan {
            self.scans = Arc::new(scan_all(self.fs.as_ref(), &self.config));
            self.lint_records.forget_listing();
        }
        let scans = Arc::clone(&self.scans);
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
        if rescan {
            self.links = scans
                .iter()
                .filter_map(|scan| scan.scan.as_ref().ok())
                .flat_map(|scan| scan.links.iter())
                .map(|link| (link.clone(), self.fs.resolve(link)))
                .collect();
        }
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

    /// The options it was opened with.
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// The working directory the workspace was opened from.
    pub fn cwd(&self) -> &Path {
        &self.options.roots.cwd
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

    /// Each object file that is a symbolic link, and what it resolves to.
    pub(crate) fn links(&self) -> &HashMap<PathBuf, PathBuf> {
        &self.links
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
    /// none (vscode-extension `docs/CONTRACTS.md`). A change that moves the
    /// workspace (a root marker created or deleted) also loads everything
    /// again. An object file that is a symbolic link is read again when
    /// the link or what it points at changes. The index is assembled again
    /// from the parses either way, and equals a full load's.
    ///
    /// # Errors
    ///
    /// The configuration no longer resolves; the workspace is then unchanged.
    #[expect(clippy::too_many_lines, reason = "kept whole; split when next reread")]
    pub fn invalidate(&mut self, changes: &[Change]) -> Result<Invalidation, OpenError> {
        if changes.is_empty() {
            return Ok(Invalidation::default());
        }
        let root = self.roots.workspace.clone();
        // Each change in the two forms a cache key can take: resolved, and
        // with only its folder resolved, as discovery names an object file
        // that is a symbolic link.
        let forms: Vec<Vec<PathBuf>> = changes
            .iter()
            .map(|change| {
                let absolute = self.options.roots.absolute(&change.path);
                let resolved = self.fs.resolve(&absolute);
                let lexical = fs::normalise(&absolute);
                let entry = match (lexical.parent(), lexical.file_name()) {
                    (Some(parent), Some(name)) => self.fs.resolve(parent).join(name),
                    _ => resolved.clone(),
                };
                if entry == resolved {
                    vec![resolved]
                } else {
                    vec![resolved, entry]
                }
            })
            .collect();
        let touches =
            |folder: &Path, path: &Path| path.starts_with(folder) || folder.starts_with(path);
        let configuration = forms.iter().flatten().any(|path| {
            self.config
                .folders
                .iter()
                .any(|folder| touches(folder, path))
        });
        let outside = forms.iter().any(|forms| {
            let configuration_only = forms.iter().any(|path| {
                self.config
                    .folders
                    .iter()
                    .any(|folder| path.starts_with(folder))
            });
            let contains_root = forms.iter().any(|path| root.starts_with(path));
            let inside = forms.iter().any(|path| path.starts_with(&root));
            !configuration_only && (contains_root || !inside)
        });
        // A root marker (`.opentide/`, `objects/`) created or deleted moves the
        // workspace: everything is loaded again from the new one.
        let full = outside || root::resolve(self.fs.as_ref(), &self.options.roots) != self.roots;
        let before = Arc::clone(&self.index);
        if full {
            // Never through a session: this is how a kept one is refreshed.
            let fresh = Self::open_observed(Arc::clone(&self.fs), self.options.clone(), |_, _| {})?;
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
            let reread = reparsed.clone();
            return Ok(Invalidation {
                full: true,
                configuration: true,
                reparsed,
                affected: affected(
                    &before,
                    &self.index,
                    &reread.iter().cloned().collect::<HashSet<PathBuf>>(),
                ),
                changed: reread,
                identity_changed: true,
                cross_changed: true,
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
            .filter(|cached| {
                let target = self.links.get(*cached);
                forms.iter().flatten().any(|path| {
                    cached.starts_with(path)
                        || target.is_some_and(|target| target.starts_with(path))
                })
            })
            .cloned()
            .collect();
        // An edit of a file already listed lists nothing new: the folders are
        // not read again. Anything else (a folder, a file the listing does not
        // hold, one that is gone, a configuration change that may move the
        // folders) lists them again.
        let content_only = !configuration
            && changes
                .iter()
                .all(|change| change.kind == ChangeKind::Changed)
            && forms.iter().all(|forms| {
                forms
                    .iter()
                    .any(|path| self.parsed.contains_key(path) && self.fs.is_file(path))
            });
        let mut reparsed = self.refresh(&stale, !content_only);
        reparsed.sort();
        let paths: HashSet<PathBuf> = stale.into_iter().chain(reparsed.iter().cloned()).collect();
        let mut reread: Vec<PathBuf> = paths.iter().cloned().collect();
        reread.sort();
        let (identity_changed, cross_changed) = what_others_read(&before, &self.index, &paths);
        if identity_changed {
            self.lint_records.forget_stems();
        }
        Ok(Invalidation {
            full: false,
            configuration,
            reparsed,
            affected: affected(&before, &self.index, &paths),
            changed: reread,
            identity_changed: identity_changed || configuration,
            cross_changed: cross_changed || configuration,
        })
    }
}

/// `node` as text, where it is written ignored: scalars as they are, a
/// collection with its contents, so two nodes that say the same dump the same.
fn dump(node: &opentide_schema::node::Node, out: &mut String) {
    use opentide_schema::node::Value;
    match &node.value {
        Value::Seq(items) => {
            out.push('[');
            for item in items {
                dump(item, out);
                out.push(',');
            }
            out.push(']');
        }
        Value::Map(entries) => {
            out.push('{');
            for entry in entries {
                dump(&entry.key, out);
                out.push(':');
                dump(&entry.value, out);
                out.push(',');
            }
            out.push('}');
        }
        // A string is quoted: `1` and `"1"` are not one value.
        Value::Str(text) | Value::Datetime(text) => {
            out.push_str(&format!("{text:?}"));
        }
        other => out.push_str(&other.to_string()),
    }
}

/// What the other objects' checks read of the objects in `paths`, in each
/// index: whether it is the same before and after, then what the cross-rule
/// checks read of their platform blocks.
fn what_others_read(before: &Index, after: &Index, paths: &HashSet<PathBuf>) -> (bool, bool) {
    // `(kind, family, uuid, name)`: an object, a file's displaced duplicate,
    // a signal of such an object.
    type Facts = BTreeSet<(u8, String, String, String)>;
    fn identity(index: &Index, paths: &HashSet<PathBuf>) -> Facts {
        let mut facts = Facts::new();
        let mut owners: HashSet<&str> = HashSet::new();
        for (family, objects) in &index.objects {
            for object in objects.values().filter(|o| paths.contains(&o.path)) {
                let name = object
                    .root()
                    .and_then(|root| root.get("name"))
                    .map_or_else(|| object.uuid.clone(), |name| name.value.to_string());
                owners.insert(object.uuid.as_str());
                facts.insert((0, family.clone(), object.uuid.clone(), name));
            }
        }
        for duplicate in index.duplicates.iter().filter(|d| paths.contains(&d.path)) {
            facts.insert((
                1,
                duplicate.family.clone(),
                duplicate.uuid.clone(),
                String::new(),
            ));
        }
        for signal in index.signals.values() {
            if owners.contains(signal.owner.as_str()) {
                let name = signal
                    .node
                    .get("name")
                    .map_or_else(|| signal.uuid.clone(), |name| name.value.to_string());
                facts.insert((2, signal.owner.clone(), signal.uuid.clone(), name));
            }
        }
        facts
    }
    /// The platform blocks the cross-rule checks compare, by rule.
    fn blocks(index: &Index, paths: &HashSet<PathBuf>) -> Facts {
        let mut facts = Facts::new();
        for object in index
            .objects
            .get("rule")
            .into_iter()
            .flat_map(|rules| rules.values())
            .filter(|rule| paths.contains(&rule.path))
        {
            let Some(configurations) = object.root().and_then(|root| root.get("configurations"))
            else {
                continue;
            };
            for platform in ["graylog", "exabeam", "google_secops"] {
                if let Some(block) = configurations.get(platform) {
                    let mut text = String::new();
                    dump(block, &mut text);
                    facts.insert((3, platform.to_owned(), object.uuid.clone(), text));
                }
            }
        }
        facts
    }
    (
        identity(before, paths) != identity(after, paths),
        blocks(before, paths) != blocks(after, paths),
    )
}

/// The UUIDs whose object, signal, references or duplicate findings may differ
/// between `before` and `after`, given that the files in `paths` are the ones
/// that were read again: the objects in them (in either index), the objects
/// that reference or are referenced by those, and the signals they own.
fn affected(before: &Index, after: &Index, paths: &HashSet<PathBuf>) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for index in [before, after] {
        for objects in index.objects.values() {
            out.extend(
                objects
                    .values()
                    .filter(|object| paths.contains(&object.path))
                    .map(|object| object.uuid.clone()),
            );
        }
        out.extend(
            index
                .duplicates
                .iter()
                .filter(|duplicate| paths.contains(&duplicate.path))
                .map(|duplicate| duplicate.uuid.clone()),
        );
    }
    let mut more: Vec<String> = Vec::new();
    for index in [before, after] {
        more.extend(
            index
                .signals
                .values()
                .filter(|signal| out.contains(&signal.owner))
                .map(|signal| signal.uuid.clone()),
        );
        for reference in &index.references {
            if out.contains(&reference.from) {
                more.push(reference.target.clone());
            }
            if out.contains(&reference.target) {
                more.push(reference.from.clone());
            }
        }
    }
    out.extend(more);
    out
}
