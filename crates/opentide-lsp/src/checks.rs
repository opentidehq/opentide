//! The checks the editor shows are the command line's: a root's Tide
//! objects are validated by `opentide-workspace` (`validate`, as `opentide
//! validate` runs it), and a configuration buffer by `opentide-schema`'s
//! configuration checks (UC-2.6, #821). This module holds a root's
//! [`Workspace`], kept up to date through its invalidation API, over the
//! disk with the editor's buffers in place of their files ([`OverlayFs`]),
//! and turns each finding into a range the editor reads (UTF-16).

use opentide_core::{Diagnostic as EngineDiagnostic, Position, Range, Severity};
use opentide_workspace::fs::{DirEntry, EntryKind};
use opentide_workspace::lint;
use opentide_workspace::validate::{
    ObjectMemo, Options as ValidateOptions, QueriesMode, Selection,
};
use opentide_workspace::{
    Change, Diagnostic, FileSystem, MemoryFs, OpenError, Options, OsFs, RootOptions, Workspace,
};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crate::session::workspace_path;

/// The disk as the server reads it between two messages that may say it
/// changed: what a folder lists and what a file holds, read once and kept
/// until [`forget`](Self::forget), which the session calls at the start and
/// the end of each batch and before each notification
/// (`Session::forget_disk`). The server's walk of a root's object files
/// (`DiskObjects`), the workspace's discovery and its read of each file, and
/// lint's scan of the object folders then list and read the disk once a
/// batch, not three times: under WASI each entry of a listing crosses to the
/// host (27 ms for a folder of a thousand files under a Wasm runtime, #1767).
pub(crate) struct Disk {
    /// The disk itself (another filesystem in tests).
    os: Box<dyn FileSystem>,
    seen: Mutex<Seen>,
}

impl Default for Disk {
    fn default() -> Self {
        Self::over(OsFs)
    }
}

/// What [`Disk`] read since it last forgot.
#[derive(Default)]
struct Seen {
    /// Counts the forgets: what a read that began before one found is not
    /// kept (a workspace loads on a thread of its own on native hosts).
    generation: u64,
    listings: HashMap<PathBuf, Vec<DirEntry>>,
    files: HashMap<PathBuf, Vec<u8>>,
}

impl Disk {
    /// `fs` read once between two forgets.
    fn over(fs: impl FileSystem + 'static) -> Self {
        Self {
            os: Box::new(fs),
            seen: Mutex::default(),
        }
    }

    /// Read the disk again from now on.
    pub(crate) fn forget(&self) {
        let mut seen = self.seen();
        seen.generation += 1;
        seen.listings.clear();
        seen.files.clear();
    }

    fn seen(&self) -> std::sync::MutexGuard<'_, Seen> {
        // What was kept is whole whatever panicked while it was held.
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What `look` finds kept, else `read` from the disk, kept unless the
    /// disk was forgotten meanwhile.
    fn once<T: Clone>(
        &self,
        look: impl Fn(&mut Seen) -> &mut HashMap<PathBuf, T>,
        path: &Path,
        read: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let generation = {
            let mut seen = self.seen();
            if let Some(kept) = look(&mut seen).get(path) {
                return Ok(kept.clone());
            }
            seen.generation
        };
        let value = read()?;
        let mut seen = self.seen();
        if seen.generation == generation {
            look(&mut seen).insert(path.to_path_buf(), value.clone());
        }
        Ok(value)
    }
}

impl FileSystem for Disk {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.once(|seen| &mut seen.files, path, || self.os.read(path))
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        self.os.kind(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        self.once(|seen| &mut seen.listings, path, || self.os.read_dir(path))
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        self.os.resolve(path)
    }
}

/// The disk ([`Disk`]), with the editor's buffers (and what a host with no
/// filesystem supplied) in place of their files: a buffer is read for its
/// path, and its folders exist, whatever the disk holds.
pub(crate) struct OverlayFs {
    base: Disk,
    buffers: MemoryFs,
}

impl OverlayFs {
    fn new() -> Self {
        Self {
            base: Disk::default(),
            buffers: MemoryFs::new(),
        }
    }
}

impl FileSystem for OverlayFs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.buffers.read(path).or_else(|_| self.base.read(path))
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        self.buffers.kind(path).or_else(|_| self.base.kind(path))
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let disk = self.base.read_dir(path);
        let buffers = self.buffers.read_dir(path);
        if disk.is_err() && buffers.is_err() {
            return disk;
        }
        let mut entries: BTreeMap<String, DirEntry> = BTreeMap::new();
        for entry in disk.into_iter().chain(buffers).flatten() {
            entries.insert(entry.name.clone(), entry);
        }
        Ok(entries.into_values().collect())
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        self.base.resolve(path)
    }
}

/// `validate`'s findings by file, resolved, shared between requests.
pub(crate) type Findings = Arc<HashMap<PathBuf, Vec<Diagnostic>>>;

/// An object a host knows by its metadata alone (`opentide-object:<uuid>`):
/// the workspace reads it as a file of its family's folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Stub {
    pub family: String,
    pub uuid: String,
    pub schema: String,
    pub name: String,
}

impl Stub {
    /// The file that stands for it in `folder`, and its text.
    fn file(&self, folder: &Path) -> (PathBuf, String) {
        let text = serde_json::json!({
            "name": self.name,
            "metadata": { "uuid": self.uuid, "schema": self.schema },
        })
        .to_string();
        (
            folder.join(format!("opentide-supplied-{}.yaml", self.uuid)),
            text,
        )
    }
}

/// What the editor and the host hold for a root: files in place of their
/// paths, and objects known by their metadata alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Buffers {
    pub files: BTreeMap<PathBuf, String>,
    pub stubs: Vec<Stub>,
}

/// How the workspace at `root` is opened: `validate` run there.
fn open_options(root: &Path) -> Options {
    Options {
        roots: RootOptions {
            repo: Some(root.to_path_buf()),
            cwd: root.to_path_buf(),
            ..RootOptions::default()
        },
    }
}

/// The folders the loaded workspace reads that a fixed glob does not name:
/// where `paths.toml` put the object families. (The configuration folder
/// layered in is the root's parent's, which needs no workspace to name.)
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct WatchScope {
    pub object_folders: Vec<PathBuf>,
}

/// The findings of every object, and what they were made in.
struct Kept {
    generation: u64,
    /// The server's environment epoch (`Session::env_epoch`): what an analysis
    /// reads besides the objects.
    epoch: u64,
    found: Findings,
}

/// A root's workspace, loaded once and kept current: what changed since
/// (an edit, a watcher's event, a file the host supplied) is handed to
/// [`Workspace::invalidate`] before the next check.
pub(crate) struct RootChecks {
    fs: Arc<OverlayFs>,
    /// The buffers in [`OverlayFs`], by path.
    buffers: BTreeMap<PathBuf, String>,
    workspace: Option<Workspace>,
    /// The workspace being loaded on a thread of its own, for its root
    /// ([`prefetch`](Self::prefetch)).
    #[cfg(not(any(target_family = "wasm", fuzzing)))]
    opening: Option<(
        PathBuf,
        std::thread::JoinHandle<Result<Workspace, OpenError>>,
    )>,
    /// Paths changed since the workspace last saw them.
    pending: Vec<Change>,
    /// The findings of the last run, by file, for the buffers and generation
    /// they were computed for.
    findings: Option<(u64, Vec<PathBuf>, Findings)>,
    /// The findings of every object, kept up to date across edits
    /// ([`refresh_all`](Self::refresh_all)).
    all: Option<Kept>,
    /// What a run over every object that stopped had checked, and the epoch
    /// it is for: the next run goes on from it. Dropped when anything the
    /// workspace reads changes ([`update`](Self::update)).
    memo: (u64, ObjectMemo),
    /// The object files whose parse changed since [`all`](Self::all) was
    /// last made current.
    dirty: std::collections::BTreeSet<PathBuf>,
    /// What other objects' checks read changed since: every object is
    /// checked again.
    stale: bool,
    /// A deployment state shard changed since [`all`](Self::all) was last
    /// made current: the shards are scanned again.
    states_changed: bool,
    /// How many times every object was checked, and how many times only the
    /// files that changed were (the tests' counters, `opentide/__stats`).
    pub(crate) validations: (u64, u64),
    /// How many times a run over every object stopped to let the messages
    /// behind it go first, and went on later.
    pub(crate) validate_stops: u64,
    /// Counts the changes to [`all`](Self::all): its entry for a file is
    /// the one made at the revision [`stamp_of`](Self::stamp_of) says.
    revision: u64,
    /// The revision of the last run over every object.
    base_stamp: u64,
    /// The revision of the last change to a file's findings since.
    stamps: HashMap<PathBuf, u64>,
    /// Why the configuration does not resolve, when it does not.
    pub failure: Option<String>,
    /// The folders the last workspace that loaded read.
    scope: WatchScope,
    /// The field catalogs generated for the workspace.
    catalog: crate::models::FieldCatalog,
}

impl Default for RootChecks {
    fn default() -> Self {
        Self {
            fs: Arc::new(OverlayFs::new()),
            buffers: BTreeMap::new(),
            workspace: None,
            #[cfg(not(any(target_family = "wasm", fuzzing)))]
            opening: None,
            pending: Vec::new(),
            findings: None,
            all: None,
            memo: (0, ObjectMemo::default()),
            validate_stops: 0,
            dirty: std::collections::BTreeSet::new(),
            stale: false,
            states_changed: false,
            validations: (0, 0),
            revision: 0,
            base_stamp: 0,
            stamps: HashMap::new(),
            failure: None,
            scope: WatchScope::default(),
            catalog: crate::models::FieldCatalog::default(),
        }
    }
}

impl RootChecks {
    /// The folders the workspace read, as the configuration last resolved them
    /// (none before the first load): kept across a configuration that does not
    /// resolve, so what watches them is not dropped while it is being mended.
    pub(crate) fn watch_scope(&self) -> WatchScope {
        self.scope.clone()
    }

    /// Take [`WatchScope`] from the workspace as it is.
    fn note_scope(&mut self) {
        let Some(workspace) = self.workspace.as_ref() else {
            return;
        };
        let configuration = workspace.configuration();
        self.scope = WatchScope {
            object_folders: configuration
                .object_folders
                .iter()
                .filter_map(|folder| folder.path.clone())
                .collect(),
        };
    }

    /// What the workspace read and parsed so far, once loaded.
    #[cfg(all(debug_assertions, not(fuzzing)))]
    pub(crate) fn stats(&self) -> Option<opentide_workspace::Stats> {
        self.workspace.as_ref().map(Workspace::stats)
    }

    /// `path` as the workspace names its files: a path that is not
    /// absolute on this platform (a browser host's, or `/a` on Windows)
    /// under the virtual root ([`workspace_path`]), then resolved as the
    /// workspace resolves what it reads (symbolic links, macOS's `/var` for
    /// `/private/var`, Windows' long form of a short name such as
    /// `RUNNER~1`). A buffer, a change, a root and a finding then name one
    /// file whatever spelling the editor used for it.
    pub(crate) fn resolve(&self, path: &Path) -> PathBuf {
        self.fs.resolve(&workspace_path(&path.to_string_lossy()))
    }

    /// The disk under the editor's buffers, as this batch reads it
    /// ([`Disk`]).
    pub(crate) fn disk(&self) -> &Disk {
        &self.fs.base
    }

    /// `paths` changed on disk (a watcher's events). What [`Disk`] kept is
    /// read again: the session forgets it before each message that may say
    /// the disk changed, and so does any change reported here.
    pub(crate) fn changed(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        self.fs.base.forget();
        let changes: Vec<Change> = paths
            .into_iter()
            .map(|path| Change::changed(self.resolve(&path)))
            .collect();
        // Nothing the workspace parses reads a shard: `validate` scans them
        // on a full run only, so the kept findings scan them again.
        self.states_changed |= changes
            .iter()
            .any(|change| is_state_shard(&change.path.to_string_lossy().replace('\\', "/")));
        self.pending.extend(changes);
    }

    /// The text of `path` as the workspace reads it (an open buffer, else the
    /// disk), when it is UTF-8 text: where a shard's findings are placed.
    pub(crate) fn read_text(&self, path: &Path) -> Option<String> {
        let bytes = self.fs.read(path).ok()?;
        let text = String::from_utf8(bytes).ok()?;
        Some(opentide_core::strip_bom(&text).to_string())
    }

    /// Put `buffers` in place of their files: the ones that changed, came or
    /// went since the last call are changes for the workspace.
    fn set_buffers(&mut self, buffers: BTreeMap<PathBuf, String>) {
        let buffers: BTreeMap<PathBuf, String> = buffers
            .into_iter()
            .map(|(path, text)| (self.resolve(&path), text))
            .collect();
        if buffers == self.buffers {
            return;
        }
        for (path, text) in &self.buffers {
            if buffers.get(path) != Some(text) {
                if !buffers.contains_key(path) {
                    self.fs.buffers.remove(path);
                }
                self.pending.push(Change::changed(path.clone()));
            }
        }
        for (path, text) in &buffers {
            if self.buffers.get(path) != Some(text) {
                self.fs.buffers.write(path, text.as_bytes().to_vec());
                if !self.buffers.contains_key(path) {
                    self.pending.push(Change::changed(path.clone()));
                }
            }
        }
        self.buffers = buffers;
    }

    /// The workspace at `root` with `buffers` in place of their files,
    /// brought up to date. `None` while its configuration does not resolve
    /// ([`failure`](Self::failure) says why).
    pub(crate) fn workspace(&mut self, root: &Path, buffers: Buffers) -> Option<&Workspace> {
        let root = &self.resolve(root);
        let mut files = buffers.files.clone();
        self.set_buffers(buffers.files);
        self.update(root);
        if buffers.stubs.is_empty() {
            return self.workspace.as_ref();
        }
        // The stubs go where the configuration puts their families' files.
        let folders: HashMap<String, PathBuf> = self
            .workspace
            .as_ref()
            .map(|workspace| {
                workspace
                    .configuration()
                    .object_folders
                    .iter()
                    .filter_map(|folder| Some((folder.family.clone(), folder.path.clone()?)))
                    .collect()
            })
            .unwrap_or_default();
        for stub in &buffers.stubs {
            if let Some(folder) = folders.get(&stub.family) {
                let (path, text) = stub.file(folder);
                files.entry(path).or_insert(text);
            }
        }
        self.set_buffers(files);
        self.update(root);
        self.workspace.as_ref()
    }

    /// Start loading the workspace at `root` on a thread of its own, while
    /// the server reads the editor's index and answers the first requests:
    /// [`update`](Self::update) takes it then, with what changed since
    /// handed to [`Workspace::invalidate`]. Nothing to do once loaded or
    /// loading, or where a thread cannot start.
    #[cfg(not(any(target_family = "wasm", fuzzing)))]
    pub(crate) fn prefetch(&mut self, root: &Path) {
        if self.workspace.is_some() || self.opening.is_some() {
            return;
        }
        let root = self.resolve(root);
        let fs: Arc<dyn FileSystem> = Arc::clone(&self.fs) as Arc<dyn FileSystem>;
        let options = open_options(&root);
        self.opening = std::thread::Builder::new()
            .name("opentide-lsp-load".to_owned())
            .spawn(move || Workspace::open(fs, options))
            .ok()
            .map(|handle| (root, handle));
    }

    /// The workspace [`prefetch`](Self::prefetch) loaded for `root`, if it
    /// did and the load succeeded; `None` otherwise (the caller loads it).
    #[cfg(not(any(target_family = "wasm", fuzzing)))]
    fn prefetched(&mut self, root: &Path) -> Option<Workspace> {
        let (at, handle) = self.opening.take()?;
        let workspace = handle.join().ok()?.ok()?;
        (at == root).then_some(workspace)
    }

    /// Whether `change` names an open buffer whose text is the file's on
    /// disk: a workspace loaded meanwhile read the same bytes either way.
    #[cfg(not(any(target_family = "wasm", fuzzing)))]
    fn is_unchanged_buffer(&self, change: &Change) -> bool {
        self.buffers.get(&change.path).is_some_and(|text| {
            self.fs
                .base
                .read(&change.path)
                .is_ok_and(|bytes| bytes == text.as_bytes())
        })
    }

    /// Hand what changed to the workspace, or load it.
    fn update(&mut self, root: &Path) {
        let current = self.pending.is_empty() && self.workspace.is_some();
        if !current {
            let changes = std::mem::take(&mut self.pending);
            self.findings = None;
            self.memo.1 = ObjectMemo::default();
            let result = match self.workspace.as_mut() {
                Some(workspace) => workspace.invalidate(&changes).map(|invalidation| {
                    // What the kept findings of every object need: the files
                    // that changed, and whether the others' checks read
                    // something that did.
                    self.stale |= invalidation.full
                        || invalidation.configuration
                        || invalidation.identity_changed
                        || invalidation.cross_changed;
                    self.dirty.extend(invalidation.changed);
                }),
                None => {
                    self.all = None;
                    self.load(root, changes)
                }
            };
            match result {
                Ok(()) => {
                    self.failure = None;
                    self.note_scope();
                }
                Err(error) => {
                    // The configuration stops every command: nothing is
                    // checked until it resolves again.
                    self.failure = Some(error.to_string());
                    self.workspace = None;
                    self.all = None;
                }
            }
            if self.all.is_none() {
                self.dirty.clear();
                self.stale = false;
                self.states_changed = false;
            }
        }
    }

    /// Load the workspace at `root`: the one [`prefetch`](Self::prefetch)
    /// loaded, with `changes` (what came in meanwhile) handed to it, but
    /// for the buffers that hold what the disk does; else read it now.
    fn load(&mut self, root: &Path, changes: Vec<Change>) -> Result<(), OpenError> {
        #[cfg(not(any(target_family = "wasm", fuzzing)))]
        if let Some(mut workspace) = self.prefetched(root) {
            let changes: Vec<Change> = changes
                .into_iter()
                .filter(|change| !self.is_unchanged_buffer(change))
                .collect();
            workspace.invalidate(&changes)?;
            self.workspace = Some(workspace);
            return Ok(());
        }
        // Read now, the buffers in place: what changed is in what it reads.
        drop(changes);
        let fs: Arc<dyn FileSystem> = Arc::clone(&self.fs) as Arc<dyn FileSystem>;
        self.workspace = Some(Workspace::open(fs, open_options(root))?);
        Ok(())
    }

    /// What `validate` reports for `files` (the open Tide documents of the
    /// root), by file: run once per `generation` and set of files. Read from
    /// the findings of every object when those are kept up to date
    /// ([`all_findings`](Self::all_findings)) and hold every one of `files`.
    pub(crate) fn findings(
        &mut self,
        root: &Path,
        buffers: Buffers,
        files: Vec<PathBuf>,
        generation: u64,
        epoch: u64,
    ) -> Findings {
        let files: Vec<PathBuf> = files.iter().map(|file| self.resolve(file)).collect();
        let cached = self.findings.as_ref().filter(|(at, wanted, _)| {
            *at == generation && files.iter().all(|file| wanted.contains(file))
        });
        if let Some((_, _, found)) = cached
            && self.pending.is_empty()
        {
            return Arc::clone(found);
        }
        if self.workspace(root, buffers.clone()).is_none() {
            return Arc::default();
        }
        if self.all.as_ref().is_some_and(|kept| kept.epoch == epoch)
            && let Ok(Some(kept)) = self.refresh_all(generation, epoch, &|| false)
        {
            let holds = self.workspace.as_ref().is_some_and(|workspace| {
                files.iter().all(|file| {
                    workspace
                        .index()
                        .sources
                        .iter()
                        .any(|source| source.path == *file)
                })
            });
            if holds {
                let mut found: HashMap<PathBuf, Vec<Diagnostic>> = files
                    .iter()
                    .filter_map(|file| Some((file.clone(), kept.get(file)?.clone())))
                    .collect();
                // `validate --file` files an open rule's shard finding on the
                // rule; the kept findings, a full run's, have it on the shard.
                if let Some(workspace) = self.workspace.as_ref() {
                    let fs = workspace.fs();
                    for finding in workspace.rule_shard_findings(&files) {
                        if let Some(file) = finding.file_path.as_deref() {
                            found.entry(fs.resolve(file)).or_default().push(finding);
                        }
                    }
                }
                let found = Arc::new(found);
                self.findings = Some((generation, files, Arc::clone(&found)));
                return found;
            }
        }
        let Some(workspace) = self.workspace.as_ref() else {
            return Arc::default();
        };
        let _span = crate::timing::Span::new("validate: the open files");
        let found = Arc::new(validate_files(workspace, &files));
        self.findings = Some((generation, files, Arc::clone(&found)));
        found
    }
}

/// The family a Tide object names (`rule` of `metadata.schema:
/// rule::1.0`), if it names one. A text the YAML loader refuses (a tag, an
/// integer past 64 bits, a key that is a collection, a syntax error) names
/// its family on its `schema:` line, so that `validate` checks it as an
/// object of that family and reports why its YAML does not load
/// (`yaml_parse`), as it does for the same file in a workspace.
fn family_of(text: &str) -> Option<String> {
    let schema = match opentide_schema::node::load(text) {
        Ok(document) => document
            .root()?
            .get("metadata")?
            .get("schema")?
            .value
            .as_str()?
            .to_owned(),
        Err(_) => opentide_tide::document_schema_id(opentide_core::strip_bom(text)),
    };
    let family = schema.split("::").next()?.trim();
    (!family.is_empty()).then(|| family.to_string())
}

impl RootChecks {
    /// Where a Tide object outside every workspace (an unsaved buffer, a
    /// file with no `objects/` or `.opentide/` around it) is checked: as a
    /// file of its family's folder in the workspace at `root` (the virtual
    /// root, which holds what a host supplied), named after `id` (its URI),
    /// so `validate` reports on it what it would on that object in a
    /// workspace of its own, a reference to an object it does not hold
    /// included. `None` for a text that names no family, or a family the
    /// configuration gives no folder.
    pub(crate) fn standalone_path(
        &mut self,
        root: &Path,
        buffers: &Buffers,
        id: &str,
        text: &str,
    ) -> Option<PathBuf> {
        use std::hash::{Hash, Hasher};
        let family = family_of(text)?;
        if self.workspace.is_none() {
            self.workspace(root, buffers.clone());
        }
        let folder = self
            .workspace
            .as_ref()?
            .configuration()
            .object_folders
            .iter()
            .find(|folder| folder.family == family)?
            .path
            .clone()?;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        id.hash(&mut hasher);
        Some(folder.join(format!("opentide-standalone-{:016x}.yaml", hasher.finish())))
    }
}

impl RootChecks {
    /// The workspace's parse of each object file it read, by the
    /// [`path_key`](crate::session::path_key) of the file under `root` as
    /// the editor names it (the walk's path): what the editor's index reads
    /// instead of parsing the files again (#926). Empty until the workspace
    /// has loaded. It never loads the workspace or hands it what changed.
    pub(crate) fn parses_under(
        &self,
        root: &Path,
    ) -> HashMap<String, Arc<opentide_schema::node::Document>> {
        let Some(workspace) = self.workspace.as_ref() else {
            return HashMap::new();
        };
        let resolved = self.resolve(root);
        workspace
            .index()
            .sources
            .iter()
            .filter_map(|source| {
                let relative = source.path.strip_prefix(&resolved).ok()?;
                let path = root.join(relative).display().to_string();
                Some((
                    crate::session::path_key(&path),
                    Arc::clone(&source.document),
                ))
            })
            .collect()
    }

    /// The Tide field catalogs the models generate for this root's
    /// configuration, as the workspace last resolved it
    /// ([`crate::models::FieldCatalog`]). `None` until the workspace has
    /// loaded and they are generated, and while its configuration does not
    /// resolve. It never loads the workspace or hands it what changed: the
    /// checks do.
    pub(crate) fn field_catalog(&mut self) -> Option<Arc<opentide_analysis::Catalog>> {
        let workspace = self.workspace.as_ref()?;
        self.catalog.for_workspace(workspace)
    }
}

impl RootChecks {
    /// What `validate` reports on every object of the root, by file: made once
    /// for the whole workspace, then kept up to date across edits by checking
    /// again only the files that changed (an editor pulls the workspace's
    /// diagnostics every two seconds, and an edit changes one file).
    pub(crate) fn all_findings(
        &mut self,
        root: &Path,
        buffers: Buffers,
        generation: u64,
        epoch: u64,
    ) -> Findings {
        self.all_findings_until(root, buffers, generation, epoch, &|| false)
            .unwrap_or_default()
    }

    /// [`all_findings`](Self::all_findings) that may stop, when `stop` says
    /// so between two batches of objects: `None` then, with what was checked
    /// kept for the next call, which reports what a run that never stopped
    /// would.
    pub(crate) fn all_findings_until(
        &mut self,
        root: &Path,
        buffers: Buffers,
        generation: u64,
        epoch: u64,
        stop: &dyn Fn() -> bool,
    ) -> Option<Findings> {
        if let Some(kept) = &self.all
            && kept.generation == generation
            && kept.epoch == epoch
            && self.pending.is_empty()
        {
            return Some(Arc::clone(&kept.found));
        }
        if self.workspace(root, buffers).is_none() {
            return Some(Arc::default());
        }
        if self.all.as_ref().is_none_or(|kept| kept.epoch != epoch) {
            self.all = None;
            self.dirty.clear();
            self.stale = true;
            self.states_changed = false;
        }
        if self.memo.0 != epoch {
            self.memo = (epoch, ObjectMemo::default());
        }
        match self.refresh_all(generation, epoch, stop) {
            Ok(found) => Some(found.unwrap_or_default()),
            Err(Stopped) => {
                self.validate_stops += 1;
                None
            }
        }
    }

    /// What identifies `file`'s entry of [`all_findings`](Self::all_findings):
    /// the same number for as long as the findings of that file are the same.
    pub(crate) fn stamp_of(&self, file: &Path) -> u64 {
        self.stamps.get(file).copied().unwrap_or(self.base_stamp)
    }

    /// The findings of every object, current for the workspace as it is: the
    /// kept ones with the files that changed checked again; every object
    /// checked again when none are kept, or something other objects' checks
    /// read changed (an object's UUID or name, a platform block the cross-rule
    /// checks compare, the configuration).
    fn refresh_all(
        &mut self,
        generation: u64,
        epoch: u64,
        stop: &dyn Fn() -> bool,
    ) -> Result<Option<Findings>, Stopped> {
        let Some(workspace) = self.workspace.as_ref() else {
            return Ok(None);
        };
        let kept = self.all.take().filter(|_| !self.stale);
        let states_changed = std::mem::take(&mut self.states_changed) && kept.is_some();
        let found = match kept {
            Some(Kept { found, .. }) if self.dirty.is_empty() && !states_changed => found,
            Some(Kept { found, .. }) if self.dirty.is_empty() => {
                let mut found = found;
                self.rescan_states(Arc::make_mut(&mut found));
                found
            }
            Some(Kept { mut found, .. }) => {
                let map = Arc::make_mut(&mut found);
                // The findings are kept by the file's resolved path (a
                // symbolic link's target), the files that changed are named as
                // the index names them.
                let keys: Vec<PathBuf> = self.dirty.iter().map(|file| self.resolve(file)).collect();
                for key in &keys {
                    map.remove(key);
                }
                let present: std::collections::HashSet<&Path> = workspace
                    .index()
                    .sources
                    .iter()
                    .map(|source| source.path.as_path())
                    .chain(
                        workspace
                            .index()
                            .load_errors
                            .iter()
                            .map(|error| error.path.as_path()),
                    )
                    .collect();
                let files: Vec<PathBuf> = self
                    .dirty
                    .iter()
                    .filter(|file| present.contains(file.as_path()))
                    .cloned()
                    .collect();
                let _span = crate::timing::Span::new("validate: the files that changed");
                self.revision += 1;
                for key in &keys {
                    self.stamps.insert(key.clone(), self.revision);
                }
                // Only the files that changed take what the narrowed run
                // found: it may put a finding on another file (a duplicate's
                // later file), whose own entry is the kept one.
                map.extend(
                    validate_changed(workspace, &files)
                        .into_iter()
                        .filter(|(key, _)| keys.contains(key)),
                );
                self.validations.1 += 1;
                if states_changed {
                    self.rescan_states(map);
                }
                found
            }
            None => {
                let _span = crate::timing::Span::new("validate: every object");
                let run = workspace
                    .validate_resumable(&ValidateOptions {
                        queries: QueriesMode::Off,
                        memo: Some(&self.memo.1),
                        stop: Some(stop),
                        ..ValidateOptions::default()
                    })
                    .ok_or(Stopped)?;
                self.revision += 1;
                self.base_stamp = self.revision;
                self.stamps.clear();
                self.validations.0 += 1;
                self.memo.1 = ObjectMemo::default();
                let _span = crate::timing::Span::new("validate: lint and placing");
                Arc::new(by_file(workspace, run, None))
            }
        };
        self.dirty.clear();
        self.stale = false;
        self.all = Some(Kept {
            generation,
            epoch,
            found: Arc::clone(&found),
        });
        Ok(Some(found))
    }
}

/// A run over every object stopped ([`RootChecks::all_findings_until`]).
struct Stopped;

impl RootChecks {
    /// Put the `deployment_state_*` findings of the shards as they are now in
    /// place of the ones `found` holds: each shard whose findings came, went
    /// or changed gets a new stamp, so the workspace pull reports it again.
    fn rescan_states(&mut self, found: &mut HashMap<PathBuf, Vec<Diagnostic>>) {
        let Some(workspace) = self.workspace.as_ref() else {
            return;
        };
        let _span = crate::timing::Span::new("validate: the deployment state shards");
        let states = workspace.root().join(".opentide").join("states");
        let mut fresh: HashMap<PathBuf, Vec<Diagnostic>> = HashMap::new();
        let fs = workspace.fs();
        for finding in workspace.deployment_state_findings() {
            if let Some(file) = finding.file_path.as_deref() {
                fresh.entry(fs.resolve(file)).or_default().push(finding);
            }
        }
        // The shards' entries: a key under the states folder holds only what
        // the scan finds (no object lives there).
        let old: Vec<PathBuf> = found
            .keys()
            .filter(|key| key.starts_with(&states) || fresh.contains_key(*key))
            .cloned()
            .collect();
        let mut touched: Vec<PathBuf> = Vec::new();
        for key in old {
            let before = found.remove(&key);
            let after = fresh.remove(&key);
            if before != after {
                touched.push(key.clone());
            }
            if let Some(after) = after {
                found.insert(key, after);
            }
        }
        for (key, after) in fresh {
            touched.push(key.clone());
            found.insert(key, after);
        }
        if !touched.is_empty() {
            self.revision += 1;
            for key in touched {
                self.stamps.insert(key, self.revision);
            }
        }
    }
}

/// Whether `path` (with `/` separators) is a deployment state shard, or a
/// folder that holds them: anything under `.opentide/states/deployment/`,
/// whose folders `validate` walks (it reports a shard in a folder below it),
/// and the two folders themselves. A client reports a deleted folder as one
/// event for the folder, not for each file in it.
pub(crate) fn is_state_shard(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path.ends_with("/.opentide/states")
        || path.ends_with("/.opentide/states/deployment")
        || path.contains("/.opentide/states/deployment/")
}

/// Whether `finding` is a `deployment_state_*` finding filed on a file other
/// than a shard. A run narrowed to some objects checks each one's shard and
/// files what it finds on the object (`validate --file`); a full run files it
/// on the shard alone ([`RootChecks::all_findings`] keeps the shards'
/// findings current). The findings of every object are a full run's: kept on
/// a closed rule, it would stay there after the shard is fixed. An open rule
/// shows it, as `validate --file` does ([`RootChecks::findings`]).
fn is_shard_finding_on_an_object(finding: &Diagnostic, file: &Path) -> bool {
    finding.code.starts_with("deployment_state_")
        && !is_state_shard(&file.to_string_lossy().replace('\\', "/"))
}

/// A run's findings by file, resolved, and lint's file name and metadata
/// findings on the same files (`files`, or every object file for `None`).
fn by_file(
    workspace: &Workspace,
    run: opentide_workspace::validate::Validation,
    files: Option<&[PathBuf]>,
) -> HashMap<PathBuf, Vec<Diagnostic>> {
    let mut by_file: HashMap<PathBuf, Vec<Diagnostic>> = HashMap::new();
    let fs = workspace.fs();
    // KG-03 and KG-05 (#893): the editor shows lint's `filename_mismatch`
    // and `metadata_recommended` (#926), `reviewed_before_modified`, and
    // `recommended_field_missing`
    // as a note (opentide 0.28.1, language-server #250).
    let lint = workspace.editor_lint(files).into_iter().map(|finding| {
        let mut diagnostic = finding.diagnostic;
        if diagnostic.code == lint::codes::FILENAME {
            // The rename quick fix's suggestion: the file name the object
            // should have, beside the file.
            diagnostic.suggestion = finding
                .entry
                .expected
                .as_deref()
                .and_then(|expected| Path::new(expected).file_name())
                .map(|name| name.to_string_lossy().into_owned());
        }
        diagnostic
    });
    for finding in run
        .report
        .issues
        .into_iter()
        .chain(run.report.warnings)
        .chain(lint)
    {
        let Some(file) = finding.file_path.as_deref() else {
            continue;
        };
        by_file.entry(fs.resolve(file)).or_default().push(finding);
    }
    by_file
}

/// `validate`'s findings on `files`, as `opentide validate --file` reports
/// them (the queries check is the editor's own analysis), and lint's file
/// name and metadata findings on them, by file, resolved.
pub(crate) fn validate_files(
    workspace: &Workspace,
    files: &[PathBuf],
) -> HashMap<PathBuf, Vec<Diagnostic>> {
    if files.is_empty() {
        return HashMap::new();
    }
    let selection = Selection {
        files: files.iter().map(|f| f.display().to_string()).collect(),
        ..Selection::default()
    };
    let run = workspace.validate(&ValidateOptions {
        selection: Some(&selection),
        queries: QueriesMode::Off,
        ..ValidateOptions::default()
    });
    by_file(workspace, run, Some(files))
}

/// [`validate_files`] for the files an edit changed, which hold every finding
/// the workspace has about them: those `validate` makes of the objects in
/// them, and lint's of the ones lint reads (a file in a folder `paths.toml`
/// moved has none, and does not keep lint from the others).
fn validate_changed(workspace: &Workspace, files: &[PathBuf]) -> HashMap<PathBuf, Vec<Diagnostic>> {
    if files.is_empty() {
        return HashMap::new();
    }
    let selection = Selection {
        files: files.iter().map(|f| f.display().to_string()).collect(),
        ..Selection::default()
    };
    let run = {
        let _span = crate::timing::Span::new("validate: the narrowed run");
        workspace.validate(&ValidateOptions {
            selection: Some(&selection),
            queries: QueriesMode::Off,
            ..ValidateOptions::default()
        })
    };
    let linted: Vec<PathBuf> = files
        .iter()
        .filter(|file| lint::is_lint_candidate(workspace.root(), file))
        .cloned()
        .collect();
    let _span = crate::timing::Span::new("validate: lint and placing");
    let mut found = by_file(workspace, run, Some(&linted));
    // These findings stand in for a full run's, which files a rule's shard
    // finding on the shard alone ([`RootChecks::rescan_states`] keeps it).
    for (file, findings) in &mut found {
        findings.retain(|finding| !is_shard_finding_on_an_object(finding, file));
    }
    found
}

/// The UTF-16 column of the code-point column `column` (from 0) of `line`,
/// clamped to the line's end.
#[expect(
    clippy::cast_possible_truncation,
    reason = "LSP positions are u32: a line of more than 4 GiB of UTF-16 is not a document an editor holds"
)]
fn utf16_column(line: &str, column: usize) -> u32 {
    line.chars()
        .take(column)
        .map(char::len_utf16)
        .sum::<usize>() as u32
}

/// The range of a finding in `text` (its file, without a byte-order mark),
/// from its 1-based line and code-point columns (`end_column` exclusive):
/// LSP's 0-based lines and UTF-16 columns. A finding without a line is at
/// the start of the file; one with a line and no column covers the line.
#[expect(
    clippy::cast_possible_truncation,
    reason = "LSP positions are u32: a document of more than 4 billion lines is not one an editor holds"
)]
pub(crate) fn finding_range(text: &str, finding: &Diagnostic) -> Range {
    let Some(line) = finding.line.filter(|line| *line > 0) else {
        return Range::point(0, 0);
    };
    let lines: Vec<&str> = text.split('\n').collect();
    let line_text = |line: usize| {
        lines
            .get(line - 1)
            .map_or("", |text| text.strip_suffix('\r').unwrap_or(text))
    };
    let start_text = line_text(line);
    let start = utf16_column(start_text, finding.column.unwrap_or(1).saturating_sub(1));
    let end_line = finding.end_line.unwrap_or(line).max(line);
    let end_text = line_text(end_line);
    let end = match finding.end_column {
        Some(column) => utf16_column(end_text, column.saturating_sub(1)),
        None if finding.column.is_some() && end_line == line => start,
        None => utf16_column(end_text, usize::MAX),
    };
    let (start_line, end_line) = ((line - 1) as u32, (end_line - 1) as u32);
    let end = if end_line == start_line {
        end.max(start)
    } else {
        end
    };
    Range {
        start: Position::new(start_line, start),
        end: Position::new(end_line, end),
    }
}

/// A finding as the editor's diagnostic: its code, severity, message and
/// field path, placed in `text`. A fix of one edit (it replaces the value
/// the finding underlines) is the suggestion a quick fix applies; lint's
/// `filename_mismatch` suggests the file name, which the quick fix renames
/// the file to.
pub(crate) fn engine_diagnostic(text: &str, finding: &Diagnostic) -> EngineDiagnostic {
    let severity = match finding.severity {
        opentide_workspace::Severity::Error => Severity::Error,
        opentide_workspace::Severity::Warning => Severity::Warning,
        _ => Severity::Information,
    };
    let suggestion = finding
        .fix
        .as_ref()
        .filter(|fix| fix.edits.len() == 1)
        .and_then(|fix| fix.edits.first())
        .map(|edit| edit.replacement.clone())
        .or_else(|| {
            (finding.code == lint::codes::FILENAME)
                .then(|| finding.suggestion.clone())
                .flatten()
        });
    EngineDiagnostic {
        code: finding.code.clone(),
        severity,
        message: finding.message.clone(),
        range: finding_range(text, finding),
        field_path: (!finding.field_path.is_empty()).then(|| finding.field_path.clone()),
        suggestion,
        object_uuid: (!finding.object_uuid.is_empty()).then(|| finding.object_uuid.clone()),
        object_type: (!finding.object_type.is_empty()).then(|| finding.object_type.clone()),
    }
}

/// The findings `opentide-schema`'s configuration checks report on a buffer
/// under `.opentide/configurations/`, as an editor sees it: the buffer
/// merged onto the bundled file, then the parent instance's file of the
/// same name; for `sharing.toml`, the statuses an open `deployment.toml`
/// buffer (else the file) declares, and whether `configurations/sharing/`
/// exists. `read` reads a file the editor has not open (the disk, or what a
/// host supplied); `is_dir` says whether a folder exists.
pub(crate) fn configuration_issues(
    path: &str,
    text: &str,
    open: &[(String, String)],
    read: &dyn Fn(&Path) -> Option<String>,
    is_dir: &dyn Fn(&Path) -> bool,
) -> Vec<opentide_analysis::ConfigIssue> {
    use opentide_schema::configuration::checks::{
        BufferContext, buffer_issues, configurations_directory,
    };
    let mut context = BufferContext::default();
    if let Some((configurations, relative)) = configurations_directory(path) {
        let configurations = PathBuf::from(configurations);
        // `<workspace>/.opentide/configurations` → `<workspace>/../.opentide/configurations`.
        let parent = configurations
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(|above| above.join(".opentide").join("configurations"));
        if let Some(parent) = parent.filter(|p| *p != configurations && is_dir(p)) {
            context.parent = read(&parent.join(&relative));
        }
        if relative == "sharing.toml" {
            let deployment = configurations.join("deployment.toml");
            let key = crate::session::path_key(&deployment.display().to_string());
            context.deployment = open
                .iter()
                .find(|(open, _)| crate::session::path_key(open) == key)
                .map(|(_, text)| text.clone())
                .or_else(|| read(&deployment));
            context.sharing_directory = is_dir(&configurations.join("sharing"));
        }
    }
    buffer_issues(path, text, &context)
        .into_iter()
        .map(|finding| opentide_analysis::ConfigIssue {
            code: finding.code,
            field_path: finding.field_path,
            severity: finding.severity,
            message: finding.message,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(line: usize, column: usize, end_column: usize) -> Diagnostic {
        let mut finding = Diagnostic::error("vocab_unknown", "unknown");
        finding.line = Some(line);
        finding.column = Some(column);
        finding.end_line = Some(line);
        finding.end_column = Some(end_column);
        finding
    }

    #[test]
    fn code_point_columns_become_utf16_columns() {
        // `é` is one code point and one UTF-16 unit; `𝄞` one code point and two units.
        let text = "name: é𝄞 x\ntlp: clearr\n";
        let range = finding_range(text, &at(1, 9, 10));
        assert_eq!(range.start, Position::new(0, 9));
        assert_eq!(range.end, Position::new(0, 10));
        let range = finding_range(text, &at(1, 8, 9));
        assert_eq!((range.start.character, range.end.character), (7, 9));
        let range = finding_range(text, &at(2, 6, 12));
        assert_eq!(range.start, Position::new(1, 5));
        assert_eq!(range.end, Position::new(1, 11));
    }

    #[test]
    fn a_finding_without_a_place_is_at_the_start_and_a_line_alone_covers_it() {
        let text = "a: 1\nbb: 22\r\n";
        let mut finding = Diagnostic::error("yaml_parse", "broken");
        assert_eq!(finding_range(text, &finding), Range::point(0, 0));
        finding.line = Some(2);
        assert_eq!(
            finding_range(text, &finding),
            Range {
                start: Position::new(1, 0),
                end: Position::new(1, 6),
            }
        );
    }

    #[test]
    fn a_column_without_an_end_column_is_a_point() {
        // `𝄞` is two UTF-16 units: column 4 (from 1) is UTF-16 unit 4.
        let text = "a𝄞 key: value\n";
        let mut finding = Diagnostic::error("schema_validation", "point");
        finding.line = Some(1);
        finding.column = Some(4);
        let point = Range::point(0, 4);
        assert_eq!(finding_range(text, &finding), point);
        // The same with the end line named, on the start's line.
        finding.end_line = Some(1);
        assert_eq!(finding_range(text, &finding), point);
        // An end line further down and no end column: to that line's end.
        let text = "a𝄞 key: value\nnext line\n";
        finding.end_line = Some(2);
        assert_eq!(
            finding_range(text, &finding),
            Range {
                start: Position::new(0, 4),
                end: Position::new(1, 9),
            }
        );
    }

    /// A nested workspace's configuration buffer is merged with the parent
    /// instance's file of the same name before it is checked, as `validate`
    /// resolves it: a key only the parent supplies is not a finding.
    #[test]
    fn a_configuration_buffer_takes_the_parent_instance_s_file() {
        let child = "/w/child/.opentide/configurations/deployment.toml";
        let text = "[promotion]\npromotion_target = \"NOPE\"\n";
        let parent_folder = PathBuf::from("/w/.opentide/configurations");
        let parent_file = parent_folder.join("deployment.toml");
        let read = |path: &Path| {
            (path == parent_file).then(|| "[promotion]\npromotion_target = \"DESIGN\"\n".to_owned())
        };
        let codes = |is_dir: &dyn Fn(&Path) -> bool| {
            configuration_issues(child, text, &[], &read, is_dir)
                .into_iter()
                .map(|issue| issue.code)
                .collect::<Vec<_>>()
        };
        // No parent instance: the child's own value is checked.
        assert_eq!(codes(&|_| false), ["promotion_target_unknown"]);
        // The parent instance's file is the later layer.
        assert_eq!(codes(&|path| path == parent_folder), Vec::<String>::new());
    }

    #[test]
    fn a_one_edit_fix_is_the_suggestion_and_the_severity_is_kept() {
        let mut finding = at(1, 6, 12);
        finding.fix = Some(opentide_workspace::Fix {
            safe: true,
            edits: vec![opentide_workspace::TextEdit {
                line: 1,
                column: 6,
                end_line: 1,
                end_column: 12,
                replacement: "clear".into(),
            }],
        });
        finding.field_path = vec!["metadata".into(), "tlp".into()];
        let diagnostic = engine_diagnostic("tlp: clearr\n", &finding);
        assert_eq!(diagnostic.suggestion.as_deref(), Some("clear"));
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.field_path,
            Some(vec!["metadata".to_string(), "tlp".to_string()])
        );
        let warning = engine_diagnostic(
            "",
            &Diagnostic::warning("nested_object_file", "not indexed"),
        );
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.suggestion, None);
        assert_eq!(warning.field_path, None);
    }

    /// A filesystem that counts what is asked of it, and can run a hook in
    /// the middle of a listing.
    #[derive(Default)]
    struct Counting {
        inner: MemoryFs,
        listings: std::sync::atomic::AtomicUsize,
        reads: std::sync::atomic::AtomicUsize,
        during_listing: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>>,
    }

    /// A [`Counting`] the test keeps a handle on.
    struct Shared(Arc<Counting>);

    impl FileSystem for Shared {
        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            self.0
                .reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.0.inner.read(path)
        }

        fn kind(&self, path: &Path) -> io::Result<EntryKind> {
            self.0.inner.kind(path)
        }

        fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
            self.0
                .listings
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let entries = self.0.inner.read_dir(path);
            if let Some(hook) = self.0.during_listing.get() {
                hook();
            }
            entries
        }

        fn resolve(&self, path: &Path) -> PathBuf {
            self.0.inner.resolve(path)
        }
    }

    fn counts(fs: &Counting) -> (usize, usize) {
        (
            fs.listings.load(std::sync::atomic::Ordering::SeqCst),
            fs.reads.load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    /// #1767: what a folder lists and a file holds is read from the disk once
    /// until the session forgets it, and read again after: a file changed on
    /// disk meanwhile is then seen as it is.
    #[test]
    fn the_disk_is_read_once_until_it_is_forgotten() {
        let counting = Arc::new(Counting::default());
        let file = Path::new("/w/objects/rules/r.yaml");
        counting.inner.write(file, b"name: a\n".to_vec());
        let disk = Disk::over(Shared(Arc::clone(&counting)));
        let folder = Path::new("/w/objects/rules");
        for _ in 0..3 {
            assert_eq!(disk.read_dir(folder).unwrap().len(), 1);
            assert_eq!(disk.read(file).unwrap(), b"name: a\n");
        }
        assert_eq!(counts(&counting), (1, 1));
        // What is not there is asked again each time: nothing is kept of it.
        assert!(disk.read(Path::new("/w/objects/rules/none.yaml")).is_err());
        assert!(disk.read(Path::new("/w/objects/rules/none.yaml")).is_err());
        assert_eq!(counts(&counting), (1, 3));

        counting.inner.write(file, b"name: b\n".to_vec());
        counting
            .inner
            .write(folder.join("s.yaml"), b"name: s\n".to_vec());
        // Not seen until the disk is forgotten.
        assert_eq!(disk.read(file).unwrap(), b"name: a\n");
        assert_eq!(disk.read_dir(folder).unwrap().len(), 1);
        disk.forget();
        assert_eq!(disk.read(file).unwrap(), b"name: b\n");
        assert_eq!(disk.read_dir(folder).unwrap().len(), 2);
        assert_eq!(counts(&counting), (2, 4));
    }

    /// A listing that began before the disk was forgotten is not kept: the
    /// next one reads the disk (a workspace loads on a thread of its own on
    /// native hosts, while the session forgets).
    #[test]
    fn a_read_begun_before_a_forget_is_not_kept() {
        let counting = Arc::new(Counting::default());
        let folder = Path::new("/w/objects");
        counting
            .inner
            .write(folder.join("r.yaml"), b"name: a\n".to_vec());
        let disk = Arc::new(Disk::over(Shared(Arc::clone(&counting))));
        let weak = Arc::downgrade(&disk);
        let forgot = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let once = Arc::clone(&forgot);
        let _ = counting.during_listing.set(Box::new(move || {
            if !once.swap(true, std::sync::atomic::Ordering::SeqCst)
                && let Some(disk) = weak.upgrade()
            {
                disk.forget();
            }
        }));
        disk.read_dir(folder).unwrap();
        disk.read_dir(folder).unwrap();
        disk.read_dir(folder).unwrap();
        // The first listing straddled a forget; the second was kept.
        assert_eq!(counts(&counting).0, 2);
    }

    #[test]
    fn a_buffer_stands_in_for_its_file_and_its_folders() {
        let fs = OverlayFs::new();
        let base =
            std::env::temp_dir().join(format!("opentide-lsp-overlay-{}", std::process::id()));
        let file = base.join("objects/rules/new.yaml");
        fs.buffers.write(&file, b"name: x\n".to_vec());
        assert_eq!(fs.read(&file).unwrap(), b"name: x\n");
        assert_eq!(fs.kind(&base.join("objects")).unwrap(), EntryKind::Dir);
        let listed: Vec<String> = fs
            .read_dir(&base.join("objects/rules"))
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(listed, ["new.yaml"]);
        assert!(fs.read(&base.join("objects/rules/other.yaml")).is_err());
    }

    /// #850: a standalone object whose YAML the loader refuses is still
    /// checked as its family, so `validate` reports its `yaml_parse`.
    #[test]
    fn the_family_of_an_object_the_loader_refuses_is_its_schema_line() {
        let rule = "name: R\nmetadata:\n  schema: rule::1.0\n";
        assert_eq!(family_of(rule).as_deref(), Some("rule"));
        assert_eq!(
            family_of("{name: R, metadata: {schema: objective::1.0}}").as_deref(),
            Some("objective")
        );
        for refused in [
            format!("{rule}query: !Ref x\n"),
            format!("{rule}big: 18446744073709551615\n"),
            format!("{rule}? [a]\n: b\n"),
            format!("\u{feff}{rule}name: S\n"),
        ] {
            assert_eq!(family_of(&refused).as_deref(), Some("rule"), "{refused}");
        }
        assert_eq!(family_of("name: R\n"), None);
        assert_eq!(family_of("name: R\nmetadata:\n  schema: 12\n"), None);
    }

    /// What an edit leaves to check: the kept findings of every object, with
    /// the files that changed checked again, are the findings a fresh run over
    /// the workspace makes, after each kind of edit, and an edit that only
    /// changes a file's own text checks that file alone.
    #[test]
    #[expect(clippy::too_many_lines, reason = "one table of edits")]
    fn kept_findings_equal_a_fresh_run_after_each_kind_of_edit() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/objects");
        let root = std::env::temp_dir().join(format!("opentide-kept-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for folder in ["rules", "objectives", "threats"] {
            std::fs::create_dir_all(root.join("objects").join(folder)).unwrap();
        }
        let rule = root.join("objects/rules/rule-1.0.yaml");
        let objective = root.join("objects/objectives/objective-1.0.yaml");
        let threat = root.join("objects/threats/threat-1.0.yaml");
        std::fs::copy(source.join("rules/rule-1.0.yaml"), &rule).unwrap();
        std::fs::copy(source.join("objective-1.0.yaml"), &objective).unwrap();
        std::fs::copy(source.join("threat-1.0.yaml"), &threat).unwrap();
        let rule_text = std::fs::read_to_string(&rule).unwrap();
        let objective_text = std::fs::read_to_string(&objective).unwrap();
        let copy = root.join("objects/rules/rule-copy.yaml");
        let renamed = root.join("objects/rules/some-other-name.yaml");
        // Two more rules whose Google SecOps blocks may share a name: a
        // finding on each, whichever is edited.
        let second = root.join("objects/rules/rule-2.yaml");
        let third = root.join("objects/rules/rule-3.yaml");
        let nameless = root.join("objects/rules/no-uuid.yaml");
        let no_uuid = |name: &str| {
            rule_text
                .replace("  uuid: 00000000-0000-4000-8003-000000000001\n", "")
                .replace("name: Sentinel KQL Rule", &format!("name: {name}"))
        };
        let with_block = |number: &str, name: &str| {
            rule_text
                .replace("8003-000000000001", &format!("8003-00000000000{number}"))
                .replace("name: Sentinel KQL Rule", &format!("name: Rule {number}"))
                .replacen(
                    "configurations:\n",
                    &format!(
                        "configurations:\n  google_secops:\n    enabled: true\n    name: {name}\n    \
                         status: X\n    events: $e.metadata.event_type = \"X\"\n    condition: $e\n"
                    ),
                    1,
                )
        };

        type Edit<'a> = Box<dyn Fn() -> Vec<PathBuf> + 'a>;
        let write = |path: &Path, text: String| {
            let path = path.to_path_buf();
            move || {
                std::fs::write(&path, &text).unwrap();
                vec![path.clone()]
            }
        };
        let remove = |path: &Path| {
            let path = path.to_path_buf();
            move || {
                let _ = std::fs::remove_file(&path);
                vec![path.clone()]
            }
        };
        let steps: Vec<(&str, bool, Edit<'_>)> = vec![
            ("nothing changed", true, Box::new(Vec::new)),
            (
                "a typed line in the rule",
                true,
                Box::new(write(&rule, format!("{rule_text}\n# typed\n"))),
            ),
            (
                "a typed line in the objective",
                true,
                Box::new(write(&objective, format!("{objective_text}\n# typed\n"))),
            ),
            (
                "the rule's severity",
                true,
                Box::new(write(
                    &rule,
                    rule_text.replace("severity: High", "severity: Nope"),
                )),
            ),
            (
                "the rule names an objective that is not there",
                true,
                Box::new(write(
                    &rule,
                    rule_text.replace("8002-000000000001", "8002-0000000000ff"),
                )),
            ),
            (
                "the rule as it was",
                true,
                Box::new(write(&rule, rule_text.clone())),
            ),
            (
                "the rule's name",
                false,
                Box::new(write(
                    &rule,
                    rule_text.replacen("name: Sentinel KQL Rule", "name: Another rule", 1),
                )),
            ),
            (
                "the rule's name as it was",
                false,
                Box::new(write(&rule, rule_text.clone())),
            ),
            ("the objective deleted", false, Box::new(remove(&objective))),
            (
                "the objective again",
                false,
                Box::new(write(&objective, objective_text.clone())),
            ),
            (
                "the rule's UUID written by a second file",
                false,
                Box::new(write(&copy, rule_text.clone())),
            ),
            (
                "the rule's severity while a copy has its UUID",
                false,
                Box::new(write(
                    &rule,
                    rule_text.replace("severity: High", "severity: Nope"),
                )),
            ),
            (
                "a typed line in the copy",
                false,
                Box::new(write(&copy, format!("{rule_text}\n# typed\n"))),
            ),
            (
                "the copy's severity",
                false,
                Box::new(write(
                    &copy,
                    rule_text.replace("severity: High", "severity: Nope"),
                )),
            ),
            (
                "a typed line in the rule, which the copy duplicates",
                false,
                Box::new(write(
                    &rule,
                    format!(
                        "{}\n# typed\n",
                        rule_text.replace("severity: High", "severity: Nope")
                    ),
                )),
            ),
            (
                "the rule mended",
                false,
                Box::new(write(&rule, rule_text.clone())),
            ),
            ("the second file deleted", false, Box::new(remove(&copy))),
            (
                "a rule with no UUID",
                false,
                Box::new(write(&nameless, no_uuid("A rule with no UUID"))),
            ),
            (
                "its name changed",
                false,
                Box::new(write(&nameless, no_uuid("Another rule with no UUID"))),
            ),
            (
                "its name is the first rule's",
                false,
                Box::new(write(&nameless, no_uuid("Sentinel KQL Rule"))),
            ),
            (
                "its name is its own again",
                false,
                Box::new(write(&nameless, no_uuid("A rule with no UUID"))),
            ),
            (
                "the rule with no UUID deleted",
                false,
                Box::new(remove(&nameless)),
            ),
            (
                "the rule's file renamed",
                false,
                Box::new({
                    let (from, to, text) = (rule.clone(), renamed.clone(), rule_text.clone());
                    move || {
                        let _ = std::fs::remove_file(&from);
                        std::fs::write(&to, &text).unwrap();
                        vec![from.clone(), to.clone()]
                    }
                }),
            ),
            (
                "the rule's file renamed back",
                false,
                Box::new({
                    let (from, to, text) = (rule.clone(), renamed.clone(), rule_text.clone());
                    move || {
                        let _ = std::fs::remove_file(&to);
                        std::fs::write(&from, &text).unwrap();
                        vec![from.clone(), to.clone()]
                    }
                }),
            ),
            (
                "the rule's YAML broken",
                false,
                Box::new(write(&rule, format!("{rule_text}\n\tbroken: [\n"))),
            ),
            (
                "the rule's YAML mended",
                false,
                Box::new(write(&rule, rule_text.clone())),
            ),
            (
                "a second rule with a Google SecOps name",
                false,
                Box::new(write(&second, with_block("2", "shared_name"))),
            ),
            (
                "a third rule with another",
                false,
                Box::new(write(&third, with_block("3", "other_name"))),
            ),
            (
                "the third rule takes the second's name",
                false,
                Box::new(write(&third, with_block("3", "SHARED_NAME"))),
            ),
            (
                "the third rule's own text",
                true,
                Box::new(write(
                    &third,
                    with_block("3", "SHARED_NAME").replace(
                        "Minimal valid detection rule",
                        "A different description of the rule",
                    ),
                )),
            ),
            (
                "the third rule names another again",
                false,
                Box::new(write(&third, with_block("3", "other_name"))),
            ),
            (
                "the third rule is named as the first (a file name both want)",
                false,
                Box::new(write(
                    &third,
                    with_block("3", "other_name")
                        .replace("name: Rule 3", "name: Sentinel KQL Rule"),
                )),
            ),
            (
                "a typed line in the third rule, which shares a name",
                true,
                Box::new(write(
                    &third,
                    format!(
                        "{}\n# typed\n",
                        with_block("3", "other_name")
                            .replace("name: Rule 3", "name: Sentinel KQL Rule")
                    ),
                )),
            ),
            (
                "the first rule's file renamed while the third has its name",
                false,
                Box::new({
                    let (from, to, text) = (rule.clone(), renamed.clone(), rule_text.clone());
                    move || {
                        let _ = std::fs::remove_file(&from);
                        std::fs::write(&to, &text).unwrap();
                        vec![from.clone(), to.clone()]
                    }
                }),
            ),
            (
                "and renamed back",
                false,
                Box::new({
                    let (from, to, text) = (rule.clone(), renamed.clone(), rule_text.clone());
                    move || {
                        let _ = std::fs::remove_file(&to);
                        std::fs::write(&from, &text).unwrap();
                        vec![from.clone(), to.clone()]
                    }
                }),
            ),
            (
                "the third rule's name as it was",
                false,
                Box::new(write(&third, with_block("3", "other_name"))),
            ),
        ];

        let fresh =
            |root: &Path| RootChecks::default().all_findings(root, Buffers::default(), 0, 0);
        let mut kept = RootChecks::default();
        let first = kept.all_findings(&root, Buffers::default(), 0, 0);
        assert_eq!(first, fresh(&root), "the first run");
        for (generation, (what, partial, edit)) in (1..).zip(&steps) {
            let (full_before, partial_before) = kept.validations;
            let changed = edit();
            kept.changed(changed);
            let found = kept.all_findings(&root, Buffers::default(), generation, 0);
            let expected = fresh(&root);
            let mut keys: Vec<_> = found.keys().collect();
            keys.sort();
            let mut want: Vec<_> = expected.keys().collect();
            want.sort();
            assert_eq!(keys, want, "{what}: the files with findings");
            for (file, findings) in expected.iter() {
                assert_eq!(
                    found.get(file),
                    Some(findings),
                    "{what}: {}",
                    file.display()
                );
            }
            let (full_after, partial_after) = kept.validations;
            if *what == "nothing changed" {
                assert_eq!((full_after, partial_after), (full_before, partial_before));
            } else if *partial {
                assert_eq!(
                    (full_after, partial_after),
                    (full_before, partial_before + 1),
                    "{what}: only the files that changed are checked"
                );
            } else {
                assert_eq!(
                    (full_after, partial_after),
                    (full_before + 1, partial_before),
                    "{what}: every object is checked again"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An object file that is a symbolic link: its findings are kept by the
    /// file it points to, and mending it replaces them, as a fresh run does,
    /// with the entry's stamp bumped.
    #[cfg(unix)]
    #[test]
    fn kept_findings_follow_a_symbolic_link_to_an_object_file() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/objects");
        let root = std::env::temp_dir().join(format!("opentide-kept-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("objects/rules")).unwrap();
        std::fs::create_dir_all(root.join("elsewhere")).unwrap();
        let rule_text = std::fs::read_to_string(source.join("rules/rule-1.0.yaml")).unwrap();
        let target = root.join("elsewhere/rule.yaml");
        let link = root.join("objects/rules/linked.yaml");
        std::fs::write(
            &target,
            rule_text.replace("severity: High", "severity: Nope"),
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let fresh =
            |root: &Path| RootChecks::default().all_findings(root, Buffers::default(), 0, 0);
        let mut kept = RootChecks::default();
        let first = kept.all_findings(&root, Buffers::default(), 0, 0);
        assert_eq!(first, fresh(&root), "the first run");
        assert!(
            first.values().any(|findings| !findings.is_empty()),
            "the broken severity is a finding: {first:?}"
        );
        let key = kept.resolve(&link);
        let stamp = kept.stamp_of(&key);
        for (generation, (what, text)) in (1..).zip([
            ("mended", rule_text.clone()),
            (
                "broken again",
                rule_text.replace("severity: High", "severity: Nope"),
            ),
        ]) {
            std::fs::write(&target, text).unwrap();
            kept.changed([link.clone()]);
            let found = kept.all_findings(&root, Buffers::default(), generation, 0);
            assert_eq!(found, fresh(&root), "{what}");
            assert_ne!(kept.stamp_of(&key), stamp, "{what}: the entry's stamp");
        }
        // Changed through the file it points to.
        std::fs::write(&target, rule_text).unwrap();
        kept.changed([target.clone()]);
        let found = kept.all_findings(&root, Buffers::default(), 9, 0);
        assert_eq!(found, fresh(&root), "mended through the target");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A run over every object that stops between batches and goes on
    /// reports what one that never stops does, however often it stops, and
    /// an edit between two attempts is in what it reports.
    #[test]
    fn a_run_over_every_object_that_stops_and_goes_on_equals_one_that_does_not() {
        use std::cell::Cell;
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/objects");
        let root = std::env::temp_dir().join(format!("opentide-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("objects/rules")).unwrap();
        let text = std::fs::read_to_string(source.join("rules/rule-1.0.yaml")).unwrap();
        let write = |i: usize, text: &str| {
            let path = root.join(format!("objects/rules/rule-{i:04}.yaml"));
            std::fs::write(&path, text).unwrap();
            path
        };
        for i in 1..=100 {
            let mut one = text.replace("8003-000000000001", &format!("8003-{i:012}"));
            if i % 7 == 0 {
                one = one.replace("severity: High", "severity: Nope");
            }
            write(i, &one);
        }
        let fresh = RootChecks::default().all_findings(&root, Buffers::default(), 0, 0);
        assert!(fresh.values().any(|findings| !findings.is_empty()));

        let mut kept = RootChecks::default();
        let asked = Cell::new(0_usize);
        let stops = Cell::new(0_usize);
        // Stops at every other ask: each attempt checks at least one batch.
        let stop = || {
            asked.set(asked.get() + 1);
            let stopping = asked.get() % 2 == 1;
            stops.set(stops.get() + usize::from(stopping));
            stopping
        };
        let mut attempts = 0;
        let found = loop {
            attempts += 1;
            assert!(attempts < 50, "it never finishes");
            if let Some(found) = kept.all_findings_until(&root, Buffers::default(), 0, 0, &stop) {
                break found;
            }
        };
        assert!(stops.get() >= 2, "it stopped {} times", stops.get());
        assert_eq!(found, fresh, "resumed equals uninterrupted");
        assert_eq!(kept.validations, (1, 0), "every object is checked once");

        // An edit between two attempts: the objects checked before it are
        // checked again.
        let mut kept = RootChecks::default();
        asked.set(0);
        assert!(
            kept.all_findings_until(&root, Buffers::default(), 0, 0, &stop)
                .is_none()
        );
        let edited = write(1, &text.replace("severity: High", "severity: Nope"));
        kept.changed([edited]);
        let found = loop {
            if let Some(found) = kept.all_findings_until(&root, Buffers::default(), 1, 0, &stop) {
                break found;
            }
        };
        let fresh = RootChecks::default().all_findings(&root, Buffers::default(), 0, 0);
        assert_eq!(found, fresh, "an edit between two attempts");
        let _ = std::fs::remove_dir_all(&root);
    }
}
