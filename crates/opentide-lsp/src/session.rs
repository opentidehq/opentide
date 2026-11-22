//! What the server knows between messages: the open documents, the
//! workspace roots and their files on disk, the client's capabilities, the
//! analyses already run, and the messages waiting to be written.

use crate::checks::{
    Buffers, Findings, RootChecks, Stub, configuration_issues, engine_diagnostic, validate_files,
};
use crate::server::{collect_objects, workspace_root};
use crate::uri::uri_to_path;
use lsp_server::{Message, Notification, ReqQueue, Response};
use opentide_analysis::{
    AnalyzeRequest, AnalyzeResponse, IndexedObject, VISIBILITY_CONFIGURATION, WorkspaceHost,
    analyze, install_visibility, is_configuration_path, place_configuration_issues,
};
use opentide_core::LanguageId;
use rayon::prelude::*;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// An open document.
pub(crate) struct Document {
    pub language: LanguageId,
    pub text: String,
    /// The editor's version, echoed on `publishDiagnostics`.
    pub version: Option<i32>,
    /// The root the document belongs to ([`Session::root_for`]).
    pub root: Option<usize>,
}

/// What the client said it can do, read once at `initialize`.
#[derive(Default, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag per client capability read at initialize"
)]
pub(crate) struct ClientCaps {
    /// The client watches files for the server (`didChangeWatchedFiles`).
    pub watch_files: bool,
    /// A watcher may be a folder and a pattern under it
    /// (`relativePatternSupport`): the way to watch a folder outside every
    /// workspace folder.
    pub relative_watch_patterns: bool,
    /// The client pulls diagnostics and can be told to pull again: the server
    /// then publishes none (#185 P0.8).
    pub pull_diagnostics: bool,
    /// Hover and completion documentation as plain text, not Markdown.
    pub plaintext_hover: bool,
    pub plaintext_completion: bool,
    /// A workspace edit may create a file (`documentChanges` with the
    /// `create` resource operation).
    pub create_files: bool,
    /// The client applies `RenameFile` operations (`workspaceEdit.documentChanges`
    /// and `resourceOperations: ["rename"]`): a `filename_slug` fix renames the file.
    pub rename_files: bool,
    pub code_description: bool,
    pub deprecated_tag: bool,
    pub related_information: bool,
    pub diagnostic_version: bool,
    pub semantic_tokens_refresh: bool,
    pub inlay_hint_refresh: bool,
    pub code_lens_refresh: bool,
    pub workspace_folders: bool,
}

/// A workspace root: a workspace folder, or the `.opentide/` (or `objects/`)
/// ancestor of a document opened outside every folder.
pub(crate) struct Root {
    pub path: PathBuf,
    /// The workspace's object files on disk, each read and indexed once
    /// (#181). With a file watcher, a file is read again when it changes;
    /// without one, each batch reads the files again and re-indexes those
    /// whose text changed.
    disk: RefCell<DiskObjects>,
    /// The batch that last looked at the disk.
    checked: Cell<u64>,
    /// The index the analysis sees: the disk objects, with the open
    /// documents of this root in place of their files.
    index: RefCell<Option<Arc<[IndexedObject]>>>,
    /// The editor's `visibility.toml` buffer while the file is open: it wins
    /// over the file on disk.
    pub visibility: Option<String>,
    /// Whether this root's catalog may have changed (#198).
    catalog: CatalogState,
    /// The last `visibility.toml` text that parsed: a buffer that is not
    /// TOML yet (mid-edit) keeps these declarations.
    #[expect(
        clippy::option_option,
        reason = "None: nothing installed yet; Some(None): no visibility.toml was found, which declares nothing; Some(Some(text)): the last text that parsed"
    )]
    good_visibility: RefCell<Option<Option<String>>>,
    /// The root's workspace, which `validate` checks (UC-2.6, #821).
    pub(crate) checks: RefCell<RootChecks>,
}

impl Root {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            disk: RefCell::default(),
            checked: Cell::new(0),
            index: RefCell::default(),
            visibility: None,
            catalog: CatalogState::default(),
            good_visibility: RefCell::default(),
            checks: RefCell::default(),
        }
    }

    /// The index is out of date: it is rebuilt on the next request, and the
    /// catalog is compared again at the end of the batch.
    fn drop_index(&self) {
        self.index.borrow_mut().take();
        self.catalog.dirty.set(true);
    }

    /// Whether `path` is one of the files [`collect_objects`] reads: YAML
    /// under the root's `objects/`.
    pub(crate) fn holds_object(&self, path: &str) -> bool {
        let path = Path::new(path);
        path.starts_with(self.path.join("objects"))
            && matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yaml" | "yml")
            )
    }

    /// Whether `path` is the root's `objects/` or under it without being an
    /// object file: a folder whose files a watcher does not report one by
    /// one.
    pub(crate) fn holds_folder(&self, path: &str) -> bool {
        Path::new(path).starts_with(self.path.join("objects")) && !self.holds_object(path)
    }

    /// A watcher reported `path`, under `objects/` but no object file: a
    /// folder created, deleted or moved, which a client reports as one event
    /// for the folder (VS Code drops the events of the files in a deleted
    /// folder). When it is a folder now, or held object files, the root's
    /// objects are read again. Whether they changed.
    pub(crate) fn refresh_folder(&self, path: &str) -> bool {
        let mut disk = self.disk.borrow_mut();
        // Not read yet: the next request reads every file.
        if !disk.loaded {
            return false;
        }
        let prefix = format!("{}/", path_key(path).trim_end_matches('/'));
        let held = disk.files.keys().any(|k| k.starts_with(&prefix));
        if !held && !Path::new(path).is_dir() {
            return false;
        }
        let changed = disk.refresh(&self.path);
        drop(disk);
        self.checks.borrow_mut().changed([PathBuf::from(path)]);
        if !changed.is_empty() {
            self.drop_index();
        }
        !changed.is_empty()
    }

    /// Read one object file again (a watcher event, or the editor closed
    /// it), or forget it when it is gone.
    pub(crate) fn refresh_object(&self, path: &str) {
        self.disk.borrow_mut().refresh_path(path);
        self.checks.borrow_mut().changed([PathBuf::from(path)]);
        self.drop_index();
    }

    fn visibility_path(&self) -> PathBuf {
        self.path.join(VISIBILITY_CONFIGURATION)
    }
}

/// Whether a root's index changed since its catalog was last compared with
/// what the client was told (`opentide/catalog`, #198). What it was told is
/// kept by the session ([`CatalogSent`]), by the root's URI, so a root that
/// is removed or re-created keeps it.
#[derive(Default)]
pub(crate) struct CatalogState {
    dirty: Cell<bool>,
}

/// What the client was told of the catalog (#198): the digest of each root's
/// catalog it got, from a response or since a `opentide/catalogChanged`, by
/// the root's `opentide/catalog` URI (`""` for the documents outside every
/// root), and whether it asked for every root, so a root that appears is
/// announced.
#[derive(Default)]
pub(crate) struct CatalogSent {
    digests: BTreeMap<String, u64>,
    every_root: bool,
}

/// The digest of what `opentide/catalog` reports of an index that
/// `opentide/catalogChanged` follows: each object's file, identity, name and
/// the UUIDs it names. Ranges are left out: they move with every edit above
/// them, and the client asks again for them.
pub(crate) fn catalog_digest(index: &[IndexedObject]) -> u64 {
    use std::hash::{Hash, Hasher};
    // Each object's own digest, keyed by its file and sorted, so the order
    // the index lists them in does not count.
    let mut entries: Vec<(String, u64)> = index
        .iter()
        .map(|o| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            (&o.uuid, &o.name, &o.schema, &o.object_type).hash(&mut hasher);
            for r in &o.refs {
                (&r.uuid, &r.field_path).hash(&mut hasher);
            }
            (path_key(&o.path), hasher.finish())
        })
        .collect();
    entries.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    entries.hash(&mut hasher);
    hasher.finish()
}

/// Whether YAML text names a Tide schema in its top-level `metadata` block
/// (`  schema: rule::1.0`), read line by line so a half-typed document counts.
pub(crate) fn names_tide_schema(text: &str) -> bool {
    let mut in_metadata = false;
    for line in text.lines() {
        if !line.starts_with([' ', '\t']) {
            in_metadata = line.trim_end() == "metadata:";
            continue;
        }
        if in_metadata && let Some(value) = line.trim_start().strip_prefix("schema:") {
            let value = value.trim().trim_matches(['"', '\'']);
            if ["rule::", "threat::", "objective::"]
                .iter()
                .any(|family| value.starts_with(family))
            {
                return true;
            }
        }
    }
    false
}

/// The key a file is cached under: `/` separators and a lower-case drive
/// letter, so the directory walk (`C:\\w\\x.yaml`) and a URI
/// (`file:///c%3A/w/x.yaml`) name one file once.
pub(crate) fn path_key(path: &str) -> String {
    let mut key = path.replace('\\', "/");
    if key.as_bytes().get(1) == Some(&b':') {
        key[..1].make_ascii_lowercase();
    }
    key
}

/// The key a root is compared under: its [`path_key`] without trailing
/// separators, so `/w/` (a client that sends its folder with a slash) and
/// `/w` are one root. A bare `/` and a drive root (`c:/`) keep theirs.
pub(crate) fn root_key(path: &str) -> String {
    let key = path_key(path);
    let trimmed = key.trim_end_matches('/');
    if trimmed.is_empty() && !key.is_empty() {
        return "/".to_string();
    }
    if trimmed.len() == 2 && trimmed.as_bytes()[1] == b':' {
        return format!("{trimmed}/");
    }
    trimmed.to_string()
}

/// What happened to the catalog a root is analysed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sighting {
    /// The root had this catalog already.
    Same,
    /// The first catalog the root has had: what an analysis read before it
    /// was the engine's compiled-in snapshot.
    First,
    /// Another catalog than the root had: every analysis of it reads it.
    Changed,
}

/// `folder` as the front of a glob: its separators `/`, and the characters a
/// glob reads (`[`, `*`, `?`) as one-character classes, which match only
/// themselves. A brace cannot be escaped in an LSP glob: the folder is
/// then its nearest ancestor with none (`true`), and the glob matches
/// everything under that, provided that ancestor is a `floor` or below one:
/// a workspace never has a glob reach the top of a filesystem or a drive.
/// `None` when it would.
fn glob_path(folder: &str, floors: &[PathBuf]) -> Option<(String, bool)> {
    let folder = folder.replace('\\', "/");
    let mut kept: Vec<&str> = Vec::new();
    let mut coarse = false;
    for part in folder.trim_end_matches('/').split('/') {
        if part.contains(['{', '}']) {
            coarse = true;
            break;
        }
        kept.push(part);
    }
    let ancestor = kept.join("/");
    if coarse
        && !floors
            .iter()
            .any(|floor| Path::new(&ancestor).starts_with(floor))
    {
        return None;
    }
    let mut escaped = String::new();
    for (i, part) in kept.iter().enumerate() {
        if i > 0 {
            escaped.push('/');
        }
        for c in part.chars() {
            match c {
                '[' | '*' | '?' => {
                    escaped.push('[');
                    escaped.push(c);
                    escaped.push(']');
                }
                other => escaped.push(other),
            }
        }
    }
    Some((escaped, coarse))
}

/// The catalog each root (`None`: a document outside every root) last had
/// installed for it, so that installing the catalog of another root, which
/// happens each time requests alternate between roots, is not mistaken for
/// a catalog that changed.
#[derive(Default)]
pub(crate) struct CatalogSightings(HashMap<Option<usize>, Arc<opentide_analysis::Catalog>>);

impl CatalogSightings {
    pub(crate) fn saw(
        &mut self,
        root: Option<usize>,
        catalog: &Arc<opentide_analysis::Catalog>,
    ) -> Sighting {
        match self.0.get(&root) {
            Some(known)
                if Arc::ptr_eq(known, catalog)
                    || (known.fields == catalog.fields
                        && known.deprecations == catalog.deprecations) =>
            {
                Sighting::Same
            }
            known => {
                let first = known.is_none();
                self.0.insert(root, Arc::clone(catalog));
                if first {
                    Sighting::First
                } else {
                    Sighting::Changed
                }
            }
        }
    }
}

/// One closed file's entry of a workspace pull: its URI, the id of its
/// diagnostics and the diagnostics.
pub(crate) type ReportEntry = (lsp_types::Uri, String, Vec<lsp_types::Diagnostic>);

/// A workspace pull's report, and the [`Session::state_key`] it was made in.
pub(crate) type CachedReport = ((u64, u64), Arc<Vec<ReportEntry>>);

/// An object file on disk: its path and text, indexed on first use (the
/// first request that reads the editor's index: a hover, a completion, the
/// catalog, an Elastic rule's advisories), not when it is read.
struct DiskFile {
    path: String,
    text: String,
    indexed: OnceLock<Option<IndexedObject>>,
    /// What the engine's analysis of this text found (the queries it carries),
    /// and the [`Session::env_epoch`] it was made in: a workspace pull
    /// repeats every two seconds for as long as the editor runs, and an
    /// analysis reads nothing but the text and the epoch's catalogs.
    analysis: Mutex<Option<(u64, Arc<Vec<opentide_core::Diagnostic>>)>>,
}

impl DiskFile {
    fn new(path: String, text: String) -> Self {
        Self {
            path,
            text,
            indexed: OnceLock::new(),
            analysis: Mutex::new(None),
        }
    }

    /// The analysis made in `epoch`, if there is one.
    fn cached_analysis(&self, epoch: u64) -> Option<Arc<Vec<opentide_core::Diagnostic>>> {
        let held = self
            .analysis
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.as_ref()
            .filter(|(at, _)| *at == epoch)
            .map(|(_, found)| Arc::clone(found))
    }

    fn keep_analysis(&self, epoch: u64, found: Arc<Vec<opentide_core::Diagnostic>>) {
        *self
            .analysis
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((epoch, found));
    }

    /// Its index entry; `None` for a file that is no object. It is read
    /// from `parsed`, the workspace's parse of the file, when that is of
    /// this text; else the file is parsed here, with the same parser, and
    /// `parsed_here` counts it (#926).
    fn indexed(
        &self,
        parsed: Option<&Arc<opentide_schema::node::Document>>,
        parsed_here: &AtomicUsize,
    ) -> Option<&IndexedObject> {
        self.indexed
            .get_or_init(|| match parsed.filter(|doc| doc.source() == self.text) {
                Some(document) => crate::index::index_document(&self.path, document),
                None => {
                    parsed_here.fetch_add(1, Ordering::Relaxed);
                    crate::index::index_text(&self.path, &self.text)
                }
            })
            .as_ref()
    }

    /// Its index entry, once indexed.
    fn entry(&self) -> Option<&IndexedObject> {
        self.indexed.get().and_then(Option::as_ref)
    }
}

/// Object files under a root, by [`path_key`].
#[derive(Default)]
struct DiskObjects {
    loaded: bool,
    files: BTreeMap<String, DiskFile>,
    /// How many files the index parsed itself, not reading the workspace's
    /// parse (`opentide/__stats`).
    parsed_here: AtomicUsize,
}

impl DiskObjects {
    /// Read every object file again; keep the index entry of those whose
    /// text did not change. The files that changed, came or went (every
    /// file on the first read).
    fn refresh(&mut self, root: &Path) -> Vec<PathBuf> {
        let found: BTreeMap<String, (String, String)> = collect_objects(root)
            .into_iter()
            .map(|(path, text)| (path_key(&path), (path, text)))
            .collect();
        let mut changed: Vec<PathBuf> = self
            .files
            .iter()
            .filter(|(key, _)| !found.contains_key(*key))
            .map(|(_, file)| PathBuf::from(&file.path))
            .collect();
        if !self.loaded && found.is_empty() {
            changed.push(root.join("objects"));
        }
        self.loaded = true;
        self.files.retain(|path, _| found.contains_key(path));
        for (key, (path, text)) in found {
            match self.files.get(&key) {
                Some(known) if known.text == text => {}
                _ => {
                    changed.push(PathBuf::from(&path));
                    self.files.insert(key, DiskFile::new(path, text));
                }
            }
        }
        changed
    }

    /// Index the files that are not indexed yet, in parallel, from the
    /// workspace's parse of each (`parses`, by [`path_key`], read only when
    /// a file needs it): every object file of the root, on the first
    /// request that reads the editor's index.
    fn index_pending(
        &self,
        parses: &dyn Fn() -> HashMap<String, Arc<opentide_schema::node::Document>>,
    ) -> &BTreeMap<String, DiskFile> {
        let pending = |file: &DiskFile| file.indexed.get().is_none();
        if !self.files.values().any(pending) {
            return &self.files;
        }
        let parses = parses();
        self.files
            .par_iter()
            .filter(|(_, file)| pending(file))
            .for_each(|(key, file)| {
                file.indexed(parses.get(key), &self.parsed_here);
            });
        &self.files
    }

    fn refresh_path(&mut self, path: &str) {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let text = opentide_core::strip_bom(&text).to_string();
                self.files
                    .insert(path_key(path), DiskFile::new(path.to_owned(), text));
            }
            Err(_) => {
                self.files.remove(&path_key(path));
            }
        }
    }
}

/// The workspace a host with no filesystem supplies on `initialize`
/// (`initializationOptions.workspace`): a browser worker
/// ([`MessageSession`](crate::MessageSession)). Its objects are indexed as
/// if they were on disk: a file under a root's folder in that root, one
/// outside every root in every root and outside them. A root's
/// `.opentide/configurations/visibility.toml` among the documents declares
/// that root's datasets. They are never checked or published.
#[derive(Default)]
pub(crate) struct Supplied {
    /// [`path_key`] → (path, text, index entry).
    pub files: BTreeMap<String, (String, String, Option<IndexedObject>)>,
    /// The text of `visibility.toml`, used where no root has one on disk.
    pub visibility: Option<String>,
}

impl Supplied {
    /// Read `initializationOptions.workspace`:
    ///
    /// - `documents`: `[{ "uri", "text" }]`, object files;
    /// - `objects`: `[{ "uuid", "schema", "name"?, "uri"? }]`, objects the
    ///   host knows by their metadata alone, indexed with just those keys;
    /// - `visibility`: the text of `visibility.toml`.
    ///
    /// Entries that lack what they need are skipped.
    pub(crate) fn from_options(workspace: Option<&serde_json::Value>) -> Self {
        use serde_json::Value;
        let mut supplied = Self::default();
        let Some(workspace) = workspace else {
            return supplied;
        };
        let entries = |key: &str| {
            workspace
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        };
        let mut add = |path: String, text: String| {
            let indexed = crate::index::index_text(&path, &text);
            supplied
                .files
                .insert(path_key(&path), (path, text, indexed));
        };
        for document in entries("documents") {
            let field = |key: &str| document.get(key).and_then(Value::as_str);
            if let (Some(uri), Some(text)) = (field("uri"), field("text")) {
                add(uri_to_path(uri), opentide_core::strip_bom(text).to_string());
            }
        }
        for object in entries("objects") {
            let field = |key: &str| object.get(key).and_then(Value::as_str);
            let (Some(uuid), Some(schema)) = (field("uuid"), field("schema")) else {
                continue;
            };
            let path = field("uri").map_or_else(|| format!("opentide-object:{uuid}"), uri_to_path);
            // JSON is YAML: the stub indexes like an object file with these
            // keys alone.
            let stub = serde_json::json!({
                "name": field("name").unwrap_or(""),
                "metadata": { "uuid": uuid, "schema": schema },
            });
            add(path, stub.to_string());
        }
        supplied.visibility = workspace
            .get("visibility")
            .and_then(Value::as_str)
            .map(str::to_string);
        supplied
    }

    /// Apply `opentide/didChangeWorkspace`: what the host's workspace holds
    /// now, as a change to what it supplied.
    ///
    /// - `documents`: `[{ "uri", "text" }]`, object files added or changed;
    /// - `objects`: `[{ "uuid", "schema", "name"?, "uri"? }]`, objects known by
    ///   their metadata, added or changed;
    /// - `removed`: `[uri]`, files gone (an object known by its metadata alone
    ///   and no `uri` is `opentide-object:<uuid>`);
    /// - `visibility`: the new text of `visibility.toml`, or `null` when it is
    ///   gone; absent, it is unchanged.
    ///
    /// Entries that lack what they need are skipped. Whether anything changed.
    pub(crate) fn apply(&mut self, change: &serde_json::Value) -> bool {
        use serde_json::Value;
        let entries = |key: &str| {
            change
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        };
        let mut changed = false;
        for uri in entries("removed").filter_map(Value::as_str) {
            changed |= self.files.remove(&path_key(&uri_to_path(uri))).is_some();
        }
        // The same reading as `initialize`, then merged: a newer text replaces
        // an older one of the same file.
        let added = Self::from_options(Some(change));
        for (key, entry) in added.files {
            let same = self
                .files
                .get(&key)
                .is_some_and(|(_, text, _)| *text == entry.1);
            if !same {
                self.files.insert(key, entry);
                changed = true;
            }
        }
        if let Some(visibility) = change.get("visibility") {
            let next = visibility.as_str().map(str::to_string);
            if next != self.visibility {
                self.visibility = next;
                changed = true;
            }
        }
        changed
    }
}

/// What a watched folder is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeKind {
    /// Object files `paths.toml` put elsewhere than `objects/`.
    Objects,
    /// Configuration files layered in from a folder outside the root.
    Configuration,
}

/// The folders of one root a fixed glob does not name.
#[derive(Default)]
struct ExtraFolders {
    /// Object folders `paths.toml` put outside `objects/`, as the editor
    /// spells the root.
    objects: Vec<PathBuf>,
    /// The configuration folder layered in from above the root, as the
    /// workspace names it.
    layered: Vec<PathBuf>,
    /// See [`WatchTarget::floors`].
    floors: Vec<PathBuf>,
    /// The root's own `.opentide/configurations/`, resolved.
    own_configuration: PathBuf,
}

/// A folder the client is asked to watch, and the files under it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WatchTarget {
    folder: PathBuf,
    pattern: &'static str,
    /// The folders above which a glob that cannot name `folder` (a brace in
    /// its path) may not reach: the root's parent, as the editor spells it and
    /// as the workspace does.
    floors: Vec<PathBuf>,
}

/// The registration that watches the loaded workspaces' own folders.
#[derive(Default)]
struct Watched {
    targets: Vec<WatchTarget>,
    /// The registration's id while one is in place.
    id: Option<String>,
    serial: u32,
}

#[derive(Default)]
pub(crate) struct Session {
    pub docs: HashMap<String, Document>,
    pub roots: Vec<Root>,
    /// How many of [`roots`](Self::roots), from the start, are workspace
    /// folders; the others were found around documents.
    pub folders: usize,
    pub caps: ClientCaps,
    /// `initialize` was answered: logs go to the client.
    pub initialized: bool,
    /// Bumped by anything that can change an analysis: an edit, a file on
    /// disk, `visibility.toml`, the roots. A cached analysis is current only
    /// for the generation it ran in (#185 P1.3).
    generation: Cell<u64>,
    /// Bumped by what changes how *any* object is analysed: the same causes as
    /// [`generation`](Self::generation) except an edit of, or a change to, an
    /// object file, which no other object's analysis reads. A closed file's
    /// analysis is current for the epoch it ran in, so typing in one rule
    /// does not make the editor's workspace pull analyse every other again.
    env_epoch: Cell<u64>,
    cache: RefCell<HashMap<String, (u64, Arc<AnalyzeResponse>)>>,
    /// How many analyses ran, for the tests (`opentide/__stats`).
    pub analyses: Cell<u64>,
    /// How many closed object files were analysed (not read from their
    /// entry), for the tests (`opentide/__stats`).
    pub closed_analyses: Cell<u64>,
    /// What the last workspace pull answered for each closed file, and the
    /// [`state_key`](Self::state_key) it was made in: the client asks again
    /// two seconds after every answer, and when nothing changed since, the
    /// answer is the same.
    pub workspace_report: RefCell<Option<CachedReport>>,
    /// How many workspace pulls were answered from [`workspace_report`](Self::workspace_report),
    /// for the tests (`opentide/__stats`).
    pub workspace_report_hits: Cell<u64>,
    /// The folders the client was last asked to watch beyond the fixed
    /// globs ([`sync_watchers`](Self::sync_watchers)).
    watched: RefCell<Watched>,
    /// The client sent `initialized`: only then may the server ask it
    /// anything.
    pub(crate) client_initialized: Cell<bool>,
    batch: Cell<u64>,
    /// The root whose catalogs and declared datasets the engine has
    /// installed; `None` until the first request, and again after they
    /// change.
    #[expect(
        clippy::option_option,
        reason = "None: nothing installed yet, or reset; Some(root): the root installed, None for a document outside every root"
    )]
    active: Cell<Option<Option<usize>>>,
    /// Documents whose diagnostics changed in this batch, and whether every
    /// open document's did.
    pending: RefCell<BTreeSet<String>>,
    everything: Cell<bool>,
    open_documents: Cell<bool>,
    outbox: RefCell<Vec<Message>>,
    requests: RefCell<ReqQueue<(), &'static str>>,
    /// The broken-file warning was shown (once per session).
    warned: Cell<bool>,
    loose_index: RefCell<Option<Arc<[IndexedObject]>>>,
    /// The catalog of the documents outside every root, when there is no root.
    loose_catalog: CatalogState,
    /// What the client was told of the catalog (#198).
    catalog_sent: RefCell<CatalogSent>,
    /// What a host with no filesystem supplied on `initialize`.
    pub supplied: Supplied,
    /// The workspaces of documents outside every root, by the folder that
    /// holds their `objects/`.
    loose_checks: RefCell<HashMap<PathBuf, RootChecks>>,
    /// The Tide field catalogs the engine has installed: the ones the models
    /// generate for the root of the last request ([`Session::host`]).
    installed_catalog: RefCell<Option<Arc<opentide_analysis::Catalog>>>,
    /// The catalog each root last had installed for it ([`install_field_catalog`](Self::install_field_catalog)).
    sightings: RefCell<CatalogSightings>,
}

/// `path` as the workspace reads it: an absolute path as it is; anything
/// else (an editor buffer's URI of another scheme, a path a browser host
/// supplied relative to its workspace) under [`VIRTUAL_ROOT`], where no disk
/// file is, so its folders and `objects/` are the buffers' alone.
pub(crate) fn workspace_path(path: &str) -> PathBuf {
    let native = Path::new(path);
    if is_absolute(native) {
        native.to_path_buf()
    } else {
        Path::new(VIRTUAL_ROOT).join(path.trim_start_matches(['/', '\\']))
    }
}

/// Whether `path` is absolute here. The browser build (wasm32-unknown-unknown)
/// is neither Unix nor Windows, and std calls no path absolute there, not
/// even [`VIRTUAL_ROOT`]'s: a rooted path is, as on Unix, or every call
/// would put the path under the virtual root once more.
fn is_absolute(path: &Path) -> bool {
    if cfg!(all(target_family = "wasm", target_os = "unknown")) {
        path.has_root()
    } else {
        path.is_absolute()
    }
}

/// The workspace an object file outside every root belongs to: the folder
/// that holds the nearest `objects/` above it.
fn objects_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .skip(1)
        .find(|a| a.file_name().is_some_and(|name| name == "objects"))
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

/// Where [`workspace_path`] puts what is not an absolute path.
#[cfg(windows)]
pub(crate) const VIRTUAL_ROOT: &str = "C:\\opentide-virtual";
/// Where [`workspace_path`] puts what is not an absolute path.
#[cfg(not(windows))]
pub(crate) const VIRTUAL_ROOT: &str = "/opentide-virtual";

/// What a request sees of the workspace: the open documents, the object
/// files of one root on disk, and their index.
pub(crate) struct SessionHost<'a> {
    session: &'a Session,
    root: Option<usize>,
}

impl WorkspaceHost for SessionHost<'_> {
    fn document(&self, uri: &str) -> Option<String> {
        let session = self.session;
        if let Some(doc) = session.docs.get(uri) {
            return Some(doc.text.clone());
        }
        let key = path_key(uri);
        if let Some((_, doc)) = session
            .docs
            .iter()
            .find(|(open, _)| path_key(&uri_to_path(open)) == key)
        {
            return Some(doc.text.clone());
        }
        for root in &session.roots {
            if let Some(file) = root.disk.borrow().files.get(&key) {
                return Some(file.text.clone());
            }
        }
        if let Some((_, text, _)) = session.supplied.files.get(&key) {
            return Some(text.clone());
        }
        let elastic = session.elastic_configuration(self.root)?;
        (path_key(&elastic.0) == key).then_some(elastic.1)
    }

    /// The root's open documents and its Elastic tenants file. Object files
    /// on disk come through [`indexed_objects`](WorkspaceHost::indexed_objects).
    fn documents(&self) -> Vec<(String, String)> {
        let session = self.session;
        let mut uris: Vec<&String> = session
            .docs
            .iter()
            .filter(|(_, doc)| doc.root == self.root)
            .map(|(uri, _)| uri)
            .collect();
        uris.sort();
        let mut files: Vec<(String, String)> = uris
            .into_iter()
            .map(|uri| (uri_to_path(uri), session.docs[uri].text.clone()))
            .collect();
        if let Some((path, text)) = session.elastic_configuration(self.root)
            && !files
                .iter()
                .any(|(open, _)| path_key(open) == path_key(&path))
        {
            files.push((path, text));
        }
        files
    }

    fn indexed_objects(&self) -> Option<Arc<[IndexedObject]>> {
        let slot = self.slot();
        if let Some(index) = slot.borrow().as_ref() {
            return Some(Arc::clone(index));
        }
        let index: Arc<[IndexedObject]> = self.collect_index().into();
        *slot.borrow_mut() = Some(Arc::clone(&index));
        Some(index)
    }
}

impl SessionHost<'_> {
    /// Where the root's index is kept.
    fn slot(&self) -> &RefCell<Option<Arc<[IndexedObject]>>> {
        match self.root {
            Some(i) => &self.session.roots[i].index,
            None => &self.session.loose_index,
        }
    }

    /// The index entries of the root's objects: the files on disk (but the
    /// open ones), the open documents, then what the host supplied that no
    /// file holds. A file on disk is indexed once, whichever call indexes
    /// it first.
    fn collect_index(&self) -> Vec<IndexedObject> {
        let session = self.session;
        let open: BTreeMap<String, (String, &String)> = session
            .docs
            .iter()
            .filter(|(_, doc)| doc.root == self.root && doc.language == LanguageId::TideYaml)
            .map(|(uri, doc)| {
                let path = uri_to_path(uri);
                (path_key(&path), (path, &doc.text))
            })
            .collect();
        let mut index: Vec<IndexedObject> = match self.root {
            Some(i) => {
                let root = &session.roots[i];
                let parses = || {
                    root.checks
                        .try_borrow()
                        .map(|checks| checks.parses_under(&root.path))
                        .unwrap_or_default()
                };
                root.disk
                    .borrow()
                    .index_pending(&parses)
                    .iter()
                    .filter(|(path, _)| !open.contains_key(*path))
                    .filter_map(|(_, file)| file.entry().cloned())
                    .collect()
            }
            None => Vec::new(),
        };
        index.extend(
            open.values()
                .filter_map(|(path, text)| crate::index::index_text(path, text)),
        );
        // What the host supplied stands in for objects the session has no
        // file for: an object open or on disk is itself, not a duplicate of
        // its own metadata. A supplied file under a root's folder is that
        // root's alone, as a file on disk would be; one outside every root
        // (an object known by its metadata, `opentide-object:<uuid>`) is
        // every root's.
        let known: HashSet<String> = index.iter().map(|o| o.uuid.clone()).collect();
        let on_disk = |key: &String| {
            self.root
                .is_some_and(|i| session.roots[i].disk.borrow().files.contains_key(key))
        };
        index.extend(
            session
                .supplied
                .files
                .iter()
                .filter(|(key, _)| !open.contains_key(*key) && !on_disk(key))
                .filter(|(_, (path, _, _))| {
                    let owner = session.owning_root(path);
                    owner.is_none() || owner == self.root
                })
                .filter_map(|(_, (_, _, indexed))| indexed.clone())
                .filter(|o| !known.contains(&o.uuid)),
        );
        index
    }
}

impl Session {
    /// The view of the workspace for a document of `root`: its files on
    /// disk are read again when no watcher reports changes, and its
    /// catalogs and declared datasets are installed in the engine.
    pub(crate) fn host(&self, root: Option<usize>) -> SessionHost<'_> {
        if let Some(r) = root.and_then(|i| self.roots.get(i))
            && r.checked.get() != self.batch.get()
        {
            r.checked.set(self.batch.get());
            let mut disk = r.disk.borrow_mut();
            if !disk.loaded || !self.caps.watch_files {
                let first = !disk.loaded;
                let changed = disk.refresh(&r.path);
                if !self.caps.watch_files && !first {
                    // Nothing reports what changed on disk: the object
                    // files the walk found changed, and the
                    // configuration, which is resolved again.
                    let mut checks = r.checks.borrow_mut();
                    checks.changed(changed.iter().cloned());
                    checks.changed([r.path.join(".opentide").join("configurations")]);
                }
                if !changed.is_empty() {
                    r.drop_index();
                    self.touch();
                }
            }
        }
        // The catalogs first: installing them resets the declared datasets,
        // which `activate` then installs again.
        self.install_field_catalog(root);
        self.activate(root);
        SessionHost {
            session: self,
            root,
        }
    }

    /// The view of the workspace for a document.
    pub(crate) fn host_for(&self, uri: &str) -> SessionHost<'_> {
        let root = match self.docs.get(uri) {
            Some(doc) => doc.root,
            None => self.root_for(&uri_to_path(uri)),
        };
        self.host(root)
    }

    /// Install `root`'s catalogs and declared datasets in the engine, unless
    /// they are installed already. With one root this happens once.
    ///
    /// The installation is process-wide and takes no lock. A `validate` or
    /// `lint` run in the same process neither reads nor replaces it: each
    /// carries its own workspace's datasets (`opentide_analysis::Datasets`,
    /// #1142).
    fn activate(&self, root: Option<usize>) {
        if self.active.get() == Some(root) {
            return;
        }
        self.active.set(Some(root));
        let r = root.and_then(|i| self.roots.get(i));
        let Some(r) = r else {
            if let Err(err) = install_visibility(self.supplied.visibility.as_deref()) {
                self.log_warning(&format!("opentide-lsp: {err}; no datasets are declared"));
                let _ = install_visibility(None);
            }
            return;
        };
        // The editor's buffer, else the file on disk, else the root's own
        // `visibility.toml` among the supplied documents, else the one
        // `visibility` the host supplied for every root.
        let text = r
            .visibility
            .clone()
            .or_else(|| std::fs::read_to_string(r.visibility_path()).ok())
            .or_else(|| {
                self.supplied
                    .files
                    .get(&path_key(&r.visibility_path().display().to_string()))
                    .map(|(_, text, _)| text.clone())
            })
            .or_else(|| self.supplied.visibility.clone());
        match install_visibility(text.as_deref()) {
            Ok(()) => {
                let previous = r.good_visibility.replace(Some(text.clone()));
                if r.visibility.is_none() && text.is_some() && previous != Some(text) {
                    self.log_info(&format!("read {}", r.visibility_path().display()));
                }
            }
            Err(err) => {
                let kept = r.good_visibility.borrow().clone();
                let message = match &kept {
                    Some(_) => format!("{err}; the last declarations that parsed stay in use"),
                    None => format!("{err}; no datasets are declared"),
                };
                self.log_warning(&format!("opentide-lsp: {message}"));
                if r.visibility.is_none() {
                    // The file on disk, not a buffer being typed.
                    self.warn_once(&format!(
                        "{} does not parse: {err}",
                        r.visibility_path().display()
                    ));
                }
                let _ = install_visibility(kept.flatten().as_deref());
            }
        }
    }

    /// Hand the engine the Tide field catalogs hover, completion and
    /// highlighting read for a document of `root`: the ones the models
    /// generate for the root's configuration, else, until they are generated or while its configuration
    /// does not resolve, and outside every root, for the bundled
    /// configuration (#926); until those are generated too, the engine keeps
    /// the catalogs compiled into it. A catalog the engine already has is not
    /// installed again; another one bumps the generation, so analyses read
    /// it. A host that
    /// supplied its own catalogs keeps them
    /// ([`use_host_catalogs`](crate::use_host_catalogs)).
    fn install_field_catalog(&self, root: Option<usize>) {
        if crate::server::host_catalogs() {
            return;
        }
        let own = root
            .and_then(|i| self.roots.get(i))
            .and_then(|r| r.checks.try_borrow_mut().ok()?.field_catalog());
        let Some(catalog) = own.or_else(crate::models::default_catalog_if_ready) else {
            return;
        };
        // What an analysis reads changes when a root's own catalog does, not
        // when the catalog installed is another root's.
        match self.sightings.borrow_mut().saw(root, &catalog) {
            Sighting::Same => {}
            Sighting::First => self.env_epoch.set(self.env_epoch.get() + 1),
            Sighting::Changed => self.touch(),
        }
        let mut installed = self.installed_catalog.borrow_mut();
        if let Some(known) = installed.as_ref() {
            if Arc::ptr_eq(known, &catalog) {
                return;
            }
            if known.fields == catalog.fields && known.deprecations == catalog.deprecations {
                *installed = Some(catalog);
                return;
            }
        }
        match opentide_analysis::install_catalog(&catalog) {
            Ok(()) => {
                // The catalogs carry no `visibility.toml` (it is installed
                // on its own), so installing them declared no dataset: the
                // root's declarations are installed again ([`activate`]).
                // Catalogs generated on a thread arrive whenever they are
                // ready, after the declarations were installed.
                self.active.set(None);
                installed.replace(catalog);
            }
            Err(err) => self.log_warning(&format!(
                "opentide-lsp: the generated field catalog does not install: {err}"
            )),
        }
    }

    /// The workspace the host supplied changed (`opentide/didChangeWorkspace`):
    /// every index holds it, and `visibility.toml` may be the supplied one, so
    /// each root's index is rebuilt and the declared datasets installed again.
    /// Open documents are analysed again and a client that pulls is asked to;
    /// a catalog the client got that changed is announced at the end of the
    /// batch.
    pub(crate) fn supplied_changed(&self) {
        for r in &self.roots {
            r.drop_index();
        }
        self.loose_index.borrow_mut().take();
        self.loose_catalog.dirty.set(true);
        self.reactivate();
        self.mark_all();
    }

    /// The installed catalogs or declared datasets are out of date.
    pub(crate) fn reactivate(&self) {
        self.active.set(None);
        self.touch();
    }

    /// The folders root `index`'s workspace reads that the fixed globs
    /// ([`initialized`](crate::handlers)) do not reach, as the editor spells
    /// them: an object folder `paths.toml` put outside `objects/`, and the
    /// configuration folder layered in from above the root. The workspace
    /// names its folders resolved (symbolic links, macOS's `/var`, a Windows
    /// short name), the root as the editor does: what is under the root is
    /// mapped back to the editor's spelling, and what is not the root's own is
    /// all that is left. The layered folder is the root's parent's, which
    /// needs no workspace to load: a configuration that does not resolve (it
    /// is being mended) does not drop the watch on it, and nor does the last
    /// folders `paths.toml` named, which are kept across it.
    fn extra_folders(&self, index: usize) -> ExtraFolders {
        let Some(root) = self.roots.get(index) else {
            return ExtraFolders::default();
        };
        let (scope, resolved_root) = root.checks.try_borrow().map_or_else(
            |_| (crate::checks::WatchScope::default(), root.path.clone()),
            |checks| (checks.watch_scope(), checks.resolve(&root.path)),
        );
        let own_objects = resolved_root.join("objects");
        let in_editor_spelling = |folder: PathBuf| match folder.strip_prefix(&resolved_root) {
            Ok(under) => root.path.join(under),
            Err(_) => folder,
        };
        let objects = scope
            .object_folders
            .into_iter()
            .filter(|folder| !folder.starts_with(&own_objects))
            .map(in_editor_spelling)
            .collect();
        // The workspace layers the folder above the root it resolved, which a
        // symbolic link, a mapped drive or a short name may spell otherwise
        // than the editor's root: that folder lies outside the root, and stays
        // as the workspace names it.
        let layered = resolved_root
            .parent()
            .map(|parent| parent.join(".opentide").join("configurations"))
            .into_iter()
            .collect();
        let floors = [root.path.parent(), resolved_root.parent()]
            .into_iter()
            .flatten()
            // Not the top of a filesystem or of a drive.
            .filter(|floor| floor.parent().is_some())
            .map(Path::to_path_buf)
            .collect();
        ExtraFolders {
            objects,
            layered,
            floors,
            own_configuration: resolved_root.join(".opentide").join("configurations"),
        }
    }

    fn watch_targets(&self) -> Vec<WatchTarget> {
        let mut targets = Vec::new();
        let all: Vec<ExtraFolders> = (0..self.roots.len())
            .map(|i| self.extra_folders(i))
            .collect();
        for folders in &all {
            let target = |folder: PathBuf, pattern| WatchTarget {
                folder,
                pattern,
                floors: folders.floors.clone(),
            };
            targets.extend(folders.objects.iter().cloned().map(|f| target(f, "**")));
            targets.extend(
                folders
                    .layered
                    .iter()
                    // Another root's own folder is a fixed glob's already.
                    .filter(|layered| !all.iter().any(|other| other.own_configuration == **layered))
                    .cloned()
                    .map(|f| target(f, "**/*.toml")),
            );
        }
        targets.sort();
        targets.dedup();
        targets
    }

    /// Ask the client to watch the folders the loaded workspaces read
    /// ([`watch_targets`](Self::watch_targets)), and to stop watching the
    /// ones they no longer read: asked again when `paths.toml` moves a folder
    /// or a layer comes or goes. Nothing is sent while they are the same.
    pub(crate) fn sync_watchers(&self) {
        use lsp_types::notification::Notification as _;
        if !self.caps.watch_files || !self.client_initialized.get() {
            return;
        }
        let targets = self.watch_targets();
        let mut watched = self.watched.borrow_mut();
        if watched.targets == targets {
            return;
        }
        if let Some(id) = watched.id.take() {
            self.send_request::<lsp_types::request::UnregisterCapability>(
                lsp_types::UnregistrationParams {
                    unregisterations: vec![lsp_types::Unregistration {
                        id,
                        method: lsp_types::notification::DidChangeWatchedFiles::METHOD.into(),
                    }],
                },
            );
        }
        watched.targets.clone_from(&targets);
        if targets.is_empty() {
            return;
        }
        watched.serial += 1;
        let id = format!("opentide-watch-folders-{}", watched.serial);
        watched.id = Some(id.clone());
        let watchers: Vec<lsp_types::FileSystemWatcher> = targets
            .iter()
            .filter_map(|target| self.watch_glob(target))
            .map(|glob_pattern| lsp_types::FileSystemWatcher {
                glob_pattern,
                kind: None,
            })
            .collect();
        if watchers.is_empty() {
            watched.id = None;
            return;
        }
        self.send_request::<lsp_types::request::RegisterCapability>(
            lsp_types::RegistrationParams {
                registrations: vec![lsp_types::Registration {
                    id,
                    method: lsp_types::notification::DidChangeWatchedFiles::METHOD.into(),
                    register_options: serde_json::to_value(
                        lsp_types::DidChangeWatchedFilesRegistrationOptions { watchers },
                    )
                    .ok(),
                }],
            },
        );
    }

    /// `target` as a watcher: a pattern under its folder, or, for a client
    /// that has no such pattern, a glob on the folder's whole path. `None`
    /// when the folder cannot be named by a glob and no folder above it may
    /// stand for it (see [`glob_path`]).
    fn watch_glob(&self, target: &WatchTarget) -> Option<lsp_types::GlobPattern> {
        let folder = target.folder.display().to_string();
        let uri = crate::uri::path_to_uri(&folder)
            .parse::<lsp_types::Uri>()
            .ok();
        if let Some(uri) = uri.filter(|_| self.caps.relative_watch_patterns) {
            return Some(lsp_types::GlobPattern::Relative(
                lsp_types::RelativePattern {
                    base_uri: lsp_types::OneOf::Right(uri),
                    pattern: target.pattern.to_string(),
                },
            ));
        }
        let Some((path, coarse)) = glob_path(&folder, &target.floors) else {
            self.log_warning(&format!(
                "opentide-lsp: {folder} has a brace in its name, which a glob cannot escape, \
                 and no folder above it that is the workspace's to watch: it is not watched"
            ));
            return None;
        };
        if coarse {
            self.log_warning(&format!(
                "opentide-lsp: {folder} has a brace in its name, which a glob cannot escape: \
                 the client is asked to watch {path} and everything under it"
            ));
        }
        let pattern = if coarse { "**" } else { target.pattern };
        Some(lsp_types::GlobPattern::String(format!("{path}/{pattern}")))
    }

    /// The roots whose workspace reads the folder `path` is in, for a
    /// folder [`sync_watchers`](Self::sync_watchers) asks about (not the
    /// root's own `objects/` and `.opentide/configurations/`, which the fixed
    /// globs name); `None` when no root does.
    pub(crate) fn scoped_roots(&self, path: &str) -> Option<Vec<(usize, ScopeKind)>> {
        let mut found = Vec::new();
        for (index, root) in self.roots.iter().enumerate() {
            let folders = self.extra_folders(index);
            let resolved = root.checks.try_borrow().map_or_else(
                |_| PathBuf::from(path),
                |checks| checks.resolve(Path::new(path)),
            );
            let inside = |folder: &PathBuf| {
                Path::new(path).starts_with(folder) || resolved.starts_with(folder)
            };
            if folders.objects.iter().any(inside) {
                found.push((index, ScopeKind::Objects));
            } else if folders.layered.iter().any(inside) {
                found.push((index, ScopeKind::Configuration));
            }
        }
        (!found.is_empty()).then_some(found)
    }

    /// The root whose own `visibility.toml` is the file at `path`.
    pub(crate) fn visibility_root(&self, path: &str) -> Option<usize> {
        self.roots.iter().position(|root| {
            let own = root.visibility_path();
            Path::new(path) == own
                || root
                    .checks
                    .try_borrow()
                    .is_ok_and(|checks| checks.resolve(Path::new(path)) == checks.resolve(&own))
        })
    }

    /// Something an analysis reads changed.
    pub(crate) fn touch(&self) {
        self.generation.set(self.generation.get() + 1);
        self.env_epoch.set(self.env_epoch.get() + 1);
    }

    /// Everything a workspace pull's answer is read from: it is current for
    /// the same pair ([`generation`](Self::generation), then
    /// [`env_epoch`](Self::env_epoch)).
    pub(crate) fn state_key(&self) -> (u64, u64) {
        (self.generation.get(), self.env_epoch.get())
    }

    /// An object file changed (an edit of an open one, a file on disk): the
    /// analyses of the open documents and the workspace's findings are out
    /// of date, the analysis of every other object is not.
    pub(crate) fn touch_object(&self) {
        self.generation.set(self.generation.get() + 1);
    }

    /// An open Tide document changed: the index of its root is rebuilt on
    /// the next request.
    pub(crate) fn invalidate_index(&self, root: Option<usize>) {
        match root.and_then(|i| self.roots.get(i)) {
            Some(r) => r.drop_index(),
            None => {
                self.loose_index.borrow_mut().take();
                self.loose_catalog.dirty.set(true);
            }
        }
        self.touch_object();
    }

    /// A new batch: without a file watcher the disk is read again, and an
    /// analysis is not reused across batches (a configuration file may have
    /// changed under it).
    pub(crate) fn begin_batch(&self) {
        self.batch.set(self.batch.get() + 1);
        if !self.caps.watch_files {
            self.cache.borrow_mut().clear();
        }
    }

    /// The analysis of an open document, run once per document state and
    /// shared by publish, pull, semantic tokens, code actions, symbols,
    /// lenses and links.
    pub(crate) fn analysis(&self, uri: &str) -> Option<Arc<AnalyzeResponse>> {
        let doc = self.docs.get(uri)?;
        let host = self.host(doc.root);
        let generation = self.generation.get();
        if let Some((at, response)) = self.cache.borrow().get(uri)
            && *at == generation
        {
            return Some(Arc::clone(response));
        }
        let request = AnalyzeRequest {
            uri: uri_to_path(uri),
            language: doc.language,
            text: doc.text.clone(),
        };
        // The analysis of a Tide object reads no other object: its own
        // checks are `validate`'s (UC-2.6, #821), and what stays here is
        // the queries it carries. The editor's index is built on the first
        // request that reads it (a hover, a completion, the catalog), not
        // before the first diagnostics (#926).
        let _span = crate::timing::Span::new("analysis of an open document");
        let mut response = {
            let _span = crate::timing::Span::new("analysis: the engine");
            analyze(&host, request)
        };
        match doc.language {
            LanguageId::TideYaml => {
                let _span = crate::timing::Span::new("analysis: the object's findings");
                let found = self.object_findings(uri, doc);
                response.diagnostics.splice(0..0, found);
            }
            LanguageId::Config => {
                response.diagnostics = self.configuration_findings(uri, doc);
            }
            _ => {}
        }
        let response = Arc::new(response);
        self.analyses.set(self.analyses.get() + 1);
        self.cache
            .borrow_mut()
            .insert(uri.to_string(), (generation, Arc::clone(&response)));
        Some(response)
    }

    /// What `validate` reports on an open Tide document, placed in its text:
    /// the root's workspace, with the open buffers (and what a host
    /// supplied) in place of their files, checked for every open Tide
    /// document of the root at once. A document outside every root, or
    /// outside the root's object folders, has none (`validate` checks no such
    /// file either).
    fn object_findings(&self, uri: &str, doc: &Document) -> Vec<opentide_core::Diagnostic> {
        let path = workspace_path(&uri_to_path(uri));
        let files: Vec<PathBuf> = {
            let mut files: Vec<PathBuf> = self
                .docs
                .iter()
                .filter(|(_, d)| d.root == doc.root && d.language == LanguageId::TideYaml)
                .map(|(u, _)| workspace_path(&uri_to_path(u)))
                .collect();
            files.sort();
            files
        };
        let buffers = self.buffers(doc.root);
        let generation = self.generation.get();
        let run = |root: &Path, checks: &mut RootChecks| {
            let found = checks.findings(root, buffers, files, generation);
            (found, checks.resolve(&path), checks.failure.clone())
        };
        let (found, key, failure, root) = match doc.root.and_then(|i| self.roots.get(i)) {
            Some(r) => {
                let (found, key, failure) = run(&r.path, &mut r.checks.borrow_mut());
                (found, key, failure, r.path.clone())
            }
            None => {
                // A document outside every root is checked in the workspace
                // its `objects/` folder names, as `validate` run there would.
                // One with no `objects/` around it is checked in a workspace
                // of its own ([`Self::standalone_findings`]).
                if let Some(root) = objects_root(&path) {
                    let mut loose = self.loose_checks.borrow_mut();
                    let (found, key, failure) = run(&root, loose.entry(root.clone()).or_default());
                    (found, key, failure, root)
                } else {
                    let Some((found, key, failure)) = self.standalone_findings(uri, None) else {
                        return Vec::new();
                    };
                    (found, key, failure, PathBuf::from(VIRTUAL_ROOT))
                }
            }
        };
        if let Some(failure) = failure {
            self.warn_once(&format!(
                "{}: the configuration does not resolve, so objects are not checked: {failure}",
                root.display()
            ));
            return Vec::new();
        }
        found
            .get(&key)
            .map(|findings| {
                findings
                    .iter()
                    .map(|finding| engine_diagnostic(&doc.text, finding))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `validate`'s findings for the Tide documents outside every root that
    /// no `objects/` folder holds (an unsaved buffer, a file opened on its
    /// own), and the key of `uri`'s among them. Each is checked as a file of
    /// its family's folder in the virtual root, with what the host supplied
    /// ([`RootChecks::standalone_path`]), so a reference to an object
    /// neither holds is `invalid_ref`, as in any workspace. `text`, when
    /// given, is `uri`'s text (an `opentide/analyze` request's), in place of
    /// an open document's. `None` when `uri` names no family.
    fn standalone_findings(
        &self,
        uri: &str,
        text: Option<&str>,
    ) -> Option<(Findings, PathBuf, Option<String>)> {
        let root = PathBuf::from(VIRTUAL_ROOT);
        let mut buffers = self.buffers(None);
        let mut standalone: BTreeMap<&str, &str> = self
            .docs
            .iter()
            .filter(|(u, d)| {
                d.root.is_none()
                    && d.language == LanguageId::TideYaml
                    && objects_root(&workspace_path(&uri_to_path(u))).is_none()
            })
            .map(|(u, d)| (u.as_str(), d.text.as_str()))
            .collect();
        if let Some(text) = text {
            standalone.insert(uri, text);
        }
        for u in standalone.keys() {
            buffers.files.remove(&workspace_path(&uri_to_path(u)));
        }
        let mut loose = self.loose_checks.borrow_mut();
        let checks = loose.entry(root.clone()).or_default();
        let placed: Vec<(&str, PathBuf, &str)> = standalone
            .into_iter()
            .filter_map(|(u, text)| {
                let path = checks.standalone_path(&root, &buffers, u, text)?;
                Some((u, path, text))
            })
            .collect();
        let this = placed.iter().find(|(u, _, _)| *u == uri)?.1.clone();
        let mut files: Vec<PathBuf> = Vec::new();
        for (_, path, text) in placed {
            files.push(checks.resolve(&path));
            buffers.files.insert(path, text.to_string());
        }
        // Not cached by generation: an `opentide/analyze` text changes
        // without one. These documents are few, and their workspace small.
        let found = match checks.workspace(&root, buffers) {
            Some(workspace) => Arc::new(validate_files(workspace, &files)),
            None => Findings::default(),
        };
        Some((found, checks.resolve(&this), checks.failure.clone()))
    }

    /// `validate`'s findings on the Tide text of an `opentide/analyze`
    /// request for `uri`, placed in `text`: an open document's, when the
    /// text is the document's; a text outside every root and `objects/`
    /// folder, checked on its own ([`Self::standalone_findings`]); none for
    /// another text of a workspace.
    pub(crate) fn analyze_findings(&self, uri: &str, text: &str) -> Vec<opentide_core::Diagnostic> {
        if let Some(doc) = self.docs.get(uri) {
            return if doc.language == LanguageId::TideYaml && doc.text == text {
                self.object_findings(uri, doc)
            } else {
                Vec::new()
            };
        }
        let path = workspace_path(&uri_to_path(uri));
        if self.root_for(&path.display().to_string()).is_some() || objects_root(&path).is_some() {
            return Vec::new();
        }
        let Some((found, key, failure)) = self.standalone_findings(uri, Some(text)) else {
            return Vec::new();
        };
        if failure.is_some() {
            return Vec::new();
        }
        found
            .get(&key)
            .map(|findings| {
                findings
                    .iter()
                    .map(|finding| engine_diagnostic(text, finding))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What `validate` reports on a closed object file of `root`, placed in
    /// `text` (a client that pulls the workspace's diagnostics).
    pub(crate) fn closed_findings(
        &self,
        root: usize,
        path: &str,
        text: &str,
    ) -> Vec<opentide_core::Diagnostic> {
        let Some(r) = self.roots.get(root) else {
            return Vec::new();
        };
        let buffers = self.buffers(Some(root));
        let mut checks = r.checks.borrow_mut();
        let _span = crate::timing::Span::new("closed findings (every object, once per generation)");
        let found = checks.all_findings(&r.path, buffers, self.generation.get());
        let key = checks.resolve(Path::new(path));
        drop(checks);
        found
            .get(&key)
            .map(|findings| {
                findings
                    .iter()
                    .map(|finding| engine_diagnostic(text, finding))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many object files on disk the editor's index holds an entry
    /// for, over every root: none until a request reads the index.
    #[cfg(all(debug_assertions, not(fuzzing)))]
    pub(crate) fn editor_indexed(&self) -> usize {
        self.roots
            .iter()
            .map(|r| {
                r.disk
                    .borrow()
                    .files
                    .values()
                    .filter(|file| file.indexed.get().is_some())
                    .count()
            })
            .sum()
    }

    /// How many object files on disk the editor's index parsed itself,
    /// over every root, rather than reading the workspace's parse (#926).
    #[cfg(all(debug_assertions, not(fuzzing)))]
    pub(crate) fn editor_parsed(&self) -> usize {
        self.roots
            .iter()
            .map(|r| r.disk.borrow().parsed_here.load(Ordering::Relaxed))
            .sum()
    }

    /// What the roots' workspaces read, parsed and resolved, summed.
    #[cfg(all(debug_assertions, not(fuzzing)))]
    pub(crate) fn workspace_stats(&self) -> opentide_workspace::Stats {
        let mut sum = opentide_workspace::Stats::default();
        for r in &self.roots {
            if let Some(stats) = r.checks.borrow().stats() {
                sum.file_reads += stats.file_reads;
                sum.parses += stats.parses;
                sum.config_resolutions += stats.config_resolutions;
                sum.config_files_read += stats.config_files_read;
            }
        }
        sum
    }

    /// The files the editor and the host hold for a root's workspace: the
    /// open documents of the root, and every file a host with no filesystem
    /// supplied.
    fn buffers(&self, root: Option<usize>) -> Buffers {
        let mut files: BTreeMap<PathBuf, String> = self
            .supplied
            .files
            .values()
            .filter(|(path, _, _)| !path.starts_with("opentide-object:"))
            .map(|(path, text, _)| (workspace_path(path), text.clone()))
            .collect();
        for (uri, d) in &self.docs {
            if d.root == root && matches!(d.language, LanguageId::TideYaml | LanguageId::Config) {
                files.insert(workspace_path(&uri_to_path(uri)), d.text.clone());
            }
        }
        // Objects the host knows by their metadata alone, unless a file
        // holds them: the workspace reads each as a file of its family.
        // Only a host can supply one: the index is not read for none.
        let supplies_stubs = self
            .supplied
            .files
            .values()
            .any(|(path, _, _)| path.starts_with("opentide-object:"));
        let index = if supplies_stubs {
            self.host(root).indexed_objects().unwrap_or_default()
        } else {
            Arc::default()
        };
        let mut stubs: Vec<Stub> = index
            .iter()
            .filter(|o| o.path.starts_with("opentide-object:"))
            .map(|o| Stub {
                family: o.object_type.clone(),
                uuid: o.uuid.clone(),
                schema: o.schema.clone(),
                name: o.name.clone(),
            })
            .collect();
        stubs.sort_by(|a, b| a.uuid.cmp(&b.uuid));
        Buffers { files, stubs }
    }

    /// What opentide-schema's configuration checks report on an open
    /// configuration buffer, placed on its keys.
    fn configuration_findings(&self, uri: &str, doc: &Document) -> Vec<opentide_core::Diagnostic> {
        let path = uri_to_path(uri);
        let open: Vec<(String, String)> = self
            .docs
            .iter()
            .filter(|(u, d)| u.as_str() != uri && d.language == LanguageId::Config)
            .map(|(u, d)| (uri_to_path(u), d.text.clone()))
            .collect();
        let read = |file: &Path| -> Option<String> {
            let key = path_key(&file.display().to_string());
            std::fs::read(file)
                .ok()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .or_else(|| {
                    self.supplied
                        .files
                        .get(&key)
                        .map(|(_, text, _)| text.clone())
                })
                .map(|text| opentide_core::strip_bom(&text).to_string())
        };
        let is_dir = |dir: &Path| -> bool {
            dir.is_dir() || {
                let prefix = format!("{}/", path_key(&dir.display().to_string()));
                self.supplied
                    .files
                    .keys()
                    .any(|key| key.starts_with(&prefix))
            }
        };
        let issues = configuration_issues(&path, &doc.text, &open, &read, &is_dir);
        place_configuration_issues(&doc.text, issues)
    }

    /// The deepest root whose folder holds `path`, if one does: unlike
    /// [`root_for`](Self::root_for), no fallback to the first.
    pub(crate) fn owning_root(&self, path: &str) -> Option<usize> {
        let path = Path::new(path);
        self.roots
            .iter()
            .enumerate()
            .filter(|(_, r)| path.starts_with(&r.path))
            .max_by_key(|(_, r)| r.path.components().count())
            .map(|(i, _)| i)
    }

    /// The root a file belongs to: the deepest workspace folder holding it,
    /// else a root found around it, else the first folder.
    pub(crate) fn root_for(&self, path: &str) -> Option<usize> {
        let path = Path::new(path);
        let best = self
            .roots
            .iter()
            .enumerate()
            .filter(|(_, r)| path.starts_with(&r.path))
            .max_by_key(|(_, r)| r.path.components().count())
            .map(|(i, _)| i);
        best.or(if self.roots.is_empty() { None } else { Some(0) })
    }

    /// Make sure a root exists for a document opened outside every
    /// workspace folder: its `.opentide/` or `objects/` ancestor
    /// ([`workspace_root`]).
    pub(crate) fn discover_root(&mut self, path: &str) {
        if self.add_found_root(path) {
            self.reassign_roots();
        }
    }

    /// Add the root found around a document outside every root, if there is
    /// one. Whether a root was added.
    fn add_found_root(&mut self, path: &str) -> bool {
        let inside = self
            .roots
            .iter()
            .any(|r| Path::new(path).starts_with(&r.path));
        if inside || !path.starts_with(['/', '\\']) && path.as_bytes().get(1) != Some(&b':') {
            return false;
        }
        match workspace_root(Path::new(path)) {
            Some(found) => {
                self.roots.push(Root::new(found));
                true
            }
            None => false,
        }
    }

    /// The workspace folders changed: each document's root is found again.
    pub(crate) fn set_folders(&mut self, folders: Vec<PathBuf>) {
        let mut roots: Vec<Root> = Vec::new();
        let mut old: Vec<(bool, Root)> = std::mem::take(&mut self.roots)
            .into_iter()
            .enumerate()
            .map(|(i, r)| (i < self.folders, r))
            .collect();
        for path in &folders {
            match old.iter().position(|(_, r)| &r.path == path) {
                Some(i) => roots.push(old.remove(i).1),
                None => roots.push(Root::new(path.clone())),
            }
        }
        self.folders = roots.len();
        // Roots found around documents stay while no folder holds them; a
        // folder that was removed goes.
        roots.extend(
            old.into_iter()
                .filter(|(folder, r)| !folder && !folders.iter().any(|f| r.path.starts_with(f)))
                .map(|(_, r)| r),
        );
        self.roots = roots;
        // A document of a folder that went is outside every folder now: its
        // root is found around it, as when it is opened there.
        let mut paths: Vec<String> = self.docs.keys().map(|uri| uri_to_path(uri)).collect();
        paths.sort();
        for path in paths {
            self.add_found_root(&path);
        }
        self.reassign_roots();
        // Each folder's workspace starts loading now, while the editor's
        // index is read; a host that supplies the files has them read with
        // the workspace instead.
        #[cfg(not(any(target_family = "wasm", fuzzing)))]
        if self.supplied.files.is_empty() {
            for r in &self.roots[..self.folders] {
                r.checks.borrow_mut().prefetch(&r.path);
            }
        }
    }

    fn reassign_roots(&mut self) {
        let assigned: Vec<(String, Option<usize>)> = self
            .docs
            .keys()
            .map(|uri| (uri.clone(), self.root_for(&uri_to_path(uri))))
            .collect();
        for (uri, root) in assigned {
            if let Some(doc) = self.docs.get_mut(&uri) {
                doc.root = root;
            }
        }
        for r in &self.roots {
            r.drop_index();
        }
        self.loose_index.borrow_mut().take();
        self.loose_catalog.dirty.set(true);
        self.reactivate();
        if !self.docs.is_empty() {
            self.mark_all();
        }
    }

    /// A root's object files on disk, as last read.
    pub(crate) fn closed_objects(&self, root: usize) -> Vec<(String, String)> {
        let Some(r) = self.roots.get(root) else {
            return Vec::new();
        };
        let parses = || {
            r.checks
                .try_borrow()
                .map(|checks| checks.parses_under(&r.path))
                .unwrap_or_default()
        };
        r.disk
            .borrow()
            .index_pending(&parses)
            .values()
            .filter_map(|file| Some((file.entry()?.path.clone(), file.text.clone())))
            .collect()
    }

    /// What the engine's analysis finds in the object file at `path` of
    /// `root`, which `text` is the text of: made once for each file text and
    /// [`env_epoch`](Self::env_epoch), then read from the file's entry (a
    /// workspace pull asks for every closed file every two seconds).
    pub(crate) fn closed_analysis(
        &self,
        root: usize,
        path: &str,
        text: &str,
        host: &dyn opentide_analysis::WorkspaceHost,
    ) -> Arc<Vec<opentide_core::Diagnostic>> {
        let epoch = self.env_epoch.get();
        let key = path_key(path);
        // A client that does not watch files is not told what changed on
        // disk (the configuration, the Elastic tenants an analysis reads):
        // nothing is kept for it.
        let keeps = self.caps.watch_files;
        let cached = self.roots.get(root).filter(|_| keeps).and_then(|r| {
            r.disk
                .borrow()
                .files
                .get(&key)
                .filter(|file| file.text == text)
                .and_then(|file| file.cached_analysis(epoch))
        });
        if let Some(found) = cached {
            return found;
        }
        self.closed_analyses.set(self.closed_analyses.get() + 1);
        let found = Arc::new(
            opentide_analysis::analyze(
                host,
                opentide_analysis::AnalyzeRequest {
                    uri: path.to_string(),
                    language: LanguageId::TideYaml,
                    text: text.to_string(),
                },
            )
            .diagnostics,
        );
        if keeps
            && let Some(r) = self.roots.get(root)
            && let Some(file) = r.disk.borrow().files.get(&key).filter(|f| f.text == text)
        {
            file.keep_analysis(epoch, Arc::clone(&found));
        }
        found
    }

    /// The root holding an object file, by its path.
    pub(crate) fn object_root(&self, path: &str) -> Option<usize> {
        self.roots.iter().position(|r| r.holds_object(path))
    }

    /// The root whose `objects/` holds the folder at `path` ([`Root::holds_folder`]).
    pub(crate) fn folder_root(&self, path: &str) -> Option<usize> {
        self.roots.iter().position(|r| r.holds_folder(path))
    }

    /// `.opentide/configurations/platforms/elastic.toml` of a root, from the
    /// editor when it is open, else from disk: its tenants decide the stack
    /// Elastic queries are checked against.
    pub(crate) fn elastic_configuration(&self, root: Option<usize>) -> Option<(String, String)> {
        let r = self.roots.get(root?)?;
        let path = r
            .path
            .join(opentide_analysis::ELASTIC_CONFIGURATION)
            .display()
            .to_string();
        let key = path_key(&path);
        if let Some((_, doc)) = self
            .docs
            .iter()
            .find(|(uri, _)| path_key(&uri_to_path(uri)) == key)
        {
            return Some((path, doc.text.clone()));
        }
        std::fs::read_to_string(&path).ok().map(|text| (path, text))
    }

    /// The language of a document, or `None` for a document this server does
    /// not read. A TOML file under `.opentide/configurations/` is
    /// `opentide-config` whatever id the client reports; any other `.toml`
    /// (`Cargo.toml`) is not read, and `opentide-config` is only those files.
    pub(crate) fn language_for(&self, uri: &str, reported: Option<&str>) -> Option<LanguageId> {
        let path = uri_to_path(uri);
        if is_configuration_path(&path.replace('\\', "/")) {
            return Some(LanguageId::Config);
        }
        match reported.and_then(LanguageId::parse) {
            Some(LanguageId::Config) => return None,
            Some(id) => return Some(id),
            None => {}
        }
        if path.to_ascii_lowercase().ends_with(".toml") {
            return None;
        }
        Some(
            uri.rsplit_once('.')
                .and_then(|(_, ext)| LanguageId::from_extension(ext))
                .unwrap_or(LanguageId::TideYaml),
        )
    }

    /// Whether a document that [`language_for`](Self::language_for) calls Tide
    /// YAML is one. Editors send any YAML as `yaml` (CI workflows,
    /// `.pre-commit-config.yaml`): only an `opentide-yaml` id, a file under an
    /// `objects/` folder, or a document that names a Tide schema
    /// (`schema: rule::1.0` under `metadata`) is analysed. The last case keeps
    /// object folders that `paths.toml` moves elsewhere.
    pub(crate) fn reads_as_tide(&self, uri: &str, reported: Option<&str>, text: &str) -> bool {
        if matches!(reported, Some("opentide-yaml" | "tide" | "tide-yaml")) {
            return true;
        }
        let path = uri_to_path(uri).replace('\\', "/");
        if path.split('/').any(|segment| segment == "objects") {
            return true;
        }
        names_tide_schema(text)
    }

    /// The document's diagnostics changed: publish them with the batch.
    pub(crate) fn mark(&self, uri: &str) {
        self.pending.borrow_mut().insert(uri.to_string());
    }

    /// Every open document's diagnostics may have changed, through what the
    /// server reads beyond them (`visibility.toml`, configuration, a file on
    /// disk, a root): a client that pulls is told to pull again, and its
    /// semantic tokens, inlay hints and lenses to refresh.
    pub(crate) fn mark_all(&self) {
        self.everything.set(true);
    }

    /// Every open Tide document's diagnostics may have changed through an
    /// edit of another (an object they reference). A client
    /// that pulls already pulls them again: LSP has it do so after an edit
    /// when diagnostics have `interFileDependencies`.
    pub(crate) fn mark_open(&self) {
        self.open_documents.set(true);
    }

    /// The catalog state of a root (`None`: outside every root).
    fn catalog_state(&self, root: Option<usize>) -> Option<&CatalogState> {
        match root {
            Some(i) => self.roots.get(i).map(|r| &r.catalog),
            None => Some(&self.loose_catalog),
        }
    }

    /// The roots `opentide/catalog` reports: every root, or the documents
    /// outside them when there is none.
    pub(crate) fn catalog_roots(&self) -> Vec<Option<usize>> {
        if self.roots.is_empty() {
            vec![None]
        } else {
            (0..self.roots.len()).map(Some).collect()
        }
    }

    /// A root's index for `opentide/catalog`, remembered as what the client
    /// now knows.
    pub(crate) fn catalog_index(&self, root: Option<usize>) -> Arc<[IndexedObject]> {
        let index = opentide_analysis::workspace_index(&self.host(root));
        if let Some(state) = self.catalog_state(root) {
            state.dirty.set(false);
        }
        self.catalog_sent
            .borrow_mut()
            .digests
            .insert(self.catalog_key(root), catalog_digest(&index));
        index
    }

    /// The client asked for every root's catalog: a root that appears is
    /// announced from now on, as one that goes is.
    pub(crate) fn catalog_every_root(&self) {
        self.catalog_sent.borrow_mut().every_root = true;
    }

    /// The `root` of `opentide/catalog` and `opentide/catalogChanged`: the
    /// root's URI, or `null` outside every root.
    pub(crate) fn catalog_root_uri(&self, root: Option<usize>) -> serde_json::Value {
        root.and_then(|i| self.roots.get(i))
            .map_or(serde_json::Value::Null, |r| {
                serde_json::Value::String(crate::uri::path_to_uri(&r.path.display().to_string()))
            })
    }

    /// The key of a root in [`CatalogSent`]: its URI, or `""` outside every
    /// root.
    fn catalog_key(&self, root: Option<usize>) -> String {
        match self.catalog_root_uri(root) {
            serde_json::Value::String(uri) => uri,
            _ => String::new(),
        }
    }

    /// `opentide/catalogChanged {root}` at the end of a batch (#198), once
    /// the client has asked for a catalog:
    ///
    /// - for each root it was told of whose catalog changed: a file saved,
    ///   created or deleted, or an open object's UUID, name or references
    ///   edited;
    /// - for each root it was told of that is gone (a workspace folder
    ///   removed, or the documents outside every root once a root is found);
    /// - for each root that appeared, once it has asked for every root (a
    ///   folder added, or a root found around a document opened outside
    ///   every folder). From then on that root is followed too.
    fn flush_catalog_changes(&self) {
        use crate::handlers::custom::{CatalogChanged, CatalogChangedParams};
        let mut sent = self.catalog_sent.borrow_mut();
        if sent.digests.is_empty() && !sent.every_root {
            return;
        }
        let roots: Vec<(Option<usize>, String)> = self
            .catalog_roots()
            .into_iter()
            .map(|root| (root, self.catalog_key(root)))
            .collect();
        let uri = |key: &str| match key {
            "" => serde_json::Value::Null,
            uri => serde_json::Value::String(uri.to_string()),
        };
        let mut changed: Vec<String> = Vec::new();
        let gone: Vec<String> = sent
            .digests
            .keys()
            .filter(|key| !roots.iter().any(|(_, k)| k == *key))
            .cloned()
            .collect();
        for key in gone {
            sent.digests.remove(&key);
            changed.push(key);
        }
        for (root, key) in roots {
            let Some(state) = self.catalog_state(root) else {
                continue;
            };
            let known = sent.digests.get(&key).copied();
            if known.is_none() && !sent.every_root {
                continue;
            }
            if !state.dirty.replace(false) && known.is_some() {
                continue;
            }
            let index = opentide_analysis::workspace_index(&self.host(root));
            let digest = catalog_digest(&index);
            // `host` may have read the disk and dropped the index again.
            state.dirty.set(false);
            if known != Some(digest) {
                sent.digests.insert(key.clone(), digest);
                changed.push(key);
            }
        }
        drop(sent);
        for key in changed {
            self.notify::<CatalogChanged>(CatalogChangedParams { root: uri(&key) });
        }
    }

    /// Publish what the batch changed, each document once. A client that
    /// pulls is asked to pull again instead, and one that can refresh its
    /// semantic tokens, inlay hints and lenses is asked to after a change
    /// that reaches beyond one document. A catalog that changed is announced
    /// first.
    pub(crate) fn flush_publishes(&mut self) {
        self.flush_catalog_changes();
        let everything = self.everything.replace(false);
        let tide_documents = self.open_documents.replace(false);
        let pending = std::mem::take(&mut *self.pending.borrow_mut());
        if self.caps.pull_diagnostics {
            if everything {
                self.send_request::<lsp_types::request::WorkspaceDiagnosticRefresh>(());
            }
        } else {
            let mut uris = pending;
            if everything {
                uris.extend(self.docs.keys().cloned());
            } else if tide_documents {
                // Only a Tide object reads the others.
                uris.extend(
                    self.docs
                        .iter()
                        .filter(|(_, doc)| doc.language == LanguageId::TideYaml)
                        .map(|(uri, _)| uri.clone()),
                );
            }
            for uri in uris {
                let diagnostics = match self.docs.get(&uri) {
                    Some(_) => crate::handlers::diagnostics_for(self, &uri),
                    None => Vec::new(),
                };
                let version = self
                    .docs
                    .get(&uri)
                    .and_then(|doc| doc.version)
                    .filter(|_| self.caps.diagnostic_version);
                let Ok(uri) = uri.parse::<lsp_types::Uri>() else {
                    continue;
                };
                self.notify::<lsp_types::notification::PublishDiagnostics>(
                    lsp_types::PublishDiagnosticsParams {
                        uri,
                        diagnostics,
                        version,
                    },
                );
            }
        }
        if everything {
            if self.caps.semantic_tokens_refresh {
                self.send_request::<lsp_types::request::SemanticTokensRefresh>(());
            }
            if self.caps.inlay_hint_refresh {
                self.send_request::<lsp_types::request::InlayHintRefreshRequest>(());
            }
            if self.caps.code_lens_refresh {
                self.send_request::<lsp_types::request::CodeLensRefresh>(());
            }
        }
    }

    pub(crate) fn discard_publishes(&mut self) {
        self.everything.set(false);
        self.open_documents.set(false);
        self.pending.borrow_mut().clear();
    }

    pub(crate) fn take_outbox(&mut self) -> Vec<Message> {
        std::mem::take(&mut *self.outbox.borrow_mut())
    }

    pub(crate) fn notify<N: lsp_types::notification::Notification>(&self, params: N::Params) {
        self.outbox
            .borrow_mut()
            .push(Message::Notification(Notification::new(
                N::METHOD.to_string(),
                params,
            )));
    }

    /// Send the client a request; its answer is matched by id
    /// ([`response`](Self::response)).
    pub(crate) fn send_request<R: lsp_types::request::Request>(&self, params: R::Params) {
        let request =
            self.requests
                .borrow_mut()
                .outgoing
                .register(R::METHOD.to_string(), params, R::METHOD);
        self.outbox.borrow_mut().push(Message::Request(request));
    }

    /// The client answered a request the server sent. A failure is logged;
    /// nothing waits on an answer.
    pub(crate) fn response(&self, response: Response) {
        let method = self
            .requests
            .borrow_mut()
            .outgoing
            .complete(response.id.clone());
        match (method, response.response_result.err()) {
            (Some(method), Some(error)) => self.log_warning(&format!(
                "the client failed {method}: {} ({})",
                error.message, error.code
            )),
            (None, _) => eprintln!(
                "opentide-lsp: a response to a request the server did not send ({:?})",
                response.id
            ),
            _ => {}
        }
    }

    fn log(&self, typ: lsp_types::MessageType, message: &str) {
        if self.initialized {
            self.notify::<lsp_types::notification::LogMessage>(lsp_types::LogMessageParams {
                typ,
                message: message.to_string(),
            });
        } else {
            eprintln!("opentide-lsp: {message}");
        }
    }

    pub(crate) fn log_info(&self, message: &str) {
        self.log(lsp_types::MessageType::INFO, message);
    }

    pub(crate) fn log_warning(&self, message: &str) {
        self.log(lsp_types::MessageType::WARNING, message);
    }

    /// Tell the user once per session that a file of theirs is broken; the
    /// log has the rest.
    pub(crate) fn warn_once(&self, message: &str) {
        if !self.initialized || self.warned.replace(true) {
            return;
        }
        self.notify::<lsp_types::notification::ShowMessage>(lsp_types::ShowMessageParams {
            typ: lsp_types::MessageType::WARNING,
            message: format!("opentide: {message}"),
        });
    }

    /// Whether `uri` is the `visibility.toml` of a root.
    pub(crate) fn is_visibility(uri: &str) -> bool {
        uri_to_path(uri)
            .replace('\\', "/")
            .ends_with(VISIBILITY_CONFIGURATION)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Arc, CatalogSightings, DiskObjects, HashMap, Ordering, Session, Sighting, glob_path,
        path_key, root_key,
    };

    #[test]
    fn a_folder_is_a_glob_that_matches_it_and_nothing_else() {
        let floors = [std::path::PathBuf::from("/w")];
        assert_eq!(
            glob_path("/w/det [prod]", &floors),
            Some(("/w/det [[]prod]".into(), false))
        );
        assert_eq!(
            glob_path("/w/a*b?c", &floors),
            Some(("/w/a[*]b[?]c".into(), false))
        );
        assert_eq!(
            glob_path("C:\\w\\x\\", &floors),
            Some(("C:/w/x".into(), false))
        );
        // A brace cannot be escaped: the folder above it, if that is the
        // workspace's to watch.
        assert_eq!(
            glob_path("/w/{team}/rules", &floors),
            Some(("/w".into(), true))
        );
        assert_eq!(glob_path("/w/a}", &floors), Some(("/w".into(), true)));
        // Never the filesystem root, or anything above the floors.
        assert_eq!(glob_path("/{team}/rules", &floors), None);
        assert_eq!(glob_path("/x/{team}/rules", &floors), None);
        assert_eq!(glob_path("C:\\{team}\\rules", &floors), None);
        assert_eq!(glob_path("/w/{team}", &[]), None);
    }

    #[test]
    fn switching_between_roots_is_not_a_catalog_that_changed() {
        let catalog = |text: &str| {
            Arc::new(opentide_analysis::Catalog {
                fields: Some(text.to_string()),
                ..opentide_analysis::Catalog::default()
            })
        };
        let (a, b) = (catalog("a"), catalog("b"));
        let mut seen = CatalogSightings::default();
        assert_eq!(seen.saw(Some(0), &a), Sighting::First);
        assert_eq!(seen.saw(Some(1), &b), Sighting::First);
        // Requests alternate between the roots: each installs its own
        // catalog, which is the one it had.
        for _ in 0..3 {
            assert_eq!(seen.saw(Some(0), &a), Sighting::Same);
            assert_eq!(seen.saw(Some(1), &b), Sighting::Same);
        }
        // The same text in another allocation is the same catalog.
        assert_eq!(seen.saw(Some(0), &catalog("a")), Sighting::Same);
        // A root's own catalog arriving, or being generated again, changes it
        // for that root alone.
        assert_eq!(seen.saw(Some(0), &catalog("a2")), Sighting::Changed);
        assert_eq!(seen.saw(Some(1), &b), Sighting::Same);
        // A document outside every root has its own.
        assert_eq!(seen.saw(None, &a), Sighting::First);
        assert_eq!(seen.saw(None, &a), Sighting::Same);
    }

    /// #914: reading a root's object files indexes none of them; the first
    /// request for the index indexes each, as `index_object` does, from the
    /// workspace's parse of the file where it has one of the same text
    /// (#926).
    #[test]
    fn object_files_are_indexed_when_the_index_is_read() {
        let root = std::env::temp_dir().join(format!("opentide-lsp-disk-{}", std::process::id()));
        // Joined one name at a time: the walk spells the path with the
        // platform's separator.
        let rules = root.join("objects").join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        let rule = "name: R\nmetadata:\n  uuid: u-1\n  schema: rule::1.0\n";
        std::fs::write(rules.join("r.yaml"), rule).unwrap();
        std::fs::write(rules.join("not-an-object.yaml"), "- a\n").unwrap();
        let mut disk = DiskObjects::default();
        let changed = disk.refresh(&root);
        assert_eq!(changed.len(), 2, "{changed:?}");
        assert!(disk.files.values().all(|file| file.indexed.get().is_none()));
        let path = rules.join("r.yaml").display().to_string();
        // The workspace parsed the rule: the index reads that parse, and
        // parses only the other file itself.
        let parses = || {
            HashMap::from([(
                path_key(&path),
                Arc::new(opentide_schema::node::load(rule).unwrap()),
            )])
        };
        let indexed: Vec<_> = disk
            .index_pending(&parses)
            .values()
            .map(|file| file.entry().cloned())
            .collect();
        assert_eq!(disk.parsed_here.load(Ordering::Relaxed), 1);
        assert!(disk.files.values().all(|file| file.indexed.get().is_some()));
        let expected = opentide_analysis::index_object(&path, rule).unwrap();
        let found: Vec<_> = indexed.into_iter().flatten().collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].uuid, expected.uuid);
        assert_eq!(found[0].path, expected.path);
        assert_eq!(found[0].refs, expected.refs);
        // Read again unchanged: nothing changed, the entries are kept.
        assert!(disk.refresh(&root).is_empty());
        assert!(disk.files.values().all(|file| file.indexed.get().is_some()));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The field catalogs the warm-up thread generates arrive whenever they
    /// are ready; installing them declares no dataset, so the declared ones
    /// are installed again after them: a query is checked against
    /// `visibility.toml` whether the catalogs arrived before the first check
    /// or between two.
    #[test]
    fn catalogs_that_arrive_late_keep_the_declared_datasets() {
        let mut session = Session::default();
        session.supplied.visibility = Some(
            "[[logsources]]\nname = \"NTANetAnalytics\"\ndescription = \"x\"\nsystem = \"sentinel\"\n"
                .to_owned(),
        );
        // Ready now: the first check installs them.
        crate::models::default_catalog();
        let codes = |session: &Session| -> Vec<String> {
            let request = opentide_analysis::AnalyzeRequest {
                uri: "/q.kql".to_owned(),
                language: opentide_core::LanguageId::Kql,
                text: "NTAIpDetails | take 1".to_owned(),
            };
            super::analyze(&session.host(None), request)
                .diagnostics
                .into_iter()
                .map(|d| d.code)
                .collect()
        };
        assert_eq!(codes(&session), ["kql_table_not_declared"]);
        // As if they arrived only now, once the declarations were installed.
        session.installed_catalog.borrow_mut().take();
        assert_eq!(codes(&session), ["kql_table_not_declared"]);
    }

    #[test]
    fn a_root_is_the_same_root_with_or_without_a_trailing_separator() {
        assert_eq!(root_key("/w/"), "/w");
        assert_eq!(root_key("/w"), "/w");
        assert_eq!(root_key(r"C:\w\"), "c:/w");
        assert_eq!(root_key("/"), "/");
        assert_eq!(root_key("c:/"), "c:/");
        assert_eq!(root_key("C:"), "c:/");
        assert_eq!(root_key(r"c:\"), "c:/");
    }
}
