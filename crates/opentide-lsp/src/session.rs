//! What the server knows between messages: the open documents, the
//! workspace roots and their files on disk, the client's capabilities, the
//! analyses already run, and the messages waiting to be written.

use crate::server::{collect_objects, install_workspace_catalog_from, workspace_root};
use crate::uri::uri_to_path;
use lsp_server::{Message, Notification, ReqQueue, Response};
use opentide_analysis::{
    AnalyzeRequest, AnalyzeResponse, IndexedObject, VISIBILITY_CONFIGURATION, WorkspaceHost,
    analyze, install_visibility, is_configuration_path,
};
use opentide_core::LanguageId;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
pub(crate) struct ClientCaps {
    /// The client watches files for the server (`didChangeWatchedFiles`).
    pub watch_files: bool,
    /// The client pulls diagnostics and can be told to pull again: the server
    /// then publishes none (#185 P0.8).
    pub pull_diagnostics: bool,
    /// Hover and completion documentation as plain text, not Markdown.
    pub plaintext_hover: bool,
    pub plaintext_completion: bool,
    /// A workspace edit may create a file (`documentChanges` with the
    /// `create` resource operation).
    pub create_files: bool,
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
    good_visibility: RefCell<Option<Option<String>>>,
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
        if changed {
            self.drop_index();
        }
        changed
    }

    /// Read one object file again (a watcher event, or the editor closed
    /// it), or forget it when it is gone.
    pub(crate) fn refresh_object(&self, path: &str) {
        self.disk.borrow_mut().refresh_path(path);
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
        if in_metadata {
            if let Some(value) = line.trim_start().strip_prefix("schema:") {
                let value = value.trim().trim_matches(['"', '\'']);
                if ["rule::", "threat::", "objective::"]
                    .iter()
                    .any(|family| value.starts_with(family))
                {
                    return true;
                }
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
/// separators, so `/w/` (a client that sends its folder with a slash, as
/// Emacs eglot does) and `/w` are one root. A bare `/` and a drive root
/// (`c:/`) keep theirs.
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

/// Object files under a root: [`path_key`] → (text, index entry).
#[derive(Default)]
struct DiskObjects {
    loaded: bool,
    files: BTreeMap<String, (String, Option<IndexedObject>)>,
}

impl DiskObjects {
    /// Read every object file again; re-index only those whose text changed.
    /// Whether anything changed.
    fn refresh(&mut self, root: &Path) -> bool {
        let found: BTreeMap<String, (String, String)> = collect_objects(root)
            .into_iter()
            .map(|(path, text)| (path_key(&path), (path, text)))
            .collect();
        let mut changed = !self.loaded || found.len() != self.files.len();
        self.loaded = true;
        self.files.retain(|path, _| found.contains_key(path));
        for (key, (path, text)) in found {
            match self.files.get(&key) {
                Some((known, _)) if *known == text => {}
                _ => {
                    let indexed = opentide_analysis::index_object(&path, &text);
                    self.files.insert(key, (text, indexed));
                    changed = true;
                }
            }
        }
        changed
    }

    fn refresh_path(&mut self, path: &str) {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let text = opentide_core::strip_bom(&text).to_string();
                let indexed = opentide_analysis::index_object(path, &text);
                self.files.insert(path_key(path), (text, indexed));
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
            let indexed = opentide_analysis::index_object(&path, &text);
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
    cache: RefCell<HashMap<String, (u64, Arc<AnalyzeResponse>)>>,
    /// How many analyses ran, for the tests (`opentide/__stats`).
    pub analyses: Cell<u64>,
    batch: Cell<u64>,
    /// The root whose catalogs and declared datasets the engine has
    /// installed; `None` until the first request, and again after they
    /// change.
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
}

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
            if let Some((text, _)) = root.disk.borrow().files.get(&key) {
                return Some(text.clone());
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
        if let Some((path, text)) = session.elastic_configuration(self.root) {
            if !files
                .iter()
                .any(|(open, _)| path_key(open) == path_key(&path))
            {
                files.push((path, text));
            }
        }
        files
    }

    fn indexed_objects(&self) -> Option<Arc<[IndexedObject]>> {
        let session = self.session;
        let slot = match self.root {
            Some(i) => &session.roots[i].index,
            None => &session.loose_index,
        };
        if let Some(index) = slot.borrow().as_ref() {
            return Some(Arc::clone(index));
        }
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
            Some(i) => session.roots[i]
                .disk
                .borrow()
                .files
                .iter()
                .filter(|(path, _)| !open.contains_key(*path))
                .filter_map(|(_, (_, indexed))| indexed.clone())
                .collect(),
            None => Vec::new(),
        };
        index.extend(
            open.values()
                .filter_map(|(path, text)| opentide_analysis::index_object(path, text)),
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
        let index: Arc<[IndexedObject]> = index.into();
        *slot.borrow_mut() = Some(Arc::clone(&index));
        Some(index)
    }
}

impl Session {
    /// The view of the workspace for a document of `root`: its files on
    /// disk are read again when no watcher reports changes, and its
    /// catalogs and declared datasets are installed in the engine.
    pub(crate) fn host(&self, root: Option<usize>) -> SessionHost<'_> {
        if let Some(r) = root.and_then(|i| self.roots.get(i)) {
            if r.checked.get() != self.batch.get() {
                r.checked.set(self.batch.get());
                let mut disk = r.disk.borrow_mut();
                if (!disk.loaded || !self.caps.watch_files) && disk.refresh(&r.path) {
                    r.drop_index();
                    self.touch();
                }
            }
        }
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
    fn activate(&self, root: Option<usize>) {
        if self.active.get() == Some(root) {
            return;
        }
        self.active.set(Some(root));
        let r = root.and_then(|i| self.roots.get(i));
        if let Err(err) = install_workspace_catalog_from(r.map(|r| r.path.as_path())) {
            self.log_warning(&err);
            self.warn_once(&err);
        }
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

    /// Something an analysis reads changed.
    pub(crate) fn touch(&self) {
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
        self.touch();
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
        if let Some((at, response)) = self.cache.borrow().get(uri) {
            if *at == generation {
                return Some(Arc::clone(response));
            }
        }
        let response = Arc::new(analyze(
            &host,
            AnalyzeRequest {
                uri: uri_to_path(uri),
                language: doc.language,
                text: doc.text.clone(),
            },
        ));
        self.analyses.set(self.analyses.get() + 1);
        self.cache
            .borrow_mut()
            .insert(uri.to_string(), (generation, Arc::clone(&response)));
        Some(response)
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
        r.disk
            .borrow()
            .files
            .values()
            .filter_map(|(text, indexed)| Some((indexed.as_ref()?.path.clone(), text.clone())))
            .collect()
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
    use super::root_key;

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
