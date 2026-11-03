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
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
            good_visibility: RefCell::default(),
        }
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

    /// Read one object file again (a watcher event, or the editor closed
    /// it), or forget it when it is gone.
    pub(crate) fn refresh_object(&self, path: &str) {
        self.disk.borrow_mut().refresh_path(path);
        self.index.borrow_mut().take();
    }

    fn visibility_path(&self) -> PathBuf {
        self.path.join(VISIBILITY_CONFIGURATION)
    }
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
                    r.index.borrow_mut().take();
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
            let _ = install_visibility(None);
            return;
        };
        let text = r
            .visibility
            .clone()
            .or_else(|| std::fs::read_to_string(r.visibility_path()).ok());
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
            Some(r) => {
                r.index.borrow_mut().take();
            }
            None => {
                self.loose_index.borrow_mut().take();
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
        let inside = self
            .roots
            .iter()
            .any(|r| Path::new(path).starts_with(&r.path));
        if inside || !path.starts_with(['/', '\\']) && path.as_bytes().get(1) != Some(&b':') {
            return;
        }
        if let Some(found) = workspace_root(Path::new(path)) {
            self.roots.push(Root::new(found));
            self.reassign_roots();
        }
    }

    /// The workspace folders changed: each document's root is found again.
    pub(crate) fn set_folders(&mut self, folders: Vec<PathBuf>) {
        let mut roots: Vec<Root> = Vec::new();
        let mut old: Vec<Root> = std::mem::take(&mut self.roots);
        for path in &folders {
            match old.iter().position(|r| &r.path == path) {
                Some(i) => roots.push(old.remove(i)),
                None => roots.push(Root::new(path.clone())),
            }
        }
        self.folders = roots.len();
        // Roots found around documents stay while no folder holds them.
        for r in old {
            if !folders.iter().any(|f| r.path.starts_with(f)) {
                roots.push(r);
            }
        }
        self.roots = roots;
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
            r.index.borrow_mut().take();
        }
        self.loose_index.borrow_mut().take();
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

    /// Publish what the batch changed, each document once. A client that
    /// pulls is asked to pull again instead, and one that can refresh its
    /// semantic tokens, inlay hints and lenses is asked to after a change
    /// that reaches beyond one document.
    pub(crate) fn flush_publishes(&mut self) {
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
