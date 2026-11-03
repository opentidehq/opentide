//! LSP server: diagnostics, semantic tokens, hover, completion, definition,
//! references, symbols, code actions, folding, inlay hints, custom RPCs.

use crate::jsonrpc::{self, Incoming};
use crate::uri::{path_to_uri, uri_to_path};
use anyhow::Result;
use opentide_analysis::{
    AnalyzeRequest, Catalog, IndexedObject, VISIBILITY_CONFIGURATION, WorkspaceHost, analyze,
    codes, compiled_kql, compiled_spl, completions, configuration_completions, configuration_hover,
    declare_dataset, hover, index_workspace, install_catalog, install_visibility,
    is_configuration_path, signature_help,
};
use opentide_core::{LanguageId, Position, Range, span_to_range};
use opentide_highlight::encode_lsp_semantic_tokens;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Default)]
struct Session {
    docs: HashMap<String, (LanguageId, String)>,
    root: Option<PathBuf>,
    /// The editor's `visibility.toml` buffer while the file is open: it wins
    /// over the file on disk.
    visibility: Option<String>,
    /// The client can watch files for the server (`didChangeWatchedFiles`).
    watch_files: bool,
    /// The client pulls diagnostics (`textDocument/diagnostic`) and can be
    /// told to pull again (`workspace/diagnostic/refresh`): the server then
    /// publishes none. Otherwise it only publishes. Never both, or a client
    /// such as VS Code shows every diagnostic twice (#185).
    pull_diagnostics: bool,
    /// The last id of a request the server sent the client.
    sent_requests: std::cell::Cell<u64>,
    /// The workspace's object files on disk, each read and indexed once
    /// (#181). With a file watcher, a file is read again when it changes;
    /// without one, every request re-reads the files and re-indexes those
    /// whose text changed.
    disk: RefCell<DiskObjects>,
    /// The index the analysis sees: the disk objects, with open documents in
    /// place of their files. Rebuilt after a Tide document or a file changes.
    index: RefCell<Option<Arc<[IndexedObject]>>>,
}

/// Whether YAML text names a Tide schema in its top-level `metadata` block
/// (`  schema: rule::1.0`), read line by line so a half-typed document counts.
fn names_tide_schema(text: &str) -> bool {
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
fn path_key(path: &str) -> String {
    let mut key = path.replace('\\', "/");
    if key.as_bytes().get(1) == Some(&b':') {
        key[..1].make_ascii_lowercase();
    }
    key
}

/// Object files under the workspace root: [`path_key`] → (text, index entry).
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

    /// Read one file again (a watcher event, or the editor closed it), or
    /// forget it when it is gone.
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

/// What a request sees of the workspace: the open documents, the object
/// files on disk, and their index.
struct SessionHost<'a> {
    session: &'a Session,
}

impl WorkspaceHost for SessionHost<'_> {
    fn document(&self, uri: &str) -> Option<String> {
        let session = self.session;
        if let Some((_, text)) = session.docs.get(uri) {
            return Some(text.clone());
        }
        if let Some((_, (_, text))) = session
            .docs
            .iter()
            .find(|(open, _)| uri_to_path(open) == uri)
        {
            return Some(text.clone());
        }
        if let Some((text, _)) = session.disk.borrow().files.get(&path_key(uri)) {
            return Some(text.clone());
        }
        let elastic = session.elastic_configuration()?;
        (elastic.0 == uri).then_some(elastic.1)
    }

    /// The open documents and the Elastic tenants file. Object files on disk
    /// come through [`indexed_objects`](WorkspaceHost::indexed_objects).
    fn documents(&self) -> Vec<(String, String)> {
        let session = self.session;
        let mut files: Vec<(String, String)> = session
            .docs
            .iter()
            .map(|(uri, (_, text))| (uri_to_path(uri), text.clone()))
            .collect();
        if let Some((path, text)) = session.elastic_configuration() {
            if !files.iter().any(|(open, _)| open == &path) {
                files.push((path, text));
            }
        }
        files
    }

    fn indexed_objects(&self) -> Option<Arc<[IndexedObject]>> {
        let session = self.session;
        if let Some(index) = session.index.borrow().as_ref() {
            return Some(Arc::clone(index));
        }
        let open: HashMap<String, (String, &String)> = session
            .docs
            .iter()
            .map(|(uri, (_, text))| {
                let path = uri_to_path(uri);
                (path_key(&path), (path, text))
            })
            .collect();
        let mut index: Vec<IndexedObject> = session
            .disk
            .borrow()
            .files
            .iter()
            .filter(|(path, _)| !open.contains_key(*path))
            .filter_map(|(_, (_, indexed))| indexed.clone())
            .collect();
        index.extend(
            open.values()
                .filter_map(|(path, text)| opentide_analysis::index_object(path, text)),
        );
        let index: Arc<[IndexedObject]> = index.into();
        *session.index.borrow_mut() = Some(Arc::clone(&index));
        Some(index)
    }
}

impl Session {
    fn host(&self) -> SessionHost<'_> {
        if let Some(root) = &self.root {
            let mut disk = self.disk.borrow_mut();
            if (!disk.loaded || !self.watch_files) && disk.refresh(root) {
                self.index.borrow_mut().take();
            }
        }
        SessionHost { session: self }
    }

    /// The index changes: rebuild it on the next request.
    fn invalidate_index(&self) {
        self.index.borrow_mut().take();
    }

    /// Whether `path` is a file [`collect_objects`] reads: YAML under the
    /// root's `objects/`.
    fn is_object_path(&self, path: &str) -> bool {
        let Some(root) = &self.root else {
            return false;
        };
        let path = Path::new(path);
        path.starts_with(root.join("objects"))
            && matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yaml" | "yml")
            )
    }

    /// `.opentide/configurations/platforms/elastic.toml`, from the editor when
    /// it is open, else from disk: its tenants decide the stack Elastic
    /// queries are checked against.
    fn elastic_configuration(&self) -> Option<(String, String)> {
        let root = self.root.as_ref()?;
        let path = root
            .join(opentide_analysis::ELASTIC_CONFIGURATION)
            .display()
            .to_string();
        if let Some((_, (_, text))) = self.docs.iter().find(|(uri, _)| uri_to_path(uri) == path) {
            return Some((path, text.clone()));
        }
        std::fs::read_to_string(&path).ok().map(|text| (path, text))
    }

    /// The language of a document, or `None` for a document this server does
    /// not read. A TOML file under `.opentide/configurations/` is
    /// `opentide-config` whatever id the client reports; any other `.toml`
    /// (`Cargo.toml`) is not read, and `opentide-config` is only those files.
    fn language_for(&self, uri: &str, reported: Option<&str>) -> Option<LanguageId> {
        let path = uri_to_path(uri);
        if is_configuration_path(&path) {
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
    fn reads_as_tide(&self, uri: &str, reported: Option<&str>, text: &str) -> bool {
        if matches!(reported, Some("opentide-yaml" | "tide" | "tide-yaml")) {
            return true;
        }
        let path = uri_to_path(uri).replace('\\', "/");
        if path.split('/').any(|segment| segment == "objects") {
            return true;
        }
        names_tide_schema(text)
    }
}

pub fn run_stdio() -> Result<()> {
    run_stdio_status().map(|_| ())
}

/// [`run_stdio`], returning whether the client shut the server down before
/// it exited ([`serve_with_status`]): the process should exit with 0 if so
/// and 1 if not.
pub fn run_stdio_status() -> Result<bool> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve_with_status(BufReader::new(stdin.lock()), stdout.lock())
}

pub fn run_listen(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("opentide-lsp listening on {addr}");
    let (stream, _) = listener.accept()?;
    serve(BufReader::new(stream.try_clone()?), stream)
}

/// Serve one client: read LSP frames from `reader` and write the replies to
/// `writer` until the client sends `exit` or the input ends. [`run_stdio`]
/// and [`run_listen`] are this on stdio and on a socket; a host with its own
/// streams calls it directly. [`serve_with_status`] also says whether the
/// client shut the server down first.
pub fn serve(reader: impl BufRead, writer: impl Write) -> Result<()> {
    serve_with_status(reader, writer).map(|_| ())
}

/// [`serve`], returning whether the session ended cleanly: `exit` (or the
/// end of input) after `shutdown`. LSP has the process exit with 0 then and
/// with 1 otherwise; the `opentide-lsp` binary does.
///
/// The session follows the LSP lifecycle: before `initialize`, a request is
/// answered `ServerNotInitialized` (-32002) and a notification is dropped;
/// after `shutdown`, a request is answered `InvalidRequest` (-32600) and
/// nothing is published; a second `initialize` is `InvalidRequest`. A frame
/// whose body is not a message is answered (-32700 or -32600, `id: null`)
/// and the session goes on, and so does a handler that panics: its request
/// is answered `InternalError` (-32603).
pub fn serve_with_status(mut reader: impl BufRead, mut writer: impl Write) -> Result<bool> {
    let mut session = Session::default();
    let mut state = Lifecycle::Uninitialized;
    loop {
        let msg = match jsonrpc::read_message(&mut reader)? {
            None => return Ok(state == Lifecycle::ShuttingDown),
            Some(jsonrpc::Frame::Invalid { code, message }) => {
                eprintln!("opentide-lsp: {message}");
                jsonrpc::write_message(
                    &mut writer,
                    &jsonrpc::failure(Some(Value::Null), code, message),
                )?;
                continue;
            }
            Some(jsonrpc::Frame::Message(msg)) => msg,
        };
        let method = msg.method.clone().unwrap_or_default();
        let method = method.as_str();
        let is_request = msg.id.is_some() && msg.method.is_some();
        if method == "exit" {
            return Ok(state == Lifecycle::ShuttingDown);
        }
        let refusal = match (state, method) {
            (Lifecycle::Uninitialized, "initialize") => None,
            (Lifecycle::Uninitialized, _) => Some((
                jsonrpc::SERVER_NOT_INITIALIZED,
                "the server is not initialized",
            )),
            (Lifecycle::Running, "initialize") => Some((
                jsonrpc::INVALID_REQUEST,
                "the server is already initialized",
            )),
            (Lifecycle::Running, _) => None,
            (Lifecycle::ShuttingDown, _) => {
                Some((jsonrpc::INVALID_REQUEST, "the server is shutting down"))
            }
        };
        if let Some((code, message)) = refusal {
            // A notification is dropped; a response to a server request is
            // fine at any time.
            if is_request {
                jsonrpc::write_message(&mut writer, &jsonrpc::failure(msg.id, code, message))?;
            }
            continue;
        }
        match method {
            "initialize" => state = Lifecycle::Running,
            "shutdown" => state = Lifecycle::ShuttingDown,
            _ => {}
        }
        let id = msg.id.clone();
        let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch(&mut session, &mut writer, msg)
        }));
        match handled {
            Ok(result) => {
                result?;
            }
            Err(panic) => {
                let what = panic
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic.downcast_ref::<&str>().copied())
                    .unwrap_or("a panic");
                eprintln!("opentide-lsp: handling {method:?} failed: {what}");
                if is_request {
                    jsonrpc::write_message(
                        &mut writer,
                        &jsonrpc::failure(
                            id,
                            jsonrpc::INTERNAL_ERROR,
                            format!("internal error: {what}"),
                        ),
                    )?;
                }
            }
        }
    }
}

/// Where a session is in the LSP lifecycle.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Uninitialized,
    Running,
    ShuttingDown,
}

fn dispatch(session: &mut Session, writer: &mut impl Write, msg: Incoming) -> Result<bool> {
    let method = msg.method.as_deref().unwrap_or("");
    let id = msg.id.clone();
    let params = msg.params.unwrap_or(Value::Null);
    match method {
        "initialize" => {
            if let Some(root) = params
                .pointer("/rootUri")
                .and_then(|v| v.as_str())
                .map(uri_to_path)
            {
                let root = PathBuf::from(root);
                install_workspace_catalog(&root);
                session.root = Some(root);
                *session.disk.borrow_mut() = DiskObjects::default();
                session.invalidate_index();
            } else {
                install_workspace_catalog(Path::new(""));
            }
            session.watch_files = params
                .pointer("/capabilities/workspace/didChangeWatchedFiles/dynamicRegistration")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            session.pull_diagnostics = params
                .pointer("/capabilities/textDocument/diagnostic")
                .is_some_and(Value::is_object)
                && params
                    .pointer("/capabilities/workspace/diagnostics/refreshSupport")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            reload_visibility(session);
            let mut result = json!({
                "capabilities": {
                    "textDocumentSync": 2,
                    "hoverProvider": true,
                    "completionProvider": { "resolveProvider": true, "triggerCharacters": ["|", " ", ":", ".", "(", ",", "`", "="] },
                    "signatureHelpProvider": { "triggerCharacters": ["(", ",", "=", "`"] },
                    "definitionProvider": true,
                    "referencesProvider": true,
                    "documentSymbolProvider": true,
                    "workspaceSymbolProvider": true,
                    "documentHighlightProvider": true,
                    "codeActionProvider": true,
                    "foldingRangeProvider": true,
                    "selectionRangeProvider": true,
                    "inlayHintProvider": true,
                    "diagnosticProvider": { "interFileDependencies": true, "workspaceDiagnostics": false },
                    "semanticTokensProvider": {
                        "legend": {
                            "tokenTypes": opentide_highlight::LSP_TOKEN_TYPES,
                            "tokenModifiers": []
                        },
                        "full": true
                    }
                },
                "serverInfo": { "name": "opentide-lsp", "version": env!("CARGO_PKG_VERSION") }
            });
            if !session.pull_diagnostics {
                // Push only: a client given both shows each diagnostic twice.
                if let Some(capabilities) = result["capabilities"].as_object_mut() {
                    capabilities.remove("diagnosticProvider");
                }
            }
            jsonrpc::write_message(writer, &jsonrpc::success(id, result))?;
        }
        "initialized" => {
            // Hear about visibility.toml edits made outside the editor.
            if session.watch_files {
                jsonrpc::write_message(
                    writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": "opentide-watch-visibility",
                        "method": "client/registerCapability",
                        "params": { "registrations": [{
                            "id": "opentide-visibility",
                            "method": "workspace/didChangeWatchedFiles",
                            "registerOptions": { "watchers": [
                                { "globPattern": format!("**/{VISIBILITY_CONFIGURATION}") },
                                // Object files, so the server's index of them stays current.
                                { "globPattern": "**/*.{yaml,yml}" }
                            ] }
                        }] }
                    }),
                )?;
            }
        }
        "workspace/didChangeWatchedFiles" => {
            if objects_changed(session, &params) {
                republish_all(session, writer)?;
            }
            let touched = params
                .get("changes")
                .and_then(|v| v.as_array())
                .is_some_and(|changes| {
                    changes.iter().any(|c| {
                        c.get("uri")
                            .and_then(|u| u.as_str())
                            .is_some_and(is_visibility)
                    })
                });
            // While the file is open the editor's buffer is the truth.
            if touched && session.visibility.is_none() {
                reload_visibility(session);
                republish_all(session, writer)?;
            }
        }
        "textDocument/didSave" => {}
        "shutdown" => {
            jsonrpc::write_message(writer, &jsonrpc::success(id, Value::Null))?;
        }
        "exit" => return Ok(false),
        // Lets the tests check that a failing handler does not end the
        // session. Debug builds only.
        #[cfg(debug_assertions)]
        "opentide/__panic" => panic!("opentide/__panic was requested"),
        "textDocument/didOpen" => {
            handle_did_open(session, writer, &params)?;
        }
        "textDocument/didChange" => {
            handle_did_change(session, writer, &params)?;
        }
        "textDocument/didClose" => {
            let uri = params.pointer("/textDocument/uri").and_then(|v| v.as_str());
            if let Some(uri) = uri {
                let closed = session.docs.remove(uri).map(|(language, _)| language);
                if closed == Some(LanguageId::TideYaml) {
                    // The file on disk is the object again, as last saved.
                    let path = uri_to_path(uri);
                    if session.is_object_path(&path) {
                        session.disk.borrow_mut().refresh_path(&path);
                    }
                    session.invalidate_index();
                }
                if !session.pull_diagnostics {
                    jsonrpc::write_message(
                        writer,
                        &jsonrpc::notify(
                            "textDocument/publishDiagnostics",
                            json!({ "uri": uri, "diagnostics": [] }),
                        ),
                    )?;
                }
                if is_visibility(uri) {
                    // Back to the file on disk (unsaved edits are dropped).
                    session.visibility = None;
                    reload_visibility(session);
                    republish_all(session, writer)?;
                } else if closed == Some(LanguageId::Config) {
                    // The others read the file on disk again.
                    republish_all(session, writer)?;
                }
            }
        }
        "textDocument/hover" => {
            let result = handle_hover(session, &params);
            jsonrpc::write_message(writer, &jsonrpc::success(id, result))?;
        }
        "textDocument/completion" => {
            let result = handle_completion(session, &params);
            jsonrpc::write_message(writer, &jsonrpc::success(id, result))?;
        }
        "textDocument/signatureHelp" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_signature_help(session, &params)),
            )?;
        }
        "completionItem/resolve" => {
            jsonrpc::write_message(writer, &jsonrpc::success(id, handle_resolve(&params)))?;
        }
        "textDocument/definition" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_definition(session, &params)),
            )?;
        }
        "textDocument/references" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_references(session, &params)),
            )?;
        }
        "textDocument/documentSymbol" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_document_symbol(session, &params)),
            )?;
        }
        "workspace/symbol" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_workspace_symbol(session, &params)),
            )?;
        }
        "textDocument/semanticTokens/full" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_semantic_tokens(session, &params)),
            )?;
        }
        "textDocument/diagnostic" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_pull_diagnostics(session, &params)),
            )?;
        }
        "textDocument/codeAction" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_code_action(session, &params)),
            )?;
        }
        "textDocument/foldingRange" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_folding(session, &params)),
            )?;
        }
        "textDocument/documentHighlight" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_document_highlight(session, &params)),
            )?;
        }
        "textDocument/selectionRange" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_selection_range(session, &params)),
            )?;
        }
        "textDocument/inlayHint" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_inlay(session, &params)),
            )?;
        }
        "opentide/analyze" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_custom_analyze(session, &params)),
            )?;
        }
        "opentide/highlight" => {
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, handle_custom_highlight(&params)),
            )?;
        }
        "opentide/compiledKql" => {
            let query = params.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let tenant = params.get("tenant").and_then(|v| v.as_str()).unwrap_or("");
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, json!({ "compiled": compiled_kql(query, tenant) })),
            )?;
        }
        "opentide/compiledSpl" => {
            let query = params.get("query").and_then(|v| v.as_str()).unwrap_or("");
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(id, json!({ "compiled": compiled_spl(query) })),
            )?;
        }
        "opentide/fs/read" => {
            let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let text = session.host().document(path).unwrap_or_default();
            jsonrpc::write_message(writer, &jsonrpc::success(id, json!({ "text": text })))?;
        }
        // A response to a request the server sent (`client/registerCapability`).
        "" => {}
        _ => {
            if id.is_some() {
                jsonrpc::write_message(
                    writer,
                    &jsonrpc::failure(id, -32601, format!("method not found: {method}")),
                )?;
            }
        }
    }
    Ok(true)
}

fn handle_did_open(session: &mut Session, writer: &mut impl Write, params: &Value) -> Result<()> {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let text = params
        .pointer("/textDocument/text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let lang = params
        .pointer("/textDocument/languageId")
        .and_then(|v| v.as_str());
    let Some(language) = session.language_for(uri, lang) else {
        // Not a document this server reads (`Cargo.toml`).
        return Ok(());
    };
    if language == LanguageId::TideYaml && !session.reads_as_tide(uri, lang, text) {
        // Some other YAML (`.github/workflows/ci.yml`).
        return Ok(());
    }
    // A byte-order mark is not text: the editor counts no column for it.
    let text = opentide_core::strip_bom(text).to_string();
    session.docs.insert(uri.to_string(), (language, text));
    document_changed(session, writer, uri, language)
}

/// Publish what an opened or edited document changes. `visibility.toml`
/// declares datasets every open document is checked against, and one
/// configuration file changes what another may say (a `deployment.toml`
/// status names what `sharing.toml` may share), so those re-check every open
/// document. Anything else re-checks itself.
fn document_changed(
    session: &mut Session,
    writer: &mut impl Write,
    uri: &str,
    language: LanguageId,
) -> Result<()> {
    if language == LanguageId::TideYaml {
        session.invalidate_index();
    }
    if is_visibility(uri) {
        session.visibility = session.docs.get(uri).map(|(_, text)| text.clone());
        return visibility_edited(session, writer);
    }
    if language == LanguageId::Config {
        return republish_all(session, writer);
    }
    publish_diagnostics(session, writer, uri)
}

/// Whether `uri` is the workspace's `visibility.toml`.
fn is_visibility(uri: &str) -> bool {
    uri_to_path(uri)
        .replace('\\', "/")
        .ends_with(VISIBILITY_CONFIGURATION)
}

/// Read again the object files a `didChangeWatchedFiles` names. Whether any
/// did change, so the open documents are checked again.
fn objects_changed(session: &mut Session, params: &Value) -> bool {
    let changes = params.get("changes").and_then(|v| v.as_array());
    let mut changed = false;
    for change in changes.into_iter().flatten() {
        let Some(uri) = change.get("uri").and_then(|u| u.as_str()) else {
            continue;
        };
        let path = uri_to_path(uri);
        if !session.is_object_path(&path) {
            continue;
        }
        session.disk.borrow_mut().refresh_path(&path);
        changed = true;
    }
    if changed {
        session.invalidate_index();
    }
    changed
}

/// `visibility.toml` changed in the editor: its declared datasets apply at
/// once, and every open document is checked again. A buffer that is not
/// TOML yet (mid-edit) keeps the declarations in use; the configuration
/// documents, `visibility.toml` among them, are still checked again.
fn visibility_edited(session: &mut Session, writer: &mut impl Write) -> Result<()> {
    if install_visibility(session.visibility.as_deref()).is_ok() {
        return republish_all(session, writer);
    }
    let mut uris: Vec<String> = session
        .docs
        .iter()
        .filter(|(_, (language, _))| *language == LanguageId::Config)
        .map(|(uri, _)| uri.clone())
        .collect();
    uris.sort();
    for uri in uris {
        publish_diagnostics(session, writer, &uri)?;
    }
    Ok(())
}

/// Read `visibility.toml` from the workspace (unless the editor has it open)
/// and install the datasets it declares. A file that is not TOML is reported
/// on stderr and declares nothing.
fn reload_visibility(session: &mut Session) {
    if session.visibility.is_some() {
        return;
    }
    let text = session
        .root
        .as_ref()
        .and_then(|root| std::fs::read_to_string(root.join(VISIBILITY_CONFIGURATION)).ok());
    if let Err(err) = install_visibility(text.as_deref()) {
        eprintln!("opentide-lsp: {err}; no datasets are declared");
        let _ = install_visibility(None);
    }
}

fn republish_all(session: &Session, writer: &mut impl Write) -> Result<()> {
    if session.pull_diagnostics {
        // The client pulls: ask it to pull every open document again.
        let id = session.sent_requests.get() + 1;
        session.sent_requests.set(id);
        return jsonrpc::write_message(
            writer,
            &json!({
                "jsonrpc": "2.0",
                "id": format!("opentide-refresh-{id}"),
                "method": "workspace/diagnostic/refresh",
            }),
        );
    }
    let mut uris: Vec<&String> = session.docs.keys().collect();
    uris.sort();
    for uri in uris {
        publish_diagnostics(session, writer, uri)?;
    }
    Ok(())
}

fn handle_did_change(session: &mut Session, writer: &mut impl Write, params: &Value) -> Result<()> {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(language) = session
        .docs
        .get(uri)
        .map(|(l, _)| *l)
        // A document opened before is tracked; one never opened is read only
        // when it is not YAML (whose kind its text decides at didOpen).
        .or_else(|| {
            session
                .language_for(uri, None)
                .filter(|language| *language != LanguageId::TideYaml)
        })
    else {
        return Ok(());
    };
    let current = session
        .docs
        .get(uri)
        .map(|(_, text)| text.clone())
        .unwrap_or_default();
    let changes = params
        .get("contentChanges")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let text = apply_content_changes(&current, &changes);
    let text = opentide_core::strip_bom(&text).to_string();
    session.docs.insert(uri.to_string(), (language, text));
    document_changed(session, writer, uri, language)
}

fn apply_content_changes(text: &str, changes: &[Value]) -> String {
    let mut current = text.to_string();
    for change in changes {
        let Some(next) = change.get("text").and_then(|v| v.as_str()) else {
            continue;
        };
        if let Some(range) = change.get("range") {
            current = splice_range(&current, range, next);
        } else {
            current = next.to_string();
        }
    }
    current
}

fn splice_range(text: &str, range: &Value, insert: &str) -> String {
    let start = offset_at(
        text,
        range.pointer("/start/line"),
        range.pointer("/start/character"),
    );
    let end = offset_at(
        text,
        range.pointer("/end/line"),
        range.pointer("/end/character"),
    );
    let mut out = String::new();
    out.push_str(&text[..start.min(text.len())]);
    out.push_str(insert);
    out.push_str(&text[end.min(text.len())..]);
    out
}

/// The byte offset of an LSP position in `text`: `character` counts UTF-16
/// code units, as LSP positions do, and the offset always falls on a char
/// boundary. A column past its line's end clamps to the end of the line, and
/// a line past the end of the text gives its length.
fn offset_at(text: &str, line: Option<&Value>, character: Option<&Value>) -> usize {
    let line = line.and_then(|v| v.as_u64()).unwrap_or(0);
    let character = character.and_then(|v| v.as_u64()).unwrap_or(0);
    let clamp = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
    opentide_core::position_to_offset(text, Position::new(clamp(line), clamp(character)))
}

fn publish_diagnostics(session: &Session, writer: &mut impl Write, uri: &str) -> Result<()> {
    if session.pull_diagnostics {
        return Ok(());
    }
    let Some((language, text)) = session.docs.get(uri) else {
        return Ok(());
    };
    let host = session.host();
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: uri_to_path(uri),
            language: *language,
            text: text.clone(),
        },
    );
    let diags: Vec<Value> = response.diagnostics.iter().map(diagnostic_json).collect();
    jsonrpc::write_message(
        writer,
        &jsonrpc::notify(
            "textDocument/publishDiagnostics",
            json!({ "uri": uri, "diagnostics": diags }),
        ),
    )?;
    Ok(())
}

/// One engine diagnostic as LSP sends it, pushed or pulled alike.
fn diagnostic_json(d: &opentide_core::Diagnostic) -> Value {
    json!({
        "range": range_json(d.range),
        "severity": match d.severity {
            opentide_core::Severity::Error => 1,
            opentide_core::Severity::Warning => 2,
            opentide_core::Severity::Information => 3,
            opentide_core::Severity::Hint => 4,
        },
        "code": d.code,
        "source": "opentide",
        "message": d.message,
        "data": {
            "field_path": d.field_path,
            "suggestion": d.suggestion
        }
    })
}

fn handle_hover(session: &Session, params: &Value) -> Value {
    let Some((uri, language, text, pos)) = doc_pos(session, params) else {
        return Value::Null;
    };
    if language == LanguageId::Config {
        let offset = position_to_offset(&text, pos);
        return configuration_hover(&uri_to_path(&uri), &text, offset)
            .map(|value| json!({ "contents": { "kind": "markdown", "value": value } }))
            .unwrap_or(Value::Null);
    }
    let host = session.host();
    hover(&host, language, &text, position_to_offset(&text, pos))
        .map(|value| json!({ "contents": { "kind": "markdown", "value": value } }))
        .unwrap_or(Value::Null)
}

fn handle_completion(session: &Session, params: &Value) -> Value {
    let Some((uri, language, text, pos)) = doc_pos(session, params) else {
        return json!([]);
    };
    let offset = position_to_offset(&text, pos);
    let host = session.host();
    // A dotted field label (`process.parent.name`) replaces the whole dotted
    // prefix already typed. Editors split words at `.`, so plain insertText
    // would append after `process.`.
    let before = &text[..offset.min(text.len())];
    let dotted = &before[before
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-')))
        .map_or(0, |i| i + 1)..];
    let start = json!({
        "line": pos.line,
        "character": pos.character.saturating_sub(dotted.encode_utf16().count() as u32),
    });
    let found = if language == LanguageId::Config {
        configuration_completions(&uri_to_path(&uri), &text, offset)
    } else {
        completions(&host, language, &text, offset)
    };
    let items: Vec<Value> = found
        .into_iter()
        .map(|c| {
            let edit = (c.label.contains('.') && !dotted.is_empty() && c.label.starts_with(dotted))
                .then(|| {
                    json!({
                        "range": { "start": start, "end": { "line": pos.line, "character": pos.character } },
                        "newText": c.label,
                    })
                });
            let mut item = json!({
                "label": c.label,
                "detail": c.detail,
                "documentation": c.documentation.as_ref().map(|d| json!({ "kind": "markdown", "value": d })),
                "kind": match c.kind.as_str() {
                    "operator" | "keyword" | "command" => 14,
                    "function" | "plugin" => 3,
                    "table" | "type" => 7,
                    "column" | "property" => 5,
                    "macro" => 23,
                    "enum" => 13,
                    "reference" => 18,
                    "module" => 9,
                    _ => 1,
                },
                "insertText": c.label,
            });
            if let Some(edit) = edit {
                item["textEdit"] = edit;
                item["filterText"] = json!(c.label);
            }
            item
        })
        .collect();
    json!(items)
}

fn handle_signature_help(session: &Session, params: &Value) -> Value {
    let Some((_uri, language, text, pos)) = doc_pos(session, params) else {
        return Value::Null;
    };
    let host = session.host();
    signature_help(&host, language, &text, position_to_offset(&text, pos))
        .map(|help| {
            json!({
                "signatures": help.signatures.iter().map(|s| json!({
                    "label": s.label,
                    "documentation": s.documentation,
                    "parameters": s.parameters.iter().map(|p| json!({
                        "label": p.label,
                        "documentation": p.documentation
                    })).collect::<Vec<_>>()
                })).collect::<Vec<_>>(),
                "activeSignature": help.active_signature,
                "activeParameter": help.active_parameter
            })
        })
        .unwrap_or(Value::Null)
}

fn handle_resolve(params: &Value) -> Value {
    let label = params
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let kind = match params.get("kind").and_then(|v| v.as_u64()) {
        Some(5) => "property",
        Some(13) => "enum",
        Some(18) => "reference",
        _ => params
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("property"),
    };
    let mut item = opentide_core::CompletionItem::new(label, kind);
    if let Some(d) = params.get("detail").and_then(|v| v.as_str()) {
        item = item.with_detail(d);
    }
    if let Some(d) = params
        .pointer("/documentation/value")
        .or_else(|| params.get("documentation"))
        .and_then(|v| v.as_str())
    {
        item = item.with_docs(d);
    }
    let item = opentide_tide::resolve_completion(item);
    // The client's item, unchanged except for what resolve adds: its
    // `textEdit` and `filterText` (a dotted field's replace range) must
    // survive, or the insertion breaks.
    let mut resolved = params.clone();
    if !resolved.is_object() {
        resolved = json!({ "label": item.label });
    }
    if resolved.get("documentation").is_none_or(Value::is_null) {
        if let Some(docs) = &item.documentation {
            resolved["documentation"] = json!({ "kind": "markdown", "value": docs });
        }
    }
    if resolved.get("detail").is_none_or(Value::is_null) {
        if let Some(detail) = &item.detail {
            resolved["detail"] = json!(detail);
        }
    }
    resolved
}

fn handle_definition(session: &Session, params: &Value) -> Value {
    let Some((_uri, _, text, pos)) = doc_pos(session, params) else {
        return Value::Null;
    };
    let uuid = uuid_at(&text, pos);
    let host = session.host();
    let workspace = index_workspace(&host);
    if let Some(uuid) = uuid {
        if let Some(obj) = opentide_tide::definition(&workspace, &uuid) {
            let source = host.document(&obj.path).unwrap_or_default();
            let range = opentide_tide::uuid_span(&source, &uuid)
                .map(|span| span_to_range(&source, span))
                .unwrap_or_else(|| Range::point(0, 0));
            return json!({
                "uri": path_to_uri(&obj.path),
                "range": range_json(range)
            });
        }
    }
    Value::Null
}

fn handle_references(session: &Session, params: &Value) -> Value {
    let Some((_, _, text, pos)) = doc_pos(session, params) else {
        return json!([]);
    };
    let Some(uuid) = uuid_at(&text, pos) else {
        return json!([]);
    };
    let host = session.host();
    let workspace = index_workspace(&host);
    let refs: Vec<Value> = opentide_tide::find_refs(&workspace, &uuid)
        .into_iter()
        .filter_map(|o| {
            let source = host.document(&o.path)?;
            let span = opentide_tide::uuid_span(&source, &uuid)?;
            Some(json!({
                "uri": path_to_uri(&o.path),
                "range": range_json(span_to_range(&source, span))
            }))
        })
        .collect();
    json!(refs)
}

fn handle_document_symbol(session: &Session, params: &Value) -> Value {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some((language, text)) = session.docs.get(uri) else {
        return json!([]);
    };
    let host = session.host();
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: uri_to_path(uri),
            language: *language,
            text: text.clone(),
        },
    );
    json!(
        response
            .symbols
            .iter()
            .map(|s| json!({
                "name": s.name,
                "kind": 5,
                "detail": s.detail,
                "range": range_json(s.range),
                "selectionRange": range_json(s.range)
            }))
            .collect::<Vec<_>>()
    )
}

fn handle_workspace_symbol(session: &Session, params: &Value) -> Value {
    let query = params.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let host = session.host();
    let workspace = index_workspace(&host);
    json!(
        opentide_tide::workspace_symbols(&workspace, query)
            .into_iter()
            .map(|o| {
                // The open buffer, else the file the index read.
                let text = host.document(&o.path).unwrap_or_default();
                let text = text.as_str();
                json!({
                    "name": o.name,
                    "kind": 5,
                    "location": {
                        "uri": path_to_uri(&o.path),
                        "range": name_token_range(text, &o.name)
                    },
                    "containerName": o.object_type
                })
            })
            .collect::<Vec<_>>()
    )
}

fn handle_semantic_tokens(session: &Session, params: &Value) -> Value {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some((language, text)) = session.docs.get(uri) else {
        return json!({ "data": [] });
    };
    let host = session.host();
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: uri_to_path(uri),
            language: *language,
            text: text.clone(),
        },
    );
    json!({ "data": encode_lsp_semantic_tokens(&response.tokens) })
}

fn handle_pull_diagnostics(session: &Session, params: &Value) -> Value {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some((language, text)) = session.docs.get(uri) else {
        return json!({ "kind": "full", "items": [] });
    };
    let host = session.host();
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: uri_to_path(uri),
            language: *language,
            text: text.clone(),
        },
    );
    json!({
        "kind": "full",
        "items": response.diagnostics.iter().map(diagnostic_json).collect::<Vec<_>>()
    })
}

fn handle_code_action(session: &Session, params: &Value) -> Value {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some((language, text)) = session.docs.get(uri) else {
        return json!([]);
    };
    let host = session.host();
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: uri_to_path(uri),
            language: *language,
            text: text.clone(),
        },
    );
    let requested = params.get("range");
    let in_range: Vec<&opentide_core::Diagnostic> = response
        .diagnostics
        .iter()
        .filter(|d| range_overlaps_param(d.range, requested))
        .collect();
    let mut actions: Vec<Value> = in_range
        .iter()
        .filter_map(|d| {
            let suggestion = d.suggestion.as_ref()?;
            Some(json!({
                "title": format!("Apply suggestion: {suggestion}"),
                "kind": "quickfix",
                "edit": {
                    "changes": {
                        uri: [{
                            "range": range_json(d.range),
                            "newText": suggestion
                        }]
                    }
                }
            }))
        })
        .collect();
    if let Some(root) = &session.root {
        let path = root.join(VISIBILITY_CONFIGURATION);
        // An open buffer may hold edits not yet saved: the edit applies to it.
        let existing = session
            .visibility
            .clone()
            .or_else(|| std::fs::read_to_string(&path).ok());
        let target = path_to_uri(&path.display().to_string());
        let mut seen = std::collections::BTreeSet::new();
        for d in &in_range {
            let Some((platform, name)) = undeclared_dataset(d) else {
                continue;
            };
            if !seen.insert((platform, name.clone())) {
                continue;
            }
            let edit = declare_dataset(existing.as_deref(), platform, &name);
            let text_edit = json!({ "range": range_json(edit.range), "newText": edit.new_text });
            let workspace_edit = if existing.is_some() {
                json!({ "changes": { target.clone(): [text_edit] } })
            } else {
                json!({ "documentChanges": [
                    { "kind": "create", "uri": target, "options": { "ignoreIfExists": true } },
                    { "textDocument": { "uri": target, "version": null }, "edits": [text_edit] }
                ] })
            };
            actions.push(json!({
                "title": edit.title,
                "kind": "quickfix",
                "diagnostics": [{
                    "range": range_json(d.range),
                    "code": d.code,
                    "message": d.message,
                }],
                "edit": workspace_edit
            }));
        }
    }
    json!(actions)
}

/// The dataset a "declare it in visibility.toml" diagnostic names: its
/// platform and name (quoted in the message: `'X'` for KQL, `` `X` `` for
/// SPL and Elastic).
fn undeclared_dataset(d: &opentide_core::Diagnostic) -> Option<(&'static str, String)> {
    let name = d.message.split('\'').nth(1).unwrap_or_default().to_string();
    let in_defender = d
        .field_path
        .as_ref()
        .is_some_and(|p| p.iter().any(|s| s == "defender_for_endpoint"));
    match d.code.as_str() {
        codes::KQL_TABLE_NOT_DECLARED => Some((
            if in_defender {
                "defender_for_endpoint"
            } else {
                "sentinel"
            },
            name,
        )),
        // An unknown table whose message names the declaration: Sentinel's
        // warning (#111), and Defender's error once it declares tables (#147).
        codes::KQL_UNKNOWN_TABLE if d.message.contains("visibility.toml") => Some((
            if in_defender {
                "defender_for_endpoint"
            } else {
                "sentinel"
            },
            name,
        )),
        // `sourcetype `syslog` is not declared ...`
        codes::SPL_DATASET_NOT_DECLARED => Some(("splunk", backticked(&d.message)?)),
        // `index pattern `logs-*` is not declared ...`
        codes::ELASTIC_DATASET_NOT_DECLARED => Some(("elastic", backticked(&d.message)?)),
        _ => None,
    }
}

fn backticked(message: &str) -> Option<String> {
    Some(message.split('`').nth(1)?.to_string())
}

fn handle_folding(session: &Session, params: &Value) -> Value {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some((_, text)) = session.docs.get(uri) else {
        return json!([]);
    };
    json!(
        folding_ranges(text)
            .into_iter()
            .map(|(start, end)| json!({ "startLine": start, "endLine": end, "kind": "region" }))
            .collect::<Vec<_>>()
    )
}

fn handle_inlay(session: &Session, params: &Value) -> Value {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some((language, text)) = session.docs.get(uri) else {
        return json!([]);
    };
    if *language != LanguageId::TideYaml {
        return json!([]);
    }
    let host = session.host();
    let workspace = index_workspace(&host);
    let requested = params.get("range");
    let hints: Vec<Value> = opentide_tide::inlay_hints(text, &workspace)
        .into_iter()
        .filter(|h| position_in_param(h.position, requested))
        .map(|h| {
            json!({
                "position": { "line": h.position.line, "character": h.position.character },
                "label": h.label,
                "kind": 1
            })
        })
        .collect();
    json!(hints)
}

fn handle_document_highlight(session: &Session, params: &Value) -> Value {
    let Some((_, _, text, pos)) = doc_pos(session, params) else {
        return json!([]);
    };
    if let Some(uuid) = uuid_at(&text, pos) {
        let hits = uuid_ranges(&text, &uuid);
        if !hits.is_empty() {
            return json!(hits);
        }
    }
    json!([])
}

fn handle_selection_range(session: &Session, params: &Value) -> Value {
    let positions = params
        .get("positions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some((_, text)) = session.docs.get(uri) else {
        return json!([]);
    };
    let lines: Vec<&str> = text.lines().collect();
    json!(
        positions
            .iter()
            .map(|p| {
                let line = p.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let (parent_start, parent_end) = enclosing_block(&lines, line);
                json!({
                    "range": {
                        "start": { "line": line, "character": 0 },
                        "end": {
                            "line": line,
                            "character": lines.get(line).map(|l| utf16_len(l)).unwrap_or(0)
                        }
                    },
                    "parent": {
                        "range": {
                            "start": { "line": parent_start, "character": 0 },
                            "end": {
                                "line": parent_end,
                                "character": lines.get(parent_end as usize).map(|l| utf16_len(l)).unwrap_or(0)
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>()
    )
}

fn handle_custom_analyze(session: &Session, params: &Value) -> Value {
    let text = params.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let language = params
        .get("language")
        .and_then(|v| v.as_str())
        .and_then(LanguageId::parse)
        .unwrap_or(LanguageId::TideYaml);
    let host = session.host();
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: params
                .get("uri")
                .and_then(|v| v.as_str())
                .unwrap_or("memory")
                .to_string(),
            language,
            text: text.to_string(),
        },
    );
    json!({ "diagnostics": response.diagnostics })
}

fn handle_custom_highlight(params: &Value) -> Value {
    let text = params.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let language = params
        .get("language")
        .and_then(|v| v.as_str())
        .and_then(LanguageId::parse)
        .unwrap_or(LanguageId::Kql);
    let result = opentide_analysis::highlight(language, text);
    json!(result)
}

fn doc_pos(session: &Session, params: &Value) -> Option<(String, LanguageId, String, Position)> {
    let uri = params.pointer("/textDocument/uri")?.as_str()?.to_string();
    let (language, text) = session.docs.get(&uri)?;
    let line = params.pointer("/position/line")?.as_u64()? as u32;
    let character = params.pointer("/position/character")?.as_u64()? as u32;
    Some((uri, *language, text.clone(), Position::new(line, character)))
}

fn name_token_range(text: &str, name: &str) -> Value {
    match text.find(name) {
        Some(start) if !name.is_empty() => range_json(span_to_range(
            text,
            opentide_core::ByteSpan::new(start, start + name.len()),
        )),
        _ => {
            json!({ "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 1 } })
        }
    }
}

fn folding_ranges(text: &str) -> Vec<(u32, u32)> {
    let lines: Vec<&str> = text.lines().collect();
    let last = lines.len().saturating_sub(1);
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(indent) = content_indent(line) else {
            continue;
        };
        let mut end = None;
        for (j, child) in lines.iter().enumerate().skip(i + 1) {
            let Some(child_indent) = content_indent(child) else {
                continue;
            };
            if child_indent > indent {
                end = Some(j);
            } else {
                break;
            }
        }
        if let Some(end) = end {
            if !(i == 0 && end == last) {
                out.push((i as u32, end as u32));
            }
        }
    }
    out
}

fn enclosing_block(lines: &[&str], line: usize) -> (u32, u32) {
    let line = line.min(lines.len().saturating_sub(1));
    let indent = content_indent(lines.get(line).copied().unwrap_or("")).unwrap_or(0);
    let mut parent = line;
    for i in (0..line).rev() {
        if let Some(parent_indent) = content_indent(lines[i]) {
            if parent_indent < indent {
                parent = i;
                break;
            }
        }
    }
    let parent_indent = content_indent(lines.get(parent).copied().unwrap_or("")).unwrap_or(0);
    let mut end = parent;
    for (j, child) in lines.iter().enumerate().skip(parent + 1) {
        if let Some(child_indent) = content_indent(child) {
            if child_indent <= parent_indent {
                break;
            }
            end = j;
        }
    }
    (parent as u32, end as u32)
}

fn content_indent(line: &str) -> Option<usize> {
    if line.trim().is_empty() {
        None
    } else {
        Some(line.chars().take_while(|c| *c == ' ').count())
    }
}

fn uuid_ranges(text: &str, uuid: &str) -> Vec<Value> {
    let lines = opentide_core::LineIndex::new(text);
    text.match_indices(uuid)
        .map(|(start, _)| {
            json!({
                "range": range_json(lines.range(opentide_core::ByteSpan::new(start, start + uuid.len()))),
                "kind": 1
            })
        })
        .collect()
}

fn range_overlaps_param(range: Range, requested: Option<&Value>) -> bool {
    let Some(requested) = requested else {
        return true;
    };
    let start_line = requested
        .pointer("/start/line")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let end_line = requested
        .pointer("/end/line")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    range.start.line <= end_line && range.end.line >= start_line
}

fn position_in_param(position: Position, requested: Option<&Value>) -> bool {
    let Some(requested) = requested else {
        return true;
    };
    let start_line = requested
        .pointer("/start/line")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let end_line = requested
        .pointer("/end/line")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX) as u32;
    position.line >= start_line && position.line <= end_line
}

fn range_json(range: Range) -> Value {
    json!({
        "start": { "line": range.start.line, "character": range.start.character },
        "end": { "line": range.end.line, "character": range.end.character }
    })
}

/// Where `opentide generate schemas` writes the workspace catalogs.
pub const WORKSPACE_CATALOGS: &str = ".opentide/lsp/catalogs/generated";

/// Install the workspace's `fields.json` and `deprecations.json` when they
/// exist, and the bundled catalogs otherwise. A file that does not parse is
/// reported on stderr and leaves the bundled catalogs in place.
/// Set by a host that installed the catalogs itself
/// ([`opentide_analysis::set_default_catalog`]): the server then leaves them
/// alone at `initialize` instead of reading the workspace's.
static HOST_CATALOGS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Keep the catalogs the host installed: `initialize` does not read
/// `.opentide/lsp/catalogs/generated/`. opentide generates the catalogs from
/// its own models for the workspace it serves, so a committed copy, possibly
/// from an older opentide, must not replace them. Process-wide.
pub fn use_host_catalogs() {
    HOST_CATALOGS.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub fn install_workspace_catalog(root: &Path) {
    if HOST_CATALOGS.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let dir = root.join(WORKSPACE_CATALOGS);
    let read = |name: &str| {
        if root.as_os_str().is_empty() {
            return None;
        }
        std::fs::read_to_string(dir.join(name)).ok()
    };
    let catalog = Catalog {
        fields: read("fields.json"),
        deprecations: read("deprecations.json"),
        // visibility.toml is read on its own (reload_visibility), so edits apply live.
        visibility: None,
    };
    if let Err(err) = install_catalog(&catalog) {
        eprintln!(
            "opentide-lsp: ignoring {}: {err}; using the bundled catalogs",
            dir.display()
        );
        let _ = install_catalog(&Catalog::default());
    }
}

fn uuid_at(text: &str, pos: Position) -> Option<String> {
    // A column past the end of its line is on no UUID (the converter would
    // clamp it to the line's end).
    let line = text.lines().nth(pos.line as usize)?;
    if pos.character as usize > utf16_len(line) {
        return None;
    }
    // The cursor's byte offset: `pos.character` counts UTF-16 units.
    let offset = position_to_offset(text, pos);
    uuid_pattern()
        .find_iter(text)
        .find(|m| m.start() <= offset && offset <= m.end())
        .map(|m| m.as_str().to_string())
}

/// A line's length in LSP columns (UTF-16 units).
fn utf16_len(line: &str) -> usize {
    line.encode_utf16().count()
}

fn uuid_pattern() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        )
        .expect("UUID pattern")
    })
}

fn position_to_offset(source: &str, position: Position) -> usize {
    opentide_core::position_to_offset(source, position)
}

/// The workspace's object YAML: the files under `<root>/objects`. A root
/// without `objects/` has none, and nothing else under it is read (a root of
/// `/tmp` or a home directory once had every YAML file there indexed).
fn collect_objects(root: &Path) -> Vec<(String, String)> {
    yaml_files(&root.join("objects"))
}

/// Every `.yaml` and `.yml` file under `dir`, with its text (byte-order mark
/// dropped). A symlinked directory is not entered, so a link back up the tree
/// cannot index a file twice or loop; a symlinked file is read. A file or
/// directory that cannot be read (not UTF-8, no permission) is left out. The
/// `opentide-lsp analyze` command and the server share this walk.
pub fn yaml_files(dir: &Path) -> Vec<(String, String)> {
    fn rec(dir: &Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                rec(&path, out);
            } else if (kind.is_file() || (kind.is_symlink() && path.is_file()))
                && matches!(
                    path.extension().and_then(|s| s.to_str()),
                    Some("yaml" | "yml")
                )
            {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    let text = opentide_core::strip_bom(&text).to_string();
                    out.push((path.display().to_string(), text));
                }
            }
        }
    }
    let mut out = Vec::new();
    rec(dir, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranged(start_line: u64, start_char: u64, end_line: u64, end_char: u64, text: &str) -> Value {
        json!({
            "range": {
                "start": { "line": start_line, "character": start_char },
                "end": { "line": end_line, "character": end_char }
            },
            "text": text
        })
    }

    fn at(text: &str, line: u64, character: u64) -> usize {
        offset_at(text, Some(&json!(line)), Some(&json!(character)))
    }

    #[test]
    fn incremental_edits_apply_in_order_and_full_replace_wins() {
        let text = "name: Rule\n";
        let edited =
            apply_content_changes(text, &[ranged(0, 6, 0, 6, "X"), ranged(0, 7, 0, 7, "Y")]);
        assert_eq!(edited, "name: XYRule\n");
        assert_eq!(
            apply_content_changes(text, &[json!({ "text": "other" })]),
            "other"
        );
        assert_eq!(
            apply_content_changes(
                text,
                &[
                    json!({ "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 0 } } })
                ]
            ),
            text
        );
    }

    #[test]
    fn offset_at_counts_utf16_and_clamps() {
        let src = "aéX";
        assert_eq!(at(src, 0, 0), 0);
        assert_eq!(at(src, 0, 1), 1);
        // UTF-16 column 2 is `X`, after the two bytes of `é`.
        assert_eq!(at(src, 0, 2), 1 + "é".len());

        // An emoji is two UTF-16 units; column 3 is `b`.
        let src = "a😀b";
        assert_eq!(at(src, 0, 1), 1);
        assert_eq!(at(src, 0, 3), 1 + "😀".len());
        assert_eq!(
            apply_content_changes(src, &[ranged(0, 1, 0, 3, "X")]),
            "aXb"
        );

        let src = "ab\ncd";
        assert_eq!(at(src, 0, 99), 2);
        assert_eq!(at(src, 9, 0), src.len());
        assert_eq!(
            apply_content_changes(src, &[ranged(0, 99, 0, 99, "Z")]),
            "abZ\ncd"
        );
        assert_eq!(
            apply_content_changes("ab", &[ranged(5, 0, 5, 0, "Z")]),
            "abZ"
        );

        // The CR stays in the line the splice indexes.
        let src = "ab\r\ncd";
        assert_eq!(at(src, 0, 2), 2);
        assert_eq!(at(src, 1, 1), "ab\r\n".len() + 1);
    }

    /// #178: an edit after a multi-byte character used to slice inside it.
    #[test]
    fn edits_after_multi_byte_characters_land_where_the_editor_put_them() {
        let src = "T | where Name == \"日本\"";
        // `日` is column 19 and `本` column 20 (one UTF-16 unit each).
        let edited = apply_content_changes(src, &[ranged(0, 20, 0, 20, "x")]);
        assert_eq!(edited, "T | where Name == \"日x本\"");
        let edited = apply_content_changes(src, &[ranged(0, 21, 0, 21, "x")]);
        assert_eq!(edited, "T | where Name == \"日本x\"");
        let edited = apply_content_changes("é😀", &[ranged(0, 3, 0, 3, "!")]);
        assert_eq!(edited, "é😀!");
        // A column inside a surrogate pair moves past the character, never into it.
        let edited = apply_content_changes("😀z", &[ranged(0, 1, 0, 1, "!")]);
        assert_eq!(edited, "😀!z");
    }

    #[test]
    fn position_to_offset_counts_utf16() {
        let src = "aéX";
        assert_eq!(position_to_offset(src, Position::new(0, 2)), 1 + "é".len());
        let src = "a😀b";
        assert_eq!(position_to_offset(src, Position::new(0, 3)), 1 + "😀".len());
        assert_eq!(at(src, 0, 3), position_to_offset(src, Position::new(0, 3)));
    }

    #[test]
    fn language_for_ignores_unknown_ids_and_sql() {
        let session = Session::default();
        let lang = |uri: &str, reported: Option<&str>| session.language_for(uri, reported);
        assert_eq!(
            lang("file:///q.sql", Some("sql")),
            Some(LanguageId::TideYaml)
        );
        assert_eq!(
            lang("file:///q.kql", Some("not-a-language")),
            Some(LanguageId::Kql)
        );
        assert_eq!(lang("file:///q.yaml", Some("kusto")), Some(LanguageId::Kql));
        assert_eq!(lang("file:///q.spl", Some("SPL")), Some(LanguageId::Spl));
        assert_eq!(lang("file:///q.txt", None), Some(LanguageId::TideYaml));
    }

    #[test]
    fn configuration_toml_is_opentide_config_and_other_toml_is_not_read() {
        let session = Session::default();
        let lang = |uri: &str, reported: Option<&str>| session.language_for(uri, reported);
        let sharing = "file:///w/.opentide/configurations/sharing.toml";
        assert_eq!(lang(sharing, Some("toml")), Some(LanguageId::Config));
        assert_eq!(lang(sharing, Some("kql")), Some(LanguageId::Config));
        assert_eq!(
            lang(
                "file:///w/.opentide/configurations/platforms/sentinel.toml",
                None
            ),
            Some(LanguageId::Config)
        );
        assert_eq!(lang("file:///w/Cargo.toml", Some("toml")), None);
        assert_eq!(lang("file:///w/pyproject.toml", None), None);
        // The id alone does not make a file a configuration file.
        assert_eq!(lang("file:///w/Cargo.toml", Some("opentide-config")), None);
    }

    #[test]
    fn folding_skips_blank_lines_and_does_not_fold_the_whole_buffer() {
        let with_blank = "metadata:\n  uuid: a\n\n  schema: b\nname: x\n";
        assert_eq!(folding_ranges(with_blank), vec![(0, 3)]);

        let whole = "root:\n  a\n  b\n";
        assert!(folding_ranges(whole).is_empty());

        let nested = "outer:\n  inner:\n    leaf\nname: x\n";
        assert_eq!(folding_ranges(nested), vec![(0, 2), (1, 2)]);

        let tabs = "meta:\n\tuuid: a\n";
        assert!(folding_ranges(tabs).is_empty());
    }

    #[test]
    fn selection_parent_includes_blank_lines_inside_the_block() {
        let lines: Vec<&str> = "metadata:\n  uuid: a\n\n  schema: b\nname: x"
            .lines()
            .collect();
        assert_eq!(enclosing_block(&lines, 1), (0, 3));
        assert_eq!(enclosing_block(&lines, 4), (4, 4));
    }

    #[test]
    fn uuid_at_matches_the_caret_including_the_end_boundary() {
        let uuid = "00000000-0000-4000-8000-000000000001";
        let text = format!("id: {uuid}\n");
        let start = text.find(uuid).unwrap() as u32;
        assert_eq!(
            uuid_at(&text, Position::new(0, start)).as_deref(),
            Some(uuid)
        );
        assert_eq!(
            uuid_at(&text, Position::new(0, start + uuid.len() as u32)).as_deref(),
            Some(uuid)
        );
        assert_eq!(
            uuid_at(&text, Position::new(0, start + uuid.len() as u32 + 1)),
            None
        );
        assert_eq!(uuid_at(&text, Position::new(1, 0)), None);
    }

    #[test]
    fn range_filters_use_line_overlap() {
        let range = Range::new(Position::new(2, 0), Position::new(4, 10));
        assert!(range_overlaps_param(range, None));
        let touch = json!({
            "start": { "line": 2, "character": 0 },
            "end": { "line": 2, "character": 0 }
        });
        assert!(range_overlaps_param(range, Some(&touch)));
        let before = json!({
            "start": { "line": 0, "character": 0 },
            "end": { "line": 1, "character": 8 }
        });
        assert!(!range_overlaps_param(range, Some(&before)));

        assert!(position_in_param(Position::new(3, 0), None));
        assert!(!position_in_param(Position::new(1, 0), Some(&touch)));
        assert!(position_in_param(Position::new(2, 99), Some(&touch)));
        let open_ended = json!({ "start": { "line": 4, "character": 0 } });
        assert!(position_in_param(Position::new(9, 0), Some(&open_ended)));
        assert!(!position_in_param(Position::new(3, 0), Some(&open_ended)));
    }
}
