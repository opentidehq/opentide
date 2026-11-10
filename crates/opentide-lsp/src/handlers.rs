//! The LSP methods, typed with `lsp-types` (#185 P1.2). A request's params
//! that do not deserialize are `InvalidParams` (-32602); a method the server
//! does not know is `MethodNotFound` (-32601). Editor positions (UTF-16
//! columns) become byte offsets here, once, before any engine sees them
//! (P1.5).

use crate::server::{host_info, path_to_uri_value};
use crate::session::{Document, Root, Session, path_key};
use crate::uri::{path_to_uri, uri_to_path};
use lsp_server::{ErrorCode, Request, Response};
use lsp_types as lsp;
use lsp_types::notification::Notification as _;
use opentide_analysis::{
    VISIBILITY_CONFIGURATION, WorkspaceHost, codes, compiled_kql, compiled_spl, completions,
    configuration_completions, configuration_hover, declare_dataset, hover, signature_help,
    workspace_index,
};
use opentide_core::{ByteSpan, LanguageId, LineIndex, Position, Range, span_to_range};
use opentide_highlight::encode_lsp_semantic_tokens;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

/// Where the diagnostics reference lives: `#<code>` is each code's section.
pub const DIAGNOSTICS_DOCS: &str = "https://opentide.org/docs/cli/diagnostics/";

/// Completion triggers. YAML is prose too: a space there opens no list
/// (P2.6), and is ignored when a client sends it.
const TRIGGERS: &[&str] = &["|", " ", ":", ".", "(", ",", "`", "="];

/// The `opentide/*` requests, and the test-only ones of debug builds.
pub mod custom {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    /// Analyse a text that need not be open: `{ text, language?, uri? }` →
    /// `{ diagnostics }` in the engine's own shape.
    pub enum Analyze {}
    impl lsp_types::request::Request for Analyze {
        type Params = TextParams;
        type Result = Value;
        const METHOD: &'static str = "opentide/analyze";
    }

    /// Highlight a text: `{ text, language? }` → the engine's tokens.
    pub enum Highlight {}
    impl lsp_types::request::Request for Highlight {
        type Params = TextParams;
        type Result = Value;
        const METHOD: &'static str = "opentide/highlight";
    }

    /// The KQL Sentinel runs for a query: `{ query, tenant? }` → `{ compiled }`.
    pub enum CompiledKql {}
    impl lsp_types::request::Request for CompiledKql {
        type Params = QueryParams;
        type Result = Compiled;
        const METHOD: &'static str = "opentide/compiledKql";
    }

    /// The SPL Splunk runs for a search: `{ query }` → `{ compiled }`.
    pub enum CompiledSpl {}
    impl lsp_types::request::Request for CompiledSpl {
        type Params = QueryParams;
        type Result = Compiled;
        const METHOD: &'static str = "opentide/compiledSpl";
    }

    /// A workspace file as the server sees it (the open buffer first):
    /// `{ path }` → `{ text }`.
    pub enum FsRead {}
    impl lsp_types::request::Request for FsRead {
        type Params = PathParams;
        type Result = Text;
        const METHOD: &'static str = "opentide/fs/read";
    }

    /// The workspace index, for catalogue and graph views (#198):
    /// `{ root? }` → `{ roots: [{ root, objects: [{ uuid, object_type,
    /// schema, name, uri, range, refs: [{ uuid, field_path, range }] }] }] }`.
    pub enum Catalog {}
    impl lsp_types::request::Request for Catalog {
        /// Every key is optional, so are the params: a request without
        /// them, or with `null`, asks for every root.
        type Params = Option<CatalogParams>;
        type Result = Value;
        const METHOD: &'static str = "opentide/catalog";
    }

    /// The workspace a host supplied on `initialize` changed: `{ documents?,
    /// objects?, removed?, visibility? }`, merged into it
    /// (`Supplied::apply`). A host with no filesystem sends it when the files
    /// it supplied change; `experimental.opentide.workspaceUpdates` says the
    /// server takes it.
    pub enum DidChangeWorkspace {}
    impl lsp_types::notification::Notification for DidChangeWorkspace {
        type Params = Value;
        const METHOD: &'static str = "opentide/didChangeWorkspace";
    }

    /// Sent after a root's index changed, once the client has asked for its
    /// catalog: `{ root }`.
    pub enum CatalogChanged {}
    impl lsp_types::notification::Notification for CatalogChanged {
        type Params = CatalogChangedParams;
        const METHOD: &'static str = "opentide/catalogChanged";
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    #[serde(default)]
    pub struct CatalogParams {
        /// A root's URI; every root without it.
        pub root: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct CatalogChangedParams {
        /// The root's URI, or `null` for the documents outside every root.
        pub root: Value,
    }

    /// Debug builds: a handler that panics, for the isolation test.
    #[cfg(debug_assertions)]
    pub enum Panic {}
    #[cfg(debug_assertions)]
    impl lsp_types::request::Request for Panic {
        type Params = Option<Value>;
        type Result = ();
        const METHOD: &'static str = "opentide/__panic";
    }

    /// Debug builds: a request that takes `ms` milliseconds, so the messages
    /// sent meanwhile queue up as one batch.
    #[cfg(debug_assertions)]
    pub enum Sleep {}
    #[cfg(debug_assertions)]
    impl lsp_types::request::Request for Sleep {
        type Params = SleepParams;
        type Result = ();
        const METHOD: &'static str = "opentide/__sleep";
    }

    #[cfg(debug_assertions)]
    #[derive(Debug, Default, Deserialize, Serialize)]
    #[serde(default)]
    pub struct SleepParams {
        pub ms: u64,
    }

    /// Debug builds: how many analyses ran, for the cache tests.
    #[cfg(debug_assertions)]
    pub enum Stats {}
    #[cfg(debug_assertions)]
    impl lsp_types::request::Request for Stats {
        type Params = Option<Value>;
        type Result = Value;
        const METHOD: &'static str = "opentide/__stats";
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    #[serde(default)]
    pub struct TextParams {
        pub text: String,
        pub language: Option<String>,
        pub uri: Option<String>,
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    #[serde(default)]
    pub struct QueryParams {
        pub query: String,
        pub tenant: String,
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    #[serde(default)]
    pub struct PathParams {
        pub path: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Compiled {
        pub compiled: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Text {
        pub text: String,
    }
}

/// Routes one request to its handler, in the rust-analyzer pattern.
struct Dispatcher<'a> {
    session: &'a mut Session,
    request: Option<Request>,
    response: Option<Response>,
}

impl Dispatcher<'_> {
    fn on<R: lsp_types::request::Request>(
        mut self,
        handler: impl FnOnce(&mut Session, R::Params) -> R::Result,
    ) -> Self {
        let Some(request) = self.request.take() else {
            return self;
        };
        if request.method != R::METHOD {
            self.request = Some(request);
            return self;
        }
        self.response = Some(match serde_json::from_value::<R::Params>(request.params) {
            Ok(params) => Response::new_ok(request.id, handler(self.session, params)),
            Err(err) => Response::new_err(
                request.id,
                ErrorCode::InvalidParams as i32,
                format!("invalid params for {}: {err}", R::METHOD),
            ),
        });
        self
    }

    fn finish(self) -> Response {
        if let Some(response) = self.response {
            return response;
        }
        let request = self.request.expect("a request");
        Response::new_err(
            request.id,
            ErrorCode::MethodNotFound as i32,
            format!("method not found: {}", request.method),
        )
    }
}

/// Answer one request.
pub(crate) fn request(session: &mut Session, request: Request) -> Response {
    use lsp::request::*;
    let raw = (request.method == Initialize::METHOD).then(|| request.params.clone());
    let dispatcher = Dispatcher {
        session,
        request: Some(request),
        response: None,
    };
    #[cfg(debug_assertions)]
    let dispatcher = dispatcher
        .on::<custom::Panic>(|_, _| panic!("opentide/__panic was requested"))
        .on::<custom::Stats>(|s, _| json!({ "analyses": s.analyses.get() }))
        .on::<custom::Sleep>(|_, p| std::thread::sleep(std::time::Duration::from_millis(p.ms)));
    dispatcher
        .on::<Initialize>(|s, p| initialize(s, p, raw.as_ref().unwrap_or(&Value::Null)))
        .on::<Shutdown>(|_, ()| ())
        .on::<HoverRequest>(handle_hover)
        .on::<Completion>(handle_completion)
        .on::<ResolveCompletionItem>(handle_resolve)
        .on::<SignatureHelpRequest>(handle_signature_help)
        .on::<GotoDefinition>(handle_definition)
        .on::<References>(handle_references)
        .on::<DocumentSymbolRequest>(handle_document_symbol)
        .on::<WorkspaceSymbolRequest>(handle_workspace_symbol)
        .on::<SemanticTokensFullRequest>(handle_semantic_tokens)
        .on::<DocumentDiagnosticRequest>(handle_pull_diagnostics)
        .on::<WorkspaceDiagnosticRequest>(handle_workspace_diagnostics)
        .on::<CodeActionRequest>(handle_code_action)
        .on::<FoldingRangeRequest>(handle_folding)
        .on::<DocumentHighlightRequest>(handle_document_highlight)
        .on::<SelectionRangeRequest>(handle_selection_range)
        .on::<InlayHintRequest>(handle_inlay)
        .on::<DocumentLinkRequest>(handle_document_link)
        .on::<CodeLensRequest>(handle_code_lens)
        .on::<custom::Analyze>(handle_custom_analyze)
        .on::<custom::Highlight>(|_, p| handle_custom_highlight(p))
        .on::<custom::Catalog>(handle_catalog)
        .on::<custom::CompiledKql>(|_, p| custom::Compiled {
            compiled: compiled_kql(&p.query, &p.tenant),
        })
        .on::<custom::CompiledSpl>(|_, p| custom::Compiled {
            compiled: compiled_spl(&p.query),
        })
        .on::<custom::FsRead>(|s, p| custom::Text {
            text: s.host_for(&p.path).document(&p.path).unwrap_or_default(),
        })
        .finish()
}

/// Apply one notification. One whose params do not deserialize is logged and
/// dropped; an unknown one is dropped.
pub(crate) fn notification(session: &mut Session, notification: lsp_server::Notification) {
    use lsp::notification::*;
    fn on<N: lsp_types::notification::Notification>(
        session: &mut Session,
        notification: &mut Option<lsp_server::Notification>,
        handler: impl FnOnce(&mut Session, N::Params),
    ) {
        let Some(n) = notification.take_if(|n| n.method == N::METHOD) else {
            return;
        };
        match serde_json::from_value::<N::Params>(n.params) {
            Ok(params) => handler(session, params),
            Err(err) => session.log_warning(&format!("invalid params for {}: {err}", N::METHOD)),
        }
    }
    let mut n = Some(notification);
    on::<Initialized>(session, &mut n, |s, _| initialized(s));
    on::<DidOpenTextDocument>(session, &mut n, did_open);
    on::<DidChangeTextDocument>(session, &mut n, did_change);
    on::<DidCloseTextDocument>(session, &mut n, did_close);
    on::<DidChangeWatchedFiles>(session, &mut n, watched_files_changed);
    on::<DidChangeWorkspaceFolders>(session, &mut n, workspace_folders_changed);
    on::<custom::DidChangeWorkspace>(session, &mut n, supplied_workspace_changed);
}

// ---------------------------------------------------------------------------
// Lifecycle and capabilities.

/// Whether a client lists Markdown among the formats it renders. A client
/// that says nothing gets Markdown, as LSP's default clients render it.
fn plaintext_only(formats: Option<&Vec<lsp::MarkupKind>>) -> bool {
    formats.is_some_and(|f| !f.is_empty() && !f.contains(&lsp::MarkupKind::Markdown))
}

fn read_caps(caps: &lsp::ClientCapabilities, raw: &Value) -> crate::session::ClientCaps {
    let text = caps.text_document.as_ref();
    let workspace = caps.workspace.as_ref();
    let publish = text.and_then(|t| t.publish_diagnostics.as_ref());
    let edit = workspace.and_then(|w| w.workspace_edit.as_ref());
    // LSP names it `workspace.diagnostics`; lsp-types 0.97 reads
    // `workspace.diagnostic`. Either counts.
    let diagnostic_refresh = ["diagnostics", "diagnostic"].iter().any(|key| {
        raw.pointer(&format!("/capabilities/workspace/{key}/refreshSupport"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    });
    crate::session::ClientCaps {
        watch_files: workspace
            .and_then(|w| w.did_change_watched_files.as_ref())
            .and_then(|w| w.dynamic_registration)
            .unwrap_or(false),
        pull_diagnostics: text.and_then(|t| t.diagnostic.as_ref()).is_some() && diagnostic_refresh,
        plaintext_hover: plaintext_only(
            text.and_then(|t| t.hover.as_ref())
                .and_then(|h| h.content_format.as_ref()),
        ),
        plaintext_completion: plaintext_only(
            text.and_then(|t| t.completion.as_ref())
                .and_then(|c| c.completion_item.as_ref())
                .and_then(|i| i.documentation_format.as_ref()),
        ),
        create_files: edit.and_then(|e| e.document_changes).unwrap_or(false)
            && edit
                .and_then(|e| e.resource_operations.as_ref())
                .is_some_and(|ops| ops.contains(&lsp::ResourceOperationKind::Create)),
        rename_files: edit.and_then(|e| e.document_changes).unwrap_or(false)
            && edit
                .and_then(|e| e.resource_operations.as_ref())
                .is_some_and(|ops| ops.contains(&lsp::ResourceOperationKind::Rename)),
        code_description: publish
            .and_then(|p| p.code_description_support)
            .unwrap_or(false),
        deprecated_tag: publish
            .and_then(|p| p.tag_support.as_ref())
            .is_some_and(|t| t.value_set.contains(&lsp::DiagnosticTag::DEPRECATED)),
        related_information: publish.and_then(|p| p.related_information).unwrap_or(false),
        diagnostic_version: publish.and_then(|p| p.version_support).unwrap_or(false),
        semantic_tokens_refresh: workspace
            .and_then(|w| w.semantic_tokens.as_ref())
            .and_then(|s| s.refresh_support)
            .unwrap_or(false),
        inlay_hint_refresh: workspace
            .and_then(|w| w.inlay_hint.as_ref())
            .and_then(|s| s.refresh_support)
            .unwrap_or(false),
        code_lens_refresh: workspace
            .and_then(|w| w.code_lens.as_ref())
            .and_then(|s| s.refresh_support)
            .unwrap_or(false),
        workspace_folders: workspace.and_then(|w| w.workspace_folders).unwrap_or(false),
    }
}

fn initialize(
    session: &mut Session,
    params: lsp::InitializeParams,
    raw: &Value,
) -> lsp::InitializeResult {
    session.caps = read_caps(&params.capabilities, raw);
    // A host with no filesystem hands over its workspace (a browser worker).
    session.supplied =
        crate::session::Supplied::from_options(raw.pointer("/initializationOptions/workspace"));
    #[allow(deprecated)] // `rootUri` and `rootPath`: what clients without folders send.
    let folders: Vec<PathBuf> = match (
        &params.workspace_folders,
        &params.root_uri,
        &params.root_path,
    ) {
        (Some(folders), _, _) if !folders.is_empty() => folders
            .iter()
            .map(|f| PathBuf::from(uri_to_path(f.uri.as_str())))
            .collect(),
        (_, Some(uri), _) => vec![PathBuf::from(uri_to_path(uri.as_str()))],
        (_, _, Some(path)) => vec![PathBuf::from(path)],
        _ => Vec::new(),
    };
    session.set_folders(folders);
    let caps = &session.caps;
    let workspace = caps
        .workspace_folders
        .then_some(lsp::WorkspaceServerCapabilities {
            workspace_folders: Some(lsp::WorkspaceFoldersServerCapabilities {
                supported: Some(true),
                change_notifications: Some(lsp::OneOf::Left(true)),
            }),
            file_operations: None,
        });
    let capabilities = lsp::ServerCapabilities {
        // The engine's ranges count UTF-16 units, as every client can.
        position_encoding: Some(lsp::PositionEncodingKind::UTF16),
        text_document_sync: Some(lsp::TextDocumentSyncCapability::Kind(
            lsp::TextDocumentSyncKind::INCREMENTAL,
        )),
        hover_provider: Some(lsp::HoverProviderCapability::Simple(true)),
        completion_provider: Some(lsp::CompletionOptions {
            resolve_provider: Some(true),
            trigger_characters: Some(TRIGGERS.iter().map(|t| t.to_string()).collect()),
            ..Default::default()
        }),
        signature_help_provider: Some(lsp::SignatureHelpOptions {
            trigger_characters: Some(["(", ",", "=", "`"].map(String::from).to_vec()),
            ..Default::default()
        }),
        definition_provider: Some(lsp::OneOf::Left(true)),
        references_provider: Some(lsp::OneOf::Left(true)),
        document_symbol_provider: Some(lsp::OneOf::Left(true)),
        workspace_symbol_provider: Some(lsp::OneOf::Left(true)),
        document_highlight_provider: Some(lsp::OneOf::Left(true)),
        code_action_provider: Some(lsp::CodeActionProviderCapability::Options(
            lsp::CodeActionOptions {
                code_action_kinds: Some(vec![lsp::CodeActionKind::QUICKFIX, fix_all_kind()]),
                ..Default::default()
            },
        )),
        folding_range_provider: Some(lsp::FoldingRangeProviderCapability::Simple(true)),
        selection_range_provider: Some(lsp::SelectionRangeProviderCapability::Simple(true)),
        inlay_hint_provider: Some(lsp::OneOf::Left(true)),
        document_link_provider: Some(lsp::DocumentLinkOptions {
            resolve_provider: Some(false),
            work_done_progress_options: Default::default(),
        }),
        code_lens_provider: Some(lsp::CodeLensOptions {
            resolve_provider: Some(false),
        }),
        // Push only, unless the client pulls: a client given both shows
        // each diagnostic twice (P0.8).
        diagnostic_provider: caps.pull_diagnostics.then(|| {
            lsp::DiagnosticServerCapabilities::Options(lsp::DiagnosticOptions {
                identifier: Some("opentide".into()),
                inter_file_dependencies: true,
                workspace_diagnostics: true,
                work_done_progress_options: Default::default(),
            })
        }),
        semantic_tokens_provider: Some(
            lsp::SemanticTokensServerCapabilities::SemanticTokensOptions(
                lsp::SemanticTokensOptions {
                    legend: lsp::SemanticTokensLegend {
                        token_types: opentide_highlight::LSP_TOKEN_TYPES
                            .iter()
                            .map(|t| lsp::SemanticTokenType::new(t))
                            .collect(),
                        token_modifiers: Vec::new(),
                    },
                    full: Some(lsp::SemanticTokensFullOptions::Bool(true)),
                    range: None,
                    work_done_progress_options: Default::default(),
                },
            ),
        ),
        workspace,
        experimental: Some(json!({ "opentide": host_info() })),
        ..Default::default()
    };
    session.initialized = true;
    lsp::InitializeResult {
        capabilities,
        server_info: Some(lsp::ServerInfo {
            name: "opentide-lsp".into(),
            version: Some(crate::VERSION.into()),
        }),
    }
}

/// Ask to watch what the analysis reads from disk: `objects/` and what is in
/// it (object YAML, and the folders, since a client reports a deleted folder
/// as one event for it), the configuration TOML (with `visibility.toml`),
/// and the generated catalogs (P2.2).
fn initialized(session: &mut Session) {
    if !session.caps.watch_files {
        return;
    }
    let watchers = [
        "**/objects".to_string(),
        "**/objects/**".to_string(),
        "**/.opentide/configurations/**/*.toml".to_string(),
        format!("**/{}/*", crate::server::WORKSPACE_CATALOGS),
    ]
    .into_iter()
    .map(|glob| lsp::FileSystemWatcher {
        glob_pattern: lsp::GlobPattern::String(glob),
        kind: None,
    })
    .collect();
    let options = lsp::DidChangeWatchedFilesRegistrationOptions { watchers };
    session.send_request::<lsp::request::RegisterCapability>(lsp::RegistrationParams {
        registrations: vec![lsp::Registration {
            id: "opentide-watch".into(),
            method: lsp::notification::DidChangeWatchedFiles::METHOD.into(),
            register_options: serde_json::to_value(options).ok(),
        }],
    });
}

// ---------------------------------------------------------------------------
// Documents.

fn did_open(session: &mut Session, params: lsp::DidOpenTextDocumentParams) {
    let item = params.text_document;
    let uri = item.uri.as_str();
    let reported = Some(item.language_id.as_str());
    let Some(language) = session.language_for(uri, reported) else {
        // Not a document this server reads (`Cargo.toml`).
        return;
    };
    if language == LanguageId::TideYaml && !session.reads_as_tide(uri, reported, &item.text) {
        // Some other YAML (`.github/workflows/ci.yml`).
        return;
    }
    let path = uri_to_path(uri);
    session.discover_root(&path);
    // A byte-order mark is not text: the editor counts no column for it.
    let text = opentide_core::strip_bom(&item.text).to_string();
    let root = session.root_for(&path);
    session.docs.insert(
        uri.to_string(),
        Document {
            language,
            text,
            version: Some(item.version),
            root,
        },
    );
    document_changed(session, uri, language, root);
}

fn did_change(session: &mut Session, params: lsp::DidChangeTextDocumentParams) {
    let uri = params.text_document.uri.as_str().to_string();
    let version = params.text_document.version;
    let known = session
        .docs
        .get(&uri)
        .map(|d| (d.language, d.version, d.root));
    let (language, root) = match known {
        Some((_, Some(current), _)) if version <= current => {
            // An edit older than the text the server has (P2.6).
            session.log_warning(&format!(
                "ignoring version {version} of {uri}: version {current} is applied"
            ));
            return;
        }
        Some((language, _, root)) => (language, root),
        // A document never opened is read only when it is not YAML (whose
        // kind its text decides at didOpen).
        None => match session
            .language_for(&uri, None)
            .filter(|l| *l != LanguageId::TideYaml)
        {
            Some(language) => (language, session.root_for(&uri_to_path(&uri))),
            None => return,
        },
    };
    let current = session
        .docs
        .get(&uri)
        .map(|d| d.text.clone())
        .unwrap_or_default();
    let text = apply_content_changes(&current, &params.content_changes);
    let text = opentide_core::strip_bom(&text).to_string();
    session.docs.insert(
        uri.clone(),
        Document {
            language,
            text,
            version: Some(version),
            root,
        },
    );
    document_changed(session, &uri, language, root);
}

fn did_close(session: &mut Session, params: lsp::DidCloseTextDocumentParams) {
    let uri = params.text_document.uri.as_str();
    let Some(closed) = session.docs.remove(uri) else {
        return;
    };
    session.touch();
    if closed.language == LanguageId::TideYaml {
        // The file on disk is the object again, as last saved.
        let path = uri_to_path(uri);
        if let Some(root) = session.object_root(&path) {
            session.roots[root].refresh_object(&path);
        }
        session.invalidate_index(closed.root);
        // Another document may reference the one closed.
        session.mark_open();
    }
    session.mark(uri);
    if Session::is_visibility(uri) {
        // Back to the file on disk (unsaved edits are dropped).
        if let Some(r) = closed.root.and_then(|i| session.roots.get_mut(i)) {
            r.visibility = None;
        }
        session.reactivate();
        session.mark_all();
    } else if closed.language == LanguageId::Config {
        if Session::is_lint(uri) {
            // The Tide checks follow the file on disk again (#214).
            session.reactivate();
        }
        // The others read the file on disk again.
        session.mark_all();
    }
}

/// Publish what an opened or edited document changes. `visibility.toml`
/// declares datasets every open document is checked against, one
/// configuration file changes what another may say (a `deployment.toml`
/// status names what `sharing.toml` may share), and a Tide object can be
/// referenced by the others, so those re-check every open document. Anything
/// else re-checks itself.
fn document_changed(session: &mut Session, uri: &str, language: LanguageId, root: Option<usize>) {
    session.touch();
    session.mark(uri);
    if language == LanguageId::TideYaml {
        session.invalidate_index(root);
        session.mark_open();
    }
    if Session::is_visibility(uri) {
        let text = session.docs.get(uri).map(|d| d.text.clone());
        let parses = text
            .as_deref()
            .is_none_or(|t| opentide_analysis::check_visibility(t).is_ok());
        if let Some(r) = root.and_then(|i| session.roots.get_mut(i)) {
            r.visibility = text;
        }
        if parses {
            session.reactivate();
            session.mark_all();
        } else {
            // Mid-edit text keeps the declarations in use: only the
            // configuration documents (`visibility.toml` among them) change.
            mark_configuration(session);
        }
    } else if language == LanguageId::Config {
        let parses = !Session::is_lint(uri)
            || session
                .docs
                .get(uri)
                .is_none_or(|d| opentide_analysis::check_lint(&d.text).is_ok());
        if !parses {
            // Mid-edit lint.toml keeps the settings that last parsed (#214):
            // the Tide checks are as they were.
            mark_configuration(session);
        } else {
            if Session::is_lint(uri) {
                // lint.toml decides the filename and metadata checks (#214).
                session.reactivate();
            }
            session.mark_all();
        }
    }
}

/// Re-check the open configuration documents only: a configuration file
/// that does not parse yet changes what the others may say, not the
/// settings the other documents are checked under.
fn mark_configuration(session: &Session) {
    let config: Vec<String> = session
        .docs
        .iter()
        .filter(|(_, d)| d.language == LanguageId::Config)
        .map(|(u, _)| u.clone())
        .collect();
    for uri in config {
        session.mark(&uri);
    }
}

fn apply_content_changes(text: &str, changes: &[lsp::TextDocumentContentChangeEvent]) -> String {
    let mut current = text.to_string();
    for change in changes {
        current = match change.range {
            Some(range) => {
                let start = offset(&current, range.start);
                let end = offset(&current, range.end).max(start);
                let mut out = String::with_capacity(current.len() + change.text.len());
                out.push_str(&current[..start]);
                out.push_str(&change.text);
                out.push_str(&current[end..]);
                out
            }
            None => change.text.clone(),
        };
    }
    current
}

/// Read again the files a watcher reports: an object file re-indexes its
/// root, and so does a folder under `objects/` that is or was one of
/// objects; `visibility.toml` (unless open), a configuration file or a
/// catalog re-checks every open document.
fn watched_files_changed(session: &mut Session, params: lsp::DidChangeWatchedFilesParams) {
    let mut everything = false;
    for change in &params.changes {
        let uri = change.uri.as_str();
        let path = uri_to_path(uri);
        let normalized = path.replace('\\', "/");
        if let Some(root) = session.object_root(&path) {
            if !session.docs.contains_key(uri) {
                session.roots[root].refresh_object(&path);
                session.touch();
                everything = true;
            }
        } else if let Some(root) = session.folder_root(&path) {
            if session.roots[root].refresh_folder(&path) {
                session.touch();
                everything = true;
            }
        } else if Session::is_visibility(uri) {
            let open = session
                .root_for(&path)
                .and_then(|i| session.roots.get(i))
                .is_some_and(|r| r.visibility.is_some());
            // While the file is open the editor's buffer is the truth.
            if !open {
                session.reactivate();
                everything = true;
            }
        } else if normalized.contains(".opentide/configurations/") {
            session.touch();
            if Session::is_lint(uri) && !session.docs.contains_key(uri) {
                // A file that does not parse keeps the settings in use
                // (#214); one that is gone is the defaults.
                let parses = std::fs::read_to_string(&path)
                    .map_or(true, |text| opentide_analysis::check_lint(&text).is_ok());
                if !parses {
                    mark_configuration(session);
                    continue;
                }
                session.reactivate();
            }
            everything = true;
        } else if normalized.contains(crate::server::WORKSPACE_CATALOGS) {
            session.log_info(&format!("{path} changed: reading the catalogs again"));
            session.reactivate();
            everything = true;
        }
    }
    if everything {
        session.mark_all();
    }
}

/// `opentide/didChangeWorkspace`: merge the change into the supplied
/// workspace, and when it changed something, re-index and re-check.
fn supplied_workspace_changed(session: &mut Session, params: Value) {
    if !params.is_object() {
        session.log_warning("invalid params for opentide/didChangeWorkspace: not an object");
        return;
    }
    if session.supplied.apply(&params) {
        session.supplied_changed();
    }
}

fn workspace_folders_changed(session: &mut Session, params: lsp::DidChangeWorkspaceFoldersParams) {
    let removed: Vec<PathBuf> = params
        .event
        .removed
        .iter()
        .map(|f| PathBuf::from(uri_to_path(f.uri.as_str())))
        .collect();
    let mut folders: Vec<PathBuf> = session.roots[..session.folders]
        .iter()
        .map(|r: &Root| r.path.clone())
        .filter(|p| !removed.contains(p))
        .collect();
    for added in &params.event.added {
        let path = PathBuf::from(uri_to_path(added.uri.as_str()));
        if !folders.contains(&path) {
            folders.push(path);
        }
    }
    session.set_folders(folders);
}

// ---------------------------------------------------------------------------
// Conversions.

/// The byte offset of an editor position: its column counts UTF-16 units,
/// and the offset always falls on a character boundary. A column past the
/// end of its line clamps to the line's end.
fn offset(text: &str, position: lsp::Position) -> usize {
    opentide_core::position_to_offset(text, Position::new(position.line, position.character))
}

fn lsp_position(position: Position) -> lsp::Position {
    lsp::Position::new(position.line, position.character)
}

fn lsp_range(range: Range) -> lsp::Range {
    lsp::Range::new(lsp_position(range.start), lsp_position(range.end))
}

fn span_range(text: &str, span: ByteSpan) -> lsp::Range {
    lsp_range(span_to_range(text, span))
}

fn file_uri(path: &str) -> Option<lsp::Uri> {
    path_to_uri(path).parse().ok()
}

/// Markdown, or the same text as plain text for a client that renders no
/// Markdown (P2.6).
fn markup(plain: bool, value: String) -> lsp::MarkupContent {
    if plain {
        lsp::MarkupContent {
            kind: lsp::MarkupKind::PlainText,
            value: plain_text(&value),
        }
    } else {
        lsp::MarkupContent {
            kind: lsp::MarkupKind::Markdown,
            value,
        }
    }
}

/// Markdown read as text: emphasis and code marks dropped, a fenced block's
/// fences dropped and its body kept.
fn plain_text(markdown: &str) -> String {
    markdown
        .lines()
        .filter(|line| !line.trim_start().starts_with("```"))
        .map(|line| {
            let line = line.trim_start_matches('#').trim_start_matches(' ');
            line.replace("**", "").replace('`', "")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The open document a position names, with the byte offset of the position.
fn at<'a>(
    session: &'a Session,
    params: &lsp::TextDocumentPositionParams,
) -> Option<(&'a str, &'a Document, usize)> {
    let (uri, doc) = session
        .docs
        .get_key_value(params.text_document.uri.as_str())?;
    Some((uri.as_str(), doc, offset(&doc.text, params.position)))
}

// ---------------------------------------------------------------------------
// Diagnostics.

/// One engine diagnostic as LSP sends it, pushed or pulled alike. The
/// optional parts follow what the client said it reads (P2.3).
fn lsp_diagnostic(
    session: &Session,
    root: Option<usize>,
    path: &str,
    d: &opentide_core::Diagnostic,
) -> lsp::Diagnostic {
    let caps = &session.caps;
    let tags = (caps.deprecated_tag && is_deprecation(&d.code))
        .then(|| vec![lsp::DiagnosticTag::DEPRECATED]);
    let code_description = caps
        .code_description
        .then(|| format!("{DIAGNOSTICS_DOCS}#{}", d.code).parse().ok())
        .flatten()
        .map(|href| lsp::CodeDescription { href });
    let related_information = (caps.related_information && d.code == codes::DUPLICATE_ID)
        .then(|| duplicates(session, root, path, d))
        .filter(|related| !related.is_empty());
    lsp::Diagnostic {
        range: lsp_range(d.range),
        severity: Some(match d.severity {
            opentide_core::Severity::Error => lsp::DiagnosticSeverity::ERROR,
            opentide_core::Severity::Warning => lsp::DiagnosticSeverity::WARNING,
            opentide_core::Severity::Information => lsp::DiagnosticSeverity::INFORMATION,
            opentide_core::Severity::Hint => lsp::DiagnosticSeverity::HINT,
        }),
        code: Some(lsp::NumberOrString::String(d.code.clone())),
        code_description,
        source: Some("opentide".into()),
        message: d.message.clone(),
        related_information,
        tags,
        data: Some(json!({ "field_path": d.field_path, "suggestion": d.suggestion })),
    }
}

fn is_deprecation(code: &str) -> bool {
    matches!(
        code,
        codes::DEPRECATED_FIELD | codes::KQL_DEPRECATED_FUNCTION | codes::KQL_DEPRECATED_OPERATOR
    ) || code.contains("deprecated")
}

/// The other files that carry a duplicated UUID, each at its UUID.
fn duplicates(
    session: &Session,
    root: Option<usize>,
    path: &str,
    d: &opentide_core::Diagnostic,
) -> Vec<lsp::DiagnosticRelatedInformation> {
    let Some(uuid) = uuid_pattern()
        .find(&d.message)
        .map(|m| m.as_str().to_string())
    else {
        return Vec::new();
    };
    let host = session.host(root);
    let own = crate::session::path_key(path);
    workspace_index(&host)
        .iter()
        .filter(|o| o.uuid == uuid && crate::session::path_key(&o.path) != own)
        .filter_map(|o| {
            let text = host.document(&o.path)?;
            let span = opentide_tide::uuid_span(&text, &uuid)?;
            Some(lsp::DiagnosticRelatedInformation {
                location: lsp::Location {
                    uri: file_uri(&o.path)?,
                    range: span_range(&text, span),
                },
                message: format!("{} {} also has this UUID", o.object_type, o.name),
            })
        })
        .collect()
}

/// An open document's diagnostics, from its cached analysis.
pub(crate) fn diagnostics_for(session: &Session, uri: &str) -> Vec<lsp::Diagnostic> {
    let Some(analysis) = session.analysis(uri) else {
        return Vec::new();
    };
    let root = session.docs.get(uri).and_then(|d| d.root);
    let path = uri_to_path(uri);
    analysis
        .diagnostics
        .iter()
        .map(|d| lsp_diagnostic(session, root, &path, d))
        .collect()
}

/// A report's id: the same diagnostics give the same id, so a client that
/// pulls again gets `unchanged`.
fn result_id(items: &[lsp::Diagnostic]) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_string(items)
        .unwrap_or_default()
        .hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn handle_pull_diagnostics(
    session: &mut Session,
    params: lsp::DocumentDiagnosticParams,
) -> lsp::DocumentDiagnosticReportResult {
    let items = diagnostics_for(session, params.text_document.uri.as_str());
    let id = result_id(&items);
    let report = if params.previous_result_id.as_deref() == Some(id.as_str()) {
        lsp::DocumentDiagnosticReport::Unchanged(lsp::RelatedUnchangedDocumentDiagnosticReport {
            related_documents: None,
            unchanged_document_diagnostic_report: lsp::UnchangedDocumentDiagnosticReport {
                result_id: id,
            },
        })
    } else {
        lsp::DocumentDiagnosticReport::Full(lsp::RelatedFullDocumentDiagnosticReport {
            related_documents: None,
            full_document_diagnostic_report: lsp::FullDocumentDiagnosticReport {
                result_id: Some(id),
                items,
            },
        })
    };
    lsp::DocumentDiagnosticReportResult::Report(report)
}

/// The object files no editor has open, with what their analysis finds:
/// a `duplicate_id` or `invalid_ref` in a file nobody opened (P3.6).
fn handle_workspace_diagnostics(
    session: &mut Session,
    params: lsp::WorkspaceDiagnosticParams,
) -> lsp::WorkspaceDiagnosticReportResult {
    let previous: HashMap<String, String> = params
        .previous_result_ids
        .into_iter()
        .map(|p| (p.uri.as_str().to_string(), p.value))
        .collect();
    let open: BTreeSet<String> = session
        .docs
        .keys()
        .map(|uri| crate::session::path_key(&uri_to_path(uri)))
        .collect();
    let mut items = Vec::new();
    for root in 0..session.roots.len() {
        let host = session.host(Some(root));
        for (path, text) in session.closed_objects(root) {
            if open.contains(&crate::session::path_key(&path)) {
                continue;
            }
            let Some(uri) = file_uri(&path) else {
                continue;
            };
            let response = opentide_analysis::analyze(
                &host,
                opentide_analysis::AnalyzeRequest {
                    uri: path.clone(),
                    language: LanguageId::TideYaml,
                    text,
                },
            );
            let found: Vec<lsp::Diagnostic> = response
                .diagnostics
                .iter()
                .map(|d| lsp_diagnostic(session, Some(root), &path, d))
                .collect();
            let id = result_id(&found);
            items.push(if previous.get(uri.as_str()) == Some(&id) {
                lsp::WorkspaceDocumentDiagnosticReport::Unchanged(
                    lsp::WorkspaceUnchangedDocumentDiagnosticReport {
                        uri,
                        version: None,
                        unchanged_document_diagnostic_report:
                            lsp::UnchangedDocumentDiagnosticReport { result_id: id },
                    },
                )
            } else {
                lsp::WorkspaceDocumentDiagnosticReport::Full(
                    lsp::WorkspaceFullDocumentDiagnosticReport {
                        uri,
                        version: None,
                        full_document_diagnostic_report: lsp::FullDocumentDiagnosticReport {
                            result_id: Some(id),
                            items: found,
                        },
                    },
                )
            });
        }
    }
    lsp::WorkspaceDiagnosticReportResult::Report(lsp::WorkspaceDiagnosticReport { items })
}

// ---------------------------------------------------------------------------
// Hover, completion, signature help.

fn handle_hover(session: &mut Session, params: lsp::HoverParams) -> Option<lsp::Hover> {
    let (uri, doc, offset) = at(session, &params.text_document_position_params)?;
    let value = if doc.language == LanguageId::Config {
        configuration_hover(&uri_to_path(uri), &doc.text, offset)?
    } else {
        let host = session.host(doc.root);
        hover(&host, doc.language, &doc.text, offset)?
    };
    Some(lsp::Hover {
        contents: lsp::HoverContents::Markup(markup(session.caps.plaintext_hover, value)),
        range: None,
    })
}

fn completion_kind(kind: &str) -> lsp::CompletionItemKind {
    match kind {
        "operator" | "keyword" | "command" => lsp::CompletionItemKind::KEYWORD,
        "function" | "plugin" => lsp::CompletionItemKind::FUNCTION,
        "table" | "type" => lsp::CompletionItemKind::CLASS,
        "column" | "property" => lsp::CompletionItemKind::FIELD,
        "macro" => lsp::CompletionItemKind::TYPE_PARAMETER,
        "enum" => lsp::CompletionItemKind::ENUM,
        "reference" => lsp::CompletionItemKind::REFERENCE,
        "module" => lsp::CompletionItemKind::MODULE,
        _ => lsp::CompletionItemKind::TEXT,
    }
}

/// What resolve needs to find an item's documentation again: the language,
/// and for a Tide value the schema and field it is a value of (P0.9).
#[derive(Debug, Default, Serialize, Deserialize)]
struct ItemData {
    language: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    field_path: Option<String>,
}

fn handle_completion(
    session: &mut Session,
    params: lsp::CompletionParams,
) -> Option<lsp::CompletionResponse> {
    let (uri, doc, offset) = at(session, &params.text_document_position)?;
    let typed_space = params.context.as_ref().is_some_and(|c| {
        c.trigger_kind == lsp::CompletionTriggerKind::TRIGGER_CHARACTER
            && c.trigger_character.as_deref() == Some(" ")
    });
    if typed_space && doc.language == LanguageId::TideYaml {
        return None;
    }
    let position = params.text_document_position.position;
    // A dotted field label (`process.parent.name`) replaces the whole dotted
    // prefix already typed. Editors split words at `.`, so plain insertText
    // would append after `process.`.
    let before = &doc.text[..offset.min(doc.text.len())];
    let dotted = &before[opentide_core::word_start(before, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-')
    })..];
    let start = lsp::Position::new(
        position.line,
        position
            .character
            .saturating_sub(dotted.encode_utf16().count() as u32),
    );
    let found = if doc.language == LanguageId::Config {
        configuration_completions(&uri_to_path(uri), &doc.text, offset)
    } else {
        let host = session.host(doc.root);
        completions(&host, doc.language, &doc.text, offset)
    };
    let plain = session.caps.plaintext_completion;
    let items = found
        .into_iter()
        .map(|c| {
            // Any label that extends the typed word replaces the whole of
            // it: a client that splits words at `.` would otherwise filter
            // and insert after the last dot.
            let dotted_edit = !dotted.is_empty() && c.label.starts_with(dotted);
            let field = (c.kind == "enum")
                .then(|| c.detail.as_deref()?.split_once(' '))
                .flatten();
            let data = ItemData {
                language: doc.language.as_str().into(),
                schema: field.map(|(schema, _)| schema.to_string()),
                field_path: field.map(|(_, path)| path.to_string()),
            };
            lsp::CompletionItem {
                kind: Some(completion_kind(&c.kind)),
                detail: c.detail.clone(),
                documentation: c
                    .documentation
                    .map(|d| lsp::Documentation::MarkupContent(markup(plain, d))),
                insert_text: Some(c.label.clone()),
                filter_text: dotted_edit.then(|| c.label.clone()),
                text_edit: dotted_edit.then(|| {
                    lsp::CompletionTextEdit::Edit(lsp::TextEdit {
                        range: lsp::Range::new(start, position),
                        new_text: c.label.clone(),
                    })
                }),
                data: serde_json::to_value(data).ok(),
                label: c.label,
                ..Default::default()
            }
        })
        .collect();
    Some(lsp::CompletionResponse::Array(items))
}

/// The client's item with documentation (and a detail) added: its edit and
/// filter text are left as they are (P0.9). A Tide value is documented from
/// the field its `data` names, not from the first field with that value.
fn handle_resolve(session: &mut Session, mut item: lsp::CompletionItem) -> lsp::CompletionItem {
    let data: ItemData = item
        .data
        .clone()
        .and_then(|d| serde_json::from_value(d).ok())
        .unwrap_or_default();
    let kind = match item.kind {
        Some(lsp::CompletionItemKind::FIELD) => "property",
        Some(lsp::CompletionItemKind::ENUM) => "enum",
        Some(lsp::CompletionItemKind::REFERENCE) => "reference",
        _ => "property",
    };
    let mut engine = opentide_core::CompletionItem::new(item.label.clone(), kind);
    let field_detail = match (&data.schema, &data.field_path) {
        (Some(schema), Some(path)) => Some(format!("{schema} {path}")),
        _ => item.detail.clone(),
    };
    if let Some(detail) = field_detail {
        engine = engine.with_detail(detail);
    }
    let resolved = opentide_tide::resolve_completion(engine);
    if item.documentation.is_none()
        && let Some(docs) = resolved.documentation
    {
        item.documentation = Some(lsp::Documentation::MarkupContent(markup(
            session.caps.plaintext_completion,
            docs,
        )));
    }
    if item.detail.is_none() {
        item.detail = resolved.detail;
    }
    item
}

fn handle_signature_help(
    session: &mut Session,
    params: lsp::SignatureHelpParams,
) -> Option<lsp::SignatureHelp> {
    let (_, doc, offset) = at(session, &params.text_document_position_params)?;
    let host = session.host(doc.root);
    let help = signature_help(&host, doc.language, &doc.text, offset)?;
    Some(lsp::SignatureHelp {
        signatures: help
            .signatures
            .into_iter()
            .map(|s| lsp::SignatureInformation {
                label: s.label,
                documentation: s.documentation.map(lsp::Documentation::String),
                parameters: Some(
                    s.parameters
                        .into_iter()
                        .map(|p| lsp::ParameterInformation {
                            label: lsp::ParameterLabel::Simple(p.label),
                            documentation: p.documentation.map(lsp::Documentation::String),
                        })
                        .collect(),
                ),
                active_parameter: None,
            })
            .collect(),
        active_signature: Some(help.active_signature),
        active_parameter: Some(help.active_parameter),
    })
}

// ---------------------------------------------------------------------------
// Navigation.

fn uuid_pattern() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        )
        .expect("UUID pattern")
    })
}

/// The UUID under the cursor, the cursor touching either end. A column past
/// the end of its line is on no UUID.
pub(crate) fn uuid_at(text: &str, position: lsp::Position) -> Option<String> {
    let line = text.lines().nth(position.line as usize)?;
    if position.character as usize > line.encode_utf16().count() {
        return None;
    }
    let at = offset(text, position);
    uuid_pattern()
        .find_iter(text)
        .find(|m| m.start() <= at && at <= m.end())
        .map(|m| m.as_str().to_string())
}

/// Where an object's UUID is in its file (the open buffer first), or its
/// first line.
fn object_location(host: &dyn WorkspaceHost, path: &str, uuid: &str) -> Option<lsp::Location> {
    let source = host.document(path).unwrap_or_default();
    let range = opentide_tide::uuid_span(&source, uuid)
        .map(|span| span_range(&source, span))
        .unwrap_or_default();
    Some(lsp::Location {
        uri: file_uri(path)?,
        range,
    })
}

fn handle_definition(
    session: &mut Session,
    params: lsp::GotoDefinitionParams,
) -> Option<lsp::GotoDefinitionResponse> {
    let position = &params.text_document_position_params;
    let doc = session.docs.get(position.text_document.uri.as_str())?;
    let uuid = uuid_at(&doc.text, position.position)?;
    let host = session.host(doc.root);
    let workspace = workspace_index(&host);
    let object = opentide_tide::definition(&workspace, &uuid)?;
    object_location(&host, &object.path, &uuid).map(lsp::GotoDefinitionResponse::Scalar)
}

fn handle_references(
    session: &mut Session,
    params: lsp::ReferenceParams,
) -> Option<Vec<lsp::Location>> {
    let position = &params.text_document_position;
    let doc = session.docs.get(position.text_document.uri.as_str())?;
    let Some(uuid) = uuid_at(&doc.text, position.position) else {
        return Some(Vec::new());
    };
    let host = session.host(doc.root);
    let workspace = workspace_index(&host);
    Some(
        opentide_tide::find_refs(&workspace, &uuid)
            .into_iter()
            .filter_map(|o| {
                let source = host.document(&o.path)?;
                let span = opentide_tide::uuid_span(&source, &uuid)?;
                Some(lsp::Location {
                    uri: file_uri(&o.path)?,
                    range: span_range(&source, span),
                })
            })
            .collect(),
    )
}

fn handle_document_highlight(
    session: &mut Session,
    params: lsp::DocumentHighlightParams,
) -> Option<Vec<lsp::DocumentHighlight>> {
    let position = &params.text_document_position_params;
    let doc = session.docs.get(position.text_document.uri.as_str())?;
    let Some(uuid) = uuid_at(&doc.text, position.position) else {
        return Some(Vec::new());
    };
    let lines = LineIndex::new(&doc.text);
    Some(
        doc.text
            .match_indices(&uuid)
            .map(|(start, _)| lsp::DocumentHighlight {
                range: lsp_range(lines.range(ByteSpan::new(start, start + uuid.len()))),
                kind: Some(lsp::DocumentHighlightKind::TEXT),
            })
            .collect(),
    )
}

#[allow(deprecated)] // `DocumentSymbol::deprecated` and `SymbolInformation::deprecated`: superseded by tags.
fn symbol(text: &str, node: &opentide_tide::OutlineNode) -> lsp::DocumentSymbol {
    lsp::DocumentSymbol {
        name: node.name.clone(),
        detail: node.detail.clone(),
        kind: match node.kind {
            opentide_tide::OutlineKind::Object => lsp::SymbolKind::CLASS,
            opentide_tide::OutlineKind::Section => lsp::SymbolKind::NAMESPACE,
            opentide_tide::OutlineKind::Platform => lsp::SymbolKind::OBJECT,
            opentide_tide::OutlineKind::Query => lsp::SymbolKind::STRING,
        },
        tags: None,
        deprecated: None,
        range: span_range(text, node.span),
        selection_range: span_range(text, node.selection),
        children: Some(node.children.iter().map(|c| symbol(text, c)).collect()),
    }
}

/// A Tide object as a tree: the object, its sections, each platform block
/// and each query (P3.1). Any other document lists the engine's symbols.
#[allow(deprecated)]
fn handle_document_symbol(
    session: &mut Session,
    params: lsp::DocumentSymbolParams,
) -> Option<lsp::DocumentSymbolResponse> {
    let uri = params.text_document.uri.as_str();
    let doc = session.docs.get(uri)?;
    if doc.language == LanguageId::TideYaml {
        let tree = opentide_tide::outline(&doc.text);
        return Some(lsp::DocumentSymbolResponse::Nested(
            tree.iter().map(|node| symbol(&doc.text, node)).collect(),
        ));
    }
    let analysis = session.analysis(uri)?;
    Some(lsp::DocumentSymbolResponse::Nested(
        analysis
            .symbols
            .iter()
            .map(|s| lsp::DocumentSymbol {
                name: s.name.clone(),
                detail: s.detail.clone(),
                kind: lsp::SymbolKind::CLASS,
                tags: None,
                deprecated: None,
                range: lsp_range(s.range),
                selection_range: lsp_range(s.range),
                children: None,
            })
            .collect(),
    ))
}

#[allow(deprecated)]
fn handle_workspace_symbol(
    session: &mut Session,
    params: lsp::WorkspaceSymbolParams,
) -> Option<lsp::WorkspaceSymbolResponse> {
    let mut symbols = Vec::new();
    let roots: Vec<Option<usize>> = if session.roots.is_empty() {
        vec![None]
    } else {
        (0..session.roots.len()).map(Some).collect()
    };
    let mut seen = BTreeSet::new();
    for root in roots {
        let host = session.host(root);
        let workspace = workspace_index(&host);
        for o in opentide_tide::workspace_symbols(&workspace, &params.query) {
            if !seen.insert(crate::session::path_key(&o.path)) {
                continue;
            }
            // The open buffer, else the file the index read.
            let text = host.document(&o.path).unwrap_or_default();
            let Some(uri) = file_uri(&o.path) else {
                continue;
            };
            symbols.push(lsp::SymbolInformation {
                name: o.name.clone(),
                kind: lsp::SymbolKind::CLASS,
                tags: None,
                deprecated: None,
                location: lsp::Location {
                    uri,
                    range: name_token_range(&text, &o.name),
                },
                container_name: Some(o.object_type.clone()),
            });
        }
    }
    Some(lsp::WorkspaceSymbolResponse::Flat(symbols))
}

fn name_token_range(text: &str, name: &str) -> lsp::Range {
    match text.find(name) {
        Some(start) if !name.is_empty() => {
            span_range(text, ByteSpan::new(start, start + name.len()))
        }
        _ => lsp::Range::new(lsp::Position::new(0, 0), lsp::Position::new(0, 1)),
    }
}

/// ATT&CK ids to their pages, and UUIDs to the object's file (P3.2).
fn handle_document_link(
    session: &mut Session,
    params: lsp::DocumentLinkParams,
) -> Option<Vec<lsp::DocumentLink>> {
    let doc = session.docs.get(params.text_document.uri.as_str())?;
    if doc.language != LanguageId::TideYaml {
        return Some(Vec::new());
    }
    let host = session.host(doc.root);
    let workspace = workspace_index(&host);
    Some(
        opentide_tide::document_links(&doc.text, &workspace)
            .into_iter()
            .filter_map(|link| {
                let target = match link.target {
                    opentide_tide::LinkTarget::Url(url) => url.parse().ok()?,
                    opentide_tide::LinkTarget::Object { path } => file_uri(&path)?,
                };
                Some(lsp::DocumentLink {
                    range: span_range(&doc.text, link.span),
                    target: Some(target),
                    tooltip: Some(link.tooltip),
                    data: None,
                })
            })
            .collect(),
    )
}

/// The command a reference lens runs: a client shows the locations it is
/// given (`opentide.showReferences`, see docs/EDITORS.md).
pub const SHOW_REFERENCES: &str = "opentide.showReferences";

/// "N rules use this objective" on an object's UUID, from the cached index
/// (P3.3).
fn handle_code_lens(
    session: &mut Session,
    params: lsp::CodeLensParams,
) -> Option<Vec<lsp::CodeLens>> {
    let uri = params.text_document.uri;
    let doc = session.docs.get(uri.as_str())?;
    if doc.language != LanguageId::TideYaml {
        return Some(Vec::new());
    }
    let host = session.host(doc.root);
    let workspace = workspace_index(&host);
    let Some(lens) = opentide_tide::reference_lens(&doc.text, &workspace) else {
        return Some(Vec::new());
    };
    let schema = opentide_tide::document_schema_id(&doc.text);
    let own_type = schema.split("::").next().unwrap_or("object");
    if lens.referenced_by.is_empty() && !matches!(own_type, "objective" | "threat") {
        return Some(Vec::new());
    }
    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for object in &lens.referenced_by {
        *counts.entry(object.object_type.as_str()).or_default() += 1;
    }
    let title = if counts.is_empty() {
        format!("No object uses this {own_type}")
    } else {
        let parts: Vec<String> = counts
            .iter()
            .map(|(kind, n)| format!("{n} {kind}{}", if *n == 1 { "" } else { "s" }))
            .collect();
        let verb = if lens.referenced_by.len() == 1 {
            "uses"
        } else {
            "use"
        };
        format!("{} {verb} this {own_type}", parts.join(", "))
    };
    let range = span_range(&doc.text, lens.span);
    let locations: Vec<lsp::Location> = lens
        .referenced_by
        .iter()
        .filter_map(|o| object_location(&host, &o.path, &lens.uuid))
        .collect();
    Some(vec![lsp::CodeLens {
        range,
        command: Some(lsp::Command {
            title,
            command: SHOW_REFERENCES.into(),
            arguments: Some(vec![json!(uri), json!(range.start), json!(locations)]),
        }),
        data: None,
    }])
}

// ---------------------------------------------------------------------------
// Code actions.

/// What a quick fix needs of a diagnostic.
struct Finding {
    diagnostic: lsp::Diagnostic,
    code: String,
    field_path: Option<Vec<String>>,
    suggestion: Option<String>,
}

impl Finding {
    /// A diagnostic the client sends back: its `data` carries the field path
    /// and suggestion the server put there.
    fn from_client(d: lsp::Diagnostic) -> Option<Self> {
        let lsp::NumberOrString::String(code) = d.code.clone()? else {
            return None;
        };
        let data = d.data.clone().unwrap_or(Value::Null);
        Some(Self {
            code,
            field_path: data
                .get("field_path")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            suggestion: data
                .get("suggestion")
                .and_then(Value::as_str)
                .map(String::from),
            diagnostic: d,
        })
    }
}

fn fix_all_kind() -> lsp::CodeActionKind {
    lsp::CodeActionKind::new("source.fixAll.opentide")
}

/// Whether a kind is one `only` asks for: itself or a kind it starts with
/// (`source` asks for `source.fixAll.opentide`).
fn wanted(only: Option<&Vec<lsp::CodeActionKind>>, kind: &lsp::CodeActionKind) -> bool {
    let Some(only) = only else {
        // Source actions are only given when asked for.
        return !kind.as_str().starts_with("source");
    };
    only.iter().any(|o| {
        kind.as_str() == o.as_str()
            || o.as_str().is_empty()
            || kind.as_str().starts_with(&format!("{}.", o.as_str()))
    })
}

/// Quick fixes for the diagnostics the client names (each carries its own
/// suggestion in `data`), or for the diagnostics in the range when it names
/// none; and, when asked for, `source.fixAll.opentide`, every suggestion of
/// the document at once (P2.4, P3.4).
fn handle_code_action(
    session: &mut Session,
    params: lsp::CodeActionParams,
) -> Option<lsp::CodeActionResponse> {
    let uri = params.text_document.uri.clone();
    let only = params.context.only.as_ref();
    let mut actions = Vec::new();
    let findings: Vec<Finding> = if params.context.diagnostics.is_empty() {
        let root = session.docs.get(uri.as_str())?.root;
        let path = uri_to_path(uri.as_str());
        let analysis = session.analysis(uri.as_str())?;
        analysis
            .diagnostics
            .iter()
            .filter(|d| {
                d.range.start.line <= params.range.end.line
                    && d.range.end.line >= params.range.start.line
            })
            .map(|d| Finding {
                diagnostic: lsp_diagnostic(session, root, &path, d),
                code: d.code.clone(),
                field_path: d.field_path.clone(),
                suggestion: d.suggestion.clone(),
            })
            .collect()
    } else {
        params
            .context
            .diagnostics
            .iter()
            .filter(|d| d.source.as_deref().is_none_or(|s| s == "opentide"))
            .cloned()
            .filter_map(Finding::from_client)
            .collect()
    };
    if wanted(only, &lsp::CodeActionKind::QUICKFIX) {
        for finding in &findings {
            let Some(suggestion) = &finding.suggestion else {
                continue;
            };
            if finding.code == codes::FILENAME_SLUG {
                // A file name, not text: rename the file where the client can.
                actions.extend(rename_action(session, &uri, finding, suggestion));
                continue;
            }
            actions.push(lsp::CodeActionOrCommand::CodeAction(lsp::CodeAction {
                title: format!("Apply suggestion: {suggestion}"),
                kind: Some(lsp::CodeActionKind::QUICKFIX),
                diagnostics: Some(vec![finding.diagnostic.clone()]),
                edit: Some(lsp::WorkspaceEdit {
                    changes: Some(HashMap::from([(
                        uri.clone(),
                        vec![lsp::TextEdit {
                            range: finding.diagnostic.range,
                            new_text: suggestion.clone(),
                        }],
                    )])),
                    ..Default::default()
                }),
                // The one fix the diagnostic offers.
                is_preferred: Some(true),
                ..Default::default()
            }));
        }
        actions.extend(declare_actions(session, &uri, &findings));
    }
    if wanted(only, &fix_all_kind())
        && let Some(action) = fix_all(session, &uri)
    {
        actions.push(action);
    }
    Some(actions)
}

/// "Rename the file to {name}" for `filename_slug` (#215): its suggestion is
/// the file name the object should have, next to the file. Only for a client
/// that applies `RenameFile`; the others get no action, since editing the
/// text the finding underlines (the object's name) would rename the object.
/// Only for a `file:` document, into its own directory, and never onto a
/// file that exists, is open or was supplied, except the document itself
/// under another case (a case-insensitive filesystem).
fn rename_action(
    session: &Session,
    uri: &lsp::Uri,
    finding: &Finding,
    file_name: &str,
) -> Option<lsp::CodeActionOrCommand> {
    if !session.caps.rename_files {
        return None;
    }
    let path = PathBuf::from(uri_to_path(uri.as_str()));
    let target = rename_target(uri.as_str(), file_name)?;
    if target.exists() && !(is_case_only_rename(&path, &target) && same_file(&path, &target)) {
        return None;
    }
    let key = path_key(&target.to_string_lossy());
    let taken = session
        .docs
        .keys()
        .any(|open| open != uri.as_str() && path_key(&uri_to_path(open)) == key)
        || session.supplied.files.contains_key(&key);
    if taken {
        return None;
    }
    let new_uri = path_to_uri_value(&target)?;
    Some(lsp::CodeActionOrCommand::CodeAction(lsp::CodeAction {
        title: format!("Rename the file to {file_name}"),
        kind: Some(lsp::CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![finding.diagnostic.clone()]),
        edit: Some(lsp::WorkspaceEdit {
            document_changes: Some(lsp::DocumentChanges::Operations(vec![
                lsp::DocumentChangeOperation::Op(lsp::ResourceOp::Rename(lsp::RenameFile {
                    old_uri: uri.clone(),
                    new_uri,
                    options: Some(lsp::RenameFileOptions {
                        overwrite: Some(false),
                        ignore_if_exists: Some(false),
                    }),
                    annotation_id: None,
                })),
            ])),
            ..Default::default()
        }),
        is_preferred: Some(true),
        ..Default::default()
    }))
}

/// Where a `filename_slug` rename moves the document at `uri`: `file_name`
/// in the document's own, non-empty directory. `None` for a document that is
/// not a `file:` URI (`untitled:Untitled-1`, a host's virtual file), a name
/// that is not one plain file name, or the document's own name.
fn rename_target(uri: &str, file_name: &str) -> Option<PathBuf> {
    if url::Url::parse(uri).ok()?.scheme() != "file" {
        return None;
    }
    if file_name.is_empty() || matches!(file_name, "." | "..") || file_name.contains(['/', '\\']) {
        return None;
    }
    let path = PathBuf::from(uri_to_path(uri));
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty())?;
    let target = parent.join(file_name);
    (target != path && target.parent() == Some(parent)).then_some(target)
}

/// Whether `target` is `path` with another case in its file name, in the
/// same directory: what a case-insensitive filesystem reports as existing
/// because it is the document itself.
fn is_case_only_rename(path: &std::path::Path, target: &std::path::Path) -> bool {
    let name = |p: &std::path::Path| p.file_name().and_then(|n| n.to_str()).map(str::to_string);
    match (name(path), name(target)) {
        (Some(from), Some(to)) => {
            path.parent() == target.parent()
                && from != to
                && from.to_lowercase() == to.to_lowercase()
        }
        _ => false,
    }
}

/// Whether two paths name one file on disk.
fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}

/// "Declare it in visibility.toml" for an undeclared table, sourcetype or
/// index pattern. Creating the file needs a client that can create one
/// (`resourceOperations: ["create"]`); the action is left out otherwise.
fn declare_actions(
    session: &Session,
    uri: &lsp::Uri,
    findings: &[Finding],
) -> Vec<lsp::CodeActionOrCommand> {
    let path = uri_to_path(uri.as_str());
    let root = session
        .docs
        .get(uri.as_str())
        .map(|d| d.root)
        .unwrap_or_else(|| session.root_for(&path));
    let Some(r) = root.and_then(|i| session.roots.get(i)) else {
        return Vec::new();
    };
    let file = r.path.join(VISIBILITY_CONFIGURATION);
    // An open buffer may hold edits not yet saved: the edit applies to it.
    let existing = r
        .visibility
        .clone()
        .or_else(|| std::fs::read_to_string(&file).ok());
    if existing.is_none() && !session.caps.create_files {
        return Vec::new();
    }
    let Some(target) = path_to_uri_value(&file) else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut actions = Vec::new();
    for finding in findings {
        let Some((platform, name)) = undeclared_dataset(finding) else {
            continue;
        };
        if !seen.insert((platform, name.clone())) {
            continue;
        }
        let edit = declare_dataset(existing.as_deref(), platform, &name);
        let text_edit = lsp::TextEdit {
            range: lsp_range(edit.range),
            new_text: edit.new_text,
        };
        let workspace_edit = if existing.is_some() {
            lsp::WorkspaceEdit {
                changes: Some(HashMap::from([(target.clone(), vec![text_edit])])),
                ..Default::default()
            }
        } else {
            lsp::WorkspaceEdit {
                document_changes: Some(lsp::DocumentChanges::Operations(vec![
                    lsp::DocumentChangeOperation::Op(lsp::ResourceOp::Create(lsp::CreateFile {
                        uri: target.clone(),
                        options: Some(lsp::CreateFileOptions {
                            overwrite: None,
                            ignore_if_exists: Some(true),
                        }),
                        annotation_id: None,
                    })),
                    lsp::DocumentChangeOperation::Edit(lsp::TextDocumentEdit {
                        text_document: lsp::OptionalVersionedTextDocumentIdentifier {
                            uri: target.clone(),
                            version: None,
                        },
                        edits: vec![lsp::OneOf::Left(text_edit)],
                    }),
                ])),
                ..Default::default()
            }
        };
        actions.push(lsp::CodeActionOrCommand::CodeAction(lsp::CodeAction {
            title: edit.title,
            kind: Some(lsp::CodeActionKind::QUICKFIX),
            diagnostics: Some(vec![finding.diagnostic.clone()]),
            edit: Some(workspace_edit),
            is_preferred: Some(true),
            ..Default::default()
        }));
    }
    actions
}

/// Every suggestion of the document as one edit; overlapping ones after the
/// first are left for another run.
fn fix_all(session: &Session, uri: &lsp::Uri) -> Option<lsp::CodeActionOrCommand> {
    let analysis = session.analysis(uri.as_str())?;
    let mut fixes: Vec<(Range, String)> = analysis
        .diagnostics
        .iter()
        // A file name is not an edit of the text (#215).
        .filter(|d| d.code != codes::FILENAME_SLUG)
        .filter_map(|d| Some((d.range, d.suggestion.clone()?)))
        .collect();
    fixes.sort_by_key(|(range, _)| (range.start.line, range.start.character));
    let mut edits: Vec<lsp::TextEdit> = Vec::new();
    let mut last_end: Option<Position> = None;
    for (range, new_text) in fixes {
        if last_end.is_some_and(|end| {
            (range.start.line, range.start.character) < (end.line, end.character)
        }) {
            continue;
        }
        last_end = Some(range.end);
        edits.push(lsp::TextEdit {
            range: lsp_range(range),
            new_text,
        });
    }
    if edits.is_empty() {
        return None;
    }
    Some(lsp::CodeActionOrCommand::CodeAction(lsp::CodeAction {
        title: format!(
            "Apply {} opentide suggestion{}",
            edits.len(),
            if edits.len() == 1 { "" } else { "s" }
        ),
        kind: Some(fix_all_kind()),
        edit: Some(lsp::WorkspaceEdit {
            changes: Some(HashMap::from([(uri.clone(), edits)])),
            ..Default::default()
        }),
        ..Default::default()
    }))
}

/// The dataset a "declare it in visibility.toml" diagnostic names: its
/// platform and name (quoted in the message: `'X'` for KQL, `` `X` `` for
/// SPL and Elastic).
fn undeclared_dataset(finding: &Finding) -> Option<(&'static str, String)> {
    let message = &finding.diagnostic.message;
    let name = message.split('\'').nth(1).unwrap_or_default().to_string();
    let in_defender = finding
        .field_path
        .as_ref()
        .is_some_and(|p| p.iter().any(|s| s == "defender_for_endpoint"));
    let kql = if in_defender {
        "defender_for_endpoint"
    } else {
        "sentinel"
    };
    match finding.code.as_str() {
        codes::KQL_TABLE_NOT_DECLARED => Some((kql, name)),
        // An unknown table whose message names the declaration: Sentinel's
        // warning (#111), and Defender's error once it declares tables (#147).
        codes::KQL_UNKNOWN_TABLE if message.contains("visibility.toml") => Some((kql, name)),
        // `sourcetype `syslog` is not declared ...`
        codes::SPL_DATASET_NOT_DECLARED => Some(("splunk", backticked(message)?)),
        // `index pattern `logs-*` is not declared ...`
        codes::ELASTIC_DATASET_NOT_DECLARED => Some(("elastic", backticked(message)?)),
        _ => None,
    }
}

fn backticked(message: &str) -> Option<String> {
    Some(message.split('`').nth(1)?.to_string())
}

// ---------------------------------------------------------------------------
// Structure.

fn handle_semantic_tokens(
    session: &mut Session,
    params: lsp::SemanticTokensParams,
) -> Option<lsp::SemanticTokensResult> {
    let analysis = session.analysis(params.text_document.uri.as_str());
    let data = analysis
        .map(|a| encode_lsp_semantic_tokens(&a.tokens))
        .unwrap_or_default();
    Some(lsp::SemanticTokensResult::Tokens(lsp::SemanticTokens {
        result_id: None,
        data: data
            .chunks_exact(5)
            .map(|t| lsp::SemanticToken {
                delta_line: t[0],
                delta_start: t[1],
                length: t[2],
                token_type: t[3],
                token_modifiers_bitset: t[4],
            })
            .collect(),
    }))
}

fn handle_folding(
    session: &mut Session,
    params: lsp::FoldingRangeParams,
) -> Option<Vec<lsp::FoldingRange>> {
    let doc = session.docs.get(params.text_document.uri.as_str())?;
    Some(
        folding_ranges(&doc.text)
            .into_iter()
            .map(|(start, end)| lsp::FoldingRange {
                start_line: start,
                end_line: end,
                kind: Some(lsp::FoldingRangeKind::Region),
                ..Default::default()
            })
            .collect(),
    )
}

/// Each object UUID a document names, with the object's type and name; the
/// name leads to the object's file (P3.5).
fn handle_inlay(
    session: &mut Session,
    params: lsp::InlayHintParams,
) -> Option<Vec<lsp::InlayHint>> {
    let doc = session.docs.get(params.text_document.uri.as_str())?;
    if doc.language != LanguageId::TideYaml {
        return Some(Vec::new());
    }
    let host = session.host(doc.root);
    let workspace = workspace_index(&host);
    let requested = params.range;
    Some(
        opentide_tide::inlay_hints(&doc.text, &workspace)
            .into_iter()
            .filter(|h| {
                h.position.line >= requested.start.line && h.position.line <= requested.end.line
            })
            .map(|h| {
                let location = object_location(&host, &h.path, &h.uuid);
                lsp::InlayHint {
                    position: lsp_position(h.position),
                    label: lsp::InlayHintLabel::LabelParts(vec![lsp::InlayHintLabelPart {
                        value: h.label,
                        tooltip: None,
                        location,
                        command: None,
                    }]),
                    kind: Some(lsp::InlayHintKind::TYPE),
                    text_edits: None,
                    tooltip: None,
                    padding_left: Some(true),
                    padding_right: None,
                    data: None,
                }
            })
            .collect(),
    )
}

fn handle_selection_range(
    session: &mut Session,
    params: lsp::SelectionRangeParams,
) -> Option<Vec<lsp::SelectionRange>> {
    let doc = session.docs.get(params.text_document.uri.as_str())?;
    let lines: Vec<&str> = doc.text.lines().collect();
    let width = |line: usize| {
        lines
            .get(line)
            .map_or(0, |l| l.encode_utf16().count() as u32)
    };
    Some(
        params
            .positions
            .iter()
            .map(|p| {
                let line = p.line as usize;
                let (parent_start, parent_end) = enclosing_block(&lines, line);
                lsp::SelectionRange {
                    range: lsp::Range::new(
                        lsp::Position::new(p.line, 0),
                        lsp::Position::new(p.line, width(line)),
                    ),
                    parent: Some(Box::new(lsp::SelectionRange {
                        range: lsp::Range::new(
                            lsp::Position::new(parent_start, 0),
                            lsp::Position::new(parent_end, width(parent_end as usize)),
                        ),
                        parent: None,
                    })),
                }
            })
            .collect(),
    )
}

pub(crate) fn folding_ranges(text: &str) -> Vec<(u32, u32)> {
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
        if let Some(end) = end
            && !(i == 0 && end == last)
        {
            out.push((i as u32, end as u32));
        }
    }
    out
}

pub(crate) fn enclosing_block(lines: &[&str], line: usize) -> (u32, u32) {
    let line = line.min(lines.len().saturating_sub(1));
    let indent = content_indent(lines.get(line).copied().unwrap_or("")).unwrap_or(0);
    let mut parent = line;
    for i in (0..line).rev() {
        if let Some(parent_indent) = content_indent(lines[i])
            && parent_indent < indent
        {
            parent = i;
            break;
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

// ---------------------------------------------------------------------------
// `opentide/*`.

fn handle_custom_analyze(session: &mut Session, params: custom::TextParams) -> Value {
    let language = params
        .language
        .as_deref()
        .and_then(LanguageId::parse)
        .unwrap_or(LanguageId::TideYaml);
    let uri = params.uri.unwrap_or_else(|| "memory".to_string());
    let host = session.host_for(&uri);
    let response = opentide_analysis::analyze(
        &host,
        opentide_analysis::AnalyzeRequest {
            uri,
            language,
            text: params.text,
        },
    );
    json!({ "diagnostics": response.diagnostics })
}

/// `opentide/catalog` (#198): each root's indexed objects, with their
/// references, from the index the other requests share. Open documents are
/// read as edited, the rest from disk.
fn handle_catalog(session: &mut Session, params: Option<custom::CatalogParams>) -> Value {
    let params = params.unwrap_or_default();
    let wanted = params
        .root
        .as_deref()
        .map(|uri| crate::session::root_key(&uri_to_path(uri)));
    let roots: Vec<Option<usize>> = session
        .catalog_roots()
        .into_iter()
        .filter(|root| match (&wanted, root) {
            (None, _) => true,
            (Some(want), Some(i)) => {
                crate::session::root_key(&session.roots[*i].path.display().to_string()) == *want
            }
            (Some(_), None) => false,
        })
        .collect();
    if wanted.is_none() {
        session.catalog_every_root();
    }
    let range = |r: Range| serde_json::to_value(lsp_range(r)).unwrap_or(Value::Null);
    let entries: Vec<Value> = roots
        .into_iter()
        .map(|root| {
            let index = session.catalog_index(root);
            let mut objects: Vec<&opentide_analysis::IndexedObject> = index.iter().collect();
            objects.sort_by(|a, b| (&a.path, &a.uuid).cmp(&(&b.path, &b.uuid)));
            let objects: Vec<Value> = objects
                .into_iter()
                .map(|o| {
                    json!({
                        "uuid": o.uuid,
                        "object_type": o.object_type,
                        "schema": o.schema,
                        "name": o.name,
                        "uri": path_to_uri(&o.path),
                        "range": range(o.name_range),
                        "refs": o.refs.iter().map(|r| json!({
                            "uuid": r.uuid,
                            "field_path": r.field_path,
                            "range": range(r.range),
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            json!({ "root": session.catalog_root_uri(root), "objects": objects })
        })
        .collect();
    json!({ "roots": entries })
}

fn handle_custom_highlight(params: custom::TextParams) -> Value {
    let language = params
        .language
        .as_deref()
        .and_then(LanguageId::parse)
        .unwrap_or(LanguageId::Kql);
    json!(opentide_analysis::highlight(language, &params.text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(
        sl: u32,
        sc: u32,
        el: u32,
        ec: u32,
        text: &str,
    ) -> lsp::TextDocumentContentChangeEvent {
        lsp::TextDocumentContentChangeEvent {
            range: Some(lsp::Range::new(
                lsp::Position::new(sl, sc),
                lsp::Position::new(el, ec),
            )),
            range_length: None,
            text: text.into(),
        }
    }

    fn whole(text: &str) -> lsp::TextDocumentContentChangeEvent {
        lsp::TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: text.into(),
        }
    }

    fn at(text: &str, line: u32, character: u32) -> usize {
        offset(text, lsp::Position::new(line, character))
    }

    #[test]
    fn incremental_edits_apply_in_order_and_full_replace_wins() {
        let text = "name: Rule\n";
        let edited =
            apply_content_changes(text, &[change(0, 6, 0, 6, "X"), change(0, 7, 0, 7, "Y")]);
        assert_eq!(edited, "name: XYRule\n");
        assert_eq!(apply_content_changes(text, &[whole("other")]), "other");
    }

    #[test]
    fn offsets_count_utf16_and_clamp() {
        let src = "aéX";
        assert_eq!(at(src, 0, 0), 0);
        assert_eq!(at(src, 0, 1), 1);
        // UTF-16 column 2 is `X`, after the two bytes of `é`.
        assert_eq!(at(src, 0, 2), 1 + "é".len());
        // An emoji is two UTF-16 units; column 3 is `b`.
        let src = "a😀b";
        assert_eq!(at(src, 0, 3), 1 + "😀".len());
        assert_eq!(
            apply_content_changes(src, &[change(0, 1, 0, 3, "X")]),
            "aXb"
        );
        let src = "ab\ncd";
        assert_eq!(at(src, 0, 99), 2);
        assert_eq!(at(src, 9, 0), src.len());
        assert_eq!(
            apply_content_changes(src, &[change(0, 99, 0, 99, "Z")]),
            "abZ\ncd"
        );
        assert_eq!(
            apply_content_changes("ab", &[change(5, 0, 5, 0, "Z")]),
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
        let edited = apply_content_changes(src, &[change(0, 20, 0, 20, "x")]);
        assert_eq!(edited, "T | where Name == \"日x本\"");
        let edited = apply_content_changes(src, &[change(0, 21, 0, 21, "x")]);
        assert_eq!(edited, "T | where Name == \"日本x\"");
        assert_eq!(
            apply_content_changes("é😀", &[change(0, 3, 0, 3, "!")]),
            "é😀!"
        );
        // A column inside a surrogate pair moves past the character, never into it.
        assert_eq!(
            apply_content_changes("😀z", &[change(0, 1, 0, 1, "!")]),
            "😀!z"
        );
        // A reversed range inserts at its start.
        assert_eq!(
            apply_content_changes("abc", &[change(0, 2, 0, 1, "!")]),
            "ab!c"
        );
    }

    #[test]
    fn folding_skips_blank_lines_and_does_not_fold_the_whole_buffer() {
        let with_blank = "metadata:\n  uuid: a\n\n  schema: b\nname: x\n";
        assert_eq!(folding_ranges(with_blank), vec![(0, 3)]);
        assert!(folding_ranges("root:\n  a\n  b\n").is_empty());
        let nested = "outer:\n  inner:\n    leaf\nname: x\n";
        assert_eq!(folding_ranges(nested), vec![(0, 2), (1, 2)]);
        assert!(folding_ranges("meta:\n\tuuid: a\n").is_empty());
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
        let pos = |c: u32| lsp::Position::new(0, c);
        assert_eq!(uuid_at(&text, pos(start)).as_deref(), Some(uuid));
        assert_eq!(
            uuid_at(&text, pos(start + uuid.len() as u32)).as_deref(),
            Some(uuid)
        );
        assert_eq!(uuid_at(&text, pos(start + uuid.len() as u32 + 1)), None);
        assert_eq!(uuid_at(&text, lsp::Position::new(1, 0)), None);
    }

    #[test]
    fn code_action_kinds_follow_only() {
        let quickfix = lsp::CodeActionKind::QUICKFIX;
        let fix_all = fix_all_kind();
        assert!(wanted(None, &quickfix));
        assert!(!wanted(None, &fix_all));
        let source = vec![lsp::CodeActionKind::SOURCE];
        assert!(wanted(Some(&source), &fix_all));
        assert!(!wanted(Some(&source), &quickfix));
        let exact = vec![lsp::CodeActionKind::SOURCE_FIX_ALL];
        assert!(wanted(Some(&exact), &fix_all));
        let quick = vec![lsp::CodeActionKind::QUICKFIX];
        assert!(wanted(Some(&quick), &quickfix));
        assert!(!wanted(Some(&quick), &fix_all));
    }

    #[test]
    fn plain_text_drops_markdown_marks() {
        assert_eq!(
            plain_text("**SecurityEvent**\n\n```kql\nT | take 1\n```\n`x` column"),
            "SecurityEvent\n\nT | take 1\nx column"
        );
    }

    #[test]
    fn deprecations_are_tagged() {
        assert!(is_deprecation(codes::DEPRECATED_FIELD));
        assert!(is_deprecation(codes::KQL_DEPRECATED_OPERATOR));
        assert!(!is_deprecation(codes::DUPLICATE_ID));
    }

    /// #219: a `filename_slug` rename is for a `file:` document, into its own
    /// directory, with one plain file name.
    #[test]
    fn rename_targets_stay_beside_a_file() {
        let dir = std::env::temp_dir().join("opentide-rename-target");
        let uri = path_to_uri(&dir.join("old-name.yaml").to_string_lossy());
        assert_eq!(
            rename_target(&uri, "new-name.yaml"),
            Some(dir.join("new-name.yaml"))
        );
        assert_eq!(rename_target(&uri, "old-name.yaml"), None);
        for name in ["", ".", "..", "sub/new.yaml", "..\\new.yaml"] {
            assert_eq!(rename_target(&uri, name), None, "{name:?}");
        }
        assert_eq!(rename_target("untitled:Untitled-1", "new-name.yaml"), None);
        assert_eq!(
            rename_target(
                "vscode-vfs://github/org/repo/objects/rules/x.yaml",
                "y.yaml"
            ),
            None
        );
    }

    #[test]
    fn case_only_renames_are_the_same_name_in_the_same_directory() {
        let dir = std::path::Path::new("/w/objects/rules");
        let from = dir.join("Rule-Name.yaml");
        assert!(is_case_only_rename(&from, &dir.join("rule-name.yaml")));
        assert!(!is_case_only_rename(&from, &from));
        assert!(!is_case_only_rename(&from, &dir.join("other.yaml")));
        assert!(!is_case_only_rename(
            &from,
            &std::path::Path::new("/w/objects/other").join("rule-name.yaml")
        ));
    }

    /// The document itself under another case is not another file; on a
    /// case-sensitive filesystem the other case does not exist at all.
    #[test]
    fn a_case_only_target_that_exists_is_the_document_itself() {
        let dir = std::env::temp_dir().join(format!("opentide-case-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let from = dir.join("Rule-Name.yaml");
        let other = dir.join("other.yaml");
        std::fs::write(&from, "name: x\n").unwrap();
        std::fs::write(&other, "name: y\n").unwrap();
        let lower = dir.join("rule-name.yaml");
        assert!(same_file(&from, &from));
        assert!(!same_file(&from, &other));
        if lower.exists() {
            // Case-insensitive: the rename is still offered.
            assert!(same_file(&from, &lower));
        } else {
            assert!(!same_file(&from, &lower));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
