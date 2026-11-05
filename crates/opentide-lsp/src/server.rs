//! The server's entry points: one client over stdio, a socket, or the
//! host's own streams. The protocol loop is [`crate::protocol`], the state
//! [`crate::session`], and the methods [`crate::handlers`].

use crate::protocol::{self, Direct};
use crate::session::Session;
use anyhow::Result;
use opentide_analysis::{Catalog, install_catalog};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

pub fn run_stdio() -> Result<()> {
    run_stdio_status().map(|_| ())
}

/// [`run_stdio`], returning whether the client shut the server down before
/// it exited ([`serve_with_status`]): the process should exit with 0 if so
/// and 1 if not. Messages are read on a thread of their own, so the ones
/// that arrive while a request is handled are batched (#185 P1.4); wasip1,
/// which has no threads, reads them on this one.
pub fn run_stdio_status() -> Result<bool> {
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let mut session = Session::default();
    #[cfg(not(target_os = "wasi"))]
    let mut source = protocol::Threaded::spawn(|| std::io::stdin().lock())?;
    #[cfg(target_os = "wasi")]
    let mut source = Direct::new(std::io::stdin().lock());
    protocol::run(&mut source, &mut writer, &mut session)
}

#[cfg(not(target_os = "wasi"))]
pub fn run_listen(addr: &str) -> Result<()> {
    let listener = std::net::TcpListener::bind(addr)?;
    eprintln!("opentide-lsp listening on {addr}");
    let (stream, _) = listener.accept()?;
    let reader = stream.try_clone()?;
    let mut source = protocol::Threaded::spawn(move || std::io::BufReader::new(reader))?;
    let mut writer = stream;
    let mut session = Session::default();
    protocol::run(&mut source, &mut writer, &mut session).map(|_| ())
}

#[cfg(target_os = "wasi")]
pub fn run_listen(_addr: &str) -> Result<()> {
    anyhow::bail!("--listen needs sockets, which wasip1 does not have")
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
/// is answered `InternalError` (-32603). Frames are read on the caller's
/// thread; those already buffered are handled as one batch.
pub fn serve_with_status(reader: impl BufRead, mut writer: impl Write) -> Result<bool> {
    let mut session = Session::default();
    let mut source = Direct::new(reader);
    protocol::run(&mut source, &mut writer, &mut session)
}

/// The language server driven one message at a time, for a host with no
/// stdio to give it: a browser worker hands [`MessageSession::handle`] each
/// JSON-RPC message its client posts and posts back what it returns. It is
/// the loop [`serve`] runs, one message to a batch: the same lifecycle, the
/// same answers to a body that is not a message, and the same publishes.
///
/// Such a host has no filesystem, so it supplies the workspace on
/// `initialize`, in `initializationOptions.workspace`:
///
/// - `documents`: `[{ "uri", "text" }]`, object files indexed as if they were
///   on disk (references resolve to them; they are not checked);
/// - `objects`: `[{ "uuid", "schema", "name"?, "uri"? }]`, objects the host
///   knows by their metadata alone, indexed with just those keys, so a
///   reference to one resolves and hover names it;
/// - `visibility`: the text of the workspace's `visibility.toml`.
///
/// A host with a filesystem may send it too: a root's own files win. When
/// the files change, the host sends `opentide/didChangeWorkspace` with what
/// changed (the same keys, plus `removed`: `[uri]`, and `visibility: null`
/// when the file is gone), and the server re-indexes and re-checks.
#[derive(Default)]
pub struct MessageSession {
    session: Session,
    driver: protocol::Driver,
    closed: bool,
}

impl MessageSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle one JSON-RPC message: its JSON text, without the
    /// `Content-Length` header. Returns what the server sends back, each
    /// message as JSON text and in order: the response to a request, the
    /// notifications it publishes (`textDocument/publishDiagnostics`,
    /// `window/logMessage`), and the requests it makes of the client
    /// (`client/registerCapability`, `workspace/diagnostic/refresh`). Text
    /// that is not a JSON-RPC message is answered with a parse error
    /// (-32700) or an invalid request (-32600). After `exit` the session is
    /// closed and handles nothing more.
    pub fn handle(&mut self, message: &str) -> Vec<String> {
        if self.closed {
            return Vec::new();
        }
        let mut out = Vec::new();
        let frame = protocol::frame_of(message);
        match self.driver.batch(&mut self.session, &mut out, vec![frame]) {
            Ok(Some(_)) => self.closed = true,
            Ok(None) => {}
            // Writing to a `Vec` does not fail.
            Err(err) => eprintln!("opentide-lsp: {err}"),
        }
        protocol::frame_bodies(&out)
    }

    /// Whether the client has sent `exit`.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether the client shut the server down before it sent `exit`: a
    /// clean end, as [`serve_with_status`] reports it.
    pub fn shut_down(&self) -> bool {
        self.driver.state == protocol::Lifecycle::ShuttingDown
    }
}

/// A path as a `file:` URI, typed.
pub(crate) fn path_to_uri_value(path: &Path) -> Option<lsp_types::Uri> {
    crate::uri::path_to_uri(&path.display().to_string())
        .parse()
        .ok()
}

/// The workspace root of a file: its nearest ancestor holding `objects/` or
/// `.opentide/`. `opentide-lsp analyze` and the server, for a document
/// outside every workspace folder, both use it.
pub fn workspace_root(file: &Path) -> Option<PathBuf> {
    file.ancestors()
        .skip(1)
        .find(|a| a.join("objects").is_dir() || a.join(".opentide").is_dir())
        .map(Path::to_path_buf)
}

// ---------------------------------------------------------------------------
// Host info (#172).

static HOST: RwLock<Option<(String, String)>> = RwLock::new(None);

/// Name the host that runs the server, process-wide: `opentide lsp start`
/// sets `("opentide", <its version>)`. Clients read it from
/// `capabilities.experimental.opentide.host` at `initialize`.
pub fn set_host_info(name: &str, version: &str) {
    *HOST.write().unwrap_or_else(|p| p.into_inner()) = Some((name.into(), version.into()));
}

/// The catalogs in use: 0 bundled, 1 the workspace's generated ones, 2 the
/// host's.
static CATALOG_SOURCE: AtomicU8 = AtomicU8::new(0);

/// What a client can learn about the server before it uses it, the same at
/// `initialize` (`capabilities.experimental.opentide`) and from
/// `opentide-lsp --version --json`. A key is added in a minor release and
/// never removed (docs/EDITORS.md).
pub fn host_info() -> Value {
    let host = HOST.read().unwrap_or_else(|p| p.into_inner()).clone();
    let catalog = if HOST_CATALOGS.load(Ordering::SeqCst) {
        "host"
    } else if CATALOG_SOURCE.load(Ordering::SeqCst) == 1 {
        "workspace"
    } else {
        "bundled"
    };
    json!({
        "host": host.map(|(name, version)| json!({ "name": name, "version": version })),
        "engine": crate::VERSION,
        "catalog": catalog,
        "configurationChecks": opentide_analysis::has_configuration_checker(),
        "configurationSchemas": opentide_analysis::has_configuration_schemas(),
        // The supplied workspace follows `opentide/didChangeWorkspace`.
        "workspaceUpdates": true,
    })
}

// ---------------------------------------------------------------------------
// Catalogs.

/// Where `opentide generate schemas` writes the workspace catalogs.
pub const WORKSPACE_CATALOGS: &str = ".opentide/lsp/catalogs/generated";

/// Set by a host that installed the catalogs itself
/// ([`opentide_analysis::set_default_catalog`]): the server then leaves them
/// alone instead of reading the workspace's.
static HOST_CATALOGS: AtomicBool = AtomicBool::new(false);

/// Keep the catalogs the host installed: the server does not read
/// `.opentide/lsp/catalogs/generated/`. opentide generates the catalogs from
/// its own models for the workspace it serves, so a committed copy, possibly
/// from an older opentide, must not replace them. Process-wide.
pub fn use_host_catalogs() {
    HOST_CATALOGS.store(true, Ordering::SeqCst);
}

/// Install the workspace's `fields.json` and `deprecations.json` when they
/// exist, and the bundled catalogs otherwise. A file that does not parse is
/// reported on stderr and leaves the bundled catalogs in place.
pub fn install_workspace_catalog(root: &Path) {
    let root = (!root.as_os_str().is_empty()).then_some(root);
    if let Err(err) = install_workspace_catalog_from(root) {
        eprintln!("opentide-lsp: {err}");
    }
}

/// [`install_workspace_catalog`] for a root, or the bundled catalogs for
/// none; what went wrong, if the workspace's do not parse.
pub(crate) fn install_workspace_catalog_from(root: Option<&Path>) -> Result<(), String> {
    if HOST_CATALOGS.load(Ordering::SeqCst) {
        return Ok(());
    }
    let dir = root.map(|r| r.join(WORKSPACE_CATALOGS));
    let read = |name: &str| std::fs::read_to_string(dir.as_ref()?.join(name)).ok();
    let catalog = Catalog {
        fields: read("fields.json"),
        deprecations: read("deprecations.json"),
        // visibility.toml is installed on its own, so edits apply live.
        visibility: None,
    };
    let from_workspace = catalog.fields.is_some() || catalog.deprecations.is_some();
    match install_catalog(&catalog) {
        Ok(()) => {
            CATALOG_SOURCE.store(u8::from(from_workspace), Ordering::SeqCst);
            Ok(())
        }
        Err(err) => {
            let _ = install_catalog(&Catalog::default());
            CATALOG_SOURCE.store(0, Ordering::SeqCst);
            Err(format!(
                "ignoring {}: {err}; using the bundled catalogs",
                dir.map(|d| d.display().to_string()).unwrap_or_default()
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// The workspace walk.

/// The workspace's object YAML: the files under `<root>/objects`. A root
/// without `objects/` has none, and nothing else under it is read (a root of
/// `/tmp` or a home directory once had every YAML file there indexed).
pub(crate) fn collect_objects(root: &Path) -> Vec<(String, String)> {
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
    use opentide_core::LanguageId;

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
    fn host_info_names_the_engine_and_no_host_by_default() {
        let info = host_info();
        assert_eq!(info["engine"], crate::VERSION);
        assert!(["bundled", "workspace", "host"].contains(&info["catalog"].as_str().unwrap()));
    }
}
