//! The wasm32-unknown-unknown build: `highlight()`, `legend()`, and the
//! language server itself ([`LanguageServer`]) for a browser worker. Do not
//! mix WASI in this artifact.
//!
//! Build it with `scripts/engine/build-wasm.sh`, which links wasi-sdk's libc for the
//! C parsers; [`libc_syscalls`] keeps that libc from importing anything.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[expect(
    unsafe_code,
    reason = "exports the libc syscall symbols (#[unsafe(no_mangle)]) and writes the clock's answer"
)]
mod libc_syscalls;

use opentide_core::LanguageId;
use wasm_bindgen::prelude::*;

/// The semantic token legend: the HighlightSpec capture names, in the order
/// the token types' indices refer to.
#[wasm_bindgen]
pub fn legend() -> js_sys::Array {
    let arr = js_sys::Array::new();
    for name in legend_names() {
        arr.push(&JsValue::from_str(&name));
    }
    arr
}

/// [`legend`]'s names, without the JavaScript array: js-sys runs only on
/// wasm32, so the logic stays here, where native tests reach it.
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
fn legend_names() -> Vec<String> {
    opentide_highlight::HighlightSpec::load()
        .expect("spec")
        .legend
}

/// Highlight `language_id` source bytes. Usable without a full language client.
#[wasm_bindgen]
pub fn highlight(language_id: &str, bytes: &[u8]) -> Result<JsValue, JsValue> {
    let json = highlight_json(language_id, bytes).map_err(|e| JsValue::from_str(&e))?;
    js_sys::JSON::parse(&json).map_err(|e| JsValue::from_str(&format!("{e:?}")))
}

/// [`highlight`]'s result as JSON text, or its error message: the part
/// native tests reach (js-sys runs only on wasm32).
fn highlight_json(language_id: &str, bytes: &[u8]) -> Result<String, String> {
    let language =
        LanguageId::parse(language_id).ok_or_else(|| format!("unknown language {language_id}"))?;
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let result = opentide_analysis::highlight(language, text);
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// The engine's version: the crate version every `opentide-*` crate shares.
#[wasm_bindgen]
pub fn version() -> String {
    opentide_lsp::VERSION.to_string()
}

/// The opentide language server (`opentide-lsp`), one JSON-RPC message at a
/// time: a worker hands [`LanguageServer::handle`] each message its client
/// posts and posts back what it returns (`serveLanguageServer` in
/// `@opentide/lsp-worker`). It is the server `--stdio` runs, with no stdio
/// and no filesystem: the client supplies the workspace on `initialize`
/// (`initializationOptions.workspace`, see `opentide_lsp::MessageSession`).
#[wasm_bindgen]
pub struct LanguageServer {
    session: opentide_lsp::MessageSession,
}

#[wasm_bindgen]
impl LanguageServer {
    /// A server before `initialize`, which is the first message it expects.
    #[wasm_bindgen(constructor)]
    #[expect(
        clippy::new_without_default,
        reason = "JavaScript constructs it with `new LanguageServer()`; Default means nothing there"
    )]
    pub fn new() -> LanguageServer {
        LanguageServer {
            session: opentide_lsp::MessageSession::new(),
        }
    }

    /// One JSON-RPC message in, as JSON text without a `Content-Length`
    /// header; the messages the server sends back out, in order, each as JSON
    /// text.
    pub fn handle(&mut self, message: &str) -> Vec<String> {
        self.session.handle(message)
    }

    /// Whether the client has sent `exit`: the session handles nothing more.
    #[wasm_bindgen(getter)]
    pub fn closed(&self) -> bool {
        self.session.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::LanguageServer;
    use opentide_analysis::highlight;
    use opentide_core::LanguageId;
    use serde_json::{Value, json};

    #[test]
    fn the_legend_is_the_highlight_spec_legend() {
        let names = super::legend_names();
        assert!(names.iter().any(|name| name == "keyword"), "{names:?}");
        assert_eq!(
            names,
            opentide_highlight::HighlightSpec::load().unwrap().legend
        );
    }

    #[test]
    fn highlight_json_is_the_analysis_result_or_an_error_message() {
        let json: Value =
            serde_json::from_str(&super::highlight_json("kql", b"SecurityEvent | take 1").unwrap())
                .unwrap();
        assert_eq!(
            json,
            serde_json::to_value(highlight(LanguageId::Kql, "SecurityEvent | take 1")).unwrap()
        );
        assert_eq!(
            super::highlight_json("cobol", b"x").unwrap_err(),
            "unknown language cobol"
        );
        assert!(
            super::highlight_json("kql", &[0xff])
                .unwrap_err()
                .contains("utf-8"),
        );
    }

    #[test]
    fn highlight_kql_and_spl() {
        let k = highlight(LanguageId::Kql, "SecurityEvent | take 1");
        assert!(k.tokens.iter().any(|t| t.capture == "keyword"));
        let s = highlight(LanguageId::Spl, "index=main | stats count by host");
        assert!(s.tokens.iter().any(|t| t.capture == "operator.pipe"));
    }

    fn send(server: &mut LanguageServer, message: Value) -> Vec<Value> {
        server
            .handle(&message.to_string())
            .iter()
            .map(|text| serde_json::from_str(text).unwrap())
            .collect()
    }

    /// The export drives the stdio server's own session: the same handshake,
    /// diagnostics and shutdown, with no stdio.
    #[test]
    fn the_language_server_answers_one_message_at_a_time() {
        let mut server = LanguageServer::new();
        let init = send(
            &mut server,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "processId": null, "rootUri": null, "capabilities": {} } }),
        );
        assert_eq!(init[0]["result"]["serverInfo"]["name"], "opentide-lsp");
        assert_eq!(
            init[0]["result"]["serverInfo"]["version"],
            super::version().as_str()
        );
        let published = send(
            &mut server,
            json!({ "jsonrpc": "2.0", "method": "textDocument/didOpen",
                "params": { "textDocument": { "uri": "untitled:q.esql", "languageId": "esql", "version": 1,
                    "text": "FROM logs-* | WEHRE x == 1" } } }),
        );
        let codes: Vec<&str> = published[0]["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|d| d["code"].as_str())
            .collect();
        assert!(codes.contains(&"esql_unknown_command"), "{codes:?}");
        send(
            &mut server,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "shutdown" }),
        );
        assert!(!server.closed());
        send(&mut server, json!({ "jsonrpc": "2.0", "method": "exit" }));
        assert!(server.closed());
    }
}
