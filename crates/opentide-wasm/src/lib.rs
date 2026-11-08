//! The wasm32-unknown-unknown build: `highlight()`, `legend()`, and the
//! language server itself ([`LanguageServer`]) for a browser worker. Do not
//! mix WASI in this artifact.
//!
//! Build it with `scripts/engine/build-wasm.sh`, which links wasi-sdk's libc for the
//! C parsers; [`libc_syscalls`] keeps that libc from importing anything.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod libc_syscalls;

use opentide_core::LanguageId;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn legend() -> js_sys::Array {
    let spec = opentide_highlight::HighlightSpec::load().expect("spec");
    let arr = js_sys::Array::new();
    for name in spec.legend {
        arr.push(&JsValue::from_str(&name));
    }
    arr
}

/// Highlight `language_id` source bytes. Usable without a full language client.
#[wasm_bindgen]
pub fn highlight(language_id: &str, bytes: &[u8]) -> Result<JsValue, JsValue> {
    let language = LanguageId::parse(language_id)
        .ok_or_else(|| JsValue::from_str(&format!("unknown language {language_id}")))?;
    let text = std::str::from_utf8(bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let result = opentide_analysis::highlight(language, text);
    serde_wasm_bindgen_compat(&result).map_err(|e| JsValue::from_str(&e))
}

fn serde_wasm_bindgen_compat<T: serde::Serialize>(value: &T) -> Result<JsValue, String> {
    let json = serde_json::to_string(value).map_err(|e| e.to_string())?;
    js_sys::JSON::parse(&json).map_err(|e| format!("{e:?}"))
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
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
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
