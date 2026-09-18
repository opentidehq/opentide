//! LSP server: diagnostics, semantic tokens, hover, completion, definition,
//! references, symbols, code actions, folding, inlay hints, custom RPCs.

use crate::jsonrpc::{self, Incoming};
use anyhow::Result;
use opentide_analysis::{
    analyze, compiled_kql, compiled_spl, completions, hover, index_workspace, signature_help,
    AnalyzeRequest, MemoryWorkspace, WorkspaceHost,
};
use opentide_core::{span_to_range, LanguageId, Position, Range};
use opentide_highlight::encode_lsp_semantic_tokens;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

struct Session {
    docs: HashMap<String, (LanguageId, String)>,
    root: Option<PathBuf>,
}

impl Session {
    fn host(&self) -> MemoryWorkspace {
        let mut files: Vec<(String, String)> = self
            .docs
            .iter()
            .map(|(uri, (_, text))| (uri_to_path(uri), text.clone()))
            .collect();
        if let Some(root) = &self.root {
            if let Ok(extra) = collect_objects(root) {
                for (p, t) in extra {
                    if !files.iter().any(|(e, _)| e == &p) {
                        files.push((p, t));
                    }
                }
            }
        }
        MemoryWorkspace { files }
    }

    fn language_for(&self, uri: &str, reported: Option<&str>) -> LanguageId {
        if let Some(id) = reported.and_then(LanguageId::parse) {
            return id;
        }
        if uri.ends_with(".kql") {
            LanguageId::Kql
        } else if uri.ends_with(".spl") {
            LanguageId::Spl
        } else {
            LanguageId::TideYaml
        }
    }
}

pub fn run_stdio() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let mut session = Session {
        docs: HashMap::new(),
        root: None,
    };
    loop {
        let Some(msg) = jsonrpc::read_message(&mut reader)? else {
            break;
        };
        if !dispatch(&mut session, &mut writer, msg)? {
            break;
        }
    }
    Ok(())
}

pub fn run_listen(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("opentide-lsp listening on {addr}");
    let (stream, _) = listener.accept()?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut session = Session {
        docs: HashMap::new(),
        root: None,
    };
    loop {
        let Some(msg) = jsonrpc::read_message(&mut reader)? else {
            break;
        };
        if !dispatch(&mut session, &mut writer, msg)? {
            break;
        }
    }
    Ok(())
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
                session.root = Some(PathBuf::from(root));
            }
            jsonrpc::write_message(
                writer,
                &jsonrpc::success(
                    id,
                    json!({
                        "capabilities": {
                            "textDocumentSync": 1,
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
                    }),
                ),
            )?;
        }
        "initialized" => {}
        "shutdown" => {
            jsonrpc::write_message(writer, &jsonrpc::success(id, Value::Null))?;
        }
        "exit" => return Ok(false),
        "textDocument/didOpen" => {
            handle_did_open(session, writer, &params)?;
        }
        "textDocument/didChange" => {
            handle_did_change(session, writer, &params)?;
        }
        "textDocument/didClose" => {
            if let Some(uri) = params.pointer("/textDocument/uri").and_then(|v| v.as_str()) {
                session.docs.remove(uri);
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
    let language = session.language_for(uri, lang);
    session
        .docs
        .insert(uri.to_string(), (language, text.to_string()));
    publish_diagnostics(session, writer, uri)?;
    Ok(())
}

fn handle_did_change(session: &mut Session, writer: &mut impl Write, params: &Value) -> Result<()> {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let text = params
        .pointer("/contentChanges/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let language = session
        .docs
        .get(uri)
        .map(|(l, _)| *l)
        .unwrap_or(LanguageId::TideYaml);
    session
        .docs
        .insert(uri.to_string(), (language, text.to_string()));
    publish_diagnostics(session, writer, uri)?;
    Ok(())
}

fn publish_diagnostics(session: &Session, writer: &mut impl Write, uri: &str) -> Result<()> {
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
    let diags: Vec<Value> = response
        .diagnostics
        .iter()
        .map(|d| {
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
        })
        .collect();
    jsonrpc::write_message(
        writer,
        &jsonrpc::notify(
            "textDocument/publishDiagnostics",
            json!({ "uri": uri, "diagnostics": diags }),
        ),
    )?;
    Ok(())
}

fn handle_hover(session: &Session, params: &Value) -> Value {
    let Some((_uri, language, text, pos)) = doc_pos(session, params) else {
        return Value::Null;
    };
    let host = session.host();
    hover(&host, language, &text, pos)
        .map(|value| json!({ "contents": { "kind": "markdown", "value": value } }))
        .unwrap_or(Value::Null)
}

fn handle_completion(session: &Session, params: &Value) -> Value {
    let Some((_uri, language, text, pos)) = doc_pos(session, params) else {
        return json!([]);
    };
    let offset = position_to_offset(&text, pos);
    let host = session.host();
    let items: Vec<Value> = completions(&host, language, &text, offset)
        .into_iter()
        .map(|c| {
            json!({
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
                    _ => 1,
                },
                "insertText": c.label,
            })
        })
        .collect();
    json!(items)
}

fn handle_signature_help(session: &Session, params: &Value) -> Value {
    let Some((_uri, language, text, pos)) = doc_pos(session, params) else {
        return Value::Null;
    };
    let host = session.host();
    signature_help(&host, language, &text, pos)
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
    json!({
        "label": item.label,
        "detail": item.detail,
        "documentation": item.documentation.as_ref().map(|d| json!({ "kind": "markdown", "value": d })),
        "kind": params.get("kind").cloned().unwrap_or(json!(1)),
        "insertText": item.label,
    })
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
    json!(response
        .symbols
        .iter()
        .map(|s| json!({
            "name": s.name,
            "kind": 5,
            "detail": s.detail,
            "range": range_json(s.range),
            "selectionRange": range_json(s.range)
        }))
        .collect::<Vec<_>>())
}

fn handle_workspace_symbol(session: &Session, params: &Value) -> Value {
    let query = params.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let host = session.host();
    let workspace = index_workspace(&host);
    json!(opentide_tide::workspace_symbols(&workspace, query)
        .into_iter()
        .map(|o| json!({
            "name": o.name,
            "kind": 5,
            "location": {
                "uri": path_to_uri(&o.path),
                "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 1 } }
            },
            "containerName": o.object_type
        }))
        .collect::<Vec<_>>())
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
        "items": response.diagnostics.iter().map(|d| json!({
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
        })).collect::<Vec<_>>()
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
    let actions: Vec<Value> = response
        .diagnostics
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
    json!(actions)
}

fn handle_folding(session: &Session, params: &Value) -> Value {
    let uri = params
        .pointer("/textDocument/uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some((_, text)) = session.docs.get(uri) else {
        return json!([]);
    };
    let last = text.lines().count().saturating_sub(1) as u32;
    if last == 0 {
        return json!([]);
    }
    json!([{ "startLine": 0, "endLine": last, "kind": "region" }])
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
    let hints: Vec<Value> = opentide_tide::inlay_hints(text, &workspace)
        .into_iter()
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
        let line = text.lines().nth(pos.line as usize).unwrap_or("");
        if let Some(idx) = line.find(&uuid) {
            return json!([{
                "range": {
                    "start": { "line": pos.line, "character": idx as u32 },
                    "end": { "line": pos.line, "character": (idx + uuid.len()) as u32 }
                },
                "kind": 1
            }]);
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
    let last_line = text.lines().count().saturating_sub(1) as u32;
    let last_col = text.lines().last().map(|l| l.len() as u32).unwrap_or(0);
    json!(positions
        .iter()
        .map(|p| {
            json!({
                "range": {
                    "start": p,
                    "end": p
                },
                "parent": {
                    "range": {
                        "start": { "line": 0, "character": 0 },
                        "end": { "line": last_line, "character": last_col }
                    }
                }
            })
        })
        .collect::<Vec<_>>())
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

fn range_json(range: Range) -> Value {
    json!({
        "start": { "line": range.start.line, "character": range.start.character },
        "end": { "line": range.end.line, "character": range.end.character }
    })
}

fn uri_to_path(uri: &str) -> String {
    uri.strip_prefix("file://").unwrap_or(uri).to_string()
}

fn path_to_uri(path: &str) -> String {
    if path.starts_with("file://") {
        path.to_string()
    } else {
        format!("file://{path}")
    }
}

fn uuid_at(text: &str, pos: Position) -> Option<String> {
    let line = text.lines().nth(pos.line as usize)?;
    let re = regex::Regex::new(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    )
    .ok()?;
    re.find_iter(line)
        .find(|m| {
            let c = pos.character as usize;
            m.start() <= c && c <= m.end()
        })
        .map(|m| m.as_str().to_string())
}

fn position_to_offset(source: &str, position: Position) -> usize {
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in source.char_indices() {
        if line == position.line && col >= position.character {
            return idx;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    source.len()
}

fn collect_objects(root: &Path) -> Result<Vec<(String, String)>, std::io::Error> {
    let objects = if root.join("objects").is_dir() {
        root.join("objects")
    } else {
        root.to_path_buf()
    };
    let mut out = Vec::new();
    fn rec(dir: &Path, out: &mut Vec<(String, String)>) -> Result<(), std::io::Error> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let p = e.path();
            if p.is_dir() {
                rec(&p, out)?;
            } else if matches!(p.extension().and_then(|s| s.to_str()), Some("yaml" | "yml")) {
                out.push((p.display().to_string(), std::fs::read_to_string(&p)?));
            }
        }
        Ok(())
    }
    rec(&objects, &mut out)?;
    Ok(out)
}
