//! Protocol tests over stdio. The CLI never speaks JSON-RPC; `--stdio` does.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

mod common;

use common::*;
use serde_json::{Value, json};
use std::process::{Command, Stdio};

#[test]
fn initialize_and_analyze_kql() {
    let mut lsp = Lsp::spawn();
    let init = lsp.request(
        "initialize",
        json!({
            "capabilities": {},
            "rootUri": file_uri(&repo_root())
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "opentide-lsp");
    assert_eq!(init["result"]["capabilities"]["hoverProvider"], true);
    assert!(
        init["result"]["capabilities"]["signatureHelpProvider"].is_object(),
        "{init}"
    );
    lsp.notify("initialized", json!({}));

    let kql = "SecurityEvent | where EventID == 4688 | take 1";
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": "file:///tmp/sample.kql",
                "languageId": "kql",
                "version": 1,
                "text": kql
            }
        }),
    );
    let _diag = lsp.read(); // publishDiagnostics
    let hover = lsp.request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "position": { "line": 0, "character": 16 }
        }),
    );
    assert!(
        hover["result"]["contents"]["value"]
            .as_str()
            .unwrap_or("")
            .contains("where"),
        "{hover}"
    );

    let event_hover = lsp.request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "position": { "line": 0, "character": 24 }
        }),
    );
    let event_md = event_hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or("");
    assert!(
        event_md.contains("EventID"),
        "column hover for EventID, got {event_hover}"
    );

    let sig = lsp.request(
        "textDocument/signatureHelp",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "position": { "line": 0, "character": 16 }
        }),
    );
    assert!(
        sig["result"].is_null() || sig["result"].is_object(),
        "{sig}"
    );
    lsp.notify(
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "contentChanges": [{ "text": "SecurityEvent | where ago(" }]
        }),
    );
    let _ = lsp.read();
    let ago = lsp.request(
        "textDocument/signatureHelp",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "position": { "line": 0, "character": 26 }
        }),
    );
    let label = ago["result"]["signatures"][0]["label"]
        .as_str()
        .unwrap_or("");
    assert!(
        label.contains("ago("),
        "signature must be an object, got {ago}"
    );

    let tokens = lsp.request(
        "textDocument/semanticTokens/full",
        json!({ "textDocument": { "uri": "file:///tmp/sample.kql" } }),
    );
    assert!(!tokens["result"]["data"].as_array().unwrap().is_empty());

    let pipe_src = "SecurityEvent | ";
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": "file:///tmp/pipe.kql",
                "languageId": "kql",
                "version": 1,
                "text": pipe_src
            }
        }),
    );
    let _ = lsp.read();
    let completion = lsp.request(
        "textDocument/completion",
        json!({
            "textDocument": { "uri": "file:///tmp/pipe.kql" },
            "position": { "line": 0, "character": pipe_src.len() }
        }),
    );
    assert!(
        completion["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["label"] == "where"),
        "{completion}"
    );

    let compiled = lsp.request(
        "opentide/compiledKql",
        json!({ "query": "DeviceEvents | take 1", "tenant": "t1" }),
    );
    assert_eq!(compiled["result"]["compiled"], "DeviceEvents | take 1");

    let highlight = lsp.request(
        "opentide/highlight",
        json!({ "language": "kql", "text": kql }),
    );
    assert!(
        highlight["result"]["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["capture"] == "operator.pipe")
    );

    lsp.request("shutdown", json!(null));
    lsp.notify("exit", json!({}));
}

#[test]
fn unknown_spl_command_is_published() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    lsp.notify("initialized", json!({}));
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": "file:///tmp/sample.spl",
                "languageId": "spl",
                "version": 1,
                "text": "index=main | bogus foo=bar"
            }
        }),
    );
    let msg = lsp.read();
    let diags = msg["params"]["diagnostics"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        diags.iter().any(|d| d["code"] == "spl_unknown_command"),
        "{msg}"
    );
}

#[test]
fn tide_yaml_pull_diagnostics_and_symbols() {
    let mut lsp = Lsp::spawn();
    let root = repo_root().join("crates/testdata/workspaces/tide_corpus");
    lsp.request(
        "initialize",
        json!({
            "capabilities": {},
            "rootUri": file_uri(&root)
        }),
    );
    lsp.notify("initialized", json!({}));
    let path = root.join("objects/rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let uri = file_uri(&path);
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "languageId": "opentide-yaml",
                "version": 1,
                "text": text
            }
        }),
    );
    let _ = lsp.read();
    let pull = lsp.request(
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    assert_eq!(pull["result"]["kind"], "full");
    let symbols = lsp.request(
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": uri } }),
    );
    assert!(
        symbols["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "Sentinel KQL Rule"),
        "{symbols}"
    );

    #[expect(
        clippy::cast_possible_truncation,
        reason = "positions in a test document of a few lines"
    )]
    fn pos(text: &str, needle: &str) -> (u32, u32) {
        let off = text.find(needle).expect(needle);
        let line = text[..off].bytes().filter(|b| *b == b'\n').count() as u32;
        let col = text[..off]
            .rsplit_once('\n')
            .map(|(_, rest)| rest.len())
            .unwrap_or(off) as u32;
        (line, col)
    }

    let (dline, dcol) = pos(&text, "description:");
    let hover = lsp.request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": dline, "character": dcol }
        }),
    );
    let hover_md = hover["result"]["contents"]["value"].as_str().unwrap_or("");
    assert!(
        hover_md.contains("Description") && hover_md.contains("required"),
        "field hover, got {hover}"
    );

    let (mline, mcol) = pos(&text, "  tlp:");
    let completion = lsp.request(
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": mline, "character": mcol }
        }),
    );
    let labels: Vec<&str> = completion["result"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["label"].as_str())
        .collect();
    assert!(labels.contains(&"author"), "{labels:?}");
    assert!(
        completion["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["documentation"]["value"]
                .as_str()
                .is_some_and(|d| d.contains("Author"))),
        "{completion}"
    );
    assert!(
        !labels.contains(&"High"),
        "no global vocab dump: {labels:?}"
    );

    let resolve = lsp.request(
        "completionItem/resolve",
        json!({ "label": "description", "kind": 5 }),
    );
    assert!(
        resolve["result"]["documentation"]["value"]
            .as_str()
            .unwrap_or("")
            .contains("Description"),
        "{resolve}"
    );

    let inlays = lsp.request(
        "textDocument/inlayHint",
        json!({
            "textDocument": { "uri": uri },
            "range": {
                "start": { "line": 0, "character": 0 },
                "end": { "line": 80, "character": 0 }
            }
        }),
    );
    assert!(
        inlays["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["label"][0]["value"]
                .as_str()
                .is_some_and(|l| l.to_lowercase().contains("objective"))
                // The label leads to the object (#185 P3.5).
                && h["label"][0]["location"]["uri"]
                    .as_str()
                    .is_some_and(|u| u.ends_with("objective-0001-credential-access.yaml"))),
        "{inlays}"
    );

    let compiled_spl = lsp.request(
        "opentide/compiledSpl",
        json!({ "query": "index=main | head 1" }),
    );
    assert_eq!(compiled_spl["result"]["compiled"], "index=main | head 1");
}

#[test]
fn cli_analyze_and_highlight_never_emit_jsonrpc() {
    let file = repo_root()
        .join("crates/testdata/workspaces/tide_corpus/objects/rules/rule-0001-sentinel-kql.yaml");
    let analyze = Command::new(bin())
        .args(["analyze", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        analyze.status.success(),
        "{}",
        String::from_utf8_lossy(&analyze.stderr)
    );
    let stdout = String::from_utf8_lossy(&analyze.stdout);
    assert!(
        !stdout.contains("jsonrpc"),
        "CLI must not speak JSON-RPC: {stdout}"
    );
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert!(v.is_array());

    let highlight = Command::new(bin())
        .args([
            "highlight",
            file.to_str().unwrap(),
            "--language",
            "opentide-yaml",
        ])
        .output()
        .unwrap();
    assert!(highlight.status.success());
    let h: Value = serde_json::from_slice(&highlight.stdout).unwrap();
    let captures: Vec<_> = h["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["capture"].as_str().unwrap())
        .collect();
    assert!(captures.contains(&"tide.property"));
    assert!(
        captures
            .iter()
            .any(|c| *c == "keyword" || *c == "function" || *c == "type"),
        "{captures:?}"
    );
}

#[test]
fn highlight_html_contains_spans() {
    let file = repo_root().join("crates/testdata/corpus/kql/take_operator__valid.kql");
    let out = Command::new(bin())
        .args(["highlight", file.to_str().unwrap(), "--html"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let html = String::from_utf8_lossy(&out.stdout);
    assert!(html.contains("<span class=\"keyword\">") && html.contains("operator-pipe"));
}

#[test]
fn tide_structure_methods_are_not_whole_buffer_stubs() {
    // An empty root: the server indexes its workspace, and `/tmp` can hold anything.
    let scratch = Scratch::new("structure");
    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": {}, "rootUri": file_uri(&scratch.0) }),
    );
    lsp.notify("initialized", json!({}));
    let yaml = "name: Sentinel Rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n  tlp: clear\ndescription: |\n  hello\n  world\n";
    let uri = file_uri(&scratch.0.join("struct-rule.yaml"));
    let uri = uri.as_str();
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "languageId": "opentide-yaml",
                "version": 1,
                "text": yaml
            }
        }),
    );
    let _ = lsp.read();

    let folds = lsp.request(
        "textDocument/foldingRange",
        json!({ "textDocument": { "uri": uri } }),
    );
    let ranges = folds["result"].as_array().unwrap();
    assert!(ranges.len() > 1, "{folds}");
    assert!(
        ranges
            .iter()
            .all(|r| !(r["startLine"] == 0 && r["endLine"].as_u64().unwrap() >= 4)),
        "folding must not be one whole-buffer region: {folds}"
    );

    let sel = lsp.request(
        "textDocument/selectionRange",
        json!({
            "textDocument": { "uri": uri },
            "positions": [{ "line": 2, "character": 4 }]
        }),
    );
    let parent_end = sel["result"][0]["parent"]["range"]["end"]["line"]
        .as_u64()
        .unwrap();
    assert!(
        parent_end < 5,
        "selection parent must be the metadata block, got {sel}"
    );

    let symbols = lsp.request("workspace/symbol", json!({ "query": "Sentinel Rule" }));
    let range = &symbols["result"][0]["location"]["range"];
    assert_eq!(range["start"]["line"], 0);
    assert!(
        range["end"]["character"].as_u64().unwrap() > range["start"]["character"].as_u64().unwrap()
    );

    let actions = lsp.request(
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": uri },
            "range": { "start": { "line": 4, "character": 0 }, "end": { "line": 4, "character": 4 } },
            "context": { "diagnostics": [] }
        }),
    );
    assert_eq!(actions["result"].as_array().unwrap().len(), 0, "{actions}");

    lsp.notify(
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": uri },
            "contentChanges": [
                { "range": { "start": { "line": 0, "character": 6 }, "end": { "line": 0, "character": 6 } }, "text": "X" },
                { "range": { "start": { "line": 0, "character": 7 }, "end": { "line": 0, "character": 7 } }, "text": "Y" }
            ]
        }),
    );
    let _ = lsp.read();
    let after = lsp.request("workspace/symbol", json!({ "query": "XYSentinel" }));
    assert!(
        !after["result"].as_array().unwrap().is_empty(),
        "both incremental edits must apply, got {after}"
    );

    lsp.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": uri } }),
    );
    let closed = lsp.read();
    assert_eq!(closed["method"], "textDocument/publishDiagnostics");
    assert!(
        closed["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let pull = lsp.request(
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    assert!(
        pull["result"]["items"].as_array().unwrap().is_empty(),
        "{pull}"
    );
}

#[test]
fn elastic_languages_over_stdio() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    lsp.notify("initialized", json!({}));
    // The URI suffix selects the engine when the client reports no known id.
    let cases = [
        (
            "file:///tmp/r.esql",
            "plaintext",
            "FROM logs-* METADATA _id | WEHRE x == 1",
            "esql_unknown_command",
        ),
        (
            "file:///tmp/r.eql",
            "plaintext",
            "sequence with maxspan=5w [a where true] [b where true]",
            "eql_maxspan_unit",
        ),
        (
            "file:///tmp/r.kuery",
            "plaintext",
            "message: cannot run",
            "kuery_parse_error",
        ),
        (
            "file:///tmp/r.lucene",
            "plaintext",
            "a:1 and b:2",
            "lucene_lowercase_operator",
        ),
    ];
    for (uri, language_id, text, code) in cases {
        let codes = published_codes(&mut lsp, uri, language_id, text);
        assert!(codes.iter().any(|c| c == code), "{uri}: {codes:?}");
    }
    let rule = "\
name: Elastic rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000077
  schema: rule::1.1
configurations:
  elastic:
    status: STAGING
    query: 'process.name:cmd.exe and _exists_:host.name'
    type: query
";
    let codes = published_codes(
        &mut lsp,
        "file:///tmp/objects/rules/elastic-rule.yaml",
        "yaml",
        rule,
    );
    assert!(
        codes.iter().any(|c| c == "kuery_lucene_syntax"),
        "the Elastic block's kuery query is analysed: {codes:?}"
    );
    let tokens = lsp.request(
        "textDocument/semanticTokens/full",
        json!({ "textDocument": { "uri": "file:///tmp/r.esql" } }),
    );
    let data = tokens["result"]["data"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(data.len() >= 10, "semantic tokens for .esql: {tokens}");

    // ECS completion replaces the dotted prefix already typed.
    let text = "host.name:x and process.pa";
    published_codes(&mut lsp, "file:///tmp/c.kuery", "plaintext", text);
    let items = lsp.request(
        "textDocument/completion",
        json!({
            "textDocument": { "uri": "file:///tmp/c.kuery" },
            "position": { "line": 0, "character": text.len() }
        }),
    );
    let item = items["result"]
        .as_array()
        .and_then(|a| a.iter().find(|i| i["label"] == "process.parent.name"))
        .cloned()
        .unwrap_or_else(|| panic!("ECS field completion: {items}"));
    assert_eq!(
        item["textEdit"]["range"]["start"]["character"], 16,
        "{item}"
    );
    assert_eq!(item["textEdit"]["newText"], "process.parent.name");
}

#[test]
fn falco_over_stdio() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    lsp.notify("initialized", json!({}));
    let codes = published_codes(
        &mut lsp,
        "file:///tmp/r.falco",
        "plaintext",
        "spawned_process and proc.nmae = bash",
    );
    assert_eq!(codes, vec!["falco_unknown_field"], "raw .falco file");
    let text = "spawned_process and proc.name = bash";
    published_codes(&mut lsp, "file:///tmp/h.falco", "falco", text);
    let hover = lsp.request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": "file:///tmp/h.falco" },
            "position": { "line": 0, "character": 3 }
        }),
    );
    let value = hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(value.contains("macro"), "{hover}");
    let tokens = lsp.request(
        "textDocument/semanticTokens/full",
        json!({ "textDocument": { "uri": "file:///tmp/h.falco" } }),
    );
    let data = tokens["result"]["data"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(data.len() >= 20, "semantic tokens for .falco: {tokens}");
    let rule = "\
name: Shell in container
metadata:
  uuid: 00000000-0000-4000-8003-000000000078
  schema: rule::1.0
configurations:
  sysdig:
    status: STAGING
    condition: >
      spawned_process and container
      and proc.name in (my_shells)
    lists:
    - name: my_shells
      items: [bash, sh]
    macros:
    - name: unused
      condition: proc.pid >
";
    let codes = published_codes(
        &mut lsp,
        "file:///tmp/objects/rules/shell-in-container.yaml",
        "yaml",
        rule,
    );
    assert!(
        codes.iter().any(|c| c == "falco_parse_error"),
        "the block's macro condition is analysed: {codes:?}"
    );
    assert!(
        !codes.iter().any(|c| c == "falco_unknown_macro"),
        "the block's list resolves: {codes:?}"
    );
}

/// A Sysdig rule whose `condition` (line 7) and `output` (line 8) are given.
fn sysdig_rule(condition: &str, output: &str) -> String {
    format!(
        "name: Probe\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000079\n  schema: rule::1.0\nconfigurations:\n  sysdig:\n    status: STAGING\n    condition: {condition}\n    output: {output}\n    lists:\n    - name: my_shells\n      items: [bash, sh]\n"
    )
}

/// Completion at the end of the condition (or of the output) of a probe rule.
fn complete_at(
    lsp: &mut Lsp,
    uri: &str,
    condition: &str,
    output: &str,
    in_output: bool,
) -> Vec<Value> {
    let text = sysdig_rule(condition, output);
    published_codes(lsp, uri, "yaml", &text);
    let (line, character) = if in_output {
        (8, "    output: ".len() + output.len())
    } else {
        (7, "    condition: ".len() + condition.len())
    };
    let r = lsp.request(
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": line, "character": character }
        }),
    );
    r["result"].as_array().cloned().unwrap_or_default()
}

fn labels(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(|i| i["label"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn falco_completion_follows_the_cursor_over_stdio() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    lsp.notify("initialized", json!({}));

    // Check position with a dotted prefix: filtered, each item replacing `proc.ex`.
    let items = complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c1.yaml",
        "spawned_process and proc.ex",
        "x",
        false,
    );
    assert!(!items.is_empty());
    for item in &items {
        let label = item["label"].as_str().unwrap();
        assert!(label.starts_with("proc.ex"), "{label}");
        assert_eq!(item["textEdit"]["newText"], label);
        assert_eq!(
            item["textEdit"]["range"]["start"]["character"],
            "    condition: spawned_process and ".len(),
            "{item}"
        );
        assert_eq!(item["filterText"], label);
    }
    assert!(labels(&items).contains(&"proc.exepath".to_string()));

    // Check position, no prefix: fields, the block's... default macros too.
    let items = complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c2.yaml",
        "proc.name = bash and ",
        "x",
        false,
    );
    let l = labels(&items);
    assert!(
        l.contains(&"proc.name".to_string()) && l.contains(&"spawned_process".to_string()),
        "{l:?}"
    );
    assert!(!l.contains(&"startswith".to_string()));

    // After a string field: the operators libsinsp's flt_is_comparable accepts
    // for CHARBUF, with modifiers; the byte-buffer operators are not among them.
    let l = labels(&complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c3.yaml",
        "proc.name ",
        "x",
        false,
    ));
    for op in [
        "=",
        "startswith",
        "startswith anyof",
        "in",
        "exists",
        "regex",
    ] {
        assert!(l.contains(&op.to_string()), "{op} in {l:?}");
    }
    assert!(
        !l.contains(&"bcontains".to_string()) && !l.contains(&"proc.name".to_string()),
        "{l:?}"
    );

    // After a numeric field: numeric operators, no string-only ones.
    let l = labels(&complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c4.yaml",
        "proc.pid ",
        "x",
        false,
    ));
    assert!(
        l.contains(&"<".to_string()) && !l.contains(&"startswith".to_string()),
        "{l:?}"
    );

    // After an operator: the field's enumerated values, or nothing.
    let l = labels(&complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c5.yaml",
        "fd.type = ",
        "x",
        false,
    ));
    assert!(
        l.contains(&"ipv4".to_string()) && l.contains(&"file".to_string()),
        "{l:?}"
    );
    let l = labels(&complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c6.yaml",
        "evt.type = exec",
        "x",
        false,
    ));
    assert!(
        l.contains(&"execve".to_string()) && l.iter().all(|e| e.starts_with("exec")),
        "{l:?}"
    );
    let l = labels(&complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c7.yaml",
        "proc.name startswith ",
        "x",
        false,
    ));
    assert!(l.is_empty(), "no values for a free string field: {l:?}");

    // Inside a value list: the block's lists first, then the defaults.
    let l = labels(&complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c8.yaml",
        "proc.name in (",
        "x",
        false,
    ));
    assert_eq!(l.first().map(String::as_str), Some("my_shells"), "{l:?}");
    assert!(l.contains(&"shell_binaries".to_string()));
    let l = labels(&complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c9.yaml",
        "fd.name startswith anyof (",
        "x",
        false,
    ));
    assert!(l.contains(&"my_shells".to_string()), "{l:?}");

    // In the output: fields after `%`.
    let items = complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c10.yaml",
        "spawned_process",
        "shell %proc.na",
        true,
    );
    let l = labels(&items);
    assert!(
        l.contains(&"proc.name".to_string()) && l.iter().all(|f| f.starts_with("proc.na")),
        "{l:?}"
    );
    let l = labels(&complete_at(
        &mut lsp,
        "file:///tmp/objects/rules/c11.yaml",
        "spawned_process",
        "shell ",
        true,
    ));
    assert!(l.is_empty(), "{l:?}");
}

#[test]
fn sysdig_lists_follow_falcos_load_order_over_stdio() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    lsp.notify("initialized", json!({}));
    let rule = |lists: &str| {
        format!(
            "name: Lists\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000080\n  schema: rule::1.0\nconfigurations:\n  sysdig:\n    status: STAGING\n    condition: evt.type in (l1) and proc.name = bash\n    lists:\n{lists}"
        )
    };
    // l1 names the later l2: it still expands (to execve), so no finding at all
    // from the Falco checks or the block's constraints.
    let codes = published_codes(
        &mut lsp,
        "file:///tmp/objects/rules/lists-forward.yaml",
        "yaml",
        &rule("    - name: l1\n      items: [l2]\n    - name: l2\n      items: [execve]\n"),
    );
    assert!(
        !codes
            .iter()
            .any(|c| c.starts_with("falco_") || c.starts_with("sysdig_")),
        "{codes:?}"
    );
    // l1 names itself: the name stays literal, a warning; as an event it is unknown.
    let codes = published_codes(
        &mut lsp,
        "file:///tmp/objects/rules/lists-self.yaml",
        "yaml",
        &rule("    - name: l1\n      items: [l1, execve]\n"),
    );
    assert!(
        codes.iter().any(|c| c == "sysdig_list_self_reference"),
        "{codes:?}"
    );
    assert!(
        codes.iter().any(|c| c == "falco_unknown_event"),
        "{codes:?}"
    );
    assert!(
        !codes.iter().any(|c| c == "sysdig_definition_order"),
        "{codes:?}"
    );
}

#[test]
fn falco_hover_over_stdio() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    lsp.notify("initialized", json!({}));
    let uri = "file:///tmp/objects/rules/hover.yaml";
    let text = sysdig_rule(
        "spawned_process and proc.name in (my_shells, shell_binaries)",
        "shell %proc.name",
    );
    published_codes(&mut lsp, uri, "yaml", &text);
    let mut hover = |line: u32, character: usize| -> String {
        let r = lsp.request(
            "textDocument/hover",
            json!({
                "textDocument": { "uri": uri },
                "position": { "line": line, "character": character }
            }),
        );
        r["result"]["contents"]["value"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    let col = |needle: &str| text.lines().nth(7).unwrap().find(needle).unwrap() + 1;
    // A default macro, attributed to the stable rules file.
    let h = hover(7, col("spawned_process"));
    assert!(
        h.contains("execve") && h.contains("falco_rules.yaml"),
        "{h}"
    );
    assert!(!h.contains("sandbox"), "{h}");
    // A field: its type and description.
    let h = hover(7, col("proc.name"));
    assert!(h.contains("proc.name") && h.contains("CHARBUF"), "{h}");
    // The block's own list, and a default list.
    let h = hover(7, col("my_shells"));
    assert!(h.contains("this block") && h.contains("bash, sh"), "{h}");
    let h = hover(7, col("shell_binaries"));
    assert!(
        h.contains("Falco default rules") && h.contains("bash"),
        "{h}"
    );
    // A block key: the Tide field's documentation.
    let h = hover(6, 6);
    assert!(h.to_lowercase().contains("status"), "{h}");
}

#[test]
fn initialize_installs_the_workspace_field_catalog() {
    let root = std::env::temp_dir().join(format!("opentide-lsp-catalog-{}", std::process::id()));
    let catalogs = root.join(".opentide/lsp/catalogs/generated");
    std::fs::create_dir_all(&catalogs).unwrap();
    std::fs::create_dir_all(root.join("objects/rules")).unwrap();
    std::fs::write(
        catalogs.join("fields.json"),
        r#"{"opentide": "0.19.0", "fields": [
            {"schema": "rule", "path": "metadata", "name": "metadata", "type": "object"},
            {"schema": "rule", "path": "metadata.tlp", "name": "tlp", "type": "string",
             "enum": ["clear", "house"]}]}"#,
    )
    .unwrap();
    let rule = "name: House Rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n  tlp: house\n";
    let uri = file_uri(&root.join("objects/rules/house-rule.yaml"));

    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": {}, "rootUri": file_uri(&root) }),
    );
    let with_catalog = published_codes(&mut lsp, &uri, "opentide-yaml", rule);
    drop(lsp);

    // Without a root, the workspace around the document is found (#185
    // P2.1): its catalog applies.
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    let discovered = published_codes(&mut lsp, &uri, "opentide-yaml", rule);
    drop(lsp);

    // A document in no workspace gets the bundled catalogs.
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    let bundled = published_codes(
        &mut lsp,
        "file:///opentide-no-such-workspace/objects/rules/house-rule.yaml",
        "opentide-yaml",
        rule,
    );
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(discovered, with_catalog);

    assert!(
        !with_catalog.contains(&"vocab_unknown".to_string()),
        "{with_catalog:?}"
    );
    assert!(
        bundled.contains(&"vocab_unknown".to_string()),
        "{bundled:?}"
    );
}

fn cli_codes(file: &std::path::Path) -> Vec<String> {
    let out = Command::new(bin())
        .args(["analyze", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let diagnostics: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    let mut codes: Vec<String> = diagnostics
        .iter()
        .map(|d| d["code"].as_str().unwrap().to_string())
        .collect();
    codes.sort();
    codes
}

/// One workspace file that is not UTF-8 is left out of the index. It used to
/// fail `analyze` outright, and leave the stdio server with no index at all,
/// so every reference to another object was reported as unresolved.
#[test]
fn an_unreadable_workspace_file_does_not_break_analysis() {
    let corpus = repo_root().join("crates/testdata/workspaces/tide_corpus");
    let rule = "objects/rules/rule-0001-sentinel-kql.yaml";
    let expected = cli_codes(&corpus.join(rule));

    let scratch = Scratch::new("unreadable");
    copy_dir(&corpus, &scratch.0);
    std::fs::write(
        scratch.0.join("objects/rules/broken.yaml"),
        [0xff, 0xfe, 0x00],
    )
    .unwrap();
    assert_eq!(cli_codes(&scratch.0.join(rule)), expected);

    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": {}, "rootUri": file_uri(&scratch.0) }),
    );
    lsp.notify("initialized", json!({}));
    let path = scratch.0.join(rule);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut published = published_codes(&mut lsp, &file_uri(&path), "opentide-yaml", &text);
    published.sort();
    assert_eq!(published, expected);
}

/// A raw query is analysed on its own: the CLI does not read the directories
/// around it, so an unreadable YAML there cannot fail it.
#[test]
fn a_raw_query_file_ignores_the_yaml_around_it() {
    let scratch = Scratch::new("raw-query");
    std::fs::write(scratch.0.join("broken.yaml"), [0xff, 0xfe, 0x00]).unwrap();
    let dir = scratch.0.join("queries");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("query.kql");
    std::fs::write(&file, "SecurityEvent | wher EventID == 1").unwrap();
    assert!(!cli_codes(&file).is_empty());
}

#[test]
fn an_undeclared_table_has_a_code_action_that_declares_it() {
    let scratch = Scratch::new("declare-table");
    let root = &scratch.0;
    let visibility = "\u{feff}[[logsources]]\nname = \"NTANetAnalytics\"\ndescription = \"Flows.\"\nsystem = \"sentinel\"\n";
    std::fs::create_dir_all(root.join(".opentide/configurations")).unwrap();
    std::fs::write(
        root.join(".opentide/configurations/visibility.toml"),
        visibility,
    )
    .unwrap();
    let uri = file_uri(&root.join("hunt.kql"));

    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": {}, "rootUri": file_uri(root) }),
    );
    let codes = published_codes(&mut lsp, &uri, "kql", "NTAIpDetails | take 1");
    assert_eq!(codes, vec!["kql_table_not_declared".to_string()]);
    let actions = lsp.request(
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": uri },
            "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 3 } },
            "context": { "diagnostics": [] }
        }),
    );
    let action = actions["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| {
            a["title"] == "Add a [[logsources]] entry declaring 'NTAIpDetails' to visibility.toml"
        })
        .unwrap_or_else(|| panic!("{actions}"))
        .clone();
    let changes = &action["edit"]["changes"];
    let (target, edits) = changes.as_object().unwrap().iter().next().unwrap();
    assert!(
        target.ends_with("/.opentide/configurations/visibility.toml"),
        "{target}"
    );
    // A new log source after the last line; the existing one is not edited.
    assert_eq!(
        edits[0]["newText"],
        "\n[[logsources]]\nname = \"NTAIpDetails\"\ndescription = \"\"\nsystem = \"sentinel\"\n"
    );
    assert_eq!(edits[0]["range"]["start"]["line"], 4);
    assert_eq!(edits[0]["range"]["start"]["character"], 0);
}

#[test]
fn an_undeclared_splunk_sourcetype_has_a_code_action_that_adds_it() {
    let scratch = Scratch::new("declare-index");
    let root = &scratch.0;
    std::fs::create_dir_all(root.join(".opentide/configurations")).unwrap();
    std::fs::write(
        root.join(".opentide/configurations/visibility.toml"),
        "[[logsources]]\nname = \"WinEventLog:Security\"\ndescription = \"Events.\"\nsystem = \"splunk\"\n",
    )
    .unwrap();
    let uri = file_uri(&root.join("hunt.spl"));
    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": {}, "rootUri": file_uri(root) }),
    );
    let codes = published_codes(&mut lsp, &uri, "spl", "sourcetype=sysmon EventCode=1");
    assert!(
        codes.contains(&"spl_dataset_not_declared".to_string()),
        "{codes:?}"
    );
    let actions = lsp.request(
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": uri },
            "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 17 } },
            "context": { "diagnostics": [] }
        }),
    );
    let action = actions["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["title"] == "Add a [[logsources]] entry declaring 'sysmon' to visibility.toml")
        .unwrap_or_else(|| panic!("{actions}"))
        .clone();
    let changes = &action["edit"]["changes"];
    let (_, edits) = changes.as_object().unwrap().iter().next().unwrap();
    assert_eq!(
        edits[0]["newText"],
        "\n[[logsources]]\nname = \"sysmon\"\ndescription = \"\"\nsystem = \"splunk\"\n"
    );
}

/// No visibility.toml: the quick fix on `kql_unknown_table` creates it, for
/// a client that can create files (#185 P2.4). Any other client gets no
/// such action.
#[test]
fn the_quick_fix_creates_visibility_toml_when_there_is_none() {
    let scratch = Scratch::new("declare-create");
    let root = &scratch.0;
    let uri = file_uri(&root.join("hunt.kql"));
    let request = json!({
        "textDocument": { "uri": uri },
        "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 3 } },
        "context": { "diagnostics": [] }
    });
    let title = "Add a [[logsources]] entry declaring 'MyCustom_CL' to visibility.toml";

    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": {}, "rootUri": file_uri(root) }),
    );
    published_codes(&mut lsp, &uri, "kql", "MyCustom_CL | take 1");
    let actions = lsp.request("textDocument/codeAction", request.clone());
    assert!(
        !actions["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["title"] == title),
        "{actions}"
    );
    drop(lsp);

    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({
            "capabilities": { "workspace": { "workspaceEdit": {
                "documentChanges": true, "resourceOperations": ["create"]
            } } },
            "rootUri": file_uri(root)
        }),
    );
    let codes = published_codes(&mut lsp, &uri, "kql", "MyCustom_CL | take 1");
    assert_eq!(codes, vec!["kql_unknown_table".to_string()]);
    let actions = lsp.request("textDocument/codeAction", request);
    let action = actions["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["title"] == title)
        .unwrap_or_else(|| panic!("{actions}"))
        .clone();
    assert_eq!(action["isPreferred"], true, "{action}");
    let changes = action["edit"]["documentChanges"].as_array().unwrap();
    assert_eq!(changes[0]["kind"], "create");
    let text = changes[1]["edits"][0]["newText"].as_str().unwrap();
    assert!(
        text.contains("name = \"MyCustom_CL\"\ndescription = \"\"\nsystem = \"sentinel\""),
        "{text}"
    );
}

/// visibility.toml applies as it is edited: in the editor, before it is
/// saved, and on disk, through the file watcher.
#[test]
#[expect(
    clippy::format_collect,
    reason = "a fixture of a few lines: the plainest way to write it"
)]
fn editing_visibility_toml_rechecks_open_queries() {
    let scratch = Scratch::new("visibility-live");
    let root = &scratch.0;
    let config = root.join(".opentide/configurations");
    std::fs::create_dir_all(&config).unwrap();
    let path = config.join("visibility.toml");
    let visibility_uri = file_uri(&path);
    let declare = |tables: &[&str]| {
        tables
            .iter()
            .map(|t| {
                format!(
                    "[[logsources]]\nname = \"{t}\"\ndescription = \"x\"\nsystem = \"sentinel\"\n\n"
                )
            })
            .collect::<String>()
    };
    let uri = file_uri(&root.join("hunt.kql"));

    let mut lsp = Lsp::spawn();
    let init = json!({
        "capabilities": { "workspace": { "didChangeWatchedFiles": { "dynamicRegistration": true } } },
        "rootUri": file_uri(root)
    });
    lsp.request("initialize", init);
    lsp.notify("initialized", json!({}));
    let register = lsp.read();
    assert_eq!(
        register["method"], "client/registerCapability",
        "{register}"
    );
    // The client's answer is not a request: the server says nothing back.
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));

    // Nothing declared: a documented table is fine.
    assert!(published_codes(&mut lsp, &uri, "kql", "NTAIpDetails | take 1").is_empty());

    // Opened and edited in the editor, not saved.
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": {
            "uri": visibility_uri, "languageId": "toml", "version": 1,
            "text": declare(&["NTANetAnalytics"])
        } }),
    );
    assert_eq!(
        next_diagnostics(&mut lsp, &uri),
        vec!["kql_table_not_declared"]
    );
    // Mid-edit text that is not TOML keeps the declarations in use.
    lsp.notify(
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": visibility_uri, "version": 2 },
            "contentChanges": [{ "text": "[[logsources" }]
        }),
    );
    lsp.notify(
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": visibility_uri, "version": 3 },
            "contentChanges": [{ "text": declare(&["NTANetAnalytics", "NTAIpDetails"]) }]
        }),
    );
    assert!(next_diagnostics(&mut lsp, &uri).is_empty());

    // Closed unsaved: the file on disk (none) applies again.
    lsp.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": visibility_uri } }),
    );
    assert!(next_diagnostics(&mut lsp, &uri).is_empty());

    // Written outside the editor.
    std::fs::write(&path, declare(&["NTANetAnalytics"])).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": visibility_uri, "type": 1 }] }),
    );
    assert_eq!(
        next_diagnostics(&mut lsp, &uri),
        vec!["kql_table_not_declared"]
    );
}

/// A Tide document that starts with a UTF-8 byte-order mark gets the same
/// diagnostics, at the same places, as without it, and hover and completion
/// work in its query (#150). The editor counts no column for the mark.
#[test]
fn a_bom_tide_document_is_analysed_like_one_without() {
    let rule = "name: BOM Rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000150\n  schema: rule::1.0\nconfigurations:\n  sentinel:\n    query: |\n      SecurityEvent\n      | frobnicate EventID\n      | where \n";
    // One server per copy, so the two are not each other's `duplicate_id`.
    let uri = "file:///tmp/objects/rules/bom-rule.yaml";
    let mut published = Vec::new();
    let mut last = None;
    for text in [rule.to_string(), format!("\u{feff}{rule}")] {
        let lsp = last.insert(Lsp::spawn());
        lsp.request("initialize", json!({ "capabilities": {} }));
        lsp.notify("initialized", json!({}));
        lsp.notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": "opentide-yaml",
                    "version": 1,
                    "text": text
                }
            }),
        );
        let msg = lsp.read();
        assert_eq!(msg["method"], "textDocument/publishDiagnostics", "{msg}");
        let mut diagnostics: Vec<(String, Value)> = msg["params"]["diagnostics"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|d| {
                (
                    d["code"].as_str().unwrap_or("").to_string(),
                    d["range"].clone(),
                )
            })
            .collect();
        diagnostics.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.to_string().cmp(&b.1.to_string())));
        published.push(diagnostics);
    }
    assert!(
        published[0]
            .iter()
            .any(|(code, range)| code == "kql_unknown_operator" && range["start"]["line"] == 8),
        "{:?}",
        published[0]
    );
    assert_eq!(published[1], published[0]);
    let mut lsp = last.expect("the BOM copy's server");

    let hover = lsp.request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 7, "character": 8 }
        }),
    );
    assert!(
        hover["result"]["contents"]["value"]
            .as_str()
            .unwrap_or("")
            .contains("SecurityEvent"),
        "{hover}"
    );
    let completion = lsp.request(
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 9, "character": 14 }
        }),
    );
    assert!(
        completion["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["label"] == "EventID"),
        "{completion}"
    );
}

/// The standalone binary has no configuration checker: a configuration file
/// is `opentide-config`, never parsed as YAML, and gets no diagnostics, no
/// tokens and no hover. Other TOML is not read at all.
#[test]
fn configuration_toml_without_a_host_checker_reports_nothing() {
    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "processId": null, "rootUri": null, "capabilities": {} }),
    );
    lsp.notify("initialized", json!({}));
    let open = |lsp: &mut Lsp, uri: &str, text: &str| {
        lsp.notify(
            "textDocument/didOpen",
            json!({ "textDocument": {
                "uri": uri, "languageId": "toml", "version": 1, "text": text
            }}),
        );
    };
    open(
        &mut lsp,
        "file:///w/Cargo.toml",
        "[package]\nname = \"x\"\n",
    );
    let sharing = "file:///w/.opentide/configurations/sharing.toml";
    open(
        &mut lsp,
        sharing,
        "[[misp]]\nname = \"misp-internal\"\ndistribution = \"this-community\"\n",
    );
    // Cargo.toml published nothing: the first frame is sharing.toml's.
    let msg = lsp.read();
    assert_eq!(msg["method"], "textDocument/publishDiagnostics", "{msg}");
    assert_eq!(msg["params"]["uri"], sharing, "{msg}");
    assert_eq!(msg["params"]["diagnostics"], json!([]), "{msg}");

    let tokens = lsp.request(
        "textDocument/semanticTokens/full",
        json!({ "textDocument": { "uri": sharing } }),
    );
    assert_eq!(tokens["result"]["data"], json!([]), "{tokens}");
    let hover = lsp.request(
        "textDocument/hover",
        json!({ "textDocument": { "uri": sharing }, "position": { "line": 2, "character": 2 } }),
    );
    assert_eq!(hover["result"], Value::Null, "{hover}");
}

/// #178: an incremental edit after a multi-byte character panicked the
/// server (it read the UTF-16 column as a byte index).
#[test]
fn an_edit_after_a_multi_byte_character_keeps_the_server_running() {
    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "processId": null, "rootUri": null, "capabilities": {} }),
    );
    lsp.notify("initialized", json!({}));
    let uri = "file:///q.kql";
    let text = "SecurityEvent | where Account == \"日本\"";
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri, "languageId": "kql", "version": 1, "text": text } }),
    );
    next_diagnostics(&mut lsp, uri);
    // Column 35 is after `日本`, and 36 after the emoji's two units.
    for (version, character, insert) in [(2, 35, "😀"), (3, 37, "é")] {
        lsp.notify(
            "textDocument/didChange",
            json!({
                "textDocument": { "uri": uri, "version": version },
                "contentChanges": [{
                    "range": {
                        "start": { "line": 0, "character": character },
                        "end": { "line": 0, "character": character }
                    },
                    "text": insert
                }]
            }),
        );
        next_diagnostics(&mut lsp, uri);
    }
    let reply = lsp.request("shutdown", Value::Null);
    assert_eq!(reply["result"], Value::Null, "{reply}");
}

/// #181: the server reads and indexes `objects/` once. An objective created
/// on disk after start is found through the file watcher, and also, for a
/// client that cannot watch files, on the next request.
#[test]
fn objects_written_after_start_are_indexed() {
    let source = repo_root().join("crates/testdata/objects");
    for watch in [true, false] {
        let root = std::env::temp_dir().join(format!(
            "opentide-index-cache-{}-{watch}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let rules = root.join("objects/rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::create_dir_all(root.join("objects/objectives")).unwrap();
        let rule_text = std::fs::read_to_string(source.join("rules/rule-1.0.yaml")).unwrap();
        let rule = rules.join("rule-1.0.yaml");
        std::fs::write(&rule, &rule_text).unwrap();
        let rule_uri = file_uri(&rule);

        let mut lsp = Lsp::spawn();
        let capabilities = if watch {
            json!({ "workspace": { "didChangeWatchedFiles": { "dynamicRegistration": true } } })
        } else {
            json!({})
        };
        lsp.request(
            "initialize",
            json!({ "processId": null, "rootUri": file_uri(&root), "capabilities": capabilities }),
        );
        lsp.notify("initialized", json!({}));
        lsp.notify(
            "textDocument/didOpen",
            json!({ "textDocument": { "uri": rule_uri, "languageId": "opentide-yaml", "version": 1, "text": rule_text } }),
        );
        let before = codes_of(&published_for(&mut lsp, &rule_uri));
        assert!(before.contains(&"invalid_ref".to_string()), "{before:?}");

        let objective = root.join("objects/objectives/objective-1.0.yaml");
        std::fs::copy(source.join("objective-1.0.yaml"), &objective).unwrap();
        if watch {
            lsp.notify(
                "workspace/didChangeWatchedFiles",
                json!({ "changes": [{ "uri": file_uri(&objective), "type": 1 }] }),
            );
        } else {
            lsp.notify(
                "textDocument/didChange",
                json!({ "textDocument": { "uri": rule_uri, "version": 2 }, "contentChanges": [{ "text": rule_text }] }),
            );
        }
        let after = codes_of(&published_for(&mut lsp, &rule_uri));
        assert!(
            !after.contains(&"invalid_ref".to_string()),
            "watch={watch}: {after:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// #185 P0.1: editors send any YAML as `yaml`. Only Tide objects are read:
/// a CI workflow gets nothing, while a rule is analysed under `objects/` or,
/// in a folder `paths.toml` moved, when it names a Tide schema.
#[test]
fn only_tide_yaml_is_analysed() {
    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "processId": null, "rootUri": null, "capabilities": {} }),
    );
    lsp.notify("initialized", json!({}));
    let open = |lsp: &mut Lsp, uri: &str, text: &str| {
        lsp.notify(
            "textDocument/didOpen",
            json!({ "textDocument": { "uri": uri, "languageId": "yaml", "version": 1, "text": text } }),
        );
    };
    let rule =
        std::fs::read_to_string(repo_root().join("crates/testdata/objects/rules/rule-1.0.yaml"))
            .unwrap();
    open(
        &mut lsp,
        "file:///w/.github/workflows/ci.yml",
        "name: CI\non: push\njobs: {}\n",
    );
    open(&mut lsp, "file:///w/.pre-commit-config.yaml", "repos: []\n");
    open(&mut lsp, "file:///w/detections/rules/r.yaml", &rule);
    // The first frame is the rule's: neither CI file published anything.
    let first = lsp.read();
    assert_eq!(
        first["params"]["uri"], "file:///w/detections/rules/r.yaml",
        "{first}"
    );
    open(
        &mut lsp,
        "file:///w/objects/rules/broken.yaml",
        "name: Broken\n",
    );
    // The rule is checked again (it may reference the new object), then the
    // new one.
    let mut second = lsp.read();
    while second["params"]["uri"] == "file:///w/detections/rules/r.yaml" {
        second = lsp.read();
    }
    assert_eq!(
        second["params"]["uri"], "file:///w/objects/rules/broken.yaml",
        "{second}"
    );
    assert!(
        !second["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// #185 P0.2: only `<root>/objects` is walked, and a symlinked directory is
/// not entered, so a link back up the tree indexes nothing twice.
#[test]
fn the_workspace_walk_stays_in_objects_and_ignores_symlinked_directories() {
    let source = repo_root().join("crates/testdata/objects");
    let root = std::env::temp_dir().join(format!("opentide-walk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let rules = root.join("objects/rules");
    std::fs::create_dir_all(&rules).unwrap();
    let rule_text = std::fs::read_to_string(source.join("rules/rule-1.0.yaml")).unwrap();
    std::fs::write(rules.join("rule-1.0.yaml"), &rule_text).unwrap();
    // A copy of the same object outside objects/: never read.
    std::fs::create_dir_all(root.join("backup")).unwrap();
    std::fs::write(root.join("backup/rule-1.0.yaml"), &rule_text).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&rules, rules.join("loop")).unwrap();

    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "processId": null, "rootUri": file_uri(&root), "capabilities": {} }),
    );
    lsp.notify("initialized", json!({}));
    let uri = file_uri(&rules.join("rule-1.0.yaml"));
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri, "languageId": "opentide-yaml", "version": 1, "text": rule_text } }),
    );
    let codes = next_diagnostics(&mut lsp, &uri);
    assert!(!codes.contains(&"duplicate_id".to_string()), "{codes:?}");
    let symbols = lsp.request("workspace/symbol", json!({ "query": "" }));
    let count = symbols["result"].as_array().map_or(0, Vec::len);
    assert_eq!(count, 1, "{symbols}");
    let _ = std::fs::remove_dir_all(&root);
}

/// #185 P0.6: the LSP lifecycle, and the exit code that says whether the
/// client shut the server down first.
#[test]
fn the_lifecycle_is_enforced_and_the_exit_code_reports_it() {
    let hover = json!({ "textDocument": { "uri": "file:///q.kql" }, "position": { "line": 0, "character": 0 } });

    // Before initialize: a request is refused, a notification dropped.
    let mut lsp = Lsp::spawn();
    let early = lsp.request("textDocument/hover", hover.clone());
    assert_eq!(early["error"]["code"], -32002, "{early}");
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": "file:///q.kql", "languageId": "kql", "version": 1, "text": "T | wher x" } }),
    );
    let init = lsp.request("initialize", json!({ "capabilities": {} }));
    assert!(init["result"]["capabilities"].is_object(), "{init}");
    // Nothing was published for the dropped didOpen: the next frame is the
    // answer to the second initialize, which is refused.
    let again = lsp.request("initialize", json!({ "capabilities": {} }));
    assert_eq!(again["error"]["code"], -32600, "{again}");

    // After shutdown: requests are refused; exit then exits 0.
    assert_eq!(lsp.request("shutdown", Value::Null)["result"], Value::Null);
    let late = lsp.request("textDocument/hover", hover.clone());
    assert_eq!(late["error"]["code"], -32600, "{late}");
    lsp.notify("exit", Value::Null);
    assert_eq!(exit_code(lsp), 0);

    // exit without shutdown: 1.
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    lsp.notify("exit", Value::Null);
    assert_eq!(exit_code(lsp), 1);

    // The stream ends without shutdown: 1.
    let status = Command::new(bin())
        .arg("--stdio")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}

/// UC-X.2 (#844): the test client ends its server with `exit` and the server
/// exits on its own (status 1: no `shutdown` came first), rather than being
/// killed, which would lose the coverage profile an instrumented build writes
/// at exit.
#[test]
fn the_test_client_ends_its_server_with_exit() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    let status = lsp.end().expect("the server exits within 10 s");
    assert_eq!(status.code(), Some(1), "{status:?}");
    // Ending it again finds it exited.
    assert_eq!(lsp.end().and_then(|s| s.code()), Some(1));
}

/// #185 P0.7: a frame whose body is not a message is answered with
/// `id: null`, and the session goes on.
#[test]
fn malformed_frames_are_answered_and_the_session_continues() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    for (body, code) in [
        ("{not json", -32700),
        (
            "[{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"shutdown\"}]",
            -32600,
        ),
    ] {
        raw(&mut lsp, body);
        let reply = lsp.read();
        assert_eq!(reply["error"]["code"], code, "{body}: {reply}");
        assert_eq!(reply["id"], Value::Null, "{reply}");
    }
    // No `jsonrpc` member and a lower-case header: still answered.
    raw(
        &mut lsp,
        r#"{"id": 7, "method": "textDocument/hover", "params": {"textDocument": {"uri": "file:///none.kql"}, "position": {"line": 0, "character": 0}}}"#,
    );
    let reply = lsp.read();
    assert_eq!(reply["id"], 7, "{reply}");
    // `"id": null` is not a valid id: answered with `id: null`.
    raw(
        &mut lsp,
        r#"{"jsonrpc": "2.0", "id": null, "method": "opentide/not-a-method"}"#,
    );
    let reply = lsp.read();
    assert!(reply.get("id").is_some_and(Value::is_null), "{reply}");
    assert_eq!(reply["error"]["code"], -32600, "{reply}");
    assert_eq!(lsp.request("shutdown", Value::Null)["result"], Value::Null);
}

/// #185 P0.5: a handler that panics fails its request, not the session.
#[test]
fn a_panicking_handler_fails_its_request_and_the_session_continues() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    let failed = lsp.request("opentide/__panic", Value::Null);
    assert_eq!(failed["error"]["code"], -32603, "{failed}");
    let hover = lsp.request(
        "textDocument/hover",
        json!({ "textDocument": { "uri": "file:///none.kql" }, "position": { "line": 0, "character": 0 } }),
    );
    assert!(hover.get("result").is_some(), "{hover}");
    assert_eq!(lsp.request("shutdown", Value::Null)["result"], Value::Null);
}

/// #185 P0.4: navigation reads and writes LSP columns (UTF-16 units) on
/// lines with multi-byte characters, where bytes and columns differ.
#[test]
fn navigation_uses_utf16_columns_after_multi_byte_characters() {
    let objective =
        std::fs::read_to_string(repo_root().join("crates/testdata/objects/objective-1.0.yaml"))
            .unwrap();
    let uuid = "00000000-0000-4000-8002-000000000001";
    assert!(objective.contains(uuid));
    let prefix = "# 😀日本é ";
    let line_text = format!("{prefix}{uuid}");
    let text = format!("name: Emoji 😀 notes\n{line_text}\n");
    let col = prefix.encode_utf16().count() as u64; // 8, where the byte index is 15

    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "processId": null, "rootUri": null, "capabilities": {} }),
    );
    lsp.notify("initialized", json!({}));
    let open = |lsp: &mut Lsp, uri: &str, text: &str| {
        lsp.notify(
            "textDocument/didOpen",
            json!({ "textDocument": { "uri": uri, "languageId": "opentide-yaml", "version": 1, "text": text } }),
        );
    };
    open(&mut lsp, "file:///w/objects/objectives/o.yaml", &objective);
    open(&mut lsp, "file:///w/objects/notes.yaml", &text);
    let at = |character: u64| json!({ "textDocument": { "uri": "file:///w/objects/notes.yaml" }, "position": { "line": 1, "character": character } });

    let definition = lsp.request("textDocument/definition", at(col + 3));
    assert!(
        definition["result"].is_object()
            || definition["result"]
                .as_array()
                .is_some_and(|a| !a.is_empty()),
        "{definition}"
    );

    let highlights = lsp.request("textDocument/documentHighlight", at(col + 3));
    let first = &highlights["result"][0]["range"];
    assert_eq!(first["start"]["character"], col, "{highlights}");
    assert_eq!(
        first["end"]["character"],
        col + uuid.len() as u64,
        "{highlights}"
    );

    let selection = lsp.request(
        "textDocument/selectionRange",
        json!({ "textDocument": { "uri": "file:///w/objects/notes.yaml" }, "positions": [{ "line": 1, "character": 0 }] }),
    );
    assert_eq!(
        selection["result"][0]["range"]["end"]["character"],
        line_text.encode_utf16().count() as u64,
        "{selection}"
    );
    assert_eq!(lsp.request("shutdown", Value::Null)["result"], Value::Null);
}

/// #185 P0.9: resolving a completion item keeps its `textEdit` and
/// `filterText` (the dotted field's replace range), and only adds docs.
#[test]
fn resolving_a_completion_item_keeps_its_edit() {
    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "processId": null, "rootUri": null, "capabilities": {} }),
    );
    lsp.notify("initialized", json!({}));
    let uri = "file:///q.esql";
    let text = "FROM logs-endpoint.events.process-* | WHERE process.pa";
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri, "languageId": "esql", "version": 1, "text": text } }),
    );
    let items = lsp.request(
        "textDocument/completion",
        json!({ "textDocument": { "uri": uri }, "position": { "line": 0, "character": text.len() } }),
    );
    let item = items["result"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item.get("textEdit").is_some()))
        .cloned()
        .unwrap_or_else(|| panic!("a dotted item with a textEdit: {items}"));
    let resolved = lsp.request("completionItem/resolve", item.clone());
    let resolved = &resolved["result"];
    for key in ["label", "textEdit", "filterText", "kind", "insertText"] {
        assert_eq!(resolved[key], item[key], "{key}: {resolved}");
    }
    assert_eq!(lsp.request("shutdown", Value::Null)["result"], Value::Null);
}

/// #185 P0.8: a client that pulls diagnostics and supports refresh gets
/// them only by pulling, with a refresh request when another file changes
/// what they say; any other client gets them only pushed. Never both.
#[test]
fn diagnostics_are_either_pulled_or_pushed_never_both() {
    let uri = "file:///q.kql";
    let text = "SecurityEvent | wher EventID == 4688";
    let pull_capabilities = json!({
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": { "diagnostics": { "refreshSupport": true } }
    });

    let mut lsp = Lsp::spawn();
    let init = lsp.request(
        "initialize",
        json!({ "processId": null, "rootUri": null, "capabilities": pull_capabilities }),
    );
    assert!(
        init["result"]["capabilities"]["diagnosticProvider"].is_object(),
        "{init}"
    );
    lsp.notify("initialized", json!({}));
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri, "languageId": "kql", "version": 1, "text": text } }),
    );
    // Nothing is pushed: the next frame is the pull's answer.
    lsp.write(&json!({ "jsonrpc": "2.0", "id": 50, "method": "textDocument/diagnostic", "params": { "textDocument": { "uri": uri } } }));
    let pulled = lsp.read();
    assert_eq!(pulled["id"], 50, "nothing pushed before the pull: {pulled}");
    let items = pulled["result"]["items"].as_array().unwrap();
    assert!(!items.is_empty(), "{pulled}");
    assert!(
        items[0].get("data").is_some(),
        "pulled items carry data: {pulled}"
    );
    // visibility.toml changes what every document may say: ask for a pull.
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": "file:///w/.opentide/configurations/visibility.toml", "languageId": "toml", "version": 1, "text": "" } }),
    );
    let refresh = lsp.read();
    assert_eq!(
        refresh["method"], "workspace/diagnostic/refresh",
        "{refresh}"
    );
    assert_eq!(lsp.request("shutdown", Value::Null)["result"], Value::Null);

    let mut lsp = Lsp::spawn();
    let init = lsp.request(
        "initialize",
        json!({ "processId": null, "rootUri": null, "capabilities": {} }),
    );
    assert!(
        init["result"]["capabilities"]
            .get("diagnosticProvider")
            .is_none(),
        "{init}"
    );
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri, "languageId": "kql", "version": 1, "text": text } }),
    );
    let pushed = lsp.read();
    assert_eq!(
        pushed["method"], "textDocument/publishDiagnostics",
        "{pushed}"
    );
}

/// vscode.dev and github.dev: a document of a `vscode-vfs:` folder is no
/// `file:` URI, and a location in another object is that object's own URI,
/// not `file:///vscode-vfs://…`.
#[test]
fn a_definition_in_a_web_workspace_is_the_other_documents_own_uri() {
    let read = |path: &str| std::fs::read_to_string(repo_root().join(path)).unwrap();
    let folder = "vscode-vfs://github/org/repo";
    let rule_uri = format!("{folder}/objects/rules/rule-1.0.yaml");
    let objective_uri = format!("{folder}/objects/objectives/objective-1.0.yaml");
    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": {}, "workspaceFolders": [{ "uri": folder, "name": "repo" }] }),
    );
    lsp.notify("initialized", json!({}));
    for (uri, path) in [
        (&objective_uri, "crates/testdata/objects/objective-1.0.yaml"),
        (&rule_uri, "crates/testdata/objects/rules/rule-1.0.yaml"),
    ] {
        lsp.notify(
            "textDocument/didOpen",
            json!({ "textDocument": { "uri": uri, "languageId": "opentide-yaml", "version": 1, "text": read(path) } }),
        );
    }
    // `detection_model: <uuid>` is the rule's 17th line.
    let definition = lsp.request(
        "textDocument/definition",
        json!({ "textDocument": { "uri": rule_uri }, "position": { "line": 16, "character": 20 } }),
    );
    let result = &definition["result"];
    let location = if result.is_array() {
        &result[0]
    } else {
        result
    };
    assert_eq!(location["uri"], objective_uri.as_str(), "{definition}");
}
