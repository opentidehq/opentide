//! The language server one message at a time ([`MessageSession`]), as the
//! browser build drives it: no stdio, no filesystem, and the workspace
//! supplied on `initialize`.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_lsp::MessageSession;
use serde_json::{Value, json};

fn send(session: &mut MessageSession, mut message: Value) -> Vec<Value> {
    message["jsonrpc"] = json!("2.0");
    session
        .handle(&message.to_string())
        .iter()
        .map(|text| serde_json::from_str(text).expect("each reply is one JSON message"))
        .collect()
}

fn start(options: Value) -> MessageSession {
    let mut session = MessageSession::new();
    let replies = send(
        &mut session,
        json!({
            "id": 1,
            "method": "initialize",
            "params": { "processId": null, "rootUri": null, "capabilities": {}, "initializationOptions": options },
        }),
    );
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "opentide-lsp");
    assert!(
        send(
            &mut session,
            json!({ "method": "initialized", "params": {} })
        )
        .is_empty()
    );
    session
}

/// Open a document and return the diagnostics the server publishes for it.
fn open(session: &mut MessageSession, uri: &str, language: &str, text: &str) -> Vec<Value> {
    let replies = send(
        session,
        json!({
            "method": "textDocument/didOpen",
            "params": { "textDocument": { "uri": uri, "languageId": language, "version": 1, "text": text } },
        }),
    );
    let published = replies
        .iter()
        .find(|m| m["method"] == "textDocument/publishDiagnostics")
        .expect("didOpen publishes diagnostics");
    assert_eq!(published["params"]["uri"], uri);
    published["params"]["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .clone()
}

fn codes(diagnostics: &[Value]) -> Vec<&str> {
    diagnostics
        .iter()
        .filter_map(|d| d["code"].as_str())
        .collect()
}

fn request(session: &mut MessageSession, id: u64, method: &str, params: Value) -> Value {
    let replies = send(
        session,
        json!({ "id": id, "method": method, "params": params }),
    );
    let reply = replies
        .into_iter()
        .find(|m| m["id"] == id)
        .expect("a response with the request's id");
    assert!(reply.get("error").is_none(), "{reply}");
    reply["result"].clone()
}

const OBJECTIVE: &str = "00000000-0000-4000-8002-000000000001";

const RULE: &str = "name: Process creation
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
description: Process creation on a server.
status: STAGING
detection_model: 00000000-0000-4000-8002-000000000001
configurations:
  sentinel:
    query: |
      SecurityEvent
      | where EventID == 4688
";

#[test]
fn a_query_is_checked_hovered_and_completed() {
    let mut session = start(Value::Null);
    let broken = open(
        &mut session,
        "untitled:broken.kql",
        "kql",
        "SecurityEvent\n| wher EventID == 4688\n",
    );
    assert!(
        codes(&broken).iter().any(|c| c.starts_with("kql_")),
        "{broken:?}"
    );

    let text = "SecurityEvent\n| where EventID == 4688\n";
    assert!(open(&mut session, "untitled:q.kql", "kql", text).is_empty());
    let hover = request(
        &mut session,
        2,
        "textDocument/hover",
        json!({ "textDocument": { "uri": "untitled:q.kql" }, "position": { "line": 1, "character": 3 } }),
    );
    assert_eq!(hover["contents"]["kind"], "markdown");
    assert!(
        hover["contents"]["value"]
            .as_str()
            .unwrap()
            .contains("where"),
        "{hover}"
    );
    let items = request(
        &mut session,
        3,
        "textDocument/completion",
        json!({ "textDocument": { "uri": "untitled:q.kql" }, "position": { "line": 1, "character": 2 } }),
    );
    assert!(
        items
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["label"] == "where"),
        "{items}"
    );
}

/// The number of items a completion answered, `None` for `null`.
fn completed(
    session: &mut MessageSession,
    id: u64,
    uri: &str,
    line: u32,
    character: u32,
) -> Option<usize> {
    let items = request(
        session,
        id,
        "textDocument/completion",
        json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": character },
                "context": { "triggerKind": 2, "triggerCharacter": " " } }),
    );
    match items {
        Value::Null => None,
        Value::Array(items) => Some(items.len()),
        other => Some(other["items"].as_array().map_or(0, Vec::len)),
    }
}

/// A space typed after `| ` in a rule's query lists the operators, as in a
/// `.kql` file; a space typed in the YAML around it still opens nothing
/// (smoke C5).
#[test]
fn a_typed_space_completes_inside_a_rule_query_only() {
    let mut session = start(Value::Null);
    let uri = "objects/rules/typed.yaml";
    let text = RULE.replace("      | where EventID == 4688\n", "      | \n");
    open(&mut session, uri, "opentide-yaml", &text);
    let line = u32::try_from(text.lines().position(|l| l == "      | ").unwrap()).unwrap();
    let in_query = completed(&mut session, 2, uri, line, 8).expect("a list");
    assert!(in_query > 10, "{in_query} items after `| `");
    open(&mut session, "untitled:q.kql", "kql", "SecurityEvent\n| ");
    assert_eq!(
        completed(&mut session, 3, "untitled:q.kql", 1, 2),
        Some(in_query)
    );
    // `description: ` is prose: a space there opens no list.
    let prose = u32::try_from(
        text.lines()
            .position(|l| l.starts_with("description:"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(completed(&mut session, 4, uri, prose, 13), None);
}

/// A `language` the server does not know is `InvalidParams`, never "no
/// findings" (smoke C10).
#[test]
fn an_unknown_language_is_invalid_params() {
    let mut session = start(Value::Null);
    for (id, method, language) in [
        (2, "opentide/analyze", "sql"),
        (3, "opentide/analyze", "kqll"),
        (4, "opentide/highlight", "nonsense"),
        (7, "opentide/analyze", "opentide-config"),
    ] {
        let replies = send(
            &mut session,
            json!({ "id": id, "method": method, "params": { "text": "x", "language": language } }),
        );
        let reply = replies.iter().find(|m| m["id"] == id).expect("an answer");
        assert_eq!(reply["error"]["code"], -32602, "{reply}");
        let message = reply["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(&format!("language \"{language}\"")),
            "{message}"
        );
    }
    // An alias is a language, and no `language` is the method's default.
    let found = request(
        &mut session,
        5,
        "opentide/analyze",
        json!({ "text": "SecurityEvent | wher x", "language": "kusto" }),
    );
    assert!(
        !found["diagnostics"].as_array().unwrap().is_empty(),
        "{found}"
    );
    request(
        &mut session,
        6,
        "opentide/highlight",
        json!({ "text": "T | take 1" }),
    );
}

/// `opentide/fs/read` reads a path relative to a workspace folder as the
/// file in it, as an absolute one (smoke C10).
#[test]
fn fs_read_takes_a_path_relative_to_a_workspace_folder() {
    let mut session = MessageSession::new();
    send(
        &mut session,
        json!({ "id": 1, "method": "initialize", "params": {
            "processId": null, "capabilities": {},
            "workspaceFolders": [{ "uri": "file:///ws", "name": "ws" }],
            "initializationOptions": { "workspace": { "documents": [
                { "uri": "file:///ws/objects/rules/r.yaml", "text": RULE },
            ] } },
        } }),
    );
    send(
        &mut session,
        json!({ "method": "initialized", "params": {} }),
    );
    for (id, path) in [
        (2, "/ws/objects/rules/r.yaml"),
        (3, "objects/rules/r.yaml"),
        (8, "./objects/rules/r.yaml"),
    ] {
        let read = request(
            &mut session,
            id,
            "opentide/fs/read",
            json!({ "path": path }),
        );
        assert_eq!(read["text"], RULE, "{path}");
    }
    let missing = request(
        &mut session,
        4,
        "opentide/fs/read",
        json!({ "path": "objects/none.yaml" }),
    );
    assert_eq!(missing["text"], "");
}

#[test]
fn references_resolve_against_the_workspace_the_host_supplies() {
    let uri = "objects/rules/process-creation.yaml";

    // Alone, the rule's detection model is nothing the session has indexed.
    let mut alone = start(Value::Null);
    assert!(codes(&open(&mut alone, uri, "opentide-yaml", RULE)).contains(&"invalid_ref"));

    // An object the host knows by its metadata alone resolves, and hover names it.
    let mut known = start(json!({ "workspace": { "objects": [
        { "uuid": OBJECTIVE, "schema": "objective::1.0", "name": "Suspicious process creation" }
    ] } }));
    let diagnostics = open(&mut known, uri, "opentide-yaml", RULE);
    assert!(
        !codes(&diagnostics).contains(&"invalid_ref"),
        "{diagnostics:?}"
    );
    let line = RULE
        .lines()
        .position(|l| l.starts_with("detection_model:"))
        .unwrap();
    let hover = request(
        &mut known,
        2,
        "textDocument/hover",
        json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": 20 } }),
    );
    assert!(
        hover.to_string().contains("Suspicious process creation"),
        "{hover}"
    );

    // So does a whole document the host supplies.
    let objective = format!(
        "name: Suspicious process creation\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n"
    );
    let mut documents = start(json!({ "workspace": { "documents": [
        { "uri": "objects/objectives/suspicious-process-creation.yaml", "text": objective }
    ] } }));
    assert!(!codes(&open(&mut documents, uri, "opentide-yaml", RULE)).contains(&"invalid_ref"));
}

/// #914: a Tide document no workspace holds (an unsaved buffer, a text an
/// `opentide/analyze` request names) is checked in a workspace of its own,
/// with what the host supplied: a reference to an object neither holds is
/// `invalid_ref`, one the host knows resolves.
#[test]
fn a_document_outside_every_workspace_still_reports_an_unknown_reference() {
    let analyzed = |session: &mut MessageSession, id: u64, uri: &str| -> Vec<String> {
        let result = request(
            session,
            id,
            "opentide/analyze",
            json!({ "language": "opentide-yaml", "text": RULE, "uri": uri }),
        );
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|d| d["code"].as_str().map(str::to_string))
            .collect()
    };
    let mut alone = start(Value::Null);
    for (id, uri) in [(2, "untitled:query.yaml"), (3, "memory")] {
        let codes = analyzed(&mut alone, id, uri);
        assert!(
            codes.contains(&"invalid_ref".to_string()),
            "{uri}: {codes:?}"
        );
    }
    let unsaved = open(&mut alone, "untitled:Untitled-1", "opentide-yaml", RULE);
    assert!(codes(&unsaved).contains(&"invalid_ref"), "{unsaved:?}");
    let invalid = unsaved.iter().find(|d| d["code"] == "invalid_ref").unwrap();
    let line = RULE
        .lines()
        .position(|l| l.starts_with("detection_model:"))
        .unwrap();
    assert_eq!(invalid["range"]["start"]["line"], line, "{invalid}");
    // Another text for the same URI is checked as it is, not as the last one.
    let resolved = RULE.replace(
        "detection_model: 00000000-0000-4000-8002-000000000001\n",
        "",
    );
    assert_ne!(resolved, RULE);
    let result = request(
        &mut alone,
        4,
        "opentide/analyze",
        json!({ "language": "opentide-yaml", "text": resolved, "uri": "untitled:query.yaml" }),
    );
    assert!(!result.to_string().contains("invalid_ref"), "{result}");

    let mut known = start(json!({ "workspace": { "objects": [
        { "uuid": OBJECTIVE, "schema": "objective::1.0", "name": "Suspicious process creation" }
    ] } }));
    let codes_known = analyzed(&mut known, 2, "untitled:query.yaml");
    assert!(
        !codes_known.contains(&"invalid_ref".to_string()),
        "{codes_known:?}"
    );
    let unsaved = open(&mut known, "untitled:Untitled-1", "opentide-yaml", RULE);
    assert!(!codes(&unsaved).contains(&"invalid_ref"), "{unsaved:?}");
}

#[test]
fn malformed_messages_unknown_methods_and_exit() {
    let mut session = MessageSession::new();
    let replies: Vec<Value> = session
        .handle("{ not json")
        .iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["error"]["code"], -32700);

    // The lifecycle is the stdio server's: nothing before `initialize`.
    let replies = send(&mut session, json!({ "id": 6, "method": "shutdown" }));
    assert_eq!(replies[0]["id"], 6);
    assert_eq!(replies[0]["error"]["code"], -32002);

    let mut session = start(Value::Null);
    let replies = send(
        &mut session,
        json!({ "id": 7, "method": "opentide/nothing", "params": {} }),
    );
    assert_eq!(replies[0]["id"], 7);
    assert_eq!(replies[0]["error"]["code"], -32601);

    // A body that is a message but not a valid one is answered, and the
    // session goes on.
    let replies = session.handle("[1, 2]");
    let reply: Value = serde_json::from_str(&replies[0]).unwrap();
    assert_eq!(reply["error"]["code"], -32600);

    assert_eq!(
        request(&mut session, 8, "shutdown", Value::Null),
        Value::Null
    );
    assert!(!session.is_closed());
    assert!(send(&mut session, json!({ "method": "exit" })).is_empty());
    assert!(session.is_closed());
    assert!(session.shut_down());
    assert!(
        session
            .handle(r#"{"jsonrpc":"2.0","id":9,"method":"shutdown"}"#)
            .is_empty()
    );
}

/// A host that knows every object by its metadata and opens one of them:
/// the open file is that object, not a second one with its UUID.
#[test]
fn an_open_object_is_not_a_duplicate_of_its_own_metadata() {
    let objective = format!(
        "name: Suspicious process creation\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: Process creation.\n"
    );
    let mut session = start(json!({ "workspace": { "objects": [
        { "uuid": OBJECTIVE, "schema": "objective::1.0", "name": "Suspicious process creation" }
    ] } }));
    let diagnostics = open(
        &mut session,
        "objects/objectives/suspicious-process-creation.yaml",
        "opentide-yaml",
        &objective,
    );
    assert!(
        !codes(&diagnostics).contains(&"duplicate_id"),
        "{diagnostics:?}"
    );
}

/// What `send` returned: the diagnostic codes published for `uri`, if any.
fn published_codes(replies: &[Value], uri: &str) -> Option<Vec<String>> {
    replies
        .iter()
        .find(|m| m["method"] == "textDocument/publishDiagnostics" && m["params"]["uri"] == uri)
        .map(|m| {
            m["params"]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|d| d["code"].as_str().map(str::to_string))
                .collect()
        })
}

/// A host with no filesystem tells the server when the files it supplied
/// change: references follow, open documents are checked again, and the
/// catalog the client got is announced as changed.
#[test]
fn the_supplied_workspace_follows_did_change_workspace() {
    let rule = "objects/rules/process-creation.yaml";
    let objective_uri = "objects/objectives/suspicious-process-creation.yaml";
    let objective = |name: &str| {
        format!("name: {name}\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n")
    };
    let mut session = start(json!({ "workspace": { "documents": [] } }));
    assert!(codes(&open(&mut session, rule, "opentide-yaml", RULE)).contains(&"invalid_ref"));
    let catalog = request(&mut session, 2, "opentide/catalog", json!({}));
    assert_eq!(catalog["roots"][0]["objects"].as_array().unwrap().len(), 1);

    // The objective appears: the rule's reference resolves.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "documents": [{ "uri": objective_uri, "text": objective("Suspicious process creation") }]
        } }),
    );
    let after = published_codes(&replies, rule).expect("the open rule is checked again");
    assert!(!after.contains(&"invalid_ref".to_string()), "{after:?}");
    assert!(
        replies
            .iter()
            .any(|m| m["method"] == "opentide/catalogChanged"),
        "{replies:?}"
    );
    let catalog = request(&mut session, 3, "opentide/catalog", json!({}));
    let names: Vec<&str> = catalog["roots"][0]["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o["name"].as_str())
        .collect();
    assert!(names.contains(&"Suspicious process creation"), "{names:?}");

    // The same text again changes nothing, and says nothing.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "documents": [{ "uri": objective_uri, "text": objective("Suspicious process creation") }]
        } }),
    );
    assert!(replies.is_empty(), "{replies:?}");

    // A new name is a catalog change; the reference still resolves.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "documents": [{ "uri": objective_uri, "text": objective("Renamed objective") }]
        } }),
    );
    assert!(
        replies
            .iter()
            .any(|m| m["method"] == "opentide/catalogChanged")
    );
    let line = RULE
        .lines()
        .position(|l| l.starts_with("detection_model:"))
        .unwrap();
    let hover = request(
        &mut session,
        4,
        "textDocument/hover",
        json!({ "textDocument": { "uri": rule }, "position": { "line": line, "character": 20 } }),
    );
    assert!(hover.to_string().contains("Renamed objective"), "{hover}");

    // Removed, the objective is gone again.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": { "removed": [objective_uri] } }),
    );
    let gone = published_codes(&replies, rule).expect("the open rule is checked again");
    assert!(gone.contains(&"invalid_ref".to_string()), "{gone:?}");

    // An object known by its metadata alone, and its removal by `opentide-object:<uuid>`.
    send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "objects": [{ "uuid": OBJECTIVE, "schema": "objective::1.0", "name": "Known by metadata" }]
        } }),
    );
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "removed": [format!("opentide-object:{OBJECTIVE}")]
        } }),
    );
    assert!(
        published_codes(&replies, rule)
            .expect("checked again")
            .contains(&"invalid_ref".to_string())
    );

    // Params that are not an object are logged, and the session goes on.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": [1] }),
    );
    assert!(
        replies.iter().all(|m| m["method"] == "window/logMessage"),
        "{replies:?}"
    );
}

#[test]
fn initialize_says_the_server_takes_workspace_updates() {
    let mut session = MessageSession::new();
    let replies = send(
        &mut session,
        json!({ "id": 1, "method": "initialize", "params": { "processId": null, "rootUri": null, "capabilities": {} } }),
    );
    assert_eq!(
        replies[0]["result"]["capabilities"]["experimental"]["opentide"]["workspaceUpdates"],
        true
    );
}

/// An object known by its metadata, supplied with a `uri`: a change by that
/// URI replaces it, and a removal by that URI drops it.
#[test]
fn an_object_supplied_with_a_uri_is_changed_and_removed_by_it() {
    let rule = "objects/rules/process-creation.yaml";
    let uri = "objects/objectives/known.yaml";
    let object = |name: &str| json!({ "uuid": OBJECTIVE, "schema": "objective::1.0", "name": name, "uri": uri });
    let mut session = start(json!({ "workspace": { "objects": [object("First name")] } }));
    assert!(!codes(&open(&mut session, rule, "opentide-yaml", RULE)).contains(&"invalid_ref"));
    let names = |session: &mut MessageSession, id: u64| -> Vec<String> {
        request(session, id, "opentide/catalog", json!({}))["roots"][0]["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["uri"].as_str().is_some_and(|u| u.ends_with("known.yaml")))
            .map(|o| o["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(names(&mut session, 2), ["First name"]);

    send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": { "objects": [object("Second name")] } }),
    );
    assert_eq!(
        names(&mut session, 3),
        ["Second name"],
        "replaced, not added"
    );

    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": { "removed": [uri] } }),
    );
    assert!(
        published_codes(&replies, rule)
            .expect("checked again")
            .contains(&"invalid_ref".to_string())
    );
    assert!(names(&mut session, 4).is_empty());
}

/// One notification that removes a URI and adds it again: the removal goes
/// first, so the file is there, with the new text.
#[test]
fn a_uri_removed_and_added_in_one_change_is_there_with_its_new_text() {
    let rule = "objects/rules/process-creation.yaml";
    let uri = "objects/objectives/moved.yaml";
    let objective = |name: &str| {
        format!("name: {name}\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n")
    };
    let mut session = start(
        json!({ "workspace": { "documents": [{ "uri": uri, "text": objective("Before") }] } }),
    );
    open(&mut session, rule, "opentide-yaml", RULE);
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "removed": [uri],
            "documents": [{ "uri": uri, "text": objective("After") }],
        } }),
    );
    let after = published_codes(&replies, rule).expect("checked again");
    assert!(!after.contains(&"invalid_ref".to_string()), "{after:?}");
    let line = RULE
        .lines()
        .position(|l| l.starts_with("detection_model:"))
        .unwrap();
    let hover = request(
        &mut session,
        2,
        "textDocument/hover",
        json!({ "textDocument": { "uri": rule }, "position": { "line": line, "character": 20 } }),
    );
    assert!(hover.to_string().contains("After"), "{hover}");
}

/// A Sentinel schedule outside the bounds Microsoft documents (#1916): the
/// editor shows `validate`'s errors, each on its key.
#[test]
fn a_sentinel_schedule_out_of_bounds_is_shown() {
    let mut session = start(Value::Null);
    let text = "name: Sentinel rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000098
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
description: A Sentinel rule.
configurations:
  sentinel:
    enabled: true
    status: STAGING
    query: SecurityEvent | take 1
    scheduling:
      frequency: 1m
      lookback: 15d
    alert:
      title: Sentinel rule
";
    let found = open(
        &mut session,
        "objects/rules/sentinel.yaml",
        "opentide-yaml",
        text,
    );
    let line = |needle: &str| {
        u64::try_from(text.lines().position(|l| l.contains(needle)).unwrap()).unwrap()
    };
    let at = |code: &str| -> Vec<u64> {
        found
            .iter()
            .filter(|d| d["code"] == code)
            .map(|d| {
                assert_eq!(d["severity"], 1, "{d}");
                d["range"]["start"]["line"].as_u64().unwrap()
            })
            .collect()
    };
    assert_eq!(at("sentinel_frequency"), [line("frequency:")], "{found:#?}");
    assert_eq!(at("sentinel_lookback"), [line("lookback:")], "{found:#?}");
}

/// A Microsoft Defender block past the limits Microsoft documents (#1890):
/// the editor shows the alert's advisories (`validate`'s) and a continuous
/// rule's NRT finding (the query's analysis), where each is broken.
#[test]
fn a_defender_block_past_its_documented_limits_is_shown() {
    let mut session = start(Value::Null);
    let details = (1..=21)
        .map(|n| format!("        Detail{n}: Column{n}\n"))
        .collect::<Vec<_>>()
        .concat();
    let text = format!(
        "name: Defender rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
description: A Defender rule.
configurations:
  microsoft_defender:
    enabled: true
    status: STAGING
    schedule:
      frequency: NRT
    query: |
      // servers only
      DeviceProcessEvents
    entities:
      hosts: [{{device_id: DeviceId}}]
    alert:
      title: \"{{{{A}}}} {{{{B}}}} {{{{C}}}} {{{{D}}}}\"
      custom_details:
{details}"
    );
    let found = open(
        &mut session,
        "objects/rules/defender.yaml",
        "opentide-yaml",
        &text,
    );
    let line_of = |needle: &str| text.lines().position(|l| l.contains(needle)).unwrap();
    let at = |code: &str| -> Vec<(u64, u64)> {
        found
            .iter()
            .filter(|d| d["code"] == code)
            .map(|d| {
                assert_eq!(d["severity"], 2, "{d}");
                (
                    d["range"]["start"]["line"].as_u64().unwrap(),
                    d["range"]["start"]["character"].as_u64().unwrap(),
                )
            })
            .collect()
    };
    let line = |needle: &str| u64::try_from(line_of(needle)).unwrap();
    assert_eq!(
        at("microsoft_defender_nrt_query"),
        [(line("// servers only"), 6)],
        "{found:#?}"
    );
    assert_eq!(
        at("microsoft_defender_placeholder_limit")
            .into_iter()
            .map(|(line, _)| line)
            .collect::<Vec<_>>(),
        [line("title:")],
        "{found:#?}"
    );
    assert_eq!(
        at("microsoft_defender_custom_details_limit")
            .into_iter()
            .map(|(line, _)| line)
            .collect::<Vec<_>>(),
        [line("custom_details:")],
        "{found:#?}"
    );
}

/// A Bitdefender block in the editor: `validate`'s findings (the model's
/// `yara_empty_signature`, the advisories), and completion and hover from
/// the criteria catalogue.
#[test]
fn a_bitdefender_block_is_checked_completed_and_hovered() {
    let mut session = start(Value::Null);
    let head = "name: GravityZone rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000098
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
description: A GravityZone rule.
response:
  alert_severity: Critical
configurations:
  bitdefender:
    enabled: true
    schema: platform::bitdefender::1.0
    status: STAGING
";
    let yara = format!("{head}    yara:\n      signature: \"  \"\n");
    let found = open(
        &mut session,
        "objects/rules/yara.yaml",
        "opentide-yaml",
        &yara,
    );
    let found = codes(&found);
    assert!(found.contains(&"yara_empty_signature"), "{found:?}");
    assert!(
        found.contains(&"bitdefender_severity_collapsed"),
        "{found:?}"
    );

    let detection = format!(
        "{head}    detection:\n      target: registry\n      criteria:\n      - field: \
         Registry.DataType\n        is: dword\n"
    );
    let uri = "objects/rules/detection.yaml";
    open(&mut session, uri, "opentide-yaml", &detection);
    let line = |needle: &str| {
        u32::try_from(detection.lines().position(|l| l.contains(needle)).unwrap()).unwrap()
    };
    let hover = request(
        &mut session,
        2,
        "textDocument/hover",
        json!({ "textDocument": { "uri": uri }, "position": { "line": line("Registry.DataType"), "character": 17 } }),
    );
    assert!(hover.to_string().contains("Registry type"), "{hover}");
    let items = request(
        &mut session,
        3,
        "textDocument/completion",
        json!({ "textDocument": { "uri": uri }, "position": { "line": line("target: registry"), "character": 22 } }),
    );
    let labels: Vec<&str> = items
        .as_array()
        .or_else(|| items["items"].as_array())
        .unwrap()
        .iter()
        .filter_map(|item| item["label"].as_str())
        .collect();
    assert!(labels.contains(&"registry"), "{labels:?}");
}

/// #1884: a Microsoft Defender entity mapping Graph refuses is shown as the
/// author types, as `validate` reports it: an error on the mapping that
/// names the missing field, and the impacted-asset warning on an account
/// mapped by name alone. With its key, the error goes.
#[test]
fn a_defender_entity_mapping_graph_refuses_is_shown_as_you_type() {
    let mut session = start(Value::Null);
    let head = "name: Defender rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000097
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
description: A Defender rule.
status: STAGING
detection_model: 00000000-0000-4000-8002-000000000001
configurations:
  microsoft_defender:
    status: STAGING
    query: |
      DeviceRegistryEvents
    schedule:
      frequency: 1H
    entities:
      accounts:
        - upn: InitiatingProcessAccountUpn
        - name: AccountName
      registry_values:
";
    let uri = "objects/rules/defender.yaml";
    let text = format!("{head}        - value_name: RegistryValueName\n");
    let found = open(&mut session, uri, "opentide-yaml", &text);
    let line = |needle: &str| text.lines().position(|l| l.contains(needle)).unwrap();
    let error = found
        .iter()
        .find(|d| d["code"] == "microsoft_defender_entity_identifier")
        .unwrap_or_else(|| panic!("{found:#?}"));
    assert_eq!(error["severity"], 1, "an error: {error}");
    assert_eq!(
        error["range"]["start"]["line"],
        line("- value_name: RegistryValueName"),
        "{error}"
    );
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("RegKey"), "{message}");
    let warning = found
        .iter()
        .find(|d| d["code"] == "microsoft_defender_impacted_asset_identifier")
        .unwrap_or_else(|| panic!("{found:#?}"));
    assert_eq!(warning["severity"], 2, "a warning: {warning}");
    assert_eq!(
        warning["range"]["start"]["line"],
        line("- name: AccountName"),
        "{warning}"
    );

    let keyed =
        format!("{head}        - key: RegistryKey\n          value_name: RegistryValueName\n");
    let replies = send(
        &mut session,
        json!({
            "method": "textDocument/didChange",
            "params": {
                "textDocument": { "uri": uri, "version": 2 },
                "contentChanges": [{ "text": keyed }],
            },
        }),
    );
    let published = replies
        .iter()
        .find(|m| m["method"] == "textDocument/publishDiagnostics")
        .expect("didChange publishes diagnostics");
    let after = codes(published["params"]["diagnostics"].as_array().unwrap());
    assert!(
        !after.contains(&"microsoft_defender_entity_identifier"),
        "{after:?}"
    );
    assert!(
        after.contains(&"microsoft_defender_impacted_asset_identifier"),
        "{after:?}"
    );
}
