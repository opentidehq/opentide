//! The tools that run in Rust (`NATIVE_TOOLS`): each returns the payload the
//! Python tool of the same name returns (`src/opentide/mcp_server/tools.py`),
//! wrapped as MCPServer wraps a dict: one text block holding the JSON, and
//! `isError` false; a refusal is one text block and `isError` true.

use std::path::Path;

use serde_json::{Map, Value, json};

use crate::env::Env;
use crate::json::{Json, document_text};

/// What a tool runs against.
pub struct Context<'a> {
    /// The server's environment, once the host started.
    pub env: &'a Env,
    /// The server's working directory.
    pub cwd: Option<&'a Path>,
    /// `--repo`, resolved.
    pub repo: Option<&'a str>,
    /// Why there is no workspace to serve (`workspace_not_found`), if so.
    pub workspace_problem: Option<String>,
}

/// The `tools/call` result of the native tool `name`.
pub fn call(name: &str, arguments: &Map<String, Value>, context: &Context<'_>) -> Value {
    let payload = match name {
        "explain" => strings(arguments, &["code"]).map(|args| explain(&args[0])),
        "validation_report" => strings(arguments, &["file", "uuid", "object_type", "queries"])
            .and_then(|args| {
                let queries = if arguments.contains_key("queries") {
                    args[3].as_str()
                } else {
                    "error"
                };
                validation_report(&args[0], &args[1], &args[2], queries, context)
            }),
        other => return error_result(&format!("Unknown tool: {other}")),
    };
    match payload {
        Ok(payload) => ok_result(&payload),
        // As MCPServer reports a tool that raised.
        Err(message) => error_result(&format!("Error executing tool {name}: {message}")),
    }
}

/// A tool's payload as MCPServer returns a dict: its JSON in one text block.
pub fn ok_result(payload: &Json) -> Value {
    let text = document_text(payload, true);
    json!({
        "content": [{"type": "text", "text": text.trim_end_matches('\n')}],
        "isError": false,
    })
}

/// A tool that refused: its message in one text block, `isError` true.
pub fn error_result(message: &str) -> Value {
    json!({"content": [{"type": "text", "text": message}], "isError": true})
}

/// The string arguments `names` (`""` when absent), or the refusal of a value
/// that is not a string. Unknown arguments are ignored, as the Python
/// server's argument model ignores them.
fn strings(arguments: &Map<String, Value>, names: &[&str]) -> Result<Vec<String>, String> {
    names
        .iter()
        .map(|name| match arguments.get(*name) {
            None => Ok(String::new()),
            Some(Value::String(text)) => Ok(text.clone()),
            Some(other) => Err(format!(
                "argument {name} must be a string, not {}",
                kind(other)
            )),
        })
        .collect()
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// `explain`: the page for `code`, every code when it is blank.
pub fn explain(code: &str) -> Json {
    let wanted = code.trim();
    if wanted.is_empty() {
        let codes = crate::explain::all()
            .into_iter()
            .map(|page| {
                Json::object([
                    ("code", Json::Str(page.code)),
                    ("meaning", Json::Str(page.summary)),
                ])
            })
            .collect();
        return Json::object([("found", Json::Bool(true)), ("codes", Json::Array(codes))]);
    }
    match crate::explain::page(wanted) {
        Some(page) => Json::object([
            ("found", Json::Bool(true)),
            ("code", Json::Str(page.code)),
            ("meaning", Json::Str(page.summary)),
            ("markdown", Json::Str(page.markdown)),
        ]),
        None => Json::object([
            ("found", Json::Bool(false)),
            ("code", Json::str(wanted)),
            (
                "message",
                Json::Str(format!(
                    "No diagnostic code {}. Call explain with no code to list them.",
                    crate::render::codeframe::quoted(wanted)
                )),
            ),
            (
                "suggestion",
                Json::opt_str(crate::suggest::did_you_mean(
                    wanted,
                    crate::explain::codes(),
                )),
            ),
        ]),
    }
}

/// The modes of `validate --queries`, in the order the refusal lists them.
const QUERIES_MODES: [&str; 3] = ["error", "warn", "off"];

/// `validation_report`: `validate`'s report on the selection, with the next
/// steps; `Err` is a refusal (`isError`).
pub fn validation_report(
    file: &str,
    uuid: &str,
    object_type: &str,
    queries: &str,
    context: &Context<'_>,
) -> Result<Json, String> {
    // The Python tool asks for the workspace before it reads an argument.
    if let Some(problem) = &context.workspace_problem {
        return Err(problem.clone());
    }
    if !QUERIES_MODES.contains(&queries) {
        return Ok(Json::object([
            ("ok", Json::Bool(false)),
            (
                "error",
                Json::Str(format!(
                    "queries must be one of {}, got {}",
                    QUERIES_MODES.join(", "),
                    crate::render::codeframe::quoted(queries)
                )),
            ),
        ]));
    }
    let one = |value: &str| {
        if value.is_empty() {
            Vec::new()
        } else {
            vec![value.to_owned()]
        }
    };
    let request = crate::embed::ValidateRequest {
        files: one(file),
        uuids: one(uuid),
        types: one(object_type),
        queries: queries.to_owned(),
        repo: context.repo.map(str::to_owned),
        ..crate::embed::ValidateRequest::default()
    };
    let cwd = context
        .cwd
        .map_or_else(|| std::path::PathBuf::from("."), Path::to_path_buf);
    let text = crate::embed::validate_json(&request, context.env, &cwd);
    let result = Json::parse(&text).map_err(|error| format!("command_failed: {error}"))?;
    if let Some(error) = result.get("error") {
        let field = |name: &str| match error.get(name) {
            Some(Json::Str(text)) => text.clone(),
            _ => String::new(),
        };
        return Err(format!("{}: {}", field("code"), field("message")));
    }
    let Some(Json::Object(mut payload)) = result.get("report").cloned() else {
        return Err("command_failed: validate returned no report".into());
    };
    let diagnostics = diagnostics_of(&payload);
    let again = again_action(file, uuid, object_type, queries);
    payload.push((
        "next_actions".into(),
        Json::Array(validation_next_actions(&diagnostics, again)),
    ));
    Ok(Json::Object(payload))
}

/// The report's issues, then its warnings: every diagnostic a next step reads.
fn diagnostics_of(payload: &[(String, Json)]) -> Vec<Json> {
    let mut diagnostics = Vec::new();
    for bucket in ["issues", "warnings"] {
        if let Some(Json::Array(items)) = payload
            .iter()
            .find(|(key, _)| key == bucket)
            .map(|(_, value)| value)
        {
            diagnostics.extend(items.iter().cloned());
        }
    }
    diagnostics
}

/// The same report again, as an MCP call and as the command line that keeps
/// the selection and a `--queries` mode that is not the default.
fn again_action(file: &str, uuid: &str, object_type: &str, queries: &str) -> Json {
    let mut arguments = Vec::new();
    let mut flags = String::new();
    for (key, flag, value) in [
        ("file", "file", file),
        ("uuid", "uuid", uuid),
        ("object_type", "type", object_type),
    ] {
        if !value.is_empty() {
            arguments.push((key, Json::str(value)));
            flags.push_str(&format!(" --{flag} {}", quote(value)));
        }
    }
    if queries != "error" {
        flags.push_str(&format!(" --queries {queries}"));
        arguments.push(("queries", Json::str(queries)));
    }
    next_action(
        "validation_report",
        Json::object(arguments),
        &format!("opentide --json validate{flags}"),
        "",
    )
}

/// A word of a command line, quoted for a POSIX shell when it needs it.
fn quote(word: &str) -> String {
    shlex::try_quote(word).map_or_else(|_| format!("{word:?}"), std::borrow::Cow::into_owned)
}

/// A tool call worth making next: the CLI's `{command, reason}` plus the MCP call.
fn next_action(tool: &str, arguments: Json, command: &str, reason: &str) -> Json {
    Json::object([
        ("tool", Json::str(tool)),
        ("arguments", arguments),
        ("command", Json::str(command)),
        ("reason", Json::str(reason)),
    ])
}

fn set(object: &mut Json, key: &str, value: Json) {
    if let Json::Object(members) = object
        && let Some((_, slot)) = members.iter_mut().find(|(name, _)| name == key)
    {
        *slot = value;
    }
}

/// Explain the first error's code, then validate again once the fixes are
/// written (`_validation_next_actions`).
fn validation_next_actions(diagnostics: &[Json], again: Json) -> Vec<Json> {
    let string = |item: &Json, key: &str| match item.get(key) {
        Some(Json::Str(text)) => Some(text.clone()),
        _ => None,
    };
    let Some(first) = diagnostics
        .iter()
        .find(|item| string(item, "severity").as_deref() == Some("error"))
        .and_then(|item| string(item, "code"))
    else {
        return Vec::new();
    };
    let explain = next_action(
        "explain",
        Json::object([("code", Json::str(&first))]),
        &format!("opentide explain {first}"),
        &format!("what {first} means and how to fix it"),
    );
    let fix = |item: &Json| item.get("fix").filter(|fix| **fix != Json::Null).cloned();
    let mut rerun = again;
    set(
        &mut rerun,
        "reason",
        Json::str("validate again after fixing the issues"),
    );
    if diagnostics
        .iter()
        .filter_map(fix)
        .any(|fix| fix.get("safe") == Some(&Json::Bool(true)))
    {
        const PREFIX: &str = "opentide --json validate";
        if let Some(Json::Str(command)) = rerun.get("command").cloned()
            && let Some(rest) = command.strip_prefix(PREFIX)
        {
            set(
                &mut rerun,
                "command",
                Json::Str(format!("{PREFIX} --fix{rest}")),
            );
        }
        set(
            &mut rerun,
            "reason",
            Json::str("apply the safe fixes, then validate again"),
        );
    } else if diagnostics.iter().any(|item| fix(item).is_some()) {
        set(
            &mut rerun,
            "reason",
            Json::str("validate again after applying the fix edits"),
        );
    }
    vec![explain, rerun]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(env: &Env) -> Context<'_> {
        Context {
            env,
            cwd: None,
            repo: None,
            workspace_problem: None,
        }
    }

    fn text_of(result: &Value) -> Value {
        let text = result["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn explain_finds_a_page_in_any_case_and_lists_every_code() {
        let env = Env::from_pairs::<&str, &str>([]);
        let result = call(
            "explain",
            &serde_json::from_value(json!({"code": " INVALID_REF "})).unwrap(),
            &context(&env),
        );
        assert_eq!(result["isError"], false);
        let page = text_of(&result);
        assert_eq!(page["found"], true);
        assert_eq!(page["code"], "invalid_ref");
        assert!(
            page["markdown"]
                .as_str()
                .unwrap()
                .starts_with("# invalid_ref")
        );
        let listing = text_of(&call("explain", &Map::new(), &context(&env)));
        assert_eq!(listing["found"], true);
        let codes: Vec<&str> = listing["codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["code"].as_str().unwrap())
            .collect();
        assert!(codes.contains(&"invalid_ref") && codes.contains(&"missing_author"));
    }

    #[test]
    fn explain_of_an_unknown_code_suggests_the_closest() {
        let page = text_of(&ok_result(&explain("vocab_unknwn")));
        assert_eq!(page["found"], false);
        assert_eq!(page["code"], "vocab_unknwn");
        assert_eq!(page["suggestion"], "vocab_unknown");
        assert_eq!(
            page["message"],
            "No diagnostic code 'vocab_unknwn'. Call explain with no code to list them."
        );
        let page = text_of(&ok_result(&explain("../vocab_unknown")));
        assert_eq!(page["found"], false);
    }

    #[test]
    fn an_argument_that_is_not_a_string_is_refused() {
        let env = Env::from_pairs::<&str, &str>([]);
        let result = call(
            "explain",
            &serde_json::from_value(json!({"code": 5})).unwrap(),
            &context(&env),
        );
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["content"][0]["text"],
            "Error executing tool explain: argument code must be a string, not a number"
        );
    }

    #[test]
    fn a_bad_queries_mode_is_an_answer_not_a_refusal() {
        let env = Env::from_pairs::<&str, &str>([]);
        let result = call(
            "validation_report",
            &serde_json::from_value(json!({"queries": "loud"})).unwrap(),
            &context(&env),
        );
        assert_eq!(result["isError"], false);
        assert_eq!(
            text_of(&result),
            json!({"ok": false, "error": "queries must be one of error, warn, off, got 'loud'"})
        );
    }

    #[test]
    fn without_a_workspace_the_report_is_refused_with_the_reason() {
        let env = Env::from_pairs::<&str, &str>([]);
        let context = Context {
            env: &env,
            cwd: None,
            repo: None,
            workspace_problem: Some("workspace_not_found: set OPENTIDE_REPO_ROOT".into()),
        };
        let result = call("validation_report", &Map::new(), &context);
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["content"][0]["text"],
            "Error executing tool validation_report: workspace_not_found: set OPENTIDE_REPO_ROOT"
        );
    }

    #[test]
    fn without_a_workspace_even_a_bad_queries_mode_is_refused_with_the_reason() {
        let env = Env::from_pairs::<&str, &str>([]);
        let context = Context {
            env: &env,
            cwd: None,
            repo: None,
            workspace_problem: Some("workspace_not_found: no workspace".into()),
        };
        let result = call(
            "validation_report",
            &serde_json::from_value(json!({"queries": "loud"})).unwrap(),
            &context,
        );
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["content"][0]["text"],
            "Error executing tool validation_report: workspace_not_found: no workspace"
        );
    }

    #[test]
    fn validating_again_keeps_the_selection_quoted_and_a_queries_mode() {
        let action = again_action("rules/a b.yaml", "u-1", "rule", "warn");
        assert_eq!(
            action.get("command"),
            Some(&Json::str(
                "opentide --json validate --file 'rules/a b.yaml' --uuid u-1 --type rule --queries warn"
            ))
        );
        assert_eq!(
            action.get("arguments"),
            Some(&Json::object([
                ("file", Json::str("rules/a b.yaml")),
                ("uuid", Json::str("u-1")),
                ("object_type", Json::str("rule")),
                ("queries", Json::str("warn")),
            ]))
        );
        assert_eq!(action.get("tool"), Some(&Json::str("validation_report")));
        let plain = again_action("", "", "", "error");
        assert_eq!(
            plain.get("command"),
            Some(&Json::str("opentide --json validate"))
        );
        assert_eq!(plain.get("arguments"), Some(&Json::object::<&str>([])));
        let off = again_action("", "", "threat", "off");
        assert_eq!(
            off.get("command"),
            Some(&Json::str(
                "opentide --json validate --type threat --queries off"
            ))
        );
    }

    #[test]
    fn a_fix_on_a_warning_alone_still_shapes_the_rerun() {
        let safe = Json::object([("safe", Json::Bool(true))]);
        let payload = vec![
            (
                "issues".to_owned(),
                Json::Array(vec![issue("e", "error", Json::Null)]),
            ),
            (
                "warnings".to_owned(),
                Json::Array(vec![issue("w", "warning", safe)]),
            ),
        ];
        let diagnostics = diagnostics_of(&payload);
        assert_eq!(diagnostics.len(), 2);
        let actions =
            validation_next_actions(&diagnostics, again_action("a b.yaml", "", "", "warn"));
        assert_eq!(
            actions[1].get("command"),
            Some(&Json::str(
                "opentide --json validate --fix --file 'a b.yaml' --queries warn"
            ))
        );
        assert_eq!(
            actions[1].get("reason"),
            Some(&Json::str("apply the safe fixes, then validate again"))
        );
    }

    fn issue(code: &str, severity: &str, fix: Json) -> Json {
        Json::object([
            ("code", Json::str(code)),
            ("severity", Json::str(severity)),
            ("fix", fix),
        ])
    }

    fn again() -> Json {
        next_action(
            "validation_report",
            Json::object([("file", Json::str("a b.yaml"))]),
            "opentide --json validate --file 'a b.yaml'",
            "",
        )
    }

    #[test]
    fn next_actions_explain_the_first_error_then_validate_again() {
        let warning_first = [
            issue("w", "warning", Json::Null),
            issue("e1", "error", Json::Null),
            issue("e2", "error", Json::Null),
        ];
        let actions = validation_next_actions(&warning_first, again());
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[0].get("arguments"),
            Some(&Json::object([("code", Json::str("e1"))]))
        );
        assert_eq!(
            actions[0].get("command"),
            Some(&Json::str("opentide explain e1"))
        );
        assert_eq!(
            actions[1].get("reason"),
            Some(&Json::str("validate again after fixing the issues"))
        );
        assert_eq!(
            actions[1].get("command"),
            Some(&Json::str("opentide --json validate --file 'a b.yaml'"))
        );
        assert!(validation_next_actions(&[issue("w", "warning", Json::Null)], again()).is_empty());
    }

    #[test]
    fn a_safe_fix_reruns_with_fix_and_an_unsafe_one_says_to_apply_it() {
        let safe = Json::object([("safe", Json::Bool(true))]);
        let actions = validation_next_actions(&[issue("e", "error", safe)], again());
        assert_eq!(
            actions[1].get("command"),
            Some(&Json::str(
                "opentide --json validate --fix --file 'a b.yaml'"
            ))
        );
        assert_eq!(
            actions[1].get("reason"),
            Some(&Json::str("apply the safe fixes, then validate again"))
        );
        let unsafe_fix = Json::object([("safe", Json::Bool(false))]);
        let actions = validation_next_actions(&[issue("e", "error", unsafe_fix)], again());
        assert_eq!(
            actions[1].get("command"),
            Some(&Json::str("opentide --json validate --file 'a b.yaml'"))
        );
        assert_eq!(
            actions[1].get("reason"),
            Some(&Json::str("validate again after applying the fix edits"))
        );
    }
}
