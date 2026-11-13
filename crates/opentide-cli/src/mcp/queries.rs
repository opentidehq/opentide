//! The query tools (`tool_validate_query`, `tool_run_query`): one query
//! checked offline on the engines, and with `live` the command line's own
//! `validate query --live` and `query`, run in this process.

use std::path::{Path, PathBuf};

use super::tools::{Context, next_action};
use crate::commands::validate_query::{live_query_platforms, offline_languages};
use crate::json::Json;
use crate::queries::{ENGINE, Profiles};

/// `run_query`'s default row limit (`MAX_QUERY_ROWS`).
pub const MAX_QUERY_ROWS: i64 = 100;

/// The platforms `run_query` runs on (`QUERY_PLATFORMS`), sorted.
pub fn query_platforms() -> Vec<&'static str> {
    crate::commands::query::query_platforms()
}

/// The language a platform's query is in when the call names none.
fn default_language(platform: &str) -> &'static str {
    match platform {
        "splunk" => "spl",
        "carbon_black_cloud" => "lucene",
        "elastic" => "kuery",
        "sysdig" => "falco",
        "crowdstrike" => "cql",
        "exabeam" => "exabeam",
        _ => "kql",
    }
}

/// The envelope's keys, which a tool's payload leaves out: the payload is
/// the command's result.
const ENVELOPE_KEYS: [&str; 8] = [
    "ok",
    "schema_version",
    "command",
    "duration_ms",
    "exit_code",
    "summary",
    "next_actions",
    "failure",
];

/// `validate_query`'s arguments.
pub struct QueryCheck {
    /// `query`.
    pub query: String,
    /// `platform`.
    pub platform: String,
    /// `live`.
    pub live: bool,
    /// `language`.
    pub language: String,
    /// `stack`.
    pub stack: String,
}

/// `run_query`'s arguments.
pub struct QueryRun {
    /// `query`.
    pub query: String,
    /// `platform`.
    pub platform: String,
    /// `tenant`: comma-separated names.
    pub tenant: String,
    /// `live`.
    pub live: bool,
    /// `rule`: a rule's UUID.
    pub rule: String,
    /// `since`.
    pub since: String,
    /// `limit`.
    pub limit: i64,
    /// `language`.
    pub language: String,
    /// `index`: comma-separated patterns.
    pub index: String,
}

/// The first 200 characters of `query`.
fn preview(query: &str) -> String {
    query.chars().take(200).collect()
}

/// A word of a command line as Python's `shlex.quote` writes it.
pub fn py_quote(word: &str) -> String {
    if word.is_empty() {
        return "''".to_owned();
    }
    let safe = word
        .chars()
        .all(|c| c.is_alphanumeric() || "_@%+=:,./-".contains(c));
    if safe {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\"'\"'"))
    }
}

/// The comma-separated names of `text`, each trimmed, blanks dropped.
fn names(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Runs the command line with `argv` (after `--json`) in this process; the
/// result: its document without the envelope's keys (the `error` the
/// envelope adds to a failed run's message included), and its exit code.
fn command_result(argv: &[String], context: &Context<'_>) -> Result<(Json, i32), String> {
    let mut full = vec!["--json".to_owned()];
    if let Some(repo) = context.repo {
        full.push("--repo".to_owned());
        full.push(repo.to_owned());
    }
    full.extend_from_slice(argv);
    let cwd = context
        .cwd
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let run = crate::embed::run_captured(&full, context.env, &cwd, context.version, false);
    let text = String::from_utf8_lossy(&run.stdout);
    match Json::parse(text.trim()) {
        Ok(Json::Object(members)) => {
            let message = members
                .iter()
                .find(|(key, _)| key == "message")
                .map(|(_, value)| value.clone());
            let added_error = |key: &str, value: &Json| {
                key == "error" && run.exit_code != 0 && Some(value) == message.as_ref()
            };
            Ok((
                Json::Object(
                    members
                        .into_iter()
                        .filter(|(key, value)| {
                            !ENVELOPE_KEYS.contains(&key.as_str()) && !added_error(key, value)
                        })
                        .collect(),
                ),
                run.exit_code,
            ))
        }
        _ => Err(format!(
            "command_failed: opentide {} wrote no result (exit code {})",
            argv.join(" "),
            run.exit_code
        )),
    }
}

/// `validate_query`: `query` checked offline, or with `live` the
/// catalogue's rules for `platform` on its tenants.
pub fn validate_query(check: &QueryCheck, context: &Context<'_>) -> Result<Json, String> {
    let platform = check.platform.as_str();
    let live_platform = live_query_platforms().contains(&platform);
    if !live_platform && (check.live || offline_languages(platform).is_none()) {
        return Ok(Json::object([
            ("valid", Json::Null),
            ("supported", Json::Bool(false)),
            ("mode", Json::str("unsupported")),
            (
                "message",
                Json::Str(format!("query validation not supported for {platform}")),
            ),
            ("errors", Json::Array(Vec::new())),
        ]));
    }
    if check.live {
        let (result, exit_code) = command_result(
            &[
                "validate".to_owned(),
                "query".to_owned(),
                "--platform".to_owned(),
                platform.to_owned(),
                "--live".to_owned(),
            ],
            context,
        )?;
        // The service's exit code stays in the payload, as the Python tool
        // leaves it (`_exit_code`); its failure code does not.
        let Json::Object(mut members) = result else {
            return Ok(result);
        };
        if exit_code != 0 {
            members.push(("_exit_code".to_owned(), Json::Int(i64::from(exit_code))));
        }
        return Ok(Json::Object(members));
    }
    Ok(offline(check, context))
}

fn offline(check: &QueryCheck, context: &Context<'_>) -> Json {
    let QueryCheck {
        query,
        platform,
        language,
        stack,
        ..
    } = check;
    let live_step = next_action(
        "validate_query",
        Json::object([
            ("query", Json::str(query)),
            ("platform", Json::str(platform)),
            ("live", Json::Bool(true)),
        ]),
        &format!("opentide --json validate query --platform {platform} --live"),
        &format!(
            "check the catalogue's {platform} rules: this contacts the {platform} tenant with \
             the configured credentials, so ask a person first"
        ),
    );
    let mut payload = vec![
        ("supported".to_owned(), Json::Bool(true)),
        ("mode".to_owned(), Json::str("offline")),
        ("platform".to_owned(), Json::str(platform)),
    ];
    let failed = |mut payload: Vec<(String, Json)>, message: String| {
        payload.push(("valid".to_owned(), Json::Null));
        payload.push(("status".to_owned(), Json::str("failed")));
        payload.push(("message".to_owned(), Json::Str(message)));
        payload
    };
    let Some(languages) = offline_languages(platform) else {
        let mut payload = failed(
            payload,
            format!(
                "{platform} queries are checked on the tenant only; the engine does not parse \
                 them. Pass live: true."
            ),
        );
        payload.push(("query_preview".to_owned(), Json::Str(preview(query))));
        payload.push(("next_actions".to_owned(), Json::Array(vec![live_step])));
        return Json::Object(payload);
    };
    if query.trim().is_empty() {
        return Json::Object(failed(
            payload,
            "query is empty: pass the query text to check".to_owned(),
        ));
    }
    let chosen = match language.trim().to_lowercase() {
        empty if empty.is_empty() => default_language(platform).to_owned(),
        named => named,
    };
    let Some(language_id) = languages
        .contains(&chosen.as_str())
        .then(|| opentide_analysis::LanguageId::from_extension(&chosen))
        .flatten()
    else {
        return Json::Object(failed(
            payload,
            format!(
                "{platform} queries are in {}, not {}; pass one of those as language",
                languages.join(", "),
                crate::render::codeframe::quoted(&chosen)
            ),
        ));
    };
    // The datasets visibility.toml declares, read afresh on each call as lint
    // and validate read them.
    let root = context
        .workspace_problem
        .is_none()
        .then(|| super::catalog::workspace(context).ok())
        .flatten()
        .map(|workspace| workspace.root().to_path_buf());
    let findings = {
        let _engine = ENGINE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _profiles = Profiles::install(&opentide_workspace::OsFs, root.as_deref());
        crate::queries::check_query_on_stack(
            query,
            language_id,
            Some(platform),
            (!stack.is_empty()).then_some(stack.as_str()),
        )
    };
    let diagnostics: Vec<Json> = findings
        .iter()
        .map(|finding| {
            let severity = match finding.severity.as_str() {
                "error" => "error",
                "warning" => "warning",
                _ => "note",
            };
            Json::object([
                ("code", Json::str(&finding.code)),
                ("severity", Json::str(severity)),
                ("message", Json::str(&finding.message)),
                ("line", Json::from(finding.line)),
                ("column", Json::from(finding.column)),
                ("end_line", Json::from(finding.end_line)),
                ("end_column", Json::from(finding.end_column)),
                ("suggestion", Json::opt_str(finding.suggestion.clone())),
                (
                    "reference",
                    Json::opt_str(
                        crate::render::codeframe::engine_reference(&finding.code)
                            .map(|(_, url)| url),
                    ),
                ),
                (
                    "explain",
                    Json::Str(format!("opentide explain {}", finding.code)),
                ),
            ])
        })
        .collect();
    let of = |severity: &str| -> Vec<Json> {
        diagnostics
            .iter()
            .filter(|item| item.get("severity").and_then(Json::as_str) == Some(severity))
            .cloned()
            .collect()
    };
    let errors = of("error");
    let warnings = of("warning");
    let message = if errors.is_empty() {
        let mut text = format!("The {chosen} query is valid offline");
        if !warnings.is_empty() {
            text.push_str(&format!(", with {} warning(s)", warnings.len()));
        }
        text
    } else {
        format!("{} error(s) in the {chosen} query", errors.len())
    };
    let mut actions = Vec::new();
    if let Some(first) = errors.first().or_else(|| warnings.first()) {
        let code = first.get("code").cloned().unwrap_or(Json::Null);
        let command = first
            .get("explain")
            .and_then(Json::as_str)
            .unwrap_or_default();
        actions.push(next_action(
            "explain",
            Json::object([("code", code)]),
            command,
            "how to fix it",
        ));
    }
    // CrowdStrike and Sysdig are checked offline only: a live step would be refused.
    if live_query_platforms().contains(&platform.as_str()) {
        actions.push(live_step);
    }
    payload.extend([
        ("language".to_owned(), Json::str(&chosen)),
        ("valid".to_owned(), Json::Bool(errors.is_empty())),
        (
            "status".to_owned(),
            Json::str(if errors.is_empty() {
                "passed"
            } else {
                "failed"
            }),
        ),
        ("message".to_owned(), Json::Str(message)),
        ("errors".to_owned(), Json::Array(errors)),
        ("warnings".to_owned(), Json::Array(warnings)),
        ("diagnostics".to_owned(), Json::Array(diagnostics)),
        (
            "engine".to_owned(),
            Json::object([("engine", Json::str(opentide_analysis::VERSION))]),
        ),
        ("query_preview".to_owned(), Json::Str(preview(query))),
        ("next_actions".to_owned(), Json::Array(actions)),
    ]);
    Json::Object(payload)
}

/// `run_query`: refused without `live`, with the call that runs it; with
/// `live`, the command line's `query` on the tenants.
pub fn run_query(run: &QueryRun, context: &Context<'_>) -> Result<Json, String> {
    let platform = run.platform.as_str();
    let tenants = names(&run.tenant);
    let indices = names(&run.index);
    if !query_platforms().contains(&platform) {
        return Ok(Json::object([
            ("supported", Json::Bool(false)),
            ("status", Json::str("failed")),
            ("platform", Json::str(platform)),
            (
                "message",
                Json::Str(format!("query execution not supported for {platform}")),
            ),
            (
                "choices",
                Json::Array(
                    query_platforms()
                        .iter()
                        .map(|name| Json::str(*name))
                        .collect(),
                ),
            ),
        ]));
    }
    let mut command: Vec<String> = vec!["query".into(), "--platform".into(), platform.into()];
    let mut arguments = vec![
        ("query".to_owned(), Json::str(&run.query)),
        ("platform".to_owned(), Json::str(platform)),
        ("live".to_owned(), Json::Bool(true)),
    ];
    if !run.tenant.is_empty() {
        arguments.push(("tenant".to_owned(), Json::str(&run.tenant)));
        for name in &tenants {
            command.extend(["--tenant".to_owned(), name.clone()]);
        }
    }
    if !run.rule.is_empty() {
        arguments.push(("rule".to_owned(), Json::str(&run.rule)));
        command.extend(["--rule".to_owned(), run.rule.clone()]);
    }
    // The live call keeps every choice the agent made, so it runs what was
    // asked; the live run passes the window and the limit as Python does.
    let since_named = !run.since.is_empty() && run.since != "24h";
    if since_named {
        arguments.push(("since".to_owned(), Json::str(&run.since)));
    }
    if since_named || (run.live && !run.since.is_empty()) {
        command.extend(["--since".to_owned(), run.since.clone()]);
    }
    let limit_named = run.limit != MAX_QUERY_ROWS;
    if limit_named {
        arguments.push(("limit".to_owned(), Json::Int(run.limit)));
    }
    if limit_named || run.live {
        command.extend(["--limit".to_owned(), run.limit.to_string()]);
    }
    if !run.language.is_empty() {
        arguments.push(("language".to_owned(), Json::str(&run.language)));
        command.extend(["--language".to_owned(), run.language.clone()]);
    }
    if !run.index.is_empty() {
        arguments.push(("index".to_owned(), Json::str(&run.index)));
        for name in &indices {
            command.extend(["--index".to_owned(), name.clone()]);
        }
    }
    if run.rule.is_empty() {
        command.push(run.query.clone());
    }
    if run.live {
        let (Json::Object(mut result), _) = command_result(&command, context)? else {
            return Err("command_failed: query wrote no result".into());
        };
        result.retain(|(key, _)| key != "supported");
        result.push(("supported".to_owned(), Json::Bool(true)));
        return Ok(Json::Object(result));
    }
    let shown = std::iter::once("opentide".to_owned())
        .chain(std::iter::once("--json".to_owned()))
        .chain(command)
        .map(|word| py_quote(&word))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(Json::object([
        ("supported", Json::Bool(true)),
        ("status", Json::str("failed")),
        ("platform", Json::str(platform)),
        (
            "message",
            Json::str("run_query sends the query to the tenant. Pass live: true."),
        ),
        ("query_preview", Json::Str(preview(&run.query))),
        (
            "next_actions",
            Json::Array(vec![next_action(
                "run_query",
                Json::Object(arguments),
                &shown,
                &format!(
                    "run it on {platform}: this contacts the tenant with the configured \
                     credentials, so ask a person first"
                ),
            )]),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::Env;

    fn context(env: &Env) -> Context<'_> {
        Context {
            env,
            cwd: None,
            repo: None,
            version: "1",
            workspace_problem: None,
        }
    }

    #[test]
    fn words_are_quoted_as_python_quotes_them() {
        assert_eq!(py_quote("logs-*"), "'logs-*'");
        assert_eq!(py_quote("a/b.c:d=e,f@g%h+i"), "a/b.c:d=e,f@g%h+i");
        assert_eq!(py_quote(""), "''");
        assert_eq!(py_quote("it's"), "'it'\"'\"'s'");
    }

    #[test]
    fn an_offline_check_reports_the_engines_findings() {
        let env = Env::default();
        let check = |query: &str, platform: &str, language: &str| {
            validate_query(
                &QueryCheck {
                    query: query.into(),
                    platform: platform.into(),
                    live: false,
                    language: language.into(),
                    stack: String::new(),
                },
                &context(&env),
            )
            .unwrap()
        };
        let bad = check("SecurityEvent | wher EventID == 4625", "sentinel", "");
        assert_eq!(bad.get("valid"), Some(&Json::Bool(false)));
        assert_eq!(bad.get("language"), Some(&Json::str("kql")));
        let Some(Json::Array(actions)) = bad.get("next_actions") else {
            panic!("no next actions");
        };
        assert_eq!(actions.len(), 2, "explain, then the live check");
        let other = check("x", "elastic", "sql");
        assert_eq!(other.get("status"), Some(&Json::str("failed")));
        let empty = check("  ", "sentinel", "");
        assert_eq!(
            empty.get("message"),
            Some(&Json::str("query is empty: pass the query text to check"))
        );
        let tenant_only = check("x", "sentinel_one", "");
        assert!(tenant_only.get("next_actions").is_some());
        let unsupported = check("x", "harfanglab", "");
        assert_eq!(unsupported.get("supported"), Some(&Json::Bool(false)));
        let falco = check("evt.type = open", "sysdig", "");
        let Some(Json::Array(actions)) = falco.get("next_actions") else {
            panic!("no next actions");
        };
        assert!(
            actions
                .iter()
                .all(|action| action.get("tool") != Some(&Json::str("validate_query"))),
            "sysdig has no live check"
        );
    }

    #[test]
    fn a_run_that_is_not_live_returns_the_call_that_runs_it() {
        let env = Env::default();
        let run = |query: &str, platform: &str, tenant: &str, limit: i64| {
            run_query(
                &QueryRun {
                    query: query.into(),
                    platform: platform.into(),
                    tenant: tenant.into(),
                    live: false,
                    rule: String::new(),
                    since: "7d".into(),
                    limit,
                    language: String::new(),
                    index: String::new(),
                },
                &context(&env),
            )
            .unwrap()
        };
        let refused = run("SecurityEvent | take 5", "sentinel", "a,b", 5);
        let Some(Json::Array(actions)) = refused.get("next_actions") else {
            panic!("no next actions");
        };
        assert_eq!(
            actions[0].get("command"),
            Some(&Json::str(
                "opentide --json query --platform sentinel --tenant a --tenant b --since 7d \
                 --limit 5 'SecurityEvent | take 5'"
            ))
        );
        let unsupported = run("x", "sysdig", "", 100);
        assert_eq!(unsupported.get("supported"), Some(&Json::Bool(false)));
    }
}
