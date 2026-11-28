//! The query tools (`tool_validate_query`, `tool_run_query`): one query
//! checked offline on the engines, and with `live` the command line's own
//! `validate query --live` and `query`, run in this process.

use std::path::{Path, PathBuf};

use super::tools::{Context, next_action, quote};
use crate::commands::validate_query::{live_query_platforms, offline_languages};
use crate::json::{Json, Object};
use crate::queries::Profiles;

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
        "carbon_black_cloud" | "graylog" => "lucene",
        "elastic" => "kuery",
        "sysdig" => "falco",
        "crowdstrike" => "cql",
        "exabeam" => "exabeam",
        "datadog" => "datadog",
        // A whole YARA-L rule (a `.yaral` file's text), checked as a rule.
        "google_secops" => "yaral",
        // A whole YARA text, under the platform's profile (harfanglab-1.0 1.2,
        // bitdefender-1.0).
        "harfanglab" | "bitdefender" => "yara",
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
    /// `position`: `search` (the default) or `rule`.
    pub position: String,
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
    command_document(argv, context).map(|(document, code, _)| (document, code))
}

/// [`command_result`], and the envelope's `summary` too (what a run counted).
fn command_document(
    argv: &[String],
    context: &Context<'_>,
) -> Result<(Json, i32, Option<Json>), String> {
    let mut full = vec!["--json".to_owned()];
    if let Some(repo) = context.repo {
        full.push("--repo".to_owned());
        full.push(repo.to_owned());
    }
    full.extend_from_slice(argv);
    let cwd = context
        .cwd
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let run = crate::embed::run_interruptible(
        &full,
        context.env,
        &cwd,
        context.version,
        false,
        context.interrupt.cloned().unwrap_or_default(),
    );
    let text = String::from_utf8_lossy(&run.stdout);
    match Json::parse(text.trim()) {
        Ok(Json::Object(members)) => {
            let message = members.get("message").cloned();
            let summary = members.get("summary").cloned();
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
                summary,
            ))
        }
        _ => Err(format!(
            "command_failed: opentide {} wrote no result (exit code {})",
            argv.join(" "),
            run.exit_code
        )),
    }
}

/// Whether `stack` is a stack the ES|QL checks read: `MAJOR.MINOR` or
/// `serverless`, as `opentide_esql::StackTarget::parse` reads it. Anything
/// else would be checked as no stack at all, against every one.
fn known_stack(stack: &str) -> bool {
    let stack = stack.trim();
    if stack.eq_ignore_ascii_case("serverless") {
        return true;
    }
    // Each part a number, as `StackTarget::parse` reads it (`u32`): `9.5`,
    // not `9.99999999999`.
    let number =
        |part: &str| part.bytes().all(|byte| byte.is_ascii_digit()) && part.parse::<u32>().is_ok();
    stack
        .split_once('.')
        .is_some_and(|(major, minor)| number(major) && number(minor))
}

/// `validate_query`: `query` checked offline, or with `live` the
/// catalogue's rules for `platform` on its tenants.
pub fn validate_query(check: &QueryCheck, context: &Context<'_>) -> Result<Json, String> {
    let platform = check.platform.as_str();
    // The position is read before either check, so a value the tool does not
    // know is refused live too, and a rule's position is not dropped by one.
    let position = match check.position.trim() {
        "" => Some(opentide_analysis::QueryPosition::Search),
        named => opentide_analysis::QueryPosition::parse(named),
    };
    let refusal = match position {
        None => Some(format!(
            "position is search (a query file or a hunt) or rule (the query of the platform's \
             rule block), not {:?}",
            check.position
        )),
        Some(opentide_analysis::QueryPosition::Rule) if check.live => Some(
            "position rule applies to the offline check of query; live: true checks the \
             catalogue's rules, which are checked as rules"
                .to_owned(),
        ),
        Some(_) => None,
    };
    if let Some(message) = refusal {
        return Ok(Json::object([
            ("valid", Json::Null),
            ("status", Json::str("failed")),
            ("platform", Json::str(platform)),
            ("message", Json::Str(message)),
        ]));
    }
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
        // The command's document without its envelope: `status` says
        // whether the check failed, so no exit code is added (smoke C7).
        let (result, _, summary) = command_document(
            &[
                "validate".to_owned(),
                "query".to_owned(),
                "--platform".to_owned(),
                platform.to_owned(),
                "--live".to_owned(),
            ],
            context,
        )?;
        return Ok(with_verdict(result, summary.as_ref()));
    }
    Ok(offline(check, context))
}

/// A live check's document with its verdict: when every tenant answered (the
/// run counted its queries, so its envelope's `summary` has `queries`) and every
/// check got an answer, `valid` says whether the queries passed, as the offline
/// check's does. A rejected query is the answer, not a failure of the call; the
/// tenants that could not be reached or refused the credential, a check that got
/// no answer, and the other ways a check stops, have no `valid`, and the call
/// failed (`tools::is_failure`).
fn with_verdict(mut result: Json, summary: Option<&Json>) -> Json {
    let checked = summary.is_some_and(|summary| summary.get("queries").is_some());
    // A check that got no answer is listed in `timed_out` (a read timeout, a gateway's
    // 502, 503 or 504, a search still running at the deadline), and counts as a
    // rejection in `status`: the tenant did not say a query is invalid, so there is
    // no verdict, and the call failed.
    let no_answer = result
        .get("timed_out")
        .and_then(Json::as_array)
        .is_some_and(|timed_out| !timed_out.is_empty());
    let passed = match result.get("status").and_then(Json::as_str) {
        Some("passed") => Some(true),
        Some("failed") => Some(false),
        _ => None,
    };
    if checked
        && !no_answer
        && let Some(passed) = passed
        && let Some(members) = result.as_object_mut()
    {
        members.insert("valid".to_owned(), Json::Bool(passed));
    }
    result
}

#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn offline(check: &QueryCheck, context: &Context<'_>) -> Json {
    let QueryCheck {
        query,
        platform,
        language,
        stack,
        position,
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
    let mut payload = Object::from([
        ("supported".to_owned(), Json::Bool(true)),
        ("mode".to_owned(), Json::str("offline")),
        ("platform".to_owned(), Json::str(platform)),
    ]);
    let failed = |mut payload: Object, message: String| {
        payload.insert("valid".to_owned(), Json::Null);
        payload.insert("status".to_owned(), Json::str("failed"));
        payload.insert("message".to_owned(), Json::Str(message));
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
        payload.insert("query_preview".to_owned(), Json::Str(preview(query)));
        payload.insert("next_actions".to_owned(), Json::Array(vec![live_step]));
        return Json::Object(payload);
    };
    if query.trim().is_empty() {
        return Json::Object(failed(
            payload,
            "query is empty: pass the query text to check".to_owned(),
        ));
    }
    // validate_query refused any other value before calling this.
    let position = opentide_analysis::QueryPosition::parse(position.trim()).unwrap_or_default();
    if !stack.trim().is_empty() && !known_stack(stack) {
        return Json::Object(failed(
            payload,
            format!(
                "stack is an Elastic stack version, MAJOR.MINOR (such as 8.19 or 9.5), or \
                 serverless, not {stack:?}"
            ),
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
                "{platform} queries are in {}, not {chosen:?}; pass one of those as language",
                languages.join(", "),
            ),
        ));
    };
    // The datasets visibility.toml declares, read afresh on each call as lint
    // and validate read them.
    // A configuration file that does not parse is `config_parse`, its place
    // in the message, not a workspace read as if it declared nothing (#1659).
    let root = if context.workspace_problem.is_none() {
        match super::catalog::open(context) {
            Ok(workspace) => Some(workspace.root().to_path_buf()),
            Err(error @ super::catalog::OpenError::ConfigParse(_)) => {
                return Json::Object(failed(payload, error.to_string()));
            }
            Err(super::catalog::OpenError::Other { .. }) => None,
        }
    } else {
        None
    };
    let findings = Profiles::install(&opentide_workspace::OsFs, root.as_deref()).check_query(
        query,
        language_id,
        Some(platform),
        (!stack.is_empty()).then_some(stack.as_str()),
        position,
    );
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
        ("position".to_owned(), Json::str(position.as_str())),
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
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
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
    let mut arguments = Object::from([
        ("query".to_owned(), Json::str(&run.query)),
        ("platform".to_owned(), Json::str(platform)),
        ("live".to_owned(), Json::Bool(true)),
    ]);
    if !run.tenant.is_empty() {
        arguments.insert("tenant".to_owned(), Json::str(&run.tenant));
        for name in &tenants {
            command.extend(["--tenant".to_owned(), name.clone()]);
        }
    }
    if !run.rule.is_empty() {
        arguments.insert("rule".to_owned(), Json::str(&run.rule));
        command.extend(["--rule".to_owned(), run.rule.clone()]);
    }
    // The live call keeps every choice the agent made, so it runs what was
    // asked; a live run passes the limit, and the window when it has one.
    let since_named = !run.since.is_empty() && run.since != "24h";
    if since_named {
        arguments.insert("since".to_owned(), Json::str(&run.since));
    }
    if since_named || (run.live && !run.since.is_empty()) {
        command.extend(["--since".to_owned(), run.since.clone()]);
    }
    let limit_named = run.limit != MAX_QUERY_ROWS;
    if limit_named {
        arguments.insert("limit".to_owned(), Json::Int(run.limit));
    }
    if limit_named || run.live {
        command.extend(["--limit".to_owned(), run.limit.to_string()]);
    }
    if !run.language.is_empty() {
        arguments.insert("language".to_owned(), Json::str(&run.language));
        command.extend(["--language".to_owned(), run.language.clone()]);
    }
    if !run.index.is_empty() {
        arguments.insert("index".to_owned(), Json::str(&run.index));
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
        result.shift_remove("supported");
        result.insert("supported".to_owned(), Json::Bool(true));
        return Ok(Json::Object(result));
    }
    let shown = std::iter::once("opentide".to_owned())
        .chain(std::iter::once("--json".to_owned()))
        .chain(command)
        .map(|word| quote(&word))
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

    /// A live check every tenant answered has a verdict, as the offline check
    /// has: a rejected query is `valid: false`, not a failed call. The other
    /// ways a live check stops have none, and neither has one in which a check
    /// got no answer (a read timeout, a gateway's 502, 503 or 504, a search still
    /// running at the deadline): the tenant did not say the query is invalid.
    #[test]
    fn a_live_check_every_tenant_answered_has_a_verdict() {
        let doc = |status: &str| Json::object([("status", Json::str(status))]);
        let counted = Json::object([("queries", Json::Int(2)), ("tenants", Json::Int(1))]);
        let verdict = |status: &str, summary: Option<&Json>| {
            with_verdict(doc(status), summary).get("valid").cloned()
        };
        assert_eq!(verdict("passed", Some(&counted)), Some(Json::Bool(true)));
        assert_eq!(verdict("failed", Some(&counted)), Some(Json::Bool(false)));
        // An unreachable or refusing tenant, a crash: nothing counted, no verdict.
        assert_eq!(verdict("failed", None), None);
        assert_eq!(verdict("failed", Some(&Json::object::<&str>([]))), None);
        // Nothing sent: no verdict either.
        assert_eq!(verdict("skipped", Some(&counted)), None);
        // Counted, rejected, but a check got no answer (`timed_out` lists them): no verdict.
        let with_timeout = |rejected: bool| {
            let mut document = doc(if rejected { "failed" } else { "passed" });
            document.as_object_mut().unwrap().insert(
                "timed_out".to_owned(),
                Json::Array(vec![Json::object([(
                    "code",
                    Json::str("query_check_timeout"),
                )])]),
            );
            with_verdict(document, Some(&counted)).get("valid").cloned()
        };
        assert_eq!(with_timeout(true), None);
        assert_eq!(with_timeout(false), None);
        // An empty `timed_out` is not one.
        let mut empty = doc("failed");
        empty
            .as_object_mut()
            .unwrap()
            .insert("timed_out".to_owned(), Json::Array(Vec::new()));
        assert_eq!(
            with_verdict(empty, Some(&counted)).get("valid"),
            Some(&Json::Bool(false))
        );
    }

    use crate::env::Env;

    fn context(env: &Env) -> Context<'_> {
        Context {
            env,
            cwd: None,
            repo: None,
            version: "1",
            workspace_problem: None,
            interrupt: None,
        }
    }

    /// A call that names no language is checked in one its platform checks
    /// offline: Bitdefender's defaulted to KQL, which it then refused.
    #[test]
    fn every_offline_platform_defaults_to_one_of_its_languages() {
        for platform in opentide_schema::platforms::PLATFORMS {
            if platform.offline_languages.is_empty() {
                continue;
            }
            let language = default_language(platform.id);
            assert!(
                platform.offline_languages.contains(&language),
                "{}: default_language is {language:?}, not one of {:?}",
                platform.id,
                platform.offline_languages
            );
        }
    }

    #[test]
    fn words_are_quoted_for_a_posix_shell() {
        assert_eq!(quote("logs-*"), "'logs-*'");
        assert_eq!(quote("plain-word_1"), "plain-word_1");
        assert_eq!(quote("a/b.c:d=e,f@g%h+i"), "'a/b.c:d=e,f@g%h+i'");
        assert_eq!(quote(""), "''");
        assert_eq!(quote("it's"), "\"it's\"");
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
                    position: String::new(),
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
        // harfanglab-1.0 1.2: HarfangLab's YARA is checked offline.
        let yara = check("rule a {\n  condition:\n    $b\n}\n", "harfanglab", "");
        assert_eq!(yara.get("valid"), Some(&Json::Bool(false)));
        assert_eq!(yara.get("language"), Some(&Json::str("yara")));
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

    /// #1950: the offline check stops on a configuration that does not parse
    /// by matching `OpenError::ConfigParse`, not the message's first word;
    /// any other refusal (no workspace) checks the query with no declared
    /// datasets.
    #[test]
    fn a_configuration_that_does_not_parse_stops_the_offline_check() {
        let env = Env::default();
        let check = |cwd: &Path| {
            let context = Context {
                cwd: Some(cwd),
                ..context(&env)
            };
            let opened = super::super::catalog::open(&context).err();
            let checked = validate_query(
                &QueryCheck {
                    query: "SecurityEvent | where Account == 'é😀'".into(),
                    platform: "sentinel".into(),
                    live: false,
                    language: String::new(),
                    stack: String::new(),
                    position: String::new(),
                },
                &context,
            )
            .unwrap();
            (opened, checked)
        };
        let broken = tempfile::tempdir().unwrap();
        let platforms = broken.path().join(".opentide/configurations/platforms");
        std::fs::create_dir_all(&platforms).unwrap();
        std::fs::write(
            platforms.join("sentinel.toml"),
            "enabled = true\n[platform\n",
        )
        .unwrap();
        let (opened, checked) = check(broken.path());
        let Some(error @ super::super::catalog::OpenError::ConfigParse(_)) = opened else {
            panic!("not config_parse: {opened:?}");
        };
        assert!(
            error
                .to_string()
                .starts_with("config_parse: .opentide/configurations/platforms/sentinel.toml:2:"),
            "{error}"
        );
        assert_eq!(checked.get("status"), Some(&Json::str("failed")));
        assert_eq!(checked.get("message"), Some(&Json::Str(error.to_string())));

        // A folder with no configuration opens: the query is checked.
        let empty = tempfile::tempdir().unwrap();
        let (opened, checked) = check(empty.path());
        assert_eq!(opened, None);
        assert_eq!(checked.get("language"), Some(&Json::str("kql")));
        assert_ne!(checked.get("status"), Some(&Json::str("failed")));
    }

    /// An `OpenError` reads `code: message`, as the string it replaced did;
    /// the variant, not the text, says whether it is `config_parse`.
    #[test]
    fn an_open_error_reads_code_then_message() {
        use super::super::catalog::OpenError;
        assert_eq!(
            OpenError::ConfigParse("a.toml:2:1: é😀".into()).to_string(),
            "config_parse: a.toml:2:1: é😀"
        );
        let other = OpenError::Other {
            code: "command_failed".into(),
            message: "config_parse in the text is not the code".into(),
        };
        assert_eq!(
            other.to_string(),
            "command_failed: config_parse in the text is not the code"
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
