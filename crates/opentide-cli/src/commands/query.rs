//! `opentide query` on the connectors (UC-4.2c, #832): a read-only query on
//! a platform's tenants, `cli/commands/query.py`, `cli/services/query.py` and
//! `query/service.py` request for request.
//!
//! The query runs on the platforms with a Rust connector and a query runner
//! ([`PLATFORMS`]: Carbon Black Cloud, CrowdStrike, Defender for Endpoint,
//! Elastic, HarfangLab, Sentinel, SentinelOne, Splunk; every platform with a
//! runner since UC-4.3, #833). A run of a rule's query (`--rule`,
//! `--file`) is the Python CLI's: refused with
//! `engine_not_ported` ([`not_ported`]), which `OPENTIDE_ENGINE=compare`
//! hands to Python.
//!
//! Each selected tenant runs the query in turn, over the window, through the
//! connector's [`opentide_connectors::connector::QueryRunner`]; a tenant that
//! refuses or cannot be reached fails the run (exit 1), and the others still
//! run. Nothing is saved on a tenant.

use std::path::Path;
use std::time::{Duration, Instant};

use opentide_connectors::connector::{QueryOutcome, QueryRequest, TenantContext, TimeWindow};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::python::python_string_repr;
use opentide_connectors::{ConnectorError, Environment, HttpClient, HttpSettings, Tenant};
use tokio_util::sync::CancellationToken;

use super::{Block, Report, Terminal, open, placement};
use crate::env::Env;
use crate::envelope::{Failure, Outcome, USAGE_EXIT_CODE, code};
use crate::json::Json;
use crate::render::progress::{Progress, TenantEvent};
use crate::render::text::{Style, Text};

/// The command's name in the envelope.
pub const COMMAND: &str = "query";

/// The platforms whose queries run here: those with a connector and a query
/// runner (`opentide.cli.engines.RUST_QUERY_PLATFORMS`).
pub const PLATFORMS: [&str; 8] = [
    "carbon_black_cloud",
    "crowdstrike",
    "defender_for_endpoint",
    "elastic",
    "harfanglab",
    "sentinel",
    "sentinel_one",
    "splunk",
];

/// Every platform with a query runner (`QUERY_PLATFORMS`), sorted.
pub const QUERY_PLATFORMS: [&str; 8] = [
    "carbon_black_cloud",
    "crowdstrike",
    "defender_for_endpoint",
    "elastic",
    "harfanglab",
    "sentinel",
    "sentinel_one",
    "splunk",
];

/// Rows per tenant when `--limit` names none (`DEFAULT_LIMIT`).
pub const DEFAULT_LIMIT: i64 = 100;
/// The most rows one query may return per tenant (`MAX_LIMIT`).
pub const MAX_LIMIT: i64 = 5_000;
/// The window `--since` takes when no window is given (`DEFAULT_SINCE`).
pub const DEFAULT_SINCE: &str = "24h";
/// Columns the table shows when `--columns` names none (`TABLE_COLUMNS`).
pub const TABLE_COLUMNS: usize = 8;
/// Characters a table cell shows before it is cut (`CELL_WIDTH`).
pub const CELL_WIDTH: usize = 60;

/// The languages each platform's runner takes; the first is the default
/// (`PLATFORM_LANGUAGES`).
pub fn languages(platform: &str) -> &'static [&'static str] {
    match platform {
        "sentinel" | "defender_for_endpoint" => &["kql"],
        "splunk" => &["spl"],
        "sentinel_one" => &["powerquery"],
        "carbon_black_cloud" => &["lucene"],
        "crowdstrike" => &["cql"],
        "harfanglab" => &["telemetry"],
        "elastic" => &["esql", "eql", "lucene", "kuery"],
        _ => &[],
    }
}

/// The client a platform's runner names when its credentials are unset, and
/// the setup keys it checks, in order (`reject_unsubstituted_placeholders`).
fn credential_keys(platform: &str) -> (&'static str, &'static [&'static str]) {
    match platform {
        "defender_for_endpoint" => (
            "Microsoft Graph",
            &["tenant_id", "client_id", "client_secret"],
        ),
        "crowdstrike" => ("CrowdStrike", &["client_id", "client_secret"]),
        "sentinel_one" => ("SentinelOne", &["url", "api_token"]),
        "elastic" => ("Elastic", &["api_key"]),
        "harfanglab" => ("HarfangLab", &["url", "api_token"]),
        "splunk" => ("Splunk", &["url", "port", "token", "app", "ssl"]),
        "carbon_black_cloud" => ("CBC", &["url", "org_key", "token"]),
        "sentinel" => (
            "Azure",
            &["azure_tenant_id", "azure_client_id", "azure_client_secret"],
        ),
        _ => ("", &[]),
    }
}

/// The address a transport failure is reported at, for a tenant configured
/// without a URL (`_DEFAULT_HOSTS`).
fn default_host(platform: &str) -> &'static str {
    match platform {
        "defender_for_endpoint" => "https://graph.microsoft.com",
        "crowdstrike" => "https://api.crowdstrike.com",
        "sentinel" => "https://api.loganalytics.io",
        _ => "",
    }
}

/// How rows are written when `--json` is off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RowFormat {
    /// A table per tenant.
    #[default]
    Table,
    /// One JSON object per row.
    Jsonl,
    /// CSV, one header.
    Csv,
}

/// `query`'s options.
#[derive(Clone, Debug, Default)]
pub struct Args {
    /// The query (`-` reads stdin).
    pub query: Option<String>,
    /// `--platform`.
    pub platform: String,
    /// `--tenant`, repeatable.
    pub tenants: Vec<String>,
    /// `--rule`.
    pub rule: Option<String>,
    /// `--file`.
    pub file: Option<String>,
    /// `--query-file`.
    pub query_file: Option<String>,
    /// `--since`.
    pub since: Option<String>,
    /// `--from`.
    pub start: Option<String>,
    /// `--to`.
    pub end: Option<String>,
    /// `--limit`.
    pub limit: i64,
    /// `--language`.
    pub language: Option<String>,
    /// `--index`, repeatable.
    pub index: Vec<String>,
    /// `--timeout`, in seconds.
    pub timeout: f64,
    /// `--columns`.
    pub columns: Option<String>,
    /// `--format`.
    pub format: RowFormat,
}

/// What a run reads besides its options.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// `--repo`.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// `--proxy`.
    pub proxy: Option<&'a str>,
    /// The streams.
    pub terminal: &'a Terminal,
    /// Whether Ctrl-C was pressed.
    pub interrupted: &'a (dyn Fn() -> bool + Sync),
    /// stdin, read whole (`QUERY` of `-`).
    pub stdin: &'a dyn Fn() -> String,
    /// The current time, the end of a window without `--to`.
    pub now: jiff::Timestamp,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("repo", &self.repo)
            .field("cwd", &self.cwd)
            .finish_non_exhaustive()
    }
}

/// The refusal of a run this engine does not cover: Python's
/// (`engine_not_ported`), named as `opentide.cli.engines` names it.
pub fn not_ported(what: &str) -> Report {
    let message = format!(
        "opentide {what} has no Rust implementation yet: unset OPENTIDE_ENGINE, or set it to \
         python or compare."
    );
    let mut failure = Failure::new(code::ENGINE_NOT_PORTED, message);
    failure.argument = Some("OPENTIDE_ENGINE".into());
    Report::failed(COMMAND, USAGE_EXIT_CODE, failure)
}

/// A call that cannot run as given (`_usage`): exit 2, `usage_invalid_value`.
fn usage(platform: &str, message: &str, argument: &str, choices: &[String]) -> Report {
    usage_with(platform, message, argument, None, choices)
}

fn usage_with(
    platform: &str,
    message: &str,
    argument: &str,
    suggestion: Option<String>,
    choices: &[String],
) -> Report {
    let mut failure = Failure::new(code::USAGE_INVALID_VALUE, message);
    failure.argument = Some(argument.to_owned());
    failure.suggestion = suggestion;
    let mut outcome = Outcome::failed(COMMAND, USAGE_EXIT_CODE, failure);
    let mut data = vec![("platform".to_owned(), Json::str(platform))];
    if !choices.is_empty() {
        data.push((
            "choices".to_owned(),
            Json::Array(choices.iter().map(Json::str).collect()),
        ));
    }
    // The envelope writes `error` after the message.
    outcome.data = data;
    let mut report = Report::failed(COMMAND, USAGE_EXIT_CODE, Failure::new("", ""));
    report.outcome = outcome;
    report
}

/// `did_you_mean`: the closest of *choices* to *value*, when one is close.
fn suggest(value: &str, choices: &[String]) -> Option<String> {
    let names: Vec<&str> = choices.iter().map(String::as_str).collect();
    crate::suggest::did_you_mean(value, names)
}

/// The query text: `QUERY`, stdin for `-`, or `--query-file`; a refusal
/// when they cannot be read (`_query_text`).
fn query_text(args: &Args, cx: &Context<'_>) -> Result<Option<String>, Box<Report>> {
    if args.query.is_some() && args.query_file.is_some() {
        return Err(Box::new(usage(
            &args.platform,
            "QUERY and --query-file cannot be combined: give one query",
            "QUERY",
            &[],
        )));
    }
    if let Some(file) = &args.query_file {
        let path = cx.cwd.join(file);
        return match std::fs::read(&path) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                Ok(Some(
                    text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned(),
                ))
            }
            Err(error) => Err(Box::new(usage(
                &args.platform,
                &format!("cannot read --query-file {file}: {}", strerror(&error)),
                "--query-file",
                &[],
            ))),
        };
    }
    if args.query.as_deref() == Some("-") {
        return Ok(Some((cx.stdin)()));
    }
    Ok(args.query.clone())
}

/// An I/O error as Python's `strerror` names it (`No such file or directory`).
fn strerror(error: &std::io::Error) -> String {
    let text = error.to_string();
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_owned(),
        None => text,
    }
}

/// An ISO 8601 date or time as UTC; a time without an offset is UTC
/// (`parse_instant`).
fn parse_instant(value: &str, flag: &str) -> Result<jiff::Timestamp, String> {
    let text = value.trim();
    let text = match text.strip_suffix(['Z', 'z']) {
        Some(rest) => format!("{rest}+00:00"),
        None => text.to_owned(),
    };
    if let Ok(moment) = text.parse::<jiff::Timestamp>() {
        return Ok(moment);
    }
    if let Ok(zoned) = text.parse::<jiff::Zoned>() {
        return Ok(zoned.timestamp());
    }
    if let Ok(civil) = text.parse::<jiff::civil::DateTime>()
        && let Ok(moment) = civil.to_zoned(jiff::tz::TimeZone::UTC)
    {
        return Ok(moment.timestamp());
    }
    if let Ok(date) = text.parse::<jiff::civil::Date>()
        && let Ok(moment) = date.to_zoned(jiff::tz::TimeZone::UTC)
    {
        return Ok(moment.timestamp());
    }
    Err(format!(
        "{flag} {} is not an ISO-8601 time, such as 2026-10-27T08:00:00Z",
        python_string_repr(value)
    ))
}

/// The window `--since` or `--from`/`--to` name (`resolve_window`), or the
/// refusal and the flag at fault.
fn resolve_window(
    since: Option<&str>,
    start: Option<&str>,
    end: Option<&str>,
    now: jiff::Timestamp,
) -> Result<TimeWindow, (String, &'static str)> {
    let since = since.filter(|value| !value.is_empty());
    let start = start.filter(|value| !value.is_empty());
    if since.is_some() && start.is_some() {
        return Err(("--since cannot be combined with --from".into(), "--since"));
    }
    let finish = match end.filter(|value| !value.is_empty()) {
        Some(end) => parse_instant(end, "--to").map_err(|message| (message, "--to"))?,
        None => now,
    };
    let begin = match start {
        Some(start) => parse_instant(start, "--from").map_err(|message| (message, "--from"))?,
        None => {
            let lookback = since.unwrap_or(DEFAULT_SINCE);
            let not_a_duration = || {
                (
                    format!(
                        "--since {} is not a duration, such as 15m, 24h, 7d or PT1H",
                        python_string_repr(lookback)
                    ),
                    "--since",
                )
            };
            let seconds = opentide_compile::duration::elastic_seconds(lookback, false)
                .map_err(|_| not_a_duration())?;
            let seconds = i64::try_from(seconds).map_err(|_| not_a_duration())?;
            jiff::SignedDuration::from_secs(seconds)
                .checked_neg()
                .and_then(|back| finish.checked_add(back).ok())
                .ok_or_else(not_a_duration)?
        }
    };
    if begin >= finish {
        return Err(("--from must be earlier than --to".into(), "--from"));
    }
    Ok(TimeWindow {
        start: begin,
        end: finish,
    })
}

/// A tenant's outcome for the query (`TenantOutcome`).
#[derive(Clone, Debug)]
struct TenantResult {
    tenant: String,
    result: Option<QueryOutcome>,
    error: Option<String>,
    detail: Option<String>,
    elapsed_ms: i64,
}

impl TenantResult {
    fn ok(&self) -> bool {
        self.result.is_some()
    }

    /// The entry of the payload's `results` (`TenantOutcome.to_dict`).
    fn to_json(&self) -> Json {
        let mut members: Vec<(String, Json)> = vec![
            ("tenant".into(), Json::str(&self.tenant)),
            (
                "status".into(),
                Json::str(if self.ok() { "ok" } else { "failed" }),
            ),
        ];
        let mut warnings: Vec<Json> = Vec::new();
        if let Some(result) = &self.result {
            warnings.extend(result.warnings.iter().map(Json::str));
            members.push((
                "columns".into(),
                Json::Array(
                    result
                        .columns
                        .iter()
                        .map(|column| {
                            Json::object([
                                ("name", Json::str(&column.name)),
                                ("type", Json::opt_str(column.kind.clone())),
                            ])
                        })
                        .collect(),
                ),
            ));
            members.push(("rows".into(), Json::Array(rows(result))));
            members.push(("row_count".into(), Json::from(result.rows.len())));
            members.push(("truncated".into(), Json::Bool(result.truncated)));
            members.push(("partial".into(), Json::Bool(result.partial)));
            if let Some(language) = &result.language {
                members.push(("language".into(), Json::str(language)));
            }
            if let Some(sent) = &result.sent {
                members.push(("sent".into(), Json::str(sent)));
            }
            if let Some(id) = &result.vendor_query_id {
                members.push(("vendor_query_id".into(), Json::str(id)));
            }
        } else {
            members.push(("error".into(), Json::opt_str(self.error.clone())));
            if let Some(detail) = self.detail.as_ref().filter(|detail| !detail.is_empty()) {
                members.push(("detail".into(), Json::str(detail)));
            }
        }
        members.push(("warnings".into(), Json::Array(warnings)));
        members.push(("elapsed_ms".into(), Json::Int(self.elapsed_ms)));
        Json::Object(members)
    }
}

/// The rows of *result* as this crate's JSON.
fn rows(result: &QueryOutcome) -> Vec<Json> {
    result
        .rows
        .iter()
        .map(|row| crate::commands::deploy::convert(&opentide_compile::Json::Object(row.clone())))
        .collect()
}

/// A configured tenant: its name and its `setup` table, in file order.
#[derive(Debug)]
struct Configured {
    name: String,
    setup: opentide_compile::json::Object,
}

/// A platform's configured tenants, in file order, and its configuration
/// file as advice names it.
fn configured(cx: &Context<'_>, platform: &str) -> (Vec<Configured>, String) {
    let shown = format!(".opentide/configurations/platforms/{platform}.toml");
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let Ok(workspace) = open(options) else {
        return (Vec::new(), shown);
    };
    let config = opentide_compile::Json::from_node(&workspace.configuration().resolved.tree);
    let tenants = opentide_compile::plan::tenants(&config, platform)
        .into_iter()
        .map(|tenant| Configured {
            name: opentide_compile::deploy::tenant_name(tenant).to_owned(),
            setup: tenant
                .get("setup")
                .and_then(opentide_compile::Json::as_object)
                .cloned()
                .unwrap_or_default(),
        })
        .collect();
    crate::app::release(workspace);
    (tenants, shown)
}

/// Why `--tenant` selects nothing: the message, the value at fault and the
/// configured names (`TenantSelectionError`).
type Refusal = (String, Option<String>, Vec<String>);

/// The tenants *names* select, in configuration order (`select_tenants`),
/// or the refusal with its value and choices.
fn select<'t>(
    platform: &str,
    names: &[String],
    available: &'t [Configured],
    config_path: &str,
) -> Result<Vec<&'t Configured>, Refusal> {
    const ALL: &str = "all";
    let known: Vec<String> = available.iter().map(|tenant| tenant.name.clone()).collect();
    if available.is_empty() {
        return Err((
            format!(
                "{platform} has no tenants configured: add a [[tenants]] entry in {config_path}"
            ),
            None,
            Vec::new(),
        ));
    }
    let mut wanted: Vec<String> = Vec::new();
    for name in names {
        let name = name.trim();
        if !name.is_empty() && !wanted.iter().any(|seen| seen == name) {
            wanted.push(name.to_owned());
        }
    }
    let choices = || {
        let mut choices = known.clone();
        choices.push(ALL.to_owned());
        choices
    };
    if wanted.is_empty() {
        if available.len() == 1 {
            return Ok(available.iter().collect());
        }
        return Err((
            format!(
                "{platform} has {} tenants ({}): name one with --tenant, or pass --tenant {ALL}",
                available.len(),
                known.join(", ")
            ),
            None,
            choices(),
        ));
    }
    if wanted.iter().any(|name| name == ALL) {
        if wanted.len() > 1 {
            return Err((
                format!("--tenant {ALL} already selects every tenant; drop the other names"),
                Some(ALL.to_owned()),
                Vec::new(),
            ));
        }
        return Ok(available.iter().collect());
    }
    if let Some(unknown) = wanted.iter().find(|name| !known.contains(name)) {
        return Err((
            format!(
                "{platform} has no tenant named {}; configured: {}",
                python_string_repr(unknown),
                known.join(", ")
            ),
            Some(unknown.clone()),
            choices(),
        ));
    }
    Ok(available
        .iter()
        .filter(|tenant| wanted.contains(&tenant.name))
        .collect())
}

/// A setup value as `toml` holds it, for [`Tenant::from_setup`].
pub(crate) fn toml_value(value: &opentide_compile::Json) -> Option<toml::Value> {
    use opentide_compile::Json as J;
    Some(match value {
        J::Str(text) => toml::Value::String(text.clone()),
        J::Int(number) => toml::Value::Integer(*number),
        J::Float(number) => toml::Value::Float(*number),
        J::Bool(flag) => toml::Value::Boolean(*flag),
        J::Array(items) => toml::Value::Array(items.iter().filter_map(toml_value).collect()),
        J::Null | J::Object(_) => return None,
    })
}

/// The `$NAME` (or `${NAME}`) a setup value names, when it is one.
fn reference(value: &opentide_compile::Json) -> Option<&str> {
    value
        .as_str()
        .and_then(opentide_workspace::info::env_reference)
}

/// Logs each tenant's unset `$NAME` credentials once, in file order, as the
/// configuration loader does (`fetch_config_envvar`:
/// `environment_variable_missing`, critical).
fn log_unset(tenants: &[Configured], env: &Env) {
    let mut reported: Vec<String> = Vec::new();
    for tenant in tenants {
        let mut pending: Vec<String> = Vec::new();
        for value in tenant.setup.values() {
            let Some(name) = reference(value) else {
                continue;
            };
            if env.get(name).is_some() || reported.iter().any(|seen| seen == name) {
                continue;
            }
            reported.push(name.to_owned());
            pending.push(name.to_owned());
        }
        if !pending.is_empty() {
            let joined: Vec<String> = pending.iter().map(|name| format!("${name}")).collect();
            tracing::error!(
                detail = format!("Unset configuration variables: {}", joined.join(", ")).as_str(),
                advice = "Set those environment variables before a live check.",
                logger = "opentide.core.environment",
                critical = true,
                "environment_variable_missing"
            );
        }
    }
}

/// The runner's refusal of credentials still `$NAME` placeholders
/// (`reject_unsubstituted_placeholders`), or `None`.
fn unset_credentials(platform: &str, tenant: &Configured, env: &Env) -> Option<String> {
    let (client, keys) = credential_keys(platform);
    let missing: Vec<String> = keys
        .iter()
        .filter_map(|key| tenant.setup.get(*key))
        .filter(|value| reference(value).is_some_and(|name| env.get(name).is_none()))
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();
    (!missing.is_empty()).then(|| {
        format!(
            "{client} credentials are unset ({}). Set those environment variables before a live \
             check.",
            missing.join(", ")
        )
    })
}

/// The HTTP settings each platform's client mounts.
fn http_settings(platform: &str, timeout: Duration) -> HttpSettings {
    use opentide_connectors::{
        carbon_black, crowdstrike, defender, elastic, harfanglab, sentinel, sentinel_one, splunk,
    };
    match platform {
        "defender_for_endpoint" => defender::http_settings(),
        "sentinel_one" => sentinel_one::http_settings(),
        "crowdstrike" => crowdstrike::http_defaults(),
        "harfanglab" => harfanglab::http_defaults(),
        "elastic" => elastic::http_settings(timeout),
        "splunk" => splunk::http_settings(timeout),
        "carbon_black_cloud" => carbon_black::http_settings(timeout),
        // azure-core reads for 300 s; the server holds the query up to its
        // own timeout (`Prefer: wait`).
        "sentinel" => sentinel::http_settings(timeout.max(Duration::from_secs(300))),
        _ => HttpSettings::default(),
    }
}

/// `{value:g}` of a number of seconds.
fn seconds_g(value: f64) -> String {
    // `{x:g}`: six significant digits, no trailing zeros.
    let text = format!("{value}");
    if value.fract() == 0.0 && value.abs() < 1e16 {
        format!("{value:.0}")
    } else {
        text
    }
}

/// One tenant's run of the query (`run_on_tenant`).
fn run_on_tenant(
    platform: &str,
    configured: &Configured,
    request: &QueryRequest,
    cx: &Context<'_>,
    environment: &Environment,
) -> TenantResult {
    let began = Instant::now();
    let mut outcome = TenantResult {
        tenant: configured.name.clone(),
        result: None,
        error: None,
        detail: None,
        elapsed_ms: 0,
    };
    let finish = |mut outcome: TenantResult| {
        outcome.elapsed_ms = i64::try_from(began.elapsed().as_millis()).unwrap_or(i64::MAX);
        outcome
    };
    if let Some(message) = unset_credentials(platform, configured, cx.env) {
        outcome.error = Some(message);
        return finish(outcome);
    }
    let setup: toml::Table = configured
        .setup
        .iter()
        .filter_map(|(key, value)| toml_value(value).map(|value| (key.clone(), value)))
        .collect();
    let settings = http_settings(platform, request.timeout);
    // A plugin reads its setup itself: an unset variable fails here, before
    // the plugin is called, as no built-in pre-check names its keys.
    let resolve = if crate::plugins::is_plugin(platform) {
        Resolve::Required
    } else {
        Resolve::Counting
    };
    let tenant = match Tenant::from_setup(
        platform,
        &configured.name,
        &setup,
        environment,
        resolve,
        &settings,
    ) {
        Ok(tenant) => tenant,
        Err(error) => {
            outcome.error = Some(error.to_string());
            return finish(outcome);
        }
    };
    let http = match HttpClient::new(&tenant.label, &tenant.http, environment, cx.proxy) {
        Ok(http) => http,
        Err(error) => {
            outcome.error = Some(error.to_string());
            return finish(outcome);
        }
    };
    let registry = crate::plugins::registry();
    let Some(runner) = registry
        .get(platform)
        .and_then(opentide_connectors::Platform::query_runner)
    else {
        outcome.error = Some(format!("{platform} has no query runner"));
        return finish(outcome);
    };
    let interrupted = cx.interrupted;
    let ran: std::thread::Result<Result<Result<QueryOutcome, ConnectorError>, String>> =
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    opentide_connectors::runtime::block_on(async {
                        let cancel = CancellationToken::new();
                        let context = TenantContext {
                            tenant: &tenant,
                            http: &http,
                            cancel: &cancel,
                        };
                        let work = runner.run(context, request);
                        // Ctrl-C stops the search, which the runner stops on the
                        // tenant where the API allows it.
                        let watch = async {
                            while !interrupted() {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                            cancel.cancel();
                            std::future::pending::<()>().await;
                        };
                        tokio::select! {
                            result = work => result,
                            () = watch => Err(ConnectorError::Cancelled),
                        }
                    })
                })
                .join()
        });
    let result = match ran {
        Ok(Ok(result)) => result,
        Ok(Err(message)) => Err(ConnectorError::Crashed {
            platform: platform.to_owned(),
            tenant: configured.name.clone(),
            message,
        }),
        Err(_) => Err(ConnectorError::Crashed {
            platform: platform.to_owned(),
            tenant: configured.name.clone(),
            message: "the query stopped unexpectedly".into(),
        }),
    };
    match result {
        Ok(result) => outcome.result = Some(result),
        Err(
            ConnectorError::Refused {
                message, detail, ..
            }
            | ConnectorError::QueryTimedOut {
                message, detail, ..
            },
        ) => {
            outcome.error = Some(message);
            outcome.detail = detail;
        }
        Err(ConnectorError::Authentication { message, .. }) => {
            outcome.error = Some(format!(
                "cannot authenticate to {platform} tenant {}: {message}",
                python_string_repr(&configured.name)
            ));
        }
        Err(ConnectorError::Gateway { message, .. }) => {
            outcome.error = Some(format!(
                "{platform} tenant {} did not answer the query within {}s: {message}",
                python_string_repr(&configured.name),
                seconds_g(request.timeout.as_secs_f64()),
            ));
            outcome.detail = Some("narrow the window or raise --timeout".into());
        }
        Err(ConnectorError::Timeout { seconds, .. }) => {
            let host = setup_host(platform, configured);
            outcome.error = Some(format!(
                "{platform} tenant {} did not answer the query within {}s: \
                 HTTPSConnectionPool(host='{host}', port=443): Read timed out. (read \
                 timeout={seconds})",
                python_string_repr(&configured.name),
                seconds_g(request.timeout.as_secs_f64()),
            ));
            outcome.detail = Some("narrow the window or raise --timeout".into());
        }
        Err(error) => outcome.error = Some(error.to_string()),
    }
    finish(outcome)
}

/// The host a tenant's failures name: its `url`, else the platform's.
fn setup_host(platform: &str, configured: &Configured) -> String {
    let url = configured
        .setup
        .get("url")
        .and_then(opentide_compile::Json::as_str)
        .unwrap_or_else(|| default_host(platform));
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned())
}

/// Runs `opentide query`.
pub fn run(args: &Args, cx: &Context<'_>) -> Report {
    let platform = args.platform.as_str();
    let text = match query_text(args, cx) {
        Ok(text) => text,
        Err(report) => return *report,
    };
    let sources: Vec<&str> = [
        (
            "QUERY",
            text.as_deref().is_some_and(|text| !text.is_empty()),
        ),
        (
            "--rule",
            args.rule.as_deref().is_some_and(|rule| !rule.is_empty()),
        ),
        (
            "--file",
            args.file.as_deref().is_some_and(|file| !file.is_empty()),
        ),
    ]
    .iter()
    .filter(|(_, given)| *given)
    .map(|(name, _)| *name)
    .collect();
    if sources.len() != 1 {
        let message = if sources.is_empty() {
            "give exactly one query: QUERY (or - for stdin), --query-file, --rule or --file"
                .to_owned()
        } else {
            format!(
                "{} cannot be combined: give one query",
                sources.join(" and ")
            )
        };
        return usage(
            platform,
            &message,
            sources.last().copied().unwrap_or("QUERY"),
            &[],
        );
    }
    if sources[0] != "QUERY" {
        // A rule's query (its per-tenant exclusions, a correlation's
        // sub-queries) is the Python CLI's.
        return not_ported(&format!("query {}", sources[0]));
    }
    // A platform plugin (UC-4.5) runs through the same runner trait.
    let plugin = crate::plugins::is_plugin(platform);
    if !PLATFORMS.contains(&platform) && !plugin {
        return not_ported(&format!("query on {platform}"));
    }
    if !(1..=MAX_LIMIT).contains(&args.limit) {
        let mut report = usage(
            platform,
            &format!("--limit must be between 1 and {MAX_LIMIT}"),
            "--limit",
            &[],
        );
        if let Some(failure) = report.outcome.failure.as_mut() {
            failure.suggestion = None;
        }
        return report;
    }
    if !args.timeout.is_finite() || args.timeout <= 0.0 {
        return usage(platform, "--timeout must be positive", "--timeout", &[]);
    }
    let languages = languages(platform);
    if let Some(language) = &args.language
        && !plugin
        && !languages.contains(&language.as_str())
    {
        let choices: Vec<String> = languages.iter().map(|l| (*l).to_owned()).collect();
        return usage_with(
            platform,
            &format!(
                "{platform} queries are {}, not {}",
                languages.join(", "),
                python_string_repr(language)
            ),
            "--language",
            suggest(language, &choices),
            &choices,
        );
    }
    let window = match resolve_window(
        args.since.as_deref(),
        args.start.as_deref(),
        args.end.as_deref(),
        cx.now,
    ) {
        Ok(window) => window,
        Err((message, flag)) => return usage(platform, &message, flag, &[]),
    };
    let query = text.unwrap_or_default();
    let stripped = query.trim();
    if stripped.is_empty() {
        return usage(platform, "the query is empty", "QUERY", &[]);
    }
    let (available, config_path) = configured(cx, platform);
    log_unset(&available, cx.env);
    let selected = match select(platform, &args.tenants, &available, &config_path) {
        Ok(selected) => selected,
        Err((message, value, choices)) => {
            let suggestion = value.as_deref().and_then(|value| suggest(value, &choices));
            return usage_with(platform, &message, "--tenant", suggestion, &choices);
        }
    };
    let language = args
        .language
        .clone()
        .unwrap_or_else(|| languages.first().copied().unwrap_or_default().to_owned());
    let mut request = QueryRequest::new(stripped, language, window);
    request.limit = usize::try_from(args.limit).unwrap_or(1);
    request.index.clone_from(&args.index);
    request.timeout = Duration::try_from_secs_f64(args.timeout).unwrap_or(Duration::MAX);
    let environment = Environment::from_pairs(cx.env.iter());
    let progress = Progress::from_env(cx.env);
    let mut outcomes: Vec<TenantResult> = Vec::new();
    for tenant in &selected {
        if (cx.interrupted)() {
            break;
        }
        let outcome = run_on_tenant(platform, tenant, &request, cx, &environment);
        progress.tenant(&TenantEvent {
            platform,
            tenant: &outcome.tenant,
            ok: outcome.ok(),
            rows: outcome
                .result
                .as_ref()
                .map_or(0, |result| result.rows.len()),
            elapsed_ms: u64::try_from(outcome.elapsed_ms).unwrap_or_default(),
            label: None,
        });
        outcomes.push(outcome);
    }
    let names: Vec<String> = selected.iter().map(|tenant| tenant.name.clone()).collect();
    let mut report = payload(platform, &window, args.limit, &names, &outcomes, stripped);
    if cx.terminal.text() {
        report.body = body(args, &outcomes, cx.terminal, &mut report);
    }
    report
}

/// The run's report (`run_payload`).
fn payload(
    platform: &str,
    window: &TimeWindow,
    limit: i64,
    tenants: &[String],
    outcomes: &[TenantResult],
    query: &str,
) -> Report {
    let rows: usize = outcomes
        .iter()
        .filter_map(|outcome| outcome.result.as_ref())
        .map(|result| result.rows.len())
        .sum();
    let failed: Vec<&TenantResult> = outcomes.iter().filter(|outcome| !outcome.ok()).collect();
    let count = tenants.len();
    let place = format!(
        "{count} {platform} tenant{}",
        if count == 1 { "" } else { "s" }
    );
    let mut data: Vec<(String, Json)> = vec![
        ("platform".into(), Json::str(platform)),
        ("source".into(), Json::str("query")),
        (
            "window".into(),
            Json::object([
                ("from", Json::str(TimeWindow::utc_z(window.start))),
                ("to", Json::str(TimeWindow::utc_z(window.end))),
            ]),
        ),
        ("limit".into(), Json::Int(limit)),
        (
            "tenants".into(),
            Json::Array(tenants.iter().map(Json::str).collect()),
        ),
        (
            "results".into(),
            Json::Array(outcomes.iter().map(TenantResult::to_json).collect()),
        ),
        ("row_count".into(), Json::from(rows)),
        ("query".into(), Json::str(query)),
    ];
    let summary = vec![
        ("tenants".to_owned(), Json::from(count)),
        ("rows".to_owned(), Json::from(rows)),
        ("failed".to_owned(), Json::from(failed.len())),
    ];
    let outcome = if let Some(first) = failed.first() {
        let message = format!(
            "{} of {} queries failed on {place}: {}: {}",
            failed.len(),
            outcomes.len(),
            first.tenant,
            first.error.as_deref().unwrap_or("None")
        );
        if let Some(detail) = first.detail.as_ref().filter(|detail| !detail.is_empty()) {
            data.push(("detail".into(), Json::str(detail)));
        }
        Outcome {
            command: COMMAND.into(),
            status: "failed".into(),
            message: message.clone(),
            data,
            exit_code: 1,
            summary,
            next_actions: Vec::new(),
            failure: Some(Failure::new(super::COMMAND_FAILED, message)),
        }
    } else {
        let truncated = outcomes.iter().any(|outcome| {
            outcome
                .result
                .as_ref()
                .is_some_and(|result| result.truncated)
        });
        let mut message = format!(
            "{rows} row{} from {place}",
            if rows == 1 { "" } else { "s" }
        );
        if truncated {
            message.push_str(&format!(" (limited to {limit} per tenant)"));
        }
        Outcome {
            command: COMMAND.into(),
            status: "completed".into(),
            message,
            data,
            exit_code: 0,
            summary,
            next_actions: Vec::new(),
            failure: None,
        }
    };
    let mut report = Report::failed(COMMAND, 1, Failure::new("", ""));
    report.outcome = outcome;
    report
}

/// A cell as the table shows it (`_cell`): whitespace collapsed, cut at
/// [`CELL_WIDTH`] characters with an ellipsis.
fn cell(value: Option<&Json>) -> String {
    let text = match value {
        None | Some(Json::Null) => return String::new(),
        Some(value @ (Json::Object(_) | Json::Array(_))) => compact(value),
        Some(value) => python_str(value),
    };
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() <= CELL_WIDTH {
        text
    } else {
        let mut cut: String = text.chars().take(CELL_WIDTH - 1).collect();
        cut.push('…');
        cut
    }
}

/// `str(value)` of a row's value.
fn python_str(value: &Json) -> String {
    match value {
        Json::Null => "None".into(),
        Json::Bool(true) => "True".into(),
        Json::Bool(false) => "False".into(),
        Json::Str(text) => text.clone(),
        other => crate::json::document_text(other, false)
            .trim_end()
            .to_owned(),
    }
}

/// `json.dumps(value, ensure_ascii=False, separators=(",", ":"))`.
fn compact(value: &Json) -> String {
    crate::json::document_text(value, false)
        .trim_end()
        .to_owned()
}

/// `json.dumps(value, ensure_ascii=False)`: `, ` and `: ` between members.
fn spaced(value: &Json) -> String {
    match value {
        Json::Array(items) => format!(
            "[{}]",
            items.iter().map(spaced).collect::<Vec<_>>().join(", ")
        ),
        Json::Object(members) => format!(
            "{{{}}}",
            members
                .iter()
                .map(|(key, value)| format!("{}: {}", compact(&Json::str(key)), spaced(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => compact(other),
    }
}

/// A row with the tenant (and label) in front (`_labelled`).
fn labelled(tenant: &str, row: &Json) -> Vec<(String, Json)> {
    let mut members = vec![("_tenant".to_owned(), Json::str(tenant))];
    if let Json::Object(fields) = row {
        for (key, value) in fields {
            match members.iter_mut().find(|(name, _)| name == key) {
                Some(slot) => slot.1 = value.clone(),
                None => members.push((key.clone(), value.clone())),
            }
        }
    }
    members
}

/// A CSV field as `csv.writer` quotes it (`QUOTE_MINIMAL`).
fn csv_field(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_owned()
    }
}

/// A CSV value (`_csv_value`).
fn csv_value(value: Option<&Json>) -> String {
    match value {
        None | Some(Json::Null) => String::new(),
        Some(value @ (Json::Object(_) | Json::Array(_))) => compact(value),
        Some(value) => python_str(value),
    }
}

/// What the text modes print: rows as `--format` asks, the failures and
/// warnings on stderr (`query_cmd` after the payload).
fn body(
    args: &Args,
    outcomes: &[TenantResult],
    terminal: &Terminal,
    report: &mut Report,
) -> Vec<Block> {
    match args.format {
        RowFormat::Jsonl => {
            let mut text = String::new();
            for outcome in outcomes {
                if let Some(result) = &outcome.result {
                    for row in rows(result) {
                        text.push_str(&spaced(&Json::Object(labelled(&outcome.tenant, &row))));
                        text.push('\n');
                    }
                }
            }
            if report.outcome.exit_code == 0 {
                report.whole_stdout = Some(text);
                return Vec::new();
            }
            vec![Block::Raw(text)]
        }
        RowFormat::Csv => {
            let mut header: Vec<String> = vec!["_tenant".into()];
            for outcome in outcomes {
                if let Some(result) = &outcome.result {
                    for column in &result.columns {
                        if !header.contains(&column.name) {
                            header.push(column.name.clone());
                        }
                    }
                }
            }
            let mut text = header
                .iter()
                .map(|name| csv_field(name))
                .collect::<Vec<_>>()
                .join(",");
            text.push('\n');
            for outcome in outcomes {
                if let Some(result) = &outcome.result {
                    for row in rows(result) {
                        let values = labelled(&outcome.tenant, &row);
                        let line: Vec<String> = header
                            .iter()
                            .map(|name| {
                                csv_field(&csv_value(
                                    values
                                        .iter()
                                        .find(|(key, _)| key == name)
                                        .map(|(_, value)| value),
                                ))
                            })
                            .collect();
                        text.push_str(&line.join(","));
                        text.push('\n');
                    }
                }
            }
            if report.outcome.exit_code == 0 {
                report.whole_stdout = Some(text);
                return Vec::new();
            }
            vec![Block::Raw(text)]
        }
        RowFormat::Table => tables(args, outcomes, terminal),
    }
}

/// The tables of the text modes (`_print_tables`).
fn tables(args: &Args, outcomes: &[TenantResult], terminal: &Terminal) -> Vec<Block> {
    let wanted: Vec<String> = args
        .columns
        .as_deref()
        .map(|columns| {
            columns
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let bold = Style::new("bold");
    let dim = Style::new("dim");
    let mut blocks: Vec<Block> = Vec::new();
    for outcome in outcomes {
        let title = outcome.tenant.clone();
        let Some(result) = &outcome.result else {
            if outcomes.len() > 1 {
                let mut line = Text::styled(&title, &bold);
                line.append(
                    &format!("  failed: {}", outcome.error.as_deref().unwrap_or("None")),
                    &Style::new("red"),
                );
                blocks.push(Block::Stderr(terminal.stderr.line(&line)));
            }
            continue;
        };
        let names: Vec<String> = result.columns.iter().map(|c| c.name.clone()).collect();
        let shown: Vec<String> = if wanted.is_empty() {
            names.iter().take(TABLE_COLUMNS).cloned().collect()
        } else {
            wanted
                .iter()
                .filter(|name| names.contains(name))
                .cloned()
                .collect()
        };
        let count = result.rows.len();
        let mut counted = format!("{count} row{}", if count == 1 { "" } else { "s" });
        if result.truncated {
            counted.push_str(" (more matched; raise --limit)");
        }
        let mut heading = Text::styled(&title, &bold);
        heading.push_str("  ");
        heading.append(&counted, &dim);
        let mut out = terminal.stdout.line(&heading);
        if count > 0 && !shown.is_empty() {
            let rows = rows(result);
            let cells: Vec<Vec<String>> = rows
                .iter()
                .map(|row| shown.iter().map(|name| cell(row.get(name))).collect())
                .collect();
            let width = terminal.stdout.width.unwrap_or(80);
            for line in rich_table(&shown, &cells, width) {
                out.push_str(&terminal.stdout.line(&line));
            }
        }
        let hidden = names.len().saturating_sub(shown.len());
        if hidden > 0 && wanted.is_empty() {
            out.push_str(&terminal.stdout.line(&Text::styled(
                &format!("{hidden} more columns: name them with --columns, or use --format jsonl"),
                &dim,
            )));
        }
        blocks.push(Block::Raw(out));
        if !terminal.quiet {
            let mut warnings = String::new();
            for warning in &result.warnings {
                let mut line = Text::styled("warning", &Style::new("yellow bold"));
                line.push_str(&format!(": {warning}"));
                warnings.push_str(&terminal.stderr.line(&line));
            }
            if !warnings.is_empty() {
                blocks.push(Block::Stderr(warnings));
            }
        }
        blocks.push(Block::Raw("\n".into()));
    }
    blocks
}

/// A Rich `Table(show_edge=False, header_style="bold", pad_edge=False)` of
/// columns that never wrap, `width` cells wide at most: the header in bold
/// over a heavy rule, the cells one space from the light rules between them.
/// A table wider than the stream loses width evenly across its columns
/// (Rich's `ratio_reduce`; no column wraps), and each cell is cut with `…`.
fn rich_table(headers: &[String], rows: &[Vec<String>], width: usize) -> Vec<Text> {
    use crate::render::text::cell_len;
    let count = headers.len();
    let last = count.saturating_sub(1);
    let pads: Vec<(usize, usize)> = (0..count)
        .map(|at| (usize::from(at > 0), usize::from(at < last)))
        .collect();
    // The room for the columns: the stream less the rules between them.
    let room = width.saturating_sub(last);
    let measure = |at: usize, limit: usize| -> usize {
        // `_measure_column`: the widest cell with its padding, at most `limit`
        // and the column's `max_width` (CELL_WIDTH) with its padding.
        if limit < 1 {
            return 0;
        }
        let (left, right) = pads[at];
        let padding = left + right;
        let widest = rows
            .iter()
            .map(|row| cell_len(&row[at]))
            .chain(std::iter::once(cell_len(&headers[at])))
            .map(|cells| {
                if limit < padding + 1 {
                    limit
                } else {
                    (cells + padding).min(limit)
                }
            })
            .max()
            .unwrap_or(limit);
        widest.min(limit).min(CELL_WIDTH + padding)
    };
    let mut widths: Vec<usize> = (0..count).map(|at| measure(at, room).max(1)).collect();
    let total: usize = widths.iter().sum();
    if total > room {
        widths = ratio_reduce(total - room, &widths);
        widths = (0..count).map(|at| measure(at, widths[at])).collect();
    }
    let bold = Style::new("bold");
    let plain = Style::new("");
    // One cell: its padding and its text cut to fit, the whole cropped to
    // the column's width.
    let cell = |line: &mut Text, at: usize, value: &str, style: &Style| {
        let (left, right) = pads[at];
        let room = widths[at];
        let inner = room.saturating_sub(left + right);
        let mut content = Text::plain(value);
        content.truncate_ellipsis(inner);
        let mut text = content.as_plain();
        if inner == 0 {
            text.clear();
        }
        text.push_str(&" ".repeat(inner.saturating_sub(cell_len(&text))));
        let mut used = 0;
        for piece in [" ".repeat(left), text, " ".repeat(right)] {
            let take: String = piece
                .chars()
                .scan(used, |cells, ch| {
                    *cells += crate::render::text::char_width(ch);
                    (*cells <= room).then_some(ch)
                })
                .collect();
            used += cell_len(&take);
            if !take.is_empty() {
                line.append(&take, style);
            }
        }
    };
    let mut lines: Vec<Text> = Vec::new();
    let mut header = Text::plain("");
    for (at, name) in headers.iter().enumerate() {
        if at > 0 {
            header.push_str("┃");
        }
        cell(&mut header, at, name, &bold);
    }
    lines.push(header);
    let rule: Vec<String> = widths.iter().map(|width| "━".repeat(*width)).collect();
    lines.push(Text::plain(&rule.join("╇")));
    for row in rows {
        let mut line = Text::plain("");
        for (at, value) in row.iter().enumerate() {
            if at > 0 {
                line.push_str("│");
            }
            cell(&mut line, at, value, &plain);
        }
        lines.push(Text::plain(&line.as_plain()));
    }
    // A table still wider than the stream is cut at its edge, as the
    // console crops each line it prints.
    lines.iter().map(|line| crop_cells(line, width)).collect()
}

/// *line*'s first *width* cells.
fn crop_cells(line: &Text, width: usize) -> Text {
    let mut cells = 0;
    let mut keep = 0;
    for ch in line.as_plain().chars() {
        cells += crate::render::text::char_width(ch);
        if cells > width {
            break;
        }
        keep += 1;
    }
    line.slice(0, keep)
}

/// Rich's `ratio_reduce(total, [1] * n, widths, widths)`: *total* cells
/// taken from the columns in turn, each its share (Python's `round`, half
/// to even), at most its whole width.
fn ratio_reduce(total: usize, widths: &[usize]) -> Vec<usize> {
    let mut ratio_left = widths.iter().filter(|width| **width > 0).count();
    if ratio_left == 0 {
        return widths.to_vec();
    }
    let mut remaining = total;
    widths
        .iter()
        .map(|&width| {
            if width == 0 || ratio_left == 0 {
                return width;
            }
            // round(remaining / ratio_left), ties to even.
            let quotient = remaining / ratio_left;
            let rest = remaining % ratio_left;
            let share = match (rest * 2).cmp(&ratio_left) {
                std::cmp::Ordering::Greater => quotient + 1,
                std::cmp::Ordering::Equal if quotient % 2 == 1 => quotient + 1,
                _ => quotient,
            };
            let distributed = share.min(width);
            remaining -= distributed.min(remaining);
            ratio_left -= 1;
            width - distributed
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> jiff::Timestamp {
        text.parse().unwrap()
    }

    #[test]
    fn windows_read_as_the_python_cli_reads_them() {
        let now = at("2026-10-27T08:00:00Z");
        let day = resolve_window(None, None, None, now).unwrap();
        assert_eq!(TimeWindow::utc_z(day.start), "2026-10-26T08:00:00.000Z");
        let hour = resolve_window(Some("PT1H"), None, Some("2026-10-27T10:00:00"), now).unwrap();
        assert_eq!(TimeWindow::utc_z(hour.start), "2026-10-27T09:00:00.000Z");
        let fixed = resolve_window(
            None,
            Some("2099-01-01T00:00:00Z"),
            Some("2099-01-01T01:00:00+01:00"),
            now,
        );
        assert_eq!(
            fixed.unwrap_err(),
            ("--from must be earlier than --to".to_owned(), "--from")
        );
        assert_eq!(
            resolve_window(Some("1h"), Some("2026-10-27"), None, now)
                .unwrap_err()
                .1,
            "--since"
        );
        assert_eq!(
            resolve_window(Some("soon"), None, None, now).unwrap_err().0,
            "--since 'soon' is not a duration, such as 15m, 24h, 7d or PT1H"
        );
        assert_eq!(
            resolve_window(None, Some("yesterday"), None, now)
                .unwrap_err()
                .0,
            "--from 'yesterday' is not an ISO-8601 time, such as 2026-10-27T08:00:00Z"
        );
    }

    #[test]
    fn tenants_are_selected_as_select_tenants_selects_them() {
        let tenant = |name: &str| Configured {
            name: name.to_owned(),
            setup: opentide_compile::json::Object::new(),
        };
        let two = [tenant("prod"), tenant("lab")];
        let names = |selected: Vec<&Configured>| -> Vec<String> {
            selected.iter().map(|t| t.name.clone()).collect()
        };
        assert_eq!(
            select("elastic", &[], &two, "x").unwrap_err().0,
            "elastic has 2 tenants (prod, lab): name one with --tenant, or pass --tenant all"
        );
        assert_eq!(
            names(select("elastic", &["lab".into(), "prod".into()], &two, "x").unwrap()),
            ["prod", "lab"]
        );
        assert_eq!(
            names(select("elastic", &["all".into()], &two, "x").unwrap()),
            ["prod", "lab"]
        );
        let unknown = select("elastic", &["qa".into()], &two, "x").unwrap_err();
        assert_eq!(
            unknown.0,
            "elastic has no tenant named 'qa'; configured: prod, lab"
        );
        assert_eq!(unknown.2, ["prod", "lab", "all"]);
        assert_eq!(
            select("elastic", &[], &[], "p.toml").unwrap_err().0,
            "elastic has no tenants configured: add a [[tenants]] entry in p.toml"
        );
    }

    #[test]
    fn rows_are_written_as_the_python_cli_writes_them() {
        let row = Json::parse(r#"{"a": "x  y", "b": [1, "é"], "c": null, "d": 1.5}"#).unwrap();
        assert_eq!(
            spaced(&Json::Object(labelled("lab", &row))),
            r#"{"_tenant": "lab", "a": "x  y", "b": [1, "é"], "c": null, "d": 1.5}"#
        );
        assert_eq!(cell(row.get("a")), "x y");
        assert_eq!(cell(row.get("b")), r#"[1,"é"]"#);
        assert_eq!(cell(row.get("c")), "");
        assert_eq!(cell(Some(&Json::str("z".repeat(70)))).chars().count(), 60);
        assert_eq!(csv_field("a,\"b\""), "\"a,\"\"b\"\"\"");
        assert_eq!(csv_value(Some(&Json::Bool(true))), "True");
        let table = |headers: &[&str], row: &[&str], width: usize| -> Vec<String> {
            let headers: Vec<String> = headers.iter().map(|h| (*h).to_owned()).collect();
            let row: Vec<String> = row.iter().map(|c| (*c).to_owned()).collect();
            rich_table(&headers, &[row], width)
                .iter()
                .map(Text::as_plain)
                .collect()
        };
        assert_eq!(
            table(&["A", "Bee"], &["long", "b"], 80),
            ["A    ┃ Bee", "━━━━━╇━━━━", "long │ b  "]
        );
        // Wider than the stream: Rich's own output for the same table.
        assert_eq!(
            table(
                &["process_name", "pid", "device", "guid"],
                &["c:\\windows\\cmd.exe", "4001", "ws-1", "ORGKEY01-0001"],
                20
            ),
            [
                "process_… ┃┃┃ guid  ",
                "━━━━━━━━━━╇╇╇━━━━━━━",
                "c:\\windo… │││ ORGKE…"
            ]
        );
        assert_eq!(
            table(
                &["alpha", "beta", "gamma"],
                &["一二三四", "x", "yyyyyyy"],
                12
            ),
            ["alp… ┃  ┃ g…", "━━━━━╇━━╇━━━", "一 … │  │ y…"]
        );
        // Still wider after the even reduction: cut at the stream's edge.
        assert_eq!(
            table(
                &["aaaaaaaaaa", "bbbbbbbbbbb", "ccc", "dddd"],
                &[&"x".repeat(30), &"y".repeat(20), "z", &"w".repeat(9)],
                20
            ),
            [
                "aaaaaaa… ┃ bbbbbb… ┃",
                "━━━━━━━━━╇━━━━━━━━━╇",
                "xxxxxxx… │ yyyyyy… │"
            ]
        );
    }

    #[test]
    fn unset_credentials_are_named_as_the_runner_names_them() {
        let mut setup = opentide_compile::json::Object::new();
        setup.insert("url".into(), opentide_compile::Json::Str("$S1_URL".into()));
        setup.insert(
            "api_token".into(),
            opentide_compile::Json::Str("${S1_TOKEN}".into()),
        );
        let tenant = Configured {
            name: "lab".into(),
            setup,
        };
        assert_eq!(
            unset_credentials("sentinel_one", &tenant, &Env::from_pairs([("S1_URL", "x")])),
            Some(
                "SentinelOne credentials are unset (${S1_TOKEN}). Set those environment \
                 variables before a live check."
                    .to_owned()
            )
        );
        assert_eq!(
            unset_credentials(
                "sentinel_one",
                &tenant,
                &Env::from_pairs([("S1_URL", "x"), ("S1_TOKEN", "y")])
            ),
            None
        );
    }

    /// A row of `(column, value)` pairs, in order.
    fn row(pairs: &[(&str, opentide_compile::Json)]) -> opentide_connectors::connector::Row {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }

    /// A result with `columns` (untyped) and `rows`.
    fn answered(columns: &[&str], rows: Vec<opentide_connectors::connector::Row>) -> QueryOutcome {
        QueryOutcome {
            columns: columns
                .iter()
                .map(|name| opentide_connectors::connector::QueryColumn::named(*name))
                .collect(),
            rows,
            ..QueryOutcome::default()
        }
    }

    fn ok(tenant: &str, result: QueryOutcome) -> TenantResult {
        TenantResult {
            tenant: tenant.into(),
            result: Some(result),
            error: None,
            detail: None,
            elapsed_ms: 7,
        }
    }

    fn failed(tenant: &str, error: &str, detail: Option<&str>) -> TenantResult {
        TenantResult {
            tenant: tenant.into(),
            result: None,
            error: Some(error.into()),
            detail: detail.map(str::to_owned),
            elapsed_ms: 3,
        }
    }

    fn window() -> TimeWindow {
        TimeWindow {
            start: at("2099-01-01T00:00:00Z"),
            end: at("2099-01-01T01:00:00Z"),
        }
    }

    fn compact_of(json: &Json) -> String {
        crate::json::document_text(json, false)
            .trim_end()
            .to_owned()
    }

    fn text_of(blocks: &[Block]) -> (String, String) {
        let (mut out, mut err) = (String::new(), String::new());
        for block in blocks {
            match block {
                Block::Raw(text) => out.push_str(text),
                Block::Stderr(text) => err.push_str(text),
                other => panic!("query lays its text out itself: {other:?}"),
            }
        }
        (out, err)
    }

    #[test]
    fn a_tenants_entry_is_written_as_tenant_outcome_writes_it() {
        use opentide_compile::Json as J;
        let mut result = answered(&["n"], vec![row(&[("n", J::Int(1))])]);
        result.columns[0].kind = Some("long".into());
        result.truncated = true;
        result.partial = true;
        result.warnings = vec!["slow".into()];
        result.language = Some("esql".into());
        result.sent = Some("FROM x | LIMIT 2".into());
        result.vendor_query_id = Some("job-1".into());
        assert_eq!(
            compact_of(&ok("soc", result).to_json()),
            r#"{"tenant":"soc","status":"ok","columns":[{"name":"n","type":"long"}],"rows":[{"n":1}],"row_count":1,"truncated":true,"partial":true,"language":"esql","sent":"FROM x | LIMIT 2","vendor_query_id":"job-1","warnings":["slow"],"elapsed_ms":7}"#
        );
        assert_eq!(
            compact_of(&failed("lab", "refused", Some("bad field")).to_json()),
            r#"{"tenant":"lab","status":"failed","error":"refused","detail":"bad field","warnings":[],"elapsed_ms":3}"#
        );
        // An empty detail is left out, as `TenantOutcome.to_dict` leaves it.
        assert_eq!(
            compact_of(&failed("lab", "refused", Some("")).to_json()),
            r#"{"tenant":"lab","status":"failed","error":"refused","warnings":[],"elapsed_ms":3}"#
        );
    }

    #[test]
    fn a_failed_tenant_fails_the_run_with_the_first_failure_and_its_detail() {
        use opentide_compile::Json as J;
        let outcomes = [
            ok("prod", answered(&["n"], vec![row(&[("n", J::Int(1))])])),
            failed(
                "lab",
                "Elastic refused the ES|QL query on lab (HTTP 400)",
                Some("bad"),
            ),
            failed("qa", "unreachable", None),
        ];
        let names: Vec<String> = ["prod", "lab", "qa"].map(str::to_owned).to_vec();
        let report = payload("elastic", &window(), 100, &names, &outcomes, "FROM x");
        let outcome = &report.outcome;
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(outcome.status, "failed");
        assert_eq!(
            outcome.message,
            "2 of 3 queries failed on 3 elastic tenants: lab: Elastic refused the ES|QL query \
             on lab (HTTP 400)"
        );
        let failure = outcome.failure.as_ref().unwrap();
        assert_eq!(failure.code, super::super::COMMAND_FAILED);
        assert_eq!(failure.message, outcome.message);
        let keys: Vec<&str> = outcome.data.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "platform",
                "source",
                "window",
                "limit",
                "tenants",
                "results",
                "row_count",
                "query",
                "detail"
            ]
        );
        assert_eq!(outcome.data[8].1, Json::str("bad"));
        assert_eq!(
            compact_of(&outcome.data[2].1),
            r#"{"from":"2099-01-01T00:00:00.000Z","to":"2099-01-01T01:00:00.000Z"}"#
        );
        assert_eq!(outcome.data[6].1, Json::Int(1));
        let summary: Vec<String> = outcome
            .summary
            .iter()
            .map(|(key, value)| format!("{key}={}", compact_of(value)))
            .collect();
        assert_eq!(summary, ["tenants=3", "rows=1", "failed=2"]);
        // A failure without a detail adds none.
        let report = payload("elastic", &window(), 100, &names[2..], &outcomes[2..], "q");
        assert_eq!(
            report.outcome.message,
            "1 of 1 queries failed on 1 elastic tenant: qa: unreachable"
        );
        assert!(report.outcome.data.iter().all(|(key, _)| key != "detail"));
    }

    #[test]
    fn a_completed_run_counts_its_rows_and_says_when_a_tenant_was_limited() {
        use opentide_compile::Json as J;
        let one = answered(&["n"], vec![row(&[("n", J::Int(1))])]);
        let names = vec!["soc".to_owned()];
        let report = payload("elastic", &window(), 5, &names, &[ok("soc", one)], "q");
        assert_eq!(report.outcome.exit_code, 0);
        assert_eq!(report.outcome.status, "completed");
        assert!(report.outcome.failure.is_none());
        assert_eq!(report.outcome.message, "1 row from 1 elastic tenant");
        let mut two = answered(
            &["n"],
            vec![row(&[("n", J::Int(1))]), row(&[("n", J::Int(2))])],
        );
        two.truncated = true;
        let names = vec!["a".to_owned(), "b".to_owned()];
        let report = payload(
            "crowdstrike",
            &window(),
            2,
            &names,
            &[ok("a", two), ok("b", answered(&[], Vec::new()))],
            "q",
        );
        assert_eq!(
            report.outcome.message,
            "2 rows from 2 crowdstrike tenants (limited to 2 per tenant)"
        );
    }

    /// Two tenants' rows, one failed tenant, and a run's report.
    fn two_tenants_and_a_failure() -> Vec<TenantResult> {
        use opentide_compile::Json as J;
        let mut first = answered(
            &["host", "note"],
            vec![
                row(&[
                    ("host", J::Str("pc-1".into())),
                    ("note", J::Str("a, \"b\"".into())),
                ]),
                row(&[("host", J::Str("pc-2".into())), ("note", J::Null)]),
            ],
        );
        first.warnings = vec!["the search was sampled".into()];
        let second = answered(
            &["host", "count"],
            vec![row(&[
                ("host", J::Str("pc-3".into())),
                ("count", J::Int(4)),
                ("_tenant", J::Str("shadowed".into())),
            ])],
        );
        vec![
            ok("prod", first),
            ok("lab", second),
            failed("qa", "unreachable", None),
        ]
    }

    #[test]
    fn json_lines_put_the_tenant_first_and_go_to_stdout_whole_on_success() {
        let args = Args {
            format: RowFormat::Jsonl,
            ..Args::default()
        };
        let outcomes = two_tenants_and_a_failure();
        let terminal = Terminal::plain(crate::mode::Mode::Plain);
        let mut report = Report::failed(COMMAND, 0, Failure::new("", ""));
        report.outcome.exit_code = 0;
        let blocks = body(&args, &outcomes, &terminal, &mut report);
        assert!(blocks.is_empty());
        let expected = "{\"_tenant\": \"prod\", \"host\": \"pc-1\", \"note\": \"a, \\\"b\\\"\"}\n\
                        {\"_tenant\": \"prod\", \"host\": \"pc-2\", \"note\": null}\n\
                        {\"_tenant\": \"shadowed\", \"host\": \"pc-3\", \"count\": 4}\n";
        assert_eq!(report.whole_stdout.as_deref(), Some(expected));
        // A failed run prints the rows it has in the body, before the outcome.
        let mut report = Report::failed(COMMAND, 1, Failure::new("", ""));
        let blocks = body(&args, &outcomes, &terminal, &mut report);
        assert!(report.whole_stdout.is_none());
        assert_eq!(text_of(&blocks), (expected.to_owned(), String::new()));
    }

    #[test]
    fn csv_has_one_header_of_every_tenants_columns() {
        let args = Args {
            format: RowFormat::Csv,
            ..Args::default()
        };
        let outcomes = two_tenants_and_a_failure();
        let terminal = Terminal::plain(crate::mode::Mode::Plain);
        let expected = "_tenant,host,note,count\n\
                        prod,pc-1,\"a, \"\"b\"\"\",\n\
                        prod,pc-2,,\n\
                        shadowed,pc-3,,4\n";
        let mut report = Report::failed(COMMAND, 0, Failure::new("", ""));
        report.outcome.exit_code = 0;
        assert!(body(&args, &outcomes, &terminal, &mut report).is_empty());
        assert_eq!(report.whole_stdout.as_deref(), Some(expected));
        let mut report = Report::failed(COMMAND, 1, Failure::new("", ""));
        let blocks = body(&args, &outcomes, &terminal, &mut report);
        assert_eq!(text_of(&blocks), (expected.to_owned(), String::new()));
        // No tenant answered: the header alone.
        let mut report = Report::failed(COMMAND, 1, Failure::new("", ""));
        let blocks = body(&args, &outcomes[2..], &terminal, &mut report);
        assert_eq!(text_of(&blocks).0, "_tenant\n");
    }

    #[test]
    fn tables_show_each_tenant_its_failures_and_its_warnings() {
        let outcomes = two_tenants_and_a_failure();
        let terminal = Terminal::plain(crate::mode::Mode::Plain);
        let (out, err) = text_of(&tables(&Args::default(), &outcomes, &terminal));
        assert_eq!(
            out,
            "prod  2 rows\n\
             host ┃ note  \n\
             ━━━━━╇━━━━━━━\n\
             pc-1 │ a, \"b\"\n\
             pc-2 │       \n\
             \n\
             lab  1 row\n\
             host ┃ count\n\
             ━━━━━╇━━━━━━\n\
             pc-3 │ 4    \n\
             \n"
        );
        assert_eq!(
            err,
            "warning: the search was sampled\nqa  failed: unreachable\n"
        );
        // --quiet drops the warnings, not the failures.
        let quiet = Terminal {
            quiet: true,
            ..Terminal::plain(crate::mode::Mode::Plain)
        };
        let (_, err) = text_of(&tables(&Args::default(), &outcomes, &quiet));
        assert_eq!(err, "qa  failed: unreachable\n");
        // One tenant that failed: the outcome line says it, no table.
        assert!(tables(&Args::default(), &outcomes[2..], &terminal).is_empty());
    }

    #[test]
    fn tables_show_the_named_columns_or_the_first_eight() {
        use opentide_compile::Json as J;
        let names: Vec<String> = (0..10).map(|at| format!("c{at}")).collect();
        let columns: Vec<&str> = names.iter().map(String::as_str).collect();
        let pairs: Vec<(&str, J)> = columns
            .iter()
            .enumerate()
            .map(|(at, name)| (*name, J::Int(i64::try_from(at).unwrap())))
            .collect();
        let mut result = answered(&columns, vec![row(&pairs)]);
        result.truncated = true;
        let outcomes = [ok("soc", result)];
        let terminal = Terminal::plain(crate::mode::Mode::Plain);
        let (out, _) = text_of(&tables(&Args::default(), &outcomes, &terminal));
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "soc  1 row (more matched; raise --limit)");
        assert_eq!(lines[1], "c0 ┃ c1 ┃ c2 ┃ c3 ┃ c4 ┃ c5 ┃ c6 ┃ c7");
        assert_eq!(
            lines[4],
            "2 more columns: name them with --columns, or use --format jsonl"
        );
        // --columns: those named that the result has, in the order named,
        // and no hint about the others.
        let args = Args {
            columns: Some(" c9, nope ,,c1".into()),
            ..Args::default()
        };
        let (out, _) = text_of(&tables(&args, &outcomes, &terminal));
        assert_eq!(
            out,
            "soc  1 row (more matched; raise --limit)\n\
             c9 ┃ c1\n\
             ━━━╇━━━\n\
             9  │ 1 \n\
             \n"
        );
        // No rows: the heading alone.
        let empty = [ok("soc", answered(&["a"], Vec::new()))];
        let (out, _) = text_of(&tables(&Args::default(), &empty, &terminal));
        assert_eq!(out, "soc  0 rows\n\n");
    }

    #[test]
    fn the_query_is_read_from_its_argument_a_file_or_stdin() {
        let scratch = tempfile::tempdir().unwrap();
        std::fs::write(scratch.path().join("q.kql"), "\u{feff}FROM logs-*\n").unwrap();
        let env = Env::from_pairs::<&str, &str>([]);
        let terminal = Terminal::plain(crate::mode::Mode::Json);
        let never = || false;
        let stdin = || "from stdin".to_owned();
        let cx = Context {
            repo: None,
            env: &env,
            cwd: scratch.path(),
            proxy: None,
            terminal: &terminal,
            interrupted: &never,
            stdin: &stdin,
            now: at("2026-10-27T08:00:00Z"),
        };
        assert!(format!("{cx:?}").starts_with("Context { repo: None, cwd: "));
        let args = |query: Option<&str>, file: Option<&str>| Args {
            query: query.map(str::to_owned),
            query_file: file.map(str::to_owned),
            platform: "elastic".into(),
            ..Args::default()
        };
        assert_eq!(
            query_text(&args(None, Some("q.kql")), &cx)
                .unwrap()
                .as_deref(),
            Some("FROM logs-*\n")
        );
        assert_eq!(
            query_text(&args(Some("-"), None), &cx).unwrap().as_deref(),
            Some("from stdin")
        );
        assert_eq!(
            query_text(&args(Some("x"), None), &cx).unwrap().as_deref(),
            Some("x")
        );
        assert_eq!(query_text(&args(None, None), &cx).unwrap(), None);
        let refused = |args: Args| {
            let report = query_text(&args, &cx).unwrap_err();
            let failure = report.outcome.failure.clone().unwrap();
            (
                report.outcome.exit_code,
                failure.code,
                failure.message,
                failure.argument,
            )
        };
        // The operating system's own words for a missing file (os error 2
        // on Unix and on Windows), as Python's strerror gives them.
        let not_found = strerror(&std::io::Error::from_raw_os_error(2));
        assert_eq!(
            refused(args(None, Some("nope.kql"))),
            (
                USAGE_EXIT_CODE,
                code::USAGE_INVALID_VALUE.to_owned(),
                format!("cannot read --query-file nope.kql: {not_found}"),
                Some("--query-file".to_owned())
            )
        );
        assert_eq!(
            refused(args(Some("x"), Some("q.kql"))).2,
            "QUERY and --query-file cannot be combined: give one query"
        );
    }

    #[test]
    fn a_usage_error_names_the_platform_and_its_choices() {
        let choices = vec!["esql".to_owned(), "eql".to_owned()];
        let report = usage_with("elastic", "no", "--language", Some("eql".into()), &choices);
        assert_eq!(
            compact_of(&Json::Object(report.outcome.data.clone())),
            r#"{"platform":"elastic","choices":["esql","eql"]}"#
        );
        let failure = report.outcome.failure.unwrap();
        assert_eq!(failure.suggestion.as_deref(), Some("eql"));
        assert_eq!(failure.argument.as_deref(), Some("--language"));
        assert_eq!(suggest("esq", &choices).as_deref(), Some("esql"));
        let refused = not_ported("query --rule");
        let failure = refused.outcome.failure.unwrap();
        assert_eq!(failure.code, code::ENGINE_NOT_PORTED);
        assert_eq!(failure.argument.as_deref(), Some("OPENTIDE_ENGINE"));
        assert_eq!(
            failure.message,
            "opentide query --rule has no Rust implementation yet: unset OPENTIDE_ENGINE, \
             or set it to python or compare."
        );
    }

    #[test]
    fn each_platform_has_its_languages_credentials_and_address() {
        for platform in QUERY_PLATFORMS {
            assert!(!languages(platform).is_empty(), "{platform}");
        }
        assert_eq!(languages("elastic"), ["esql", "eql", "lucene", "kuery"]);
        assert_eq!(languages("sentinel"), ["kql"]);
        assert_eq!(languages("splunk"), ["spl"]);
        assert_eq!(languages("carbon_black_cloud"), ["lucene"]);
        assert!(languages("sysdig").is_empty());
        assert_eq!(
            credential_keys("harfanglab"),
            ("HarfangLab", &["url", "api_token"][..])
        );
        assert_eq!(credential_keys("elastic").1, ["api_key"]);
        assert_eq!(credential_keys("crowdstrike").0, "CrowdStrike");
        assert_eq!(credential_keys("defender_for_endpoint").1.len(), 3);
        assert_eq!(
            credential_keys("splunk"),
            ("Splunk", &["url", "port", "token", "app", "ssl"][..])
        );
        assert_eq!(credential_keys("carbon_black_cloud").0, "CBC");
        assert_eq!(credential_keys("sentinel").1.len(), 3);
        assert_eq!(credential_keys("sysdig"), ("", &[][..]));
        let tenant = |url: Option<&str>| Configured {
            name: "lab".into(),
            setup: url
                .map(|url| {
                    [("url".to_owned(), opentide_compile::Json::Str(url.into()))]
                        .into_iter()
                        .collect()
                })
                .unwrap_or_default(),
        };
        assert_eq!(
            setup_host("sentinel_one", &tenant(Some("https://s1.invalid:8443/x"))),
            "s1.invalid"
        );
        assert_eq!(
            setup_host("crowdstrike", &tenant(None)),
            "api.crowdstrike.com"
        );
        assert_eq!(
            setup_host("defender_for_endpoint", &tenant(None)),
            "graph.microsoft.com"
        );
        assert_eq!(
            setup_host("harfanglab", &tenant(Some("not a url"))),
            "not a url"
        );
        assert_eq!(setup_host("elastic", &tenant(None)), "");
        assert_eq!(seconds_g(120.0), "120");
        assert_eq!(seconds_g(0.25), "0.25");
        for platform in PLATFORMS {
            let settings = http_settings(platform, Duration::from_secs(30));
            assert!(settings.timeout > Duration::ZERO, "{platform}");
        }
        // Splunk and Carbon Black Cloud read for --timeout; Sentinel for
        // azure-core's 300 s at least; a platform with no runner mounts the
        // defaults.
        assert_eq!(
            http_settings("splunk", Duration::from_secs(5)).timeout,
            Duration::from_secs(5)
        );
        assert_eq!(
            http_settings("carbon_black_cloud", Duration::from_secs(5)).timeout,
            Duration::from_secs(5)
        );
        assert_eq!(
            http_settings("sentinel", Duration::from_secs(5)).timeout,
            Duration::from_secs(300)
        );
        assert_eq!(
            http_settings("sysdig", Duration::from_secs(5)).timeout,
            HttpSettings::default().timeout
        );
    }

    #[test]
    fn setup_values_become_toml_and_references_are_named() {
        use opentide_compile::Json as J;
        assert_eq!(
            toml_value(&J::Str("x".into())),
            Some(toml::Value::String("x".into()))
        );
        assert_eq!(toml_value(&J::Int(3)), Some(toml::Value::Integer(3)));
        assert_eq!(toml_value(&J::Float(1.5)), Some(toml::Value::Float(1.5)));
        assert_eq!(toml_value(&J::Bool(true)), Some(toml::Value::Boolean(true)));
        assert_eq!(
            toml_value(&J::Array(vec![J::Int(1), J::Null, J::Str("a".into())])),
            Some(toml::Value::Array(vec![
                toml::Value::Integer(1),
                toml::Value::String("a".into())
            ]))
        );
        assert_eq!(toml_value(&J::Null), None);
        assert_eq!(
            toml_value(&J::Object(opentide_compile::json::Object::new())),
            None
        );
        assert_eq!(reference(&J::Str("$TOKEN".into())), Some("TOKEN"));
        assert_eq!(reference(&J::Str("${TOKEN}".into())), Some("TOKEN"));
        assert_eq!(reference(&J::Str("plain".into())), None);
        assert_eq!(reference(&J::Int(1)), None);
    }

    #[test]
    fn instants_read_as_parse_instant_reads_them() {
        let utc = |text: &str| TimeWindow::utc_z(parse_instant(text, "--from").unwrap());
        assert_eq!(utc("2026-10-27"), "2026-10-27T00:00:00.000Z");
        assert_eq!(utc(" 2026-10-27T08:00:00z "), "2026-10-27T08:00:00.000Z");
        assert_eq!(utc("2026-10-27T10:00:00+02:00"), "2026-10-27T08:00:00.000Z");
        assert_eq!(utc("2026-10-27T08:00:00"), "2026-10-27T08:00:00.000Z");
        assert_eq!(
            parse_instant("27/10/2026", "--to").unwrap_err(),
            "--to '27/10/2026' is not an ISO-8601 time, such as 2026-10-27T08:00:00Z"
        );
        // strerror is the OS message without Rust's " (os error N)".
        let missing = std::io::Error::from_raw_os_error(2);
        let text = missing.to_string();
        assert_eq!(
            strerror(&missing),
            text[..text.rfind(" (os error ").unwrap()]
        );
        #[cfg(unix)]
        assert_eq!(strerror(&missing), "No such file or directory");
        #[cfg(windows)]
        assert_eq!(
            strerror(&missing),
            "The system cannot find the file specified."
        );
        assert_eq!(strerror(&std::io::Error::other("plain")), "plain");
    }

    #[test]
    fn credentials_of_a_platform_without_a_runner_are_never_unset() {
        let mut setup = opentide_compile::json::Object::new();
        setup.insert("api_key".into(), opentide_compile::Json::Str("$KEY".into()));
        let tenant = Configured {
            name: "soc".into(),
            setup,
        };
        let env = Env::from_pairs::<&str, &str>([]);
        assert_eq!(
            unset_credentials("elastic", &tenant, &env).as_deref(),
            Some(
                "Elastic credentials are unset ($KEY). Set those environment variables before a live check."
            )
        );
        assert_eq!(unset_credentials("splunk", &tenant, &env), None);
    }
}
