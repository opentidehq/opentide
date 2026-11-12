//! The traits a platform implements, and the registry of platforms.
//!
//! A platform is a [`Platform`]: its identifier and the capabilities it has,
//! each a trait of its own, so a platform that cannot validate a query live
//! (CrowdStrike, HarfangLab, Sysdig) has no [`LiveValidator`] rather than
//! one that pretends. Every operation takes a [`TenantContext`] (the tenant,
//! its client, the run's cancellation) and returns a [`ConnectorError`] on
//! failure. The methods return boxed futures so a registry holds platforms
//! as trait objects; UC-4.2 to UC-4.4 implement them, and UC-4.5 adds the
//! Python plugin hook through [`Registry::register`].

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::error::ConnectorError;
use crate::{HttpClient, Tenant};

/// A future a connector returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What every operation on one tenant receives.
#[derive(Clone, Copy, Debug)]
pub struct TenantContext<'a> {
    /// The tenant.
    pub tenant: &'a Tenant,
    /// Its client.
    pub http: &'a HttpClient,
    /// Fires when the run is cancelled.
    pub cancel: &'a CancellationToken,
}

/// What a deploy does to one rule on one tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// The rule is new there.
    Create,
    /// The rule is there and changes.
    Update,
    /// The rule is there and is turned off.
    Disable,
    /// The rule is removed.
    Delete,
}

/// One compiled rule to deploy (the body `opentide-compile` built).
#[derive(Clone, Debug, PartialEq)]
pub struct DeployRequest {
    /// The rule's identifier on the platform (its UUID or name).
    pub rule_id: String,
    /// What to do.
    pub operation: Operation,
    /// The request body, as `opentide-compile` wrote it: bytes, so the key
    /// order and layout the platform receives are the compiled ones.
    pub body: Vec<u8>,
}

/// What a deploy did.
#[derive(Clone, Debug, PartialEq)]
pub struct DeployOutcome {
    /// The platform's identifier of the rule, kept in deployment state.
    pub remote_id: Option<String>,
    /// What was done.
    pub operation: Operation,
}

/// Rows returned when the caller names no limit (`query.models.DEFAULT_LIMIT`).
pub const DEFAULT_LIMIT: usize = 100;
/// How long an asynchronous search may run when the caller names no timeout
/// (`query.models.DEFAULT_TIMEOUT`).
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(120);

/// A UTC interval, `start` inclusive (Python's `TimeWindow`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeWindow {
    /// Where it starts.
    pub start: jiff::Timestamp,
    /// Where it ends.
    pub end: jiff::Timestamp,
}

impl TimeWindow {
    /// *at* as `format_utc_z` writes it: UTC, milliseconds (truncated), `Z`
    /// (`2026-10-26T08:00:00.000Z`).
    pub fn utc_z(at: jiff::Timestamp) -> String {
        let civil = jiff::tz::Offset::UTC.to_datetime(at);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            civil.year(),
            civil.month(),
            civil.day(),
            civil.hour(),
            civil.minute(),
            civil.second(),
            civil.subsec_nanosecond() / 1_000_000
        )
    }

    /// The window's length in whole seconds, at least one (`seconds`).
    pub fn seconds(&self) -> i64 {
        let span = self.end.as_second() - self.start.as_second();
        let nanos = self.end.subsec_nanosecond() - self.start.subsec_nanosecond();
        // `int(total_seconds())` truncates toward zero.
        let whole = if nanos < 0 && span > 0 {
            span - 1
        } else if nanos > 0 && span < 0 {
            span + 1
        } else {
            span
        };
        whole.max(1)
    }

    /// The minute before *now* (`check_window`): `validate query --live`'s.
    pub fn check(now: jiff::Timestamp) -> Self {
        let start = now
            .checked_sub(jiff::SignedDuration::from_secs(60))
            .unwrap_or(now);
        Self { start, end: now }
    }
}

/// *at* as `format_utc_z` writes it ([`TimeWindow::utc_z`]).
pub fn utc_z(at: jiff::Timestamp) -> String {
    TimeWindow::utc_z(at)
}

/// One query to run or check on one tenant (Python's `query.models.QueryRequest`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRequest {
    /// The query text.
    pub text: String,
    /// Its language (`kql`, `esql`, `cql`, `telemetry`); empty takes the
    /// platform's first (Elastic's `esql`).
    pub language: String,
    /// The time the search covers.
    pub window: TimeWindow,
    /// The most rows to return; a runner asks for one more, to tell a cut.
    pub limit: usize,
    /// Elastic indices, the HarfangLab telemetry source, the CrowdStrike
    /// repository (`--index`).
    pub index: Vec<String>,
    /// Elastic's data view, when a rule names one instead of indices.
    pub data_view: Option<String>,
    /// How long an asynchronous search may run (`--timeout`).
    pub timeout: Duration,
}

impl QueryRequest {
    /// A request for *text* in *language* over *window*, with the defaults
    /// (`DEFAULT_LIMIT` rows, `DEFAULT_TIMEOUT`, no index).
    pub fn new(text: impl Into<String>, language: impl Into<String>, window: TimeWindow) -> Self {
        Self {
            text: text.into(),
            language: language.into(),
            window,
            limit: DEFAULT_LIMIT,
            index: Vec::new(),
            data_view: None,
            timeout: DEFAULT_QUERY_TIMEOUT,
        }
    }

    /// The same request for one row: a live check's (`QueryRunner.check`).
    #[must_use]
    pub fn for_check(&self) -> Self {
        Self {
            limit: 1,
            ..self.clone()
        }
    }
}

/// A column of a query's rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryColumn {
    /// Its name (`process.name`).
    pub name: String,
    /// The vendor's type name, verbatim; `None` when the platform names none.
    pub kind: Option<String>,
}

impl QueryColumn {
    /// A column without a type.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: None,
        }
    }
}

/// One row: its columns in the order they came (`opentide_compile`'s
/// ordered JSON, since serde_json's map sorts its keys).
pub type Row = opentide_compile::json::Object;

/// What a query returned (Python's `query.models.QueryResult`).
#[derive(Clone, Debug, PartialEq, Default)]
pub struct QueryOutcome {
    /// The columns, in order.
    pub columns: Vec<QueryColumn>,
    /// The rows, at most the request's limit.
    pub rows: Vec<Row>,
    /// More rows matched than the limit let through.
    pub truncated: bool,
    /// The platform stopped early and says the rows are incomplete.
    pub partial: bool,
    /// The platform's reservations about the result.
    pub warnings: Vec<String>,
    /// The platform's id of the search (CrowdStrike's job id).
    pub vendor_query_id: Option<String>,
    /// What was sent, when the runner changed the query (a `head` it added).
    pub sent: Option<String>,
    /// The language the runner used.
    pub language: Option<String>,
}

/// Nested objects as dotted keys (`process.name`), in order; lists and empty
/// objects stay values (`query.models.flatten`).
pub fn flatten(document: &Row) -> Row {
    fn into(flat: &mut Row, document: &Row, prefix: &str) {
        for (key, value) in document {
            let name = format!("{prefix}{key}");
            match value {
                opentide_compile::Json::Object(inner) if !inner.is_empty() => {
                    into(flat, inner, &format!("{name}."));
                }
                _ => {
                    flat.insert(name, value.clone());
                }
            }
        }
    }
    let mut flat = Row::new();
    into(&mut flat, document, "");
    flat
}

/// The union of the rows' keys, in first-seen order, for a platform that
/// names no schema (`query.models.columns_of`).
pub fn columns_of(rows: &[Row]) -> Vec<QueryColumn> {
    let mut seen = std::collections::BTreeSet::new();
    rows.iter()
        .flat_map(|row| row.keys())
        .filter(|name| seen.insert(name.as_str()))
        .map(|name| QueryColumn {
            name: name.clone(),
            kind: None,
        })
        .collect()
}

/// *query* with its `//` comments and string literals blanked, positions
/// (characters) kept (`query.runner.kql_code`).
pub fn kql_code(query: &str) -> String {
    let chars: Vec<char> = query.chars().collect();
    let length = chars.len();
    let mut out = String::with_capacity(query.len());
    let mut index = 0;
    while index < length {
        let character = chars[index];
        if character == '/' && chars.get(index + 1) == Some(&'/') {
            let end = chars[index..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(length, |offset| index + offset);
            out.extend(std::iter::repeat_n(' ', end - index));
            index = end;
            continue;
        }
        if character == '\'' || character == '"' {
            let verbatim = index > 0 && chars[index - 1] == '@';
            let mut end = index + 1;
            while end < length && chars[end] != character {
                end += if chars[end] == '\\' && !verbatim {
                    2
                } else {
                    1
                };
            }
            let end = (end + 1).min(length);
            out.extend(std::iter::repeat_n(' ', end - index));
            index = end;
            continue;
        }
        out.push(character);
        index += 1;
    }
    out
}

/// *query* with `| take limit+1` on a line of its own, unless it already
/// ends in `take` or `limit` (`query.runner.kql_with_limit`).
pub fn kql_with_limit(query: &str, limit: usize) -> String {
    static TAIL: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let text = query.trim_end().trim_end_matches(';').trim_end();
    let ends_in_take = TAIL
        .get_or_init(|| regex::Regex::new(r"(?i)\|\s*(?:take|limit)\s+\d+\s*$").ok())
        .as_ref()
        .is_some_and(|tail| tail.is_match(kql_code(text).trim_end()));
    if ends_in_take {
        return text.to_owned();
    }
    format!("{text}\n| take {}", limit.saturating_add(1))
}

/// What a live check learns from a tenant that accepted a query (Python's
/// `query.models.LiveCheck`, with what the platform's validator's `inspect`
/// adds). A refusal is an error instead: [`ConnectorError::Refused`], or
/// [`ConnectorError::QueryTimedOut`] for a search that outlived the check
/// timeout.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct LiveCheck {
    /// The search's answer, when the check ran one (Defender's required
    /// columns are read from its columns).
    pub result: Option<QueryOutcome>,
    /// Why validation fails the query although the tenant accepted it
    /// (`LiveQueryValidator.inspect`: Defender's custom-detection columns).
    pub errors: Vec<String>,
    /// The tenant's reservations about the verdict.
    pub warnings: Vec<String>,
}

/// Deploys rules.
pub trait Deployer: Send + Sync {
    /// Applies *request* to the tenant.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>>;
}

/// Checks queries on the tenant (`validate query --live`).
pub trait LiveValidator: Send + Sync {
    /// Checks *request* (`QueryRunner.check`, then the validator's
    /// `inspect`): by default a search for one row over its window, which
    /// the caller sets to the minute before now ([`TimeWindow::check`]).
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>>;
}

/// Runs queries (`opentide query`). Saves nothing on the tenant.
pub trait QueryRunner: Send + Sync {
    /// Runs *request*. A search the runner stops waiting for (cancellation)
    /// is stopped on the tenant where the API allows it (CrowdStrike).
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>>;
}

/// Shares objects (MISP).
pub trait Sharer: Send + Sync {
    /// Shares *object*, returning the remote identifier.
    fn share<'a>(
        &'a self,
        cx: TenantContext<'a>,
        object: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<Option<String>, ConnectorError>>;
}

/// Moves deployment state between formats with what the tenant knows
/// (`deploy migrate-state`).
pub trait StateMigrator: Send + Sync {
    /// The tenant's identifier of each rule named in *rule_ids*, in order.
    fn lookup<'a>(
        &'a self,
        cx: TenantContext<'a>,
        rule_ids: &'a [String],
    ) -> BoxFuture<'a, Result<Vec<Option<String>>, ConnectorError>>;
}

/// A platform and what it can do.
pub trait Platform: Send + Sync {
    /// Its identifier (`sentinel`, `elastic`).
    fn id(&self) -> &'static str;
    /// Its deployer.
    fn deployer(&self) -> Option<&dyn Deployer> {
        None
    }
    /// Its live validator; `None` where the API cannot check a query
    /// (`supported: False`, never a faked validation).
    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        None
    }
    /// Its query runner.
    fn query_runner(&self) -> Option<&dyn QueryRunner> {
        None
    }
    /// Its sharer.
    fn sharer(&self) -> Option<&dyn Sharer> {
        None
    }
    /// Its state migrator.
    fn state_migrator(&self) -> Option<&dyn StateMigrator> {
        None
    }
}

/// The platforms a run knows: the built-in ones, then any registered.
#[derive(Default)]
pub struct Registry {
    platforms: Vec<Box<dyn Platform>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.platforms.iter().map(|platform| platform.id()))
            .finish()
    }
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds *platform*. A second platform with an identifier already
    /// registered is refused: a plugin cannot replace a built-in platform.
    pub fn register(&mut self, platform: Box<dyn Platform>) -> Result<(), String> {
        if self.get(platform.id()).is_some() {
            return Err(format!("platform {} is already registered", platform.id()));
        }
        self.platforms.push(platform);
        Ok(())
    }

    /// The platform *id*.
    pub fn get(&self, id: &str) -> Option<&dyn Platform> {
        self.platforms
            .iter()
            .find(|platform| platform.id() == id)
            .map(AsRef::as_ref)
    }

    /// Every platform's identifier, in registration order.
    pub fn ids(&self) -> Vec<&'static str> {
        self.platforms
            .iter()
            .map(|platform| platform.id())
            .collect()
    }
}
