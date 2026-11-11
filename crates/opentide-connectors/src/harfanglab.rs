//! HarfangLab EDR (UC-4.2, #832): the Sigma rules and YARA files a deploy
//! sends, and the telemetry searches `opentide query` runs.
//!
//! A port of `platforms/harfanglab/client.py` (`HarfangLabService`: the
//! `Token` header, a Sigma rule put by the rule's UUID and created with
//! `POST` when the tenant does not hold it, a YARA file posted, deletes),
//! `deployer.py` (a tenant's `type` says which kind of rule it takes) and
//! `runner.py` (one telemetry source filtered by `field=value` words),
//! request for request. HarfangLab has no live validation (`supported:
//! False`) and no query language for a rule: `opentide query` runs a
//! telemetry search, never a rule's query (no `--rule`).
//!
//! The rule bodies are `opentide-compile`'s (`harfanglab::compile`), as
//! bytes. HarfangLab keeps no deployment state: a rule is known by its UUID.
//!
//! The Python service never reaches the tenant: its constructor looks the
//! platform up in the registry as `HarfangLab`, which the registry reads as
//! `harfang_lab` and does not find (`AttributeError`), so the oracle's
//! HarfangLab deploy and query stop before any request. This port builds
//! the client the constructor meant to build.

use opentide_compile::Json;

use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, Operation, Platform, QueryOutcome,
    QueryRequest, QueryRunner, Row, TenantContext, TimeWindow, columns_of, flatten,
};
use crate::encode;
use crate::error::ConnectorError;
use crate::http::HttpSettings;

/// The platform's identifier.
pub const PLATFORM: &str = "harfanglab";

/// The Sigma rules endpoint, after the tenant's URL.
const SIGMA: &str = "/api/data/threat_intelligence/SigmaRule/";
/// The YARA files endpoint.
const YARA: &str = "/api/data/threat_intelligence/YaraFile/";

/// Telemetry sources a query may name, and the API path that serves each
/// (`TELEMETRY_SOURCES`).
pub const TELEMETRY_SOURCES: [(&str, &str); 8] = [
    ("processes", "/api/data/telemetry/Processes/"),
    ("binary", "/api/data/telemetry/Binary/"),
    ("network", "/api/data/telemetry/Network/"),
    ("eventlog", "/api/data/telemetry/FullEventLog/"),
    ("dns", "/api/data/telemetry/DNSResolution/"),
    (
        "windows_authentications",
        "/api/data/telemetry/authentication/AuthenticationWindows/",
    ),
    (
        "linux_authentications",
        "/api/data/telemetry/authentication/AuthenticationLinux/",
    ),
    (
        "macos_authentications",
        "/api/data/telemetry/authentication/AuthenticationMacos/",
    ),
];

/// Filters the runner sets itself from the window and the limit.
const RESERVED: [&str; 5] = [
    "limit",
    "offset",
    "@event_create_date__gte",
    "@event_create_date__lte",
    "ordering",
];

/// How a HarfangLab tenant is reached when nothing else says: `requests`'
/// 120 s and no retries.
pub fn http_defaults() -> HttpSettings {
    HttpSettings::default()
}

/// The kind of rule a tenant takes (its `type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Sigma rules.
    Sigma,
    /// YARA files.
    Yara,
}

fn refused(cx: TenantContext<'_>, message: String, detail: Option<String>) -> ConnectorError {
    ConnectorError::Refused {
        platform: PLATFORM.to_owned(),
        tenant: cx.tenant.label.tenant.clone(),
        message,
        detail,
    }
}

fn setup(cx: TenantContext<'_>, message: String) -> ConnectorError {
    ConnectorError::Setup {
        platform: PLATFORM.to_owned(),
        tenant: cx.tenant.label.tenant.clone(),
        message,
    }
}

/// One tenant's client (`HarfangLabService`).
#[derive(Debug, Clone, Copy)]
pub struct Client<'a> {
    cx: TenantContext<'a>,
}

impl<'a> Client<'a> {
    /// The tenant's client; its `url` and `api_token` are read when sent.
    pub fn new(cx: TenantContext<'a>) -> Self {
        Self { cx }
    }

    /// The tenant's `type`.
    pub fn kind(&self) -> Result<Kind, ConnectorError> {
        let kind = self.cx.tenant.secret("type")?;
        match kind.expose() {
            "Sigma" => Ok(Kind::Sigma),
            "YARA" => Ok(Kind::Yara),
            other => Err(setup(
                self.cx,
                format!("type is Sigma or YARA, got {other:?}"),
            )),
        }
    }

    fn base(&self) -> Result<String, ConnectorError> {
        Ok(self
            .cx
            .tenant
            .secret("url")?
            .expose()
            .trim_end_matches('/')
            .to_owned())
    }

    /// A request with the service's headers.
    fn request(
        &self,
        method: reqwest::Method,
        url: &str,
    ) -> Result<reqwest::RequestBuilder, ConnectorError> {
        let token = self.cx.tenant.secret("api_token")?;
        Ok(self
            .cx
            .http
            .request(method, url)
            .header("Authorization", format!("Token {}", token.expose()))
            .header("Content-Type", "application/json"))
    }

    async fn send(&self, builder: reqwest::RequestBuilder) -> Result<Answer, ConnectorError> {
        let request = builder
            .build()
            .map_err(|error| setup(self.cx, crate::error::describe(error)))?;
        Answer::fetch(self.cx.http, request, self.cx.cancel).await
    }

    /// An answer that is not the one expected (`_http_errors`): 401 and
    /// 403 are the token's permissions, any other the rule's refusal.
    fn http_error(&self, answer: &Answer, failed: &str) -> ConnectorError {
        let tenant = &self.cx.tenant.label.tenant;
        let message = match answer.status {
            401 => format!(
                "HarfangLab tenant {tenant} refused the API token (HTTP 401): check the api_token"
            ),
            403 => format!(
                "HarfangLab tenant {tenant} forbids it (HTTP 403): check the API token's permissions"
            ),
            status => format!("{failed} on HarfangLab tenant {tenant} (HTTP {status})"),
        };
        refused(self.cx, message, Some(answer.text()))
    }

    fn endpoint(&self, kind: Kind) -> Result<String, ConnectorError> {
        Ok(format!(
            "{}{}",
            self.base()?,
            if kind == Kind::Sigma { SIGMA } else { YARA }
        ))
    }

    /// Puts the Sigma rule *rule_id* (the rule's UUID) from its compiled
    /// *body*, and creates it with `POST` when the tenant answers 404
    /// (`create_or_update_sigma_rule`).
    pub async fn put_sigma_rule(&self, rule_id: &str, body: &[u8]) -> Result<(), ConnectorError> {
        let endpoint = self.endpoint(Kind::Sigma)?;
        let put = self
            .send(
                self.request(reqwest::Method::PUT, &format!("{endpoint}{rule_id}/"))?
                    .body(body.to_vec()),
            )
            .await?;
        if put.status == 200 {
            return Ok(());
        }
        let answer = if put.status == 404 {
            let posted = self
                .send(
                    self.request(reqwest::Method::POST, &endpoint)?
                        .body(body.to_vec()),
                )
                .await?;
            if matches!(posted.status, 200 | 201) {
                return Ok(());
            }
            posted
        } else {
            put
        };
        Err(self.http_error(&answer, "Could not create or update the Sigma rule"))
    }

    /// Posts a YARA file from its compiled *body*, which the tenant creates
    /// or overwrites (`create_or_update_yara_rule`).
    pub async fn post_yara_rule(&self, body: &[u8]) -> Result<(), ConnectorError> {
        let endpoint = self.endpoint(Kind::Yara)?;
        let answer = self
            .send(
                self.request(reqwest::Method::POST, &endpoint)?
                    .body(body.to_vec()),
            )
            .await?;
        if matches!(answer.status, 200 | 201) {
            return Ok(());
        }
        Err(self.http_error(&answer, "Could not create or update the YARA file"))
    }

    /// Deletes the rule *rule_id* of *kind* (`delete_sigma_rule`,
    /// `delete_yara_rule`: 200 or 204).
    pub async fn delete_rule(&self, kind: Kind, rule_id: &str) -> Result<(), ConnectorError> {
        let url = format!("{}{rule_id}/", self.endpoint(kind)?);
        let answer = self
            .send(self.request(reqwest::Method::DELETE, &url)?)
            .await?;
        if matches!(answer.status, 200 | 204) {
            return Ok(());
        }
        Err(self.http_error(&answer, &format!("Could not delete rule {rule_id}")))
    }

    /// A telemetry search (`HarfangLabQueryRunner.run` once the query is
    /// read): the source's filters, the window, newest first, one row past
    /// the limit.
    pub async fn telemetry(
        &self,
        source: &str,
        filters: &[(String, String)],
        request: &QueryRequest,
    ) -> Result<QueryOutcome, ConnectorError> {
        let path = TELEMETRY_SOURCES
            .iter()
            .find(|(name, _)| *name == source)
            .map_or("", |(_, path)| path);
        let gte = TimeWindow::utc_z(request.window.start);
        let lte = TimeWindow::utc_z(request.window.end);
        let limit = request.limit.saturating_add(1).to_string();
        let mut params: Vec<(&str, &str)> = filters
            .iter()
            .filter(|(field, _)| !RESERVED.contains(&field.as_str()))
            .map(|(field, value)| (field.as_str(), value.as_str()))
            .collect();
        params.extend([
            ("@event_create_date__gte", gte.as_str()),
            ("@event_create_date__lte", lte.as_str()),
            ("ordering", "-@event_create_date"),
            ("limit", limit.as_str()),
            ("offset", "0"),
        ]);
        let url = format!("{}{path}?{}", self.base()?, encode::urlencode(params));
        let answer = self
            .send(
                self.request(reqwest::Method::GET, &url)?
                    .timeout(request.timeout),
            )
            .await?;
        let tenant = &self.cx.tenant.label.tenant;
        if answer.status != 200 {
            let detail = answer
                .not_json_detail()
                .or_else(|| Some(answer.text_head(500)).filter(|text| !text.is_empty()));
            return Err(refused(
                self.cx,
                format!(
                    "HarfangLab refused the telemetry search on {tenant} (HTTP {})",
                    answer.status
                ),
                detail,
            ));
        }
        let Some(body) = answer.json() else {
            return Err(refused(
                self.cx,
                format!("HarfangLab did not answer the telemetry search on {tenant} with JSON"),
                answer.not_json_detail(),
            ));
        };
        let rows: Vec<Row> = match body.get("results") {
            Some(Json::Array(results)) => results
                .iter()
                .filter_map(Json::as_object)
                .map(flatten)
                .collect(),
            _ => Vec::new(),
        };
        let count = match body.get("count") {
            Some(Json::Int(count)) => usize::try_from(*count).ok(),
            _ => None,
        };
        let truncated =
            rows.len() > request.limit || count.is_some_and(|count| count > request.limit);
        let kept: Vec<Row> = rows.into_iter().take(request.limit).collect();
        Ok(QueryOutcome {
            columns: columns_of(&kept),
            rows: kept,
            truncated,
            language: Some("telemetry".to_owned()),
            ..QueryOutcome::default()
        })
    }
}

/// `(source, filters)` of `SOURCE field=value ...` (`parse_telemetry_query`).
///
/// The words are split as a shell splits them (the `shlex` crate): quotes
/// group, and a backslash is part of the word, as in a Windows path, not an
/// escape. A word that starts with `#` starts a comment.
pub fn parse_telemetry_query(text: &str) -> Result<(String, Vec<(String, String)>), String> {
    // shlex reads a backslash as an escape; a private-use character the
    // text does not hold stands in for each one while it splits.
    let stand_in = ('\u{E000}'..='\u{F8FF}')
        .find(|candidate| !text.contains(*candidate))
        .ok_or_else(|| {
            "cannot read the telemetry query: it holds every private-use character".to_owned()
        })?;
    let words = shlex::split(&text.replace('\\', &stand_in.to_string()))
        .ok_or_else(|| "cannot read the telemetry query: No closing quotation".to_owned())?;
    let words: Vec<String> = words
        .into_iter()
        .map(|word| word.replace(stand_in, "\\"))
        .collect();
    let Some((first, rest)) = words.split_first() else {
        return Err(no_source());
    };
    let source = first.to_lowercase();
    if !TELEMETRY_SOURCES.iter().any(|(name, _)| *name == source) {
        return Err(no_source());
    }
    let mut filters: Vec<(String, String)> = Vec::new();
    for word in rest {
        let Some((field, value)) = word.split_once('=').filter(|(field, _)| !field.is_empty())
        else {
            return Err(format!("'{word}' is not a field=value filter"));
        };
        if RESERVED.contains(&field) {
            return Err(format!(
                "{field} is set from --since, --from, --to and --limit"
            ));
        }
        // A field named twice keeps its place and takes the last value.
        match filters.iter_mut().find(|(known, _)| known == field) {
            Some(entry) => value.clone_into(&mut entry.1),
            None => filters.push((field.to_owned(), value.to_owned())),
        }
    }
    Ok((source, filters))
}

/// The refusal of a query that names no source, its detail listing them.
fn no_source() -> String {
    "a HarfangLab query starts with a telemetry source".to_owned()
}

/// The sources a query may name, as a refusal's detail lists them.
pub fn sources_detail() -> String {
    let names: Vec<&str> = TELEMETRY_SOURCES.iter().map(|(name, _)| *name).collect();
    format!("one of: {}; then field=value filters", names.join(", "))
}

/// The platform: a deployer of the kind of rule each tenant takes, and the
/// telemetry runner. No live validator.
#[derive(Debug, Default)]
pub struct HarfangLab;

impl Deployer for HarfangLab {
    /// Puts a Sigma rule (creating it on a 404) or posts a YARA file, by
    /// the tenant's `type`; a delete removes it. *request*'s `rule_id` is
    /// the rule's UUID, its body the compiled rule; nothing is kept in
    /// deployment state.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let client = Client::new(cx);
            let kind = client.kind()?;
            match (request.operation, kind) {
                (Operation::Delete, kind) => client.delete_rule(kind, &request.rule_id).await?,
                (_, Kind::Sigma) => {
                    client
                        .put_sigma_rule(&request.rule_id, &request.body)
                        .await?;
                }
                (_, Kind::Yara) => client.post_yara_rule(&request.body).await?,
            }
            Ok(DeployOutcome {
                remote_id: None,
                operation: request.operation,
            })
        })
    }
}

impl QueryRunner for HarfangLab {
    /// A telemetry search; a query that names no source, or a filter that is
    /// not `field=value`, is refused before any request.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(async move {
            let (source, filters) = parse_telemetry_query(&request.text).map_err(|message| {
                let detail = (message == no_source()).then(sources_detail);
                refused(cx, message, detail)
            })?;
            cx.tenant.secret("url")?;
            cx.tenant.secret("api_token")?;
            Client::new(cx).telemetry(&source, &filters, request).await
        })
    }
}

impl Platform for HarfangLab {
    fn id(&self) -> &'static str {
        PLATFORM
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }

    fn query_runner(&self) -> Option<&dyn QueryRunner> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(words: &[(&str, &str)]) -> Vec<(String, String)> {
        words
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn telemetry_queries_are_read_as_words() {
        assert_eq!(
            parse_telemetry_query(r#"Processes a=1 'b=x y' c="C:\Windows\cmd.exe" a=2"#).unwrap(),
            (
                "processes".to_owned(),
                pairs(&[("a", "2"), ("b", "x y"), ("c", r"C:\Windows\cmd.exe")])
            )
        );
        assert_eq!(
            parse_telemetry_query(r"dns name=a\b").unwrap().1,
            pairs(&[("name", r"a\b")])
        );
        assert_eq!(
            parse_telemetry_query("dns x=1 # a comment").unwrap().1,
            pairs(&[("x", "1")])
        );
        for (query, message) in [
            ("", "a HarfangLab query starts with a telemetry source"),
            (
                "registry key=x",
                "a HarfangLab query starts with a telemetry source",
            ),
            ("processes cmd.exe", "'cmd.exe' is not a field=value filter"),
            ("processes =x", "'=x' is not a field=value filter"),
            (
                "processes limit=5",
                "limit is set from --since, --from, --to and --limit",
            ),
            (
                "processes 'open",
                "cannot read the telemetry query: No closing quotation",
            ),
        ] {
            assert_eq!(
                parse_telemetry_query(query).unwrap_err(),
                message,
                "{query}"
            );
        }
    }
}
