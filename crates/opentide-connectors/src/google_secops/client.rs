//! The Chronicle API v1 client of one Google SecOps instance, ported from
//! 0.28.0's `platforms/google_secops/client.py`.
//!
//! Every request goes to `<endpoint>/v1/projects/<project>/locations/
//! <location>/instances/<instance>` with an access token ([`super::auth`]).
//! HTTP 401 and 403 stop the tenant. HTTP 429, and 503 on any call but a
//! create, are waited out: `Retry-After` (at most 300 seconds), else the
//! `RetryInfo.retryDelay` of `error.details`, else 5, 15 and 60 seconds, and
//! the same request is sent again, at most three times; then the call
//! fails. Any other error is an [`ApiError`] with Google's `error.status` and
//! `error.message`. No transport-level retry is mounted, and `POST rules` is
//! never resent after a 5xx or no answer: the rule may exist
//! (`google_secops_create_unconfirmed`).

use std::future::Future;
use std::time::{Duration, Instant};

use opentide_compile::Json;
use opentide_compile::google_secops::{self as compile, Request, RunState};

use crate::answer::Answer;
use crate::connector::TenantContext;
use crate::error::ConnectorError;

use super::PLATFORM;
use super::auth::{Authorizer, TENANT_UNAUTHORIZED};

/// Seconds each request may take.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Waits after a 429 or 503 whose answer names none. A request is resent at
/// most this many times, whether or not Google names the wait.
pub const BACKOFF: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(60),
];

/// The most one named wait (`Retry-After` or `RetryInfo`) is honoured for.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

/// `error.details` entry that names how long to wait.
pub const RETRY_INFO: &str = "type.googleapis.com/google.rpc.RetryInfo";

/// One request that failed: Google's HTTP status, `error.status` and
/// `error.message`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    /// The method.
    pub method: String,
    /// The path relative to the instance (`rules/ru_…`, `:verifyRuleText`).
    pub path: String,
    /// The HTTP status.
    pub http_status: u16,
    /// Google's `error.status` (`NOT_FOUND`), empty when it names none.
    pub status: String,
    /// Google's `error.message`, or a description of the answer.
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = format!(
            "{} {}: HTTP {} {}: {}",
            self.method, self.path, self.http_status, self.status, self.message
        );
        f.write_str(text.trim_end_matches([':', ' ']))
    }
}

impl ApiError {
    /// The rule (or its deployment) does not exist.
    pub fn not_found(&self) -> bool {
        self.http_status == 404 || self.status == "NOT_FOUND"
    }

    /// A stale `etag` (`ABORTED`) or another concurrent change.
    pub fn conflict(&self) -> bool {
        self.http_status == 409 || self.status == "ABORTED"
    }

    /// A 5xx.
    pub fn server_error(&self) -> bool {
        self.http_status >= 500
    }

    /// A `DELETE` Google refused: any 4xx but 401, 403, 404 and 429.
    pub fn refused_delete(&self) -> bool {
        (400..500).contains(&self.http_status) && !matches!(self.http_status, 401 | 403 | 404 | 429)
    }

    /// `error.status`, else `HTTP <status>`, then the message
    /// (`_request_failed`'s text).
    pub fn short(&self) -> String {
        let status = if self.status.is_empty() {
            format!("HTTP {}", self.http_status)
        } else {
            self.status.clone()
        };
        format!("{status}: {}", self.message)
    }
}

/// A protobuf `Duration` (`"1800s"`) in seconds.
fn duration(value: Option<&Json>) -> Option<f64> {
    compile::protobuf_seconds(value)
}

/// The wait an answer names: `Retry-After`, else `RetryInfo.retryDelay`;
/// capped at [`MAX_RETRY_AFTER`].
pub fn retry_after(header: Option<&str>, body: Option<&Json>) -> Option<Duration> {
    let cap = MAX_RETRY_AFTER.as_secs_f64();
    if let Some(seconds) = header.and_then(|value| value.trim().parse::<f64>().ok())
        && seconds.is_finite()
    {
        return Some(Duration::from_secs_f64(seconds.clamp(0.0, cap)));
    }
    let Some(Json::Array(details)) = body
        .and_then(|body| body.get("error"))
        .and_then(|error| error.get("details"))
    else {
        return None;
    };
    details
        .iter()
        .filter(|detail| detail.get("@type").and_then(Json::as_str) == Some(RETRY_INFO))
        .find_map(|detail| duration(detail.get("retryDelay")))
        .map(|seconds| Duration::from_secs_f64(seconds.min(cap)))
}

/// Google's `error.status` and `error.message`, or a description of the
/// answer.
pub fn error_of(answer: &Answer) -> (String, String) {
    let Some(body) = answer.json() else {
        return (
            String::new(),
            answer
                .not_json_detail()
                .unwrap_or_else(|| format!("HTTP {}", answer.status)),
        );
    };
    match body.get("error") {
        Some(error @ Json::Object(_)) => (
            error.get("status").map(text).unwrap_or_default(),
            error.get("message").map(text).unwrap_or_default(),
        ),
        _ => (String::new(), format!("HTTP {}", answer.status)),
    }
}

/// Python's `str(value or "")`.
fn text(value: &Json) -> String {
    if value.truthy() {
        opentide_compile::deploy::text(value)
    } else {
        String::new()
    }
}

/// An answer and its `Retry-After` header.
#[derive(Clone, Debug)]
pub struct Reply {
    /// The answer.
    pub answer: Answer,
    /// Its `Retry-After`, as sent.
    pub retry_after: Option<String>,
}

/// Sends a request with `send` until it is answered with a status other
/// than one of `resent`, at most [`BACKOFF`]`.len()` resends, waiting
/// between them as the answer names or as [`BACKOFF`] says. The waits run on
/// tokio's clock and stop at cancellation.
///
/// # Errors
///
/// What `send` returns, or [`ConnectorError::Cancelled`].
pub async fn with_waits<F, Fut>(
    cancel: &tokio_util::sync::CancellationToken,
    resent: &[u16],
    mut send: F,
) -> Result<Reply, ConnectorError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Reply, ConnectorError>>,
{
    let mut retries = 0;
    loop {
        let reply = send().await?;
        if !resent.contains(&reply.answer.status) || retries >= BACKOFF.len() {
            return Ok(reply);
        }
        // Retry-After counts against the same budget: a tenant that keeps
        // naming a wait must not hold the run forever.
        let wait = retry_after(reply.retry_after.as_deref(), reply.answer.json().as_ref())
            .unwrap_or(BACKOFF[retries]);
        tokio::select! {
            () = cancel.cancelled() => return Err(ConnectorError::Cancelled),
            () = tokio::time::sleep(wait) => {}
        }
        retries += 1;
    }
}

/// What failed: one request ([`Failure::Api`]), or the tenant.
#[derive(Debug)]
pub enum Failure {
    /// Google answered with an error.
    Api(ApiError),
    /// The tenant refused the credentials or could not be reached, or the
    /// run was cancelled.
    Tenant(ConnectorError),
}

impl From<ConnectorError> for Failure {
    fn from(error: ConnectorError) -> Self {
        Self::Tenant(error)
    }
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

/// One instance's client (`GoogleSecopsClient`).
#[derive(Clone, Copy, Debug)]
pub struct Client<'a> {
    cx: TenantContext<'a>,
    auth: &'a Authorizer,
    endpoint: &'a str,
    instance: &'a str,
}

impl<'a> Client<'a> {
    /// The client of the instance resource `instance` at `endpoint`.
    pub fn new(
        cx: TenantContext<'a>,
        auth: &'a Authorizer,
        endpoint: &'a str,
        instance: &'a str,
    ) -> Self {
        Self {
            cx,
            auth,
            endpoint,
            instance,
        }
    }

    /// The instance resource.
    pub fn instance(&self) -> &str {
        self.instance
    }

    fn tenant(&self) -> &str {
        &self.cx.tenant.label.tenant
    }

    /// Sends one request once, with a fresh token.
    async fn send_once(
        &self,
        request: &Request,
        body: Option<&[u8]>,
    ) -> Result<Reply, ConnectorError> {
        let headers = self.auth.headers(self.cx).await?;
        let mut url = format!("{}{}", self.endpoint.trim_end_matches('/'), request.path);
        if !request.query.is_empty() {
            url.push('?');
            url.push_str(&crate::encode::urlencode(
                request
                    .query
                    .iter()
                    .map(|(key, value)| (*key, value.as_str())),
            ));
        }
        let mut builder = self
            .cx
            .http
            .request(
                crate::transport::Method::from_bytes(request.method.as_bytes())
                    .unwrap_or(crate::transport::Method::GET),
                &url,
            )
            .header("Accept", "application/json");
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = body {
            builder = builder
                .header("Content-Type", "application/json")
                .body(body.to_vec());
        }
        let built = builder.build().map_err(|error| ConnectorError::Setup {
            platform: PLATFORM.to_owned(),
            tenant: self.tenant().to_owned(),
            message: error.describe(),
        })?;
        let started = Instant::now();
        let response = self.cx.http.send(built, self.cx.cancel).await?;
        let elapsed = started.elapsed();
        let status = response.status().as_u16();
        let header = |name: crate::transport::HeaderName| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let content_type = header(crate::transport::header::CONTENT_TYPE);
        let retry_after = header(crate::transport::header::RETRY_AFTER);
        let body = self.cx.http.bytes(response, self.cx.cancel).await?;
        Ok(Reply {
            answer: Answer {
                status,
                content_type,
                body,
                elapsed,
            },
            retry_after,
        })
    }

    /// Sends `request` and returns its JSON answer: the waits on 429 (and
    /// 503 with `resend_unavailable`), 401 and 403 as the tenant's refusal,
    /// any other error as an [`ApiError`].
    ///
    /// # Errors
    ///
    /// [`Failure::Tenant`] for a refusal or a request that got no answer,
    /// [`Failure::Api`] for an error answer.
    pub async fn request(
        &self,
        request: &Request,
        resend_unavailable: bool,
    ) -> Result<Json, Failure> {
        let body = request
            .body
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| ConnectorError::Setup {
                platform: PLATFORM.to_owned(),
                tenant: self.tenant().to_owned(),
                message: error.to_string(),
            })?;
        let resent: &[u16] = if resend_unavailable {
            &[429, 503]
        } else {
            &[429]
        };
        let reply = with_waits(self.cx.cancel, resent, || {
            self.send_once(request, body.as_deref())
        })
        .await?;
        let answer = reply.answer;
        let relative = request
            .path
            .strip_prefix(&format!("/v1/{}", self.instance))
            .map(|path| path.trim_start_matches('/'))
            .unwrap_or(&request.path)
            .to_owned();
        if matches!(answer.status, 401 | 403) {
            let (status, message) = error_of(&answer);
            let status = if status.is_empty() {
                String::new()
            } else {
                format!(" {status}")
            };
            return Err(Failure::Tenant(ConnectorError::Authentication {
                platform: PLATFORM.to_owned(),
                tenant: self.tenant().to_owned(),
                message: format!(
                    "{TENANT_UNAUTHORIZED}: tenant {} refused the request (HTTP {}{status}): \
                     {message}",
                    self.tenant(),
                    answer.status
                ),
                detail: None,
            }));
        }
        let failed = |status: String, message: String| ApiError {
            method: request.method.to_owned(),
            path: relative.clone(),
            http_status: answer.status,
            status,
            message,
        };
        if answer.status >= 300 {
            let (status, message) = error_of(&answer);
            return Err(Failure::Api(failed(status, message)));
        }
        if answer.body.is_empty() {
            return Ok(Json::Object(opentide_compile::json::Object::new()));
        }
        match answer.json() {
            Some(body @ Json::Object(_)) => Ok(body),
            Some(_) => Ok(Json::Object(opentide_compile::json::Object::new())),
            None => Err(Failure::Api(failed(
                String::new(),
                answer
                    .not_json_detail()
                    .unwrap_or_else(|| "the answer is not JSON".to_owned()),
            ))),
        }
    }

    /// `POST :verifyRuleText`.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn verify(&self, text: &str) -> Result<Json, Failure> {
        self.request(&compile::verify_request(self.instance, text), true)
            .await
    }

    /// `POST rules`, never resent after a 5xx: the rule may have been
    /// created. A 429 is resent: Google did not execute it.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn create(&self, text: &str, scope: Option<&str>) -> Result<Json, Failure> {
        self.request(&compile::create_request(self.instance, text, scope), false)
            .await
    }

    /// `GET rules/<id>?view=FULL`.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn get_rule(&self, rule_id: &str) -> Result<Json, Failure> {
        self.request(&compile::get_rule_request(self.instance, rule_id), true)
            .await
    }

    /// `PATCH rules/<id>?updateMask=text`.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn update_text(
        &self,
        rule_id: &str,
        text: &str,
        etag: Option<&str>,
    ) -> Result<Json, Failure> {
        self.request(
            &compile::update_text_request(self.instance, rule_id, text, etag),
            true,
        )
        .await
    }

    /// `PATCH rules/<id>?updateMask=scope`; an empty `scope` makes the rule
    /// global.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn update_scope(
        &self,
        rule_id: &str,
        scope: &str,
        etag: Option<&str>,
    ) -> Result<Json, Failure> {
        self.request(
            &compile::update_scope_request(self.instance, rule_id, scope, etag),
            true,
        )
        .await
    }

    /// `GET rules/<id>/deployment`.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn get_deployment(&self, rule_id: &str) -> Result<Json, Failure> {
        self.request(
            &compile::get_deployment_request(self.instance, rule_id),
            true,
        )
        .await
    }

    /// `PATCH rules/<id>/deployment?updateMask=<mask>`.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn update_deployment(
        &self,
        rule_id: &str,
        state: &RunState,
    ) -> Result<Json, Failure> {
        self.request(
            &compile::deployment_request(self.instance, rule_id, state),
            true,
        )
        .await
    }

    /// `PATCH rules/<id>/deployment?updateMask=archived`.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn set_archived(&self, rule_id: &str, archived: bool) -> Result<Json, Failure> {
        self.request(
            &compile::archived_request(self.instance, rule_id, archived),
            true,
        )
        .await
    }

    /// `DELETE rules/<id>`, never with `force`.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn delete(&self, rule_id: &str) -> Result<Json, Failure> {
        self.request(&compile::delete_request(self.instance, rule_id), true)
            .await
    }

    /// `GET :udmSearch`.
    ///
    /// # Errors
    ///
    /// As [`Client::request`].
    pub async fn udm_search(&self, params: &[(&'static str, String)]) -> Result<Json, Failure> {
        self.request(&compile::udm_search_request(self.instance, params), true)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio_util::sync::CancellationToken;

    use super::*;

    fn reply(status: u16, retry_after: Option<&str>, body: &str) -> Reply {
        Reply {
            answer: Answer {
                status,
                content_type: Some("application/json".to_owned()),
                body: body.as_bytes().to_vec(),
                elapsed: Duration::ZERO,
            },
            retry_after: retry_after.map(str::to_owned),
        }
    }

    /// Sends the answers in order, counting the sends.
    async fn run(
        answers: Vec<Reply>,
        resent: &[u16],
    ) -> (Result<Reply, ConnectorError>, usize, Duration) {
        let sent = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let started = tokio::time::Instant::now();
        let outcome = with_waits(&cancel, resent, || {
            let index = sent.fetch_add(1, Ordering::SeqCst);
            let answer = answers[index.min(answers.len() - 1)].clone();
            async move { Ok(answer) }
        })
        .await;
        (outcome, sent.load(Ordering::SeqCst), started.elapsed())
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_named_wait_the_backoff_is_5_15_60_then_the_answer() {
        let (outcome, sent, waited) = run(vec![reply(429, None, "{}")], &[429]).await;
        assert_eq!(outcome.unwrap().answer.status, 429);
        assert_eq!(sent, 4);
        assert_eq!(waited, Duration::from_secs(80));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_after_then_retry_info_are_honoured_and_capped() {
        let info = r#"{"error": {"details": [
            {"@type": "type.googleapis.com/google.rpc.Other"},
            {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "2.5s"}]}}"#;
        let (outcome, sent, waited) = run(
            vec![
                reply(503, Some("7"), "{}"),
                reply(429, None, info),
                reply(429, Some("999"), "{}"),
                reply(200, None, "{}"),
            ],
            &[429, 503],
        )
        .await;
        assert_eq!(outcome.unwrap().answer.status, 200);
        assert_eq!(sent, 4);
        assert_eq!(waited, Duration::from_millis(7_000 + 2_500 + 300_000));
    }

    #[tokio::test(start_paused = true)]
    async fn a_create_is_not_resent_after_a_503() {
        let (outcome, sent, waited) = run(vec![reply(503, None, "{}")], &[429]).await;
        assert_eq!(outcome.unwrap().answer.status, 503);
        assert_eq!(sent, 1);
        assert_eq!(waited, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_stops_a_wait() {
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let waiting = with_waits(&cancel, &[429], || async {
            Ok(reply(429, Some("60"), "{}"))
        });
        let canceller = async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            stop.cancel();
        };
        let (outcome, ()) = tokio::join!(waiting, canceller);
        assert!(matches!(outcome, Err(ConnectorError::Cancelled)));
    }

    #[test]
    fn retry_after_values() {
        assert_eq!(
            retry_after(Some(" 1.5 "), None),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(retry_after(Some("-3"), None), Some(Duration::ZERO));
        assert_eq!(
            retry_after(Some("Wed, 21 Oct 2015 07:28:00 GMT"), None),
            None
        );
        assert_eq!(retry_after(None, Some(&Json::Null)), None);
    }

    #[test]
    fn api_errors_read_as_python_reads_them() {
        let error = ApiError {
            method: "DELETE".to_owned(),
            path: "rules/ru_1".to_owned(),
            http_status: 400,
            status: "FAILED_PRECONDITION".to_owned(),
            message: "has detections".to_owned(),
        };
        assert_eq!(
            error.to_string(),
            "DELETE rules/ru_1: HTTP 400 FAILED_PRECONDITION: has detections"
        );
        assert!(error.refused_delete() && !error.not_found() && !error.conflict());
        assert_eq!(error.short(), "FAILED_PRECONDITION: has detections");
        let bare = ApiError {
            status: String::new(),
            message: String::new(),
            http_status: 409,
            ..error
        };
        assert_eq!(bare.to_string(), "DELETE rules/ru_1: HTTP 409");
        assert!(bare.conflict() && bare.refused_delete());
        assert_eq!(bare.short(), "HTTP 409: ");
        let answer = reply(
            404,
            None,
            r#"{"error": {"status": "NOT_FOUND", "message": "gone"}}"#,
        );
        assert_eq!(
            error_of(&answer.answer),
            ("NOT_FOUND".to_owned(), "gone".to_owned())
        );
        let answer = reply(500, None, r#"[1]"#);
        assert_eq!(
            error_of(&answer.answer),
            (String::new(), "HTTP 500".to_owned())
        );
    }
}
