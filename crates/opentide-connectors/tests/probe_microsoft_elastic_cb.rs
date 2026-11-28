//! `Prober` (`opentide doctor --live`, #1658) of Sentinel, Defender for
//! Endpoint, Elastic and Carbon Black Cloud, on a scripted wire installed as
//! the run's transport: Entra ID's, ARM's and Graph's addresses are fixed in
//! the connectors, so a stand-in transport answers for them and nothing
//! leaves the process. A test binary of its own: the transport is the
//! process's while installed.
//!
//! Each probe opens the tenant as a deploy does (Entra ID's sign-in for
//! Sentinel and Defender), then sends one `GET`, and nothing else.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentide_connectors::connector::{BoxFuture, DeployError, Platform, Prober, TenantContext};
use opentide_connectors::credentials::Mode;
use opentide_connectors::runtime::block_on;
use opentide_connectors::transport::{
    self, HeaderMap, Request, Response, StatusCode, Transport, TransportFactory, TransportFailure,
    TransportSpec,
};
use opentide_connectors::{
    Environment, HttpClient, HttpSettings, Tenant, carbon_black, elastic, microsoft_defender,
    sentinel,
};
use tokio_util::sync::CancellationToken;

/// What the scripted wire does with the one read each probe sends.
#[derive(Clone, Copy, Debug)]
enum Read {
    /// Answers with this status.
    Status(u16),
    /// Takes the request and never answers.
    NoAnswer,
    /// Refuses the connection.
    Refused,
}

/// The wire: Entra ID's token endpoint answers `sign_in`, every other
/// request is the probe's read and gets `read`. `seen` lists each request as
/// `METHOD host/path`.
#[derive(Clone, Debug)]
struct Wire {
    sign_in: u16,
    read: Read,
    seen: Arc<Mutex<Vec<String>>>,
    /// The full URL of each request, query included.
    urls: Arc<Mutex<Vec<String>>>,
}

impl Wire {
    fn new(read: Read) -> Self {
        Self {
            sign_in: 200,
            read,
            seen: Arc::default(),
            urls: Arc::default(),
        }
    }

    fn signing_in(mut self, status: u16) -> Self {
        self.sign_in = status;
        self
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    fn urls(&self) -> Vec<String> {
        self.urls.lock().unwrap().clone()
    }
}

impl Transport for Wire {
    fn execute<'a>(
        &'a self,
        request: Request,
        _cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Response, TransportFailure>> {
        let url = request.url().clone();
        self.urls.lock().unwrap().push(url.to_string());
        self.seen.lock().unwrap().push(format!(
            "{} {}{}",
            request.method(),
            url.host_str().unwrap_or_default(),
            url.path()
        ));
        let outcome = if url.host_str() == Some("login.microsoftonline.com") {
            Ok(match self.sign_in {
                200 => (
                    200,
                    br#"{"access_token":"stand-in-token","expires_in":3600,"token_type":"Bearer"}"#
                        .to_vec(),
                ),
                status => (
                    status,
                    br#"{"error":"invalid_client","error_description":"AADSTS7000215: bad secret"}"#
                        .to_vec(),
                ),
            })
        } else {
            match self.read {
                Read::Status(status) => Ok((status, b"{}".to_vec())),
                Read::NoAnswer => Err(TransportFailure::Timeout),
                Read::Refused => Err(TransportFailure::Connect {
                    reason: "Connection refused (os error 111)".into(),
                }),
            }
        };
        Box::pin(async move {
            let (status, body) = outcome?;
            Ok(Response::new(
                StatusCode::from_u16(status).unwrap(),
                HeaderMap::new(),
                url,
                (Duration::ZERO, Duration::ZERO),
                Ok(body),
            ))
        })
    }
}

impl TransportFactory for Wire {
    fn make(&self, _spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, transport::SetupError> {
        Ok(Arc::new(self.clone()))
    }
}

/// One installed wire at a time: the transport is the process's.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

const SENTINEL_SETUP: &str = "resource_group = \"soc-rg\"\nworkspace_name = \"soc\"\n\
     workspace_id = \"11111111-2222-4333-8444-555555555555\"\n\
     azure_tenant_id = \"contoso-tenant-id\"\nazure_subscription_id = \"sub-0001\"\n\
     azure_client_id = \"app-id\"\nazure_client_secret = \"$SECRET\"\n";
const DEFENDER_SETUP: &str =
    "tenant_id = \"contoso-tenant-id\"\nclient_id = \"app-id\"\nclient_secret = \"$SECRET\"\n";
const ELASTIC_SETUP: &str = "url = \"https://kibana.stand-in.invalid\"\n\
     elasticsearch_url = \"https://es.stand-in.invalid\"\napi_key = \"$SECRET\"\n";
const CARBON_BLACK_SETUP: &str =
    "url = \"https://cbc.stand-in.invalid\"\norg_key = \"ORGKEY01\"\ntoken = \"$SECRET\"\n";

/// Probes `platform`'s tenant `soc`, set up as `setup`, over `wire`. The
/// variable `SECRET` is set unless `secret` is `None`.
fn probe(
    platform: &dyn Platform,
    setup: &str,
    secret: Option<&str>,
    wire: &Wire,
) -> Result<(), DeployError> {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _installed = transport::install(Arc::new(wire.clone()));
    let env = match secret {
        Some(secret) => Environment::default().with("SECRET", secret),
        None => Environment::default(),
    };
    let setup: opentide_core::json::Object = toml::from_str(setup).unwrap();
    // As deploy mounts it: an unset variable is the connector's to report.
    let tenant = Tenant::from_setup(
        platform.id(),
        "soc",
        &setup,
        &env,
        Mode::Counting,
        &HttpSettings::default(),
    )
    .unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let prober: &dyn Prober = platform.prober().unwrap();
    block_on(async { prober.probe(cx).await }).unwrap()
}

fn code(result: Result<(), DeployError>) -> &'static str {
    result.unwrap_err().failure.code
}

fn sentinel_platform() -> sentinel::Sentinel {
    sentinel::Sentinel::new()
}

fn defender_platform() -> microsoft_defender::MicrosoftDefender {
    microsoft_defender::MicrosoftDefender::new()
}

#[test]
fn every_platform_here_has_a_prober() {
    assert!(sentinel_platform().prober().is_some());
    assert!(defender_platform().prober().is_some());
    assert!(elastic::Elastic.prober().is_some());
    assert!(carbon_black::CarbonBlack.prober().is_some());
}

// ---- Sentinel (Entra ID sign-in, then ARM) ----

#[test]
fn sentinel_signs_in_then_reads_the_analytics_rules_and_nothing_else() {
    let wire = Wire::new(Read::Status(200));
    probe(
        &sentinel_platform(),
        SENTINEL_SETUP,
        Some("s3cret-value"),
        &wire,
    )
    .unwrap();
    let seen = wire.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(
        seen[0],
        "POST login.microsoftonline.com/contoso-tenant-id/oauth2/v2.0/token"
    );
    assert!(
        seen[1]
            .starts_with("GET management.azure.com/subscriptions/sub-0001/resourceGroups/soc-rg/")
            && seen[1].ends_with("/alertRules"),
        "{seen:?}"
    );
}

#[test]
fn sentinel_with_a_refused_sign_in_fails_authentication_before_any_read() {
    let wire = Wire::new(Read::Status(200)).signing_in(401);
    let result = probe(
        &sentinel_platform(),
        SENTINEL_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "authentication_failed");
    assert_eq!(wire.seen().len(), 1, "{:?}", wire.seen());
}

#[test]
fn sentinel_whose_read_is_refused_with_401_fails_authentication() {
    let wire = Wire::new(Read::Status(401));
    let result = probe(
        &sentinel_platform(),
        SENTINEL_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "authentication_failed");
}

#[test]
fn sentinel_whose_read_gets_no_answer_fails_as_a_timeout() {
    let wire = Wire::new(Read::NoAnswer);
    let result = probe(
        &sentinel_platform(),
        SENTINEL_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "tenant_timeout");
}

#[test]
fn sentinel_with_an_unset_credential_fails_before_sending_anything() {
    let wire = Wire::new(Read::Status(200));
    let result = probe(&sentinel_platform(), SENTINEL_SETUP, None, &wire);
    assert_eq!(code(result), "credential_unset");
    assert!(wire.seen().is_empty(), "{:?}", wire.seen());
}

// ---- Microsoft Defender (Entra ID sign-in, then Graph) ----

#[test]
fn defender_signs_in_then_reads_the_first_page_of_detection_rules_and_nothing_else() {
    let wire = Wire::new(Read::Status(200));
    probe(
        &defender_platform(),
        DEFENDER_SETUP,
        Some("s3cret-value"),
        &wire,
    )
    .unwrap();
    let seen = wire.seen();
    assert_eq!(
        seen,
        [
            "POST login.microsoftonline.com/contoso-tenant-id/oauth2/v2.0/token",
            "GET graph.microsoft.com/beta/security/rules/detectionRules",
        ]
    );
    // The collection URL as it is, with no `$top`: no recording shows Graph
    // accepting it on this beta collection.
    assert_eq!(
        wire.urls().last().map(String::as_str),
        Some("https://graph.microsoft.com/beta/security/rules/detectionRules")
    );
}

#[test]
fn defender_with_a_refused_sign_in_fails_authentication() {
    let wire = Wire::new(Read::Status(200)).signing_in(400);
    let result = probe(
        &defender_platform(),
        DEFENDER_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "authentication_failed");
}

#[test]
fn defender_whose_read_is_refused_with_403_fails_authentication() {
    let wire = Wire::new(Read::Status(403));
    let result = probe(
        &defender_platform(),
        DEFENDER_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "authentication_failed");
}

#[test]
fn defender_whose_read_fails_with_a_server_error_is_refused() {
    let wire = Wire::new(Read::Status(500));
    let result = probe(
        &defender_platform(),
        DEFENDER_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "tenant_refused");
}

#[test]
fn defender_whose_read_cannot_connect_is_unreachable() {
    let wire = Wire::new(Read::Refused);
    let result = probe(
        &defender_platform(),
        DEFENDER_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "tenant_unreachable");
}

// ---- Elastic (API key, no sign-in) ----

#[test]
fn elastic_reads_one_rule_from_kibana_and_nothing_else() {
    let wire = Wire::new(Read::Status(200));
    probe(
        &elastic::Elastic,
        ELASTIC_SETUP,
        Some("s3cret-value"),
        &wire,
    )
    .unwrap();
    assert_eq!(
        wire.seen(),
        ["GET kibana.stand-in.invalid/api/detection_engine/rules/_find"]
    );
}

#[test]
fn elastic_whose_key_is_refused_with_401_fails_authentication() {
    let wire = Wire::new(Read::Status(401));
    let result = probe(
        &elastic::Elastic,
        ELASTIC_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "authentication_failed");
}

#[test]
fn elastic_that_gives_no_answer_fails_as_a_timeout() {
    let wire = Wire::new(Read::NoAnswer);
    let result = probe(
        &elastic::Elastic,
        ELASTIC_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "tenant_timeout");
}

#[test]
fn elastic_with_an_unset_key_is_reported_before_any_request() {
    let wire = Wire::new(Read::Status(200));
    let result = probe(&elastic::Elastic, ELASTIC_SETUP, None, &wire);
    assert_eq!(code(result), "credential_unset");
    assert!(wire.seen().is_empty(), "{:?}", wire.seen());
}

// ---- Carbon Black Cloud (API token, no sign-in) ----

#[test]
fn carbon_black_reads_the_watchlists_and_nothing_else() {
    let wire = Wire::new(Read::Status(200));
    probe(
        &carbon_black::CarbonBlack,
        CARBON_BLACK_SETUP,
        Some("s3cret-value"),
        &wire,
    )
    .unwrap();
    assert_eq!(
        wire.seen(),
        ["GET cbc.stand-in.invalid/threathunter/watchlistmgr/v3/orgs/ORGKEY01/watchlists"]
    );
}

#[test]
fn carbon_black_whose_token_is_refused_with_401_fails_authentication() {
    let wire = Wire::new(Read::Status(401));
    let result = probe(
        &carbon_black::CarbonBlack,
        CARBON_BLACK_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "authentication_failed");
}

#[test]
fn carbon_black_that_cannot_be_connected_to_is_unreachable() {
    let wire = Wire::new(Read::Refused);
    let result = probe(
        &carbon_black::CarbonBlack,
        CARBON_BLACK_SETUP,
        Some("s3cret-value"),
        &wire,
    );
    assert_eq!(code(result), "tenant_unreachable");
}

#[test]
fn no_error_names_the_secret() {
    let wire = Wire::new(Read::Status(401));
    for (platform, setup) in [
        (&elastic::Elastic as &dyn Platform, ELASTIC_SETUP),
        (&carbon_black::CarbonBlack, CARBON_BLACK_SETUP),
    ] {
        let error = probe(platform, setup, Some("s3cret-value"), &wire).unwrap_err();
        assert!(
            !error.failure.message.contains("s3cret-value"),
            "{}",
            error.failure.message
        );
    }
}
