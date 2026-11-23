//! `opentide doctor --live` (#1658, smoke ED6), run in-process on the golden
//! `tenants` fixture against a scripted wire installed as the run's
//! transport: Entra ID's, ARM's and Kibana's addresses are the fixture's
//! (`*.invalid`) or fixed in the connectors, so a stand-in answers for them
//! and nothing leaves the process.
//!
//! Sentinel has a sign-in (Entra ID's token endpoint, then one `GET` of its
//! analytics rules); Elastic has none (one `GET` of Kibana's rules). The
//! fixture's other six platforms have their credential variables unset in
//! every test, so they are skipped and send nothing.
//!
//! The wire is the process's while installed, so each test holds `WIRE`.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use opentide_cli::app::Interrupt;
use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use opentide_connectors::connector::BoxFuture;
use opentide_connectors::transport::{
    self, HeaderMap, Request, Response, StatusCode, Transport, TransportFactory, TransportFailure,
    TransportSpec,
};
use tokio_util::sync::CancellationToken;

/// Serialises the tests: the installed transport is the process's.
static WIRE: Mutex<()> = Mutex::new(());

/// What the wire does with a tenant's read (every request that is not Entra
/// ID's token endpoint, the metadata server's or a key check).
#[derive(Clone, Copy, Debug)]
enum Read {
    Status(u16),
    NoAnswer,
    /// 401 for a request whose `Authorization` holds this key, 200 for any
    /// other.
    Rejecting(&'static str),
    /// Presses Ctrl-C on the first request, then holds it until the run
    /// cancels it (or five seconds, which the tests call a failure).
    Hold,
}

/// What the metadata host `metadata.google.internal` does.
#[derive(Clone, Copy, Debug)]
enum Metadata {
    /// No such host: the connection fails at once.
    Unreachable,
    /// Answers `status`, with `Metadata-Flavor: Google` or without it, and
    /// an access token when it is `200`.
    Answers { status: u16, flavored: bool },
    /// Takes the request and says nothing for as long as its client waits
    /// (at most fifteen seconds).
    Stalls,
}

#[derive(Clone, Debug)]
struct Wire {
    sign_in: u16,
    read: Read,
    metadata: Metadata,
    /// Whether the client this wire was made for routes `http://` through a
    /// proxy, and the timeout it was given: what `make` saw.
    proxied: bool,
    timeout: Duration,
    /// For each request to the metadata host, whether its client had a proxy.
    metadata_proxied: Arc<Mutex<Vec<bool>>>,
    /// For each request to the metadata host, the timeout its client had.
    metadata_timeouts: Arc<Mutex<Vec<Duration>>>,
    interrupt: Option<Interrupt>,
    seen: Arc<Mutex<Vec<String>>>,
    /// `host` and the `Authorization` header of each request that had one.
    keyed: Arc<Mutex<Vec<(String, String)>>>,
}

impl Wire {
    fn new(read: Read) -> Self {
        Self {
            sign_in: 200,
            read,
            metadata: Metadata::Unreachable,
            proxied: false,
            timeout: Duration::ZERO,
            metadata_proxied: Arc::default(),
            metadata_timeouts: Arc::default(),
            interrupt: None,
            seen: Arc::default(),
            keyed: Arc::default(),
        }
    }

    fn metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Whether each request to the metadata host came from a client with a
    /// proxy.
    fn metadata_proxied(&self) -> Vec<bool> {
        self.metadata_proxied.lock().unwrap().clone()
    }

    /// The timeout of the client that sent each request to the metadata host.
    fn metadata_timeouts(&self) -> Vec<Duration> {
        self.metadata_timeouts.lock().unwrap().clone()
    }

    fn signing_in(mut self, status: u16) -> Self {
        self.sign_in = status;
        self
    }

    fn pressing(mut self, interrupt: &Interrupt) -> Self {
        self.interrupt = Some(interrupt.clone());
        self
    }

    /// Every request the run sent to a tenant or its sign-in, as `METHOD
    /// host/path`: `doctor`'s own `opentide_latest` ask of PyPI is left out.
    fn seen(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|line| !line.contains(" pypi.org/"))
            .cloned()
            .collect()
    }

    /// The `Authorization` header values sent to `host`.
    fn keys_sent_to(&self, host: &str) -> Vec<String> {
        self.keyed
            .lock()
            .unwrap()
            .iter()
            .filter(|(sent_to, _)| sent_to == host)
            .map(|(_, key)| key.clone())
            .collect()
    }
}

impl Transport for Wire {
    fn execute<'a>(
        &'a self,
        request: Request,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Response, TransportFailure>> {
        let url = request.url().clone();
        let host = url.host_str().unwrap_or_default().to_owned();
        self.seen
            .lock()
            .unwrap()
            .push(format!("{} {}{}", request.method(), host, url.path()));
        let key = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if let Some(key) = &key {
            self.keyed.lock().unwrap().push((host.clone(), key.clone()));
        }
        // Only a tenant's request is held: doctor's own ask of PyPI is not
        // the probe, and is answered at once.
        let held = matches!(self.read, Read::Hold)
            && host != "login.microsoftonline.com"
            && host != "pypi.org";
        if held && let Some(interrupt) = &self.interrupt {
            interrupt.request();
        }
        if host == "metadata.google.internal" {
            self.metadata_proxied.lock().unwrap().push(self.proxied);
            self.metadata_timeouts.lock().unwrap().push(self.timeout);
            let metadata = self.metadata;
            let waits = self.timeout.min(Duration::from_secs(15));
            return Box::pin(async move {
                match metadata {
                    Metadata::Unreachable => Err(TransportFailure::Connect {
                        reason: "no such host".into(),
                    }),
                    Metadata::Stalls => {
                        tokio::time::sleep(waits).await;
                        Err(TransportFailure::Timeout)
                    }
                    Metadata::Answers { status, flavored } => {
                        let mut headers = HeaderMap::new();
                        if flavored {
                            headers.insert("metadata-flavor", "Google".parse().unwrap());
                        }
                        let body = if status == 200 {
                            br#"{"access_token":"stand-in-token","expires_in":3600}"#.to_vec()
                        } else {
                            b"<html>Bad gateway</html>".to_vec()
                        };
                        Ok(Response::new(
                            StatusCode::from_u16(status).unwrap(),
                            headers,
                            url,
                            (Duration::ZERO, Duration::ZERO),
                            Ok(body),
                        ))
                    }
                }
            });
        }
        let outcome = if host == "login.microsoftonline.com" {
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
                Read::Rejecting(marker) => {
                    let refused = key.as_deref().is_some_and(|key| key.contains(marker));
                    Ok((if refused { 401 } else { 200 }, b"{}".to_vec()))
                }
                Read::Hold => Ok((200, b"{}".to_vec())),
            }
        };
        Box::pin(async move {
            if held {
                tokio::select! {
                    () = cancel.cancelled() => return Err(TransportFailure::Cancelled),
                    () = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
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
    fn make(&self, spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, String> {
        let metadata = url::Url::parse("http://metadata.google.internal/").unwrap();
        Ok(Arc::new(Self {
            proxied: spec.proxies.route(&metadata).is_some(),
            timeout: spec.settings.timeout,
            ..self.clone()
        }))
    }
}

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What a run printed.
struct Ran {
    code: i32,
    document: serde_json::Value,
}

impl Ran {
    /// The `connectivity` or `credentials` check for `subject`.
    fn check(&self, code: &str, subject: &str) -> &serde_json::Value {
        self.document["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["code"] == code && check["subject"] == subject)
            .unwrap_or_else(|| panic!("no {code} check for {subject}: {}", self.document))
    }

    fn status(&self, code: &str, subject: &str) -> &str {
        self.check(code, subject)["status"].as_str().unwrap()
    }

    fn message(&self, code: &str, subject: &str) -> &str {
        self.check(code, subject)["message"].as_str().unwrap()
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn workspace() -> (tempfile::TempDir, PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    copy_tree(&repo.join("tests/golden/fixtures/tenants"), &ws);
    (scratch, ws)
}

/// What a run printed, as it came.
struct Raw {
    code: i32,
    stdout: String,
    stderr: String,
    took: Duration,
}

/// `opentide --json doctor <args>` in `ws` with `env` besides `HOME`, on
/// `wire` when it is given, Ctrl-C being `interrupt`.
fn run_doctor(
    ws: &Path,
    args: &[&str],
    env: &[(&str, &str)],
    wire: Option<&Wire>,
    interrupt: &Interrupt,
) -> Raw {
    let _held: MutexGuard<'_, ()> = WIRE.lock().unwrap_or_else(|held| held.into_inner());
    let _installed = wire.map(|wire| transport::install(Arc::new(wire.clone())));
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: interrupt.clone(),
    };
    let mut words: Vec<String> = vec!["--json".into(), "doctor".into()];
    words.extend(args.iter().map(|word| (*word).to_owned()));
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs(
        env.iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .chain([("HOME".to_owned(), home.display().to_string())]),
    );
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let started = std::time::Instant::now();
    let code = run(&words, &env, &host, &mut out, &mut err);
    let took = started.elapsed();
    Raw {
        code,
        stdout: String::from_utf8(out).unwrap(),
        stderr: String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap(),
        took,
    }
}

/// [`run_doctor`] for a run that prints its one JSON document.
fn doctor(ws: &Path, args: &[&str], env: &[(&str, &str)], wire: Option<&Wire>) -> Ran {
    let raw = run_doctor(ws, args, env, wire, &Interrupt::default());
    let document = serde_json::from_str(&raw.stdout)
        .unwrap_or_else(|error| panic!("{error}: not one JSON document: {}", raw.stdout));
    Ran {
        code: raw.code,
        document,
    }
}

/// Writes the platform file `name` of the workspace `ws`.
fn platform(ws: &Path, name: &str, text: &str) {
    let folder = ws.join(".opentide/configurations/platforms");
    std::fs::write(folder.join(format!("{name}.toml")), text).unwrap();
}

/// Both stand-in tenants' credentials; the fixture's other platforms get none.
const CREDENTIALS: [(&str, &str); 2] = [
    ("AZURE_CLIENT_SECRET", "stand-in-secret-value"),
    ("ELASTIC_API_KEY", "stand-in-api-key-value"),
];

#[test]
fn missing_credentials_are_reported_and_not_a_failure() {
    let (_scratch, ws) = workspace();
    let wire = Wire::new(Read::Status(200));
    let ran = doctor(&ws, &["--live"], &[], Some(&wire));
    assert_eq!(ran.code, 0, "{}", ran.document);
    // The env check names the tenant and the variable, as a warning.
    assert_eq!(ran.status("credentials", "sentinel/lab"), "warn");
    assert!(
        ran.message("credentials", "sentinel/lab")
            .contains("AZURE_CLIENT_SECRET"),
        "{}",
        ran.document
    );
    // Connectivity skips the tenant, naming why; nothing is sent.
    assert_eq!(ran.status("connectivity", "sentinel/lab"), "skip");
    assert!(
        ran.message("connectivity", "sentinel/lab")
            .contains("credentials not set: AZURE_CLIENT_SECRET"),
        "{}",
        ran.document
    );
    assert_eq!(ran.status("connectivity", "elastic/soc"), "skip");
    assert_eq!(wire.seen(), Vec::<String>::new());
    assert_eq!(ran.document["summary"]["failed"], 0);
}

#[test]
fn tenants_with_credentials_that_answer_pass() {
    let (_scratch, ws) = workspace();
    let wire = Wire::new(Read::Status(200));
    let ran = doctor(&ws, &["--live"], &CREDENTIALS, Some(&wire));
    assert_eq!(ran.code, 0, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "sentinel/lab"), "pass");
    assert_eq!(ran.status("connectivity", "elastic/soc"), "pass");
    // A tenant without credentials is skipped beside them.
    assert_eq!(ran.status("connectivity", "splunk/lab"), "skip");
    // Sentinel signed in, then read once; Elastic read once; nothing wrote.
    let seen = wire.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(
        seen[0],
        "POST login.microsoftonline.com/contoso-tenant-id/oauth2/v2.0/token"
    );
    assert!(
        seen.iter()
            .all(|line| line.starts_with("GET ") || line.starts_with("POST login.")),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|line| line.starts_with("GET management.azure.com/")),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|line| line.starts_with("GET kibana.elastic.invalid/")),
        "{seen:?}"
    );
    // No credential value reaches the document.
    let text = ran.document.to_string();
    for (_, value) in CREDENTIALS {
        assert!(!text.contains(value), "{text}");
    }
}

#[test]
fn a_tenant_that_refuses_the_credentials_fails_the_run() {
    let (_scratch, ws) = workspace();
    let wire = Wire::new(Read::Status(401));
    let ran = doctor(&ws, &["--live"], &CREDENTIALS, Some(&wire));
    assert_eq!(ran.code, 1, "{}", ran.document);
    assert_eq!(ran.document["failure"]["code"], "doctor_checks_failed");
    for subject in ["sentinel/lab", "elastic/soc"] {
        assert_eq!(ran.status("connectivity", subject), "fail", "{subject}");
        let message = ran.message("connectivity", subject);
        assert!(message.contains("authentication_failed"), "{message}");
        // The message names the tenant: its subject, then the error.
        assert!(message.starts_with(subject), "{message}");
    }
    // Credentials were set, so the env check is not what failed.
    assert_eq!(ran.status("credentials", "sentinel/lab"), "pass");
}

#[test]
fn a_refused_sign_in_fails_the_tenant_before_any_read() {
    let (_scratch, ws) = workspace();
    let wire = Wire::new(Read::Status(200)).signing_in(401);
    let ran = doctor(
        &ws,
        &["--live"],
        &[("AZURE_CLIENT_SECRET", "stand-in-secret-value")],
        Some(&wire),
    );
    assert_eq!(ran.code, 1, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "sentinel/lab"), "fail");
    assert!(
        ran.message("connectivity", "sentinel/lab")
            .contains("authentication_failed"),
        "{}",
        ran.document
    );
    assert_eq!(wire.seen().len(), 1, "{:?}", wire.seen());
}

#[test]
fn a_tenant_that_does_not_answer_fails_the_run() {
    let (_scratch, ws) = workspace();
    let wire = Wire::new(Read::NoAnswer);
    let ran = doctor(
        &ws,
        &["--live"],
        &[("ELASTIC_API_KEY", "stand-in-api-key-value")],
        Some(&wire),
    );
    assert_eq!(ran.code, 1, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "elastic/soc"), "fail");
    let message = ran.message("connectivity", "elastic/soc");
    assert!(message.contains("tenant_timeout"), "{message}");
    assert!(message.contains("'soc'"), "{message}");
}

#[test]
fn without_live_connectivity_is_not_run() {
    let (_scratch, ws) = workspace();
    let wire = Wire::new(Read::Status(401));
    let ran = doctor(&ws, &["--offline"], &CREDENTIALS, Some(&wire));
    assert_eq!(ran.code, 0, "{}", ran.document);
    let checks: Vec<_> = ran.document["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|check| check["code"] == "connectivity")
        .collect();
    assert_eq!(checks.len(), 1, "{checks:?}");
    assert_eq!(checks[0]["status"], "skip");
    assert_eq!(checks[0]["message"], "Not checked: --live not set");
    assert_eq!(wire.seen(), Vec::<String>::new());
}

#[test]
fn live_and_offline_contradict_each_other() {
    let (_scratch, ws) = workspace();
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.clone()),
        width: None,
        interrupt: Interrupt::default(),
    };
    let argv: Vec<String> = ["--json", "doctor", "--live", "--offline"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    let env = Env::from_pairs([("HOME".to_owned(), ws.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), stderr);
    assert_eq!(run(&argv, &env, &host, &mut out, &mut err), 2);
    // The usage error names the conflict, not an unknown flag.
    let shown = String::from_utf8(out).unwrap();
    assert!(
        shown.contains("--live") && shown.contains("--offline") && !shown.contains("unexpected"),
        "{shown}"
    );
}

// ---- the review's cases (#1726) ----

const GOOGLE_SECOPS: &str = r#"
[platform]
enabled = true
name = "Google Security Operations"

[[tenants]]
name = "secops"
strategies = ["PREVIEW"]
[tenants.setup]
ssl = true
project = "acme-secops"
location = "eu"
instance = "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6"
"#;

#[test]
fn google_secops_with_no_credentials_anywhere_is_skipped_not_failed() {
    let (_scratch, ws) = workspace();
    platform(&ws, "google_secops", GOOGLE_SECOPS);
    // No `credentials`, no GOOGLE_APPLICATION_CREDENTIALS, no gcloud file in
    // HOME, and the wire answers no metadata server.
    let wire = Wire::new(Read::Status(200));
    let ran = doctor(&ws, &["--live"], &[], Some(&wire));
    assert_eq!(ran.code, 0, "{}", ran.document);
    // The credentials check reports them missing, as a warning.
    assert_eq!(ran.status("credentials", "google_secops/secops"), "warn");
    assert!(
        ran.message("credentials", "google_secops/secops")
            .contains("no credentials"),
        "{}",
        ran.document
    );
    // Connectivity skips the tenant; no request reached Google's API.
    assert_eq!(ran.status("connectivity", "google_secops/secops"), "skip");
    assert!(
        wire.seen()
            .iter()
            .all(|line| line.contains("metadata.google.internal")),
        "{:?}",
        wire.seen()
    );
}

#[test]
fn google_secops_whose_default_credentials_are_refused_fails() {
    let (scratch, ws) = workspace();
    platform(&ws, "google_secops", GOOGLE_SECOPS);
    let key = scratch.path().join("adc.json");
    std::fs::write(
        &key,
        r#"{"type":"authorized_user","client_id":"stand-in-client-id",
            "client_secret":"stand-in-client-secret","refresh_token":"stand-in-refresh-token"}"#,
    )
    .unwrap();
    let wire = Wire::new(Read::Status(401));
    let key = key.display().to_string();
    let ran = doctor(
        &ws,
        &["--live"],
        &[("GOOGLE_APPLICATION_CREDENTIALS", key.as_str())],
        Some(&wire),
    );
    assert_eq!(ran.code, 1, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "google_secops/secops"), "fail");
    assert!(
        ran.message("connectivity", "google_secops/secops")
            .contains("authentication_failed"),
        "{}",
        ran.document
    );
    // The credentials were found, so no request went to the metadata server.
    assert!(
        wire.seen()
            .iter()
            .all(|line| !line.contains("metadata.google.internal")),
        "{:?}",
        wire.seen()
    );
}

const BITDEFENDER: &str = r#"
[platform]
enabled = true
name = "Bitdefender GravityZone"

[[tenants]]
name = "gz"
strategies = ["PREVIEW"]
[tenants.setup]
ssl = true
url = "https://gz.stand-in.invalid"
api_key = "$STAND_IN_GZ_KEY"
"#;

#[test]
fn bitdefender_is_not_supported_whatever_its_variables_are() {
    // Stand-in variable names only, and the wire answers nothing for it.
    for env in [&[][..], &[("STAND_IN_GZ_KEY", "stand-in-key-value")][..]] {
        let (_scratch, ws) = workspace();
        platform(&ws, "bitdefender", BITDEFENDER);
        let wire = Wire::new(Read::Status(200));
        let ran = doctor(&ws, &["--live"], env, Some(&wire));
        assert_eq!(ran.code, 0, "{}", ran.document);
        assert_eq!(ran.status("connectivity", "bitdefender/gz"), "skip");
        let check = ran.check("connectivity", "bitdefender/gz");
        assert!(
            check["message"]
                .as_str()
                .unwrap()
                .contains("not supported by doctor --live"),
            "{check}"
        );
        // Never told to set a variable and run again: that would not check it.
        assert!(check["fix"].is_null(), "{check}");
        assert!(
            !check["message"]
                .as_str()
                .unwrap()
                .contains("STAND_IN_GZ_KEY"),
            "{check}"
        );
        assert!(
            wire.seen()
                .iter()
                .all(|line| !line.contains("stand-in.invalid")),
            "{:?}",
            wire.seen()
        );
    }
}

const TWO_ELASTIC: &str = r#"
[platform]
enabled = true
name = "Elastic Security"

[[tenants]]
name = "soc"
strategies = ["PREVIEW"]
[tenants.setup]
ssl = true
url = "https://kibana.elastic.invalid"
elasticsearch_url = "https://es.elastic.invalid"
api_key = "$ELASTIC_API_KEY"
space = "soc"
index = ["logs-*"]

[[tenants]]
name = "lab"
strategies = ["PREVIEW"]
[tenants.setup]
ssl = true
url = "https://kibana.lab.invalid"
elasticsearch_url = "https://es.lab.invalid"
api_key = "$ELASTIC_LAB_KEY"
space = "lab"
index = ["logs-*"]
"#;

#[test]
fn two_tenants_of_one_platform_each_have_their_own_result_and_settings() {
    // One has credentials and answers; the other has none and is skipped:
    // only the first's host is contacted, with the first's key.
    let (_scratch, ws) = workspace();
    platform(&ws, "elastic", TWO_ELASTIC);
    let wire = Wire::new(Read::Status(200));
    let ran = doctor(
        &ws,
        &["--live"],
        &[("ELASTIC_API_KEY", "soc-key-value")],
        Some(&wire),
    );
    assert_eq!(ran.code, 0, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "elastic/soc"), "pass");
    assert_eq!(ran.status("connectivity", "elastic/lab"), "skip");
    assert!(
        ran.message("connectivity", "elastic/lab")
            .contains("ELASTIC_LAB_KEY"),
        "{}",
        ran.document
    );
    assert_eq!(
        wire.keys_sent_to("kibana.elastic.invalid"),
        ["ApiKey soc-key-value"]
    );
    assert!(wire.keys_sent_to("kibana.lab.invalid").is_empty());

    // Both have credentials, the second's is wrong: the first still passes,
    // the second alone fails, each with its own host and key.
    let wire = Wire::new(Read::Rejecting("lab-wrong-key"));
    let ran = doctor(
        &ws,
        &["--live"],
        &[
            ("ELASTIC_API_KEY", "soc-key-value"),
            ("ELASTIC_LAB_KEY", "lab-wrong-key"),
        ],
        Some(&wire),
    );
    assert_eq!(ran.code, 1, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "elastic/soc"), "pass");
    assert_eq!(ran.status("connectivity", "elastic/lab"), "fail");
    assert!(
        ran.message("connectivity", "elastic/lab")
            .contains("authentication_failed"),
        "{}",
        ran.document
    );
    assert_eq!(
        wire.keys_sent_to("kibana.elastic.invalid"),
        ["ApiKey soc-key-value"]
    );
    assert_eq!(
        wire.keys_sent_to("kibana.lab.invalid"),
        ["ApiKey lab-wrong-key"]
    );
}

#[test]
fn ctrl_c_stops_a_probe_that_the_tenant_holds() {
    let (_scratch, ws) = workspace();
    let interrupt = Interrupt::default();
    // The wire presses Ctrl-C on the request and holds it for five seconds
    // unless the run cancels it.
    let wire = Wire::new(Read::Hold).pressing(&interrupt);
    let raw = run_doctor(
        &ws,
        &["--live"],
        &[("ELASTIC_API_KEY", "stand-in-api-key-value")],
        Some(&wire),
        &interrupt,
    );
    assert_eq!((raw.code, raw.stdout.as_str()), (130, ""), "{}", raw.stderr);
    assert!(
        raw.stderr.ends_with("error: interrupted\n"),
        "{}",
        raw.stderr
    );
    assert!(raw.took < Duration::from_secs(3), "{:?}", raw.took);
}

// ---- the metadata server (#1726, round 3) ----

/// A proxy that accepts connections, so `doctor`'s own `proxy` check passes:
/// the metadata request must not reach it. Its address, and the listener to
/// keep alive.
fn listening_proxy() -> (String, std::net::TcpListener) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    (address, listener)
}

#[test]
fn a_proxys_answer_for_the_metadata_host_is_no_metadata_server() {
    let (_scratch, ws) = workspace();
    platform(&ws, "google_secops", GOOGLE_SECOPS);
    // A 502 with no `Metadata-Flavor`: a gateway's page, not Google's.
    let wire = Wire::new(Read::Status(200)).metadata(Metadata::Answers {
        status: 502,
        flavored: false,
    });
    let ran = doctor(&ws, &["--live"], &[], Some(&wire));
    assert_eq!(ran.code, 0, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "google_secops/secops"), "skip");
    // Even a 200 with a token, from a host that is not a metadata server.
    let wire = Wire::new(Read::Status(200)).metadata(Metadata::Answers {
        status: 200,
        flavored: false,
    });
    let ran = doctor(&ws, &["--live"], &[], Some(&wire));
    assert_eq!(ran.code, 0, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "google_secops/secops"), "skip");
}

#[test]
fn the_metadata_request_never_goes_through_the_runs_proxy() {
    let (_scratch, ws) = workspace();
    platform(&ws, "google_secops", GOOGLE_SECOPS);
    let (proxy, _listener) = listening_proxy();
    let wire = Wire::new(Read::Status(200)).metadata(Metadata::Answers {
        status: 502,
        flavored: false,
    });
    let env = [
        ("http_proxy", proxy.as_str()),
        ("all_proxy", proxy.as_str()),
    ];
    let ran = doctor(&ws, &["--live"], &env, Some(&wire));
    assert_eq!(ran.code, 0, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "google_secops/secops"), "skip");
    // The proxy was configured and reachable, and the tenant's own client has
    // it; the metadata request's did not.
    let proxy_check = ran.document["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["code"] == "proxy")
        .unwrap();
    assert_eq!(proxy_check["status"], "pass", "{proxy_check}");
    assert_eq!(wire.metadata_proxied(), [false]);
    // `--proxy` is no different.
    let ran = doctor(
        &ws,
        &["--live"],
        &[("OPENTIDE_PROXY", proxy.as_str())],
        Some(&wire),
    );
    assert_eq!(ran.code, 0, "{}", ran.document);
    assert_eq!(wire.metadata_proxied(), [false, false]);
}

#[test]
fn a_metadata_host_that_stalls_is_skipped_within_a_short_timeout() {
    let (_scratch, ws) = workspace();
    platform(&ws, "google_secops", GOOGLE_SECOPS);
    let wire = Wire::new(Read::Status(200)).metadata(Metadata::Stalls);
    let raw = run_doctor(&ws, &["--live"], &[], Some(&wire), &Interrupt::default());
    let document: serde_json::Value = serde_json::from_str(&raw.stdout).unwrap();
    assert_eq!(raw.code, 0, "{document}");
    // The wire holds a request for as long as its client's timeout: the
    // metadata host was asked once, with google-auth's three seconds, not a
    // tenant's two minutes. The client's timeout is what is held, not the
    // run's wall clock, which a loaded runner stretches by seconds whatever
    // the timeout (a run that never stalls has taken 8.2 s in CI).
    assert_eq!(wire.metadata_timeouts(), [Duration::from_secs(3)]);
    assert!(raw.took >= Duration::from_secs(3), "{:?}", raw.took);
    let check = document["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["code"] == "connectivity" && check["subject"] == "google_secops/secops")
        .unwrap();
    assert_eq!(check["status"], "skip", "{check}");
}

#[test]
fn a_real_metadata_server_supplies_the_credentials() {
    let (_scratch, ws) = workspace();
    platform(&ws, "google_secops", GOOGLE_SECOPS);
    let wire = Wire::new(Read::Status(200)).metadata(Metadata::Answers {
        status: 200,
        flavored: true,
    });
    let ran = doctor(&ws, &["--live"], &[], Some(&wire));
    assert_eq!(ran.code, 0, "{}", ran.document);
    assert_eq!(ran.status("connectivity", "google_secops/secops"), "pass");
    assert!(
        wire.seen()
            .iter()
            .any(|line| line.starts_with("GET eu-chronicle.googleapis.com/")),
        "{:?}",
        wire.seen()
    );
}
