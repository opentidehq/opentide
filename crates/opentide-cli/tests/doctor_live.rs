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
/// ID's token endpoint).
#[derive(Clone, Copy, Debug)]
enum Read {
    Status(u16),
    NoAnswer,
}

#[derive(Clone, Debug)]
struct Wire {
    sign_in: u16,
    read: Read,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Wire {
    fn new(read: Read) -> Self {
        Self {
            sign_in: 200,
            read,
            seen: Arc::default(),
        }
    }

    fn signing_in(mut self, status: u16) -> Self {
        self.sign_in = status;
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
}

impl Transport for Wire {
    fn execute<'a>(
        &'a self,
        request: Request,
        _cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Response, TransportFailure>> {
        let url = request.url().clone();
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
    fn make(&self, _spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, String> {
        Ok(Arc::new(self.clone()))
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

/// `opentide --json doctor <args>` in `ws` with `env` besides `HOME`, on
/// `wire` when it is given.
fn doctor(ws: &Path, args: &[&str], env: &[(&str, &str)], wire: Option<&Wire>) -> Ran {
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
        interrupt: Interrupt::default(),
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
    let mut err = stderr;
    let code = run(&words, &env, &host, &mut out, &mut err);
    let stdout = String::from_utf8(out).unwrap();
    let document = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{error}: not one JSON document: {stdout}"));
    Ran { code, document }
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
