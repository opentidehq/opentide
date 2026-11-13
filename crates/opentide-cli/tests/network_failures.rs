//! The network failures no golden case can record (UC-4.2, #832; UC-4.4,
//! #834), run in-process against stand-ins on the loopback.
//!
//! A cassette replays answers, at once: it has no way to say "no answer in
//! time", and Ctrl-C is not something the oracle's recording proxy sees. So
//! the timeouts and the cancelled runs of `query`, `validate query --live`,
//! `deploy`, `share`, `generate extract`, `validate --check cve`, `doctor`
//! and `setup skills discover` are proven here; a refused connection is in
//! the goldens (the `*unreachable*` cases of `tests/golden/cases.toml`),
//! except on HarfangLab, whose 0.23.0 client failed with `AttributeError:
//! HarfangLab` before it sent anything (CHANGELOG, #895), so the oracle has
//! no unreachable HarfangLab tenant to record.
//!
//! A cancelled run is `interrupted` (#1034 made the connectors' cancellation
//! deterministic): Ctrl-C during a tenant call ends the run with `error:
//! interrupted` on stderr, no document and exit 130. A command that polls
//! Ctrl-C (`query`, `validate query --live`, `deploy`, `doctor`, `setup
//! skills`) stops while its stand-in still holds the request; one that does
//! not (`share`, `generate extract`, the CVE lookups) ends at its call's end,
//! which the stand-in brings at once by closing the connection, and is
//! reported interrupted all the same.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken stand-in is a failure"
)]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opentide_cli::app::Interrupt;
use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};

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
#[derive(Debug)]
struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
    took: Duration,
}

impl Ran {
    fn document(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|error| {
            panic!(
                "{error}: not one JSON document:\n{}\n{}",
                self.stdout, self.stderr
            )
        })
    }

    /// The run was stopped by Ctrl-C: no document, 130, and `error:
    /// interrupted` last on stderr, once, after the log lines written before.
    fn assert_interrupted(&self) {
        assert_eq!((self.code, self.stdout.as_str()), (130, ""), "{self:?}");
        assert!(self.stderr.ends_with("error: interrupted\n"), "{self:?}");
        assert_eq!(
            self.stderr.matches("error: interrupted").count(),
            1,
            "{self:?}"
        );
        // Stopped at Ctrl-C, not at a timeout of the call.
        assert!(self.took < Duration::from_secs(10), "{self:?}");
    }
}

/// Runs `opentide` with `words` in-process at `ws` (not a terminal), with
/// `env` besides `HOME`, Ctrl-C being `interrupt`.
fn run_at(ws: &Path, words: &[&str], env: &[(&str, &str)], interrupt: &Interrupt) -> Ran {
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: interrupt.clone(),
    };
    let argv: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs(
        env.iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .chain([("HOME".to_owned(), home.display().to_string())]),
    );
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let started = Instant::now();
    let code = run(&argv, &env, &host, &mut out, &mut err);
    let took = started.elapsed();
    let stderr = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    Ran {
        code,
        stdout: String::from_utf8(out).unwrap(),
        stderr,
        took,
    }
}

/// What a stand-in does with each connection it takes.
#[derive(Clone, Copy)]
enum Answer {
    /// Keeps it open and sends nothing.
    Hold,
    /// Closes it at once, unanswered.
    Close,
}

/// A stand-in on the loopback that takes each connection and `answer`s it;
/// when `ctrl_c` is given, it presses Ctrl-C on the first connection,
/// before answering. Its address, `127.0.0.1:<port>`.
fn stand_in(answer: Answer, ctrl_c: Option<Interrupt>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let mut held: Vec<TcpStream> = Vec::new();
        for stream in listener.incoming().flatten() {
            if let Some(interrupt) = &ctrl_c {
                interrupt.request();
            }
            match answer {
                Answer::Hold => held.push(stream),
                Answer::Close => drop(stream),
            }
        }
    });
    address
}

/// An address on the loopback nothing listens on.
fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    address
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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

/// A copy of the golden fixture `fixture` (`tests/golden/fixtures/`), with
/// each `(from, to)` of `replace` made in the file at `path`.
fn fixture(fixture: &str, path: &str, replace: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    copy_tree(&repo().join("tests/golden/fixtures").join(fixture), &ws);
    let file = ws.join(path);
    let mut text = std::fs::read_to_string(&file).unwrap();
    for (from, to) in replace {
        assert!(text.contains(from), "{from} not in {path}");
        text = text.replace(from, to);
    }
    std::fs::write(&file, text).unwrap();
    (scratch, ws)
}

const KEY: &str = "stand-in-credential";
const ELASTIC: &str = ".opentide/configurations/platforms/elastic.toml";
const WINDOW: [&str; 4] = [
    "--from",
    "2099-01-01T00:00:00Z",
    "--to",
    "2099-01-01T01:00:00Z",
];

/// An Elastic tenant of `fixture` whose Kibana and Elasticsearch are `address`.
fn elastic_at(fixture_name: &str, address: &str) -> (tempfile::TempDir, PathBuf) {
    let url = format!("http://{address}");
    fixture(
        fixture_name,
        ELASTIC,
        &[
            ("https://kibana.elastic.invalid", &url),
            ("https://es.elastic.invalid", &url),
        ],
    )
}

// ---- query ----

#[test]
fn a_query_ctrl_c_stops_while_the_tenant_holds_it_is_interrupted() {
    let interrupt = Interrupt::default();
    let address = stand_in(Answer::Hold, Some(interrupt.clone()));
    let (_scratch, ws) = elastic_at("tenants", &address);
    let mut words = vec!["--json", "query", "--platform", "elastic"];
    words.extend(WINDOW);
    words.push("FROM logs-*");
    let ran = run_at(&ws, &words, &[("ELASTIC_API_KEY", KEY)], &interrupt);
    ran.assert_interrupted();
}

#[test]
fn a_harfanglab_query_on_a_tenant_that_refuses_the_connection_fails_it() {
    let url = format!("http://{}", closed_port());
    let (_scratch, ws) = fixture(
        "tenants",
        ".opentide/configurations/platforms/harfanglab.toml",
        &[("https://hl-tenant.invalid", &url)],
    );
    let mut words = vec!["--json", "query", "--platform", "harfanglab"];
    words.extend(WINDOW);
    words.push("processes process_name=cmd.exe");
    let ran = run_at(
        &ws,
        &words,
        &[("HARFANGLAB_API_TOKEN", KEY)],
        &Interrupt::default(),
    );
    assert_eq!(ran.code, 1, "{ran:?}");
    let document = ran.document();
    let result = &document["results"][0];
    assert_eq!(result["status"], "failed", "{result}");
    let error = result["error"].as_str().unwrap();
    assert!(
        error.starts_with(&format!("Cannot reach harfanglab tenant 'lab' at {url}")),
        "{error}"
    );
    assert!(error.contains("Connection refused"), "{error}");
}

// ---- validate query --live ----

#[test]
fn a_live_check_ctrl_c_stops_while_the_tenant_holds_it_is_interrupted() {
    let interrupt = Interrupt::default();
    let address = stand_in(Answer::Hold, Some(interrupt.clone()));
    let (_scratch, ws) = elastic_at("live-tenants", &address);
    let ran = run_at(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--live",
            "--platform",
            "elastic",
        ],
        &[("ELASTIC_API_KEY", KEY)],
        &interrupt,
    );
    ran.assert_interrupted();
}

#[test]
fn a_live_check_with_no_answer_within_the_check_timeout_fails() {
    let address = stand_in(Answer::Hold, None);
    let (_scratch, ws) = elastic_at("live-tenants", &address);
    let ran = run_at(
        &ws,
        &[
            "--json",
            "validate",
            "query",
            "--live",
            "--platform",
            "elastic",
            "--check-timeout",
            "1",
        ],
        &[("ELASTIC_API_KEY", KEY)],
        &Interrupt::default(),
    );
    assert_eq!(ran.code, 1, "{ran:?}");
    let document = ran.document();
    assert_eq!(document["status"], "failed", "{document}");
    // The tenant took the request and answered none: a tenant reached as
    // requests reached it is reported unreachable after its last rule, even
    // with fewer than three timeouts, the check timeout named first in the
    // advice (docs/cli/validate.md, "Slow queries and timeouts").
    let message = document["message"].as_str().unwrap();
    assert!(
        message.starts_with(&format!(
            "Cannot reach elastic tenant 'soc' at http://{address}: it answered no request: 1 \
             timed out after 1s (the last: "
        )),
        "{message}"
    );
    assert!(
        message.contains("Read timed out. (read timeout=1)"),
        "{message}"
    );
    let advice = document["advice"].as_str().unwrap();
    assert!(
        advice.starts_with(
            "if the tenant is up and only slow, raise the check timeout with --check-timeout"
        ),
        "{advice}"
    );
    assert!(ran.took < Duration::from_secs(30), "{:?}", ran.took);
}

// ---- deploy ----

#[test]
fn a_deploy_ctrl_c_stops_while_the_tenant_holds_it_is_interrupted() {
    let interrupt = Interrupt::default();
    let address = stand_in(Answer::Hold, Some(interrupt.clone()));
    let (_scratch, ws) = elastic_at("deploy-tenants", &address);
    let ran = run_at(
        &ws,
        &[
            "--json",
            "deploy",
            "--platform",
            "elastic",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        &[("ELASTIC_API_KEY", KEY)],
        &interrupt,
    );
    ran.assert_interrupted();
    // The tenant's batch stopped on the connectors' `interrupted`.
    let line: serde_json::Value = serde_json::from_str(ran.stderr.lines().next().unwrap()).unwrap();
    assert_eq!(line["event"], "elastic_tenant_deployment_failed", "{line}");
    assert_eq!(line["error"], "interrupted", "{line}");
}

#[test]
fn a_harfanglab_deploy_to_a_tenant_that_refuses_the_connection_fails() {
    let url = format!("http://{}", closed_port());
    let (_scratch, ws) = fixture(
        "deploy-tenants",
        ".opentide/configurations/platforms/harfanglab.toml",
        &[("https://hl-tenant.invalid", &url)],
    );
    let ran = run_at(
        &ws,
        &[
            "--json",
            "deploy",
            "--platform",
            "harfanglab",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        &[("HARFANGLAB_API_TOKEN", KEY)],
        &Interrupt::default(),
    );
    assert_eq!(ran.code, 1, "{ran:?}");
    let document = ran.document();
    let error = document["error"].as_str().unwrap();
    assert!(
        error.contains(&format!("Cannot reach harfanglab tenant 'lab' at {url}")),
        "{error}"
    );
    assert!(error.contains("Connection refused"), "{error}");
}

// ---- share ----

#[test]
fn a_share_push_ctrl_c_during_a_call_is_interrupted() {
    let interrupt = Interrupt::default();
    let address = stand_in(Answer::Close, Some(interrupt.clone()));
    let (_scratch, ws) = fixture(
        "share-misp",
        ".opentide/configurations/sharing.toml",
        &[("https://misp.invalid", &format!("http://{address}"))],
    );
    let ran = run_at(
        &ws,
        &["--json", "share", "push", "--target", "misp-prod"],
        &[("MISP_API_KEY", KEY)],
        &interrupt,
    );
    ran.assert_interrupted();
}

// ---- generate extract ----

#[test]
fn an_elastic_extract_ctrl_c_during_a_call_is_interrupted() {
    let interrupt = Interrupt::default();
    let address = stand_in(Answer::Close, Some(interrupt.clone()));
    let (_scratch, ws) = elastic_at("tenants", &address);
    let ran = run_at(
        &ws,
        &["--json", "generate", "extract", "elastic", "--space", "soc"],
        &[("ELASTIC_API_KEY", KEY)],
        &interrupt,
    );
    ran.assert_interrupted();
}

#[test]
fn a_defender_extract_ctrl_c_during_the_sign_in_is_interrupted() {
    let interrupt = Interrupt::default();
    let proxy = format!(
        "http://{}",
        stand_in(Answer::Close, Some(interrupt.clone()))
    );
    let (_scratch, ws) = fixture("tenants", ELASTIC, &[]);
    let ran = run_at(
        &ws,
        &["--json", "generate", "extract", "defender"],
        &[("DEFENDER_CLIENT_SECRET", KEY), ("HTTPS_PROXY", &proxy)],
        &interrupt,
    );
    ran.assert_interrupted();
}

// ---- validate --check cve ----

/// A workspace whose threat names a CVE, looked up on `base_url` with
/// `[cve] timeout = 1`.
fn cve_workspace(base_url: &str) -> (tempfile::TempDir, PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    let configurations = ws.join(".opentide/configurations");
    std::fs::create_dir_all(&configurations).unwrap();
    std::fs::write(
        configurations.join("documentation.toml"),
        format!("[cve]\nbase_url = \"{base_url}\"\ntimeout = 1\n"),
    )
    .unwrap();
    let threats = ws.join("objects/threats");
    std::fs::create_dir_all(&threats).unwrap();
    let threat = std::fs::read_to_string(
        repo().join("tests/fixtures/tide_corpus/current/Objects/Threat Vectors/threat-0001-simulated-actor.yaml"),
    )
    .unwrap();
    let anchor = "\nthreat:\n  description: Simulated threat actor for CLI E2E corpus\n";
    assert!(threat.contains(anchor));
    std::fs::write(
        threats.join("threat-0001-simulated-actor.yaml"),
        threat.replace(anchor, &format!("{anchor}  cve:\n    - CVE-2024-3094\n")),
    )
    .unwrap();
    (scratch, ws)
}

#[test]
fn a_cve_lookup_with_no_answer_within_its_timeout_is_a_warning() {
    let address = stand_in(Answer::Hold, None);
    let (_scratch, ws) = cve_workspace(&format!("http://{address}"));
    let ran = run_at(
        &ws,
        &["--json", "validate", "--check", "cve"],
        &[],
        &Interrupt::default(),
    );
    let document = ran.document();
    let text = document.to_string();
    assert!(text.contains("cve_lookup_unavailable"), "{text}");
    assert_eq!(ran.code, 0, "{ran:?}");
    assert!(ran.took < Duration::from_secs(30), "{:?}", ran.took);
}

#[test]
fn a_cve_lookup_ctrl_c_during_the_lookup_is_interrupted() {
    let interrupt = Interrupt::default();
    let address = stand_in(Answer::Close, Some(interrupt.clone()));
    let (_scratch, ws) = cve_workspace(&format!("http://{address}"));
    let ran = run_at(
        &ws,
        &["--json", "validate", "--check", "cve"],
        &[],
        &interrupt,
    );
    ran.assert_interrupted();
}

// ---- doctor ----

#[test]
fn doctors_network_checks_through_a_proxy_that_never_answers_time_out() {
    let proxy = format!("http://{}", stand_in(Answer::Hold, None));
    let (_scratch, ws) = fixture("tenants", ELASTIC, &[]);
    let ran = run_at(
        &ws,
        &["--json", "doctor"],
        &[("HTTPS_PROXY", &proxy)],
        &Interrupt::default(),
    );
    // PyPI is asked through the proxy, which takes the CONNECT and never
    // answers: after `NETWORK_TIMEOUT` the check is a warning named as
    // requests names a proxied request that failed, and the proxy check
    // still passes (its TCP connection opens).
    assert_eq!(ran.code, 0, "{ran:?}");
    let document = ran.document();
    let checks = document["checks"].as_array().unwrap();
    let check = |code: &str| {
        checks
            .iter()
            .find(|check| check["code"] == code)
            .unwrap_or_else(|| panic!("no {code} in {document}"))
            .clone()
    };
    let latest = check("opentide_latest");
    assert_eq!(latest["status"], "warn", "{latest}");
    assert_eq!(
        latest["message"], "Could not ask PyPI for the latest release (ProxyError)",
        "{latest}"
    );
    assert_eq!(check("proxy")["status"], "pass");
    let timeout = opentide_cli::commands::doctor_network::NETWORK_TIMEOUT;
    assert!(ran.took >= timeout, "{:?}", ran.took);
    assert!(ran.took < timeout * 5, "{:?}", ran.took);
}

#[test]
fn a_doctor_ctrl_c_while_the_proxy_holds_its_request_is_interrupted() {
    let interrupt = Interrupt::default();
    let proxy = format!("http://{}", stand_in(Answer::Hold, Some(interrupt.clone())));
    let (_scratch, ws) = fixture("tenants", ELASTIC, &[]);
    let ran = run_at(
        &ws,
        &["--json", "doctor"],
        &[("HTTPS_PROXY", &proxy)],
        &interrupt,
    );
    ran.assert_interrupted();
}

// ---- setup skills discover ----

#[test]
fn a_skills_discover_ctrl_c_while_the_proxy_holds_its_request_is_interrupted() {
    let interrupt = Interrupt::default();
    let proxy = format!("http://{}", stand_in(Answer::Hold, Some(interrupt.clone())));
    let (_scratch, ws) = fixture("tenants", ELASTIC, &[]);
    let ran = run_at(
        &ws,
        &["--json", "setup", "skills", "discover"],
        &[("HTTPS_PROXY", &proxy)],
        &interrupt,
    );
    ran.assert_interrupted();
    assert!(ran.took < Duration::from_secs(10), "{:?}", ran.took);
}

#[test]
fn a_skills_catalogue_with_no_answer_in_time_fails_as_an_unreachable_one() {
    // The catalogue's request waits `skills::TIMEOUT` (urlopen's 15 s), then
    // fails as the golden `setup skills discover` case with the network
    // refused does: `skills_manifest_remote_unavailable`, exit 1.
    let proxy = format!("http://{}", stand_in(Answer::Hold, None));
    let (_scratch, ws) = fixture("tenants", ELASTIC, &[]);
    let ran = run_at(
        &ws,
        &["--json", "setup", "skills", "discover"],
        &[("HTTPS_PROXY", &proxy)],
        &Interrupt::default(),
    );
    assert_eq!(ran.code, 1, "{ran:?}");
    let document = ran.document();
    assert_eq!(
        document["error"],
        "Could not fetch skills catalogue from opentidehq/skills@main. Check network access and \
         that the skills repository is publicly reachable.",
        "{document}"
    );
    assert!(
        ran.stderr
            .contains("\"event\":\"skills_manifest_remote_unavailable\""),
        "{ran:?}"
    );
    assert!(
        ran.took >= opentide_cli::commands::skills::TIMEOUT,
        "{:?}",
        ran.took
    );
}
