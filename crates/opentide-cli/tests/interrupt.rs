//! Ctrl-C at the command line while a tenant request is in flight (#830):
//! the `opentide` binary runs `query` against a stand-in Elasticsearch that
//! takes the request and never answers, and gets SIGINT once the request has
//! arrived. The run stops on its own, well before the grace after which the
//! process would end without it ([`INTERRUPT_GRACE`]), says `interrupted` and
//! exits `130`. The connectors' own cancellation is tested in
//! opentide-connectors; this is the command line around it.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a stand-in or a child that fails is a failure"
)]

use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use opentide_cli::app::INTERRUPT_GRACE;

/// How long the test waits for the request, and for the exit.
const PATIENCE: Duration = Duration::from_secs(60);

/// A stand-in Elasticsearch that reads each request's head, reports it, and
/// holds the connection open without answering. Its address.
fn stalling_tenant(arrived: mpsc::Sender<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut open = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut head = Vec::new();
            let mut byte = [0_u8; 1];
            while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            let first = String::from_utf8_lossy(&head)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            let _ = arrived.send(first);
            open.push(stream);
        }
    });
    address
}

#[test]
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn ctrl_c_during_a_tenant_query_stops_the_run_with_interrupted_and_130() {
    let (arrived, requests) = mpsc::channel();
    let address = stalling_tenant(arrived);

    let scratch = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    let ws = root.join("ws");
    let home = root.join("home");
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        platforms.join("elastic.toml"),
        format!(
            "[platform]\nenabled = true\nname = \"Elastic Security\"\n\n\
             [[tenants]]\nname = \"stalls\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\n\
             url = \"{address}\"\nelasticsearch_url = \"{address}\"\napi_key = \"key\"\n"
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_opentide-cli"))
        .args([
            "--json",
            "query",
            "--platform",
            "elastic",
            "--from",
            "2099-01-01T00:00:00Z",
            "--to",
            "2099-01-01T01:00:00Z",
            "--timeout",
            "600",
            "FROM x",
        ])
        .current_dir(&ws)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let Ok(request) = requests.recv_timeout(PATIENCE) else {
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        panic!(
            "the query never reached the tenant; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    };
    assert!(request.starts_with("POST /_query"), "{request}");

    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    let sent = Instant::now();
    rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();

    let deadline = sent + PATIENCE;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("opentide query did not exit {PATIENCE:?} after Ctrl-C");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stopped_in = sent.elapsed();
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();

    assert_eq!(
        status.code(),
        Some(130),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.lines().any(|line| line == "error: interrupted"),
        "stderr: {stderr}"
    );
    assert_eq!(
        stderr.matches("interrupted").count(),
        1,
        "reported once: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "an interrupted run prints no document: {stdout}"
    );
    // The run stopped itself: the handler's grace would have ended the
    // process at INTERRUPT_GRACE with the same code and line.
    assert!(
        stopped_in < INTERRUPT_GRACE,
        "the run took {stopped_in:?} to stop, not before the {INTERRUPT_GRACE:?} grace"
    );
}

/// A stand-in tenant that accepts each connection, reports it, and holds it
/// open without a word (a TLS handshake that never completes). Its port.
fn silent_tenant(accepted: mpsc::Sender<()>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut open = Vec::new();
        for stream in listener.incoming().flatten() {
            let _ = accepted.send(());
            open.push(stream);
        }
    });
    port
}

const PROMOTED_RULE: &str = "name: Promoted\nmetadata:\n  uuid: \
     00000000-0000-4000-8047-000000000930\n  schema: rule::1.0\n  version: 1\n  created: \
     2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: A rule.\nresponse:\n  \
     alert_severity: High\nconfigurations:\n  splunk:\n    status: STAGING\n    query: \
     index=main\n";

/// A repository whose last commit changed `objects/rules/r.yaml`, with a
/// Splunk tenant on `port`.
fn pushed_workspace(ws: &std::path::Path, port: u16) {
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::create_dir_all(ws.join("objects/rules")).unwrap();
    std::fs::write(
        platforms.join("splunk.toml"),
        format!(
            "[platform]\nenabled = true\nname = \"Splunk\"\n\n[[tenants]]\nname = \"stalls\"\n\
             strategies = [\"RELEASE\"]\n[tenants.setup]\nurl = \"127.0.0.1\"\nport = {port}\n\
             token = \"token\"\n"
        ),
    )
    .unwrap();
    let rule = ws.join("objects/rules/r.yaml");
    std::fs::write(&rule, PROMOTED_RULE).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args([
                "-c",
                "init.defaultBranch=main",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(ws)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .envs([
                ("GIT_AUTHOR_NAME", "t"),
                ("GIT_AUTHOR_EMAIL", "t@opentide.invalid"),
                ("GIT_COMMITTER_NAME", "t"),
                ("GIT_COMMITTER_EMAIL", "t@opentide.invalid"),
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "base"]);
    std::fs::write(&rule, PROMOTED_RULE.replace("A rule.", "A changed rule.")).unwrap();
    git(&["commit", "-q", "-a", "-m", "push"]);
}

/// A RELEASE push's deploy that gets `signals` while its tenant holds the
/// request: the rule it promoted, which no tenant received, keeps the
/// status it had (#1653). SIGTERM puts the pending files back, then ends
/// the process as its default does; a second Ctrl-C ends it at once, after
/// putting them back. The status the process ended with, and its stderr.
fn signalled_deploy_puts_the_promotion_back(
    launcher: &[&str],
    signals: &[rustix::process::Signal],
    pause: Duration,
) -> (std::process::ExitStatus, String) {
    let (accepted, connections) = mpsc::channel();
    let port = silent_tenant(accepted);
    let scratch = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    pushed_workspace(&ws, port);
    let rule = ws.join("objects/rules/r.yaml");
    let before = std::fs::read_to_string(&rule).unwrap();
    let binary = env!("CARGO_BIN_EXE_opentide-cli");
    let (program, words) = match launcher {
        [] => (binary, Vec::new()),
        [first, rest @ ..] => (*first, rest.iter().copied().chain([binary]).collect()),
    };
    let mut child = Command::new(program)
        .args(words)
        .args([
            "--json",
            "deploy",
            "--platform",
            "splunk",
            "--strategy",
            "RELEASE",
        ])
        .current_dir(&ws)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .envs([
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_REF", "refs/heads/main"),
            ("OPENTIDE_DEFAULT_BRANCH", "main"),
            ("GITHUB_SHA", "HEAD"),
        ])
        .env("GITHUB_WORKSPACE", &ws)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if connections.recv_timeout(PATIENCE).is_err() {
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        panic!(
            "the deploy never reached the tenant; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    }
    let promoted = std::fs::read_to_string(&rule).unwrap();
    assert!(promoted.contains("status: PRODUCTION"), "{promoted}");
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    for signal in signals {
        rustix::process::kill_process(pid, *signal).unwrap();
        std::thread::sleep(pause);
    }
    let deadline = Instant::now() + PATIENCE;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("opentide deploy did not exit {PATIENCE:?} after {signals:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&rule).unwrap(),
        before,
        "{signals:?}: the promotion was put back; stderr: {stderr}"
    );
    (status, stderr)
}

#[test]
fn sigterm_during_a_deploy_puts_its_promotion_back() {
    use std::os::unix::process::ExitStatusExt as _;
    let (status, stderr) = signalled_deploy_puts_the_promotion_back(
        &[],
        &[rustix::process::Signal::TERM],
        Duration::ZERO,
    );
    assert_eq!(
        status.signal(),
        Some(15),
        "ended by SIGTERM: {status:?}; {stderr}"
    );
    assert!(
        stderr.contains("r.yaml: status promotion undone, as no tenant received the rule"),
        "{stderr}"
    );
}

/// SIGHUP puts the promotion back where it has its default action; under
/// `nohup`, which ignores it, it is left ignored and the deploy runs on
/// until SIGTERM. Linux reads which from `/proc/self/status`.
#[cfg(target_os = "linux")]
#[test]
fn sighup_puts_the_promotion_back_unless_nohup_ignores_it() {
    use std::os::unix::process::ExitStatusExt as _;
    let (status, stderr) = signalled_deploy_puts_the_promotion_back(
        &[],
        &[rustix::process::Signal::HUP],
        Duration::ZERO,
    );
    assert_eq!(
        status.signal(),
        Some(1),
        "ended by SIGHUP: {status:?}; {stderr}"
    );
    let (status, stderr) = signalled_deploy_puts_the_promotion_back(
        &["nohup"],
        &[rustix::process::Signal::HUP, rustix::process::Signal::TERM],
        Duration::from_millis(500),
    );
    assert_eq!(
        status.signal(),
        Some(15),
        "SIGHUP was ignored, SIGTERM ended it: {status:?}; {stderr}"
    );
}

/// Ctrl-C stops the deploy, which puts its promotion back. A second Ctrl-C
/// cannot be timed from here (the run stops on the first, every wait it
/// makes is cancellable): `tests/promotion_signals.rs` drives that path in
/// the process.
#[test]
fn ctrl_c_during_a_deploy_puts_its_promotion_back() {
    let (status, stderr) = signalled_deploy_puts_the_promotion_back(
        &[],
        &[rustix::process::Signal::INT],
        Duration::ZERO,
    );
    assert_eq!(status.code(), Some(130), "{stderr}");
}
