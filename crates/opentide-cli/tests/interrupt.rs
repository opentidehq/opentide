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
