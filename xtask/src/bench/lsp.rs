//! The language server's first diagnostics: the time from spawning the
//! server to the first `textDocument/publishDiagnostics` for a rule it was
//! asked to open in the heavy workspace, as an editor sees it on start-up.
//!
//! The client sends `initialize` (the workspace as `rootUri` and its one
//! workspace folder, so the server indexes all of it), `initialized` and
//! `textDocument/didOpen`, answers any request the server makes with `null`,
//! and stops the clock at the first diagnostics for the opened document. It
//! then shuts the server down (`shutdown`, `exit`) and reaps it with
//! `wait4(2)` for its peak RSS. A server that does not exit within
//! [`EXIT_TIMEOUT`] of `exit`, or does not answer within the
//! timeout is killed and the run fails.

use crate::bench::measure::{self, RunDir};
use crate::bench::report::Sample;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{ChildStdin, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a server may take to its first diagnostics, and to shut down.
pub const TIMEOUT: Duration = Duration::from_secs(300);

/// How long a server may take to exit after `exit` (or after it was killed
/// for not answering).
pub const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Writes one LSP message: a `Content-Length` header and the JSON body.
pub fn write_message(writer: &mut impl Write, message: &Value) -> Result<()> {
    let body = serde_json::to_vec(message)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

/// Reads one LSP message; `Ok(None)` at the end of the stream.
pub fn read_message(reader: &mut impl BufRead) -> Result<Option<Value>> {
    let mut length: Option<usize> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse().context("Content-Length")?);
        }
    }
    let length = length.context("an LSP message without Content-Length")?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

/// A `file://` URI for an absolute path, percent-encoding what a URI path
/// may not hold (the heavy workspace's paths are ASCII; spaces are encoded).
pub fn file_uri(path: &Path) -> String {
    let mut uri = String::from("file://");
    for byte in path.to_string_lossy().bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                uri.push(char::from(byte));
            }
            _ => uri.push_str(&format!("%{byte:02X}")),
        }
    }
    uri
}

/// What one run of the server measured.
#[derive(Clone, Copy, Debug)]
pub struct FirstDiagnostics {
    /// Spawn to first diagnostics for the document, and the server's peak RSS.
    pub sample: Sample,
    /// How many diagnostics that first publish held.
    pub diagnostics: usize,
}

/// Starts `program args` in `run.workspace`, opens `document` (a path
/// relative to the workspace) and measures the first diagnostics for it.
pub fn first_diagnostics(
    program: &Path,
    args: &[OsString],
    run: &RunDir,
    document: &Path,
    inject: Option<Duration>,
) -> Result<FirstDiagnostics> {
    first_diagnostics_with(program, args, run, document, inject, || {})
}

/// [`first_diagnostics`], calling `before_spawn` between the reset of
/// xtask's high-water mark and the spawn (the tests fault memory there).
fn first_diagnostics_with(
    program: &Path,
    args: &[OsString],
    run: &RunDir,
    document: &Path,
    inject: Option<Duration>,
    before_spawn: impl FnOnce(),
) -> Result<FirstDiagnostics> {
    let (outcome, peak_rss_bytes) = run_server(
        program,
        args,
        run,
        document,
        before_spawn,
        |stdin, messages, session| {
            drive(
                stdin,
                messages,
                &session.root_uri,
                &session.uri,
                &session.text,
                session.start,
                inject,
            )
        },
    )?;
    let (elapsed, diagnostics) = outcome;
    Ok(FirstDiagnostics {
        sample: Sample {
            wall_s: elapsed.as_secs_f64(),
            peak_rss_bytes,
        },
        diagnostics,
    })
}

/// What a session's driver is given about the run.
struct SessionInfo {
    root_uri: String,
    uri: String,
    text: String,
    /// When the server was spawned.
    start: Instant,
}

/// Spawns `program args` in `run.workspace`, runs `drive` against its stdio
/// (it must end the session with `shutdown` and `exit`), reaps the server
/// and returns what `drive` returned with the server's peak RSS. A server
/// that does not exit within [`EXIT_TIMEOUT`], exits with a status other
/// than 0, or whose peak RSS does not exceed xtask's own fails the run.
fn run_server<T>(
    program: &Path,
    args: &[OsString],
    run: &RunDir,
    document: &Path,
    before_spawn: impl FnOnce(),
    drive: impl FnOnce(
        &mut ChildStdin,
        &mpsc::Receiver<Result<Option<Value>>>,
        &SessionInfo,
    ) -> Result<T>,
) -> Result<(T, u64)> {
    let mut command = measure::command(program, args, run)?;
    command.stdin(Stdio::piped()).stdout(Stdio::piped());
    let root = run
        .workspace
        .canonicalize()
        .with_context(|| format!("resolve {}", run.workspace.display()))?;
    let path = root.join(document);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let root_uri = file_uri(&root);
    let uri = file_uri(&path);

    // The floor is read as soon as the spawn returns, not after the reap:
    // the reader thread and the messages below are xtask's, never the
    // server's (`measure::spawn`).
    let measure::Spawned {
        mut child,
        start,
        own_peak_rss: floor,
    } = measure::spawn(&mut command, before_spawn)?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = measure::reap(child);
        bail!("the language server's stdio was not piped");
    };
    let (sender, messages) = mpsc::channel::<Result<Option<Value>>>();
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        loop {
            let message = read_message(&mut stdout);
            let done = !matches!(message, Ok(Some(_)));
            if sender.send(message).is_err() || done {
                break;
            }
        }
    });

    let info = SessionInfo {
        root_uri,
        uri,
        text,
        start,
    };
    let session = drive(&mut stdin, &messages, &info);
    drop(stdin);
    let outcome = match session {
        Ok(found) => Ok(found),
        Err(err) => {
            let _ = child.kill();
            Err(err)
        }
    };
    // Bounded: a server that ignores `exit` is killed at the deadline. The
    // reader thread is not joined: a grandchild holding the server's stdout
    // open would block it; it ends when the pipe closes.
    let deadline = Instant::now() + EXIT_TIMEOUT;
    let reaped = measure::reap_by(child, deadline);
    drop(reader);
    let (peak_rss_bytes, exit_code) = reaped.with_context(|| {
        format!(
            "{} did not exit within {EXIT_TIMEOUT:?} of `exit`",
            program.display()
        )
    })?;
    let found = outcome.with_context(|| {
        format!(
            "{} (stderr: {})",
            program.display(),
            run.stderr_tail().trim()
        )
    })?;
    if exit_code != Some(0) {
        bail!(
            "the language server exited with {exit_code:?} after shutdown (stderr: {})",
            run.stderr_tail().trim()
        );
    }
    // Last: a server that failed says why above, not that its RSS was small.
    measure::distinct_from_own(peak_rss_bytes, floor)?;
    Ok((found, peak_rss_bytes))
}

/// The session: returns the time to the first diagnostics for `uri` and
/// their count, after shutting the server down.
fn drive(
    stdin: &mut ChildStdin,
    messages: &mpsc::Receiver<Result<Option<Value>>>,
    root_uri: &str,
    uri: &str,
    text: &str,
    start: Instant,
    inject: Option<Duration>,
) -> Result<(Duration, usize)> {
    let name = Path::new(root_uri).file_name().map_or_else(
        || "workspace".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    write_message(
        stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "processId": std::process::id(),
                "rootUri": root_uri,
                "workspaceFolders": [{ "uri": root_uri, "name": name }],
                "capabilities": {
                    "textDocument": { "publishDiagnostics": {} },
                    "workspace": { "workspaceFolders": true, "configuration": true }
                }
            }
        }),
    )?;
    wait_for(stdin, messages, start, |m| {
        m.get("id") == Some(&json!(1)) && m.get("method").is_none()
    })?;
    write_message(
        stdin,
        &json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    )?;
    let language = if Path::new(uri)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("toml"))
    {
        "toml"
    } else {
        "yaml"
    };
    write_message(
        stdin,
        &json!({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": { "textDocument": {
                "uri": uri, "languageId": language, "version": 1, "text": text
            } }
        }),
    )?;
    let published = wait_for(stdin, messages, start, |m| {
        m.get("method").and_then(Value::as_str) == Some("textDocument/publishDiagnostics")
            && m.pointer("/params/uri").and_then(Value::as_str) == Some(uri)
    })?;
    if let Some(sleep) = inject {
        std::thread::sleep(sleep);
    }
    let elapsed = start.elapsed();
    let count = published
        .pointer("/params/diagnostics")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);

    write_message(
        stdin,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "shutdown" }),
    )?;
    wait_for(stdin, messages, start, |m| {
        m.get("id") == Some(&json!(2)) && m.get("method").is_none()
    })?;
    write_message(stdin, &json!({ "jsonrpc": "2.0", "method": "exit" }))?;
    Ok((elapsed, count))
}

/// Reads messages until one matches, answering the server's requests with
/// `null` on the way (an editor that supports none of them).
fn wait_for(
    stdin: &mut ChildStdin,
    messages: &mpsc::Receiver<Result<Option<Value>>>,
    start: Instant,
    matches: impl Fn(&Value) -> bool,
) -> Result<Value> {
    loop {
        let left = TIMEOUT
            .checked_sub(start.elapsed())
            .context("the language server did not answer in time")?;
        let message = match messages.recv_timeout(left) {
            Ok(message) => message?,
            Err(_) => bail!("the language server did not answer within {TIMEOUT:?}"),
        };
        let Some(message) = message else {
            bail!("the language server closed its output");
        };
        if matches(&message) {
            if let Some(error) = message.get("error") {
                bail!("the language server answered with an error: {error}");
            }
            return Ok(message);
        }
        if let (Some(id), Some(_)) = (message.get("id"), message.get("method")) {
            write_message(
                stdin,
                &json!({ "jsonrpc": "2.0", "id": id, "result": null }),
            )?;
        }
    }
}

/// How many times the editor pulls the workspace while it completes, in
/// [`editor_latency`].
pub const EDITOR_CYCLES: i64 = 10;

/// The pulls after the first that [`editor_latency`] leaves unmeasured.
const SETTLE_PULLS: i64 = 2;

/// What one run of [`editor_latency`] measured.
#[derive(Clone, Copy, Debug)]
pub struct EditorLatency {
    /// The longest a completion waited, over [`EDITOR_CYCLES`] of them (each
    /// sent just after a workspace pull that nothing has changed since), and
    /// the server's peak RSS.
    pub sample: Sample,
    /// The first workspace pull, when nothing is cached.
    pub first_pull: Duration,
    /// The median of the later pulls.
    pub repeat_pull: Duration,
}

/// The editor's steady state: the client (vscode-languageclient) pulls the
/// workspace's diagnostics again two seconds after every answer, for as long
/// as it runs, and the user presses Ctrl+Space between two pulls or during
/// one. The run opens `document` in the heavy workspace, pulls its
/// diagnostics and the workspace's three times, then [`EDITOR_CYCLES`] times pulls
/// the workspace again and, 2 ms later, asks for a completion: the time that
/// completion waits is what a server that runs the pull to its end first
/// makes the user wait for.
///
/// With `typing`, each cycle starts with a keystroke in the open document
/// (`didChange`) and the pull of that document's diagnostics beside the
/// workspace's: what an editor sends when the user types and then presses
/// Ctrl+Space. The server then validates the workspace again before it can
/// answer the pulls, so that is what a completion waits for.
pub fn editor_latency(
    program: &Path,
    args: &[OsString],
    run: &RunDir,
    document: &Path,
    typing: bool,
) -> Result<EditorLatency> {
    let ((worst, first_pull, repeat_pull), peak_rss_bytes) = run_server(
        program,
        args,
        run,
        document,
        || {},
        |stdin, messages, session| drive_editor(stdin, messages, session, typing),
    )?;
    Ok(EditorLatency {
        sample: Sample {
            wall_s: worst.as_secs_f64(),
            peak_rss_bytes,
        },
        first_pull,
        repeat_pull,
    })
}

/// `initialize` as VS Code's client sends it (pull diagnostics, refresh and
/// file watching), `initialized`, and `didOpen` of the document.
fn start_editor(
    stdin: &mut ChildStdin,
    messages: &mpsc::Receiver<Result<Option<Value>>>,
    session: &SessionInfo,
) -> Result<()> {
    let name = Path::new(&session.root_uri).file_name().map_or_else(
        || "workspace".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    write_message(
        stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "processId": std::process::id(),
                "rootUri": session.root_uri,
                "workspaceFolders": [{ "uri": session.root_uri, "name": name }],
                "capabilities": {
                    "textDocument": { "diagnostic": { "dynamicRegistration": false } },
                    "workspace": {
                        "workspaceFolders": true,
                        "configuration": true,
                        "diagnostics": { "refreshSupport": true },
                        "didChangeWatchedFiles": { "dynamicRegistration": true }
                    }
                }
            }
        }),
    )?;
    wait_for(stdin, messages, session.start, |m| {
        m.get("id") == Some(&json!(1)) && m.get("method").is_none()
    })?;
    write_message(
        stdin,
        &json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    )?;
    write_message(
        stdin,
        &json!({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": { "textDocument": {
                "uri": session.uri, "languageId": "yaml", "version": 1, "text": session.text
            } }
        }),
    )?;
    Ok(())
}

fn drive_editor(
    stdin: &mut ChildStdin,
    messages: &mpsc::Receiver<Result<Option<Value>>>,
    session: &SessionInfo,
    typing: bool,
) -> Result<(Duration, Duration, Duration)> {
    start_editor(stdin, messages, session)?;
    let request = |stdin: &mut ChildStdin, id: i64, method: &str, params: Value| {
        write_message(
            stdin,
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        )
    };
    request(
        stdin,
        2,
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": session.uri } }),
    )?;
    wait_for_all(stdin, messages, session.start, &[2])?;

    let pull = json!({ "previousResultIds": [] });
    let began = Instant::now();
    request(stdin, 3, "workspace/diagnostic", pull.clone())?;
    let arrived = wait_for_all(stdin, messages, session.start, &[3])?;
    let first_pull = arrived[0].1.duration_since(began);

    // Two more pulls, unmeasured: the catalogs the server generates for the
    // workspace's own configuration arrive after the first one and make the
    // next analyse every file again, once, at start-up. The steady state
    // is what the user spends the day in.
    for settle in 0..SETTLE_PULLS {
        request(stdin, 4 + settle, "workspace/diagnostic", pull.clone())?;
        wait_for_all(stdin, messages, session.start, &[4 + settle])?;
    }

    let mut worst = Duration::ZERO;
    let mut pulls = Vec::new();
    for cycle in 0..EDITOR_CYCLES {
        let (pull_id, completion_id, document_id) =
            (10 + 3 * cycle, 11 + 3 * cycle, 12 + 3 * cycle);
        if typing {
            // A keystroke, then the pull of the document it changed.
            let text = if cycle % 2 == 0 {
                format!("{}\n# typed\n", session.text)
            } else {
                session.text.clone()
            };
            write_message(
                stdin,
                &json!({
                    "jsonrpc": "2.0", "method": "textDocument/didChange",
                    "params": {
                        "textDocument": { "uri": session.uri, "version": 2 + cycle },
                        "contentChanges": [{ "text": text }]
                    }
                }),
            )?;
            request(
                stdin,
                document_id,
                "textDocument/diagnostic",
                json!({ "textDocument": { "uri": session.uri } }),
            )?;
        }
        let pull_sent = Instant::now();
        request(stdin, pull_id, "workspace/diagnostic", pull.clone())?;
        // The server has the pull by now, as it has two seconds after the
        // client's last answer.
        std::thread::sleep(Duration::from_millis(2));
        let completion_sent = Instant::now();
        request(
            stdin,
            completion_id,
            "textDocument/completion",
            json!({
                "textDocument": { "uri": session.uri },
                "position": { "line": 1, "character": 0 },
                "context": { "triggerKind": 1 }
            }),
        )?;
        let mut waiting = vec![pull_id, completion_id];
        if typing {
            waiting.push(document_id);
        }
        for (id, at) in wait_for_all(stdin, messages, session.start, &waiting)? {
            if id == completion_id {
                worst = worst.max(at.duration_since(completion_sent));
            } else if id == pull_id {
                pulls.push(at.duration_since(pull_sent));
            }
        }
    }
    pulls.sort();
    let repeat_pull = pulls.get(pulls.len() / 2).copied().unwrap_or_default();

    write_message(
        stdin,
        &json!({ "jsonrpc": "2.0", "id": 2_000_000, "method": "shutdown" }),
    )?;
    wait_for(stdin, messages, session.start, |m| {
        m.get("id") == Some(&json!(2_000_000)) && m.get("method").is_none()
    })?;
    write_message(stdin, &json!({ "jsonrpc": "2.0", "method": "exit" }))?;
    Ok((worst, first_pull, repeat_pull))
}

/// Reads messages until a response to each of `ids` arrived, answering the
/// server's requests with `null` on the way; each id with the instant its
/// response was read.
fn wait_for_all(
    stdin: &mut ChildStdin,
    messages: &mpsc::Receiver<Result<Option<Value>>>,
    start: Instant,
    ids: &[i64],
) -> Result<Vec<(i64, Instant)>> {
    let mut left: Vec<i64> = ids.to_vec();
    let mut arrived = Vec::with_capacity(ids.len());
    while !left.is_empty() {
        let remaining = TIMEOUT
            .checked_sub(start.elapsed())
            .context("the language server did not answer in time")?;
        let message = match messages.recv_timeout(remaining) {
            Ok(message) => message?,
            Err(_) => bail!("the language server did not answer within {TIMEOUT:?}"),
        };
        let Some(message) = message else {
            bail!("the language server closed its output");
        };
        let at = Instant::now();
        if message.get("method").is_none()
            && let Some(id) = message.get("id").and_then(Value::as_i64)
            && let Some(index) = left.iter().position(|wanted| *wanted == id)
        {
            if let Some(error) = message.get("error") {
                bail!("the language server answered {id} with an error: {error}");
            }
            left.swap_remove(index);
            arrived.push((id, at));
        } else if let (Some(id), Some(_)) = (message.get("id"), message.get("method")) {
            write_message(
                stdin,
                &json!({ "jsonrpc": "2.0", "id": id, "result": null }),
            )?;
        }
    }
    Ok(arrived)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A language server in `sh` that answers just enough: `initialize`, the
    /// first diagnostics for the opened document, `shutdown` and `exit`.
    /// `{prelude}` runs first (a `dd` that peaks at a known size, or
    /// nothing); the shell and its `dd`, `tr` and `sed` children otherwise
    /// peak far below this test process.
    #[cfg(target_os = "linux")]
    const STUB_SERVER: &str = r#"#!/bin/sh
{prelude}
send() { printf 'Content-Length: %d\r\n\r\n%s' "${#1}" "$1"; }
while :; do
  len=
  while IFS= read -r line; do
    line=$(printf '%s' "$line" | tr -d '\r')
    [ -z "$line" ] && break
    case $line in Content-Length:*) len=${line#Content-Length: } ;; esac
  done
  [ -z "$len" ] && exit 0
  body=$(dd bs=1 count="$len" 2>/dev/null)
  case $body in
    *'"method":"initialize"'*) send '{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}' ;;
    *'"method":"textDocument/didOpen"'*)
      uri=$(printf '%s' "$body" | sed 's/.*"uri":"\([^"]*\)".*/\1/')
      send "{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\",\"params\":{\"uri\":\"$uri\",\"diagnostics\":[]}}" ;;
    *'"method":"shutdown"'*) send '{"jsonrpc":"2.0","id":2,"result":null}' ;;
    *'"method":"exit"'*) exit 0 ;;
  esac
done
"#;

    /// Runs the stub server (with `prelude`) on a one-rule workspace.
    #[cfg(target_os = "linux")]
    fn stub_session(
        name: &str,
        prelude: &str,
        before_spawn: impl FnOnce(),
    ) -> Result<FirstDiagnostics> {
        let temp = tempfile::Builder::new()
            .prefix(&format!("xtask-bench-lsp-{name}-"))
            .tempdir()
            .unwrap();
        let dir = temp.path().to_path_buf();
        let source = dir.join("source");
        std::fs::create_dir_all(source.join("objects/rules")).unwrap();
        std::fs::write(source.join("objects/rules/a.yaml"), "name: a\n").unwrap();
        let server = dir.join("server");
        crate::script::write_executable(&server, &STUB_SERVER.replace("{prelude}", prelude))
            .unwrap();
        let run = RunDir::prepare(&dir.join("run"), Some(&source)).unwrap();
        first_diagnostics_with(
            &server,
            &[],
            &run,
            Path::new("objects/rules/a.yaml"),
            None,
            before_spawn,
        )
    }

    // The floor reads /proc (VmHWM, clear_refs): Linux only.
    #[cfg(target_os = "linux")]
    #[test]
    fn memory_xtask_touches_after_the_reset_is_part_of_the_lsp_floor() {
        if !crate::bench::measured_alone(
            module_path!(),
            "memory_xtask_touches_after_the_reset_is_part_of_the_lsp_floor",
        ) {
            return;
        }
        // No ballast: 16 MiB touched between the reset and the spawn is in
        // the floor the server inherits, so the stub, which completes the
        // session, is refused. A floor read before that window would let it
        // pass for a server that peaks above xtask.
        let mut late = Vec::new();
        let error = stub_session("late", "", || {
            late = vec![1u8; 16 << 20];
            std::hint::black_box(&late);
        })
        .unwrap_err();
        drop(late);
        assert!(
            format!("{error:#}").contains("does not exceed xtask's own"),
            "{error:#}"
        );
    }

    // The floor reads /proc (VmHWM, clear_refs): Linux only.
    #[cfg(target_os = "linux")]
    #[test]
    fn memory_xtask_freed_before_the_spawn_does_not_raise_the_lsp_floor() {
        if !crate::bench::measured_alone(
            module_path!(),
            "memory_xtask_freed_before_the_spawn_does_not_raise_the_lsp_floor",
        ) {
            return;
        }
        // 256 MiB touched and freed (its own mapping, unmapped on free):
        // without the reset of VmHWM before the spawn, a server peaking at
        // 64 MiB would inherit this process's 256 MiB peak as its floor, and
        // the guard would refuse it.
        let freed = vec![1u8; 256 << 20];
        std::hint::black_box(&freed);
        drop(freed);
        let prelude = "dd if=/dev/zero of=/dev/null bs=64M count=1 2>/dev/null";
        let first = stub_session("freed", prelude, || {}).unwrap();
        let peak = first.sample.peak_rss_bytes;
        assert!(
            (64 << 20..200 << 20).contains(&peak),
            "the server reported {peak} bytes"
        );
        assert_eq!(first.diagnostics, 0);
    }

    #[test]
    fn a_message_round_trips_through_its_framing() {
        let mut buffer = Vec::new();
        write_message(
            &mut buffer,
            &json!({ "jsonrpc": "2.0", "id": 1, "result": "é" }),
        )
        .unwrap();
        let text = String::from_utf8(buffer.clone()).unwrap();
        let (header, body) = text.split_once("\r\n\r\n").unwrap();
        assert_eq!(header, format!("Content-Length: {}", body.len()));
        assert!(body.contains('é'), "{body}");
        let mut reader = std::io::Cursor::new(buffer);
        let back = read_message(&mut reader).unwrap().unwrap();
        assert_eq!(back["result"], "é");
        assert!(read_message(&mut reader).unwrap().is_none());
    }

    #[test]
    fn a_header_without_a_length_is_an_error() {
        let mut reader = std::io::Cursor::new(b"Content-Type: x\r\n\r\n{}".to_vec());
        assert!(read_message(&mut reader).is_err());
    }

    #[test]
    fn file_uris_encode_spaces_and_keep_slashes() {
        assert_eq!(
            file_uri(Path::new("/tmp/a b/rule-1.yaml")),
            "file:///tmp/a%20b/rule-1.yaml"
        );
    }
}
