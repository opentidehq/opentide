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

    let session = drive(&mut stdin, &messages, &root_uri, &uri, &text, start, inject);
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
    let (elapsed, diagnostics) = outcome.with_context(|| {
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
    Ok(FirstDiagnostics {
        sample: Sample {
            wall_s: elapsed.as_secs_f64(),
            peak_rss_bytes,
        },
        diagnostics,
    })
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
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("xtask-bench-lsp-{name}-{}", std::process::id()));
        let source = dir.join("source");
        std::fs::create_dir_all(source.join("objects/rules")).unwrap();
        std::fs::write(source.join("objects/rules/a.yaml"), "name: a\n").unwrap();
        let server = dir.join("server");
        std::fs::write(&server, STUB_SERVER.replace("{prelude}", prelude)).unwrap();
        std::fs::set_permissions(&server, std::fs::Permissions::from_mode(0o755)).unwrap();
        let run = RunDir::prepare(&dir.join("run"), Some(&source)).unwrap();
        let result = first_diagnostics_with(
            &server,
            &[],
            &run,
            Path::new("objects/rules/a.yaml"),
            None,
            before_spawn,
        );
        std::fs::remove_dir_all(&dir).unwrap();
        result
    }

    // The floor reads /proc (VmHWM, clear_refs): Linux only.
    #[cfg(target_os = "linux")]
    #[test]
    fn memory_xtask_touches_after_the_reset_is_part_of_the_lsp_floor() {
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
