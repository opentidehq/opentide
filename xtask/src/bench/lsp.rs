//! The language server's first diagnostics: the time from spawning the
//! server to the first `textDocument/publishDiagnostics` for a rule it was
//! asked to open in the heavy workspace, as an editor sees it on start-up.
//!
//! The client sends `initialize` (the workspace as `rootUri` and its one
//! workspace folder, so the server indexes all of it), `initialized` and
//! `textDocument/didOpen`, answers any request the server makes with `null`,
//! and stops the clock at the first diagnostics for the opened document. It
//! then shuts the server down (`shutdown`, `exit`) and reaps it with
//! `wait4(2)` for its peak RSS. A server that does not answer within the
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

    let start = Instant::now();
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {}", program.display()))?;
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
    let (peak_rss_bytes, exit_code) = measure::reap(child)?;
    let _ = reader.join();
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
