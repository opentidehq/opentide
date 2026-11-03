//! The protocol loop (#185 P1): frames read and written with `lsp-server`,
//! the LSP lifecycle, and batches of the messages that are ready.
//!
//! A batch is every message the client has sent that the server has not
//! handled yet. Its notifications apply in order; a request the batch also
//! cancels is answered `RequestCanceled` (-32800), and one for a document the
//! batch edits again later is answered `ContentModified` (-32801) when its
//! result describes the whole document (semantic tokens, code actions, inlay
//! hints, pulled diagnostics). Diagnostics are published once per batch, for
//! each document it changed, so twenty queued keystrokes cost one analysis.
//!
//! Two sources feed the loop. [`Threaded`] reads on its own thread, so the
//! messages that arrive while a request is handled form the next batch: the
//! `opentide-lsp` binary and `opentide lsp start` use it. [`Direct`] reads on
//! the caller's thread and batches only the frames already buffered: the
//! library's [`serve`](crate::serve) and wasip1, which has no threads.

use crate::session::Session;
use lsp_server::{ErrorCode, Message, Notification, Request, RequestId, Response};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read, Write};

/// One frame from the client.
pub(crate) enum Frame {
    Message(Message),
    /// A frame whose body is not a message. It is answered with the id it
    /// names, if it names a valid one, else `id: null`.
    Invalid {
        id: Value,
        code: i32,
        message: String,
    },
    /// A body that is not a message but answers nothing (a response with
    /// `id: null`): logged, never answered.
    Skipped(String),
}

/// Read one frame; `Ok(None)` at the end of input. A body that is not a
/// message is a [`Frame::Invalid`], and the next frame can still be read; a
/// broken header ends the session, since nothing after it can be framed.
pub(crate) fn read_frame(reader: &mut dyn BufRead) -> io::Result<Option<Frame>> {
    let mut recording = Recording {
        inner: reader,
        seen: Vec::new(),
    };
    match Message::read(&mut recording) {
        // `lsp-server` reads `"id": null` as a notification; it is a request
        // whose id is not valid, and is answered with `id: null`.
        Ok(Some(Message::Notification(n))) if recording.names_an_id() => Ok(Some(Frame::Invalid {
            id: Value::Null,
            code: ErrorCode::InvalidRequest as i32,
            message: format!(
                "invalid request: `id` of {} must be an integer or a string",
                n.method
            ),
        })),
        Ok(Some(message)) => Ok(Some(Frame::Message(message))),
        Ok(None) => Ok(None),
        Err(err) if err.kind() == io::ErrorKind::InvalidData => match recording.body() {
            Some(body) if !body.is_empty() => Ok(Some(classify(body))),
            _ => Err(err),
        },
        Err(err) => Err(err),
    }
}

/// Why a framed body is not a message: not JSON (-32700), or JSON that is
/// not a request, response or notification (-32600). A batch is one of the
/// latter: LSP has none.
fn classify(body: &[u8]) -> Frame {
    let value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(err) => {
            return Frame::Invalid {
                id: Value::Null,
                code: ErrorCode::ParseError as i32,
                message: format!("parse error: {err}"),
            };
        }
    };
    let (id, message) = match &value {
        Value::Array(_) => (
            Value::Null,
            "invalid request: a batch is not an LSP message".to_string(),
        ),
        Value::Object(map)
            if !map.contains_key("method")
                && (map.contains_key("result") || map.contains_key("error")) =>
        {
            return Frame::Skipped("a response with an id the server never sent".to_string());
        }
        Value::Object(map) => {
            let id = map
                .get("id")
                .filter(|id| id.is_string() || id.is_i64() || id.is_u64())
                .cloned()
                .unwrap_or(Value::Null);
            let why = match map.get("id") {
                Some(Value::Null) => "`id` must be an integer or a string",
                _ => "not a request, response or notification",
            };
            (id, format!("invalid request: {why}"))
        }
        _ => (
            Value::Null,
            "invalid request: not a JSON-RPC object".to_string(),
        ),
    };
    Frame::Invalid {
        id,
        code: ErrorCode::InvalidRequest as i32,
        message,
    }
}

/// A reader that keeps what it handed out, so a frame `lsp-server` could not
/// parse can still be answered from its body.
struct Recording<'a> {
    inner: &'a mut dyn BufRead,
    seen: Vec<u8>,
}

impl Recording<'_> {
    /// The body of the frame read, after the blank line ending its header.
    fn body(&self) -> Option<&[u8]> {
        let end = self.seen.windows(4).position(|w| w == b"\r\n\r\n")?;
        Some(&self.seen[end + 4..])
    }
}

impl Recording<'_> {
    /// Whether the body has a top-level `id` member. Cheap for the usual
    /// notification, which never spells `"id"` at all.
    fn names_an_id(&self) -> bool {
        let Some(body) = self.body() else {
            return false;
        };
        if !body.windows(4).any(|w| w == b"\"id\"") {
            return false;
        }
        serde_json::from_slice::<Value>(body)
            .ok()
            .is_some_and(|v| v.get("id").is_some())
    }
}

impl Read for Recording<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl BufRead for Recording<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        // The buffer `fill_buf` returned is still there: no read happens.
        if let Ok(buf) = self.inner.fill_buf() {
            let n = amt.min(buf.len());
            self.seen.extend_from_slice(&buf[..n]);
        }
        self.inner.consume(amt);
    }
}

/// Where the loop's batches come from.
pub(crate) trait Source {
    /// The next batch, never empty; `None` at the end of input.
    fn next_batch(&mut self) -> io::Result<Option<Vec<Frame>>>;
}

/// Frames read on the caller's thread. A batch is one frame and every
/// further frame already in the buffer: reading never waits for a message
/// that has not started to arrive.
pub(crate) struct Direct<R: Read> {
    reader: BufReader<R>,
}

impl<R: Read> Direct<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
        }
    }
}

impl<R: Read> Source for Direct<R> {
    fn next_batch(&mut self) -> io::Result<Option<Vec<Frame>>> {
        let Some(first) = read_frame(&mut self.reader)? else {
            return Ok(None);
        };
        let mut batch = vec![first];
        while !self.reader.buffer().is_empty() {
            match read_frame(&mut self.reader)? {
                Some(frame) => batch.push(frame),
                None => break,
            }
        }
        Ok(Some(batch))
    }
}

/// Frames read on a thread of their own, so the next batch is everything
/// that arrived while the last one was handled.
#[cfg(not(target_os = "wasi"))]
pub(crate) struct Threaded {
    frames: std::sync::mpsc::Receiver<io::Result<Option<Frame>>>,
    /// What ended the input, kept until the batch before it is handled.
    end: Option<io::Result<()>>,
}

#[cfg(not(target_os = "wasi"))]
impl Threaded {
    /// Read the stream `open` returns on a new thread. The thread ends at
    /// the end of input or when the loop is gone.
    pub(crate) fn spawn<R, F>(open: F) -> io::Result<Self>
    where
        R: BufRead,
        F: FnOnce() -> R + Send + 'static,
    {
        let (sender, frames) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("opentide-lsp-reader".into())
            .spawn(move || {
                let mut reader = open();
                loop {
                    let frame = read_frame(&mut reader);
                    let last = !matches!(frame, Ok(Some(_)));
                    if sender.send(frame).is_err() || last {
                        return;
                    }
                }
            })?;
        Ok(Self { frames, end: None })
    }
}

#[cfg(not(target_os = "wasi"))]
impl Source for Threaded {
    fn next_batch(&mut self) -> io::Result<Option<Vec<Frame>>> {
        if let Some(end) = self.end.take() {
            return end.map(|()| None);
        }
        let first = match self.frames.recv() {
            Ok(frame) => frame?,
            Err(_) => None,
        };
        let Some(first) = first else {
            return Ok(None);
        };
        let mut batch = vec![first];
        while let Ok(next) = self.frames.try_recv() {
            match next {
                Ok(Some(frame)) => batch.push(frame),
                Ok(None) => {
                    self.end = Some(Ok(()));
                    break;
                }
                Err(err) => {
                    self.end = Some(Err(err));
                    break;
                }
            }
        }
        Ok(Some(batch))
    }
}

/// Where a session is in the LSP lifecycle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Lifecycle {
    Uninitialized,
    Running,
    ShuttingDown,
}

/// Requests whose result describes a whole document as it is: answered
/// `ContentModified` when a later message in the batch edits that document.
const DOCUMENT_STATE: &[&str] = &[
    "textDocument/semanticTokens/full",
    "textDocument/codeAction",
    "textDocument/inlayHint",
    "textDocument/diagnostic",
    "textDocument/codeLens",
    "textDocument/documentLink",
];

/// Serve one client until it sends `exit` or the input ends. Whether the
/// session ended cleanly: `exit` (or the end of input) after `shutdown`.
pub(crate) fn run(
    source: &mut dyn Source,
    writer: &mut dyn Write,
    session: &mut Session,
) -> anyhow::Result<bool> {
    let mut driver = Driver::default();
    while let Some(batch) = source.next_batch()? {
        if let Some(clean) = driver.batch(session, writer, batch)? {
            return Ok(clean);
        }
    }
    Ok(driver.state == Lifecycle::ShuttingDown)
}

/// The loop's state between batches: where the session is in the
/// lifecycle. [`run`] feeds it batches from a [`Source`];
/// [`MessageSession`](crate::MessageSession) feeds it one message at a time.
pub(crate) struct Driver {
    pub(crate) state: Lifecycle,
}

impl Default for Driver {
    fn default() -> Self {
        Self {
            state: Lifecycle::Uninitialized,
        }
    }
}

impl Driver {
    /// Handle one batch and write what it answers and publishes. `Some`
    /// once the client sent `exit`, with whether it shut the server down
    /// first; nothing after `exit` is handled.
    pub(crate) fn batch(
        &mut self,
        session: &mut Session,
        writer: &mut dyn Write,
        batch: Vec<Frame>,
    ) -> io::Result<Option<bool>> {
        session.begin_batch();
        let cancelled: HashSet<RequestId> = batch.iter().filter_map(cancelled_id).collect();
        // The documents a frame at or after each index edits.
        let mut edited_after: Vec<HashSet<String>> = vec![HashSet::new(); batch.len() + 1];
        for (i, frame) in batch.iter().enumerate().rev() {
            let mut edited = edited_after[i + 1].clone();
            if let Some(uri) = edited_uri(frame) {
                edited.insert(uri);
            }
            edited_after[i] = edited;
        }
        for (i, frame) in batch.into_iter().enumerate() {
            let message = match frame {
                Frame::Invalid { id, code, message } => {
                    eprintln!("opentide-lsp: {message}");
                    write_raw(
                        writer,
                        &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
                    )?;
                    continue;
                }
                Frame::Skipped(why) => {
                    eprintln!("opentide-lsp: ignoring {why}");
                    continue;
                }
                Frame::Message(message) => message,
            };
            match message {
                // A response to a request the server sent.
                Message::Response(response) => session.response(response),
                Message::Notification(notification) => {
                    if notification.method == "exit" {
                        flush(session, writer, self.state)?;
                        return Ok(Some(self.state == Lifecycle::ShuttingDown));
                    }
                    // Dropped before `initialize` and after `shutdown`; a
                    // cancellation is read with its batch.
                    if self.state == Lifecycle::Running && notification.method != "$/cancelRequest"
                    {
                        handle_notification(session, notification);
                    }
                }
                Message::Request(request) => {
                    let staled_by = &edited_after[i + 1];
                    let response =
                        respond(session, &mut self.state, request, &cancelled, staled_by);
                    // What the handler queued (a publish before `shutdown`)
                    // goes first.
                    write_outbox(session, writer)?;
                    write(writer, &Message::Response(response))?;
                }
            }
            write_outbox(session, writer)?;
        }
        flush(session, writer, self.state)?;
        Ok(None)
    }
}

/// One message's JSON text, without its `Content-Length` header, read as
/// [`read_frame`] reads a framed one: the same answers for a body that is
/// not a message.
pub(crate) fn frame_of(text: &str) -> Frame {
    let mut framed = format!("Content-Length: {}\r\n\r\n", text.len()).into_bytes();
    framed.extend_from_slice(text.as_bytes());
    match read_frame(&mut io::Cursor::new(framed)) {
        Ok(Some(frame)) => frame,
        _ => classify(text.as_bytes()),
    }
}

/// The bodies of the frames written into `bytes`, in order: what a host
/// with no stdio posts, one message at a time.
pub(crate) fn frame_bodies(mut bytes: &[u8]) -> Vec<String> {
    let mut bodies = Vec::new();
    while let Some(sep) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        let length = std::str::from_utf8(&bytes[..sep]).ok().and_then(|header| {
            header.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        });
        let start = sep + 4;
        let Some(body) = length.and_then(|length| bytes.get(start..start + length)) else {
            break;
        };
        bodies.push(String::from_utf8_lossy(body).into_owned());
        bytes = &bytes[start + body.len()..];
    }
    bodies
}

/// The answer to one request, whatever the lifecycle and the batch say.
fn respond(
    session: &mut Session,
    state: &mut Lifecycle,
    request: Request,
    cancelled: &HashSet<RequestId>,
    staled_by: &HashSet<String>,
) -> Response {
    let refusal = match (*state, request.method.as_str()) {
        (Lifecycle::Uninitialized, "initialize") => None,
        (Lifecycle::Uninitialized, _) => Some((
            ErrorCode::ServerNotInitialized,
            "the server is not initialized",
        )),
        (Lifecycle::Running, "initialize") => Some((
            ErrorCode::InvalidRequest,
            "the server is already initialized",
        )),
        (Lifecycle::Running, _) => None,
        (Lifecycle::ShuttingDown, _) => {
            Some((ErrorCode::InvalidRequest, "the server is shutting down"))
        }
    };
    if let Some((code, message)) = refusal {
        return Response::new_err(request.id, code as i32, message.to_string());
    }
    if cancelled.contains(&request.id) {
        return Response::new_err(
            request.id,
            ErrorCode::RequestCanceled as i32,
            "the request was cancelled".to_string(),
        );
    }
    if DOCUMENT_STATE.contains(&request.method.as_str())
        && document_uri(&request.params).is_some_and(|uri| staled_by.contains(&uri))
    {
        return Response::new_err(
            request.id,
            ErrorCode::ContentModified as i32,
            "the document changed".to_string(),
        );
    }
    if request.method == "shutdown" {
        // What the edits before it changed is published before the reply;
        // nothing is after it.
        session.flush_publishes();
    }
    let method = request.method.clone();
    let id = request.id.clone();
    let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::handlers::request(session, request)
    }));
    let response = match handled {
        Ok(response) => response,
        Err(panic) => {
            let what = panic_text(&panic);
            eprintln!("opentide-lsp: handling {method:?} failed: {what}");
            Response::new_err(
                id,
                ErrorCode::InternalError as i32,
                format!("internal error: {what}"),
            )
        }
    };
    if response.response_result.is_ok() {
        match method.as_str() {
            "initialize" => *state = Lifecycle::Running,
            "shutdown" => *state = Lifecycle::ShuttingDown,
            _ => {}
        }
    }
    response
}

fn handle_notification(session: &mut Session, notification: Notification) {
    let method = notification.method.clone();
    let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::handlers::notification(session, notification)
    }));
    if let Err(panic) = handled {
        eprintln!(
            "opentide-lsp: handling {method:?} failed: {}",
            panic_text(&panic)
        );
    }
}

fn panic_text(panic: &Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "a panic".to_string())
}

/// The id a `$/cancelRequest` in the batch cancels.
fn cancelled_id(frame: &Frame) -> Option<RequestId> {
    let Frame::Message(Message::Notification(n)) = frame else {
        return None;
    };
    if n.method != "$/cancelRequest" {
        return None;
    }
    match n.params.get("id")? {
        Value::Number(n) => Some(RequestId::from(i32::try_from(n.as_i64()?).ok()?)),
        Value::String(s) => Some(RequestId::from(s.clone())),
        _ => None,
    }
}

/// The document a `didChange` edits.
fn edited_uri(frame: &Frame) -> Option<String> {
    let Frame::Message(Message::Notification(n)) = frame else {
        return None;
    };
    (n.method == "textDocument/didChange")
        .then(|| document_uri(&n.params))
        .flatten()
}

fn document_uri(params: &Value) -> Option<String> {
    Some(
        params
            .get("textDocument")?
            .get("uri")?
            .as_str()?
            .to_string(),
    )
}

/// Publish what the batch changed (nothing once the server is shut down),
/// then write what is queued.
fn flush(session: &mut Session, writer: &mut dyn Write, state: Lifecycle) -> io::Result<()> {
    if state == Lifecycle::Running {
        session.flush_publishes();
    } else {
        session.discard_publishes();
    }
    write_outbox(session, writer)
}

fn write_outbox(session: &mut Session, writer: &mut dyn Write) -> io::Result<()> {
    for message in session.take_outbox() {
        write(writer, &message)?;
    }
    Ok(())
}

pub(crate) fn write(writer: &mut dyn Write, message: &Message) -> io::Result<()> {
    let mut buffer = Vec::new();
    message.clone().write(&mut buffer)?;
    writer.write_all(&buffer)?;
    writer.flush()
}

/// A message `lsp-server` cannot represent: an error answered with
/// `id: null`.
fn write_raw(writer: &mut dyn Write, body: &Value) -> io::Result<()> {
    let text = serde_json::to_string(body)?;
    write!(writer, "Content-Length: {}\r\n\r\n{text}", text.len())?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(body: &str) -> Vec<u8> {
        format!("Content-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    fn invalid(frame: Frame) -> (Value, i32) {
        match frame {
            Frame::Invalid { id, code, .. } => (id, code),
            Frame::Skipped(why) => panic!("skipped: {why}"),
            Frame::Message(m) => panic!("a message: {m:?}"),
        }
    }

    #[test]
    fn bodies_that_are_not_messages_are_classified_and_reading_goes_on() {
        let mut input = framed("{not json");
        input.extend(framed(r#"[{"jsonrpc":"2.0","id":1,"method":"shutdown"}]"#));
        input.extend(framed(r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#));
        input.extend(framed(r#"{"jsonrpc":"2.0","id":4,"params":{}}"#));
        input.extend(framed(r#"{"id":5,"method":"shutdown"}"#));
        let mut reader = &input[..];
        let next = |reader: &mut &[u8]| read_frame(reader).unwrap().unwrap();
        assert_eq!(invalid(next(&mut reader)), (Value::Null, -32700));
        assert_eq!(invalid(next(&mut reader)), (Value::Null, -32600));
        assert_eq!(invalid(next(&mut reader)), (Value::Null, -32600));
        assert_eq!(invalid(next(&mut reader)), (json!(4), -32600));
        match next(&mut reader) {
            Frame::Message(Message::Request(r)) => assert_eq!(r.method, "shutdown"),
            _ => panic!("the request without `jsonrpc`"),
        }
        assert!(read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn a_broken_header_ends_the_input() {
        let mut reader: &[u8] = b"Content-Length 3\r\n\r\n{}";
        assert!(read_frame(&mut reader).is_err());
        let mut reader: &[u8] = b"X-Other: 1\r\n\r\n";
        assert!(read_frame(&mut reader).is_err());
    }

    #[test]
    fn direct_batches_the_frames_already_buffered() {
        let mut input = framed(r#"{"jsonrpc":"2.0","method":"a"}"#);
        input.extend(framed(r#"{"jsonrpc":"2.0","method":"b"}"#));
        let mut source = Direct::new(&input[..]);
        assert_eq!(source.next_batch().unwrap().unwrap().len(), 2);
        assert!(source.next_batch().unwrap().is_none());
    }

    #[test]
    fn frame_bodies_splits_what_write_wrote() {
        let mut buf = Vec::new();
        write(
            &mut buf,
            &Message::Notification(Notification::new("a".into(), json!("é😀"))),
        )
        .unwrap();
        write_raw(
            &mut buf,
            &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "x" } }),
        )
        .unwrap();
        let bodies = frame_bodies(&buf);
        assert_eq!(bodies.len(), 2);
        let first: Value = serde_json::from_str(&bodies[0]).unwrap();
        assert_eq!(first["params"], "é😀");
        let second: Value = serde_json::from_str(&bodies[1]).unwrap();
        assert_eq!(second["id"], Value::Null);
        assert!(frame_bodies(b"").is_empty());
        // A frame cut short is dropped, never read past.
        assert!(frame_bodies(b"Content-Length: 10\r\n\r\n{}").is_empty());
    }

    #[test]
    fn frame_of_reads_a_body_as_read_frame_does() {
        assert!(matches!(
            frame_of(r#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#),
            Frame::Message(Message::Notification(_))
        ));
        assert_eq!(
            invalid(frame_of("{ not json")).1,
            ErrorCode::ParseError as i32
        );
        let (id, code) = invalid(frame_of(r#"{"jsonrpc":"2.0","id":3}"#));
        assert_eq!((id, code), (json!(3), ErrorCode::InvalidRequest as i32));
        assert!(matches!(frame_of(""), Frame::Invalid { .. }));
    }
}
