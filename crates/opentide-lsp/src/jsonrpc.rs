//! Minimal JSON-RPC 2.0 framing for LSP over stdio (`Content-Length`).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Write};

#[derive(Debug, Deserialize)]
pub struct Incoming {
    /// `"2.0"`. Optional on input: a client that leaves it out still gets
    /// answers.
    #[allow(dead_code)]
    #[serde(default)]
    pub jsonrpc: Option<String>,
    /// `None` when the member is absent (a notification); `Some(Value::Null)`
    /// for `"id": null`, which a reply must echo.
    #[serde(default, deserialize_with = "present")]
    pub id: Option<Value>,
    pub method: Option<String>,
    pub params: Option<Value>,
}

/// A member that is present, `null` included.
fn present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// One frame read from the client.
#[derive(Debug)]
pub enum Frame {
    Message(Incoming),
    /// A frame whose body is not a JSON-RPC message. The frame was consumed,
    /// so the stream is still in step: answer with `code` and go on.
    Invalid {
        code: i32,
        message: String,
    },
}

/// JSON-RPC: the body is not JSON.
pub const PARSE_ERROR: i32 = -32700;
/// JSON-RPC: the body is JSON but not a request, notification or response.
pub const INVALID_REQUEST: i32 = -32600;
/// LSP: a request before `initialize`.
pub const SERVER_NOT_INITIALIZED: i32 = -32002;
/// JSON-RPC: the handler failed.
pub const INTERNAL_ERROR: i32 = -32603;

#[derive(Debug, Serialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct Notification {
    pub jsonrpc: &'static str,
    pub method: String,
    pub params: Value,
}

/// Read one frame. `Ok(None)` at end of input. An I/O error, or a header
/// block without `Content-Length` (the frame's end is unknown), is an error;
/// a body that is not a message is [`Frame::Invalid`].
pub fn read_message(reader: &mut impl BufRead) -> Result<Option<Frame>> {
    let mut content_length = None;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header)?;
        if n == 0 {
            return Ok(None);
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        // Header names are case-insensitive.
        if let Some((name, value)) = header.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = Some(value.trim().parse::<usize>().context("content-length")?);
            }
        }
    }
    let len = content_length.context("missing Content-Length")?;
    let mut buf = vec![0u8; len];
    std::io::Read::read_exact(reader, &mut buf)?;
    let value: Value = match serde_json::from_slice(&buf) {
        Ok(value) => value,
        Err(err) => {
            return Ok(Some(Frame::Invalid {
                code: PARSE_ERROR,
                message: format!("the message is not JSON: {err}"),
            }));
        }
    };
    if !value.is_object() {
        return Ok(Some(Frame::Invalid {
            code: INVALID_REQUEST,
            message: "a message must be a JSON object; batches are not supported".into(),
        }));
    }
    match serde_json::from_value(value) {
        Ok(msg) => Ok(Some(Frame::Message(msg))),
        Err(err) => Ok(Some(Frame::Invalid {
            code: INVALID_REQUEST,
            message: format!("not a JSON-RPC message: {err}"),
        })),
    }
}

pub fn write_message(writer: &mut impl Write, body: &impl Serialize) -> Result<()> {
    let payload = serde_json::to_vec(body)?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn success(id: Option<Value>, result: Value) -> Response {
    Response {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

pub fn failure(id: Option<Value>, code: i32, message: impl Into<String>) -> Response {
    Response {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: message.into(),
        }),
    }
}

pub fn notify(method: impl Into<String>, params: Value) -> Notification {
    Notification {
        jsonrpc: "2.0",
        method: method.into(),
        params,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn message(frame: Frame) -> Incoming {
        match frame {
            Frame::Message(msg) => msg,
            Frame::Invalid { message, .. } => panic!("invalid frame: {message}"),
        }
    }

    fn frame(body: &str) -> Vec<u8> {
        format!("content-length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    /// #185 P0.7: a bad body is answered and the stream stays in step.
    #[test]
    fn a_bad_body_is_an_invalid_frame_and_the_next_one_reads() {
        let mut bytes = frame("{not json");
        bytes.extend(frame("[1, 2]"));
        bytes.extend(frame(r#"{"id": 1, "method": "shutdown"}"#));
        bytes.extend(frame(r#"{"jsonrpc": "2.0", "id": null, "method": "x"}"#));
        let mut reader = Cursor::new(bytes);
        let codes: Vec<i32> = (0..2)
            .map(|_| match read_message(&mut reader).unwrap().unwrap() {
                Frame::Invalid { code, .. } => code,
                Frame::Message(msg) => panic!("{msg:?}"),
            })
            .collect();
        assert_eq!(codes, [PARSE_ERROR, INVALID_REQUEST]);
        // No `jsonrpc` member, lower-case header: still a request.
        let msg = message(read_message(&mut reader).unwrap().unwrap());
        assert_eq!(msg.method.as_deref(), Some("shutdown"));
        assert_eq!(msg.id, Some(serde_json::json!(1)));
        // `"id": null` is kept apart from a missing id.
        let msg = message(read_message(&mut reader).unwrap().unwrap());
        assert_eq!(msg.id, Some(Value::Null));
    }

    fn payload_of(frame: &[u8]) -> &[u8] {
        let sep = frame
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header separator");
        &frame[sep + 4..]
    }

    #[test]
    fn write_then_read_roundtrips_multibyte_params() {
        let note = notify("ping", serde_json::json!("é😀"));
        let mut buf = Vec::new();
        write_message(&mut buf, &note).unwrap();
        let body = payload_of(&buf);
        let header = std::str::from_utf8(&buf[..buf.len() - body.len()]).unwrap();
        let len: usize = header
            .trim_start_matches("Content-Length:")
            .trim()
            .trim_end_matches("\r\n")
            .parse()
            .unwrap();
        assert_eq!(len, body.len());
        assert!(body.windows("é".len()).any(|w| w == "é".as_bytes()));

        let msg = message(read_message(&mut Cursor::new(buf)).unwrap().unwrap());
        assert_eq!(msg.method.as_deref(), Some("ping"));
        assert_eq!(msg.params.unwrap().as_str(), Some("é😀"));
    }

    #[test]
    fn extra_headers_are_ignored() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let frame = format!(
            "Content-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut bytes = frame.into_bytes();
        bytes.extend_from_slice(body);
        let msg = message(read_message(&mut Cursor::new(bytes)).unwrap().unwrap());
        assert_eq!(msg.method.as_deref(), Some("initialize"));
        assert_eq!(msg.id, Some(serde_json::json!(1)));
    }

    #[test]
    fn missing_content_length_is_an_error() {
        let frame = b"Content-Type: application/vscode-jsonrpc\r\n\r\n{}";
        let err = read_message(&mut Cursor::new(&frame[..])).unwrap_err();
        assert!(err.to_string().contains("Content-Length"), "{err}");
    }

    #[test]
    fn eof_before_a_frame_is_none() {
        assert!(read_message(&mut Cursor::new(&b""[..])).unwrap().is_none());
    }

    #[test]
    fn failure_omits_result() {
        let resp = failure(Some(serde_json::json!(4)), -32601, "method not found");
        let mut buf = Vec::new();
        write_message(&mut buf, &resp).unwrap();
        let value: serde_json::Value = serde_json::from_slice(payload_of(&buf)).unwrap();
        assert_eq!(value["id"], 4);
        assert_eq!(value["error"]["code"], -32601);
        assert!(value.get("result").is_none());
    }
}
