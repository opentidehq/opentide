//! Minimal JSON-RPC 2.0 framing for LSP over stdio (`Content-Length`).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Write};

#[derive(Debug, Deserialize)]
pub struct Incoming {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: Option<String>,
    pub params: Option<Value>,
}

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

pub fn read_message(reader: &mut impl BufRead) -> Result<Option<Incoming>> {
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
        if let Some(v) = header.strip_prefix("Content-Length:") {
            content_length = Some(v.trim().parse::<usize>().context("content-length")?);
        }
    }
    let len = content_length.context("missing Content-Length")?;
    let mut buf = vec![0u8; len];
    std::io::Read::read_exact(reader, &mut buf)?;
    let msg = serde_json::from_slice(&buf)?;
    Ok(Some(msg))
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

        let msg = read_message(&mut Cursor::new(buf)).unwrap().unwrap();
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
        let msg = read_message(&mut Cursor::new(bytes)).unwrap().unwrap();
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
