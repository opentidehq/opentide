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
