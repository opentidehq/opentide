//! `tenant` progress events (`OPENTIDE_PROGRESS=json`; vscode-extension
//! `docs/CONTRACTS.md`): one per tenant of a run across tenants, as
//! `opentide.core.progress_events.tenant` writes it:
//!
//! ```json
//! {"event":"tenant","platform":"sentinel","tenant":"prod","status":"ok","rows":120,"elapsed_ms":1800}
//! ```

use std::io::Write;
use std::sync::Mutex;

use serde::Serialize;

/// One tenant's outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TenantEvent {
    /// Always `tenant`.
    pub event: &'static str,
    /// The platform's identifier.
    pub platform: String,
    /// The tenant's name.
    pub tenant: String,
    /// `ok` or `failed`.
    pub status: &'static str,
    /// Rows the tenant returned (0 for a command that returns none).
    pub rows: u64,
    /// Milliseconds the tenant took.
    pub elapsed_ms: u64,
    /// The query's label, for a platform whose rule holds several.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl TenantEvent {
    /// The event of one tenant.
    pub fn new(platform: &str, tenant: &str, ok: bool, rows: u64, elapsed_ms: u64) -> Self {
        Self {
            event: "tenant",
            platform: platform.to_owned(),
            tenant: tenant.to_owned(),
            status: if ok { "ok" } else { "failed" },
            rows,
            elapsed_ms,
            label: None,
        }
    }
}

/// Where events go.
pub trait ProgressSink: Send + Sync {
    /// Receives one event.
    fn emit(&self, event: &TenantEvent);
}

/// Drops every event: progress is off.
#[derive(Debug, Default)]
pub struct Silent;

impl ProgressSink for Silent {
    fn emit(&self, _event: &TenantEvent) {}
}

/// One JSON object per line, ASCII only, on a writer (stderr).
#[derive(Debug)]
pub struct Ndjson<W: Write + Send> {
    out: Mutex<W>,
}

impl<W: Write + Send> Ndjson<W> {
    /// Events written to *out*.
    pub fn new(out: W) -> Self {
        Self {
            out: Mutex::new(out),
        }
    }

    /// The writer back.
    pub fn into_inner(self) -> W {
        self.out
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl<W: Write + Send> ProgressSink for Ndjson<W> {
    fn emit(&self, event: &TenantEvent) {
        let Ok(text) = serde_json::to_string(event) else {
            return;
        };
        let mut line = ascii(&text).into_bytes();
        line.push(b'\n');
        let mut out = self
            .out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A closed stderr is not worth a failure.
        let _ = out.write_all(&line).and_then(|()| out.flush());
    }
}

/// *text* with every character outside ASCII as a `\uXXXX` escape (inside
/// JSON strings, the only place serde_json writes one).
fn ascii(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii() {
            out.push(character);
        } else {
            let mut units = [0u16; 2];
            for unit in character.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}
