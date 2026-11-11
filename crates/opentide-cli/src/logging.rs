//! Log lines on `tracing`: always on stderr, never on stdout, redacted.
//!
//! Levels as the CLI has always set them: everything from DEBUG with
//! `--debug` (or `OPENTIDE_DEBUG`) in every mode, only ERROR with `--quiet`,
//! WARNING and above otherwise, `--json` and MCP included. A line reads
//! `warning: Tenant targets failed · system: sentinel` (an event name is made
//! readable), with the UTC time in front under `--debug`;
//! `OPENTIDE_LOG_JSON=1` writes one JSON object per line instead. Library
//! crates log through `tracing` and never print: this layer is the one place
//! that writes their events.

use crate::json::{Json, document_text};
use crate::redact::Redactor;
use std::fmt::Write as _;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Where log lines go: the process's stderr, or a test's buffer.
pub type Sink = Arc<Mutex<dyn Write + Send>>;

/// How the run logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// `--debug` or `OPENTIDE_DEBUG`.
    pub debug: bool,
    /// `--quiet`.
    pub quiet: bool,
    /// `OPENTIDE_LOG_JSON=1`.
    pub json_lines: bool,
}

impl Config {
    /// The most verbose level written.
    pub fn level(&self) -> Level {
        if self.debug {
            Level::DEBUG
        } else if self.quiet {
            Level::ERROR
        } else {
            Level::WARN
        }
    }
}

/// The layer that writes the run's log lines.
pub struct LogLayer {
    config: Config,
    sink: Sink,
    redactor: Redactor,
    clock: fn() -> String,
}

impl LogLayer {
    /// A layer writing to `sink`.
    pub fn new(config: Config, sink: Sink, redactor: Redactor, clock: fn() -> String) -> LogLayer {
        LogLayer {
            config,
            sink,
            redactor,
            clock,
        }
    }
}

/// The level's word, as the CLI prints it.
pub fn label(level: Level) -> &'static str {
    match level {
        Level::TRACE | Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warning",
        Level::ERROR => "error",
    }
}

/// `tenant_targets_failed` -> `Tenant targets failed`; prose is left as written.
pub fn readable_event(event: &str) -> String {
    let text = event.trim();
    let slug = !text.is_empty()
        && text.split(['.', '_']).all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
    if !slug {
        return text.to_owned();
    }
    let spaced = text.replace(['.', '_'], " ");
    let mut chars = spaced.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// A field's value, its type kept: a JSON line writes numbers and booleans
/// as JSON numbers and booleans, a text line writes each as `Debug` does.
#[derive(Clone, Debug, PartialEq)]
enum Value {
    Text(String),
    Int(i64),
    UInt(u64),
    Float(f64),
    Bool(bool),
}

impl Value {
    /// The value as a text line writes it.
    fn text(&self) -> String {
        match self {
            Value::Text(text) => text.clone(),
            Value::Int(value) => format!("{value:?}"),
            Value::UInt(value) => format!("{value:?}"),
            Value::Float(value) => format!("{value:?}"),
            Value::Bool(value) => format!("{value:?}"),
        }
    }

    /// The value as a JSON line writes it.
    fn json(&self) -> Json {
        match self {
            Value::Text(text) => Json::str(text),
            Value::Int(value) => Json::Int(*value),
            Value::UInt(value) => Json::UInt(*value),
            Value::Float(value) => Json::Float(*value),
            Value::Bool(value) => Json::Bool(*value),
        }
    }

    /// The value redacted: a typed value a secret matches becomes the
    /// redacted text, so the line never carries the secret as a number.
    fn redacted(self, redactor: &Redactor) -> Value {
        match self {
            Value::Text(text) => Value::Text(redactor.redact(&text)),
            typed => {
                let text = typed.text();
                let redacted = redactor.redact(&text);
                if redacted == text {
                    typed
                } else {
                    Value::Text(redacted)
                }
            }
        }
    }
}

#[derive(Default)]
struct Fields {
    message: String,
    pairs: Vec<(String, Value)>,
}

impl Fields {
    fn push(&mut self, field: &Field, value: Value) {
        if field.name() == "message" {
            self.message = value.text();
        } else {
            self.pairs.push((field.name().to_owned(), value));
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, Value::Text(value.to_owned()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, Value::Int(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, Value::UInt(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push(field, Value::Float(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, Value::Bool(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push(field, Value::Text(format!("{value:?}")));
    }
}

impl LogLayer {
    /// One line for an event: `label: Event · key: value`.
    fn line(&self, level: Level, fields: &Fields) -> String {
        if self.config.json_lines {
            // The event's fields, then the event, its level and its time, in
            // the order structlog's JSON lines have them.
            let mut members: Vec<(String, Json)> = fields
                .pairs
                .iter()
                .map(|(key, value)| (key.clone(), value.json()))
                .collect();
            members.extend([
                ("event".to_owned(), Json::str(&fields.message)),
                ("level".to_owned(), Json::str(label(level))),
                ("timestamp".to_owned(), Json::Str((self.clock)())),
            ]);
            return document_text(&Json::Object(members), false);
        }
        let mut line = String::new();
        if self.config.debug {
            // The time of day: the clock's date-time without its date.
            let clock = (self.clock)();
            let time = clock.rsplit(' ').next().unwrap_or_default();
            let _ = write!(line, "{time} ");
        }
        let _ = write!(
            line,
            "{}: {}",
            label(level),
            readable_event(&fields.message)
        );
        for (key, value) in &fields.pairs {
            let _ = write!(line, " · {key}: {}", value.text());
        }
        line.push('\n');
        line
    }
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        *metadata.level() <= self.config.level()
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = *event.metadata().level();
        if level > self.config.level() {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        // Each value is redacted as it was logged, before the line escapes
        // it (JSON) or a Debug field quoted it: a secret with a `"` or a `\`
        // in it must match as written. The whole line is redacted again for
        // what spans a field and its key (`token=...`).
        fields.message = self.redactor.redact(&fields.message);
        fields.pairs = std::mem::take(&mut fields.pairs)
            .into_iter()
            .map(|(key, value)| (key, value.redacted(&self.redactor)))
            .collect();
        let line = self.redactor.redact(&self.line(level, &fields));
        if let Ok(mut sink) = self.sink.lock() {
            let _ = sink.write_all(line.as_bytes());
            let _ = sink.flush();
        }
    }
}

/// A subscriber with this run's layer.
pub fn subscriber(layer: LogLayer) -> impl Subscriber + Send + Sync {
    use tracing_subscriber::layer::SubscriberExt;
    tracing_subscriber::registry().with(layer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(config: Config, emit: impl FnOnce()) -> String {
        let buffer = Buffer::default();
        let sink: Sink = Arc::new(Mutex::new(buffer.clone()));
        let redactor = Redactor::new(vec!["hunter22".to_owned()], Vec::new());
        let layer = LogLayer::new(config, sink, redactor, || "12:00:00".to_owned());
        tracing::subscriber::with_default(subscriber(layer), emit);
        String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
    }

    fn config(debug: bool, quiet: bool, json_lines: bool) -> Config {
        Config {
            debug,
            quiet,
            json_lines,
        }
    }

    #[test]
    fn framework_logging_levels_per_mode() {
        let emit = || {
            tracing::debug!("engine_loaded");
            tracing::info!("note");
            tracing::warn!(system = "sentinel", "tenant_targets_failed");
            tracing::error!("Disk full");
        };
        assert_eq!(
            capture(config(false, false, false), emit),
            "warning: Tenant targets failed · system: sentinel\nerror: Disk full\n"
        );
        assert_eq!(
            capture(config(false, true, false), emit),
            "error: Disk full\n"
        );
        let debug = capture(config(true, true, false), emit);
        assert!(debug.starts_with("12:00:00 debug: Engine loaded\n12:00:00 info: Note\n"));
        assert_eq!(debug.lines().count(), 4);
    }

    #[test]
    fn framework_logging_json_lines_and_redaction() {
        let text = capture(config(false, false, true), || {
            tracing::warn!(token = "hunter22", count = 3, "proxy_failed");
        });
        assert_eq!(
            text,
            "{\"token\":\"***\",\"count\":3,\"event\":\"proxy_failed\",\"level\":\"warning\",\"timestamp\":\"12:00:00\"}\n"
        );
    }

    #[test]
    fn a_json_line_keeps_each_field_type() {
        let emit = || {
            tracing::warn!(
                objects = 12,
                negative = -4,
                ratio = 0.5,
                whole = 2.0,
                changed = true,
                dry_run = false,
                name = "x",
                path = ?"a/b",
                "indexed"
            );
        };
        assert_eq!(
            capture(config(false, false, true), emit),
            "{\"objects\":12,\"negative\":-4,\"ratio\":0.5,\"whole\":2.0,\"changed\":true,\"dry_run\":false,\"name\":\"x\",\"path\":\"\\\"a/b\\\"\",\"event\":\"indexed\",\"level\":\"warning\",\"timestamp\":\"12:00:00\"}\n"
        );
        // A text line is as it was.
        assert_eq!(
            capture(config(false, false, false), emit),
            "warning: Indexed · objects: 12 · negative: -4 · ratio: 0.5 · whole: 2.0 · changed: true · dry_run: false · name: x · path: \"a/b\"\n"
        );
    }

    #[test]
    fn a_secret_logged_as_a_number_is_redacted_as_text() {
        let run = |json_lines: bool| {
            let buffer = Buffer::default();
            let sink: Sink = Arc::new(Mutex::new(buffer.clone()));
            let redactor = Redactor::new(vec!["987654".to_owned()], Vec::new());
            let layer = LogLayer::new(config(false, false, json_lines), sink, redactor, || {
                "12:00:00".to_owned()
            });
            tracing::subscriber::with_default(subscriber(layer), || {
                tracing::warn!(pin = 987_654, count = 3, "login");
            });
            String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
        };
        assert_eq!(
            run(true),
            "{\"pin\":\"***\",\"count\":3,\"event\":\"login\",\"level\":\"warning\",\"timestamp\":\"12:00:00\"}\n"
        );
        assert_eq!(run(false), "warning: Login · pin: *** · count: 3\n");
    }

    #[test]
    fn a_json_line_carries_the_date_and_a_debug_line_the_time() {
        let run = |config: Config| {
            let buffer = Buffer::default();
            let sink: Sink = Arc::new(Mutex::new(buffer.clone()));
            let layer = LogLayer::new(config, sink, Redactor::new(Vec::new(), Vec::new()), || {
                "2026-11-09 12:00:00".to_owned()
            });
            tracing::subscriber::with_default(subscriber(layer), || {
                tracing::error!(system = "sentinel", "platform_status_missing");
            });
            String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
        };
        assert_eq!(
            run(config(true, false, false)),
            "12:00:00 error: Platform status missing · system: sentinel\n"
        );
        assert_eq!(
            run(config(false, false, true)),
            "{\"system\":\"sentinel\",\"event\":\"platform_status_missing\",\"level\":\"error\",\"timestamp\":\"2026-11-09 12:00:00\"}\n"
        );
    }

    #[test]
    fn framework_logging_readable_events() {
        assert_eq!(readable_event("share.completed"), "Share completed");
        assert_eq!(readable_event("Already prose."), "Already prose.");
        assert_eq!(readable_event(""), "");
        assert_eq!(readable_event("a__b"), "a__b");
        assert_eq!(label(Level::TRACE), "debug");
    }
}
