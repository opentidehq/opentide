//! Progress: the step checklist on stderr, and NDJSON progress events.
//!
//! A long command runs its work as steps. In `plain` and `agent` mode each
//! finished step is one line on stderr (`✓ schemas · 7 files · 1.6s ·
//! .opentide/schemas/`); in `human` mode the finished steps stay as aligned
//! rows ([`checklist`]) once the live display is gone; `json`, `mcp` and
//! `--quiet` print none.
//!
//! With `OPENTIDE_PROGRESS=json`, `generate`, a workspace `validate`, `query`
//! across tenants and `deploy --dry-run` also write one JSON object per line
//! on stderr as they go (`docs/cli/json-output.md`; vscode-extension
//! `CONTRACTS.md`, plan §3 invariant 4):
//!
//! ```text
//! {"event":"progress","step":"schemas","done":3,"total":6}
//! {"event":"tenant","platform":"sentinel","tenant":"prod","status":"ok","rows":120,"elapsed_ms":1800}
//! ```

use super::glyphs;
use super::text::{Colour, Style, Text};
use crate::env::Env;
use crate::json::Json;
use std::io::Write;
use std::sync::{Arc, Mutex};

/// The environment variable that turns the events on, with the value [`JSON_VALUE`].
pub const PROGRESS_ENV: &str = "OPENTIDE_PROGRESS";
/// The value of [`PROGRESS_ENV`] that writes events on stderr.
pub const JSON_VALUE: &str = "json";

/// `1 file`, `7 files`, `0 rules`; `plural_noun` for an irregular one.
pub fn plural(count: usize, noun: &str, plural_noun: Option<&str>) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        match plural_noun {
            Some(plural) => format!("{count} {plural}"),
            None => format!("{count} {noun}s"),
        }
    }
}

/// `0.3s`, `12.4s`, `2m05s`.
pub fn seconds_text(seconds: f64) -> String {
    if seconds < 60.0 {
        return format!("{seconds:.1}s");
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a run's seconds: positive, and far below u64::MAX"
    )]
    let whole = seconds.round_ties_even() as u64;
    format!("{}m{:02}s", whole / 60, whole % 60)
}

/// Where a step stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepStatus {
    /// Still going (a step cut short shows as failed).
    Running,
    /// Done.
    Ok,
    /// Failed.
    Failed,
    /// Not run.
    Skipped,
}

/// One unit of work and what it produced.
#[derive(Clone, Debug)]
pub struct Step {
    /// Its name: `schemas`.
    pub name: String,
    /// What it produced, in `unit`s; `None` when it counts nothing.
    pub count: Option<usize>,
    /// What it counts: `file`.
    pub unit: String,
    /// Replaces the count where a step has more to say (`2 deployed, 1 failed`).
    pub outcome: Option<String>,
    /// Where the output went (`.opentide/schemas/`).
    pub place: Option<String>,
    /// The reason a skipped step did not run.
    pub detail: String,
    /// Where it stands.
    pub status: StepStatus,
    /// How long it took.
    pub seconds: f64,
}

impl Step {
    /// A running step called `name`, counting files.
    pub fn new(name: &str) -> Step {
        Step {
            name: name.to_owned(),
            count: None,
            unit: "file".to_owned(),
            outcome: None,
            place: None,
            detail: String::new(),
            status: StepStatus::Running,
            seconds: 0.0,
        }
    }

    /// The parts a finished step prints after its name, in order.
    pub fn facts(&self) -> Vec<String> {
        let mut parts = Vec::new();
        if let Some(outcome) = self.outcome.as_ref().filter(|outcome| !outcome.is_empty()) {
            parts.push(outcome.clone());
        } else if let Some(count) = self.count {
            parts.push(plural(count, &self.unit, None));
        }
        if self.status == StepStatus::Skipped && !self.detail.is_empty() {
            parts.push(self.detail.clone());
        }
        if self.status != StepStatus::Skipped {
            parts.push(seconds_text(self.seconds));
        }
        if let Some(place) = self.place.as_ref().filter(|place| !place.is_empty()) {
            parts.push(place.clone());
        }
        parts
    }

    /// Its glyph and the glyph's style; a running step shows as failed.
    fn mark(&self) -> Text {
        let (glyph, style) = match self.status {
            StepStatus::Ok => (glyphs::OK, "bold green"),
            StepStatus::Failed | StepStatus::Running => (glyphs::FAILED, "bold red"),
            StepStatus::Skipped => (glyphs::DISABLE, "dim"),
        };
        Text::styled(glyph, &Style::new(style))
    }
}

/// `✓ schemas · 7 files · 1.6s · .opentide/schemas/`, a finished step in `plain` and `agent`.
pub fn step_line(step: &Step) -> Text {
    let mut line = step.mark();
    line.push_str(" ");
    line.push_str(&step.name);
    let dim = Style::new("dim");
    for part in step.facts() {
        line.append(&format!(" {} ", glyphs::SEPARATOR), &dim);
        line.push_str(&part);
    }
    line
}

/// The finished steps as `human` mode leaves them: one row each, two in from
/// the edge, columns aligned with no trailing blanks, a count's number right
/// under the one above, a row wider than the terminal cut with `…`.
pub fn checklist(steps: &[Step], width: usize, colour: Colour) -> String {
    let digits = steps
        .iter()
        .filter_map(|step| step.count)
        .map(|count| count.to_string().len())
        .max()
        .unwrap_or(0);
    let dim = Style::new("dim");
    let rows: Vec<Vec<Text>> = steps
        .iter()
        .map(|step| {
            if step.status == StepStatus::Skipped {
                return vec![
                    step.mark(),
                    Text::styled(&step.name, &dim),
                    Text::default(),
                    Text::default(),
                    Text::styled(&step.detail, &dim),
                ];
            }
            let mut count = step.outcome.clone().unwrap_or_default();
            if count.is_empty()
                && let Some(number) = step.count
            {
                count = " ".repeat(digits.saturating_sub(number.to_string().len()))
                    + &plural(number, &step.unit, None);
            }
            vec![
                step.mark(),
                Text::styled(&step.name, &Style::new("bold")),
                Text::styled(&count, &dim),
                Text::styled(&seconds_text(step.seconds), &dim),
                Text::styled(step.place.as_deref().unwrap_or_default(), &dim),
            ]
        })
        .collect();
    let mut out = String::new();
    for line in columns(&rows, 2, 2, &[3]) {
        let line = crop(&line, width);
        out.push_str(&line.render(colour, false));
        out.push('\n');
    }
    out
}

/// `rows` as aligned columns, one line each, trailing blanks trimmed; the
/// columns in `right` right-aligned. A column empty on every row takes no room.
pub fn columns(rows: &[Vec<Text>], gap: usize, indent: usize, right: &[usize]) -> Vec<Text> {
    let count = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..count)
        .map(|index| {
            rows.iter()
                .filter_map(|row| row.get(index))
                .map(Text::cell_len)
                .max()
                .unwrap_or(0)
        })
        .collect();
    rows.iter()
        .map(|row| {
            let mut line = Text::plain(&" ".repeat(indent));
            let mut pending = String::new();
            for (index, cell) in row.iter().enumerate() {
                let width = widths[index];
                if width == 0 {
                    continue;
                }
                line.push_str(&pending);
                let pad = " ".repeat(width - cell.cell_len());
                if right.contains(&index) {
                    line.push_str(&pad);
                    line.append_text(cell);
                    pending = " ".repeat(gap);
                } else {
                    line.append_text(cell);
                    pending = pad + &" ".repeat(gap);
                }
            }
            line.rstrip();
            line
        })
        .collect()
}

/// `line` in at most `width` cells, ending in `…` when cut.
fn crop(line: &Text, width: usize) -> Text {
    let mut line = line.clone();
    line.truncate_ellipsis(width);
    line
}

/// Receives each event instead of stderr (`opentide serve` forwards them to its client).
pub type EventSink = Arc<dyn Fn(Json) + Send + Sync>;

/// Where events go: a sink, stderr when `OPENTIDE_PROGRESS=json`, or nowhere.
#[derive(Clone)]
pub struct Progress {
    sink: Option<EventSink>,
    stderr: bool,
    lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for Progress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Progress")
            .field("sink", &self.sink.is_some())
            .field("stderr", &self.stderr)
            .finish_non_exhaustive()
    }
}

impl Progress {
    /// Events on stderr when `env` asks for them (`OPENTIDE_PROGRESS=json`, any case).
    pub fn from_env(env: &Env) -> Progress {
        Progress {
            sink: None,
            stderr: env
                .get(PROGRESS_ENV)
                .is_some_and(|value| value.trim().to_lowercase() == JSON_VALUE),
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Events to `sink` and nowhere else.
    pub fn to_sink(sink: EventSink) -> Progress {
        Progress {
            sink: Some(sink),
            stderr: false,
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Whether an event emitted now goes anywhere.
    pub fn enabled(&self) -> bool {
        self.sink.is_some() || self.stderr
    }

    /// Sends `event` to the sink, or writes it as one line on stderr. A closed
    /// stderr is not worth failing the command.
    pub fn emit(&self, event: Json) {
        if let Some(sink) = &self.sink {
            sink(event);
            return;
        }
        if !self.stderr {
            return;
        }
        let line = event_line(&event);
        // One line at a time: steps report from worker threads.
        let _guard = self.lock.lock();
        let mut stderr = std::io::stderr().lock();
        let _ignored = stderr
            .write_all(line.as_bytes())
            .and_then(|()| stderr.flush());
    }

    /// `{"event":"progress","step":…,"done":…,"total":…}`; `total` may be null.
    pub fn progress(&self, step: &str, done: usize, total: Option<usize>) {
        if self.enabled() {
            self.emit(progress_event(step, done, total));
        }
    }

    /// One tenant's outcome in a run across tenants (`opentide query`).
    pub fn tenant(&self, event: &TenantEvent<'_>) {
        if self.enabled() {
            self.emit(event.to_json());
        }
    }
}

/// An event as its NDJSON line: compact, every character past ASCII escaped
/// (`🚀`), so any stderr encoding carries it, then a newline.
pub fn event_line(event: &Json) -> String {
    let compact = crate::json::document_text(event, false);
    let mut out = String::with_capacity(compact.len());
    for ch in compact.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let mut units = [0u16; 2];
            for unit in ch.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

fn count(value: usize) -> Json {
    i64::try_from(value).map_or(Json::UInt(value as u64), Json::Int)
}

/// A `progress` event.
pub fn progress_event(step: &str, done: usize, total: Option<usize>) -> Json {
    Json::object([
        ("event", Json::str("progress")),
        ("step", Json::str(step)),
        ("done", count(done)),
        ("total", total.map_or(Json::Null, count)),
    ])
}

/// A `tenant` event.
#[derive(Clone, Copy, Debug)]
pub struct TenantEvent<'a> {
    /// The platform.
    pub platform: &'a str,
    /// The tenant's name.
    pub tenant: &'a str,
    /// Whether it answered.
    pub ok: bool,
    /// The rows it returned.
    pub rows: usize,
    /// How long it took.
    pub elapsed_ms: u64,
    /// Which query, for a platform whose rule holds several.
    pub label: Option<&'a str>,
}

impl TenantEvent<'_> {
    /// The event.
    pub fn to_json(&self) -> Json {
        let mut members = vec![
            ("event", Json::str("tenant")),
            ("platform", Json::str(self.platform)),
            ("tenant", Json::str(self.tenant)),
            ("status", Json::str(if self.ok { "ok" } else { "failed" })),
            ("rows", count(self.rows)),
            (
                "elapsed_ms",
                i64::try_from(self.elapsed_ms).map_or(Json::UInt(self.elapsed_ms), Json::Int),
            ),
        ];
        if let Some(label) = self.label {
            members.push(("label", Json::str(label)));
        }
        Json::object(members)
    }
}

/// `progress` events for `total` units of one step, at most about 20 of them;
/// the last unit always reports, so a reader sees `done == total`. Thread-safe.
#[derive(Debug)]
pub struct Ticker {
    step: String,
    total: usize,
    every: usize,
    done: Mutex<usize>,
    progress: Progress,
}

impl Ticker {
    /// Events per step, at most (plus the last one).
    pub const BATCHES: usize = 20;

    /// A ticker for `total` units of `step`.
    pub fn new(progress: &Progress, step: &str, total: usize) -> Ticker {
        Ticker {
            step: step.to_owned(),
            total,
            every: (total / Self::BATCHES).max(1),
            done: Mutex::new(0),
            progress: progress.clone(),
        }
    }

    /// `count` more units done.
    pub fn advance(&self, count: usize) {
        if !self.progress.enabled() {
            return;
        }
        let (before, done) = {
            let mut done = self
                .done
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = *done;
            *done += count;
            (before, *done)
        };
        if done >= self.total || done / self.every != before / self.every {
            self.progress.progress(&self.step, done, Some(self.total));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words() {
        assert_eq!(plural(1, "file", None), "1 file");
        assert_eq!(plural(2, "entry", Some("entries")), "2 entries");
        assert_eq!(seconds_text(0.05), "0.1s");
        assert_eq!(seconds_text(125.4), "2m05s");
        assert_eq!(seconds_text(150.5), "2m30s");
    }

    #[test]
    fn events_escape_past_ascii() {
        let event = TenantEvent {
            platform: "sentinel",
            tenant: "prod 🔥",
            ok: false,
            rows: 0,
            elapsed_ms: 12,
            label: None,
        };
        assert_eq!(
            event_line(&event.to_json()),
            "{\"event\":\"tenant\",\"platform\":\"sentinel\",\"tenant\":\"prod \\ud83d\\udd25\",\"status\":\"failed\",\"rows\":0,\"elapsed_ms\":12}\n"
        );
        assert!(!Progress::from_env(&Env::default()).enabled());
        assert!(Progress::from_env(&Env::from_pairs([(PROGRESS_ENV, " JSON ")])).enabled());
    }

    #[test]
    fn checklist_aligns_and_crops() {
        let mut one = Step::new("schemas");
        one.count = Some(7);
        one.status = StepStatus::Ok;
        one.seconds = 1.25;
        one.place = Some(".opentide/schemas/".into());
        let mut two = Step::new("docs");
        two.count = Some(12);
        two.status = StepStatus::Ok;
        let mut three = Step::new("explorer");
        three.status = StepStatus::Skipped;
        three.detail = "no rules".into();
        let text = checklist(&[one, two, three], 80, Colour::None);
        assert_eq!(
            text,
            "  ✓  schemas    7 files  1.2s  .opentide/schemas/\n  ✓  docs      12 files  0.0s\n  -  explorer                  no rules\n"
        );
        let narrow = checklist(&[Step::new("a-very-long-step-name")], 10, Colour::None);
        assert_eq!(narrow, "  ✗  a-ve…\n");
    }
}
