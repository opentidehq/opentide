//! What differs between two runs of the same command for reasons that are not
//! the implementation's: the workspace each ran in, wall time and the clock.
//! The normaliser rewrites both runs the same way before they are compared,
//! in place and without re-serialising anything, so the byte comparison still
//! sees the layout each implementation printed.
//!
//! | Rule | Becomes |
//! |------|---------|
//! | a literal the caller names (a workspace copy's path) | what the caller says (`<WS>`) |
//! | the number after `"duration_ms"`, `"wall_ms"` or `"elapsed_ms"` | `0` |
//! | an ISO 8601 time of day with its date (`2026-11-08T10:15:00.123Z`) | `<TIME>` |
//! | a crash log's name (`crash-20261108T101500123456Z-648.log`) | `crash-<TIME>-<PID>.log` |
//!
//! A date alone (`2026-11-08`) is data an object holds, and stays.
//!
//! `cargo xtask golden` (UC-0.5) normalises its recordings the same way;
//! the two are to share one implementation (`crates/opentide-compare/AGENTS.md`).

use crate::{FileState, Run, replace};
use regex::bytes::Regex;
use std::sync::OnceLock;

/// The JSON keys whose number is wall time, which [`Normaliser`] sets to `0`.
pub const WALL_TIME_KEYS: [&str; 3] = ["duration_ms", "wall_ms", "elapsed_ms"];

/// What a time of day reads as after normalisation.
pub const TIME_PLACEHOLDER: &str = "<TIME>";

struct Patterns {
    wall_time: Regex,
    crash_log: Regex,
    time: Regex,
}

#[expect(
    clippy::expect_used,
    reason = "the patterns are literals, checked by the tests below"
)]
fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        wall_time: Regex::new(&format!(
            r#"("(?:{})"\s*:\s*)-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"#,
            WALL_TIME_KEYS.join("|")
        ))
        .expect("a valid pattern"),
        crash_log: Regex::new(r"crash-[0-9]{8}T[0-9]{6,12}Z-[0-9]+\.log").expect("a valid pattern"),
        time: Regex::new(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?",
        )
        .expect("a valid pattern"),
    })
}

/// Rewrites runs: literal replacements first (an absolute path to `<WS>`),
/// then wall time, crash-log names and times of day.
#[derive(Debug, Clone, Default)]
pub struct Normaliser {
    replacements: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Normaliser {
    /// A normaliser with the built-in rules alone.
    pub fn new() -> Normaliser {
        Normaliser::default()
    }

    /// Also replaces every occurrence of `from` with `to`. Longer texts are
    /// replaced first, so a path is replaced before its parent folder.
    pub fn replace(mut self, from: impl Into<Vec<u8>>, to: impl Into<Vec<u8>>) -> Normaliser {
        let from = from.into();
        if !from.is_empty() {
            self.replacements.push((from, to.into()));
            self.replacements
                .sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
        }
        self
    }

    /// `bytes`, normalised.
    pub fn bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        for (from, to) in &self.replacements {
            out = replace(&out, from, to);
        }
        let patterns = patterns();
        let out = patterns.wall_time.replace_all(&out, &b"${1}0"[..]);
        let crash = format!("crash-{TIME_PLACEHOLDER}-<PID>.log");
        let out = patterns.crash_log.replace_all(&out, crash.as_bytes());
        patterns
            .time
            .replace_all(&out, TIME_PLACEHOLDER.as_bytes())
            .into_owned()
    }

    /// Normalises `run`'s streams and the contents of the files it wrote.
    pub fn run(&self, run: &mut Run) {
        run.stdout = self.bytes(&run.stdout);
        run.stderr = self.bytes(&run.stderr);
        for state in run.files.values_mut() {
            if let FileState::Written { bytes, .. } = state {
                *bytes = self.bytes(bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalised(text: &str) -> String {
        String::from_utf8(Normaliser::new().bytes(text.as_bytes())).unwrap()
    }

    #[test]
    fn wall_time_is_zeroed_in_both_layouts() {
        assert_eq!(
            normalised(r#"{"duration_ms":1234,"x":"duration_ms"}"#),
            r#"{"duration_ms":0,"x":"duration_ms"}"#
        );
        assert_eq!(
            normalised("{\n  \"duration_ms\": 87\n}\n"),
            "{\n  \"duration_ms\": 0\n}\n"
        );
        assert_eq!(
            normalised(r#"{"stats":{"wall_ms":1288.93},"elapsed_ms":1.5e3}"#),
            r#"{"stats":{"wall_ms":0},"elapsed_ms":0}"#
        );
        assert_eq!(
            normalised(r#"{"duration_ms":"x"}"#),
            r#"{"duration_ms":"x"}"#
        );
        assert_eq!(normalised(r#"{"rules_ms":12}"#), r#"{"rules_ms":12}"#);
    }

    #[test]
    fn times_of_day_and_crash_logs_are_placeholders_and_dates_stay() {
        assert_eq!(
            normalised(
                r#"{"generated_at":"2026-11-08T10:15:00.123456+00:00","reviewed":"2026-11-01"}"#
            ),
            r#"{"generated_at":"<TIME>","reviewed":"2026-11-01"}"#
        );
        assert_eq!(normalised("at 2026-11-08 10:15:00Z"), "at <TIME>");
        assert_eq!(
            normalised("/s/opentide/crash-20261108T101500123456Z-648.log"),
            "/s/opentide/crash-<TIME>-<PID>.log"
        );
    }

    #[test]
    fn longer_paths_are_replaced_first() {
        let normaliser = Normaliser::new()
            .replace("/tmp/a", "<TMP>")
            .replace("/tmp/a/ws", "<WS>");
        assert_eq!(
            normaliser.bytes(b"/tmp/a/ws/x and /tmp/a/y"),
            b"<WS>/x and <TMP>/y"
        );
    }

    #[test]
    fn non_utf8_bytes_pass_through() {
        assert_eq!(
            Normaliser::new().bytes(b"\xff\xfe {\"duration_ms\":5}"),
            b"\xff\xfe {\"duration_ms\":0}"
        );
    }

    #[test]
    fn files_are_normalised_too() {
        let mut run = Run::default();
        run.files.insert(
            "out.json".into(),
            FileState::Written {
                mode: 0o644,
                bytes: b"/w/x".to_vec(),
            },
        );
        Normaliser::new().replace("/w", "<WS>").run(&mut run);
        assert_eq!(
            run.files["out.json"],
            FileState::Written {
                mode: 0o644,
                bytes: b"<WS>/x".to_vec()
            }
        );
    }
}
