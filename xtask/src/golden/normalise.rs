//! Normalisation: what differs between two runs of the same case, and only
//! that, is replaced by a placeholder before anything is recorded or compared.
//!
//! The rules, in the order they apply:
//!
//! 1. **Live regions** (`<LIVE>`): a Rich live display (spinner, progress)
//!    redraws itself as often as the clock allows, between hiding the cursor
//!    (`ESC[?25l`) and showing it again (`ESC[?25h`). Its frames are dropped;
//!    what was printed above it during the region is kept, in order. A region
//!    erased when it stops (transient) loses its last frame too; otherwise the
//!    last frame stays, as on screen.
//! 2. **Paths** (`<WS>`, `<HOME>`, `<TMP>`, `<ENGINE_BIN>`, `<ENGINE>`): the
//!    case's directories and the engine's installation, longest first.
//! 3. **Crash logs** (`crash-<TIMESTAMP>-<PID>.log`): the name the crash
//!    handler gives its log.
//! 4. **Timestamps** (`<TIMESTAMP>`): ISO 8601 date-times on the dates the
//!    case ran; and `<TIME>` for the clock time that starts a debug log line
//!    (`18:22:33 debug: …`).
//! 5. **Today** (`<TODAY>`): the dates the case ran, `YYYY-MM-DD`.
//! 6. **Durations**: the values of the JSON keys `duration_ms`, `elapsed_ms`,
//!    `wall_ms` and `seconds` (every one a wall time in opentide's output)
//!    become `0`, so a JSON document stays JSON; `1.3s` and `2m05s` in text
//!    become `<SECONDS>`.
//! 7. **Hyperlink ids** (`id=<ID>`): Rich numbers terminal hyperlinks
//!    (`ESC]8;id=…;url`) at random.
//! 8. **Host tool versions** (`git <GIT_VERSION>`): `opentide doctor` prints
//!    the git it finds.
//! 9. **Fresh UUIDs** (`<UUID-1>`, …, only for cases that opt in): UUIDs the
//!    fixture does not contain, numbered by first appearance.
//!
//! ANSI escape codes are kept: they are part of what human mode prints.

use crate::golden::case::Rule;
use regex::{Captures, Regex};
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

/// Values that are only known once a case has run.
#[derive(Clone, Debug, Default)]
pub struct Volatile {
    /// Literal text and its placeholder, such as the workspace path and `<WS>`.
    pub literals: Vec<(String, String)>,
    /// The dates (`YYYY-MM-DD`, UTC) the case ran on: one, or two across midnight.
    pub dates: Vec<String>,
    /// `git --version`'s number on this host, when git is installed.
    pub git_version: Option<String>,
}

/// Normalises the outputs of one case: stdout, then stderr, then each file in
/// path order, so that fresh UUIDs are numbered the same way every time.
#[derive(Debug)]
pub struct Normaliser {
    literals: Vec<(String, String)>,
    timestamp: Option<Regex>,
    today: Option<Regex>,
    git: Option<String>,
    fresh_uuids: Option<FreshUuids>,
}

#[derive(Debug)]
struct FreshUuids {
    known: BTreeSet<String>,
    seen: HashMap<String, usize>,
}

macro_rules! regex {
    ($name:ident, $pattern:expr) => {
        // A literal pattern, compiled by every unit test below: it cannot fail.
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            CELL.get_or_init(|| Regex::new($pattern).expect("valid regex"))
        }
    };
}

regex!(position_cursor, r"\r\x1b\[2K((?:\x1b\[1A\x1b\[2K)*)");
regex!(transient_erase, r"^\r((?:\x1b\[1A\x1b\[2K)+)");
regex!(
    log_clock,
    r"(?m)^((?:\x1b\[[0-9;]*m)*)\d{2}:\d{2}:\d{2}(?:[.,]\d+)?((?:\x1b\[[0-9;]*m)* )"
);
regex!(crash_log, r"crash-\d{8}T\d{6}\d*Z-\d+\.log");
regex!(
    duration_ms,
    r#"("(?:duration_ms|elapsed_ms|wall_ms|seconds)"\s*:\s*)\d+(?:\.\d+)?"#
);
regex!(
    seconds,
    r"(^|[^\w.]|\x1b\[[0-9;]*m)(?:\d+\.\ds|\d+m\d\ds)\b"
);
regex!(osc8_id, r"(\x1b\]8;[^;\x07\x1b]*?)id=[^;:\x07\x1b]*");
regex!(
    uuid,
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
);

impl Normaliser {
    /// A normaliser for one case. `fixture_text` is the text of the fixture's
    /// files before the run: the UUIDs it holds are not fresh.
    pub fn new<'a>(
        volatile: &Volatile,
        rules: &[Rule],
        fixture_text: impl IntoIterator<Item = &'a str>,
    ) -> Normaliser {
        let mut literals: Vec<(String, String)> = volatile
            .literals
            .iter()
            .filter(|(literal, _)| !literal.is_empty())
            .cloned()
            .collect();
        literals.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        let dates: Vec<String> = volatile.dates.iter().map(|d| regex::escape(d)).collect();
        let (timestamp, today) = if dates.is_empty() {
            (None, None)
        } else {
            let any = dates.join("|");
            (
                Regex::new(&format!(
                    r"(?:{any})[T ]\d{{2}}:\d{{2}}(?::\d{{2}}(?:[.,]\d+)?)?(?:Z|[+-]\d{{2}}:?\d{{2}})?"
                ))
                .ok(),
                Regex::new(&format!(r"\b(?:{any})\b")).ok(),
            )
        };
        let fresh_uuids = rules.contains(&Rule::FreshUuids).then(|| FreshUuids {
            known: fixture_text
                .into_iter()
                .flat_map(|text| {
                    uuid()
                        .find_iter(text)
                        .map(|m| m.as_str().to_ascii_lowercase())
                })
                .collect(),
            seen: HashMap::new(),
        });
        Normaliser {
            literals,
            timestamp,
            today,
            git: volatile.git_version.clone(),
            fresh_uuids,
        }
    }

    /// Normalises bytes: UTF-8 text goes through [`Normaliser::text`]; other
    /// bytes are returned unchanged.
    pub fn bytes(&mut self, bytes: &[u8]) -> Vec<u8> {
        match std::str::from_utf8(bytes) {
            Ok(text) => self.text(text).into_bytes(),
            Err(_) => bytes.to_vec(),
        }
    }

    /// Applies every rule to `text`.
    pub fn text(&mut self, text: &str) -> String {
        let mut out = live_regions(text);
        for (literal, placeholder) in &self.literals {
            if out.contains(literal.as_str()) {
                out = out.replace(literal.as_str(), placeholder);
            }
        }
        out = crash_log()
            .replace_all(&out, "crash-<TIMESTAMP>-<PID>.log")
            .into_owned();
        out = log_clock().replace_all(&out, "${1}<TIME>${2}").into_owned();
        if let Some(timestamp) = &self.timestamp {
            out = timestamp.replace_all(&out, "<TIMESTAMP>").into_owned();
        }
        if let Some(today) = &self.today {
            out = today.replace_all(&out, "<TODAY>").into_owned();
        }
        out = duration_ms().replace_all(&out, "${1}0").into_owned();
        out = seconds().replace_all(&out, "${1}<SECONDS>").into_owned();
        out = osc8_id().replace_all(&out, "${1}id=<ID>").into_owned();
        if let Some(version) = &self.git {
            out = out.replace(&format!("git {version}"), "git <GIT_VERSION>");
        }
        if let Some(fresh) = &mut self.fresh_uuids {
            out = uuid()
                .replace_all(&out, |caps: &Captures<'_>| {
                    let found = caps[0].to_ascii_lowercase();
                    if fresh.known.contains(&found) {
                        return caps[0].to_owned();
                    }
                    let next = fresh.seen.len() + 1;
                    let n = *fresh.seen.entry(found).or_insert(next);
                    format!("<UUID-{n}>")
                })
                .into_owned();
        }
        out
    }
}

const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

/// Rule 1: drops the frames of every live region (see the module docs).
pub fn live_regions(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(HIDE_CURSOR) {
        let body_start = start + HIDE_CURSOR.len();
        let Some(len) = rest[body_start..].find(SHOW_CURSOR) else {
            break;
        };
        let body = &rest[body_start..body_start + len];
        let after = &rest[body_start + len + SHOW_CURSOR.len()..];
        out.push_str(&rest[..start]);
        out.push_str(HIDE_CURSOR);
        out.push_str("<LIVE>");
        let transient = transient_erase()
            .captures(after)
            .map(|caps| caps[1].matches("\x1b[1A").count());
        out.push_str(&printed_in_region(body, transient));
        out.push_str(SHOW_CURSOR);
        rest = after;
    }
    out.push_str(rest);
    out
}

/// What a live region printed above its frames. Rich redraws a frame of
/// height `h` by moving to its start, `\r ESC[2K (ESC[1A ESC[2K){h-1}`, and
/// prints anything else right before the next frame; so the text before each
/// redraw ends with the frame it erases. The last frame is dropped when the
/// region is erased on stop (`transient` holds its height), kept otherwise.
fn printed_in_region(body: &str, transient: Option<usize>) -> String {
    let mut printed = String::new();
    let mut last = 0;
    for caps in position_cursor().captures_iter(body) {
        let Some(whole) = caps.get(0) else { continue };
        let height = caps[1].matches("\x1b[1A").count() + 1;
        printed.push_str(drop_last_lines(&body[last..whole.start()], height));
        last = whole.end();
    }
    let tail = &body[last..];
    match transient {
        Some(height) => {
            let frame = tail.strip_suffix('\n').unwrap_or(tail);
            printed.push_str(drop_last_lines(frame, height));
        }
        None => printed.push_str(tail),
    }
    printed
}

/// `chunk` without its last `lines` lines (the frame, which has no final newline).
fn drop_last_lines(chunk: &str, lines: usize) -> &str {
    let mut end = chunk.len();
    for _ in 0..lines {
        match chunk[..end].rfind('\n') {
            Some(newline) => end = newline,
            None => return "",
        }
    }
    &chunk[..=end]
}

/// The UTC date of a moment, `YYYY-MM-DD` (Howard Hinnant's `civil_from_days`).
pub fn utc_date(time: std::time::SystemTime) -> String {
    let secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn volatile() -> Volatile {
        Volatile {
            literals: vec![
                ("/tmp/golden-abc123/ws".into(), "<WS>".into()),
                ("/tmp/golden-abc123/home".into(), "<HOME>".into()),
                ("/tmp/golden-abc123".into(), "<TMP>".into()),
            ],
            dates: vec!["2026-11-08".into()],
            git_version: Some("2.43.0".into()),
        }
    }

    fn norm(text: &str) -> String {
        Normaliser::new(&volatile(), &[], []).text(text)
    }

    #[test]
    fn paths_longest_first() {
        assert_eq!(
            norm(
                "wrote /tmp/golden-abc123/ws/a.yaml and /tmp/golden-abc123/home/.x in /tmp/golden-abc123/tmp"
            ),
            "wrote <WS>/a.yaml and <HOME>/.x in <TMP>/tmp"
        );
        assert_eq!(
            norm("file:///tmp/golden-abc123/ws/r.yaml"),
            "file://<WS>/r.yaml"
        );
    }

    #[test]
    fn durations_keep_json_valid() {
        let doc = "{\n  \"ok\": true,\n  \"duration_ms\": 1234,\n  \"x\": {\"elapsed_ms\":7, \"wall_ms\": 1504.52, \"seconds\": 0.125}\n}";
        let out = norm(doc);
        assert_eq!(
            out,
            "{\n  \"ok\": true,\n  \"duration_ms\": 0,\n  \"x\": {\"elapsed_ms\":0, \"wall_ms\": 0, \"seconds\": 0}\n}"
        );
        serde_json::from_str::<serde_json::Value>(&out).unwrap();
        // A count is not a duration.
        assert_eq!(norm("\"rows\": 120"), "\"rows\": 120");
    }

    #[test]
    fn seconds_in_outcome_lines() {
        assert_eq!(
            norm("✓ 12 objects valid · 7 queries · 1.9s"),
            "✓ 12 objects valid · 7 queries · <SECONDS>"
        );
        assert_eq!(
            norm("Generated 3 files in 12.4s · docs"),
            "Generated 3 files in <SECONDS> · docs"
        );
        assert_eq!(norm("took 2m05s\n"), "took <SECONDS>\n");
        assert_eq!(norm("\x1b[2m0.3s\x1b[0m"), "\x1b[2m<SECONDS>\x1b[0m");
        // Versions, decimals with two places and words are left alone.
        assert_eq!(
            norm("python 3.13s1 v1.2.3s 0.25s rule::1.0"),
            "python 3.13s1 v1.2.3s 0.25s rule::1.0"
        );
    }

    #[test]
    fn timestamps_and_today_only_on_the_run_dates() {
        assert_eq!(
            norm("at 2026-11-08T10:11:12.123456+00:00 and 2026-11-08 10:11:12Z"),
            "at <TIMESTAMP> and <TIMESTAMP>"
        );
        assert_eq!(
            norm("created: 2026-11-08\nmodified: 2024-01-01"),
            "created: <TODAY>\nmodified: 2024-01-01"
        );
        assert_eq!(norm("at 2024-01-01T00:00:00Z"), "at 2024-01-01T00:00:00Z");
        let none = Normaliser::new(&Volatile::default(), &[], []).text("2026-11-08");
        assert_eq!(none, "2026-11-08");
    }

    #[test]
    fn log_line_clock_times() {
        assert_eq!(
            norm("18:22:33 debug: Resolving · vocab: tlp::1.0\n\x1b[2m09:01:02.5\x1b[0m info: x\n"),
            "<TIME> debug: Resolving · vocab: tlp::1.0\n\x1b[2m<TIME>\x1b[0m info: x\n"
        );
        // Only at the start of a line.
        assert_eq!(norm("at 18:22:33 today"), "at 18:22:33 today");
    }

    #[test]
    fn crash_log_names() {
        assert_eq!(
            norm(
                "log: /tmp/golden-abc123/home/.local/state/opentide/crash-20261108T101112123456Z-4242.log"
            ),
            "log: <HOME>/.local/state/opentide/crash-<TIMESTAMP>-<PID>.log"
        );
    }

    #[test]
    fn hyperlink_ids() {
        let link = "\x1b]8;id=581337;file:///tmp/golden-abc123/ws/a.yaml\x1b\\a.yaml\x1b]8;;\x1b\\";
        assert_eq!(
            norm(link),
            "\x1b]8;id=<ID>;file://<WS>/a.yaml\x1b\\a.yaml\x1b]8;;\x1b\\"
        );
        assert_eq!(norm("\x1b]8;;https://x\x07"), "\x1b]8;;https://x\x07");
    }

    #[test]
    fn git_version() {
        assert_eq!(norm("✓ git 2.43.0 · git"), "✓ git <GIT_VERSION> · git");
        assert_eq!(norm("tool 2.43.0"), "tool 2.43.0");
    }

    #[test]
    fn fresh_uuids_only_when_asked_and_not_the_fixtures() {
        let fixture = "uuid: 00000000-0000-4000-8001-000000000001\n";
        let text = "new 9F1C2B3A-1111-4222-8333-444455556666 for threat 00000000-0000-4000-8001-000000000001; \
                    again 9f1c2b3a-1111-4222-8333-444455556666, other 11111111-2222-4333-8444-555566667777";
        let mut n = Normaliser::new(&volatile(), &[Rule::FreshUuids], [fixture]);
        assert_eq!(
            n.text(text),
            "new <UUID-1> for threat 00000000-0000-4000-8001-000000000001; again <UUID-1>, other <UUID-2>"
        );
        // Numbering carries over to the next output of the same case.
        assert_eq!(
            n.text("file 11111111-2222-4333-8444-555566667777"),
            "file <UUID-2>"
        );
        assert_eq!(norm(text), text);
    }

    #[test]
    fn live_region_frames_are_dropped_transient() {
        // As recorded from `opentide validate` on a pseudo-terminal.
        let spin = |c: &str| format!("\x1b[1;36m{c}\x1b[0m Validating objects");
        let mut stream = String::from(HIDE_CURSOR);
        for c in ["⠋", "⠙", "⠹"] {
            stream.push_str(&spin(c));
            stream.push_str("\r\x1b[2K");
        }
        stream.push_str(&spin("⠸"));
        stream.push('\n');
        stream.push_str(SHOW_CURSOR);
        stream.push_str("\r\x1b[1A\x1b[2K");
        let fewer = format!("{HIDE_CURSOR}{}\n{SHOW_CURSOR}\r\x1b[1A\x1b[2K", spin("⠋"));
        let expected = format!("{HIDE_CURSOR}<LIVE>{SHOW_CURSOR}\r\x1b[1A\x1b[2K");
        assert_eq!(live_regions(&stream), expected);
        assert_eq!(live_regions(&fewer), expected);
    }

    #[test]
    fn live_region_keeps_what_was_printed_above_and_a_kept_last_frame() {
        // Two-line frames; a warning printed during the region; not transient.
        let frame = |n: u32| format!("step {n}\n[{n}/2]");
        let redraw = "\r\x1b[2K\x1b[1A\x1b[2K";
        let stream = format!(
            "before\n{HIDE_CURSOR}{}{redraw}warning: x\n{}{redraw}{}\n{SHOW_CURSOR}after\n",
            frame(1),
            frame(1),
            frame(2)
        );
        assert_eq!(
            live_regions(&stream),
            format!(
                "before\n{HIDE_CURSOR}<LIVE>warning: x\n{}\n{SHOW_CURSOR}after\n",
                frame(2)
            )
        );
    }

    #[test]
    fn unterminated_region_is_left_alone() {
        let text = format!("{HIDE_CURSOR}frame\r\x1b[2Kframe");
        assert_eq!(live_regions(&text), text);
        assert_eq!(live_regions("plain\n"), "plain\n");
    }

    #[test]
    fn binary_is_unchanged() {
        let bytes = [0xff, 0xfe, b'2', b'0'];
        assert_eq!(Normaliser::new(&volatile(), &[], []).bytes(&bytes), bytes);
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc_date(UNIX_EPOCH), "1970-01-01");
        assert_eq!(
            utc_date(UNIX_EPOCH + Duration::from_secs(1_794_009_600)),
            "2026-11-07"
        );
        assert_eq!(
            utc_date(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "2000-02-29"
        );
    }
}
