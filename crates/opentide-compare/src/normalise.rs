//! Normalisation: what differs between two runs of the same case, and only
//! that, is replaced by a placeholder before anything is recorded or compared.
//!
//! The rules, in the order they apply:
//!
//! 1. **Live regions** (`<LIVE>…</LIVE>`): a Rich live display (spinner,
//!    progress) redraws itself as often as the clock allows, between hiding
//!    the cursor (`ESC[?25l`) and showing it again (`ESC[?25h`). Its first
//!    frame is kept between the markers, with the spinner glyph as `<SPIN>`
//!    (Live renders it before any work, so its label is compared); the later
//!    frames, and how many there were, are dropped. What was printed above it
//!    during the region is kept, in order. A region erased when it stops
//!    (transient) loses its last frame too; otherwise the last frame stays,
//!    as on screen.
//! 2. **Paths** (`<WS>`, `<HOME>`, `<TMP>`, `<ENGINE_BIN>`, `<ENGINE>`): the
//!    case's directories and the engine's installation, longest first.
//! 3. **Crash logs** (`crash-<TIMESTAMP>-<PID>.log`): the name the crash
//!    handler gives its log; and the language-server catalog cache's
//!    directory (`lsp-catalogs/<CATALOG-FINGERPRINT>`), a hash of the
//!    installation's paths and file times.
//! 4. **Timestamps**: ISO 8601 date-times on the dates the case ran or the
//!    seven days before (a default window reaches back from now), and the
//!    clock time that starts a log line (`18:22:33 debug: …`), get every digit
//!    replaced by `0`, so the format (separators, fraction width, offset
//!    style) is still compared.
//! 5. **Today** (`<TODAY>`): the dates the case ran, `YYYY-MM-DD`.
//! 6. **Durations**: the values of the JSON keys `duration_ms`, `elapsed_ms`,
//!    `wall_ms` and `seconds` (every one a wall time in opentide's output)
//!    become `0`, or `0.0` for a float, so the document keeps its types;
//!    `1.3s` and `2m05s` in text become `<SECONDS>`, with any run of spaces
//!    on either side made one (a table column pads to its widest value).
//! 7. **Hyperlink ids** (`id=<ID>`): Rich numbers terminal hyperlinks
//!    (`ESC]8;id=…;url`) at random.
//! 8. **Host tool versions** (`git <GIT_VERSION>`, only for cases that opt
//!    in with `host-git`): `opentide doctor` prints the git it finds; help
//!    text quotes a literal example that must stay.
//! 9. **Fresh UUIDs** (`<UUID-1>`, …, only for cases that opt in): UUIDs the
//!    fixture does not contain, numbered by first appearance.
//!
//! When two runs are compared, and not when a case is recorded,
//! [`opentide_version`] also replaces opentide's own version, the exact
//! string each side reports, with `<OPENTIDE_VERSION>` on that side: the
//! oracle is a release and the candidate a build of this repository, and the
//! installed version is not behaviour.
//!
//! ANSI escape codes are kept: they are part of what human mode prints.
//!
//! Written for `cargo xtask golden` (UC-0.5, #803) and moved here (UC-0.7,
//! #805) so that the command line's golden replays normalise as the goldens
//! do; `xtask::golden::normalise` re-exports it.

use crate::{FileState, Run};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

/// An extra normalisation rule a case opts into (`normalise` in `cases.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rule {
    /// UUIDs that the fixture does not contain become `<UUID-1>`, `<UUID-2>`, …
    /// in order of first appearance: for commands that mint identifiers.
    FreshUuids,
    /// `git <version>` becomes `git <GIT_VERSION>`, for the host's git that
    /// `opentide doctor` reports. Not global: opentide's own help text
    /// carries a literal example (`✓ git 2.43.0 · git`) that must stay.
    HostGit,
    /// A live region's first frame becomes `<PROGRESS>`, and progress rows
    /// that run into a line printed during the region are dropped: for a
    /// progress row the command updates as it works (deploy's rule count and
    /// current rule), which on a loaded machine Rich may draw before or after
    /// the first update, or not at all before the first printed line. Not
    /// global: every other live frame is compared whole.
    LiveProgress,
}

/// Values that are only known once a case has run.
#[derive(Clone, Debug, Default)]
pub struct Volatile {
    /// Literal text and its placeholder, such as the workspace path and `<WS>`.
    pub literals: Vec<(String, String)>,
    /// The dates (`YYYY-MM-DD`, UTC) the case ran on: one, or two across midnight.
    pub dates: Vec<String>,
    /// Earlier dates whose date-times are the clock too: a command's default
    /// window reaches back from now (`query` starts 24 hours ago).
    pub recent_dates: Vec<String>,
    /// `git --version`'s number on this host, when git is installed.
    pub git_version: Option<String>,
    /// UUIDs that are never fresh, beyond the fixture's: those in the case's
    /// argv, environment and stdin, and in the engine's bundled data. Only a
    /// UUID the run minted becomes `<UUID-n>`.
    pub known_uuids: BTreeSet<String>,
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
    live_progress: bool,
}

#[derive(Debug)]
struct FreshUuids {
    known: BTreeSet<String>,
    seen: HashMap<String, usize>,
}

/// Compiles a pattern once. Every pattern is a literal of this module (or
/// built from escaped dates), compiled by the unit tests: it cannot fail.
#[expect(
    clippy::expect_used,
    reason = "literal patterns, compiled by every unit test"
)]
fn compiled(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("a valid pattern"))
}

#[expect(
    clippy::expect_used,
    reason = "escaped dates in a fixed pattern, compiled by the unit tests"
)]
fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a valid pattern")
}

macro_rules! regex {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            compiled(&CELL, $pattern)
        }
    };
}

regex!(position_cursor, r"\r\x1b\[2K((?:\x1b\[1A\x1b\[2K)*)");
regex!(transient_erase, r"^\r((?:\x1b\[1A\x1b\[2K)+)");
regex!(
    log_clock,
    r"(?m)^((?:\x1b\[\?25l<LIVE>[^\n]*?</LIVE>)?(?:\x1b\[[0-9;]*m)*)(\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)((?:\x1b\[[0-9;]*m)* (?:\x1b\[[0-9;]*m)*(?:debug|info|warning|error|critical)\b)"
);
regex!(catalog_fingerprint, r"(lsp-catalogs[/\\])[0-9a-f]{32}\b");
regex!(crash_log, r"crash-\d{8}T\d{6}\d*Z-\d+\.log");
regex!(
    duration_ms,
    r#"("(?:duration_ms|elapsed_ms|wall_ms|seconds)"\s*:\s*)\d+(\.\d+)?"#
);
regex!(
    seconds,
    r"(^|[^ \w.]|[\w.] )( *)((?:\x1b\[[0-9;]*m)*)( *)(?:\d+\.\ds|\d+m\d\ds)\b((?:\x1b\[[0-9;]*m)*)( *)"
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
            let recent: Vec<String> = dates
                .iter()
                .cloned()
                .chain(volatile.recent_dates.iter().map(|d| regex::escape(d)))
                .collect();
            let recent = recent.join("|");
            (
                Some(compile(&format!(
                    r"(?:{recent})[T ]\d{{2}}:\d{{2}}(?::\d{{2}}(?:[.,]\d+)?)?(?:Z|[+-]\d{{2}}:?\d{{2}})?"
                ))),
                Some(compile(&format!(r"\b(?:{any})\b"))),
            )
        };
        let fresh_uuids = rules.contains(&Rule::FreshUuids).then(|| FreshUuids {
            known: fixture_text
                .into_iter()
                .flat_map(uuids_in)
                .chain(volatile.known_uuids.iter().cloned())
                .collect(),
            seen: HashMap::new(),
        });
        Normaliser {
            literals,
            timestamp,
            today,
            git: volatile
                .git_version
                .clone()
                .filter(|_| rules.contains(&Rule::HostGit)),
            fresh_uuids,
            live_progress: rules.contains(&Rule::LiveProgress),
        }
    }

    /// Normalises a run as a recording is: stdout, stderr, then each written
    /// file in path order (a [`Run`]'s files are kept in path order).
    pub fn run(&mut self, run: &mut Run) {
        run.stdout = self.bytes(&run.stdout);
        run.stderr = self.bytes(&run.stderr);
        for state in run.files.values_mut() {
            if let FileState::Written { bytes, .. } = state {
                *bytes = self.bytes(bytes);
            }
        }
    }

    /// `text` with every fresh UUID as `<UUID>`, numbering nothing: a sort key
    /// that does not depend on the UUIDs a run minted. Without the
    /// fresh-UUIDs rule, `text` unchanged.
    pub fn mask_fresh(&self, text: &str) -> String {
        let Some(fresh) = &self.fresh_uuids else {
            return text.to_owned();
        };
        uuid()
            .replace_all(text, |caps: &Captures<'_>| {
                if fresh.known.contains(&caps[0].to_ascii_lowercase()) {
                    caps[0].to_owned()
                } else {
                    "<UUID>".to_owned()
                }
            })
            .into_owned()
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
        if self.live_progress {
            out = live_progress(&out);
        }
        for (literal, placeholder) in &self.literals {
            if out.contains(literal.as_str()) {
                out = out.replace(literal.as_str(), placeholder);
            }
        }
        out = crash_log()
            .replace_all(&out, "crash-<TIMESTAMP>-<PID>.log")
            .into_owned();
        out = catalog_fingerprint()
            .replace_all(&out, "${1}<CATALOG-FINGERPRINT>")
            .into_owned();
        out = log_clock()
            .replace_all(&out, |caps: &Captures<'_>| {
                format!("{}{}{}", &caps[1], zero_digits(&caps[2]), &caps[3])
            })
            .into_owned();
        if let Some(timestamp) = &self.timestamp {
            out = timestamp
                .replace_all(&out, |caps: &Captures<'_>| zero_digits(&caps[0]))
                .into_owned();
        }
        if let Some(today) = &self.today {
            out = today.replace_all(&out, "<TODAY>").into_owned();
        }
        out = duration_ms()
            .replace_all(&out, |caps: &Captures<'_>| {
                let zero = if caps.get(2).is_some() { "0.0" } else { "0" };
                format!("{}{zero}", &caps[1])
            })
            .into_owned();
        // The trailing spaces a match takes can be the leading ones of the next
        // duration (`1.6s 2.4s`): repeat until nothing changes.
        loop {
            let next = seconds()
                .replace_all(&out, |caps: &Captures<'_>| {
                    // A table pads the column to its widest value: the padding on
                    // either side of the token is timing too, so any run of spaces
                    // becomes one.
                    let space = |i: usize| if caps[i].is_empty() { "" } else { " " };
                    let lead = if caps[1].ends_with(' ') { "" } else { space(2) };
                    format!(
                        "{}{}{}{}<SECONDS>{}{}",
                        &caps[1],
                        lead,
                        &caps[3],
                        space(4),
                        &caps[5],
                        space(6)
                    )
                })
                .into_owned();
            if next == out {
                break;
            }
            out = next;
        }
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

/// Every ASCII digit of `text` as `0`: a clock value keeps its format
/// (separators, fraction width, offset style), which is part of the contract.
fn zero_digits(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_ascii_digit() { '0' } else { c })
        .collect()
}

/// Every UUID in `text`, lower-cased.
pub fn uuids_in(text: &str) -> impl Iterator<Item = String> + '_ {
    uuid()
        .find_iter(text)
        .map(|m| m.as_str().to_ascii_lowercase())
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
        let transient = transient_erase()
            .captures(after)
            .map(|caps| caps[1].matches("\x1b[1A").count());
        let (printed, first) = printed_in_region(body, transient);
        out.push_str("<LIVE>");
        out.push_str(&mask_spinner(first));
        out.push_str("</LIVE>");
        out.push_str(&printed);
        out.push_str(SHOW_CURSOR);
        rest = after;
    }
    out.push_str(rest);
    out
}

/// What a live region printed above its frames, and its first frame. Rich
/// redraws a frame of height `h` by moving to its start,
/// `\r ESC[2K (ESC[1A ESC[2K){h-1}`, and prints anything else right before
/// the next frame; so the text before each redraw ends with the frame it
/// erases. Live starts with a render, so the first frame is drawn before any
/// work and is the same on every run; the later frames follow the clock. The
/// last frame is dropped when the region is erased on stop (`transient` holds
/// its height), kept otherwise.
fn printed_in_region(body: &str, transient: Option<usize>) -> (String, &str) {
    let mut printed = String::new();
    let mut first: Option<&str> = None;
    let mut last = 0;
    for caps in position_cursor().captures_iter(body) {
        let Some(whole) = caps.get(0) else { continue };
        let height = caps[1].matches("\x1b[1A").count() + 1;
        let chunk = &body[last..whole.start()];
        let before = drop_last_lines(chunk, height);
        first.get_or_insert(&chunk[before.len()..]);
        printed.push_str(before);
        last = whole.end();
    }
    let tail = &body[last..];
    match transient {
        Some(height) => {
            let frame = tail.strip_suffix('\n').unwrap_or(tail);
            let before = drop_last_lines(frame, height);
            first.get_or_insert(&frame[before.len()..]);
            printed.push_str(before);
        }
        None => printed.push_str(tail),
    }
    (printed, first.unwrap_or(""))
}

/// [`Rule::LiveProgress`]: every `<LIVE>` frame of `text` (already through
/// [`live_regions`]) as `<PROGRESS>`, whatever Rich drew first (the bare row,
/// an updated one, or nothing).
///
/// What the region printed loses the progress rows a loaded machine leaks
/// into it: Rich's refresh thread can draw a frame just before a line is
/// printed above the display, with no cursor move between them, so the row
/// runs into the printed line. A row followed by a newline (a frame kept on
/// screen) stays.
pub fn live_progress(text: &str) -> String {
    live_frame()
        .replace_all(text, |caps: &Captures<'_>| {
            let printed = without_leaked_rows(&caps[1]);
            format!("<LIVE><PROGRESS></LIVE>{printed}{SHOW_CURSOR}")
        })
        .into_owned()
}

/// `printed` without the progress rows that run into a printed line (see
/// [`live_progress`]).
fn without_leaked_rows(printed: &str) -> String {
    let mut out = String::with_capacity(printed.len());
    let mut last = 0;
    for row in progress_row().find_iter(printed) {
        if printed[row.end()..].starts_with('\n') || row.end() == printed.len() {
            continue;
        }
        out.push_str(&printed[last..row.start()]);
        last = row.end();
    }
    out.push_str(&printed[last..]);
    out
}

regex!(live_frame, r"(?s)<LIVE>.*?</LIVE>(.*?)\x1b\[\?25h");
// A progress row: the spinner, then segments in the row's own styles (bold
// cyan, bold, dim), never a warning's or an error's.
regex!(
    progress_row,
    r"  \x1b\[1;36m[\u{2800}-\u{28ff}]\x1b\[0m(?:\x1b\[(?:1;36|1|2|1;2)m[^\x1b\n]*\x1b\[0m| +)*"
);

/// A frame with its spinner glyphs (the Braille block Rich's spinners draw
/// from) as `<SPIN>`: which glyph shows first depends on the clock.
fn mask_spinner(frame: &str) -> String {
    let mut out = String::with_capacity(frame.len());
    for c in frame.chars() {
        if ('\u{2800}'..='\u{28ff}').contains(&c) {
            out.push_str("<SPIN>");
        } else {
            out.push(c);
        }
    }
    out
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

/// What opentide's own version becomes when two runs are compared.
pub const OPENTIDE_VERSION: &str = "<OPENTIDE_VERSION>";

/// Whether `c` continues a version token: `0.23.0` is not opentide's
/// `0.23.0` inside `10.23.0`, `0.23.01`, `0.23.0.dev1` or `0.23.0+local`.
fn continues_version(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '+'
}

/// `text` with every whole occurrence of `version`, opentide's own version as
/// the side that ran reports it, as [`OPENTIDE_VERSION`]. Comparison only:
/// the oracle's release and the candidate's build have different versions,
/// and the installed version is not behaviour. Only that exact string, and
/// only as a whole token, is replaced: another package's version, a longer
/// version that contains it, and any other version-shaped text stay. An
/// empty `version` replaces nothing.
pub fn opentide_version(text: &str, version: &str) -> String {
    if version.is_empty() {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (start, _) in text.match_indices(version) {
        if start < last {
            continue;
        }
        let end = start + version.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        if before.is_some_and(continues_version) || after.is_some_and(continues_version) {
            continue;
        }
        out.push_str(&text[last..start]);
        out.push_str(OPENTIDE_VERSION);
        last = end;
    }
    out.push_str(&text[last..]);
    out
}

/// [`opentide_version`] for a line padded to a width: a line that holds
/// the version and ends in spaces keeps the width it was printed at, its
/// trailing spaces lengthened or shortened by what the token's length takes
/// from the version's (`0.23.0` against `0.23.1.dev7+g1f90` in the home
/// screen's padded title row, where the screen's width is the same on both
/// sides). Every other line is [`opentide_version`]'s.
pub fn opentide_version_padded(text: &str, version: &str) -> String {
    if version.is_empty() || !text.contains(version) {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, ending) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        let replaced = opentide_version(body, version);
        let count = |text: &str| text.chars().count();
        let trailing = count(body) - count(body.trim_end_matches(' '));
        if replaced == body || trailing == 0 {
            out.push_str(&replaced);
        } else {
            let printed = count(body);
            let kept = replaced.trim_end_matches(' ');
            let width = printed.max(count(kept) + 1);
            out.push_str(kept);
            out.push_str(&" ".repeat(width - count(kept)));
        }
        out.push_str(ending);
    }
    out
}

/// [`opentide_version_padded`] over a run's streams and the UTF-8 files it
/// wrote.
pub fn opentide_version_in_run(run: &mut Run, version: &str) {
    let replace = |bytes: &mut Vec<u8>| {
        if let Ok(text) = std::str::from_utf8(bytes) {
            *bytes = opentide_version_padded(text, version).into_bytes();
        }
    };
    replace(&mut run.stdout);
    replace(&mut run.stderr);
    for state in run.files.values_mut() {
        if let FileState::Written { bytes, .. } = state {
            replace(bytes);
        }
    }
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

    #[test]
    fn a_padded_line_keeps_its_width_whatever_the_version() {
        // The home screen's title row: the version, then the padding.
        assert_eq!(
            opentide_version_padded("pill  0.23.0\u{1b}[0m              \nnext\n", "0.23.0"),
            "pill  <OPENTIDE_VERSION>\u{1b}[0m  \nnext\n"
        );
        // Both printed 30 columns wide: the same line after normalisation.
        let wide = |version: &str| format!("ab {version}{}", " ".repeat(30 - 3 - version.len()));
        assert_eq!(
            opentide_version_padded(&wide("0.23.0"), "0.23.0"),
            opentide_version_padded(
                &wide("0.23.1.dev1203+gfb19974d1"),
                "0.23.1.dev1203+gfb19974d1"
            )
        );
        // A line without trailing spaces, or without the version, is as before.
        assert_eq!(
            opentide_version_padded("opentide 0.23.0\n", "0.23.0"),
            "opentide <OPENTIDE_VERSION>\n"
        );
        assert_eq!(opentide_version_padded("x   \n", "0.23.0"), "x   \n");
    }

    fn volatile() -> Volatile {
        Volatile {
            // The shortest first: `paths_longest_first` fails unless the
            // normaliser sorts them.
            literals: vec![
                ("/tmp/golden-abc123".into(), "<TMP>".into()),
                ("/tmp/golden-abc123/ws".into(), "<WS>".into()),
                ("/tmp/golden-abc123/home".into(), "<HOME>".into()),
            ],
            dates: vec!["2026-11-08".into()],
            recent_dates: vec!["2026-11-07".into()],
            git_version: Some("2.43.0".into()),
            known_uuids: BTreeSet::new(),
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
            "{\n  \"ok\": true,\n  \"duration_ms\": 0,\n  \"x\": {\"elapsed_ms\":0, \"wall_ms\": 0.0, \"seconds\": 0.0}\n}"
        );
        serde_json::from_str::<serde_json::Value>(&out).unwrap();
        // A count, a timeout and a time to live are not durations.
        for kept in ["\"rows\": 120", "\"timeout_ms\": 30", "\"ttl_seconds\": 5"] {
            assert_eq!(norm(kept), kept);
        }
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
        // A table column padded to its widest value: the padding is timing too.
        let fast =
            "templates  4 files \x1b[2m 1.6s\x1b[0m\nschemas    8 files \x1b[2m 2.4s\x1b[0m\n";
        let slow =
            "templates  4 files \x1b[2m  1.6s\x1b[0m\nschemas    8 files \x1b[2m 12.4s\x1b[0m\n";
        assert_eq!(norm(fast), norm(slow));
        assert_eq!(
            norm(fast),
            "templates  4 files \x1b[2m <SECONDS>\x1b[0m\nschemas    8 files \x1b[2m <SECONDS>\x1b[0m\n"
        );
        assert_eq!(norm("| 0.3s   | x |"), norm("| 12.3s  | x |"));
        // Two durations side by side.
        assert_eq!(
            norm("took 1.6s 2.4s total"),
            "took <SECONDS> <SECONDS> total"
        );
        assert_eq!(norm("a 0.3s  1.2s"), "a <SECONDS> <SECONDS>");
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
            "at 0000-00-00T00:00:00.000000+00:00 and 0000-00-00 00:00:00Z"
        );
        assert_eq!(
            norm("created: 2026-11-08\nmodified: 2024-01-01"),
            "created: <TODAY>\nmodified: 2024-01-01"
        );
        assert_eq!(norm("at 2024-01-01T00:00:00Z"), "at 2024-01-01T00:00:00Z");
        // A window that starts a day back is the clock; a bare date of then is not today.
        assert_eq!(
            norm("from 2026-11-07T23:34:14.566Z on 2026-11-07"),
            "from 0000-00-00T00:00:00.000Z on 2026-11-07"
        );
        let none = Normaliser::new(&Volatile::default(), &[], []).text("2026-11-08");
        assert_eq!(none, "2026-11-08");
    }

    #[test]
    fn log_line_clock_times() {
        assert_eq!(
            norm("18:22:33 debug: Resolving · vocab: tlp::1.0\n\x1b[2m09:01:02.5\x1b[0m info: x\n"),
            "00:00:00 debug: Resolving · vocab: tlp::1.0\n\x1b[2m00:00:00.0\x1b[0m info: x\n"
        );
        // The first line printed during a live region follows its marker.
        assert_eq!(
            norm(
                "\x1b[?25l<LIVE>\x1b[1;36m⠋\x1b[0m Validating objects</LIVE>\x1b[2m18:41:29 \x1b[0m\x1b[2;35mdebug: \x1b[0mResolving\n"
            ),
            "\x1b[?25l<LIVE>\x1b[1;36m⠋\x1b[0m Validating objects</LIVE>\x1b[2m00:00:00 \x1b[0m\x1b[2;35mdebug: \x1b[0mResolving\n"
        );
        // Only at the start of a line, and only before a log level.
        assert_eq!(norm("at 18:22:33 today"), "at 18:22:33 today");
        assert_eq!(norm("12:30:00 lunch\n"), "12:30:00 lunch\n");
    }

    #[test]
    fn crash_log_names() {
        assert_eq!(
            norm(
                "log: /tmp/golden-abc123/home/.local/state/opentide/crash-20261108T101112123456Z-4242.log"
            ),
            "log: <HOME>/.local/state/opentide/crash-<TIMESTAMP>-<PID>.log"
        );
        // Only the timestamped name is masked.
        for kept in ["crash-handler.log", "crash-2026.log"] {
            assert_eq!(norm(kept), kept);
        }
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
    fn git_version_only_where_asked() {
        let mut doctor = Normaliser::new(&volatile(), &[Rule::HostGit], []);
        assert_eq!(
            doctor.text("✓ git 2.43.0 · git"),
            "✓ git <GIT_VERSION> · git"
        );
        assert_eq!(doctor.text("tool 2.43.0"), "tool 2.43.0");
        // Help text quotes the same line as an example: it is content.
        assert_eq!(
            norm("Example\n\n✓ git 2.43.0 · git"),
            "Example\n\n✓ git 2.43.0 · git"
        );
    }

    #[test]
    fn catalog_cache_fingerprints() {
        // A hash of the installation's paths and file times.
        assert_eq!(
            norm("home/.cache/opentide/lsp-catalogs/1b710955f6665676aede66615e5c3e59/fields.json"),
            "home/.cache/opentide/lsp-catalogs/<CATALOG-FINGERPRINT>/fields.json"
        );
        assert_eq!(
            norm("objects/1b710955f6665676aede66615e5c3e59"),
            "objects/1b710955f6665676aede66615e5c3e59"
        );
    }

    /// A deploy progress row as Rich draws it first: before the first
    /// update, or (on a loaded machine) after it; the last frame, kept on
    /// screen, is the same either way.
    const BARE_ROW: &str = "  \x1b[1;36m⠋\x1b[0m  \x1b[1;36mcrowdstrike\x1b[0m\x1b[1m  \x1b[0m\x1b[2m \x1b[0m\x1b[2m0.1s\x1b[0m\x1b[2m \x1b[0m";
    const UPDATED_ROW: &str = "  \x1b[1;36m⠙\x1b[0m  \x1b[1;36mcrowdstrike\x1b[0m\x1b[1m  \x1b[0m\x1b[2m3 rules\x1b[0m\x1b[2m \x1b[0m\x1b[2m0.2s\x1b[0m\x1b[2m \x1b[0m\x1b[2mCrowdStrike create rule\x1b[0m";

    fn deploy_stream(first: &str) -> String {
        format!(
            "{HIDE_CURSOR}{first}\r\x1b[2K{UPDATED_ROW}\r\x1b[2K{UPDATED_ROW}\n{SHOW_CURSOR}warning: done\n"
        )
    }

    #[test]
    fn live_progress_normalises_every_first_frame_the_same() {
        let progress =
            |text: &str| Normaliser::new(&volatile(), &[Rule::LiveProgress], []).text(text);
        let bare = progress(&deploy_stream(BARE_ROW));
        assert_eq!(bare, progress(&deploy_stream(UPDATED_ROW)));
        // Nothing drawn before the region ends.
        assert_eq!(
            progress(&format!(
                "{HIDE_CURSOR}{UPDATED_ROW}\n{SHOW_CURSOR}warning: done\n"
            )),
            bare
        );
        assert!(
            bare.starts_with("\x1b[?25l<LIVE><PROGRESS></LIVE>"),
            "{bare:?}"
        );
        // What follows the region is still compared.
        assert_ne!(
            bare,
            progress(&deploy_stream(BARE_ROW).replace("done", "other"))
        );
    }

    #[test]
    fn live_progress_drops_a_progress_row_that_runs_into_a_printed_line() {
        let label = |text: &str| Normaliser::new(&volatile(), &[Rule::LiveProgress], []).text(text);
        let warning = "\x1b[1;33mwarning: \x1b[0mRetrying\n";
        let stream = |leak: &str| {
            format!(
                "{HIDE_CURSOR}{BARE_ROW}\r\x1b[2K{leak}{warning}{UPDATED_ROW}\r\x1b[2K{UPDATED_ROW}\n{SHOW_CURSOR}done\n"
            )
        };
        let clean = label(&stream(""));
        assert_eq!(label(&stream(UPDATED_ROW)), clean);
        assert!(clean.contains(warning), "{clean:?}");
        // Without the rule the leaked row is still a difference.
        assert_ne!(norm(&stream(UPDATED_ROW)), norm(&stream("")));
    }

    #[test]
    fn without_live_progress_the_whole_first_frame_is_compared() {
        let bare = norm(&deploy_stream(BARE_ROW));
        let updated = norm(&deploy_stream(UPDATED_ROW));
        assert_ne!(bare, updated);
        assert!(bare.starts_with("\x1b[?25l<LIVE>  \x1b[1;36m<SPIN>\x1b[0m  \x1b[1;36mcrowdstrike\x1b[0m\x1b[1m  \x1b[0m\x1b[2m \x1b[0m"));
        assert!(!bare.contains("<PROGRESS>"));
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
    fn uuids_from_the_argv_and_the_bundled_data_stay_literal() {
        // `new objective --threat <uuid>` echoes the argv's UUID; a bundled
        // vocabulary's UUIDs are the engine's data: neither was minted.
        let argv = "00000000-0000-4000-8000-000000000000";
        let bundled = "4d3c2b1a-0f9e-4d8c-b7a6-958473625140";
        let minted = "9f1c2b3a-1111-4222-8333-444455556666";
        let volatile = Volatile {
            known_uuids: [argv.to_owned(), bundled.to_owned()].into_iter().collect(),
            ..volatile()
        };
        let mut n = Normaliser::new(&volatile, &[Rule::FreshUuids], []);
        assert_eq!(
            n.text(&format!(
                "threat {argv} not found; tactic {bundled}; created {minted}"
            )),
            format!("threat {argv} not found; tactic {bundled}; created <UUID-1>")
        );
        // A different UUID in the output is not hidden behind the argv's.
        assert_ne!(
            n.text("threat 00000000-0000-4000-8000-0000000000ff not found"),
            format!("threat {argv} not found")
        );
    }

    #[test]
    fn live_region_keeps_its_first_frame_and_drops_the_rest_transient() {
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
        let expected = format!(
            "{HIDE_CURSOR}<LIVE>\x1b[1;36m<SPIN>\x1b[0m Validating objects</LIVE>{SHOW_CURSOR}\r\x1b[1A\x1b[2K"
        );
        assert_eq!(live_regions(&stream), expected);
        assert_eq!(live_regions(&fewer), expected);
        // V857-I-3: a port with another label differs.
        let other = format!(
            "{HIDE_CURSOR}{}\n{SHOW_CURSOR}\r\x1b[1A\x1b[2K",
            spin("⠋").replace("Validating", "Checking")
        );
        assert_ne!(live_regions(&other), expected);
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
                "before\n{HIDE_CURSOR}<LIVE>{}</LIVE>warning: x\n{}\n{SHOW_CURSOR}after\n",
                frame(1),
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
    fn opentide_version_is_replaced_as_a_whole_token() {
        assert_eq!(
            opentide_version(
                "opentide 0.23.0\n  version  0.23.0\n{\"opentide\":\"0.23.0\"} (0.23.0)",
                "0.23.0"
            ),
            "opentide <OPENTIDE_VERSION>\n  version  <OPENTIDE_VERSION>\n\
             {\"opentide\":\"<OPENTIDE_VERSION>\"} (<OPENTIDE_VERSION>)"
        );
        // The candidate's build version, whole, with its local part.
        assert_eq!(
            opentide_version(
                "opentide 0.23.1.dev719+g1f903689",
                "0.23.1.dev719+g1f903689"
            ),
            "opentide <OPENTIDE_VERSION>"
        );
    }

    #[test]
    fn opentide_version_leaves_other_versions_alone() {
        let text = "pydantic 2.11.0 · typer 0.23.1 · 10.23.0 · 0.23.01 · v0.23.0x \
                    · 0.23.0.dev1 · 0.23.0+local · 1.0.23.0\nversion: 1\nversion: 0.23\n";
        assert_eq!(opentide_version(text, "0.23.0"), text);
        assert_eq!(opentide_version("0.23.0", ""), "0.23.0");
    }

    #[test]
    fn opentide_version_leaves_a_rules_version_field_alone() {
        // A rule carries its own `version`; only opentide's string is replaced.
        let rule = "name: Example\nversion: 3\nmeta:\n  version: 2.0.1\n";
        assert_eq!(opentide_version(rule, "0.23.0"), rule);
        assert_eq!(
            opentide_version(&format!("{rule}generated by opentide 0.23.0\n"), "0.23.0"),
            format!("{rule}generated by opentide <OPENTIDE_VERSION>\n")
        );
    }

    #[test]
    fn opentide_version_in_a_run_covers_streams_and_text_files() {
        let mut run = Run {
            exit_code: 0,
            stdout: b"opentide 0.23.0\n".to_vec(),
            stderr: b"0.23.0".to_vec(),
            files: [
                (
                    "a.json".to_owned(),
                    FileState::Written {
                        mode: 0o644,
                        bytes: b"{\"opentide\": \"0.23.0\"}".to_vec(),
                    },
                ),
                (
                    "b.bin".to_owned(),
                    FileState::Written {
                        mode: 0o644,
                        bytes: vec![0xff, b'0', b'.', b'2', b'3', b'.', b'0'],
                    },
                ),
                ("c".to_owned(), FileState::Deleted),
            ]
            .into_iter()
            .collect(),
        };
        opentide_version_in_run(&mut run, "0.23.0");
        assert_eq!(run.stdout, b"opentide <OPENTIDE_VERSION>\n");
        assert_eq!(run.stderr, b"<OPENTIDE_VERSION>");
        let bytes = |path: &str| match &run.files[path] {
            FileState::Written { bytes, .. } => bytes.clone(),
            FileState::Deleted => Vec::new(),
        };
        assert_eq!(bytes("a.json"), b"{\"opentide\": \"<OPENTIDE_VERSION>\"}");
        assert_eq!(
            bytes("b.bin"),
            vec![0xff, b'0', b'.', b'2', b'3', b'.', b'0']
        );
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc_date(UNIX_EPOCH), "1970-01-01");
        assert_eq!(
            utc_date(UNIX_EPOCH + Duration::from_hours(498_336)),
            "2026-11-07"
        );
        assert_eq!(
            utc_date(UNIX_EPOCH + Duration::from_hours(264_384)),
            "2000-02-29"
        );
    }
}
