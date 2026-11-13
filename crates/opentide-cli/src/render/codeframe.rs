//! Diagnostics as code frames, for the `human`, `plain` and `agent` modes.
//!
//! ```text
//! error[vocab_unknown]: Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry
//!   ╭─▶ objects/rules/sentinel-kql-rule.yaml:8:8
//!   │
//! 7 │   modified: 2026-01-02
//! 8 │   tlp: clearr
//!   │        ━━━━━━ not in tlp::1.0
//!   │
//!   ╰─ help: did you mean 'clear'?
//! ```
//!
//! The layout is the CLI's contract (plan §3 invariant 1, `docs/cli/diagnostics.md`), so it
//! is drawn here rather than by `annotate-snippets`: rustc's renderer draws ` --> `,
//! `^^^` and `= help:` (or, in its Unicode style, `╭▸` and `╰╴`), always numbers the
//! underline row's gutter differently and shows no previous line, and none of that can
//! be configured to this frame.
//!
//! Diagnostics are grouped by file and ordered by line. A frame line is never
//! wrapped by the terminal: at a terminal ([`Frames::columns`]) the message and
//! notes wrap at a space or after a `/`, and the location is shortened in the
//! middle; on a pipe each line is whole. The underline is placed by terminal
//! cell, so it stays under its value after a tab or a wide character. In
//! `human` mode the location is an OSC 8 link and query lines are coloured as
//! the editor colours them.

use super::diagnostic::{Diagnostic, Severity, Sources, relative_path, sort_diagnostics};
use super::glyphs;
use super::text::{Colour, Style, Text, cell_len, char_width};
use crate::env::Env;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// How frames are drawn on one stream.
#[derive(Clone, Debug)]
pub struct Frames {
    /// The styles the stream gets.
    pub colour: Colour,
    /// Whether locations are hyperlinks (`human` mode).
    pub links: bool,
    /// The terminal's width; `None` on a pipe or a file, whose reader wraps lines itself.
    pub columns: Option<usize>,
    /// Whether query lines are coloured (`human` mode).
    pub highlight: bool,
    /// Where paths are shown relative to: the current directory.
    pub cwd: PathBuf,
    /// The environment the link scheme is read from (`OPENTIDE_LINKS`, `TERM_PROGRAM`).
    pub env: Env,
}

/// `OPENTIDE_LINKS` values.
pub const LINK_SCHEMES: [&str; 4] = ["file", "vscode", "cursor", "none"];

/// The query languages' reference pages, by the code prefix of their findings.
pub const ENGINE_REFERENCES: [(&str, &str, &str); 9] = [
    ("kql_", "KQL", "https://learn.microsoft.com/kusto/query/"),
    (
        "spl_",
        "SPL",
        "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference",
    ),
    (
        "esql_",
        "ES|QL",
        "https://www.elastic.co/docs/reference/query-languages/esql",
    ),
    (
        "eql_",
        "EQL",
        "https://www.elastic.co/docs/reference/query-languages/eql",
    ),
    (
        "kuery_",
        "Kibana KQL",
        "https://www.elastic.co/docs/reference/query-languages/kql",
    ),
    (
        "lucene_",
        "Lucene query string",
        "https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query",
    ),
    (
        "ecs_",
        "ECS field",
        "https://www.elastic.co/docs/reference/ecs/ecs-field-reference",
    ),
    (
        "falco_",
        "Falco condition",
        "https://falco.org/docs/concepts/rules/conditions/",
    ),
    (
        "cql_",
        "CQL",
        "https://library.humio.com/crowdstrike-query-language/",
    ),
];

/// `(language, url)` of the reference for an engine `code`, when it is a query code.
pub fn engine_reference(code: &str) -> Option<(&'static str, &'static str)> {
    ENGINE_REFERENCES
        .iter()
        .find(|(prefix, _, _)| code.starts_with(prefix))
        .map(|(_, language, url)| (*language, *url))
}

/// The style of a severity's header and underline.
fn severity_style(severity: Severity) -> Style {
    Style::new(match severity {
        Severity::Error => "bold red",
        Severity::Warning => "bold yellow",
        Severity::Note => "bold blue",
    })
}

fn note_style(label: &str) -> Style {
    Style::new(match label {
        "help" | "fix" => "bold cyan",
        "note" => "bold blue",
        _ => "bold",
    })
}

fn gutter_style() -> Style {
    Style::new("blue")
}

/// Whitespace as Python's `str.strip` sees it: Unicode's, plus the four
/// separator controls U+001C to U+001F.
fn is_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

fn rstrip(text: &str) -> &str {
    text.trim_end_matches(is_space)
}

/// Characters `start..end` of `text`, clamped as a Python slice is.
fn char_slice(text: &str, start: usize, end: usize) -> String {
    if end <= start {
        return String::new();
    }
    text.chars().skip(start).take(end - start).collect()
}

/// What a path keeps unencoded in a link or a SARIF URI: letters, digits,
/// `_.-~` and the `/` separator, as `urllib.parse.quote(path)` keeps them.
pub const PATH_SAFE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~')
    .remove(b'/');

/// [`PATH_SAFE`] and `:`, for an editor link's `path:line:column`.
pub const EDITOR_SAFE: &AsciiSet = &PATH_SAFE.remove(b':');

/// `text` percent-encoded as UTF-8, every byte outside `safe` as `%XX`.
pub fn quote(text: &str, safe: &'static AsciiSet) -> String {
    utf8_percent_encode(text, safe).to_string()
}

/// The OSC 8 target for a location: `file://` unless the editor can open a line.
///
/// `OPENTIDE_LINKS` picks the scheme; otherwise `vscode://` when
/// `TERM_PROGRAM=vscode` (Cursor reports it as well), else `file://`.
pub fn link_url(
    file_path: &Path,
    line: Option<usize>,
    column: Option<usize>,
    cwd: &Path,
    env: &Env,
) -> Option<String> {
    let requested = env
        .get("OPENTIDE_LINKS")
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let scheme = if LINK_SCHEMES.contains(&requested.as_str()) {
        requested
    } else if env.get("TERM_PROGRAM").unwrap_or_default().to_lowercase() == "vscode" {
        "vscode".to_owned()
    } else {
        "file".to_owned()
    };
    if scheme == "none" {
        return None;
    }
    let absolute = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        cwd.join(file_path)
    };
    let posix = absolute.to_string_lossy().replace('\\', "/");
    if scheme == "file" {
        let posix = if posix.starts_with('/') {
            posix
        } else {
            format!("/{posix}")
        };
        return Some(format!("file://{}", quote(&posix, PATH_SAFE)));
    }
    let mut target = quote(&posix, EDITOR_SAFE);
    if let Some(line) = line {
        target.push_str(&format!(":{line}"));
        if let Some(column) = column {
            target.push_str(&format!(":{column}"));
        }
    }
    Some(format!(
        "{scheme}://file/{}",
        target.trim_start_matches('/')
    ))
}

/// Blanks that reach `column` in `source` as the terminal draws it: tabs kept,
/// so they expand to the same stop, and a wide character as many spaces as its cells.
pub fn underline_offset(source: &str, column: usize) -> String {
    source
        .chars()
        .take(column.saturating_sub(1))
        .map(|ch| {
            if ch == '\t' {
                "\t".to_owned()
            } else {
                " ".repeat(char_width(ch))
            }
        })
        .collect()
}

/// The cell a terminal reaches after writing `text` from cell `from`: a tab
/// moves to the next stop of 8, as [`Text::expand_tabs`] expands it.
pub fn expanded_end(text: &str, from: usize) -> usize {
    text.chars().fold(from, |cell, ch| {
        if ch == '\t' {
            (cell / 8 + 1) * 8
        } else {
            cell + char_width(ch)
        }
    })
}

/// The path to show: relative to `cwd` when inside it, else the workspace path.
pub fn display_path(diagnostic: &Diagnostic, cwd: &Path) -> Option<String> {
    let Some(file_path) = &diagnostic.file_path else {
        return diagnostic.path.clone();
    };
    let shown = relative_path(file_path, Some(cwd));
    if Path::new(&shown).is_absolute()
        && let Some(path) = &diagnostic.path
    {
        return Some(path.clone());
    }
    Some(shown)
}

fn location(diagnostic: &Diagnostic, cwd: &Path) -> Option<String> {
    let mut shown = display_path(diagnostic, cwd)?;
    if let Some(line) = diagnostic.line {
        shown.push_str(&format!(":{line}"));
        if let Some(column) = diagnostic.column {
            shown.push_str(&format!(":{column}"));
        }
    }
    Some(shown)
}

/// A quoted value, as the fix note, `fixed:` and "did you mean" show it.
///
/// Quoted as Python's `repr` quotes (`'clear'`, `"it's"`), with what is inside
/// escaped by [`str::escape_debug`]: a character that is not printable reads
/// `\u{a0}` or `\u{1b}` (Python wrote `\xa0`), and only the quote that
/// delimits the value is escaped.
pub fn quoted(text: &str) -> String {
    let (quote, other) = if text.contains('\'') && !text.contains('"') {
        ('"', '\'')
    } else {
        ('\'', '"')
    };
    let mut out = String::from(quote);
    // Every `\` in `escape_debug`'s output starts an escape of two or more
    // characters; the one for the other quote is undone.
    let mut escaped = text.escape_debug();
    while let Some(ch) = escaped.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match escaped.next() {
            Some(next) if next == other => out.push(next),
            Some(next) => {
                out.push('\\');
                out.push(next);
            }
            None => out.push('\\'),
        }
    }
    out.push(quote);
    out
}

fn notes(diagnostic: &Diagnostic) -> Vec<(String, String)> {
    let mut notes = diagnostic.notes.clone();
    if let Some(help) = diagnostic.help.as_deref().filter(|help| !help.is_empty()) {
        notes.push(("help".to_owned(), help.to_owned()));
    } else if let Some(fix) = diagnostic.fix.as_ref().filter(|fix| !fix.edits.is_empty()) {
        let values: Vec<String> = fix
            .edits
            .iter()
            .map(|edit| quoted(&edit.replacement))
            .collect();
        notes.push((
            "fix".to_owned(),
            format!("replace with {}", values.join(", ")),
        ));
    }
    notes
}

/// `text` in lines of at most `width` cells, each after the first led by `indent`
/// (a character wider than a whole row is the one exception).
///
/// Breaks at a space, or after a `/` inside a word too long for the line (a
/// path), and mid-word only when neither is there. Styles carry over.
pub fn wrap_text(text: &Text, width: usize, indent: &Text) -> Vec<Text> {
    let plain: Vec<char> = text.as_plain().chars().collect();
    let cells = |start: usize| -> usize {
        plain[start.min(plain.len())..]
            .iter()
            .copied()
            .map(char_width)
            .sum()
    };
    let mut lines = Vec::new();
    let (mut start, mut room) = (0usize, width);
    while room > 0 && cells(start) > room {
        // The characters from `start` that fit in `room` cells (one at least,
        // so a character wider than the row still moves on).
        let mut used = 0;
        let fit = plain[start..]
            .iter()
            .take_while(|ch| {
                used += char_width(**ch);
                used <= room
            })
            .count()
            .max(1);
        // A space just past them still ends a row that fits.
        let window = &plain[start..(start + fit + 1).min(plain.len())];
        let space = window.iter().rposition(|ch| *ch == ' ');
        let slash = window[..fit.min(window.len())]
            .iter()
            .rposition(|ch| *ch == '/');
        let (end, resume) = match (space, slash) {
            (Some(space), _) if space > 0 => (start + space, start + space + 1),
            (_, Some(slash)) if slash > 0 => (start + slash + 1, start + slash + 1),
            _ => (start + fit, start + fit),
        };
        lines.push(text.slice(start, end));
        start = resume;
        room = width.saturating_sub(indent.cell_len());
    }
    // Only a character wider than a row can be the whole remainder.
    if start < plain.len() || lines.is_empty() || plain.get(start.saturating_sub(1)) == Some(&' ') {
        lines.push(text.slice(start, plain.len()));
    }
    lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                line
            } else {
                let mut led = indent.clone();
                led.append_text(&line);
                led
            }
        })
        .collect()
}

/// `location` in at most `room` cells, its middle folders replaced by `…`.
///
/// Keeps the first folder, the file name and the `:line:col`; cuts the middle
/// of what is left only when even that is too long.
pub fn shorten_path(location: &str, room: usize) -> String {
    if cell_len(location) <= room || room < 1 {
        return location.to_owned();
    }
    let parts: Vec<&str> = location.split('/').collect();
    if parts.len() > 2 {
        let mut kept: Vec<&str> = vec![parts[parts.len() - 1]];
        for part in parts[1..parts.len() - 1].iter().rev() {
            let mut candidate = vec![parts[0], "…", part];
            candidate.extend(&kept);
            if cell_len(&candidate.join("/")) > room {
                break;
            }
            kept.insert(0, part);
        }
        let mut shortened = vec![parts[0], "…"];
        shortened.extend(&kept);
        let shortened = shortened.join("/");
        if cell_len(&shortened) <= room {
            return shortened;
        }
    }
    let head = ((room.saturating_sub(1)) / 3).max(1);
    let tail = room.saturating_sub(1).saturating_sub(head).max(1);
    // Cut by cells: the start and the end of `location` that fit in `head`
    // and `tail` cells.
    let within = |cells: usize, chars: &mut dyn Iterator<Item = char>| -> Vec<char> {
        let mut used = 0;
        chars
            .take_while(|ch| {
                used += char_width(*ch);
                used <= cells
            })
            .collect()
    };
    let head_text: String = within(head, &mut location.chars()).into_iter().collect();
    let tail_text: String = within(tail, &mut location.chars().rev())
        .into_iter()
        .rev()
        .collect();
    format!("{head_text}…{tail_text}")
}

/// `(column, end_column, style)` spans of one source line of a file, 1-based code points.
pub trait LineStyles {
    /// The spans of line `line` (1-based) of `path`, whose text `sources` holds.
    fn styles(
        &mut self,
        path: &Path,
        line: usize,
        sources: &mut dyn Sources,
    ) -> Vec<(usize, usize, Style)>;
}

/// HighlightSpec capture → terminal style, for the query lines of a frame.
/// Captures not listed (variables, properties, punctuation, Tide keys) keep the
/// terminal's colour.
pub fn query_style(capture: &str) -> Option<&'static str> {
    Some(match capture {
        "keyword" | "operator.pipe" => "bold magenta",
        "operator" => "magenta",
        "function" | "function.builtin" | "macro" => "cyan",
        "type" => "bright_cyan",
        "string" => "green",
        "number" | "boolean" | "constant" => "yellow",
        "comment" => "dim",
        "error" => "red",
        _ => return None,
    })
}

/// A file's styled spans, by line.
type ByLine = HashMap<usize, Vec<(usize, usize, Style)>>;

/// The engine's highlight tokens for each file a frame shows, read once per file.
/// A file the engine cannot read is shown without colour: highlighting never
/// fails a command.
#[derive(Debug, Default)]
pub struct QueryHighlighter {
    files: HashMap<PathBuf, ByLine>,
}

impl QueryHighlighter {
    fn read(path: &Path, sources: &mut dyn Sources) -> ByLine {
        let mut by_line = ByLine::new();
        let Some(language) = language_of(path) else {
            return by_line;
        };
        let Some(text) = sources.text(path) else {
            return by_line;
        };
        // As a text file is read: every line break a `\n`.
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        for token in opentide_analysis::highlight(language, &text).tokens {
            let Some(style) = query_style(&token.capture) else {
                continue;
            };
            let (line, column) = position(&text, token.span.start);
            let (end_line, mut end_column) = position(&text, token.span.end);
            if (end_line, end_column) <= (line, column) {
                end_column = column + 1;
            } else if end_line != line {
                continue;
            }
            by_line
                .entry(line)
                .or_default()
                .push((column, end_column, Style::new(style)));
        }
        by_line
    }
}

/// The 1-based line and code-point column of byte `offset` in `text`.
fn position(text: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(text.len());
    let mut offset = offset;
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let start = before.rfind('\n').map_or(0, |at| at + 1);
    (line, text[start..offset].chars().count() + 1)
}

/// `opentide-yaml` for an object file, a query language for its extension.
fn language_of(path: &Path) -> Option<opentide_analysis::LanguageId> {
    let extension = path.extension()?.to_str()?;
    if matches!(extension.to_ascii_lowercase().as_str(), "yaml" | "yml") {
        return Some(opentide_analysis::LanguageId::TideYaml);
    }
    opentide_analysis::LanguageId::from_extension(extension)
}

impl LineStyles for QueryHighlighter {
    fn styles(
        &mut self,
        path: &Path,
        line: usize,
        sources: &mut dyn Sources,
    ) -> Vec<(usize, usize, Style)> {
        self.files
            .entry(path.to_path_buf())
            .or_insert_with(|| QueryHighlighter::read(path, sources))
            .get(&line)
            .cloned()
            .unwrap_or_default()
    }
}

impl Frames {
    /// The lines of one diagnostic's frame.
    pub fn diagnostic_lines(
        &self,
        diagnostic: &Diagnostic,
        sources: &mut dyn Sources,
        mut styles: Option<&mut dyn LineStyles>,
    ) -> Vec<Text> {
        let style = severity_style(diagnostic.severity);
        let bold = Style::new("bold");
        let mut header = Text::default();
        header.append(
            &format!("{}[{}]", diagnostic.severity.as_str(), diagnostic.code),
            &style,
        );
        header.append(": ", &bold);
        header.append(&diagnostic.message, &bold);
        // A line break in the message continues it on an indented row: no
        // printed line starts with text from a file.
        let mut lines = Vec::new();
        for (index, part) in header.split_lines().into_iter().enumerate() {
            let mut row = if index == 0 {
                Text::default()
            } else {
                Text::plain("  ")
            };
            row.append_text(&part);
            match self.columns {
                Some(columns) if columns > 0 => {
                    lines.extend(wrap_text(&row, columns, &Text::plain("  ")));
                }
                _ => lines.push(row),
            }
        }

        let source = match (&diagnostic.file_path, diagnostic.line) {
            (Some(path), Some(line)) => sources.line(path, line),
            _ => None,
        };
        let width = match (&source, diagnostic.line) {
            (Some(_), Some(line)) if line > 0 => line.to_string().len(),
            _ => 1,
        };
        let pad = " ".repeat(width + 1);
        let blue = gutter_style();
        let notes = notes(diagnostic);
        let gutter = |number: Option<usize>| -> Text {
            let mut text = Text::default();
            match number {
                Some(number) => text.append(&format!("{number:>width$} "), &blue),
                None => text.append(&pad, &blue),
            };
            text.append(glyphs::FRAME_BAR, &blue);
            text
        };

        if let Some(location) = location(diagnostic, &self.cwd) {
            let opener = if source.is_some() || !notes.is_empty() {
                glyphs::FRAME_OPEN
            } else {
                glyphs::FRAME_ONLY
            };
            let mut line = Text::plain(&pad);
            line.append(opener, &blue);
            line.push_str(" ");
            let url = if self.links {
                diagnostic.file_path.as_deref().and_then(|path| {
                    link_url(
                        path,
                        diagnostic.line,
                        diagnostic.column,
                        &self.cwd,
                        &self.env,
                    )
                })
            } else {
                None
            };
            // `␤`: a file name's line break stays on its row.
            let mut shown = location.replace('\n', "\u{2424}");
            if let Some(columns) = self.columns.filter(|columns| *columns > 0) {
                shown = shorten_path(&shown, columns.saturating_sub(line.cell_len()));
            }
            line.append(&shown, &url.map(Style::link).unwrap_or_default());
            lines.push(line);
        }

        if let (Some(source), Some(number)) = (&source, diagnostic.line) {
            lines.push(gutter(None));
            let file = diagnostic.file_path.clone();
            let previous = match (&file, number) {
                (Some(path), number) if number > 1 => sources.line(path, number - 1),
                _ => None,
            };
            let highlighted = engine_reference(&diagnostic.code).is_some();
            let mut source_text = |text: &str, line_number: usize| -> Text {
                let mut line = Text::plain(&format!(" {}", rstrip(text)));
                if highlighted && let (Some(styles), Some(path)) = (styles.as_deref_mut(), &file) {
                    for (column, end_column, span_style) in
                        styles.styles(path, line_number, &mut *sources)
                    {
                        line.stylize(&span_style, column, end_column);
                    }
                }
                line
            };
            if let Some(previous) = previous.filter(|text| !text.trim_matches(is_space).is_empty())
            {
                let mut row = gutter(Some(number - 1));
                row.append_text(&source_text(&previous, number - 1));
                lines.push(row);
            }
            let mut row = gutter(Some(number));
            row.append_text(&source_text(source, number));
            lines.push(row);
            if let Some(column) = diagnostic.column {
                let end = diagnostic
                    .single_line_end()
                    .unwrap_or(column.saturating_add(1));
                let marked = char_slice(source, column.saturating_sub(1), end.saturating_sub(1));
                // Measured as the terminal shows the row: the source starts one
                // cell after the gutter, and a tab reaches the next stop of 8.
                let from = gutter(None).cell_len() + 1;
                let prefix = char_slice(source, 0, column.saturating_sub(1));
                let span_start = expanded_end(&prefix, from);
                let length = if marked.is_empty() {
                    end.saturating_sub(column)
                } else {
                    expanded_end(&marked, span_start) - span_start
                }
                .max(1);
                let mut row = gutter(None);
                row.push_str(&format!(" {}", underline_offset(source, column)));
                row.append(&glyphs::UNDERLINE.repeat(length), &style);
                let label_lines: Vec<&str> = diagnostic
                    .label
                    .as_deref()
                    .filter(|label| !label.is_empty())
                    .map(|label| label.split('\n').collect())
                    .unwrap_or_default();
                if let Some(label) = label_lines.first() {
                    match self.columns {
                        Some(columns)
                            if columns > 0 && row.cell_len() + 1 + cell_len(label) > columns =>
                        {
                            // Past the edge the terminal would break the label
                            // mid-word: it goes on the next row, under the
                            // underline when it fits there.
                            lines.push(row);
                            row = gutter(None);
                            let mut offset = underline_offset(source, column);
                            if row.cell_len() + 1 + cell_len(&offset) + cell_len(label) > columns {
                                offset = String::new();
                            }
                            row.push_str(&format!(" {offset}"));
                            row.append(label, &style);
                        }
                        _ => {
                            row.append(&format!(" {label}"), &style);
                        }
                    }
                }
                // The label's further lines, each on its own row under the first.
                for part in label_lines.iter().skip(1) {
                    lines.push(row);
                    row = gutter(None);
                    row.push_str(&format!(" {}", underline_offset(source, column)));
                    row.append(part, &style);
                }
                lines.push(row);
            }
            if !notes.is_empty() {
                lines.push(gutter(None));
            }
        }

        let count = notes.len();
        for (index, (label, text)) in notes.iter().enumerate() {
            let last = index + 1 == count;
            let mut row = Text::plain(&pad);
            row.append(
                if last {
                    glyphs::FRAME_CLOSE
                } else {
                    glyphs::FRAME_NOTE
                },
                &blue,
            );
            row.push_str(" ");
            row.append(&format!("{label}:"), &note_style(label));
            let lead = row.cell_len() + 1;
            row.push_str(&format!(" {text}"));
            // Continuation lines keep the frame's bar and start under the text.
            let mut indent = Text::plain(&pad);
            indent.append(if last { " " } else { glyphs::FRAME_BAR }, &blue);
            let fill = lead.saturating_sub(indent.cell_len());
            indent.push_str(&" ".repeat(fill));
            // A line break in the note continues it on such a line too.
            for (index, part) in row.split_lines().into_iter().enumerate() {
                let part = if index == 0 {
                    part
                } else {
                    let mut continued = indent.clone();
                    continued.append_text(&part);
                    continued
                };
                match self.columns.filter(|columns| *columns > 0) {
                    Some(columns) => lines.extend(wrap_text(&part, columns, &indent)),
                    None => lines.push(part),
                }
            }
        }
        lines
    }

    /// Every diagnostic as a frame, a blank line after each one, as the stream gets
    /// it. `quiet` keeps errors only.
    pub fn render(
        &self,
        diagnostics: &[Diagnostic],
        sources: &mut dyn Sources,
        quiet: bool,
    ) -> String {
        self.render_notes(diagnostics, sources, quiet, true).0
    }

    /// [`Frames::render`], and with `notes` false without the notes (a
    /// missing optional field, say): `validate`, `lint` and `validate query`
    /// leave them out without `--verbose`. Also how many notes it left out,
    /// for [`crate::commands::Terminal::hidden_notes_step`].
    pub fn render_notes(
        &self,
        diagnostics: &[Diagnostic],
        sources: &mut dyn Sources,
        quiet: bool,
        notes: bool,
    ) -> (String, usize) {
        let shown: Vec<&Diagnostic> = diagnostics
            .iter()
            .filter(|item| shows(item.severity, quiet, notes))
            .collect();
        let hidden = if notes || quiet {
            0
        } else {
            diagnostics.len() - shown.len()
        };
        let mut highlighter = QueryHighlighter::default();
        let mut out = String::new();
        for diagnostic in sort_diagnostics(shown) {
            let styles: Option<&mut dyn LineStyles> = if self.highlight {
                Some(&mut highlighter)
            } else {
                None
            };
            for mut line in self.diagnostic_lines(diagnostic, sources, styles) {
                line.expand_tabs();
                out.push_str(&line.render(self.colour, self.links));
                out.push('\n');
            }
            out.push('\n');
        }
        (out, hidden)
    }
}

/// Whether a finding of `severity` prints (`shows`): `quiet` keeps errors,
/// `notes` false leaves out notes.
fn shows(severity: Severity, quiet: bool, notes: bool) -> bool {
    if quiet {
        return severity == Severity::Error;
    }
    notes || severity != Severity::Note
}

/// A unified diff (`validate --fix --dry-run`): `+` lines green, `-` lines red, then a blank line.
pub fn render_diff(diff: &str, colour: Colour) -> String {
    if diff.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for raw in diff.lines() {
        let style = [
            ("+++", "bold"),
            ("---", "bold"),
            ("@@", "cyan"),
            ("+", "green"),
            ("-", "red"),
        ]
        .iter()
        .find(|(prefix, _)| raw.starts_with(prefix))
        .map_or_else(Style::default, |(_, style)| Style::new(style));
        let mut line = Text::styled(raw, &style);
        line.expand_tabs();
        out.push_str(&line.render(colour, false));
        out.push('\n');
    }
    out.push('\n');
    out
}

/// One value `validate --fix` replaced.
#[derive(Clone, Debug)]
pub struct FixedValue {
    /// The file, absolute.
    pub file_path: PathBuf,
    /// The workspace path, shown when the file is outside the current directory.
    pub path: String,
    /// 1-based.
    pub line: usize,
    /// 1-based, code points.
    pub column: usize,
    /// The value before.
    pub before: String,
    /// The value after.
    pub after: String,
}

/// `fixed: objects/rules/x.yaml:8:8 'clearr' → 'clear'`, one line per value replaced.
pub fn render_fixed(changes: &[FixedValue], cwd: &Path, colour: Colour) -> String {
    if changes.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for change in changes {
        let mut shown = relative_path(&change.file_path, Some(cwd));
        if Path::new(&shown).is_absolute() {
            shown.clone_from(&change.path);
        }
        let mut line = Text::default();
        line.append("fixed:", &Style::new("bold green"));
        line.push_str(&format!(
            " {shown}:{}:{} {} ",
            change.line,
            change.column,
            quoted(&change.before)
        ));
        line.push_str(glyphs::NEXT);
        line.push_str(&format!(" {}", quoted(&change.after)));
        out.push_str(&line.render(colour, false));
        out.push('\n');
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_matches_python() {
        assert_eq!(
            quote("/a b#c/名.yaml", PATH_SAFE),
            "/a%20b%23c/%E5%90%8D.yaml"
        );
        assert_eq!(quote("C:/x", EDITOR_SAFE), "C:/x");
    }

    #[test]
    fn link_schemes() {
        let cwd = Path::new("/ws");
        let at = |pairs: &[(&str, &str)]| {
            link_url(
                Path::new("/ws/a b.yaml"),
                Some(3),
                Some(4),
                cwd,
                &Env::from_pairs(pairs.iter().copied()),
            )
        };
        assert_eq!(at(&[]).as_deref(), Some("file:///ws/a%20b.yaml"));
        assert_eq!(
            at(&[("TERM_PROGRAM", "vscode")]).as_deref(),
            Some("vscode://file/ws/a%20b.yaml:3:4")
        );
        assert_eq!(
            at(&[("OPENTIDE_LINKS", " Cursor ")]).as_deref(),
            Some("cursor://file/ws/a%20b.yaml:3:4")
        );
        assert_eq!(at(&[("OPENTIDE_LINKS", "none")]), None);
        assert_eq!(
            link_url(Path::new("rel.yaml"), None, None, cwd, &Env::default()).as_deref(),
            Some("file:///ws/rel.yaml")
        );
    }

    #[test]
    fn shorten_and_wrap() {
        assert_eq!(
            shorten_path("a/b/c/d/file.yaml:1:2", 19),
            "a/…/d/file.yaml:1:2"
        );
        assert_eq!(
            shorten_path("a/b/c/d/file.yaml:1:2", 18),
            "a/…/file.yaml:1:2"
        );
        assert_eq!(shorten_path("abcdefghijkl", 7), "ab…ijkl");
        assert_eq!(shorten_path("short", 10), "short");
        let lines = wrap_text(&Text::plain("aaa bbb/ccc/ddd"), 6, &Text::plain("  "));
        let plain: Vec<String> = lines.iter().map(Text::as_plain).collect();
        assert_eq!(plain, ["aaa", "  bbb/", "  ccc/", "  ddd"]);
        let lines = wrap_text(&Text::plain("abcdefghij"), 4, &Text::plain(" "));
        let plain: Vec<String> = lines.iter().map(Text::as_plain).collect();
        assert_eq!(plain, ["abcd", " efg", " hij"]);
    }

    #[test]
    fn repr_and_offsets() {
        assert_eq!(quoted("clear"), "'clear'");
        assert_eq!(quoted("it's"), "\"it's\"");
        assert_eq!(quoted("a'\"b\n"), "'a\\'\"b\\n'");
        assert_eq!(quoted("a\\b\t"), "'a\\\\b\\t'");
        // Not printable: escaped as Rust escapes it, never written raw.
        assert_eq!(
            quoted("a\u{a0}b\u{200b}\u{85}\u{1b}\0"),
            "'a\\u{a0}b\\u{200b}\\u{85}\\u{1b}\\0'"
        );
        // A combining mark after its letter is text, as Python shows it.
        assert_eq!(quoted("e\u{301}名"), "'e\u{301}名'");
        assert_eq!(underline_offset("\t名x", 4), "\t   ");
        assert_eq!(
            engine_reference("cql_parse"),
            Some((
                "CQL",
                "https://library.humio.com/crowdstrike-query-language/"
            ))
        );
        assert_eq!(engine_reference("vocab_unknown"), None);
        assert_eq!(position("ab\ncd", 4), (2, 2));
    }

    /// `notes` false leaves the notes out and counts them; `quiet` keeps
    /// errors only and hides nothing it would count (opentide 0.28.1).
    #[test]
    fn notes_print_only_when_asked_and_are_counted_when_left_out() {
        let frames = Frames {
            colour: Colour::None,
            links: false,
            columns: None,
            highlight: false,
            cwd: std::env::temp_dir(),
            env: Env::default(),
        };
        let found = [
            Diagnostic::new("e", Severity::Error, "broken"),
            Diagnostic::new("w", Severity::Warning, "style"),
            Diagnostic::new("n1", Severity::Note, "optional one"),
            Diagnostic::new("n2", Severity::Note, "optional two"),
        ];
        let mut sources = super::super::diagnostic::MemorySources::default();
        let (all, hidden) = frames.render_notes(&found, &mut sources, false, true);
        assert_eq!(hidden, 0);
        assert!(
            all.contains("optional one") && all.contains("style"),
            "{all}"
        );
        assert_eq!(all, frames.render(&found, &mut sources, false));
        let (some, hidden) = frames.render_notes(&found, &mut sources, false, false);
        assert_eq!(hidden, 2);
        assert!(!some.contains("optional") && some.contains("style") && some.contains("broken"));
        let (quiet, hidden) = frames.render_notes(&found, &mut sources, true, false);
        assert_eq!(hidden, 0);
        assert!(
            quiet.contains("broken") && !quiet.contains("style"),
            "{quiet}"
        );
    }

    /// A frame of `diagnostic` over `/…/ws/a.yaml` holding `text`, at `columns`.
    fn framed(diagnostic: &mut Diagnostic, text: &str, columns: Option<usize>) -> String {
        let cwd = std::env::temp_dir().join("ws");
        let file = cwd.join("a.yaml");
        diagnostic.file_path = Some(file.clone());
        diagnostic.path = Some("a.yaml".into());
        let mut sources = super::super::diagnostic::MemorySources::default();
        sources.texts.insert(file, text.to_owned());
        let frames = Frames {
            colour: Colour::None,
            links: false,
            columns,
            highlight: false,
            cwd,
            env: Env::default(),
        };
        frames.render(std::slice::from_ref(diagnostic), &mut sources, false)
    }

    fn at(line: usize, column: usize, end_column: usize) -> Diagnostic {
        let mut item = Diagnostic::new("x", Severity::Error, "m");
        item.line = Some(line);
        item.column = Some(column);
        item.end_column = Some(end_column);
        item
    }

    #[test]
    fn an_underline_covers_a_tab_inside_its_span() {
        let out = framed(&mut at(1, 4, 7), "k: a\tb\n", None);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[3], "1 │ k: a        b", "{out}");
        // `a` at cell 7, the tab to the stop at 16, `b` at cell 16.
        assert_eq!(lines[4], format!("  │    {}", "━".repeat(10)), "{out}");
        // A tab before the span moves it; the span after it is one cell.
        let out = framed(&mut at(1, 3, 4), "\tk: v\n", None);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[3], "1 │     k: v");
        assert_eq!(lines[4], "  │      ━");
        assert_eq!(expanded_end("a\tb", 4), 9);
        assert_eq!(expanded_end("\t", 8), 16);
    }

    #[test]
    fn wide_text_stays_within_the_terminal() {
        let columns = 20;
        let mut item = at(1, 4, 6);
        item.message = "漢字漢字漢字漢字漢字漢字漢字 漢字 漢字漢字漢字漢字漢字漢字漢字漢字".into();
        item.label = Some("名前".into());
        item.help = Some("名前名前名前名前名前名前 名前".into());
        let out = framed(&mut item, "k: 名前\n", Some(columns));
        for line in out.lines() {
            assert!(
                cell_len(line) <= columns,
                "{line:?} is wider than {columns}:\n{out}"
            );
        }
        let lines = wrap_text(
            &Text::plain("名前名前名前名前名前 x"),
            10,
            &Text::plain("  "),
        );
        let plain: Vec<String> = lines.iter().map(Text::as_plain).collect();
        assert_eq!(plain, ["名前名前名", "  前名前名", "  前 x"]);
        let shortened = shorten_path("名前名前名前名前名前名前.yaml:1:2", 9);
        assert!(cell_len(&shortened) <= 9, "{shortened}");
        assert_eq!(shortened, "名…ml:1:2");
        // A character wider than the row still moves on.
        let lines = wrap_text(&Text::plain("名名"), 1, &Text::default());
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn controls_and_line_breaks_from_a_file_never_reach_the_terminal_raw() {
        let mut item = at(1, 4, 5);
        item.message = "bad\n::error::x".into();
        item.label = Some("one\n::warning::y".into());
        item.help = Some("h\n::notice::z".into());
        let out = framed(&mut item, "k: \u{1b}[2Jv\u{9b}\n", None);
        assert!(!out.contains('\u{1b}') && !out.contains('\u{9b}'), "{out}");
        for line in out.lines() {
            assert!(!line.starts_with("::"), "{line:?}:\n{out}");
        }
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines,
            [
                "error[x]: bad",
                "  ::error::x",
                "  ╭─▶ a.yaml:1:4",
                "  │",
                "1 │ k: ␛[2Jv\u{fffd}",
                "  │    ━ one",
                "  │    ::warning::y",
                "  │",
                "  ╰─ help: h",
                "           ::notice::z",
                "",
            ]
        );
    }

    #[test]
    fn a_column_past_any_line_is_drawn_without_overflow() {
        let mut item = at(1, usize::MAX, 0);
        item.end_column = None;
        let out = framed(&mut item, "k: v\n", None);
        assert!(out.contains(&format!("a.yaml:1:{}", usize::MAX)), "{out}");
    }

    #[test]
    fn a_label_moves_to_its_own_row_only_past_the_edge() {
        let mut item = at(1, 4, 5);
        item.label = Some("ab".into());
        // `  │    ━ ab` is 11 cells.
        let fits = framed(&mut item, "k: v\n", Some(11));
        assert!(fits.lines().any(|line| line == "  │    ━ ab"), "{fits}");
        let past = framed(&mut item, "k: v\n", Some(10));
        let lines: Vec<&str> = past.lines().collect();
        let underline = lines.iter().position(|line| *line == "  │    ━");
        assert!(underline.is_some(), "{past}");
        assert_eq!(
            underline.map(|at| lines[at + 1]),
            Some("  │    ab"),
            "{past}"
        );
    }

    /// The styles the engine gives a line of a query file.
    fn styled_line(file: &str, text: &str, line: usize) -> Vec<(usize, usize, Style)> {
        let path = std::env::temp_dir().join(file);
        let mut sources = super::super::diagnostic::MemorySources::default();
        sources.texts.insert(path.clone(), text.to_owned());
        QueryHighlighter::default().styles(&path, line, &mut sources)
    }

    #[test]
    fn query_colours_land_on_code_point_columns() {
        // `é` and `名` before the tokens: two bytes and three, one column each.
        let text = "T | where Name == \"é名\" and Count > 3\n";
        let styles = styled_line("q.kql", text, 1);
        let string = styles
            .iter()
            .find(|(_, _, style)| *style == Style::new("green"))
            .map(|(column, end, _)| (*column, *end));
        // `"é名"` runs from column 19 up to 23 (exclusive).
        assert_eq!(string, Some((19, 23)), "{styles:?}");
        let number = styles
            .iter()
            .find(|(_, _, style)| *style == Style::new("yellow"))
            .map(|(column, end, _)| (*column, *end));
        assert_eq!(number, Some((36, 37)), "{styles:?}");
        // A token over two lines is left without colour on both.
        let text = "T\n| where x == \"a\nb\" and y > 1\n";
        for line in [2, 3] {
            let styles = styled_line("m.kql", text, line);
            assert!(
                styles
                    .iter()
                    .all(|(_, _, style)| *style != Style::new("green")),
                "line {line}: {styles:?}"
            );
        }
        assert_eq!(position("é名\nx", "é名".len()), (1, 3));
        assert_eq!(position("é名", 1), (1, 1));
    }

    #[test]
    fn diff_and_fixed() {
        assert_eq!(render_diff("", Colour::Full), "");
        assert_eq!(
            render_diff("--- a\n+x\n y", Colour::Full),
            "\u{1b}[1m--- a\u{1b}[0m\n\u{1b}[32m+x\u{1b}[0m\n y\n\n"
        );
        // Absolute on every platform (`/ws` is not on Windows).
        let base = std::env::temp_dir();
        let change = FixedValue {
            file_path: base.join("ws").join("objects").join("x.yaml"),
            path: "objects/x.yaml".into(),
            line: 8,
            column: 8,
            before: "clearr".into(),
            after: "clear".into(),
        };
        assert_eq!(
            render_fixed(
                std::slice::from_ref(&change),
                &base.join("ws"),
                Colour::None
            ),
            "fixed: objects/x.yaml:8:8 'clearr' → 'clear'\n\n"
        );
        // Outside the current directory: the workspace path.
        assert_eq!(
            render_fixed(&[change], &base.join("elsewhere"), Colour::None),
            "fixed: objects/x.yaml:8:8 'clearr' → 'clear'\n\n"
        );
        assert_eq!(render_fixed(&[], Path::new("/"), Colour::None), "");
    }
}
