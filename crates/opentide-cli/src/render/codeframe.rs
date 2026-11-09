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

/// Python's `urllib.parse.quote`: everything but letters, digits, `_.-~` and `safe`
/// percent-encoded, as UTF-8.
pub fn quote(text: &str, safe: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        let ch = char::from(byte);
        if byte.is_ascii_alphanumeric()
            || "_.-~".contains(ch)
            || (byte.is_ascii() && safe.contains(ch))
        {
            out.push(ch);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
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
        return Some(format!("file://{}", quote(&posix, "/")));
    }
    let mut target = quote(&posix, "/:");
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

/// A Python `repr` of a string, as the fix note quotes a replacement.
pub fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
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
            .map(|edit| py_repr(&edit.replacement))
            .collect();
        notes.push((
            "fix".to_owned(),
            format!("replace with {}", values.join(", ")),
        ));
    }
    notes
}

/// `text` in lines of at most `width` cells, each after the first led by `indent`.
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
        let window_end = (start + room + 1).min(plain.len());
        let window = &plain[start..window_end];
        let space = window.iter().rposition(|ch| *ch == ' ');
        let slash = window[..room.min(window.len())]
            .iter()
            .rposition(|ch| *ch == '/');
        let (end, resume) = match (space, slash) {
            (Some(space), _) if space > 0 => (start + space, start + space + 1),
            (_, Some(slash)) if slash > 0 => (start + slash + 1, start + slash + 1),
            _ => (start + room, start + room),
        };
        lines.push(text.slice(start, end));
        start = resume;
        room = width.saturating_sub(indent.cell_len());
    }
    lines.push(text.slice(start, plain.len()));
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
    let chars: Vec<char> = location.chars().collect();
    let head_text: String = chars.iter().take(head).collect();
    let tail_text: String = chars[chars.len().saturating_sub(tail)..].iter().collect();
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
        let mut lines = match self.columns {
            Some(columns) if columns > 0 => wrap_text(&header, columns, &Text::plain("  ")),
            _ => vec![header],
        };

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
            let mut shown = location;
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
                let end = diagnostic.single_line_end().unwrap_or(column + 1);
                let marked = char_slice(source, column.saturating_sub(1), end.saturating_sub(1))
                    .replace('\t', " ");
                let length = if marked.is_empty() {
                    end.saturating_sub(column)
                } else {
                    cell_len(&marked)
                }
                .max(1);
                let mut row = gutter(None);
                row.push_str(&format!(" {}", underline_offset(source, column)));
                row.append(&glyphs::UNDERLINE.repeat(length), &style);
                if let Some(label) = diagnostic.label.as_ref().filter(|label| !label.is_empty()) {
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
            let Some(columns) = self.columns.filter(|columns| *columns > 0) else {
                lines.push(row);
                continue;
            };
            // Continuation lines keep the frame's bar and start under the text.
            let mut indent = Text::plain(&pad);
            indent.append(if last { " " } else { glyphs::FRAME_BAR }, &blue);
            let fill = lead.saturating_sub(indent.cell_len());
            indent.push_str(&" ".repeat(fill));
            lines.extend(wrap_text(&row, columns, &indent));
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
        let shown: Vec<&Diagnostic> = diagnostics
            .iter()
            .filter(|item| !quiet || item.severity == Severity::Error)
            .collect();
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
        out
    }
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
            py_repr(&change.before)
        ));
        line.push_str(glyphs::NEXT);
        line.push_str(&format!(" {}", py_repr(&change.after)));
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
        assert_eq!(quote("/a b#c/名.yaml", "/"), "/a%20b%23c/%E5%90%8D.yaml");
        assert_eq!(quote("C:/x", "/:"), "C:/x");
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
        assert_eq!(py_repr("clear"), "'clear'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("a'\"b\n"), "'a\\'\"b\\n'");
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

    #[test]
    fn diff_and_fixed() {
        assert_eq!(render_diff("", Colour::Full), "");
        assert_eq!(
            render_diff("--- a\n+x\n y", Colour::Full),
            "\u{1b}[1m--- a\u{1b}[0m\n\u{1b}[32m+x\u{1b}[0m\n y\n\n"
        );
        let change = FixedValue {
            file_path: PathBuf::from("/ws/objects/x.yaml"),
            path: "objects/x.yaml".into(),
            line: 8,
            column: 8,
            before: "clearr".into(),
            after: "clear".into(),
        };
        assert_eq!(
            render_fixed(
                std::slice::from_ref(&change),
                Path::new("/ws"),
                Colour::None
            ),
            "fixed: objects/x.yaml:8:8 'clearr' → 'clear'\n\n"
        );
        assert_eq!(
            render_fixed(&[change], Path::new("/elsewhere"), Colour::None),
            "fixed: objects/x.yaml:8:8 'clearr' → 'clear'\n\n"
        );
        assert_eq!(render_fixed(&[], Path::new("/"), Colour::None), "");
    }
}
