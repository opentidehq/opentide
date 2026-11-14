//! Diagnostics as code frames, for the `human`, `plain` and `agent` modes.
//!
//! ```text
//! error[vocab_unknown]: Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry
//!   ╭▸ objects/rules/sentinel-kql-rule.yaml:8:8
//!   │
//! 7 │   modified: 2026-01-02
//! 8 │   tlp: clearr
//!   │        ━━━━━━ not in tlp::1.0
//!   │
//!   ╰ help: did you mean 'clear'?
//! ```
//!
//! [`annotate_snippets`] draws each frame, rustc's renderer in its Unicode
//! style: the header, the location, the line before and the line itself
//! with the span underlined and labelled, then the notes. Text from a file or
//! a message has its control characters shown, never written raw, and a line
//! break in a message continues on an indented row, so no printed line starts
//! with text from a file. Diagnostics are grouped by file and ordered by line.
//! At a terminal ([`Frames::columns`]) a source line too long for it is cut;
//! on a pipe each line is whole. In `human` mode the location is an OSC 8
//! link.

use super::diagnostic::{Diagnostic, Severity, Sources, relative_path, sort_diagnostics};
use super::glyphs;
use super::text::{Colour, Text, shown};
use crate::env::Env;
use annotate_snippets::renderer::DecorStyle;
use annotate_snippets::{AnnotationKind, Group, Level, Origin, Renderer, Snippet};
use anstyle::{AnsiColor, Style};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
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
    /// Where paths are shown relative to: the current directory.
    pub cwd: PathBuf,
    /// The environment the link scheme is read from (`OPENTIDE_LINKS`, `TERM_PROGRAM`).
    pub env: Env,
}

/// `OPENTIDE_LINKS` values.
pub const LINK_SCHEMES: [&str; 4] = ["file", "vscode", "cursor", "none"];

/// The query languages' reference pages, by the code prefix of their
/// findings: the one table `validate` and `lint` read (`crate::queries`).
pub use crate::queries::ENGINE_REFERENCES;

/// `(language, url)` of the reference for an engine `code`, when it is a query code.
pub fn engine_reference(code: &str) -> Option<(&'static str, &'static str)> {
    ENGINE_REFERENCES
        .iter()
        .find(|(prefix, _, _)| code.starts_with(prefix))
        .map(|(_, language, url)| (*language, *url))
}

/// What a path keeps unencoded in a link or a SARIF URI: the RFC 3986
/// unreserved characters (letters, digits, `_.-~`) and the `/` separator.
/// SARIF readers compare these URIs as text, so the set is part of the
/// report's contract.
pub const PATH_SAFE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~')
    .remove(b'/');

/// [`PATH_SAFE`] and `:`, for an editor link's `path:line:column`.
pub const EDITOR_SAFE: &AsciiSet = &PATH_SAFE.remove(b':');

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
        return Some(format!("file://{}", utf8_percent_encode(&posix, PATH_SAFE)));
    }
    let mut target = utf8_percent_encode(&posix, EDITOR_SAFE).to_string();
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

/// A value quoted as Python's `repr` quotes (`'clear'`, `"it's"`), with what is inside
/// escaped by [`str::escape_debug`]: a character that is not printable reads
/// `\u{a0}` or `\u{1b}` (Python wrote `\xa0`), and only the quote that
/// delimits the value is escaped. Kept only for `explain`'s unknown-code
/// message (`commands/explain.rs`) until it quotes with `{:?}` as every other
/// message does; then this goes.
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
            .map(|edit| format!("{:?}", edit.replacement))
            .collect();
        notes.push((
            "fix".to_owned(),
            format!("replace with {}", values.join(", ")),
        ));
    }
    notes
}

/// HighlightSpec capture → terminal style, for the query lines `opentide tui`
/// shows. Captures not listed (variables, properties, punctuation, Tide keys)
/// keep the terminal's colour.
pub fn query_style(capture: &str) -> Option<Style> {
    Some(match capture {
        "keyword" | "operator.pipe" => AnsiColor::Magenta.on_default().bold(),
        "operator" => AnsiColor::Magenta.on_default(),
        "function" | "function.builtin" | "macro" => AnsiColor::Cyan.on_default(),
        "type" => AnsiColor::BrightCyan.on_default(),
        "string" => AnsiColor::Green.on_default(),
        "number" | "boolean" | "constant" => AnsiColor::Yellow.on_default(),
        "comment" => Style::new().dimmed(),
        "error" => AnsiColor::Red.on_default(),
        _ => return None,
    })
}

impl Frames {
    /// The renderer for this stream: rustc's Unicode frame, in colour, in
    /// bold alone ([`Colour::Mono`]) or plain; as wide as the terminal, or
    /// whole on a pipe.
    fn renderer(&self) -> Renderer {
        let bold = Style::new().bold();
        let renderer = match self.colour {
            Colour::None => Renderer::plain(),
            Colour::Full => Renderer::styled(),
            Colour::Mono => Renderer::styled()
                .error(bold)
                .warning(bold)
                .info(bold)
                .note(bold)
                .help(bold)
                .line_num(bold)
                .context(bold)
                .addition(Style::new())
                .removal(Style::new()),
        };
        renderer
            .decor_style(DecorStyle::Unicode)
            .term_width(self.columns.unwrap_or(usize::from(u16::MAX)))
    }

    /// One diagnostic's frame, as [`annotate_snippets`] draws it: the header,
    /// the location (an OSC 8 link in `human` mode), the line before and the
    /// line itself with the span underlined and labelled, then the notes.
    pub fn frame(&self, diagnostic: &Diagnostic, sources: &mut dyn Sources) -> String {
        let level = match diagnostic.severity {
            Severity::Error => Level::ERROR,
            Severity::Warning => Level::WARNING,
            Severity::Note => Level::NOTE,
        };
        let title = level
            .primary_title(clean(&diagnostic.message))
            .id(clean(&diagnostic.code));
        let mut group = Group::with_title(title);
        // `␤`: a file name's line break stays on its row.
        let one_row = |shown: String| clean(&shown.replace('\n', "\u{2424}"));
        let location = location(diagnostic, &self.cwd).map(one_row);
        let path = display_path(diagnostic, &self.cwd).map(one_row);
        let file = diagnostic.file_path.as_deref();
        let line = |number: usize, sources: &mut dyn Sources| {
            file.and_then(|file| sources.line(file, number))
                .map(|text| clean(text.trim_end()))
        };
        if let Some((number, source)) = diagnostic
            .line
            .and_then(|number| Some((number, line(number, sources)?)))
        {
            let previous = (number > 1)
                .then(|| line(number - 1, sources))
                .flatten()
                .filter(|text| !text.trim().is_empty());
            let (text, first, offset) = match previous {
                Some(previous) => {
                    let offset = previous.len() + 1;
                    (format!("{previous}\n{source}"), number - 1, offset)
                }
                None => (source.clone(), number, 0),
            };
            let mut snippet = Snippet::source(text)
                .line_start(first)
                .path(path.clone())
                .fold(false);
            if let Some(column) = diagnostic.column {
                let end = diagnostic
                    .single_line_end()
                    .unwrap_or(column.saturating_add(1));
                let byte = |chars: usize| {
                    source
                        .char_indices()
                        .nth(chars)
                        .map_or(source.len(), |(at, _)| at)
                };
                let start = byte(column.saturating_sub(1));
                let stop = byte(end.saturating_sub(1)).max(start);
                let label = diagnostic
                    .label
                    .as_deref()
                    .filter(|label| !label.is_empty());
                snippet = snippet.annotation(
                    AnnotationKind::Primary
                        .span(offset + start..offset + stop)
                        .label(label.map(|label| clean(&label.replace('\n', " ")))),
                );
            }
            group = group.element(snippet);
        } else if let Some(path) = &path {
            // No line to show: the location alone.
            let mut origin = Origin::path(path.clone());
            if let Some(line) = diagnostic.line {
                origin = origin.line(line);
                if let Some(column) = diagnostic.column {
                    origin = origin.char_column(column);
                }
            }
            group = group.element(origin);
        }
        for (label, text) in notes(diagnostic) {
            let level = if matches!(label.as_str(), "help" | "fix") {
                Level::HELP
            } else {
                Level::NOTE
            };
            group = group.element(level.with_name(clean(&label)).message(clean(&text)));
        }
        let out = self.renderer().render(&[group]);
        let url = file.filter(|_| self.links).and_then(|file| {
            link_url(
                file,
                diagnostic.line,
                diagnostic.column,
                &self.cwd,
                &self.env,
            )
        });
        match (url, location) {
            (Some(url), Some(location)) => out.replacen(
                &location,
                &format!("\u{1b}]8;;{url}\u{1b}\\{location}\u{1b}]8;;\u{1b}\\"),
                1,
            ),
            _ => out,
        }
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
        let mut out = String::new();
        for diagnostic in sort_diagnostics(shown) {
            out.push_str(&self.frame(diagnostic, sources));
            out.push_str("\n\n");
        }
        (out, hidden)
    }
}

/// Text from a file or a message as a frame shows it: each character
/// [`shown`] (one a terminal would act on as a blank), so no escape sequence
/// reaches the terminal raw and a column still counts the same characters.
fn clean(text: &str) -> String {
    text.chars().map(|ch| shown(ch).unwrap_or(' ')).collect()
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
        let style = if raw.starts_with("+++") || raw.starts_with("---") {
            Style::new().bold()
        } else if raw.starts_with("@@") {
            AnsiColor::Cyan.on_default()
        } else if raw.starts_with('+') {
            AnsiColor::Green.on_default()
        } else if raw.starts_with('-') {
            AnsiColor::Red.on_default()
        } else {
            Style::new()
        };
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

/// `fixed: objects/rules/x.yaml:8:8 "clearr" → "clear"`, one line per value replaced.
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
        line.append("fixed:", &AnsiColor::Green.on_default().bold());
        line.push_str(&format!(
            " {shown}:{}:{} {:?} ",
            change.line, change.column, change.before
        ));
        line.push_str(glyphs::NEXT);
        line.push_str(&format!(" {:?}", change.after));
        out.push_str(&line.render(colour, false));
        out.push('\n');
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::super::diagnostic::MemorySources;
    use super::*;

    #[test]
    fn quote_matches_python() {
        assert_eq!(
            utf8_percent_encode("/a b#c/名.yaml", PATH_SAFE).to_string(),
            "/a%20b%23c/%E5%90%8D.yaml"
        );
        assert_eq!(utf8_percent_encode("C:/x", EDITOR_SAFE).to_string(), "C:/x");
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
        assert_eq!(
            engine_reference("cql_parse"),
            Some((
                "CQL",
                "https://library.humio.com/crowdstrike-query-language/"
            ))
        );
        // 0.28.1: the Graylog dialect's warnings have their reference, so
        // `lint` keeps them (`graylog_analyzed_field`, `graylog_regex_operator`).
        assert_eq!(
            engine_reference("graylog_analyzed_field").map(|(language, _)| language),
            Some("Graylog search query")
        );
        assert_eq!(engine_reference("vocab_unknown"), None);
        assert_eq!(
            engine_reference("yara_slow_pattern").map(|(language, _)| language),
            Some("YARA rule")
        );
        // 0.28.1's reference page, word for word.
        assert_eq!(
            engine_reference("exabeam_unknown_value"),
            Some((
                "Exabeam Query Language",
                "https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-syntax.html"
            ))
        );
    }

    /// `notes` false leaves the notes out and counts them; `quiet` keeps
    /// errors only and hides nothing it would count (opentide 0.28.1).
    #[test]
    fn notes_print_only_when_asked_and_are_counted_when_left_out() {
        let frames = Frames {
            colour: Colour::None,
            links: false,
            columns: None,
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
    fn a_frame_shows_the_header_location_lines_label_and_notes() {
        let mut item = at(2, 4, 10);
        item.label = Some("not in tlp::1.0".into());
        item.help = Some("did you mean 'clear'?".into());
        let out = framed(&mut item, "modified: 2026-01-02\nk: clearr\n", None);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "error[x]: m", "{out}");
        assert!(lines[1].ends_with("a.yaml:2:4"), "{out}");
        let at = |text: &str| lines.iter().position(|line| line.contains(text));
        let (previous, line) = (at("1 │ modified: 2026-01-02"), at("2 │ k: clearr"));
        assert!(previous.is_some() && previous < line, "{out}");
        let underline = at("━━━━━━ not in tlp::1.0");
        assert!(line < underline, "{out}");
        assert!(at("help: did you mean 'clear'?") > underline, "{out}");
        // Without a source line: the location alone, then the notes.
        let mut bare = Diagnostic::new("y", Severity::Warning, "w");
        bare.path = Some("a.yaml".into());
        bare.help = Some("h".into());
        let out = Frames {
            colour: Colour::None,
            links: false,
            columns: None,
            cwd: std::env::temp_dir(),
            env: Env::default(),
        }
        .render(&[bare], &mut MemorySources::default(), false);
        assert!(
            out.starts_with("warning[y]: w\n") && out.contains("a.yaml") && out.contains("help: h"),
            "{out}"
        );
    }

    #[test]
    fn colour_mono_and_links_follow_the_stream() {
        let mut item = at(1, 1, 2);
        let cwd = std::env::temp_dir().join("ws");
        item.file_path = Some(cwd.join("a.yaml"));
        item.path = Some("a.yaml".into());
        let mut sources = MemorySources::default();
        sources.texts.insert(cwd.join("a.yaml"), "k: v\n".into());
        let frames = |colour, links| Frames {
            colour,
            links,
            columns: Some(80),
            cwd: cwd.clone(),
            env: Env::default(),
        };
        let full =
            frames(Colour::Full, true).render(std::slice::from_ref(&item), &mut sources, false);
        assert!(
            full.contains("\u{1b}[31m") || full.contains("\u{1b}[91m"),
            "{full:?}"
        );
        assert!(full.contains("\u{1b}]8;;file://"), "{full:?}");
        let mono =
            frames(Colour::Mono, false).render(std::slice::from_ref(&item), &mut sources, false);
        assert!(mono.contains("\u{1b}[1m"), "{mono:?}");
        assert!(
            !mono.contains("\u{1b}[3") && !mono.contains("\u{1b}[9"),
            "{mono:?}"
        );
        let plain =
            frames(Colour::None, false).render(std::slice::from_ref(&item), &mut sources, false);
        assert!(!plain.contains('\u{1b}'), "{plain:?}");
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
        assert!(out.contains("1 │ k: ␛[2Jv\u{fffd}"), "{out}");
    }

    #[test]
    fn a_column_past_any_line_is_drawn_without_overflow() {
        let mut item = at(1, usize::MAX, 0);
        item.end_column = None;
        let out = framed(&mut item, "k: v\n", None);
        assert!(
            out.contains("a.yaml:1:5") && out.contains("1 │ k: v"),
            "{out}"
        );
        // Multi-byte characters before the column: the span lands on characters.
        let out = framed(&mut at(1, 4, 6), "é: 名前x\n", None);
        assert!(out.contains("1 │ é: 名前x"), "{out}");
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
            "fixed: objects/x.yaml:8:8 \"clearr\" → \"clear\"\n\n"
        );
        // Outside the current directory: the workspace path.
        assert_eq!(
            render_fixed(&[change], &base.join("elsewhere"), Colour::None),
            "fixed: objects/x.yaml:8:8 \"clearr\" → \"clear\"\n\n"
        );
        assert_eq!(render_fixed(&[], Path::new("/"), Colour::None), "");
    }
}
