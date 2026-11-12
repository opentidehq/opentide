//! The Catalogue tab's detail pane, as lines laid out at a width
//! (`tui_app.py`'s `diagnostic_text`, `source_view`, `object_page`): the
//! counts of what the language server and the last validate run report, the
//! object as a page read from its schema, or its file with line numbers,
//! coloured by the engine, each finding in place under its line.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use opentide_analysis::LanguageId;
use opentide_workspace::views::object::{FieldRow, LinkTarget, ObjectView, RowKind, Scalar};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthChar;

use super::model::Finding;
use super::text::{WHITE, inside, slashed};

/// The frame's blue.
const FRAME: Color = Color::Blue;

/// A severity's style.
pub fn severity_style(severity: &str) -> Style {
    let bold = Style::new().add_modifier(Modifier::BOLD);
    match severity {
        "error" => bold.fg(Color::Red),
        "warning" => bold.fg(Color::Yellow),
        "note" => bold.fg(Color::Blue),
        _ => bold,
    }
}

/// A severity's rank: errors first.
fn rank(severity: &str) -> u8 {
    match severity {
        "error" => 0,
        "warning" => 1,
        "note" => 2,
        _ => 3,
    }
}

/// The gutter mark of a line with a finding, the worst one's.
fn gutter_mark(severity: &str) -> &'static str {
    match severity {
        "error" => "✗",
        "warning" => "!",
        _ => "·",
    }
}

/// The tint behind a finding's span: a terminal cannot colour an underline
/// apart from its text, so the tokens keep their colours.
fn span_style(severity: &str) -> Style {
    let tint = match severity {
        "error" => Color::Rgb(0x5a, 0x1d, 0x1d),
        "warning" => Color::Rgb(0x4a, 0x3f, 0x12),
        _ => Color::Rgb(0x1f, 0x2f, 0x4f),
    };
    let style = Style::new().add_modifier(Modifier::UNDERLINED).bg(tint);
    if severity == "error" {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

fn dim() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}

fn bold() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

/// The style of a highlight capture, as the editor colours it.
pub fn capture_style(capture: &str) -> Option<Style> {
    if let Some(name) = crate::render::codeframe::query_style(capture) {
        return Some(named_style(name));
    }
    Some(match capture {
        "tide.keyword" => bold().fg(Color::Magenta),
        "tide.property" | "markdown.heading" | "markdown.strong" => bold(),
        "tide.schema" => Style::new().fg(Color::LightCyan),
        "tide.uuid" => Style::new().fg(Color::Yellow),
        "punctuation" | "punctuation.bracket" | "punctuation.delimiter" | "markdown.list" => dim(),
        "markdown.emphasis" => Style::new().add_modifier(Modifier::ITALIC),
        "markdown.code" => Style::new().fg(Color::Green),
        "markdown.link" => Style::new()
            .fg(Color::Cyan)
            .add_modifier(Modifier::UNDERLINED),
        "markdown.quote" => dim().add_modifier(Modifier::ITALIC),
        _ => return None,
    })
}

/// A style the renderers name (`bold magenta`), as ratatui's.
fn named_style(name: &str) -> Style {
    let mut style = Style::new();
    for word in name.split_whitespace() {
        style = match word {
            "bold" => style.add_modifier(Modifier::BOLD),
            "dim" => style.add_modifier(Modifier::DIM),
            "magenta" => style.fg(Color::Magenta),
            "cyan" => style.fg(Color::Cyan),
            "bright_cyan" => style.fg(Color::LightCyan),
            "green" => style.fg(Color::Green),
            "yellow" => style.fg(Color::Yellow),
            "red" => style.fg(Color::Red),
            _ => style,
        };
    }
    style
}

/// `text`, each character styled by the engine's tokens for `language`.
fn highlighted(text: &str, language: Option<LanguageId>) -> Vec<Vec<(char, Style)>> {
    let mut styles: Vec<Style> = vec![Style::new(); text.len() + 1];
    if let Some(language) = language {
        for token in opentide_analysis::highlight(language, text).tokens {
            let Some(style) = capture_style(&token.capture) else {
                continue;
            };
            let end = token.span.end.min(text.len());
            for slot in styles.iter_mut().take(end).skip(token.span.start) {
                *slot = slot.patch(style);
            }
        }
    }
    let mut lines = vec![Vec::new()];
    for (offset, ch) in text.char_indices() {
        if ch == '\n' {
            lines.push(Vec::new());
            continue;
        }
        if let Some(line) = lines.last_mut() {
            line.push((ch, styles[offset]));
        }
    }
    if text.ends_with('\n') {
        lines.pop();
    }
    lines
}

/// Characters folded into rows of `width` cells, each row a line.
fn fold(chars: &[(char, Style)], width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let mut rows: Vec<Vec<(char, Style)>> = vec![Vec::new()];
    let mut used = 0;
    for (ch, style) in chars {
        let cell = ch.width().unwrap_or(0);
        if used + cell > width && used > 0 {
            rows.push(Vec::new());
            used = 0;
        }
        used += cell;
        if let Some(row) = rows.last_mut() {
            row.push((*ch, *style));
        }
    }
    rows.iter().map(|row| line_of(row)).collect()
}

fn line_of(chars: &[(char, Style)]) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut text = String::new();
    let mut current: Option<Style> = None;
    for (ch, style) in chars {
        if current.is_some_and(|current| current != *style) {
            spans.push(Span::styled(
                std::mem::take(&mut text),
                current.unwrap_or_default(),
            ));
        }
        current = Some(*style);
        text.push(*ch);
    }
    if let Some(style) = current {
        spans.push(Span::styled(text, style));
    }
    Line::from(spans)
}

fn chars_of(line: &Line<'_>) -> Vec<(char, Style)> {
    line.spans
        .iter()
        .flat_map(|span| {
            let style = line.style.patch(span.style);
            span.content.chars().map(move |ch| (ch, style))
        })
        .collect()
}

/// `line` folded to `width`, each row after the first behind `indent` cells.
pub fn fold_line(line: &Line<'_>, width: usize) -> Vec<Line<'static>> {
    let chars = chars_of(line);
    if chars.is_empty() {
        return vec![Line::default()];
    }
    fold(&chars, width)
}

/// Rows of a two-column grid: `left` in `left_width` cells, `right` folded
/// into the rest, `gap` cells between.
fn grid_row(
    left: &Line<'_>,
    right: &[Line<'static>],
    left_width: usize,
    gap: usize,
    width: usize,
) -> Vec<Line<'static>> {
    let room = width.saturating_sub(left_width + gap).max(1);
    let mut rows = Vec::new();
    let mut folded: Vec<Line<'static>> = right
        .iter()
        .flat_map(|line| fold_line(line, room))
        .collect();
    if folded.is_empty() {
        folded.push(Line::default());
    }
    let left_chars = chars_of(left);
    let left_text: Vec<(char, Style)> =
        super::text::fit_label(&line_of(&left_chars), left_width, 0)
            .spans
            .iter()
            .flat_map(|span| {
                span.content
                    .chars()
                    .map(|ch| (ch, span.style))
                    .collect::<Vec<_>>()
            })
            .collect();
    for (index, right) in folded.into_iter().enumerate() {
        let mut spans: Vec<Span<'static>> = Vec::new();
        let used = if index == 0 {
            spans.extend(line_of(&left_text).spans);
            left_text
                .iter()
                .map(|(ch, _)| ch.width().unwrap_or(0))
                .sum()
        } else {
            0
        };
        spans.push(Span::raw(" ".repeat(left_width.saturating_sub(used) + gap)));
        spans.extend(right.spans);
        rows.push(Line::from(spans));
    }
    rows
}

/// `error[code]: message` and where, without the source lines (the pane
/// shows the file):
///
/// ```text
/// error[vocab_unknown]: 'clearr' is not a TLP value
///   ╭─▶ objects/rules/sentinel-kql-rule.yaml:8:8
///   ╰─ help: did you mean 'clear'?
/// ```
///
/// `╰─▶` closes the location when there is no help. The path is relative to
/// the working directory when inside it, else to the workspace; the field
/// stands in for the line when the line is not known.
pub fn diagnostic_text(finding: &Finding, root: &Path, cwd: &Path) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::styled(
            format!("{}[{}]", finding.severity, finding.code),
            severity_style(&finding.severity),
        ),
        Span::styled(format!(": {}", finding.message), bold()),
    ])];
    let mut at = finding
        .path
        .as_deref()
        .map(|path| {
            inside(path, cwd)
                .or_else(|| inside(path, root))
                .unwrap_or_else(|| slashed(path))
        })
        .unwrap_or_default();
    if !at.is_empty() && finding.line.is_some() {
        if let Some(line) = finding.line {
            at = format!("{at}:{line}");
        }
        if let Some(column) = finding.column {
            at = format!("{at}:{column}");
        }
    } else if !finding.field_path.is_empty() {
        let field = finding.field_path.join(".");
        at = if at.is_empty() {
            field
        } else {
            format!("{at} · {field}")
        };
    }
    let help = finding.help_text();
    if !at.is_empty() {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                if help.is_some() {
                    "╭─▶"
                } else {
                    "╰─▶"
                },
                Style::new().fg(FRAME),
            ),
            Span::raw(format!(" {at}")),
        ]));
    }
    if let Some(help) = help {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("╰─", Style::new().fg(FRAME)),
            Span::styled(" help:", bold().fg(Color::Cyan)),
            Span::raw(format!(" {help}")),
        ]));
    }
    lines
}

/// `✗ 1  ! 2  on lines 8, 28 · n next finding, p previous`; a finding with
/// no line is shown in full.
pub fn findings_summary(findings: &[&Finding], root: &Path, cwd: &Path) -> Vec<Line<'static>> {
    let placed: Vec<&&Finding> = findings.iter().filter(|item| item.line.is_some()).collect();
    let mut lines = Vec::new();
    if !placed.is_empty() {
        let errors = placed
            .iter()
            .filter(|item| item.severity == "error")
            .count();
        let warnings = placed
            .iter()
            .filter(|item| item.severity == "warning")
            .count();
        let notes = placed.len() - errors - warnings;
        let mut spans = Vec::new();
        for (count, mark, severity) in [
            (errors, "✗", "error"),
            (warnings, "!", "warning"),
            (notes, "·", "note"),
        ] {
            if count > 0 {
                spans.push(Span::styled(
                    format!("{mark} {count}  "),
                    severity_style(severity),
                ));
            }
        }
        let mut numbers: Vec<usize> = placed.iter().filter_map(|item| item.line).collect();
        numbers.sort_unstable();
        numbers.dedup();
        let mut at = numbers
            .iter()
            .take(6)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if numbers.len() > 6 {
            at.push_str(" …");
        }
        let plural = if numbers.len() > 1 { "s" } else { "" };
        spans.push(Span::styled(format!("on line{plural} {at}"), dim()));
        spans.push(Span::styled("  · n next finding, p previous", dim()));
        lines.push(Line::from(spans));
    }
    for item in findings.iter().filter(|item| item.line.is_none()) {
        lines.extend(diagnostic_text(item, root, cwd));
    }
    lines
}

/// `╰─ error[code]: message · help: …` under the line a finding is about;
/// `▶ ` marks the current one.
pub fn annotation(item: &Finding, current: bool) -> Line<'static> {
    let mut spans = vec![
        if current {
            Span::styled("▶ ", bold().add_modifier(Modifier::REVERSED))
        } else {
            Span::styled("╰─ ", Style::new().fg(FRAME))
        },
        Span::styled(
            format!("{}[{}]", item.severity, item.code),
            severity_style(&item.severity),
        ),
        Span::raw(format!(": {}", item.message)),
    ];
    if let Some(help) = item.help_text() {
        spans.push(Span::styled(" · ", dim()));
        spans.push(Span::styled("help:", bold().fg(Color::Cyan)));
        spans.push(Span::raw(format!(" {help}")));
    }
    Line::from(spans)
}

/// The source pane, laid out.
#[derive(Debug, Clone, Default)]
pub struct Source {
    /// Its rows.
    pub lines: Vec<Line<'static>>,
    /// The findings with a line, in the order `n` and `p` move through them.
    pub findings: Vec<Finding>,
    /// The row the current finding's annotation starts on.
    pub marked_row: Option<usize>,
}

/// The findings of `findings` that have a line, in file order, errors first
/// on a line.
pub fn placed(findings: &[&Finding]) -> Vec<Finding> {
    let mut placed: Vec<Finding> = findings
        .iter()
        .filter(|item| item.line.is_some())
        .map(|item| (*item).clone())
        .collect();
    placed.sort_by_key(|item| (item.line, item.column, rank(&item.severity)));
    placed
}

/// The object's file with line numbers, coloured as the editor colours it,
/// each finding in place, at `width` cells. A finding with a column is
/// underlined on its span with a tint of its severity; under each line with
/// findings, an annotation gives each one's code, message and help. The
/// finding `current` (`n`/`p`) is marked `▶`. A long line folds inside the
/// source column, and an underline stays on its own characters.
pub fn source_view(
    path: Option<&Path>,
    findings: &[&Finding],
    current: Option<usize>,
    width: usize,
) -> Source {
    let Some(path) = path else {
        return Source {
            lines: vec![Line::styled(
                "The index does not record this object's file.",
                dim(),
            )],
            ..Source::default()
        };
    };
    let code = match std::fs::read(path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| crate::queries::decode(&bytes))
    {
        Ok(code) => code,
        Err(error) => {
            return Source {
                lines: vec![Line::styled(
                    format!("Cannot read {}: {error}", path.display()),
                    Style::new().fg(Color::Red),
                )],
                ..Source::default()
            };
        }
    };
    let findings = placed(findings);
    let language = matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("yaml" | "yml")
    )
    .then_some(LanguageId::TideYaml);
    let mut lines = highlighted(&code, language);
    for item in &findings {
        let (Some(number), Some(column)) = (item.line, item.column) else {
            continue;
        };
        let Some(line) = lines.get_mut(number - 1) else {
            continue;
        };
        let begin = column.saturating_sub(1);
        if begin >= line.len() {
            continue;
        }
        let end = item
            .end_column
            .map_or(line.len(), |end| end.saturating_sub(1).min(line.len()))
            .max(begin + 1);
        for slot in &mut line[begin..end] {
            slot.1 = slot.1.patch(span_style(&item.severity));
        }
    }
    let number_width = lines.len().max(1).to_string().len();
    let source_width = width.saturating_sub(number_width + 3).max(10);
    let mut out = Vec::new();
    let mut marked_row = None;
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let here: Vec<(usize, &Finding)> = findings
            .iter()
            .enumerate()
            .filter(|(_, item)| item.line == Some(number))
            .collect();
        let mark = here
            .iter()
            .min_by_key(|(_, item)| rank(&item.severity))
            .map_or_else(
                || Span::raw(" "),
                |(_, item)| {
                    Span::styled(gutter_mark(&item.severity), severity_style(&item.severity))
                },
            );
        let rows = if line.is_empty() {
            vec![Line::default()]
        } else {
            fold(line, source_width)
        };
        for (row, text) in rows.into_iter().enumerate() {
            let mut spans = if row == 0 {
                vec![
                    Span::styled(format!("{number:>number_width$}"), dim()),
                    Span::raw(" "),
                    mark.clone(),
                    Span::raw(" "),
                ]
            } else {
                vec![Span::raw(" ".repeat(number_width + 3))]
            };
            spans.extend(text.spans);
            out.push(Line::from(spans));
        }
        for (at, item) in here {
            if current == Some(at) {
                marked_row = Some(out.len());
            }
            for row in fold_line(&annotation(item, current == Some(at)), source_width) {
                let mut spans = vec![Span::raw(" ".repeat(number_width + 3))];
                spans.extend(row.spans);
                out.push(Line::from(spans));
            }
        }
    }
    Source {
        lines: out,
        findings,
        marked_row,
    }
}

fn badge(text: String, foreground: Color, background: Color) -> Span<'static> {
    Span::styled(format!(" {text} "), bold().fg(foreground).bg(background))
}

/// A severity value as a badge (`High` on deep orange).
pub fn severity_badge(value: &str) -> Span<'static> {
    let background = match value.to_lowercase().as_str() {
        "critical" => Color::Rgb(0x8b, 0x00, 0x00),
        "high" => Color::Rgb(0xb0, 0x3a, 0x00),
        "medium" => Color::Rgb(0x8a, 0x6d, 0x00),
        "low" => Color::Rgb(0x1f, 0x4f, 0x7a),
        _ => Color::Rgb(0x3a, 0x3a, 0x3a),
    };
    badge(value.to_owned(), WHITE, background)
}

/// `TLP:AMBER` in FIRST's colours.
pub fn tlp_badge(value: &str) -> Span<'static> {
    let black = Color::Rgb(0, 0, 0);
    let (foreground, background) = match value.to_lowercase().as_str() {
        "clear" => (black, WHITE),
        "green" => (black, Color::Rgb(0x33, 0xff, 0x00)),
        "amber" | "amber+strict" => (black, Color::Rgb(0xff, 0xc0, 0x00)),
        "red" => (WHITE, Color::Rgb(0xff, 0x2b, 0x2b)),
        _ => (WHITE, Color::Rgb(0x3a, 0x3a, 0x3a)),
    };
    badge(
        format!("TLP:{}", value.to_uppercase()),
        foreground,
        background,
    )
}

fn link_spans(target: &LinkTarget) -> Vec<Span<'static>> {
    vec![
        Span::styled("→ ", bold()),
        Span::styled(
            target.name.clone(),
            bold().add_modifier(Modifier::UNDERLINED),
        ),
        Span::styled(format!("  {}", target.kind), dim()),
    ]
}

/// A value as the page shows it: badges, links, and what a vocabulary
/// value means; one line per value.
fn value_lines(row: &FieldRow) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (index, value) in row.values.iter().enumerate() {
        let meaning = row.meanings.get(index).cloned().unwrap_or_default();
        if let Some(Some(target)) = row.links.get(index) {
            let mut spans = link_spans(target);
            spans.push(Span::styled(format!("  {}", value.text()), dim()));
            lines.push(Line::from(spans));
            continue;
        }
        let mut spans = Vec::new();
        match value {
            Scalar::Bool(flag) => spans.push(Span::styled(
                if *flag { "yes" } else { "no" },
                bold().fg(if *flag { Color::Green } else { Color::Red }),
            )),
            Scalar::Text(text) if row.severity => spans.push(severity_badge(text)),
            Scalar::Text(text) => {
                let shown = text.trim_end_matches('\n');
                let mut parts = shown.split('\n');
                spans.push(Span::raw(parts.next().unwrap_or_default().to_owned()));
                for part in parts {
                    lines.push(Line::from(std::mem::take(&mut spans)));
                    spans.push(Span::raw(part.to_owned()));
                }
            }
        }
        if !meaning.is_empty() {
            spans.push(Span::styled(
                format!("  {meaning}"),
                dim().add_modifier(Modifier::ITALIC),
            ));
        }
        lines.push(Line::from(spans));
    }
    if row.values.is_empty() {
        lines.push(Line::styled("—", dim()));
    }
    lines
}

/// A query in its own panel, coloured in its language by the engine.
fn query_panel(row: &FieldRow, language: Option<&str>, width: usize) -> Vec<Line<'static>> {
    let code = row.values.first().map(Scalar::text).unwrap_or_default();
    let code = code.trim_end_matches('\n');
    let title = if row.path.starts_with("configurations.") {
        row.path.split('.').nth(1).unwrap_or_default().to_owned()
    } else {
        row.title.clone()
    };
    let border = Style::new().fg(Color::DarkGray);
    let inner = width.saturating_sub(4).max(1);
    let heading = format!(" {title}  {} ", language.unwrap_or("query"));
    let used = heading.chars().count() + 3;
    let mut lines = vec![Line::from(vec![
        Span::styled("╭─", border),
        Span::styled(format!(" {title}"), bold()),
        Span::styled(format!("  {} ", language.unwrap_or("query")), dim()),
        Span::styled(
            format!("{}╮", "─".repeat(width.saturating_sub(used + 1))),
            border,
        ),
    ])];
    let language = language.and_then(LanguageId::parse);
    for line in highlighted(code, language) {
        for row in if line.is_empty() {
            vec![Line::default()]
        } else {
            fold(&line, inner)
        } {
            let used: usize = row.width();
            let mut spans = vec![Span::styled("│ ", border)];
            spans.extend(row.spans);
            spans.push(Span::raw(" ".repeat(inner.saturating_sub(used))));
            spans.push(Span::styled(" │", border));
            lines.push(Line::from(spans));
        }
    }
    lines.push(Line::styled(
        format!("╰{}╯", "─".repeat(width.saturating_sub(2))),
        border,
    ));
    lines
}

/// An object as a page at `width` cells: a header, a section per top-level
/// field, queries in panels; a field with a finding is marked under its
/// value, as the file marks its line.
pub fn object_page(
    view: &ObjectView,
    findings: &[&Finding],
    languages: &BTreeMap<String, String>,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut facts = Vec::new();
    if let Some(version) = view.header.get("version") {
        facts.push(Span::styled(format!("v{version}"), bold()));
    }
    for label in ["created", "modified"] {
        if let Some(value) = view.header.get(label) {
            facts.push(Span::styled(format!("  {label} {value}"), dim()));
        }
    }
    if let Some(tlp) = view.header.get("tlp") {
        facts.push(Span::raw("  "));
        facts.push(tlp_badge(tlp));
        if !view.tlp_meaning.is_empty() {
            facts.push(Span::styled(
                format!("  {}", view.tlp_meaning),
                dim().add_modifier(Modifier::ITALIC),
            ));
        }
    }
    lines.extend(fold_line(&Line::from(facts), width));
    if let Some(schema) = view.header.get("schema") {
        lines.push(Line::styled(schema.clone(), dim()));
    }
    if let Some(unknown) = &view.unknown_schema {
        lines.extend(fold_line(
            &Line::styled(unknown.clone(), Style::new().fg(Color::Yellow)),
            width,
        ));
    }
    let mut by_path: HashMap<String, Vec<&Finding>> = HashMap::new();
    for item in findings {
        if !item.field_path.is_empty() {
            by_path
                .entry(item.field_path.join("."))
                .or_default()
                .push(item);
        }
    }
    for section in &view.sections {
        lines.push(Line::default());
        let title_width = section.title.chars().count() + 1;
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", section.title), bold()),
            Span::styled(
                "─".repeat(width.saturating_sub(title_width)),
                Style::new().fg(Color::DarkGray),
            ),
        ]));
        if !section.description.is_empty() {
            lines.extend(fold_line(
                &Line::styled(
                    section.description.clone(),
                    dim().add_modifier(Modifier::ITALIC),
                ),
                width,
            ));
        }
        let left_width = section
            .rows
            .iter()
            .map(|row| row.title.chars().count() + 2 * row.depth)
            .max()
            .unwrap_or(0)
            .min(36);
        let mut queries = Vec::new();
        for row in &section.rows {
            let indent = "  ".repeat(row.depth);
            if row.kind == RowKind::Value
                && (languages.contains_key(&row.path)
                    || (row.path.starts_with("configurations.")
                        && row.path.rsplit('.').next() == Some("query")))
            {
                queries.extend(query_panel(
                    row,
                    languages.get(&row.path).map(String::as_str),
                    width,
                ));
                for item in by_path.get(&row.path).into_iter().flatten() {
                    queries.extend(fold_line(&annotation(item, false), width));
                }
                continue;
            }
            let (left, right) = match row.kind {
                RowKind::Group => (
                    Line::styled(format!("{indent}{}", row.title), bold()),
                    vec![Line::styled(
                        row.description.clone(),
                        dim().add_modifier(Modifier::ITALIC),
                    )],
                ),
                RowKind::Item => (
                    Line::styled(format!("{indent}{}", row.title), bold().fg(Color::Cyan)),
                    vec![Line::default()],
                ),
                RowKind::Value => (
                    Line::styled(format!("{indent}{}", row.title), bold()),
                    value_lines(row),
                ),
            };
            lines.extend(grid_row(&left, &right, left_width, 2, width));
            for item in by_path.get(&row.path).into_iter().flatten() {
                lines.extend(grid_row(
                    &Line::default(),
                    &[annotation(item, false)],
                    left_width,
                    2,
                    width,
                ));
            }
        }
        lines.extend(queries);
    }
    lines
}

/// The optional fields the object's revision allows and it does not set,
/// with what each is: `▶ Not set (N)` collapsed, the list when `open`.
pub fn unset_fields(view: &ObjectView, open: bool, width: usize) -> Vec<Line<'static>> {
    if view.unset.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![
        Line::default(),
        Line::from(vec![
            Span::styled(if open { "▼ " } else { "▶ " }, bold()),
            Span::styled(format!("Not set ({})", view.unset.len()), bold()),
            Span::styled(if open { "" } else { "  · u shows them" }, dim()),
        ]),
    ];
    if !open {
        return lines;
    }
    let left_width = view
        .unset
        .iter()
        .map(|item| item.path.chars().count() + 2)
        .max()
        .unwrap_or(0)
        .min(36);
    for item in &view.unset {
        let mut label = vec![Span::styled(item.path.clone(), bold())];
        if item.recommended {
            label.push(Span::styled(" ★", Style::new().fg(Color::Yellow)));
        }
        let about = if item.description.is_empty() {
            item.title.clone()
        } else {
            item.description.clone()
        };
        let mut right = vec![Line::styled(about, dim())];
        if !item.choices.is_empty() {
            let mut choices = format!(
                "one of: {}",
                item.choices
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if item.choices.len() > 8 {
                choices.push_str(" …");
            }
            right.push(Line::styled(choices, dim().add_modifier(Modifier::ITALIC)));
        }
        lines.extend(grid_row(&Line::from(label), &right, left_width, 2, width));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::model::Source as From;
    use crate::tui::text::plain;
    use std::path::PathBuf;

    fn finding(line: Option<usize>, help: Option<&str>, source: From) -> Finding {
        Finding {
            code: "vocab_unknown".into(),
            severity: "error".into(),
            message: "'clearr' is not a TLP value".into(),
            object_uuid: String::new(),
            path: Some(
                PathBuf::from("ws")
                    .join("objects")
                    .join("rules")
                    .join("r.yaml"),
            ),
            line,
            column: line.map(|_| 8),
            end_column: line.map(|_| 14),
            field_path: vec!["metadata".into(), "tlp".into()],
            help: help.map(str::to_owned),
            source,
        }
    }

    /// `item` placed in a workspace under a real absolute folder, read
    /// from a working directory outside it: its frame's lines.
    fn framed(item: &Finding, base: &Path) -> Vec<String> {
        let mut item = item.clone();
        item.path = item.path.map(|path| base.join(path));
        let elsewhere = base.join("elsewhere");
        diagnostic_text(&item, &base.join("ws"), &elsewhere)
            .iter()
            .map(plain)
            .collect()
    }

    #[test]
    fn a_diagnostic_reads_as_the_frame_without_its_source() {
        let base = tempfile::tempdir().unwrap();
        let item = finding(Some(8), Some("clear"), From::Validate);
        assert_eq!(
            framed(&item, base.path()),
            [
                "error[vocab_unknown]: 'clearr' is not a TLP value",
                "  ╭─▶ objects/rules/r.yaml:8:8",
                "  ╰─ help: did you mean 'clear'?",
            ]
        );
        // No line: the field stands in; no help: the location closes the frame.
        let loose = finding(None, None, From::Validate);
        assert_eq!(
            framed(&loose, base.path())[1],
            "  ╰─▶ objects/rules/r.yaml · metadata.tlp"
        );
        // Relative to the working directory first, when the file is in it.
        let mut item = item;
        item.path = Some(base.path().join("ws").join("objects").join("r.yaml"));
        let lines: Vec<String> = diagnostic_text(&item, base.path(), &base.path().join("ws"))
            .iter()
            .map(plain)
            .collect();
        assert_eq!(lines[1], "  ╭─▶ objects/r.yaml:8:8");
        // Outside both: the path as it is, with `/`.
        let outside = base.path().join("other").join("r.yaml");
        item.path = Some(outside.clone());
        let lines: Vec<String> =
            diagnostic_text(&item, &base.path().join("ws"), &base.path().join("ws"))
                .iter()
                .map(plain)
                .collect();
        assert_eq!(
            lines[1],
            format!("  ╭─▶ {}:8:8", super::super::text::slashed(&outside))
        );
        assert!(!lines[1].contains('\\'));
    }

    #[test]
    fn help_asks_did_you_mean_only_for_a_value() {
        assert_eq!(
            finding(None, Some("clear"), From::Validate)
                .help_text()
                .as_deref(),
            Some("did you mean 'clear'?")
        );
        // The language server's help is written already.
        assert_eq!(
            finding(None, Some("try: x"), From::LanguageServer)
                .help_text()
                .as_deref(),
            Some("try: x")
        );
        let mut prose = finding(None, Some("Use a CVE id"), From::Validate);
        prose.code = "invalid_cve".into();
        assert_eq!(prose.help_text().as_deref(), Some("Use a CVE id"));
    }

    #[test]
    fn the_summary_counts_findings_by_line_and_shows_loose_ones_in_full() {
        let placed = finding(Some(8), Some("clear"), From::Validate);
        let mut warning = finding(Some(28), None, From::Validate);
        warning.severity = "warning".into();
        let loose = finding(None, None, From::Validate);
        let base = tempfile::tempdir().unwrap();
        let lines: Vec<String> = findings_summary(
            &[&placed, &warning, &loose],
            &base.path().join("ws"),
            &base.path().join("ws"),
        )
        .iter()
        .map(plain)
        .collect();
        assert_eq!(
            lines[0],
            "✗ 1  ! 1  on lines 8, 28  · n next finding, p previous"
        );
        assert!(lines[1].starts_with("error[vocab_unknown]"));
    }

    #[test]
    fn a_long_line_folds_with_the_underline_on_its_own_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("long.yaml");
        let long = "x".repeat(60);
        std::fs::write(&path, format!("name: R\ndescription: {long}BAD{long}\n")).unwrap();
        let mut item = finding(Some(2), None, From::LanguageServer);
        item.path = Some(path.clone());
        item.column = Some(14 + 60);
        item.end_column = Some(14 + 63);
        let view = source_view(Some(&path), &[&item], Some(0), 50);
        // Every row fits; the underlined span is exactly `BAD`.
        assert!(
            view.lines.iter().all(|line| line.width() <= 50),
            "{:?}",
            view.lines
        );
        let underlined: String = view
            .lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .filter(|span| span.style.add_modifier.contains(Modifier::UNDERLINED))
            .map(|span| span.content.as_ref())
            .collect();
        assert_eq!(underlined, "BAD");
        // The annotation follows its line, marked as the current finding.
        let row = view.marked_row.unwrap();
        assert!(
            plain(&view.lines[row])
                .trim_start()
                .starts_with("▶ error[vocab_unknown]")
        );
        assert!(plain(&view.lines[1]).starts_with("2 ✗ description:"));
    }
}
