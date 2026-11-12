//! The pieces of text the UI lays out (`tui_app.py`'s `pill`,
//! `masthead_brand`, `fit_label`, `empty_state`): pure functions over
//! ratatui's [`Line`], widths in terminal cells by `unicode-width`.

use std::path::Path;

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthChar;

/// Pantone Reflex Blue: a fill, never a text colour.
pub const BLUE: Color = Color::Rgb(0x00, 0x14, 0x89);
/// White.
pub const WHITE: Color = Color::Rgb(0xff, 0xff, 0xff);
/// The tagline beside the pill.
pub const TAGLINE: &str = "Spec-driven development for agentic detection engineering";
/// Between the pill and the tagline, and before the summary.
const GAP: &str = "  ";

/// The one-line pill `▐ ≋ opentide ▌`: white on Reflex Blue, half-block caps.
pub fn pill() -> Line<'static> {
    Line::from(vec![
        Span::styled("▐", Style::new().fg(BLUE)),
        Span::styled(
            " ≋ opentide ",
            Style::new().fg(WHITE).bg(BLUE).add_modifier(Modifier::BOLD),
        ),
        Span::styled("▌", Style::new().fg(BLUE)),
    ])
}

/// The pill, then the tagline when it fits whole beside a summary of
/// `summary` cells in `width` cells. The tagline is never cut: at a narrow
/// width it goes, the pill stays.
pub fn masthead_brand(width: usize, summary: usize) -> Line<'static> {
    let mut with_tagline = pill();
    with_tagline.push_span(Span::raw(GAP));
    with_tagline.push_span(Span::raw(TAGLINE));
    if with_tagline.width() + GAP.len() + summary <= width {
        return with_tagline;
    }
    pill()
}

/// Each character of `line` with the style it is drawn in.
fn cells(line: &Line<'_>) -> Vec<(char, Style)> {
    line.spans
        .iter()
        .flat_map(|span| {
            let style = line.style.patch(span.style);
            span.content.chars().map(move |ch| (ch, style))
        })
        .collect()
}

/// Characters back into a line, one span per run of a style.
fn assemble(chars: &[(char, Style)]) -> Line<'static> {
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

fn width_of(chars: &[(char, Style)]) -> usize {
    chars.iter().map(|(ch, _)| ch.width().unwrap_or(0)).sum()
}

/// `chars` in `width` cells, the last one `…`: cut after a whole character,
/// with no space before the ellipsis, which takes the style of the cell it
/// replaces.
fn cut(chars: &[(char, Style)], width: usize) -> Vec<(char, Style)> {
    let room = width.saturating_sub(1);
    let mut kept = 0;
    let mut used = 0;
    for (ch, _) in chars {
        let cell = ch.width().unwrap_or(0);
        if used + cell > room {
            break;
        }
        used += cell;
        kept += 1;
    }
    while kept > 0 && chars[kept - 1].0.is_whitespace() {
        kept -= 1;
    }
    let style = chars.get(kept).map(|(_, style)| *style).unwrap_or_default();
    let mut out = chars[..kept].to_vec();
    out.push(('…', style));
    out
}

/// `label` in at most `width` cells, cut after a whole character and ended
/// by `…`.
///
/// The last `tail` characters (an object's facts and finding counts) stay
/// whole while the name before them keeps room for a character and the
/// ellipsis; below that the whole label is cut.
pub fn fit_label(label: &Line<'static>, width: usize, tail: usize) -> Line<'static> {
    let chars = cells(label);
    if width == 0 || width_of(&chars) <= width {
        return label.clone();
    }
    let split = chars.len().saturating_sub(tail);
    let end = &chars[split..];
    let room = width.saturating_sub(width_of(end));
    if tail > 0 && room >= 2 {
        let mut fitted = cut(&chars[..split], room);
        fitted.extend_from_slice(end);
        return assemble(&fitted);
    }
    assemble(&cut(&chars, width))
}

/// `path` relative to `root`, with `/` between its parts on every
/// system; `.` for `root` itself; `None` when it is not inside `root`.
/// Compared as written first, then resolved (symbolic links, `..`), as far
/// as the paths exist.
pub fn inside(path: &Path, root: &Path) -> Option<String> {
    let resolve = |path: &Path| {
        soft_canonicalize::soft_canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    };
    let found = path
        .strip_prefix(root)
        .ok()
        .map(Path::to_path_buf)
        .or_else(|| {
            resolve(path)
                .strip_prefix(resolve(root))
                .ok()
                .map(Path::to_path_buf)
        })?;
    if found.as_os_str().is_empty() {
        return Some(".".to_owned());
    }
    Some(
        found
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

/// `path` as the UI shows it: with `/` between its parts, as the renderers
/// write a path, on every system.
pub fn slashed(path: &Path) -> String {
    let text = path.display().to_string();
    if std::path::MAIN_SEPARATOR == '/' {
        text
    } else {
        text.replace(std::path::MAIN_SEPARATOR, "/")
    }
}

/// `path` relative to `root` when inside it ([`inside`]); else `path`
/// itself, with `/`.
pub fn relative(path: Option<&Path>, root: &Path) -> String {
    path.map(|path| inside(path, root).unwrap_or_else(|| slashed(path)))
        .unwrap_or_default()
}

/// The tree's only line when the workspace holds no object, its path
/// relative to `cwd`.
pub fn empty_state(repo: &Path, cwd: &Path) -> String {
    match inside(repo, cwd) {
        // Outside the current directory, or the workspace itself: relative
        // to the workspace, the path is the workspace.
        None => "No detection objects in this workspace".to_owned(),
        Some(at) if at == "." => "No detection objects in this workspace".to_owned(),
        Some(at) => format!("No detection objects under {at}"),
    }
}

/// The plain text of a line.
pub fn plain(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tagline_shows_whole_or_not_at_all() {
        let summary = "acme-detections · 0 threats · 0 objectives · 0 rules"
            .chars()
            .count();
        assert_eq!(plain(&masthead_brand(98, summary)), "▐ ≋ opentide ▌");
        let wide = plain(&masthead_brand(200, summary));
        assert_eq!(wide, format!("▐ ≋ opentide ▌  {TAGLINE}"));
        // Exactly wide enough, and one cell short of it.
        let fits = wide.chars().count() + 2 + summary;
        assert_eq!(plain(&masthead_brand(fits, summary)), wide);
        assert_eq!(plain(&masthead_brand(fits - 1, summary)), "▐ ≋ opentide ▌");
    }

    #[test]
    fn the_pill_is_white_on_reflex_blue() {
        let line = pill();
        assert_eq!(line.spans[1].style.fg, Some(WHITE));
        assert_eq!(line.spans[1].style.bg, Some(BLUE));
        // The caps are the fill's colour, never text on it.
        assert_eq!(line.spans[0].style.fg, Some(BLUE));
        assert_eq!(line.spans[0].style.bg, None);
    }

    #[test]
    fn fit_label_cuts_with_an_ellipsis_and_keeps_the_counts() {
        let cases = [
            (
                "Spec-driven development for agentic",
                28,
                0,
                "Spec-driven development for…",
            ),
            // A cut after a space reads the same as one after a letter.
            (
                "Spec-driven development for agentic",
                29,
                0,
                "Spec-driven development for…",
            ),
            (
                "Credential Access Objective  1 rule",
                26,
                8,
                "Credential Access…  1 rule",
            ),
            (
                "Simulated Actor  0 objectives · 0 rules",
                30,
                24,
                "Simul…  0 objectives · 0 rules",
            ),
            ("Short  1 rule", 13, 8, "Short  1 rule"),
            // No room for the name: the whole label is cut.
            ("Name  0 objectives · 0 rules", 10, 24, "Name  0 o…"),
        ];
        for (label, width, tail, fitted) in cases {
            let result = fit_label(&Line::from(label), width, tail);
            assert_eq!(plain(&result), fitted, "{label} at {width}");
            assert!(result.width() <= width);
        }
    }

    #[test]
    fn fit_label_counts_wide_characters_in_cells() {
        let result = fit_label(&Line::from("検知ルール名前"), 6, 0);
        assert_eq!(plain(&result), "検知…");
        assert!(result.width() <= 6);
    }

    #[test]
    fn fit_label_keeps_the_style_of_the_cell_it_cuts() {
        let reverse = Style::new().add_modifier(Modifier::REVERSED);
        let label = Line::from(Span::styled("Credential Access Objective", reverse));
        let cut = fit_label(&label, 10, 0);
        assert_eq!(plain(&cut), "Credentia…");
        assert!(cut.spans.iter().all(|span| span.style == reverse));
        // The tail keeps its own style.
        let dim = Style::new().add_modifier(Modifier::DIM);
        let label = Line::from(vec![
            Span::raw("Credential Access Objective"),
            Span::styled("  1 rule", dim),
        ]);
        let cut = fit_label(&label, 20, 8);
        assert_eq!(plain(&cut), "Credential…  1 rule");
        assert_eq!(cut.spans.last().map(|span| span.style), Some(dim));
    }

    #[test]
    fn an_empty_workspace_names_its_path_relative_to_the_current_directory() {
        let base = tempfile::tempdir().unwrap();
        let repo = base.path().join("acme-detections");
        std::fs::create_dir_all(repo.join("objects")).unwrap();
        assert_eq!(
            empty_state(&repo, &repo),
            "No detection objects in this workspace"
        );
        assert_eq!(
            empty_state(&repo, base.path()),
            "No detection objects under acme-detections"
        );
        assert_eq!(
            empty_state(&repo, &repo.join("objects")),
            "No detection objects in this workspace"
        );
        let elsewhere = base.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        assert_eq!(
            empty_state(&repo, &elsewhere),
            "No detection objects in this workspace"
        );
    }
}
