//! `opentide explain [CODE]` (`cli/commands/explain.py`): what a diagnostic
//! code means and how to fix it, or the list of every code.
//!
//! `human` mode renders the page's Markdown for the terminal (parsed by
//! pulldown-cmark, styled and wrapped by this crate's renderers); `plain`
//! and `agent` print its source; `--json` gives `{code, meaning, markdown}`.

use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};

use super::{Block, Report, Terminal, USAGE_INVALID_CHOICE};
use crate::explain::{self, Page};
use crate::json::Json;
use crate::mode::Mode;
use crate::render::text::{Style, Text};

/// Runs `explain`, with `code` when one was given.
pub fn run(code: Option<&str>, terminal: &Terminal) -> Report {
    let Some(code) = code else {
        return list(terminal);
    };
    let Some(page) = explain::page(code.trim()) else {
        let codes = explain::codes();
        return Report::usage(
            "explain",
            format!(
                "No diagnostic code {}. Run 'opentide explain' to list them.",
                crate::render::codeframe::quoted(code)
            ),
            USAGE_INVALID_CHOICE,
            "code",
            Some(code),
            &codes,
        );
    };
    let mut report = Report::completed(
        "explain",
        vec![
            ("code".into(), Json::str(&page.code)),
            ("meaning".into(), Json::str(&page.summary)),
            ("markdown".into(), Json::str(&page.markdown)),
        ],
    );
    page.summary.clone_into(&mut report.outcome.message);
    if terminal.text() {
        report.body_only = true;
        let text = if terminal.mode == Mode::Human {
            render_markdown(&page.markdown, terminal)
        } else {
            let mut source = page.markdown.trim_end_matches('\n').to_owned();
            source.push('\n');
            source
        };
        report.body.push(Block::Raw(text));
    }
    report
}

/// Every code, with its one-sentence meaning.
fn list(terminal: &Terminal) -> Report {
    let pages = explain::all();
    let codes = Json::Array(
        pages
            .iter()
            .map(|page| {
                Json::Object(vec![
                    ("code".into(), Json::str(&page.code)),
                    ("meaning".into(), Json::str(&page.summary)),
                ])
            })
            .collect(),
    );
    let mut report = Report::completed("explain", vec![("codes".into(), codes)]);
    report.outcome.message = format!("{} diagnostic codes", pages.len());
    report.outcome.summary = vec![("codes".into(), Json::from(pages.len()))];
    if terminal.text() {
        report.body.push(Block::Raw(index_text(&pages, terminal)));
    }
    report
}

/// One line per page: the code, padded, then its meaning, continued under
/// itself between words on a terminal.
fn index_text(pages: &[Page], terminal: &Terminal) -> String {
    let width = pages.iter().map(|page| page.code.len()).max().unwrap_or(0);
    let bold = Style::new("bold");
    let mut out = String::new();
    for page in pages {
        let mut line = Text::styled(&format!("{:<width$}  ", page.code), &bold);
        line.push_str(&page.summary);
        out.push_str(&terminal.stdout.print_line(&line, width + 2));
    }
    out
}

/// What a block of the page is, as it is laid out.
enum Part {
    /// A heading's text.
    Heading(Text),
    /// A paragraph or a list item's text, with its indent and bullet.
    Para(Text, String),
    /// A fenced or indented code block's lines.
    Code(Vec<String>),
}

/// The page's Markdown as styled, wrapped lines for a terminal.
pub fn render_markdown(markdown: &str, terminal: &Terminal) -> String {
    let mut parts: Vec<Part> = Vec::new();
    let mut current = Text::default();
    let mut styles: Vec<Style> = Vec::new();
    let mut code: Option<Vec<String>> = None;
    let mut lists: Vec<Option<u64>> = Vec::new();
    let mut bullet = String::new();
    let mut target: Option<String> = None;
    let style = |styles: &[Style]| {
        styles
            .iter()
            .fold(Style::default(), |acc, style| acc.combine(style))
    };
    for event in Parser::new(markdown) {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                let bold = if level == HeadingLevel::H1 {
                    "bold underline"
                } else {
                    "bold"
                };
                styles.push(Style::new(bold));
            }
            Event::End(TagEnd::Heading(_)) => {
                styles.pop();
                parts.push(Part::Heading(std::mem::take(&mut current)));
            }
            Event::Start(Tag::List(start)) => lists.push(start),
            Event::End(TagEnd::List(_)) => {
                lists.pop();
            }
            Event::Start(Tag::Item) => {
                let depth = lists.len().saturating_sub(1);
                let mark = match lists.last_mut() {
                    Some(Some(number)) => {
                        let mark = format!("{number}.");
                        *number += 1;
                        mark
                    }
                    _ => "•".to_owned(),
                };
                bullet = format!("{}{mark} ", "  ".repeat(depth));
            }
            Event::End(TagEnd::Item | TagEnd::Paragraph) => {
                if !current.as_plain().is_empty() {
                    parts.push(Part::Para(
                        std::mem::take(&mut current),
                        std::mem::take(&mut bullet),
                    ));
                }
            }
            Event::Start(Tag::Emphasis) => styles.push(Style::new("italic")),
            Event::Start(Tag::Strong) => styles.push(Style::new("bold")),
            Event::End(TagEnd::Emphasis | TagEnd::Strong) => {
                styles.pop();
            }
            Event::Start(Tag::Link { dest_url, .. }) => {
                styles.push(Style::new("underline"));
                target = Some(dest_url.to_string());
            }
            Event::End(TagEnd::Link) => {
                styles.pop();
                if let Some(url) = target.take() {
                    current.append(&format!(" ({url})"), &Style::new("dim"));
                }
            }
            Event::Start(Tag::CodeBlock(_)) => {
                code = Some(Vec::new());
            }
            Event::End(TagEnd::CodeBlock) => {
                if let Some(lines) = code.take() {
                    parts.push(Part::Code(lines));
                }
            }
            Event::Text(text) => {
                if let Some(lines) = code.as_mut() {
                    lines.extend(text.lines().map(str::to_owned));
                } else {
                    current.append(&text, &style(&styles));
                }
            }
            Event::Code(text) => {
                current.append(&text, &style(&styles).combine(&Style::new("bold cyan")));
            }
            Event::SoftBreak => {
                current.append(" ", &style(&styles));
            }
            Event::HardBreak => {
                current.append("\n", &style(&styles));
            }
            _ => {}
        }
    }
    let console = terminal.stdout;
    let mut out = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        match part {
            Part::Heading(text) => out.push_str(&console.print_line(text, 0)),
            Part::Para(text, bullet) => {
                let mut line = Text::plain(bullet);
                line.append_text(text);
                out.push_str(&console.print_line(&line, bullet.chars().count()));
            }
            Part::Code(lines) => {
                let style = Style::new("cyan");
                for line in lines {
                    out.push_str(&console.line(&Text::styled(&format!("    {line}"), &style)));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_is_its_document_and_its_source_in_plain_mode() {
        let report = run(Some("vocab_unknown"), &Terminal::plain(Mode::Plain));
        let keys: Vec<&str> = report
            .outcome
            .data
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(keys, ["code", "meaning", "markdown"]);
        assert_eq!(
            report.outcome.message,
            "A value is not in the vocabulary its field uses."
        );
        assert!(report.body_only);
        let Some(Block::Raw(text)) = report.body.first() else {
            panic!("no body");
        };
        assert!(text.starts_with("# vocab_unknown\n\nA value"));
        assert!(text.ends_with("recommends it).\n"));
    }

    #[test]
    fn an_unknown_code_is_a_usage_error_with_the_closest_code() {
        let report = run(Some("vocab_unknwn"), &Terminal::plain(Mode::Json));
        assert_eq!(report.outcome.exit_code, 2);
        let failure = report.outcome.failure.unwrap();
        assert_eq!(failure.code, "usage_invalid_choice");
        assert_eq!(failure.argument.as_deref(), Some("code"));
        assert_eq!(failure.suggestion.as_deref(), Some("vocab_unknown"));
        assert_eq!(
            failure.message,
            "No diagnostic code 'vocab_unknwn'. Run 'opentide explain' to list them."
        );
    }

    #[test]
    fn the_list_names_every_code_once() {
        let report = run(None, &Terminal::plain(Mode::Plain));
        let count = explain::all().len();
        assert_eq!(report.outcome.message, format!("{count} diagnostic codes"));
        let Some(Block::Raw(text)) = report.body.first() else {
            panic!("no body");
        };
        assert_eq!(text.lines().count(), count);
        assert!(text.lines().any(|line| line.starts_with("yaml_parse ")));
    }

    #[test]
    fn markdown_renders_headings_code_and_paragraphs() {
        let text = render_markdown(
            "# code\n\nA `value` and *more*.\n\n## Example\n\n```yaml\nk: v\n```\n\n- one\n- two\n",
            &Terminal::plain(Mode::Human),
        );
        assert_eq!(
            text,
            "code\n\nA value and more.\n\nExample\n\n    k: v\n\n• one\n\n• two\n"
        );
    }
}
