//! Markdown as plain text: the one converter, on pulldown-cmark (#1957).
//!
//! The SARIF `help.text` of a code's page (opentide-cli), a hover or a
//! completion's documentation for an editor that renders no Markdown
//! (opentide-lsp), and the plain `description` beside a schema's
//! `markdownDescription` (opentide-schema) all read Markdown through
//! [`to_text`], each with its own [`Options`].
//!
//! What every surface gets: CommonMark read as CommonMark, with no
//! extension (a table stays its text). Heading marks, emphasis, strong
//! emphasis, code-span backticks, code fences (and their info string),
//! backslash escapes and entity references are dropped or decoded; a code
//! block's lines are kept as written (joined as any block's are under
//! [`Lines::Join`]); a list item starts `- ` or `1. `,
//! indented two spaces a level; blocks are separated by a blank line, the
//! items of one list by a line break when lines are kept. HTML is kept as
//! written, and an image reads as its alternative text.

use pulldown_cmark::{Event, Parser, Tag, TagEnd};

/// How a link reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Links {
    /// Its text only: `[revision](x)` reads `revision`.
    Text,
    /// Its text, then its destination in parentheses: `text (url)`. An
    /// autolink, whose text is its destination, reads once.
    TextAndUrl,
}

/// What becomes of the line breaks inside a paragraph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lines {
    /// Kept: a hard-wrapped paragraph keeps its lines, and the items of a
    /// list are one line each.
    Keep,
    /// Joined: each block is one line, its white space collapsed to single
    /// spaces, and every block (each list item too) is a paragraph.
    Join,
}

/// How [`to_text`] writes a surface's text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// How a link reads.
    pub links: Links,
    /// What becomes of line breaks.
    pub lines: Lines,
}

/// One block of the text, before the blocks are joined.
#[derive(Debug)]
struct Block {
    text: String,
    /// The outermost list of a list item's line (or of a later paragraph
    /// of one): the items of one list are written line after line.
    list: Option<usize>,
}

/// What [`to_text`] keeps while it walks the events.
struct Writer {
    options: Options,
    blocks: Vec<Block>,
    current: String,
    /// The open lists: the next number of an ordered one.
    lists: Vec<Option<u64>>,
    /// The outermost lists started so far.
    outermost: usize,
    /// The marker of an item whose text has not been written yet.
    marker: Option<String>,
    /// The open items: whether each already wrote a block.
    items: Vec<bool>,
    /// The open links: where their text starts in `current`, and their
    /// destination.
    links: Vec<(usize, String)>,
    /// Inside a code block: its text is kept as written.
    code: bool,
}

impl Writer {
    /// Ends the block being written, if it holds any text.
    fn flush(&mut self) {
        let text = std::mem::take(&mut self.current);
        let text = if self.code && self.options.lines == Lines::Keep {
            text.trim_end_matches('\n').to_owned()
        } else {
            match self.options.lines {
                Lines::Keep => text.trim().to_owned(),
                Lines::Join => text.split_whitespace().collect::<Vec<_>>().join(" "),
            }
        };
        if text.is_empty() {
            return;
        }
        let depth = self.lists.len().saturating_sub(1);
        let text = match (self.marker.take(), self.items.last_mut()) {
            (Some(marker), Some(wrote)) => {
                *wrote = true;
                format!("{}{marker}{text}", "  ".repeat(depth))
            }
            // A later paragraph of an item: under its text.
            (None, Some(_)) => {
                let indent = "  ".repeat(depth + 1);
                text.lines()
                    .map(|line| format!("{indent}{line}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            (_, None) => text,
        };
        self.blocks.push(Block {
            text,
            list: self.list(),
        });
    }

    /// The outermost open list, inside an item.
    fn list(&self) -> Option<usize> {
        (!self.items.is_empty()).then_some(self.outermost)
    }

    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Start(Tag::List(start)) => {
                self.flush();
                if self.lists.is_empty() {
                    self.outermost += 1;
                }
                self.lists.push(start);
            }
            Event::End(TagEnd::List(_)) => {
                self.flush();
                self.lists.pop();
            }
            Event::Start(Tag::Item) => {
                self.flush();
                let marker = match self.lists.last_mut() {
                    Some(Some(number)) => {
                        let marker = format!("{number}. ");
                        *number += 1;
                        marker
                    }
                    _ => "- ".to_owned(),
                };
                self.marker = Some(marker);
                self.items.push(false);
            }
            Event::End(TagEnd::Item) => {
                self.flush();
                // An empty item still reads as its marker.
                if let (Some(marker), Some(false)) = (self.marker.take(), self.items.last()) {
                    let depth = self.lists.len().saturating_sub(1);
                    self.blocks.push(Block {
                        text: format!("{}{}", "  ".repeat(depth), marker.trim_end()),
                        list: self.list(),
                    });
                }
                self.items.pop();
            }
            Event::Start(Tag::CodeBlock(_)) => {
                self.flush();
                self.code = true;
            }
            Event::End(TagEnd::CodeBlock) => {
                self.flush();
                self.code = false;
            }
            Event::Start(
                Tag::Paragraph | Tag::Heading { .. } | Tag::BlockQuote(_) | Tag::HtmlBlock,
            )
            | Event::End(
                TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::BlockQuote(_) | TagEnd::HtmlBlock,
            ) => self.flush(),
            Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                self.links
                    .push((self.current.len(), dest_url.into_string()));
            }
            Event::End(TagEnd::Link | TagEnd::Image) => {
                if let Some((start, url)) = self.links.pop()
                    && self.options.links == Links::TextAndUrl
                    && !url.is_empty()
                    && self.current.get(start..) != Some(url.as_str())
                {
                    self.current.push_str(&format!(" ({url})"));
                }
            }
            Event::Text(text) | Event::Code(text) | Event::Html(text) | Event::InlineHtml(text) => {
                self.current.push_str(&text);
            }
            Event::SoftBreak | Event::HardBreak => self.current.push(match self.options.lines {
                Lines::Keep => '\n',
                Lines::Join => ' ',
            }),
            Event::Rule => {
                self.flush();
                if self.options.lines == Lines::Keep {
                    self.blocks.push(Block {
                        text: "---".to_owned(),
                        list: None,
                    });
                }
            }
            // Emphasis, strong emphasis and what no extension turns on.
            _ => {}
        }
    }
}

/// `markdown` as plain text, as `options` say (the module's page).
#[must_use]
pub fn to_text(markdown: &str, options: Options) -> String {
    let mut writer = Writer {
        options,
        blocks: Vec::new(),
        current: String::new(),
        lists: Vec::new(),
        outermost: 0,
        marker: None,
        items: Vec::new(),
        links: Vec::new(),
        code: false,
    };
    for event in Parser::new(markdown) {
        writer.event(event);
    }
    writer.flush();
    let mut out = String::with_capacity(markdown.len());
    let mut previous: Option<&Block> = None;
    for block in &writer.blocks {
        if let Some(previous) = previous {
            let tight = options.lines == Lines::Keep
                && previous.list.is_some()
                && previous.list == block.list;
            out.push_str(if tight { "\n" } else { "\n\n" });
        }
        out.push_str(&block.text);
        previous = Some(block);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEEP: Options = Options {
        links: Links::TextAndUrl,
        lines: Lines::Keep,
    };
    const JOIN: Options = Options {
        links: Links::Text,
        lines: Lines::Join,
    };

    #[test]
    fn marks_are_dropped_and_text_kept() {
        assert_eq!(
            to_text(
                "# Título\n\nUne **règle** et __gras__ avec `code` 😀.\n",
                KEEP
            ),
            "Título\n\nUne règle et gras avec code 😀."
        );
        assert_eq!(
            to_text("_italique_ et snake_case_name et **open", KEEP),
            "italique et snake_case_name et **open"
        );
        assert_eq!(to_text("a\\*b &amp; c", KEEP), "a*b & c");
        assert_eq!(to_text("> cité 😀", KEEP), "cité 😀");
        assert_eq!(to_text("", KEEP), "");
    }

    #[test]
    fn links_read_as_their_text_with_or_without_the_url() {
        let markdown = "Voir [la page](https://exemple.fr/é) et <https://x.y>.";
        assert_eq!(
            to_text(markdown, KEEP),
            "Voir la page (https://exemple.fr/é) et https://x.y."
        );
        assert_eq!(to_text(markdown, JOIN), "Voir la page et https://x.y.");
        assert_eq!(to_text("![logo 😀](l.png)", JOIN), "logo 😀");
    }

    #[test]
    fn lines_are_kept_or_joined() {
        let markdown = "Ligne une\nligne  deux\n\nParagraphe 2";
        assert_eq!(
            to_text(markdown, KEEP),
            "Ligne une\nligne  deux\n\nParagraphe 2"
        );
        assert_eq!(
            to_text(markdown, JOIN),
            "Ligne une ligne deux\n\nParagraphe 2"
        );
    }

    #[test]
    fn list_items_are_lines_or_paragraphs() {
        let markdown = "Avant\n- élément un\n- élément *deux*\n  - imbriqué\n\n3. trois\n4. quatre";
        assert_eq!(
            to_text(markdown, KEEP),
            "Avant\n\n- élément un\n- élément deux\n  - imbriqué\n\n3. trois\n4. quatre"
        );
        assert_eq!(
            to_text(markdown, JOIN),
            "Avant\n\n- élément un\n\n- élément deux\n\n  - imbriqué\n\n3. trois\n\n4. quatre"
        );
        assert_eq!(to_text("- a\n\n  suite\n-\n", KEEP), "- a\n  suite\n-");
    }

    #[test]
    fn a_code_block_keeps_its_lines_without_its_fences() {
        let markdown = "```kql\nT\n  | where Name == \"é\"\n```\nAprès";
        assert_eq!(
            to_text(markdown, KEEP),
            "T\n  | where Name == \"é\"\n\nAprès"
        );
        assert_eq!(to_text("    indenté\n", KEEP), "indenté");
    }

    #[test]
    fn headings_and_rules_are_blocks() {
        let markdown = "## Section\nTexte sous le titre:\n\n---\n\n**Label:** valeur";
        assert_eq!(
            to_text(markdown, KEEP),
            "Section\n\nTexte sous le titre:\n\n---\n\nLabel: valeur"
        );
        assert_eq!(
            to_text(markdown, JOIN),
            "Section\n\nTexte sous le titre:\n\nLabel: valeur"
        );
    }

    #[test]
    fn a_wrapped_item_keeps_its_continuation_under_its_text() {
        assert_eq!(to_text("- a\n  b\n- c", KEEP), "- a\n  b\n- c");
        assert_eq!(
            to_text("- x\n  - élément\n    suite 😀\n2. un\n   deux", KEEP),
            "- x\n  - élément\n    suite 😀\n\n2. un\n  deux"
        );
        assert_eq!(to_text("- a\n  b", JOIN), "- a b");
    }

    #[test]
    fn a_code_block_s_leading_blank_lines_are_dropped() {
        assert_eq!(to_text("Avant\n\n```\n\n  é 😀\n```", KEEP), "Avant\n\n  é 😀");
        assert_eq!(to_text("```\n \n\nx\n\ny\n```", KEEP), "x\n\ny");
    }

    #[test]
    fn an_image_inside_a_link_reads_one_url() {
        assert_eq!(to_text("[![logo é](i.png)](https://u/😀)", KEEP), "logo é (https://u/😀)");
        assert_eq!(to_text("![logo](i.png)", KEEP), "logo (i.png)");
        assert_eq!(to_text("[![logo](i.png)](u)", JOIN), "logo");
    }

    #[test]
    fn a_table_is_its_text() {
        assert_eq!(
            to_text("| a | b |\n|---|---|\n| `x` | y |", KEEP),
            "| a | b |\n|---|---|\n| x | y |"
        );
    }
}
