//! Text helpers every section shares (`documentation/markdown/text.py`).
//!
//! Values reach a page from YAML, vocabularies and platform models. These
//! turn them into Markdown that renders the same on every flavour: no raw
//! newlines inside table cells, no unescaped pipes, code spans that hold
//! backticks.
//!
//! [`code_span`] and [`markdown_lines`] are the one copy for every place
//! that writes Markdown, the command line's job summaries included (#1957).

/// Whitespace runs collapsed to one space, the ends trimmed.
pub fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every `|` not already escaped, escaped: a `|` after an odd run of
/// backslashes is escaped already; after an even run (`\\|`) the
/// backslashes escape each other, and the `|` would end the cell.
pub fn escape_pipes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut backslashes = 0usize;
    for c in text.chars() {
        if c == '|' && backslashes.is_multiple_of(2) {
            out.push('\\');
        }
        out.push(c);
        backslashes = if c == '\\' { backslashes + 1 } else { 0 };
    }
    out
}

/// A name (an object's, a signal's) as Markdown text that renders as
/// itself: `\\`, `[`, `]`, `<` and `>` backslash-escaped, so a name cannot
/// open a link (`[x](javascript:…)`), an image or raw HTML (`<b>`).
///
/// A code span (a backtick run, the text, a closing run of the same length)
/// is kept as it is: nothing in it is Markdown, and a backslash there would
/// show.
pub fn markdown_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let mut chars = rest.chars();
        let Some(c) = chars.next() else {
            break;
        };
        if c == '`' {
            let after = rest.trim_start_matches('`');
            let run = rest.len() - after.len();
            out.extend(std::iter::repeat_n('`', run));
            rest = after;
            // No closing run: the backticks are text, as CommonMark reads them.
            if let Some((code, tail)) = closing_code_span(after, run) {
                out.push_str(code);
                rest = tail;
            }
            continue;
        }
        if matches!(c, '\\' | '[' | ']' | '<' | '>') {
            out.push('\\');
        }
        out.push(c);
        rest = chars.as_str();
    }
    out
}

/// `text` cut after the first run of exactly `length` backticks: the code and
/// that closing run, then what follows; `None` when no run closes the span.
fn closing_code_span(text: &str, length: usize) -> Option<(&str, &str)> {
    let mut searched = text;
    while let Some((_, run_on)) = searched.split_once('`') {
        let tail = run_on.trim_start_matches('`');
        if run_on.len() - tail.len() + 1 == length {
            // `tail` is a suffix of `text`, so the cut is on a char boundary.
            let cut = text.len() - tail.len();
            debug_assert!(text.is_char_boundary(cut), "{text:?} cut at {cut}");
            return text.split_at_checked(cut);
        }
        searched = tail;
    }
    None
}

/// One table cell of free text: one line, pipes escaped, `-` when empty.
pub fn table_cell(text: &str) -> String {
    let out = escape_pipes(&collapse(text));
    if out.is_empty() { "-".to_owned() } else { out }
}

/// `text` as a code span, its white space collapsed ([`code_span`]); empty
/// when the text is.
pub fn inline_code(text: &str) -> String {
    let text = collapse(text);
    if text.is_empty() {
        return String::new();
    }
    code_span(&text)
}

/// `text` as a code span, as it is: fenced with a run of backticks longer
/// than any it holds. Nothing in it is escaped; empty when the text is, as
/// CommonMark has no empty code span (`` `` `` is two backticks as text).
///
/// It is padded with a space inside the fence when it starts or ends with a
/// backtick, which would otherwise join the fence, and when it starts and
/// ends with a space (a line ending counts as one), of which CommonMark
/// strips one from each end.
pub fn code_span(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut fence = "`".to_owned();
    while text.contains(&fence) {
        fence.push('`');
    }
    let space = [' ', '\n', '\r'];
    let stripped = text.starts_with(space)
        && text.ends_with(space)
        && !text.chars().all(|c| space.contains(&c));
    let padding = if stripped || text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{padding}{text}{padding}{fence}")
}

/// The lines of `text` as Markdown reads them: a line ends at `\n`, `\r\n`
/// or a lone `\r` (CommonMark), and a line ending at the end of the text
/// starts no line after it. A writer that must keep text on one line, a
/// table cell, joins these.
pub fn markdown_lines(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let Some(at) = rest.find(['\r', '\n']) else {
            return Some(std::mem::take(&mut rest));
        };
        // `at` is the offset of an ASCII byte, so a char boundary.
        let (line, ending) = rest.split_at_checked(at)?;
        rest = ending
            .strip_prefix("\r\n")
            .or_else(|| ending.get(1..))
            .unwrap_or_default();
        Some(line)
    })
}

/// `text` without ATT&CK's inline `(Citation: …)` markers, and the blanks
/// before each.
pub fn strip_citations(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, marker)) = rest.split_once("(Citation:") {
        // An unclosed marker is text.
        let Some((_, after)) = marker.split_once(')') else {
            break;
        };
        out.push_str(before.trim_end());
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Whether `candidate` ends with an abbreviation that does not end a
/// sentence (`e.g.`, `i.e.`, `etc.`, `vs.`, `ex.`).
fn ends_with_abbreviation(candidate: &str) -> bool {
    let lower = candidate.to_lowercase();
    ["e.g.", "i.e.", "etc.", "vs.", "ex."].iter().any(|word| {
        lower.strip_suffix(word).is_some_and(|before| {
            before
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
        })
    })
}

/// The opening sentence of `text`, citations removed, at most `limit`
/// characters: it ends at `.`, `!` or `?` followed by a blank and a capital,
/// a `[` or a `(`.
pub fn first_sentence(text: &str, limit: usize) -> String {
    let collapsed = collapse(&strip_citations(text));
    if collapsed.is_empty() {
        return String::new();
    }
    let chars: Vec<(usize, char)> = collapsed.char_indices().collect();
    for (position, &(at, c)) in chars.iter().enumerate() {
        if c != ' ' || position == 0 {
            continue;
        }
        let before = chars[position - 1].1;
        let after = chars.get(position + 1).map(|&(_, c)| c);
        if matches!(before, '.' | '!' | '?')
            && after.is_some_and(|c| c.is_ascii_uppercase() || c == '[' || c == '(')
        {
            #[expect(
                clippy::string_slice,
                reason = "`at` is a `char_indices` offset, so a char boundary"
            )]
            let candidate = &collapsed[..at];
            if ends_with_abbreviation(candidate) {
                continue;
            }
            return truncate(candidate, limit);
        }
    }
    truncate(&collapsed, limit)
}

/// `text`, whitespace collapsed, cut at `limit` characters on a word
/// boundary, with an ellipsis.
pub fn truncate(text: &str, limit: usize) -> String {
    let collapsed = collapse(text);
    if collapsed.chars().count() <= limit {
        return collapsed;
    }
    let cut: String = collapsed.chars().take(limit.saturating_sub(1)).collect();
    let cut = cut.rsplit_once(' ').map_or(cut.as_str(), |(head, _)| head);
    format!("{}…", cut.trim_end_matches([' ', ',', ';', ':']))
}

/// `1 rule`, `3 rules`.
pub fn plural(count: usize, singular: &str) -> String {
    plural_as(count, singular, &format!("{singular}s"))
}

/// `1 entry`, `3 entries`.
pub fn plural_as(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

/// Values one per line inside a table cell.
pub fn join_lines<I, S>(values: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    values
        .into_iter()
        .filter(|value| !value.as_ref().is_empty())
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>()
        .join("<br>")
}

/// Markdown blocks separated by exactly one blank line: each without its
/// leading and trailing newlines, blank ones left out.
pub fn join<I, S>(parts: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parts
        .into_iter()
        .filter(|part| !part.as_ref().trim().is_empty())
        .map(|part| part.as_ref().trim_matches('\n').to_owned())
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// `str.title()` for the type and direction words tables show.
pub fn title_case(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut start = true;
    for c in text.chars() {
        if c.is_alphabetic() {
            if start {
                out.extend(c.to_uppercase());
            } else {
                out.extend(c.to_lowercase());
            }
            start = false;
        } else {
            out.push(c);
            start = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_cannot_open_links_or_html() {
        assert_eq!(
            markdown_text("[x](javascript:alert(1)) <b>"),
            "\\[x\\](javascript:alert(1)) \\<b\\>"
        );
        assert_eq!(markdown_text("a\\b"), "a\\\\b");
        assert_eq!(markdown_text("Plain name"), "Plain name");
        assert_eq!(
            markdown_text("Detect `<script>` in `C:\\Windows` <b>"),
            "Detect `<script>` in `C:\\Windows` \\<b\\>"
        );
        assert_eq!(markdown_text("``a`b`` [x]"), "``a`b`` \\[x\\]");
        assert_eq!(markdown_text("open ` [x]"), "open ` \\[x\\]");
        assert_eq!(markdown_text("é`<é>`é <"), "é`<é>`é \\<");
    }

    #[test]
    fn a_pipe_after_escaped_backslashes_is_escaped() {
        assert_eq!(table_cell("a|b"), "a\\|b");
        assert_eq!(table_cell("a\\|b"), "a\\|b");
        assert_eq!(table_cell("a\\\\|b"), "a\\\\\\|b");
        assert_eq!(table_cell(&markdown_text("a\\|b")), "a\\\\\\|b");
    }

    #[test]
    fn cells_are_one_line_with_pipes_escaped() {
        assert_eq!(table_cell(" a|b\\|c\n d "), "a\\|b\\|c d");
        assert_eq!(table_cell("  \n"), "-");
    }

    #[test]
    fn code_spans_widen_their_fence() {
        assert_eq!(inline_code("PT1H"), "`PT1H`");
        assert_eq!(inline_code("a`b"), "``a`b``");
        assert_eq!(inline_code("`a`"), "`` `a` ``");
        assert_eq!(inline_code(" \n "), "");
        assert_eq!(inline_code("a\n  b"), "`a b`");
        assert_eq!(inline_code("é ``😀"), "```é ``😀```");
        assert_eq!(inline_code("😀`"), "`` 😀` ``");
    }

    #[test]
    fn code_spans_keep_the_spaces_at_their_ends() {
        // #2059: CommonMark strips one space from each end of a span that
        // starts and ends with one, so those spans take one more.
        assert_eq!(code_span(" a "), "`  a  `");
        assert_eq!(code_span(" é😀 "), "`  é😀  `");
        assert_eq!(code_span("\né\n"), "` \né\n `");
        // One end only, or spaces only: nothing is stripped.
        assert_eq!(code_span(" é"), "` é`");
        assert_eq!(code_span("😀 "), "`😀 `");
        assert_eq!(code_span("  "), "`  `");
        // A backtick at one end and a space at the other.
        assert_eq!(code_span("`é "), "`` `é  ``");
        assert_eq!(code_span(" 😀`"), "``  😀` ``");
    }

    #[test]
    fn an_empty_code_span_is_nothing() {
        // #2059: "``" is two backticks as text, not an empty span.
        assert_eq!(code_span(""), "");
        assert_eq!(code_span("é"), "`é`");
        assert_eq!(code_span("😀"), "`😀`");
    }

    #[test]
    fn a_line_ending_at_the_end_starts_no_line() {
        // #2059: a lone `\r` at the end ends the last line, as `\n` does.
        let lines = |text| markdown_lines(text).collect::<Vec<_>>();
        assert_eq!(lines("a\r"), ["a"]);
        assert_eq!(lines("é\r😀\r"), ["é", "😀"]);
        assert_eq!(lines("é\n"), ["é"]);
        assert_eq!(lines("é\r\n"), ["é"]);
        assert_eq!(lines("é\r\r\n😀"), ["é", "", "😀"]);
        assert_eq!(lines("\r"), [""]);
        assert_eq!(lines("\n\n"), ["", ""]);
        assert!(lines("").is_empty());
        assert_eq!(lines("é"), ["é"]);
    }

    #[test]
    fn first_sentences_skip_abbreviations_and_citations() {
        assert_eq!(
            first_sentence(
                "Adversaries may abuse things. (Citation: OPM) Next one.",
                240
            ),
            "Adversaries may abuse things."
        );
        assert_eq!(
            first_sentence("Tools, e.g. Mimikatz, dump. Then more.", 240),
            "Tools, e.g. Mimikatz, dump."
        );
        assert_eq!(
            first_sentence("Ends here.(Citation: A) And then.", 240),
            "Ends here."
        );
        assert_eq!(first_sentence("one. two", 240), "one. two");
        assert_eq!(
            first_sentence("A [link] here. [B] next", 240),
            "A [link] here."
        );
        assert_eq!(first_sentence("", 240), "");
    }

    #[test]
    fn truncation_cuts_on_a_word() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("alpha beta, gamma delta", 14), "alpha beta…");
        assert_eq!(truncate("abcdefghijkl", 5), "abcd…");
    }

    #[test]
    fn plurals_lines_and_blocks() {
        assert_eq!(plural(1, "rule"), "1 rule");
        assert_eq!(plural(0, "rule"), "0 rules");
        assert_eq!(plural_as(2, "entry", "entries"), "2 entries");
        assert_eq!(join_lines(["a", "", "b"]), "a<br>b");
        assert_eq!(join(["\na\n\n", " ", "", "b\n"]), "a\n\nb");
        assert_eq!(title_case("a-b c"), "A-B C");
    }

    #[test]
    fn multi_byte_text_is_never_cut_inside_a_character() {
        // #1946: code spans, citations, sentences and truncation.
        assert_eq!(
            markdown_text("`é[` [😀] ``a`é`` é"),
            "`é[` \\[😀\\] ``a`é`` é"
        );
        assert_eq!(markdown_text("``é`"), "``é`");
        assert_eq!(markdown_text("😀`"), "😀`");
        assert_eq!(
            strip_citations("Één (Citation: 😀) deux (Citation: é"),
            "Één deux (Citation: é"
        );
        assert_eq!(truncate("ééé 😀😀 ààà", 6), "ééé…");
        assert_eq!(truncate("😀😀😀😀😀😀😀", 4), "😀😀😀…");
        assert_eq!(
            first_sentence("Été chaud. Le 😀 dort. Fin", 100),
            "Été chaud."
        );
    }
}
