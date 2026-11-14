//! Text helpers every section shares (`documentation/markdown/text.py`).
//!
//! Values reach a page from YAML, vocabularies and platform models. These
//! turn them into Markdown that renders the same on every flavour: no raw
//! newlines inside table cells, no unescaped pipes, code spans that hold
//! backticks.

/// Whitespace runs collapsed to one space, the ends trimmed.
pub fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every `|` not already escaped, escaped.
fn escape_pipes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut previous = '\0';
    for c in text.chars() {
        if c == '|' && previous != '\\' {
            out.push('\\');
        }
        out.push(c);
        previous = c;
    }
    out
}

/// One table cell of free text: one line, pipes escaped, `-` when empty.
pub fn table_cell(text: &str) -> String {
    let out = escape_pipes(&collapse(text));
    if out.is_empty() { "-".to_owned() } else { out }
}

/// `text` as a code span, the fence widened when the text holds backticks;
/// empty when the text is.
pub fn inline_code(text: &str) -> String {
    let text = collapse(text);
    if text.is_empty() {
        return String::new();
    }
    let mut fence = "`".to_owned();
    while text.contains(&fence) {
        fence.push('`');
    }
    let padding = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{padding}{text}{padding}{fence}")
}

/// `text` without ATT&CK's inline `(Citation: …)` markers, and the blanks
/// before each.
pub fn strip_citations(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("(Citation:") {
        let Some(end) = rest[at..].find(')') else {
            break;
        };
        out.push_str(rest[..at].trim_end());
        rest = &rest[at + end + 1..];
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
    let cut = match cut.rfind(' ') {
        Some(at) => &cut[..at],
        None => cut.as_str(),
    };
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
}
