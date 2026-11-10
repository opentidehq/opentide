//! A query `opentide new` left as a placeholder is not checked.
//!
//! `opentide new rule` writes each query it cannot know as the stand-in `...`
//! and marks its key with the comment `# opentide:placeholder`:
//!
//! ```yaml
//!     query: |  # opentide:placeholder
//!       ...
//! ```
//!
//! `opentide validate` skips such a query (it is `opentide lint`'s
//! `placeholders` finding, and a draft must still validate), so the engine
//! reports nothing in it either. The rule is opentide's
//! (`opentide.validation.queries.is_placeholder_query`), for every query
//! language: the marker ends the query's first line (`query: ...  #
//! opentide:placeholder`) or the line above it (`query: |  #
//! opentide:placeholder`), and the query's first line, from where the query
//! starts, is still `...`. A query written under a marker someone forgot to
//! delete is checked.

use crate::InjectedQuery;

/// The comment `opentide new` writes after a value it invented, without its `#`.
const MARKER: &str = "opentide:placeholder";

/// The free-text stand-in `opentide new` writes, a query included.
const STAND_IN: &str = "...";

/// Whether `query`, injected into `source`, is still the stand-in `opentide
/// new` wrote under its marker. `source` is the text the query's offsets are
/// in (after a byte-order mark).
pub fn is_placeholder_query(source: &str, query: &InjectedQuery) -> bool {
    let start = query.host_span.start;
    let Some(before) = source.get(..start) else {
        return false;
    };
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let line_end = source[start..]
        .find('\n')
        .map_or(source.len(), |i| start + i);
    let line = &source[line_start..line_end];
    let above = line_start.checked_sub(1).map(|newline| {
        let above_start = source[..newline].rfind('\n').map_or(0, |i| i + 1);
        &source[above_start..newline]
    });
    let marked = marker_start(line).is_some() || above.is_some_and(|l| marker_start(l).is_some());
    marked && is_stand_in(&source[start..line_end])
}

/// Whether `value`, a line from where a value starts, is the stand-in, with or
/// without the marker after it.
fn is_stand_in(value: &str) -> bool {
    let value = marker_start(value).map_or(value, |at| &value[..at]);
    value.trim_matches(is_space) == STAND_IN
}

/// Where the marker that ends `line` starts: opentide's
/// `\s#\s*opentide:placeholder\s*$`, from the blank before the `#`.
fn marker_start(line: &str) -> Option<usize> {
    let rest = line.trim_end_matches(is_space).strip_suffix(MARKER)?;
    let rest = rest.trim_end_matches(is_space).strip_suffix('#')?;
    let blank = rest.chars().next_back().filter(|&c| is_space(c))?;
    Some(rest.len() - blank.len_utf8())
}

/// Python's whitespace (`\s` in a `str` pattern, `str.strip`): Unicode
/// `White_Space` and the separators `U+001C`..=`U+001F`.
fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_ends_the_line_after_a_blank() {
        assert_eq!(marker_start("query: |  # opentide:placeholder"), Some(9));
        assert_eq!(marker_start("query: |\t#opentide:placeholder \r"), Some(8));
        assert_eq!(marker_start("x\u{a0}#\u{1f}opentide:placeholder"), Some(1));
        // Not at the end, no blank before the `#`, or another word.
        assert_eq!(marker_start("query: |  # opentide:placeholder x"), None);
        assert_eq!(marker_start("query: |# opentide:placeholder"), None);
        assert_eq!(marker_start("#opentide:placeholder"), None);
        assert_eq!(marker_start("query: |  # opentide:placeholders"), None);
        assert_eq!(marker_start("query: |  # OpenTide:placeholder"), None);
    }

    #[test]
    fn the_stand_in_is_three_dots_and_nothing_else() {
        assert!(is_stand_in("..."));
        assert!(is_stand_in("  ...\r"));
        assert!(is_stand_in("...  # opentide:placeholder"));
        assert!(!is_stand_in("...."));
        assert!(!is_stand_in("'...'"));
        assert!(!is_stand_in("… # opentide:placeholder"));
        assert!(!is_stand_in("SecurityEvent  # opentide:placeholder"));
    }

    #[test]
    fn a_file_with_windows_line_endings_keeps_its_placeholder() {
        let source = "configurations:\r\n  sentinel:\r\n    query: |  # opentide:placeholder\r\n      ...\r\n  splunk:\r\n    query: ...  # opentide:placeholder\r\n";
        let queries = crate::extract_injections(source);
        assert_eq!(queries.len(), 2);
        assert!(queries.iter().all(|q| is_placeholder_query(source, q)));
    }
}
