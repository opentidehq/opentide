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
    let Some((before, from_query)) = source.split_at_checked(query.host_span.start) else {
        return false;
    };
    let (earlier, head) = before
        .rsplit_once('\n')
        .map_or((None, before), |(earlier, head)| (Some(earlier), head));
    let value = from_query
        .split_once('\n')
        .map_or(from_query, |(value, _)| value);
    let line = format!("{head}{value}");
    let above = earlier.map(|earlier| earlier.rsplit_once('\n').map_or(earlier, |(_, line)| line));
    let marked = marker_start(&line).is_some() || above.is_some_and(|l| marker_start(l).is_some());
    marked && is_stand_in(value)
}

/// Whether `value`, a line from where a value starts, is the stand-in, with or
/// without the marker after it.
fn is_stand_in(value: &str) -> bool {
    before_marker(value).unwrap_or(value).trim() == STAND_IN
}

/// Where the marker that ends `line` starts: opentide's
/// `\s#\s*opentide:placeholder\s*$`, from the blank before the `#`.
fn marker_start(line: &str) -> Option<usize> {
    before_marker(line).map(str::len)
}

/// `line` before the marker that ends it ([`marker_start`]).
fn before_marker(line: &str) -> Option<&str> {
    let rest = line.trim_end().strip_suffix(MARKER)?;
    let rest = rest.trim_end().strip_suffix('#')?;
    let mut chars = rest.chars();
    chars.next_back().filter(|c| c.is_whitespace())?;
    Some(chars.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_ends_the_line_after_a_blank() {
        assert_eq!(marker_start("query: |  # opentide:placeholder"), Some(9));
        assert_eq!(marker_start("query: |\t#opentide:placeholder \r"), Some(8));
        assert_eq!(
            marker_start("x\u{a0}#\u{2003}opentide:placeholder"),
            Some(1)
        );
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

    /// #1946: the stand-in and its marker among multi-byte text.
    #[test]
    fn the_stand_in_among_multi_byte_text() {
        assert!(is_stand_in("... \u{a0}# opentide:placeholder"));
        assert!(!is_stand_in("é... # opentide:placeholder"));
        assert_eq!(
            before_marker("é😀\u{2003}#opentide:placeholder"),
            Some("é😀")
        );
        assert_eq!(before_marker("é😀#opentide:placeholder"), None);
    }
}
