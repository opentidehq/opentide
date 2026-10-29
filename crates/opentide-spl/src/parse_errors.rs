//! `spl_parse_error` at the token tree-sitter could not place.
//!
//! Only the generic error API is used (`ERROR` and `MISSING` nodes and the
//! anonymous `(`, `)`, `[`, `]` tokens), never a grammar rule name, so the
//! positions survive grammar rewrites.

use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};
use opentide_syntax::node_span;
use tree_sitter::Node;

/// A badly broken query reports this many error regions, not one per token.
pub(crate) const MAX_PARSE_ERRORS: usize = 5;

/// Longest token text quoted in a message.
const MAX_QUOTED: usize = 32;

pub(crate) fn collect(root: Node, source: &str, out: &mut Vec<Diagnostic>) {
    for region in error_regions(root, MAX_PARSE_ERRORS) {
        let (span, message) = describe(region, source);
        out.push(Diagnostic::error(
            codes::SPL_PARSE_ERROR,
            message,
            span_to_range(source, span),
        ));
    }
}

/// Outermost `ERROR` and `MISSING` nodes in document order, at most `cap`.
/// A region's own nested errors belong to it and are not listed again.
fn error_regions(root: Node, cap: usize) -> Vec<Node> {
    let mut regions = Vec::new();
    if !erroneous(root) {
        return regions;
    }
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        let region = node.is_error() || node.is_missing();
        if region {
            regions.push(node);
            if regions.len() == cap {
                return regions;
            }
        }
        if !region && erroneous(node) && cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return regions;
            }
        }
    }
}

/// Where and what to report for one error region.
fn describe(region: Node, source: &str) -> (ByteSpan, String) {
    let node = innermost(region);
    if node.is_missing() {
        return missing(node);
    }
    let token = first_leaf(node);
    let text = source
        .get(token.start_byte()..token.end_byte())
        .unwrap_or("")
        .trim();
    let message = if text.is_empty() {
        "SPL syntax error".to_string()
    } else {
        format!("SPL syntax error: unexpected '{}'", quoted(text))
    };
    (node_span(token), message)
}

/// The first error inside `region`: a nested `ERROR` or `MISSING` node wins
/// over the region itself, since recovery often wraps valid text around it.
fn innermost(region: Node) -> Node {
    let mut found = region;
    let mut node = region;
    loop {
        if node.is_missing() {
            return node;
        }
        let mut cursor = node.walk();
        let next = node.children(&mut cursor).find(|child| erroneous(*child));
        match next {
            Some(child) => {
                if child.is_error() || child.is_missing() {
                    found = child;
                }
                node = child;
            }
            None => return found,
        }
    }
}

/// A single-token `ERROR` leaf does not report `has_error`, so ask all three.
fn erroneous(node: Node) -> bool {
    node.is_error() || node.is_missing() || node.has_error()
}

fn first_leaf(node: Node) -> Node {
    let mut leaf = node;
    while let Some(child) = leaf.child(0) {
        leaf = child;
    }
    leaf
}

/// A missing closer points at the opener it would close: that is the token to
/// fix, and the place where the closer is missing is often the end of the query.
fn missing(node: Node) -> (ByteSpan, String) {
    let kind = node.kind();
    let opener = match kind {
        ")" => Some("("),
        "]" => Some("["),
        _ => None,
    };
    if let Some(opener) = opener {
        let mut sibling = node.prev_sibling();
        while let Some(s) = sibling {
            if s.kind() == opener && !s.is_missing() {
                return (
                    node_span(s),
                    format!("SPL syntax error: '{opener}' is never closed"),
                );
            }
            sibling = s.prev_sibling();
        }
    }
    (
        node_span(node),
        format!("SPL syntax error: missing '{kind}'"),
    )
}

fn quoted(text: &str) -> String {
    let line = text.lines().next().unwrap_or("");
    if line.chars().count() <= MAX_QUOTED {
        return line.to_string();
    }
    let cut: String = line.chars().take(MAX_QUOTED).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use crate::analyze;
    use opentide_core::{Diagnostic, Position, codes};

    fn parse_errors(src: &str) -> Vec<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::SPL_PARSE_ERROR)
            .collect()
    }

    fn only_error(src: &str) -> Diagnostic {
        let errors = parse_errors(src);
        assert_eq!(errors.len(), 1, "{src}: {errors:?}");
        errors.into_iter().next().unwrap()
    }

    /// Line and column of the first occurrence of `needle` at or after `from`.
    fn at(src: &str, needle: &str, from: usize) -> Position {
        let offset = from + src[from..].find(needle).expect(needle);
        opentide_core::offset_to_position(src, offset)
    }

    #[test]
    fn stray_token_mid_pipeline_points_at_the_token() {
        let src = "index=a | stats count by host ) | head 1";
        let d = only_error(src);
        assert_eq!(d.range.start, at(src, ")", 0), "{d:?}");
        assert_eq!(d.range.end.character, d.range.start.character + 1);
        assert!(d.message.contains("unexpected ')'"), "{}", d.message);
    }

    #[test]
    fn unclosed_paren_points_at_the_paren() {
        let src = "index=a\n| stats count by host\n| where x=(1\n| head 1";
        let d = only_error(src);
        assert_eq!(d.range.start, at(src, "(", 0), "{d:?}");
        assert_eq!(d.range.start.line, 2);
        assert!(d.message.contains("'(' is never closed"), "{}", d.message);
    }

    #[test]
    fn unclosed_subsearch_points_at_the_bracket() {
        let src = "index=a | join host [ search index=b | head 1";
        let d = only_error(src);
        assert_eq!(d.range.start, at(src, "[", 0), "{d:?}");
        assert!(d.message.contains("'[' is never closed"), "{}", d.message);
    }

    #[test]
    fn eval_concatenation_error_is_on_its_line() {
        // `.` after a string is not concatenation in this grammar yet (#121).
        let src = "index=a\n| stats count\n| eval k=a.\"-\".b";
        let errors = parse_errors(src);
        assert!(!errors.is_empty(), "{errors:?}");
        let d = &errors[0];
        assert_eq!(d.range.start.line, 2, "{d:?}");
        assert!(d.range.start.character > 0, "{d:?}");
        let start = d.range.start.character as usize;
        let line = src.lines().nth(2).unwrap();
        assert_eq!(&line[start..start + 1], ".", "{d:?}");
    }

    #[test]
    fn recovery_around_valid_text_still_finds_the_bad_token() {
        // A table name with `-` splits the identifier; the error is the `-`,
        // not the start of the query that recovery wraps.
        let src = "index=a | lookup t-x.csv key AS dest OUTPUT c AS m";
        let d = &parse_errors(src)[0];
        assert_eq!(d.range.start, at(src, "-", 0), "{d:?}");
    }

    #[test]
    fn one_diagnostic_per_region_and_capped() {
        let two = "index=a | stats count ) | head 1 | eval x=1 = = 2";
        assert_eq!(parse_errors(two).len(), 2, "{:?}", parse_errors(two));
        let many = (0..20)
            .map(|_| "| eval x=1 = = 2")
            .collect::<Vec<_>>()
            .join(" ");
        let src = format!("index=a {many}");
        let errors = parse_errors(&src);
        assert_eq!(errors.len(), super::MAX_PARSE_ERRORS, "{errors:?}");
    }

    #[test]
    fn valid_query_has_no_parse_error() {
        assert!(parse_errors("index=a | stats count by host | head 1").is_empty());
    }

    #[test]
    fn long_tokens_are_shortened_in_the_message() {
        assert_eq!(super::quoted("abc"), "abc");
        let long = "x".repeat(super::MAX_QUOTED + 5);
        let q = super::quoted(&long);
        assert!(q.ends_with('…'), "{q}");
        assert_eq!(q.chars().count(), super::MAX_QUOTED + 1);
        assert_eq!(super::quoted("a\nb"), "a");
    }
}
