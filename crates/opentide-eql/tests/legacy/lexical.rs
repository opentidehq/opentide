//! Checks that follow Elasticsearch's EQL lexer rather than the grammar:
//! nested block comments and the expression-depth pre-scan.

use opentide_core::ByteSpan;
use std::borrow::Cow;
use tree_sitter::Node;

/// Depth limit of `EqlParser.MAX_EXPRESSION_DEPTH`.
pub(crate) const MAX_EXPRESSION_DEPTH: i64 = 250;

/// How Elasticsearch reads one `/* ... */` comment, when that differs from
/// the grammar's first-`*/` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CommentFinding {
    /// Elasticsearch nests this comment; it ends later than the first `*/`.
    Nested(ByteSpan),
    /// Elasticsearch does not read a comment here: `/` and `*` become
    /// operator tokens, which no query can contain side by side.
    NotAComment(ByteSpan),
}

/// The text the grammar parses (block comments Elasticsearch nests have their
/// inner `/` and `*` blanked so tree-sitter ends them where Elasticsearch
/// does; byte offsets are unchanged), and what was found on the way.
pub(crate) struct Prepared<'a> {
    pub text: Cow<'a, str>,
    pub comments: Vec<CommentFinding>,
}

pub(crate) fn prepare(source: &str) -> Prepared<'_> {
    let bytes = source.as_bytes();
    let mut masked: Option<Vec<u8>> = None;
    let mut comments = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' if source[i..].starts_with("\"\"\"") => match raw_string_end(source, i) {
                Some(end) => i = end,
                None => break,
            },
            b'"' | b'\'' => match quoted_end(bytes, i + 1, bytes[i]) {
                Some(end) => i = end,
                None => break,
            },
            b'?' if matches!(bytes.get(i + 1), Some(b'"' | b'\'')) => {
                match quoted_end(bytes, i + 2, bytes[i + 1]) {
                    Some(end) => i = end,
                    None => break,
                }
            }
            b'`' => {
                let mut j = i + 1;
                loop {
                    match bytes.get(j) {
                        None => return finish(source, masked, comments),
                        Some(b'`') if bytes.get(j + 1) == Some(&b'`') => j += 2,
                        Some(b'`') => break,
                        Some(_) => j += 1,
                    }
                }
                i = j + 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i = source[i..].find('\n').map_or(bytes.len(), |n| i + n + 1);
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                // The grammar ends a block comment at the first `*/`.
                let Some(first) = source[i + 2..].find("*/").map(|n| i + 2 + n + 2) else {
                    break;
                };
                if !source[i + 2..first - 1].contains("/*") {
                    i = first;
                    continue;
                }
                match es_comment_end(bytes, i) {
                    Some(end) if end == first => i = first,
                    Some(end) => {
                        let buf = masked.get_or_insert_with(|| bytes.to_vec());
                        for b in &mut buf[i + 2..end - 2] {
                            if matches!(*b, b'*' | b'/') {
                                *b = b' ';
                            }
                        }
                        comments.push(CommentFinding::Nested(ByteSpan::new(i, end)));
                        i = end;
                    }
                    None => {
                        comments.push(CommentFinding::NotAComment(ByteSpan::new(i, i + 2)));
                        i = first;
                    }
                }
            }
            _ => i += 1,
        }
    }
    finish(source, masked, comments)
}

fn finish(source: &str, masked: Option<Vec<u8>>, comments: Vec<CommentFinding>) -> Prepared<'_> {
    // Only ASCII `*` and `/` inside a comment were replaced, so the bytes
    // stay valid UTF-8.
    let text = match masked.map(String::from_utf8) {
        Some(Ok(s)) => Cow::Owned(s),
        _ => Cow::Borrowed(source),
    };
    Prepared { text, comments }
}

/// End of a `"""` string: content runs to the first `"""` on the same line,
/// and up to two more `"` belong to the value.
fn raw_string_end(source: &str, start: usize) -> Option<usize> {
    let rest = &source[start + 3..];
    let close = rest.find("\"\"\"")?;
    if rest[..close].contains(['\r', '\n']) {
        return None;
    }
    let mut end = start + 3 + close + 3;
    for _ in 0..2 {
        if source.as_bytes().get(end) == Some(&b'"') {
            end += 1;
        }
    }
    Some(end)
}

/// End of a single-line quoted string whose body starts at `from`.
fn quoted_end(bytes: &[u8], from: usize, quote: u8) -> Option<usize> {
    let mut j = from;
    loop {
        match *bytes.get(j)? {
            b'\\' => j += 2,
            b'\r' | b'\n' => return None,
            b if b == quote => return Some(j + 1),
            _ => j += 1,
        }
    }
}

/// Where Elasticsearch's lexer ends the block comment that opens at `start`.
///
/// The rule is `'/*' (BRACKETED_COMMENT | .)*? '*/'`: an inner `/*` may open a
/// nested comment or be plain text, and an inner `*/` closes the innermost
/// level. ANTLR explores the alternatives in order (close, nest, any
/// character), drops lower-priority paths once one path finishes the token,
/// and keeps the longest finish. This simulates that, one character at a
/// time, over `(depth, phase)` states. `None` means no comment is lexed. A
/// comment with too many open paths is left to the grammar (`Some(first)`).
fn es_comment_end(bytes: &[u8], start: usize) -> Option<usize> {
    const NORMAL: u8 = 0;
    const STAR: u8 = 1;
    const SLASH: u8 = 2;
    const MAX_STATES: usize = 96;
    let mut states: Vec<(u32, u8)> = vec![(1, NORMAL)];
    let mut best = None;
    let mut pos = start + 2;
    while !states.is_empty() && pos < bytes.len() {
        let c = bytes[pos];
        let mut next: Vec<(u32, u8)> = Vec::with_capacity(states.len() + 2);
        for &(depth, phase) in &states {
            match phase {
                NORMAL => {
                    if c == b'*' {
                        push((depth, STAR), &mut next);
                    }
                    if c == b'/' {
                        push((depth, SLASH), &mut next);
                    }
                    push((depth, NORMAL), &mut next);
                }
                STAR if c == b'/' => {
                    if depth == 1 {
                        best = Some(pos + 1);
                        break;
                    }
                    push((depth - 1, NORMAL), &mut next);
                }
                SLASH if c == b'*' => push((depth + 1, NORMAL), &mut next),
                _ => {}
            }
        }
        if next.len() > MAX_STATES {
            // Pathological input: fall back to the grammar's reading.
            let first = std::str::from_utf8(&bytes[start + 2..]).ok()?.find("*/")?;
            return Some(start + 2 + first + 2);
        }
        states = next;
        pos += 1;
    }
    best
}

/// Adds a state unless an earlier (higher-priority) path already holds it.
fn push(state: (u32, u8), next: &mut Vec<(u32, u8)>) {
    if !next.contains(&state) {
        next.push(state);
    }
}

/// `EqlParser` scans the tokens before parsing: `(` and `)` move a depth
/// counter, and a run of prefix-capable `not`, `-`, `+` tokens adds to it;
/// any other visible token ends the run. Whitespace and comments do not.
/// Returns the token where `depth + run` first exceeds the limit.
pub(crate) fn expression_depth_exceeded(root: Node) -> Option<ByteSpan> {
    let mut depth: i64 = 0;
    let mut chain: i64 = 0;
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if node.child_count() == 0 && !node.is_missing() && node.end_byte() > node.start_byte() {
            match node.kind() {
                "(" => depth += 1,
                ")" => depth -= 1,
                "not" | "-" | "+" if !node.is_named() => chain += 1,
                "comment" => {}
                _ => chain = 0,
            }
            if depth + chain > MAX_EXPRESSION_DEPTH {
                return Some(ByteSpan::new(node.start_byte(), node.end_byte()));
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn end(src: &str) -> Option<&str> {
        let start = src.find("/*")?;
        es_comment_end(src.as_bytes(), start).map(|e| &src[start..e])
    }

    /// Cases checked against the generated `EqlBaseLexer` (ANTLR 4.13).
    #[test]
    fn comment_extent_matches_the_elasticsearch_lexer() {
        assert_eq!(end("a /* x /* y */ z */ b"), Some("/* x /* y */ z */"));
        assert_eq!(end("a /* x /* y */ b"), Some("/* x /* y */"));
        assert_eq!(end("/* /* */ */ */ c"), Some("/* /* */ */"));
        assert_eq!(
            end("a /* x /* y /* z */ */ b"),
            Some("/* x /* y /* z */ */")
        );
        assert_eq!(end("a /*/**y/*/*y*/*/"), Some("/*/**y/*/*y*/"));
        assert_eq!(end("a /*xx /**//*/"), Some("/*xx /**//*/"));
        assert_eq!(end("a /* never closed"), None);
    }

    #[test]
    fn nested_comments_are_masked_to_their_elasticsearch_extent() {
        let src = "process where /* a /* b */ c */ true";
        let p = prepare(src);
        assert_eq!(p.text.len(), src.len());
        assert_eq!(
            p.comments,
            vec![CommentFinding::Nested(ByteSpan::new(14, 31))]
        );
        assert_eq!(&p.text[14..31], "/* a    b    c */");
        // Strings and backticks are not comments.
        let p = prepare("process where a == \"/* /* */\" and `/*` == 1");
        assert!(p.comments.is_empty());
        assert!(matches!(p.text, Cow::Borrowed(_)));
    }
}
