//! `regex` / `regex~` patterns. Elasticsearch compiles them as Lucene
//! `RegExp` with `ALL | DEPRECATED_COMPLEMENT` (`RLikePattern`, and the
//! `regexp` query's default flags), always against the whole value.
//!
//! In that dialect `^` and `$` are ordinary characters, and `@` (any
//! string), `#` (empty language), `&` (intersection), `~` (complement), and
//! `<n-m>` (numeric interval) are operators. A `>` outside an interval is a
//! plain character, and a `<` that does not start `<n-m>` fails to compile.
//! There are no inline flags: `(?i)` matches the text `?i`.

use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};
use tree_sitter::Node;

/// The value of an EQL string literal, or `None` for forms the lexer
/// rejects (those are reported elsewhere).
pub(crate) fn string_value(raw: &str) -> Option<String> {
    if let Some(body) = raw.strip_prefix("\"\"\"") {
        // Content, closing `"""`, then up to two extra quotes in the value.
        let close = body.find("\"\"\"")?;
        let extra = &body[close + 3..];
        return Some(format!("{}{extra}", &body[..close]));
    }
    let body = raw.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            'b' => out.push('\u{8}'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'f' => out.push('\u{c}'),
            'r' => out.push('\r'),
            '"' => out.push('"'),
            '\'' => out.push('\''),
            '\\' => out.push('\\'),
            'u' => {
                let rest: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let hex = rest.strip_prefix('{')?;
                out.push(char::from_u32(u32::from_str_radix(hex, 16).ok()?)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Findings {
    /// Unescaped `^` or `$` outside a character class.
    pub anchors: Vec<char>,
    /// Unescaped Lucene operators that are rarely meant: `@ # & ~`.
    pub operators: Vec<char>,
    /// A `(?` group, which Lucene reads as a literal `?`.
    pub inline_flag: bool,
}

pub(crate) fn scan(pattern: &str) -> Findings {
    let chars: Vec<char> = pattern.chars().collect();
    let mut f = Findings::default();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '[' => {
                // A character class: only `\` escapes and the closing `]`
                // matter inside it.
                i += 1;
                while i < chars.len() && chars[i] != ']' {
                    i += if chars[i] == '\\' { 2 } else { 1 };
                }
                i += 1;
            }
            '"' => {
                // A quoted literal: everything up to the next `"` is text.
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    i += 1;
                }
                i += 1;
            }
            '(' if chars.get(i + 1) == Some(&'?') => {
                f.inline_flag = true;
                i += 2;
            }
            c @ ('^' | '$') => {
                note(&mut f.anchors, c);
                i += 1;
            }
            c @ ('@' | '#' | '&' | '~') => {
                note(&mut f.operators, c);
                i += 1;
            }
            _ => i += 1,
        }
    }
    f
}

/// `eql_regex` warnings for each pattern of a `regex` / `regex~` predicate.
pub(crate) fn check_regex(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let operator = node
        .child_by_field_name("operator")
        .map(|o| &source[o.start_byte()..o.end_byte()])
        .unwrap_or("");
    if !operator.starts_with("regex") {
        return;
    }
    let mut cursor = node.walk();
    for value in node.children_by_field_name("values", &mut cursor) {
        if value.kind() != "string" {
            continue;
        }
        let raw = &source[value.start_byte()..value.end_byte()];
        let Some(pattern) = string_value(raw) else {
            continue;
        };
        let f = scan(&pattern);
        let range = span_to_range(source, ByteSpan::new(value.start_byte(), value.end_byte()));
        if !f.anchors.is_empty() {
            let (list, is) = quote_list(&f.anchors);
            out.push(Diagnostic::warning(
                codes::EQL_REGEX,
                format!(
                    "{list} {is} literal in EQL regex (Lucene syntax), not an anchor: patterns always match the whole value. Drop the anchor, or escape it to match the character"
                ),
                range,
            ));
        }
        if !f.operators.is_empty() {
            let (list, is) = quote_list(&f.operators);
            out.push(Diagnostic::warning(
                codes::EQL_REGEX,
                format!(
                    "{list} {is} an operator in EQL regex (Lucene syntax: `@` any string, `#` empty language, `&` intersection, `~` complement); escape with a backslash to match the character"
                ),
                range,
            ));
        }
        if f.inline_flag {
            out.push(Diagnostic::warning(
                codes::EQL_REGEX,
                "EQL regex (Lucene syntax) has no inline flags or `(?...)` groups: `(?i)` matches the text `?i`. Use `regex~` for a case-insensitive match",
                range,
            ));
        }
        // What Elasticsearch's Lucene RegExp makes of it: syntax errors
        // (`a<b`, `\\b`), patterns too complex to determinize, and the
        // `index.max_regex_length` default. Checked against live clusters
        // (testdata/oracles/elasticsearch/eql-misc).
        for problem in opentide_lucene::regexp::elasticsearch_problems(&pattern) {
            let mut d = Diagnostic::error(codes::EQL_REGEX, problem.message, range);
            d.severity = problem.severity;
            out.push(d);
        }
    }
}

fn note(list: &mut Vec<char>, c: char) {
    if !list.contains(&c) {
        list.push(c);
    }
}

/// "`^`" with "is", or "`^`, `$`" with "are".
fn quote_list(chars: &[char]) -> (String, &'static str) {
    let list = chars
        .iter()
        .map(|c| format!("`{c}`"))
        .collect::<Vec<_>>()
        .join(", ");
    (list, if chars.len() == 1 { "is" } else { "are" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_values_follow_the_lexer() {
        assert_eq!(string_value(r#""a\\.b""#).as_deref(), Some(r"a\.b"));
        assert_eq!(string_value(r#""""a\.b""""#).as_deref(), Some(r"a\.b"));
        assert_eq!(string_value("\"\"\"a\"\"\"\"").as_deref(), Some("a\""));
        assert_eq!(string_value(r#""\u{41}""#).as_deref(), Some("A"));
    }

    /// Operator behaviour checked with Lucene 10.5.2 `RegExp(p, ALL |
    /// DEPRECATED_COMPLEMENT)`: `a@b`, `a#b`, `a&b`, `a~b` parse as
    /// operators, `^abc$` matches only the literal text `^abc$`, `a>b` is
    /// literal, `a<b` and `<script>` fail to compile, and `(?i)abc` reads as
    /// the literal `?iabc`.
    #[test]
    fn lucene_operators_and_anchors() {
        assert_eq!(scan("^abc$").anchors, vec!['^', '$']);
        assert_eq!(scan("a@b#c&d~e").operators, vec!['@', '#', '&', '~']);
        assert_eq!(scan(r"a\@b\^c[$^@]").operators, Vec::<char>::new());
        assert!(scan(r"a\@b\^c[$^@]").anchors.is_empty());
        assert_eq!(scan("a>b"), Findings::default());
        assert_eq!(scan("\"@#\""), Findings::default());
        assert!(scan("(?i)abc").inline_flag);
        assert!(!scan(r"\(?i").inline_flag);
    }
}
