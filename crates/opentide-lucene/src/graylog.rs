//! The Graylog dialect (graylog-1.0, "Query dialect" and "Query
//! diagnostics").
//!
//! Graylog hands the query to OpenSearch or Elasticsearch `query_string`
//! unchanged, so the Elastic checks apply, and its own validator
//! (`POST /api/search/validate`) parses it with Lucene's classic parser and
//! compiles each regex. What Graylog adds is checked here:
//!
//! - `graylog_leading_wildcard`: `allow_leading_wildcard_searches` is off by
//!   default, and Graylog refuses `*x`, `?x`, and `f:*` ("'*' or '?' not
//!   allowed as first character in WildcardQuery"). opentide filters it per
//!   tenant; the engine reports it unconditionally.
//! - `graylog_regex_unsupported`: PCRE-only regex syntax. `(?i)`, `(?:`,
//!   lookarounds and backreferences are literal text to Lucene, so the regex
//!   silently matches nothing; `\b` and `\B` are refused.
//! - `graylog_regex_operator`, `graylog_regex_quote`: characters Lucene reads
//!   as regex operators (`#`, `&`, `~`, `<`, `>`) or as a quoted literal
//!   (`"`), which Graylog's validator still calls OK.
//! - `graylog_double_backslash`: `\\` is one literal backslash in a Graylog
//!   query, so `\\\\` matches two.
//! - `graylog_analyzed_field`: `message` and `full_message` are tokenised.
//!
//! Verified on Graylog 7.2.2 and 6.3.5 (`testdata/oracles/graylog/`).

use opentide_core::{ByteSpan, CompletionItem, Diagnostic, codes, span_to_range};
use tree_sitter::Node;

/// Graylog's built-in message fields, with what each holds.
pub const MESSAGE_FIELDS: [(&str, &str); 8] = [
    (
        "message",
        "The message text. Analysed: tokenised and lower-cased, so a regex, wildcard, or range matches single tokens.",
    ),
    (
        "full_message",
        "The full message text (GELF). Analysed like `message`.",
    ),
    (
        "source",
        "The host that sent the message. A lower-cased keyword.",
    ),
    ("timestamp", "When the message was created."),
    (
        "streams",
        "The ids of the streams the message is routed to.",
    ),
    (
        "gl2_source_input",
        "The id of the input that received the message.",
    ),
    (
        "gl2_source_node",
        "The id of the Graylog node that received the message.",
    ),
    ("gl2_message_id", "Graylog's unique id of the message."),
];

/// The fields Graylog tokenises, where a regex, wildcard, or range sees
/// single tokens.
const ANALYZED: [&str; 2] = ["message", "full_message"];

const DOCS: &str =
    "https://go2docs.graylog.org/current/making_sense_of_your_log_data/writing_search_queries.html";

fn text<'a>(node: Node, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn range(source: &str, start: usize, end: usize) -> opentide_core::Range {
    span_to_range(source, ByteSpan::new(start, end))
}

/// `graylog_leading_wildcard` on a `term_query` whose term starts with `*`
/// or `?`.
pub(crate) fn leading_wildcard(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let Some(term) = node.child_by_field_name("term") else {
        return;
    };
    if !matches!(term.kind(), "star" | "wildcard_term") {
        return;
    }
    let word = text(term, source);
    let Some(first) = word.chars().next().filter(|c| matches!(c, '*' | '?')) else {
        return;
    };
    let field = node
        .parent()
        .filter(|p| p.kind() == "field_query")
        .and_then(|p| p.child_by_field_name("field"))
        .map(|f| text(f, source));
    let advice = match field {
        Some("*") | None if word == "*" => {
            "to match messages that have a field, write `_exists_:<field>`".to_string()
        }
        Some(f) if word == "*" => format!("to match any value, write `_exists_:{f}`"),
        Some(f) => format!(
            "a regex with a leading `.*` is the portable form (`{f}:/{}/`)",
            regex_for(word)
        ),
        None => "a regex with a leading `.*` on a field is the portable form".to_string(),
    };
    out.push(Diagnostic::error(
        codes::GRAYLOG_LEADING_WILDCARD,
        format!(
            "`{word}` starts with `{first}`: Graylog refuses a leading wildcard (\"'*' or '?' not allowed as first character\") unless the server sets `allow_leading_wildcard_searches`; {advice}"
        ),
        range(source, term.start_byte(), term.end_byte()),
    ));
}

/// `graylog_open_range` on each `*` bound of a `range_query`: Graylog's
/// validator refuses it, so deploy cannot save the definition.
pub(crate) fn open_range(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let field = node
        .parent()
        .filter(|p| p.kind() == "field_query")
        .and_then(|p| p.child_by_field_name("field"))
        .map_or("field", |f| text(f, source));
    let token = |name: &str| node.child_by_field_name(name).map(|n| text(n, source));
    let (Some(lower), Some(upper)) = (
        node.child_by_field_name("lower"),
        node.child_by_field_name("upper"),
    ) else {
        return;
    };
    let advice = match (text(lower, source), text(upper, source)) {
        ("*", "*") => format!("to match any value, write `_exists_:{field}`"),
        ("*", value) => {
            let op = if token("close") == Some("]") {
                "<="
            } else {
                "<"
            };
            format!("write `{field}:{op}{value}`")
        }
        (value, "*") => {
            let op = if token("open") == Some("[") {
                ">="
            } else {
                ">"
            };
            format!("write `{field}:{op}{value}`")
        }
        _ => return,
    };
    for star in [lower, upper]
        .into_iter()
        .filter(|b| text(*b, source) == "*")
    {
        out.push(Diagnostic::error(
            codes::GRAYLOG_OPEN_RANGE,
            format!(
                "Graylog's query validator refuses `*` as a range bound, so deploy cannot save the definition; {advice}"
            ),
            range(source, star.start_byte(), star.end_byte()),
        ));
    }
}

/// A wildcard term as the Lucene regex that matches the same values.
fn regex_for(word: &str) -> String {
    let mut out = String::new();
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '\\' => {
                if let Some(next) = chars.next() {
                    push_literal(&mut out, next);
                }
            }
            c => push_literal(&mut out, c),
        }
    }
    out
}

fn push_literal(out: &mut String, c: char) {
    if ".?+*|{}[]()\"\\#@&<>~/".contains(c) {
        out.push('\\');
    }
    out.push(c);
}

/// `graylog_analyzed_field`: a regex, wildcard, or range under
/// `message:` or `full_message:`. `node` is a `regexp_query`, `term_query`,
/// or `range_query`.
pub(crate) fn analyzed_field(
    node: Node,
    ancestors: &[Node],
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let what = match node.kind() {
        "regexp_query" => "a regex",
        "range_query" => "a range",
        "term_query" => {
            let Some(term) = node.child_by_field_name("term") else {
                return;
            };
            let word = text(term, source);
            if matches!(term.kind(), "star" | "wildcard_term") {
                "a wildcard"
            } else if word.len() > 1 && word.starts_with(['<', '>']) {
                "a range"
            } else {
                return;
            }
        }
        _ => return,
    };
    let Some(field) = ancestors
        .iter()
        .rev()
        .find(|n| n.kind() == "field_query")
        .and_then(|n| n.child_by_field_name("field"))
        .map(|f| text(f, source))
    else {
        return;
    };
    if !ANALYZED.contains(&field) {
        return;
    }
    out.push(Diagnostic::warning(
        codes::GRAYLOG_ANALYZED_FIELD,
        format!(
            "`{field}` is analysed (tokenised and lower-cased), so {what} on it matches single tokens, never the whole value; match a keyword field, or a lower-cased copy a pipeline writes"
        ),
        range(source, node.start_byte(), node.end_byte()),
    ));
}

/// `graylog_double_backslash`: each run of four or more backslashes.
pub(crate) fn double_backslash(source: &str, out: &mut Vec<Diagnostic>) {
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i] == b'\\' {
            i += 1;
        }
        if i - start >= 4 {
            out.push(Diagnostic::warning(
                codes::GRAYLOG_DOUBLE_BACKSLASH,
                "`\\\\` is already one literal backslash in a Graylog query, so four backslashes match two; write `\\\\` for one",
                range(source, start, i),
            ));
        }
    }
}

/// One finding inside a regex body: byte offset and length in the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BodyFinding {
    pub at: usize,
    pub len: usize,
    pub message: String,
}

/// What the scan of a regex body found.
#[derive(Debug, Default)]
pub(crate) struct RegexScan {
    /// `graylog_regex_unsupported`.
    pub unsupported: Vec<BodyFinding>,
    /// `graylog_regex_operator`.
    pub operators: Vec<BodyFinding>,
    /// `graylog_regex_quote`: each quoted literal.
    pub quotes: Vec<BodyFinding>,
    /// The body with the unsupported syntax replaced by `.` (same length in
    /// characters and bytes), for Lucene's own check, so one construct is
    /// not reported twice.
    pub masked: String,
}

/// Scan a `/regex/` body the way Lucene's `RegExp` reads it: `\` escapes
/// the next character, `[...]` is a class (its first member may be `]`),
/// `"..."` a quoted literal, `<n-m>` a numeric interval.
pub(crate) fn scan_regex(body: &str) -> RegexScan {
    let chars: Vec<(usize, char)> = body.char_indices().collect();
    let mut scan = RegexScan::default();
    let mut masked: Vec<char> = chars.iter().map(|&(_, c)| c).collect();
    let byte = |i: usize| chars.get(i).map_or(body.len(), |c| c.0);
    let width = |from: usize, to: usize| byte(to) - byte(from);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i].1;
        match c {
            '\\' => {
                let Some(&(_, next)) = chars.get(i + 1) else {
                    break;
                };
                match next {
                    'b' | 'B' => {
                        scan.unsupported.push(BodyFinding {
                            at: byte(i),
                            len: width(i, i + 2),
                            message: format!(
                                "`\\{next}` is a PCRE word boundary; Lucene regular expressions have none, and Graylog refuses the query (\"invalid character class\"). Lucene regexps match the whole term: drop it, or use `.*` around the word"
                            ),
                        });
                        masked[i + 1] = '.';
                    }
                    '1'..='9' => scan.unsupported.push(BodyFinding {
                        at: byte(i),
                        len: width(i, i + 2),
                        message: format!(
                            "`\\{next}` is a PCRE backreference; Lucene reads it as the digit `{next}`, so the regex silently matches something else. Repeat the group's text instead"
                        ),
                    }),
                    _ => {}
                }
                i += 2;
            }
            '[' => {
                // The first member after `[` or `[^` may be `]`.
                i += 1;
                if chars.get(i).is_some_and(|c| c.1 == '^') {
                    i += 1;
                }
                let mut first = true;
                while i < chars.len() && (first || chars[i].1 != ']') {
                    first = false;
                    if chars[i].1 == '\\' {
                        if let Some(&(_, n @ ('b' | 'B'))) = chars.get(i + 1) {
                            scan.unsupported.push(BodyFinding {
                                at: byte(i),
                                len: width(i, i + 2),
                                message: format!(
                                    "`\\{n}` is not a Lucene character class; Graylog refuses the query (\"invalid character class\")"
                                ),
                            });
                            masked[i + 1] = '.';
                        }
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                let open = i;
                i += 1;
                while i < chars.len() && chars[i].1 != '"' {
                    i += 1;
                }
                if i < chars.len() {
                    scan.quotes.push(BodyFinding {
                        at: byte(open),
                        len: width(open, i + 1),
                        message: "`\"` starts a quoted literal in a Lucene regular expression, so the quotes are not matched as characters; escape each as `\\\"`".into(),
                    });
                }
                i += 1;
            }
            '(' if chars.get(i + 1).is_some_and(|c| c.1 == '?') => {
                // `(?…)`: flags, a non-capturing or named group, or a
                // lookaround. Mask the `?…` prefix up to the group's body.
                let start = i + 1;
                let mut end = start + 1;
                while end < chars.len()
                    && (chars[end].1.is_ascii_alphanumeric()
                        || matches!(chars[end].1, '_' | '<' | '>' | '=' | '!' | ':' | '-'))
                {
                    end += 1;
                }
                let prefix: String = chars[i..end.min(i + 5)].iter().map(|c| c.1).collect();
                let (kind, advice) = match chars.get(start + 1).map(|c| c.1) {
                    Some('=' | '!') => ("a lookahead", ""),
                    Some('<') if matches!(chars.get(start + 2).map(|c| c.1), Some('=' | '!')) => {
                        ("a lookbehind", "")
                    }
                    Some(':') => ("a non-capturing group", "; a plain `(…)` group is the same"),
                    Some('<' | 'P') => ("a named group", "; use a plain `(…)` group"),
                    _ => (
                        "an inline flag",
                        "; Lucene regexps are case-sensitive, so match a lower-cased copy of the field with lower-case text",
                    ),
                };
                scan.unsupported.push(BodyFinding {
                    at: byte(i),
                    len: width(i, start + 1),
                    message: format!(
                        "`{prefix}…` is {kind}, which Lucene regular expressions do not have: Lucene reads `?` and what follows as text, so the regex silently matches nothing{advice}"
                    ),
                });
                for m in masked.iter_mut().take(end).skip(start) {
                    *m = '.';
                }
                i = end;
            }
            '#' | '&' | '~' | '>' => {
                scan.operators.push(operator(c, byte(i), width(i, i + 1)));
                i += 1;
            }
            '<' => {
                // A numeric interval `<n-m>` is fine.
                let close = (i + 1..chars.len()).find(|&j| chars[j].1 == '>');
                let interval = close.is_some_and(|j| {
                    let inner: String = chars[i + 1..j].iter().map(|c| c.1).collect();
                    numeric_interval(&inner)
                });
                if let (true, Some(j)) = (interval, close) {
                    i = j + 1;
                } else {
                    scan.operators.push(operator(c, byte(i), width(i, i + 1)));
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    scan.masked = masked.into_iter().collect();
    scan
}

fn numeric_interval(inner: &str) -> bool {
    let Some((lo, hi)) = inner.split_once('-') else {
        return false;
    };
    let int = |s: &str| {
        let digits = s.strip_prefix('+').unwrap_or(s);
        !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
    };
    int(lo) && int(hi)
}

fn operator(c: char, at: usize, len: usize) -> BodyFinding {
    let meaning = match c {
        '#' => "the empty language (it matches nothing)",
        '&' => "intersection",
        '~' => "complement",
        '<' | '>' => "a numeric interval `<n-m>` or a named automaton",
        _ => "an operator",
    };
    BodyFinding {
        at,
        len,
        message: format!(
            "`{c}` is {meaning} in a Lucene regular expression, not the character, and Graylog's validator does not say so; escape it as `\\{c}`"
        ),
    }
}

/// Documentation of a built-in message field, or of `_exists_`.
pub fn field_docs(name: &str) -> Option<String> {
    if name == "_exists_" {
        return Some(format!(
            "**`_exists_`** (Graylog)\n\n`_exists_:field` matches messages that have the field.\n\n[Graylog docs]({DOCS})"
        ));
    }
    MESSAGE_FIELDS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(n, d)| format!("**`{n}`** (Graylog message field)\n\n{d}\n\n[Graylog docs]({DOCS})"))
}

/// The built-in message fields and `_exists_`, for completion.
pub fn completions() -> Vec<CompletionItem> {
    MESSAGE_FIELDS
        .iter()
        .map(|(n, d)| {
            CompletionItem::new(*n, "property")
                .with_detail("Graylog message field")
                .with_docs(*d)
        })
        .chain(std::iter::once(
            CompletionItem::new("_exists_", "keyword")
                .with_detail("Graylog")
                .with_docs("`_exists_:field` matches messages that have the field."),
        ))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_finds_pcre_syntax_and_masks_it() {
        let s = scan_regex(r"(?i)cmd\b.*");
        assert_eq!(s.unsupported.len(), 2);
        assert_eq!(s.masked, r"(..)cmd\..*");
        let s = scan_regex(r"(?<=a)b(?!c)");
        assert_eq!(s.unsupported.len(), 2);
        assert!(s.unsupported[0].message.contains("lookbehind"));
        assert!(s.unsupported[1].message.contains("lookahead"));
        assert!(
            scan_regex(r"(a)\1").unsupported[0]
                .message
                .contains("backreference")
        );
        // In a class, `(?` and `\1` are members.
        assert!(scan_regex(r"[(?1]x").unsupported.is_empty());
        assert!(scan_regex(r"\\b\(?").unsupported.is_empty());
    }

    #[test]
    fn scan_finds_operators_outside_classes_quotes_and_intervals() {
        let at = |body: &str| -> Vec<usize> {
            scan_regex(body).operators.iter().map(|f| f.at).collect()
        };
        assert_eq!(at(".*f~g.*"), [3]);
        assert_eq!(at("a#b&c"), [1, 3]);
        assert_eq!(at("a<16-31>b"), Vec::<usize>::new());
        assert_eq!(at("a<+1-5>"), Vec::<usize>::new());
        assert_eq!(at("a<b"), [1]);
        assert_eq!(at("a>b"), [1]);
        assert_eq!(at(r"a\~b[<>#&~]"), Vec::<usize>::new());
        assert_eq!(at("\"a~b\""), Vec::<usize>::new());
        // Byte offsets past multibyte text.
        assert_eq!(at("é~"), [2]);
    }

    #[test]
    fn open_range_bounds_are_refused_with_a_rewrite() {
        let found = |q: &str| {
            crate::analyze_dialect(q, crate::Dialect::Graylog)
                .diagnostics
                .into_iter()
                .filter(|d| d.code == codes::GRAYLOG_OPEN_RANGE)
                .map(|d| (d.message, d.range))
                .collect::<Vec<_>>()
        };
        let upper = found("bytes:[1 TO *]");
        assert_eq!(upper.len(), 1);
        assert!(upper[0].0.ends_with("write `bytes:>=1`"), "{upper:?}");
        assert_eq!(
            (upper[0].1.start.character, upper[0].1.end.character),
            (12, 13)
        );
        let lower = found("bytes:{* TO 5}");
        assert!(lower[0].0.ends_with("write `bytes:<5`"), "{lower:?}");
        let both = found("é:[* TO *]");
        assert_eq!(both.len(), 2);
        assert!(both[0].0.ends_with("write `_exists_:é`"), "{both:?}");
        assert!(found("bytes:[1 TO 5]").is_empty());
        assert!(
            crate::analyze_dialect("bytes:[1 TO *]", crate::Dialect::Elastic)
                .diagnostics
                .iter()
                .all(|d| d.code != codes::GRAYLOG_OPEN_RANGE)
        );
    }

    #[test]
    fn scan_finds_quoted_literals() {
        let s = scan_regex(r#"a"b c"d"#);
        assert_eq!(s.quotes.len(), 1);
        assert_eq!((s.quotes[0].at, s.quotes[0].len), (1, 5));
        assert!(scan_regex(r#"a\"b"#).quotes.is_empty());
        assert!(scan_regex(r#"["]"#).quotes.is_empty());
    }

    #[test]
    fn wildcards_become_regexes() {
        assert_eq!(regex_for("*cmd.exe"), r".*cmd\.exe");
        assert_eq!(regex_for("?a\\*"), r".a\*");
    }

    #[test]
    fn fields_are_documented() {
        assert!(field_docs("message").unwrap().contains("Analysed"));
        assert!(field_docs("_exists_").is_some());
        assert!(field_docs("EventID").is_none());
        assert_eq!(completions().len(), MESSAGE_FIELDS.len() + 1);
    }
}
