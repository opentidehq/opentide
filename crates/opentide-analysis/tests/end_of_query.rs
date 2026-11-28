//! A query that stops too early is reported right after its last token, in
//! every engine: in a file, past a final newline, blank lines or a comment,
//! and in a Tide block (a `|` literal block, then the next key). An error at
//! the end of the input sat on the line after the text or after its comment
//! (#1431 follow-up), or, before #1431, on the query's first character.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]
#![expect(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    reason = "test helpers: a panic fails the test, and the texts are short"
)]

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze};
use opentide_core::LanguageId as L;

/// One engine's query that stops early.
struct Case {
    name: &'static str,
    language: L,
    /// The Tide block up to its query key (`query: |`); empty for none.
    block: &'static str,
    /// The indentation of the block's query lines.
    indent: &'static str,
    query: &'static str,
    /// A comment in the language, when it has comments.
    comment: Option<&'static str>,
}

/// The engines that mark the query's last token rather than the empty span
/// after it.
const MARK_THE_LAST_TOKEN: [&str; 3] = ["kql", "spl", "falco"];

const fn case(
    name: &'static str,
    language: L,
    block: &'static str,
    indent: &'static str,
    query: &'static str,
    comment: Option<&'static str>,
) -> Case {
    Case {
        name,
        language,
        block,
        indent,
        query,
        comment,
    }
}

const CASES: &[Case] = &[
    case(
        "esql",
        L::Esql,
        "configurations:\n  elastic:\n    type: esql\n    query: |\n",
        "      ",
        "FROM logs-* | WHERE (",
        Some("// c"),
    ),
    case(
        "eql",
        L::Eql,
        "configurations:\n  elastic:\n    type: eql\n    query: |\n",
        "      ",
        "process where (",
        Some("// c"),
    ),
    case(
        "kuery",
        L::Kuery,
        "configurations:\n  elastic:\n    type: query\n    query: |\n",
        "      ",
        "a:(b",
        None,
    ),
    case(
        "lucene",
        L::Lucene,
        "configurations:\n  elastic:\n    type: query\n    language: lucene\n    query: |\n",
        "      ",
        "name:(a OR b",
        None,
    ),
    case(
        "kql",
        L::Kql,
        "configurations:\n  sentinel:\n    query: |\n",
        "      ",
        "T | where (",
        Some("// c"),
    ),
    case(
        "spl",
        L::Spl,
        "configurations:\n  splunk:\n    query: |\n",
        "      ",
        "index=x | eval a=(",
        Some("```c```"),
    ),
    case(
        "cql",
        L::Cql,
        "configurations:\n  crowdstrike:\n    query: |\n",
        "      ",
        "a=1 | groupBy(",
        Some("// c"),
    ),
    case(
        "yara",
        L::Yara,
        "configurations:\n  bitdefender:\n    yara:\n      signature: |\n",
        "        ",
        "rule a { condition:",
        Some("// c"),
    ),
    case(
        "exabeam",
        L::Exabeam,
        "configurations:\n  exabeam:\n    sequences:\n      - query: |\n",
        "          ",
        "a =",
        None,
    ),
    case(
        "falco",
        L::Falco,
        "configurations:\n  sysdig:\n    condition: |\n",
        "      ",
        "proc.name = (",
        None,
    ),
    // A Google SecOps block's sections are one assembled rule: its end is
    // not a section's, so YARA-L is checked as a file.
    case(
        "yaral",
        L::Yaral,
        "",
        "",
        "rule r {\n  events:\n    $e.a =",
        Some("// c"),
    ),
];

/// The range and the message of the first syntax error of `text`.
fn first_error(language: L, text: &str) -> Option<((u32, u32, u32, u32), String)> {
    let host = MemoryWorkspace {
        files: vec![("objects/rules/r.yaml".into(), text.to_string())],
    };
    let request = AnalyzeRequest {
        uri: "objects/rules/r.yaml".into(),
        language,
        text: text.to_string(),
    };
    analyze(&host, request)
        .diagnostics
        .into_iter()
        .find(|d| d.code.ends_with("_parse_error"))
        .map(|d| {
            let (start, end) = (d.range.start, d.range.end);
            (
                (start.line, start.character, end.line, end.character),
                d.message,
            )
        })
}

/// Line and UTF-16 column right after `last` (the query's last line) in `text`.
fn after(text: &str, last: &str) -> (u32, u32) {
    let at = text.find(last).unwrap() + last.len();
    let line = text[..at].matches('\n').count() as u32;
    let col = (at - text[..at].rfind('\n').map_or(0, |i| i + 1)) as u32;
    (line, col)
}

/// `text` as the query lines of a block indented by `indent`.
fn indented(text: &str, indent: &str) -> String {
    text.lines()
        .map(|l| {
            if l.is_empty() {
                "\n".to_string()
            } else {
                format!("{indent}{l}\n")
            }
        })
        .collect()
}

/// The first syntax error is the empty span right after the query's last
/// token, or that token where KQL, SPL and Falco mark it: never on a later
/// line, past a comment, on the next YAML key or over the blanks after the
/// query, and its message never quotes the comment that follows.
#[test]
fn every_engine_reports_the_end_of_a_query_after_its_last_token() {
    let mut wrong = Vec::new();
    for c in CASES {
        let last = c.query.lines().last().unwrap();
        let width = last.chars().last().unwrap().len_utf16() as u32;
        let mut endings = vec![
            ("a newline", "\n".to_owned()),
            ("blank lines", "\n\n\n".to_owned()),
        ];
        if let Some(comment) = c.comment {
            endings.push(("a comment", format!(" {comment}\n")));
            endings.push(("a comment touching it", format!("{comment}\n")));
        }
        for (ending, end) in &endings {
            let file = format!("{}{end}", c.query);
            let mut texts = vec![("file", c.language, file.clone())];
            if !c.block.is_empty() {
                let doc = format!("{}{}name: x\n", c.block, indented(&file, c.indent));
                texts.push(("Tide block", L::TideYaml, doc));
            }
            for (host, language, text) in texts {
                let (line, col) = after(&text, last);
                let (range, message) = first_error(language, &text).unwrap_or_default();
                // The empty span right after the last token, or that token.
                let expected = if MARK_THE_LAST_TOKEN.contains(&c.name) {
                    (line, col - width, line, col)
                } else {
                    (line, col, line, col)
                };
                // What follows the query is never quoted as the error.
                let quoted = c.comment.is_some_and(|comment| {
                    message.contains(comment) || message.contains(&comment[..2])
                });
                if range != expected || quoted {
                    wrong.push(format!(
                        "{} {host} ending in {ending}: expected {expected:?}, got {range:?} {message:?}",
                        c.name
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
