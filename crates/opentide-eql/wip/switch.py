import re,sys
root='/home/user/wt/eql2/crates/opentide-eql/src/'
def edit(name, pairs):
    p=root+name; s=open(p).read()
    for a,b in pairs:
        if a not in s: sys.exit(f"{name}: missing {a[:60]!r}")
        s=s.replace(a,b)
    open(p,'w').write(s)

edit('lib.rs',[
("""mod ecs;
mod lexical;
mod regex;
mod semantics;
""","""mod ecs;
mod lexer;
mod lexical;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the tree printer serves the snapshot tests")
)]
mod parser;
mod regex;
mod semantics;
mod syntax;
mod tree;
"""),
("""use opentide_syntax::{first_error, node_span, parse as ts_parse, walk};
use serde::Deserialize;
use std::sync::OnceLock;
use tree_sitter::Node;
""","""use serde::Deserialize;
use std::sync::OnceLock;
use tree::{Node, node_span, walk};
"""),
("""/// Parses `source` as Elasticsearch reads it: block comments that its lexer
/// nests are blanked inside (same byte offsets) so the grammar ends them at
/// the same place.
fn parse_prepared(source: &str) -> Option<(tree_sitter::Tree, lexical::Prepared<'_>)> {
    let prepared = lexical::prepare(source);
    let tree = ts_parse(LanguageId::Eql, &prepared.text)?;
    Some((tree, prepared))
}
""","""/// Parses `source` as Elasticsearch reads it (the lexer ends a block comment where its lexer
/// does, nested ones too), with what `lexical` finds about its comments.
fn parse_prepared(source: &str) -> Option<(tree::Tree, lexical::Prepared<'_>)> {
    let prepared = lexical::prepare(source);
    Some((tree::parse(source), prepared))
}
"""),
("""    if let Some(err) = first_error(root) {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            parse_error_message(err, source),
            range(source, node_span(err)),
        ));
    }
    check_comments(&prepared.comments, source, &mut out);
    if let Some(span) = lexical::expression_depth_exceeded(root) {""","""    if let Some(problem) = tree.problems.first() {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            parse_error_message(problem, source),
            range(source, problem.token),
        ));
    }
    check_comments(&prepared.comments, source, &mut out);
    if let Some(span) = expression_depth_exceeded(root) {"""),
("""    opentide_syntax::walk_with_ancestors(root, |node, ancestors| {""","""    tree::walk_with_ancestors(root, |node, ancestors| {"""),
("""    let tokens = highlight(&spec, source, &prepared.text);""","""    let tokens = highlight(&spec, source, root);"""),
("""fn parse_error_message(err: Node, source: &str) -> String {
    if err.is_missing() {
        return format!("EQL syntax error: missing `{}`", err.kind());
    }
    let snippet = text(err, source).trim();
    if snippet.starts_with('=') && !snippet.starts_with("==") {
        return "EQL syntax error: use `==` for equality; `=` is not a comparison".into();
    }
    match snippet.split_whitespace().next() {
        Some(first) => {
            let lower = first.to_ascii_lowercase();
            if KEYWORD_WORDS.contains(&lower.as_str()) && first != lower {
                format!("EQL syntax error near `{first}`: keywords are lower case (`{lower}`)")
            } else {
                format!("EQL syntax error near `{first}`")
            }
        }
        None => "EQL syntax error".into(),
    }
}""","""/// The parser's first error, worded for a reader: the token it stopped at and what it
/// expected there.
fn parse_error_message(problem: &tree::Problem, source: &str) -> String {
    if problem.too_deep {
        return format!("EQL syntax error: {}", problem.message);
    }
    let near = source
        .get(problem.token.start..problem.token.end)
        .unwrap_or("")
        .trim();
    if near.starts_with('=') && !near.starts_with("==") {
        return "EQL syntax error: use `==` for equality; `=` is not a comparison".into();
    }
    let expected = problem
        .expected
        .as_deref()
        .map(|e| format!("; expected {e}"))
        .unwrap_or_default();
    if near.is_empty() {
        return format!("EQL syntax error: the query ends too early{expected}");
    }
    let lower = near.to_ascii_lowercase();
    if KEYWORD_WORDS.contains(&lower.as_str()) && near != lower {
        format!("EQL syntax error near `{near}`: keywords are lower case (`{lower}`)")
    } else {
        format!("EQL syntax error near `{near}`{expected}")
    }
}

/// `EqlParser` scans the tokens before parsing: `(` and `)` move a depth counter, and a run of
/// prefix-capable `not`, `-`, `+` tokens adds to it; any other visible token ends the run.
/// Whitespace and comments do not. Returns the token where `depth + run` first exceeds the
/// limit.
fn expression_depth_exceeded(root: Node) -> Option<ByteSpan> {
    let mut depth: i64 = 0;
    let mut chain: i64 = 0;
    let mut found = None;
    walk(root, |node| {
        if found.is_some() || node.child_count() > 0 || node.end_byte() <= node.start_byte() {
            return;
        }
        match node.kind() {
            "(" => depth += 1,
            ")" => depth -= 1,
            "not" | "-" | "+" if !node.is_named() => chain += 1,
            "comment" => {}
            _ => chain = 0,
        }
        if depth + chain > lexical::MAX_EXPRESSION_DEPTH {
            found = Some(node_span(node));
        }
    });
    found
}"""),
("""/// `parsed` is `source` with nested comments blanked; offsets are the same.
fn highlight(spec: &HighlightSpec, source: &str, parsed: &str) -> Vec<HighlightToken> {
    let Ok(mut spans) = opentide_syntax::query_captures(
        LanguageId::Eql,
        parsed,
        opentide_highlight::EQL_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    let catalog = Catalog::cached();
    for (span, capture) in &mut spans {
        if capture == "function" {
            let name = source.get(span.start..span.end).unwrap_or("");
            if catalog.function(name.trim_end_matches('~')).is_some() {
                *capture = "function.builtin".into();
            }
        }
    }
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}""","""/// Each leaf's capture (`tree::capture`), a known function's as `function.builtin`.
fn highlight(spec: &HighlightSpec, source: &str, root: Node) -> Vec<HighlightToken> {
    let catalog = Catalog::cached();
    let mut spans: Vec<(ByteSpan, &str)> = Vec::new();
    walk(root, |node| {
        if node.child_count() > 0 || node.end_byte() <= node.start_byte() {
            return;
        }
        let Some(mut capture) = tree::capture(node) else {
            return;
        };
        if capture == "function"
            && catalog
                .function(text(node, source).trim_end_matches('~'))
                .is_some()
        {
            capture = "function.builtin";
        }
        spans.push((node_span(node), capture));
    });
    tokens_from_spans(spec, source, &spans).unwrap_or_default()
}"""),
])
edit('ecs.rs',[
("""use opentide_syntax::node_span;
use tree_sitter::Node;
""","""use crate::tree::{Node, node_span};
"""),
("""    opentide_syntax::walk(root, |node| check(node, source, &mut out));""","""    crate::tree::walk(root, |node| check(node, source, &mut out));"""),
])
edit('semantics.rs',[("use tree_sitter::Node;\n","use crate::tree::Node;\n")])
edit('regex.rs',[("use tree_sitter::Node;\n","use crate::tree::Node;\n")])
p=root+'lexical.rs'; s=open(p).read()
a=s.index("/// `EqlParser` scans the tokens before parsing")
b=s.index("#[cfg(test)]")
s=s[:a]+s[b:]
s=s.replace("use std::borrow::Cow;\nuse tree_sitter::Node;\n","use std::borrow::Cow;\n")
s=s.replace("//! nested block comments and the expression-depth pre-scan.","//! nested block comments, and the expression-depth pre-scan's limit.")
open(p,'w').write(s)
