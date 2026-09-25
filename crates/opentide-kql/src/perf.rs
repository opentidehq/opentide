//! Warnings for public slow KQL shapes.
//!
//! Source: <https://learn.microsoft.com/en-us/kusto/query/best-practices>
//!
//! Join cardinality and `hint.shufflekey` are intentionally absent: the engine
//! cannot know which side is larger.

use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};
use tree_sitter::Node;

const CITE: &str = "https://learn.microsoft.com/en-us/kusto/query/best-practices";

pub(crate) fn collect(root: Node, source: &str, out: &mut Vec<Diagnostic>) {
    walk(root, source, out);
    warn_scope(source, out);
}

fn walk(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    if node.kind() == "tabular_expression" {
        warn_pipeline(node, source, out);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, out);
    }
}

fn operators(expr: Node<'_>) -> Vec<Node<'_>> {
    let mut ops = Vec::new();
    let mut cursor = expr.walk();
    for child in expr.children(&mut cursor) {
        if child.kind() != "tabular_operator" {
            continue;
        }
        let mut inner = child.walk();
        for grand in child.children(&mut inner) {
            if grand.kind().ends_with("_operator") {
                ops.push(grand);
                break;
            }
        }
    }
    ops
}

fn source_is_table(expr: Node) -> bool {
    expr.child_by_field_name("source")
        .and_then(|src| src.child_by_field_name("table"))
        .is_some_and(|table| table.kind() == "identifier")
}

fn is_filter(kind: &str) -> bool {
    matches!(kind, "where_operator" | "filter_operator")
}

fn is_narrowing_project(kind: &str) -> bool {
    matches!(
        kind,
        "project_operator" | "project_keep_operator" | "project_away_operator"
    )
}

fn warn_pipeline(expr: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let ops = operators(expr);
    if source_is_table(expr) {
        if let Some(first) = ops.first() {
            if !is_filter(first.kind()) {
                if let Some(late) = ops.iter().find(|op| is_filter(op.kind())) {
                    let keyword = if late.kind() == "filter_operator" {
                        "filter"
                    } else {
                        "where"
                    };
                    push(
                        out,
                        source,
                        codes::KQL_WHERE_NOT_FIRST,
                        format!(
                            "`{keyword}` is not the first operator after the table reference; filter before later operators ({CITE})"
                        ),
                        late.start_byte(),
                        late.end_byte(),
                    );
                }
            }
        }
    }

    // Warn only when columns are still wide and a later `project` shows the
    // reversed order. A project already before the operator, or no project
    // at all, is not this diagnostic.
    let mut narrowed = false;
    for (index, op) in ops.iter().enumerate() {
        if is_narrowing_project(op.kind()) {
            narrowed = true;
            continue;
        }
        if narrowed {
            continue;
        }
        let name = match op.kind() {
            "join_operator" => "join",
            "summarize_operator" => "summarize",
            _ => continue,
        };
        let project_later = ops
            .iter()
            .skip(index + 1)
            .any(|later| is_narrowing_project(later.kind()));
        if !project_later {
            continue;
        }
        push(
            out,
            source,
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT,
            format!(
                "`{name}` runs before `project` narrows columns; project the needed columns first ({CITE})"
            ),
            op.start_byte(),
            op.end_byte(),
        );
    }
}

#[derive(Debug)]
enum Kind {
    Word(String),
    Star,
    Pipe,
    LParen,
    RParen,
    Semi,
    String,
}

struct Tok {
    start: usize,
    end: usize,
    kind: Kind,
}

fn tokenize(source: &str) -> Vec<Tok> {
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if c == b'@' && matches!(bytes.get(i + 1), Some(b'"' | b'\'')) {
            let quote = bytes[i + 1];
            let start = i;
            i += 2;
            while i < bytes.len() && bytes[i] != quote {
                i += 1;
            }
            i = (i + 1).min(bytes.len());
            out.push(Tok {
                start,
                end: i,
                kind: Kind::String,
            });
            continue;
        }
        if c == b'"' || c == b'\'' {
            let start = i;
            i = end_quoted(bytes, i);
            out.push(Tok {
                start,
                end: i,
                kind: Kind::String,
            });
            continue;
        }
        if c == b'*' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::Star,
            });
            i += 1;
            continue;
        }
        if c == b'|' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::Pipe,
            });
            i += 1;
            continue;
        }
        if c == b'(' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::LParen,
            });
            i += 1;
            continue;
        }
        if c == b')' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::RParen,
            });
            i += 1;
            continue;
        }
        if c == b';' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::Semi,
            });
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-')
            {
                i += 1;
            }
            out.push(Tok {
                start,
                end: i,
                kind: Kind::Word(source[start..i].to_string()),
            });
            continue;
        }
        i += 1;
    }
    out
}

fn end_quoted(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

enum SearchShape {
    Unscoped,
    Scoped,
    Wildcard(Vec<(usize, usize)>),
}

fn warn_scope(source: &str, out: &mut Vec<Diagnostic>) {
    let tokens = tokenize(source);
    let mut depth = 0i32;
    let mut at_source = true;
    let mut after_pipe = false;
    for (i, tok) in tokens.iter().enumerate() {
        match &tok.kind {
            Kind::LParen => {
                depth += 1;
            }
            Kind::RParen => {
                depth = (depth - 1).max(0);
                after_pipe = false;
            }
            Kind::Semi if depth == 0 => {
                at_source = true;
                after_pipe = false;
            }
            Kind::Pipe => {
                after_pipe = true;
                at_source = false;
            }
            Kind::Star if at_source => {
                push(
                    out,
                    source,
                    codes::KQL_WILDCARD_TABLE,
                    format!(
                        "wildcard table `*` scans every table; name the table instead ({CITE})"
                    ),
                    tok.start,
                    tok.end,
                );
                at_source = false;
                after_pipe = false;
            }
            Kind::Word(word) if word == "search" && at_source => {
                match classify_search(&tokens, i) {
                    SearchShape::Unscoped => push(
                        out,
                        source,
                        codes::KQL_UNSCOPED_SEARCH,
                        format!(
                            "unscoped `search` reads every table; scope it with `in (Table, ...)` or start from a table ({CITE})"
                        ),
                        tok.start,
                        tok.end,
                    ),
                    SearchShape::Wildcard(stars) => {
                        for (start, end) in stars {
                            push(
                                out,
                                source,
                                codes::KQL_WILDCARD_TABLE,
                                format!(
                                    "wildcard table `*` scans every table; name the table instead ({CITE})"
                                ),
                                start,
                                end,
                            );
                        }
                    }
                    SearchShape::Scoped => {}
                }
                at_source = false;
                after_pipe = false;
            }
            Kind::Word(word) if word == "union" && (at_source || after_pipe) => {
                if let Some((start, end)) = union_star(&tokens, i) {
                    push(
                        out,
                        source,
                        codes::KQL_UNSCOPED_UNION,
                        format!(
                            "unscoped `union` uses wildcard table `*` and reads every table; name the tables instead ({CITE})"
                        ),
                        start,
                        end,
                    );
                }
                at_source = false;
                after_pipe = false;
            }
            Kind::Word(_) | Kind::String | Kind::Star => {
                if at_source {
                    at_source = false;
                }
                after_pipe = false;
            }
            Kind::Semi => {}
        }
    }
}

fn classify_search(tokens: &[Tok], index: usize) -> SearchShape {
    let mut depth = 0i32;
    let mut saw_in = false;
    let mut list_at = None;
    let mut predicate = false;
    for (offset, tok) in tokens.iter().enumerate().skip(index + 1) {
        match &tok.kind {
            Kind::Pipe | Kind::Semi if depth == 0 => break,
            Kind::RParen if depth == 0 => break,
            Kind::LParen => {
                if saw_in && depth == 0 && list_at.is_none() {
                    list_at = Some(offset);
                }
                depth += 1;
            }
            Kind::RParen => {
                depth -= 1;
            }
            Kind::Word(word) if depth == 0 && word == "in" => {
                saw_in = true;
            }
            Kind::Word(word)
                if depth == 0 && word != "kind" && word != "isfuzzy" && word != "withsource" =>
            {
                predicate = true;
            }
            Kind::Star | Kind::String if depth == 0 => {
                predicate = true;
            }
            _ => {}
        }
    }
    if let Some(paren) = list_at {
        let stars = stars_in_list(tokens, paren);
        if stars.is_empty() {
            SearchShape::Scoped
        } else {
            SearchShape::Wildcard(stars)
        }
    } else if predicate {
        SearchShape::Unscoped
    } else {
        SearchShape::Scoped
    }
}

fn stars_in_list(tokens: &[Tok], paren_idx: usize) -> Vec<(usize, usize)> {
    let mut depth = 0i32;
    let mut stars = Vec::new();
    for tok in tokens.iter().skip(paren_idx) {
        match &tok.kind {
            Kind::LParen => depth += 1,
            Kind::RParen => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Kind::Star if depth == 1 => stars.push((tok.start, tok.end)),
            _ => {}
        }
    }
    stars
}

fn union_star(tokens: &[Tok], union_idx: usize) -> Option<(usize, usize)> {
    let mut depth = 0i32;
    for tok in tokens.iter().skip(union_idx + 1) {
        match &tok.kind {
            Kind::Pipe | Kind::Semi if depth == 0 => break,
            Kind::RParen if depth == 0 => break,
            Kind::LParen => depth += 1,
            Kind::RParen => depth -= 1,
            Kind::Star if depth == 0 => return Some((tok.start, tok.end)),
            _ => {}
        }
    }
    None
}

fn push(
    out: &mut Vec<Diagnostic>,
    source: &str,
    code: &str,
    message: String,
    start: usize,
    end: usize,
) {
    let start = start.min(source.len());
    let end = end.min(source.len());
    if start >= end {
        return;
    }
    let range = span_to_range(source, ByteSpan::new(start, end));
    if out.iter().any(|d| d.code == code && d.range == range) {
        return;
    }
    out.push(Diagnostic::warning(code, message, range));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Profile, analyze};
    use opentide_core::Severity;

    fn warnings(src: &str) -> Vec<Diagnostic> {
        analyze(src, Profile::Sentinel)
            .diagnostics
            .into_iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect()
    }

    fn has(src: &str, code: &str) -> bool {
        warnings(src)
            .iter()
            .any(|d| d.code == code && d.message.contains(CITE))
    }

    #[test]
    fn where_not_first_after_table() {
        let src = "SecurityEvent | extend Computer = tolower(Computer) | where EventID == 4688";
        let found = warnings(src)
            .into_iter()
            .find(|d| d.code == codes::KQL_WHERE_NOT_FIRST)
            .expect("where warning");
        assert_eq!(found.severity, Severity::Warning);
        assert!(found.message.contains(CITE));
        assert!(found.range.end.character > found.range.start.character);
        assert!(!has(
            "SecurityEvent | where EventID == 4688 | extend Computer = Computer",
            codes::KQL_WHERE_NOT_FIRST
        ));
        assert!(!has(
            "SecurityEvent | filter EventID == 4688 | take 1",
            codes::KQL_WHERE_NOT_FIRST
        ));
    }

    #[test]
    fn unscoped_search_union_and_wildcard_table() {
        assert!(has("search \"error\"", codes::KQL_UNSCOPED_SEARCH));
        assert!(has("search *", codes::KQL_UNSCOPED_SEARCH));
        assert!(!has("search *", codes::KQL_WILDCARD_TABLE));
        assert!(!has(
            "search in (SecurityEvent) \"error\"",
            codes::KQL_UNSCOPED_SEARCH
        ));
        assert!(!has(
            "SecurityEvent | search \"error\"",
            codes::KQL_UNSCOPED_SEARCH
        ));
        assert!(has("union *", codes::KQL_UNSCOPED_UNION));
        assert!(!has(
            "SecurityEvent | union SecurityAlert",
            codes::KQL_UNSCOPED_UNION
        ));
        assert!(has("* | take 1", codes::KQL_WILDCARD_TABLE));
        assert!(has(
            "search in (SecurityEvent, *) \"error\"",
            codes::KQL_WILDCARD_TABLE
        ));
    }

    #[test]
    fn join_or_summarize_before_visible_project() {
        assert!(has(
            "SecurityEvent | join kind=inner SecurityAlert on EventID | project Computer",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(has(
            "SecurityEvent | where EventID == 4688 | summarize count() by Computer | project Computer",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(!has(
            "SecurityEvent | join kind=inner SecurityAlert on EventID",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(!has(
            "SecurityEvent | where EventID == 4688 | summarize count() by Computer",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(!has(
            "SecurityEvent | where EventID == 4688 | project Computer, EventID | summarize count() by Computer",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(!has(
            "SecurityEvent | project Computer, EventID | join kind=inner SecurityAlert on EventID",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
    }

    #[test]
    fn no_cardinality_or_shufflekey_warning() {
        let src = "SecurityEvent | join hint.shufflekey=EventID SecurityAlert on EventID";
        let r = analyze(src, Profile::Sentinel);
        assert!(r.diagnostics.iter().all(|d| {
            let msg = d.message.to_ascii_lowercase();
            !msg.contains("shuffle")
                && !msg.contains("cardinality")
                && !msg.contains("prefer lookup")
                && !d.code.contains("shuffle")
                && !d.code.contains("cardinality")
        }));
    }

    #[test]
    fn filtered_sentinel_hunt_is_clean() {
        let src = "\
SecurityEvent
| where EventID == 4688 and TimeGenerated > ago(1d)
| project Computer, EventID, TimeGenerated
| summarize count() by Computer";
        let r = analyze(src, Profile::Sentinel);
        assert!(
            r.diagnostics.iter().all(|d| {
                !matches!(
                    d.code.as_str(),
                    codes::KQL_WHERE_NOT_FIRST
                        | codes::KQL_UNSCOPED_SEARCH
                        | codes::KQL_UNSCOPED_UNION
                        | codes::KQL_WILDCARD_TABLE
                        | codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
                )
            }),
            "{:?}",
            r.diagnostics
        );
        assert!(
            !r.diagnostics
                .iter()
                .any(|d| d.code == codes::KQL_PARSE_ERROR),
            "{:?}",
            r.diagnostics
        );
    }
}
