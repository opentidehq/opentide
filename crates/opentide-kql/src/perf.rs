//! Warnings for public slow KQL shapes.
//!
//! Source: <https://learn.microsoft.com/en-us/kusto/query/best-practices>
//!
//! Join cardinality and `hint.shufflekey` are intentionally absent: the engine
//! cannot know which side is larger.

use crate::schema::{self, Analysis, Known};
use foldhash::{HashMap, HashMapExt};
use opentide_core::{ByteSpan, Diagnostic, LineIndex, codes};

const CITE: &str = "https://learn.microsoft.com/en-us/kusto/query/best-practices";

/// One tabular expression as the checks read it: its span, and its
/// operators (the legacy node name of each, and its span).
pub(crate) struct Pipeline {
    pub(crate) span: ByteSpan,
    pub(crate) ops: Vec<Op>,
}

/// An operator of a [`Pipeline`].
#[derive(Clone, Copy)]
pub(crate) struct Op {
    pub(crate) kind: &'static str,
    pub(crate) span: ByteSpan,
}

/// The checks over the pipelines of a query, in source order.
pub(crate) fn check(
    pipelines: &[Pipeline],
    lines: &LineIndex<'_>,
    columns: &Analysis,
    out: &mut Vec<Diagnostic>,
) {
    let columns = Columns::new(columns);
    for pipeline in pipelines {
        warn_pipeline(pipeline, lines, &columns, out);
    }
}

/// The column pass's analysis, with its pipelines indexed by span:
/// [`Analysis::pipeline`] is a scan of every pipeline, and the checks look
/// one up per pipeline, so a query of thousands of `let` functions spent
/// most of its analysis here (#1424).
struct Columns<'a> {
    analysis: &'a Analysis,
    by_span: HashMap<ByteSpan, &'a schema::Pipeline>,
}

impl<'a> Columns<'a> {
    fn new(analysis: &'a Analysis) -> Self {
        let mut by_span = HashMap::with_capacity(analysis.pipelines.len());
        for pipeline in &analysis.pipelines {
            // The first of a span, as `Analysis::pipeline` finds it.
            by_span.entry(pipeline.span).or_insert(pipeline);
        }
        Columns { analysis, by_span }
    }

    fn pipeline(&self, span: ByteSpan) -> Option<&'a schema::Pipeline> {
        self.by_span.get(&span).copied()
    }

    fn reads(&self, span: ByteSpan) -> impl Iterator<Item = &'a schema::Reference> {
        self.analysis.reads(span)
    }
}

/// The checks over the text of a query (`search`, `union *`, a wildcard
/// table): a token scan that reads no tree, so it runs on broken input too.
pub(crate) fn check_scope(source: &str, lines: &LineIndex<'_>, out: &mut Vec<Diagnostic>) {
    warn_scope(source, lines, out);
}

/// The pipeline starts from a table (or ASIM parser), not a `let`.
fn source_is_table(expr: ByteSpan, columns: &Columns<'_>) -> bool {
    columns.pipeline(expr).is_some_and(|p| p.reads_dataset())
}

/// The filter reads a column an operator before it makes, so it cannot move
/// ahead of that operator (#109): one an `extend` (or `summarize`, `parse`,
/// ...) made, or one the source does not have, which a `join`, `lookup` or
/// `union` brought in.
fn reads_made_column(filter: ByteSpan, expr: ByteSpan, columns: &Columns<'_>) -> bool {
    let source = columns
        .pipeline(expr)
        .map(|p| &p.source)
        .filter(|s| s.known != Known::Open);
    columns.reads(filter).any(|r| {
        let made = r
            .column
            .as_ref()
            .and_then(|c| c.made_by)
            .is_some_and(|made| made.span.end <= filter.start);
        made || source.is_some_and(|s| s.column(&r.name).is_none())
    })
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

/// The operator leaves only the columns it names or makes: a `join` after it
/// is already narrow (#109).
fn narrows(kind: &str) -> bool {
    is_narrowing_project(kind)
        || matches!(
            kind,
            "summarize_operator" | "distinct_operator" | "count_operator" | "make_series_operator"
        )
}

fn warn_pipeline(
    pipeline: &Pipeline,
    lines: &LineIndex,
    columns: &Columns<'_>,
    out: &mut Vec<Diagnostic>,
) {
    let ops = &pipeline.ops;
    let expr = pipeline.span;
    if source_is_table(expr, columns)
        && let Some(first) = ops.first()
        && !is_filter(first.kind)
        && let Some(late) = ops
            .iter()
            .find(|op| is_filter(op.kind))
            .filter(|late| !reads_made_column(late.span, expr, columns))
    {
        let keyword = if late.kind == "filter_operator" {
            "filter"
        } else {
            "where"
        };
        push(
            out,
            lines,
            codes::KQL_WHERE_NOT_FIRST,
            format!(
                "`{keyword}` is not the first operator after the table reference; filter before later operators ({CITE})"
            ),
            late.span.start,
            late.span.end,
        );
    }

    // Warn only when a `join` runs on wide columns and a later `project`
    // shows the reversed order. A project, summarize or distinct already
    // before the join, or no project at all, is not this diagnostic. A `let`
    // (or a `union` of them) that ends in one of those is narrow already.
    // `summarize` itself is never warned: it already returns only the
    // columns it names, and projecting before `arg_max(T, *)` would change
    // its result (#109).
    let mut narrowed = columns.pipeline(expr).is_some_and(|p| p.source.narrowed);
    for (index, op) in ops.iter().enumerate() {
        if narrows(op.kind) {
            narrowed = true;
            continue;
        }
        if narrowed || op.kind != "join_operator" {
            continue;
        }
        let project_later = ops
            .iter()
            .skip(index + 1)
            .any(|later| is_narrowing_project(later.kind));
        if !project_later {
            continue;
        }
        push(
            out,
            lines,
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT,
            format!(
                "`join` runs before `project` narrows columns; project the needed columns first ({CITE})"
            ),
            op.span.start,
            op.span.end,
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

fn warn_scope(source: &str, lines: &LineIndex, out: &mut Vec<Diagnostic>) {
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
                    lines,
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
                        lines,
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
                                lines,
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
                        lines,
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
    lines: &LineIndex,
    code: &str,
    message: String,
    start: usize,
    end: usize,
) {
    // The spans come from the query itself: never past its end.
    if start >= end {
        return;
    }
    let range = lines.range(ByteSpan::new(start, end));
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

    /// The checks look a pipeline up by its span in an index, not with a
    /// scan of every pipeline per pipeline (#1424): thousands of `let`
    /// functions spent most of `analyze` in that scan.
    #[test]
    fn pipelines_are_looked_up_without_a_scan() {
        let mut src = String::from("let f0 = (x:long) { SigninLogs | extend c = x };\n");
        for i in 1..500 {
            src.push_str(&format!(
                "let f{i} = (x:long) {{ f{}(x) | where c > 1 }};\n",
                i - 1
            ));
        }
        src.push_str("f499(1) | where c > 2");
        crate::schema::tests::PIPELINES_SCANNED.with(|n| n.set(0));
        let _ = analyze(&src, Profile::Sentinel);
        let scanned = crate::schema::tests::PIPELINES_SCANNED.with(std::cell::Cell::get);
        assert_eq!(scanned, 0, "pipelines scanned by `Analysis::pipeline`");
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
        // #109 B3: summarize already narrows its own output; never warned.
        assert!(!has(
            "SecurityEvent | where EventID == 4688 | summarize count() by Computer | project Computer",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(!has(
            "SigninLogs | summarize count() by UserPrincipalName | project UserPrincipalName",
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
    fn a_filter_on_a_column_an_earlier_operator_makes_cannot_move() {
        // #109 B2: Domain only exists after the extend.
        assert!(!has(
            "SigninLogs | extend Domain = tostring(split(UserPrincipalName, '@')[1]) | where Domain == 'example.com'",
            codes::KQL_WHERE_NOT_FIRST
        ));
        assert!(has(
            "SigninLogs | extend Domain = tostring(split(UserPrincipalName, '@')[1]) | where AppId == 'x'",
            codes::KQL_WHERE_NOT_FIRST
        ));
        // A custom table is still a table.
        assert!(has(
            "MyLog_CL | extend A = 1 | where B == 2",
            codes::KQL_WHERE_NOT_FIRST
        ));
        // A let is not a table reference.
        assert!(!has(
            "let base = SigninLogs | where ResultType == 0; base | extend A = 1 | where AppId == 'x'",
            codes::KQL_WHERE_NOT_FIRST
        ));
    }

    #[test]
    fn a_let_that_ends_in_project_is_narrow_where_it_is_used() {
        assert!(!has(
            "let base = SigninLogs | project UserPrincipalName, AppId; base | summarize count() by AppId | project AppId",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(has(
            "let base = SigninLogs | where ResultType == 0; base | join kind=inner AuditLogs on $left.AppId == $right.Id | project AppId",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
    }

    #[test]
    fn summarize_arg_max_star_needs_every_column() {
        assert!(!has(
            "SigninLogs | summarize arg_max(TimeGenerated, *) by UserPrincipalName | project UserPrincipalName, AppId",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(!has(
            "SigninLogs | summarize Last = arg_min( TimeGenerated , * ) by UserPrincipalName | project UserPrincipalName",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
    }

    // #109 B2, the shapes from the issue comment.
    #[test]
    fn where_after_summarize_on_a_let_source_is_not_flagged() {
        assert!(!has(
            "let resolved = SigninLogs | project IPAddress, Asn = AutonomousSystemNumber;\n\
             resolved\n\
             | summarize AsnCount = dcount(Asn) by IPAddress\n\
             | where AsnCount == 1",
            codes::KQL_WHERE_NOT_FIRST
        ));
        // On a table, a filter on the summarize output cannot move either.
        assert!(!has(
            "SigninLogs | summarize AsnCount = dcount(AutonomousSystemNumber) by IPAddress | where AsnCount == 1",
            codes::KQL_WHERE_NOT_FIRST
        ));
    }

    #[test]
    fn where_on_a_column_from_the_right_side_of_a_join_is_not_flagged() {
        let src = "let resets = AuditLogs | project ResetTime = TimeGenerated, Upn = tostring(TargetResources[0].userPrincipalName);\n\
             SigninLogs\n\
             | join kind=inner resets on $left.UserPrincipalName == $right.Upn\n\
             | where TimeGenerated between (ResetTime .. (ResetTime + 1h))";
        assert!(!has(src, codes::KQL_WHERE_NOT_FIRST));
        // A right side that is a table: its columns are not the left table's.
        assert!(!has(
            "SigninLogs | join kind=inner (AuditLogs) on $left.UserPrincipalName == $right.Identity | where ActivityDisplayName has 'Add'",
            codes::KQL_WHERE_NOT_FIRST
        ));
        // A filter on the left table's own column still could move first.
        assert!(has(
            "SigninLogs | join kind=inner (AuditLogs) on $left.UserPrincipalName == $right.Identity | where ResultType == 0",
            codes::KQL_WHERE_NOT_FIRST
        ));
    }

    // #109 B3, the join shapes from the issue comment.
    #[test]
    fn join_on_narrow_inputs_is_not_flagged() {
        // The left input is a let that ends in project, summarize or distinct.
        for tail in [
            "project UserPrincipalName, AppId",
            "summarize count() by UserPrincipalName",
            "distinct UserPrincipalName",
        ] {
            let src = format!(
                "let base = SigninLogs | {tail}; base | join kind=inner AuditLogs on $left.UserPrincipalName == $right.Identity | project UserPrincipalName"
            );
            assert!(
                !has(&src, codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT),
                "{src}"
            );
        }
        // A union of such lets.
        assert!(!has(
            "let a = SigninLogs | project UserPrincipalName; let b = AADNonInteractiveUserSignInLogs | distinct UserPrincipalName;\n\
             union a, b | join kind=inner AuditLogs on $left.UserPrincipalName == $right.Identity | project UserPrincipalName",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        // A union with one wide leg is still wide.
        assert!(has(
            "let a = SigninLogs | project UserPrincipalName;\n\
             union a, AADNonInteractiveUserSignInLogs | join kind=inner AuditLogs on $left.UserPrincipalName == $right.Identity | project UserPrincipalName",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        // summarize or distinct earlier in the same pipeline.
        for narrow in [
            "summarize count() by UserPrincipalName",
            "distinct UserPrincipalName",
        ] {
            let src = format!(
                "SigninLogs | {narrow} | join kind=inner AuditLogs on $left.UserPrincipalName == $right.Identity | project UserPrincipalName"
            );
            assert!(
                !has(&src, codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT),
                "{src}"
            );
        }
        // A wide table straight into join still warns.
        assert!(has(
            "SigninLogs | where ResultType == 0 | join kind=inner (AuditLogs | where OperationName has 'Add') on $left.UserPrincipalName == $right.Identity | project UserPrincipalName, OperationName",
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

    #[test]
    fn late_filter_is_named_and_a_leading_filter_is_clean() {
        let src = "SecurityEvent | extend Computer = tolower(Computer) | filter EventID == 4688";
        let found = warnings(src)
            .into_iter()
            .find(|d| d.code == codes::KQL_WHERE_NOT_FIRST)
            .expect("filter warning");
        assert!(found.message.contains("`filter`"), "{}", found.message);
        assert!(found.message.contains(CITE));
        assert!(!has(
            "SecurityEvent | filter EventID == 4688 | extend Computer = Computer",
            codes::KQL_WHERE_NOT_FIRST
        ));
    }

    #[test]
    fn project_keep_and_away_narrow_but_project_rename_does_not() {
        assert!(!has(
            "SecurityEvent | project-keep Computer, EventID | join kind=inner SecurityAlert on EventID | project Computer",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(!has(
            "SecurityEvent | where EventID == 4688 | project-away CommandLine | summarize count() by Computer | project Computer",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(has(
            "SecurityEvent | where EventID == 4688 | join kind=inner SecurityAlert on EventID | project-away EventID",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
        assert!(has(
            "SecurityEvent | project-rename Host = Computer | join kind=inner SecurityAlert on EventID | project Host",
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT
        ));
    }

    #[test]
    fn comments_and_a_later_statement_do_not_leak_scope() {
        let commented = "// search \"error\"\n/* union * */\nSecurityEvent | take 1";
        assert!(
            warnings(commented).is_empty(),
            "comments must not warn: {:?}",
            warnings(commented)
        );
        assert!(!has(
            "SecurityEvent\n// note\n| where EventID == 4688",
            codes::KQL_WHERE_NOT_FIRST
        ));
        assert!(has(
            "SecurityEvent | take 1;\nsearch \"error\"",
            codes::KQL_UNSCOPED_SEARCH
        ));
        assert!(has(
            "search kind=case_sensitive \"error\"",
            codes::KQL_UNSCOPED_SEARCH
        ));
        assert!(
            has("search kind=simple", codes::KQL_UNSCOPED_SEARCH),
            "a kind value is not a table scope"
        );
        assert!(!has(
            "search kind=case_sensitive in (SecurityEvent) \"error\"",
            codes::KQL_UNSCOPED_SEARCH
        ));
        assert!(!has(
            "search in (SecurityEvent) *",
            codes::KQL_UNSCOPED_SEARCH
        ));
        assert!(!has(
            "search in (SecurityEvent) *",
            codes::KQL_WILDCARD_TABLE
        ));
        assert!(has("union withsource=Src *", codes::KQL_UNSCOPED_UNION));
        assert!(!has(
            "union (SecurityEvent, SecurityAlert)",
            codes::KQL_UNSCOPED_UNION
        ));
    }
}
