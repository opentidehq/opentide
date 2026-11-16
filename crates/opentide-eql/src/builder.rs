//! The checks Elasticsearch's EQL builder makes after its grammar accepts a query
//! (`LogicalPlanBuilder`, `AbstractBuilder`), on the typed AST: string escapes, keyword and
//! category case, literal wildcards, function names and arity, sequence and sample shapes
//! (`by`, `maxspan`, `runs`, `until`, join keys, missing events), and pipes.

use crate::ast;
use crate::nav::{first_child_span, span, text};
use crate::syntax::SyntaxNode;
use crate::{
    Catalog, KEYWORD_WORDS, MAX_RUNS, MAX_SAMPLE_QUERIES, MAX_SEQUENCE_QUERIES, MAXSPAN_UNITS,
    codes, range,
};
use opentide_core::{ByteSpan, Diagnostic, Severity, suggest};
use opentide_parse::ast::AstNode;

/// Whether a subquery opens with `![` (a missing event) rather than `[`.
fn opens_missing(subquery: &ast::Subquery) -> bool {
    subquery.l_brack_token().is_none() && subquery.open().is_some()
}

/// Whether a term's subquery opens with `![`.
fn is_missing_term(subquery: Option<ast::Subquery>) -> bool {
    subquery.is_some_and(|s| opens_missing(&s))
}

pub(crate) fn check_string(node: &ast::String, source: &str, out: &mut Vec<Diagnostic>) {
    let node = node.syntax();
    let t = text(node, source);
    let message = if t.starts_with('\'') {
        Some("use double quotes [\"] for string literals, not single quotes [']")
    } else if t.starts_with('?') {
        Some(
            "`?\"` and `?'` are not raw strings in Elasticsearch EQL; use triple double quotes [\"\"\"]",
        )
    } else {
        None
    };
    // Elasticsearch's lexer has no token for these, so they fail to parse.
    if let Some(message) = message {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            message,
            range(source, span(node)),
        ));
        return;
    }
    if t.starts_with("\"\"\"") {
        return;
    }
    // `"…"` accepts only these escapes; anything else fails the lexer.
    let bytes = t.as_bytes();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        let bad = match next {
            b'b' | b't' | b'n' | b'f' | b'r' | b'"' | b'\'' | b'\\' => false,
            b'u' => {
                let rest = &t[i + 2..];
                let digits = rest
                    .strip_prefix('{')
                    .and_then(|r| r.split_once('}'))
                    .map(|(h, _)| h);
                !digits.is_some_and(|h| {
                    (2..=8).contains(&h.len()) && h.chars().all(|c| c.is_ascii_hexdigit())
                })
            }
            _ => true,
        };
        if bad {
            let at = span(node).start + i;
            // The escaped character may be several bytes (`\é`): the span and the message
            // take all of it.
            let escaped = t[i + 1..].chars().next().unwrap_or(next as char);
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!(
                    "invalid escape `\\{escaped}`: EQL strings accept \\b \\t \\n \\f \\r \\\" \\' \\\\ and \\u{{2-8 hex}}; use `\\\\` or a triple-quoted string"
                ),
                range(source, ByteSpan::new(at, at + 1 + escaped.len_utf8())),
            ));
            return;
        }
        i += 2;
    }
}

/// `x == TRUE` reads a field named `TRUE`: keywords are lower case.
pub(crate) fn check_field_case(node: &ast::Field, source: &str, out: &mut Vec<Diagnostic>) {
    let node = node.syntax();
    let t = text(node, source).trim_start_matches('?').trim();
    let lower = t.to_ascii_lowercase();
    if KEYWORD_WORDS.contains(&lower.as_str()) && t != lower {
        out.push(
            Diagnostic::warning(
                codes::EQL_CASE_SENSITIVE,
                format!("EQL keywords are lower case: `{t}` here is a field name, not `{lower}`"),
                range(source, span(node)),
            )
            .with_suggestion(lower),
        );
    }
}

/// Categories compare case-sensitively with `event.category`, which ECS keeps lower case:
/// `PROCESS where` matches nothing.
pub(crate) fn check_category_case(
    node: &ast::EventCategory,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let node = node.syntax();
    let t = text(node, source).trim_matches('"');
    if t.chars().any(|c| c.is_ascii_uppercase()) {
        out.push(
            Diagnostic::warning(
                codes::EQL_CASE_SENSITIVE,
                format!(
                    "event category `{t}` is compared case-sensitively; ECS categories are lower case"
                ),
                range(source, span(node)),
            )
            .with_suggestion(t.to_ascii_lowercase()),
        );
    }
}

/// `==` and `!=` do not expand wildcards, so `"*.exe"` is matched literally.
pub(crate) fn check_comparison_wildcard(
    node: &ast::Comparison,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let operator = node.operator().map(|t| t.text().to_owned());
    check_literal_wildcard(operator, node.right().into_iter(), source, out);
}

/// Neither do `in` and `in~`, in the values after a predicate's subject.
pub(crate) fn check_predicate_wildcard(
    node: &ast::PredicateExpression,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let operator = node.operator().map(|t| t.text().to_owned());
    check_literal_wildcard(operator, node.exprs().skip(1), source, out);
}

/// The first string among `candidates` with a `*` matched literally. A `*` next to a
/// backslash (`\\*\\ADMIN$`) is left alone.
fn check_literal_wildcard(
    operator: Option<String>,
    candidates: impl Iterator<Item = ast::Expr>,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let operator = operator.unwrap_or_default();
    if !matches!(operator.as_str(), "==" | "!=" | "in" | "in~") {
        return;
    }
    for value in candidates {
        let ast::Expr::String(value) = value else {
            continue;
        };
        let value = value.syntax();
        let t = text(value, source);
        let bytes = t.as_bytes();
        let wild = bytes.iter().enumerate().any(|(i, b)| {
            *b == b'*'
                && bytes.get(i.wrapping_sub(1)) != Some(&b'\\')
                && bytes.get(i + 1) != Some(&b'\\')
        });
        if wild {
            let suggestion = if operator.starts_with("in") {
                ":"
            } else {
                "like"
            };
            out.push(
                Diagnostic::warning(
                    codes::EQL_LITERAL_WILDCARD,
                    format!(
                        "`{operator}` matches `*` literally; use `{suggestion}` for a wildcard"
                    ),
                    range(source, span(value)),
                )
                .with_suggestion(suggestion),
            );
            return;
        }
    }
}

/// Name, `~`, and arity checks. Returns whether the call resolves, so its argument types are
/// worth checking.
pub(crate) fn check_function(
    call: &ast::FunctionCall,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) -> bool {
    let Some(name_node) = call.name() else {
        return false;
    };
    let raw = text(name_node.syntax(), source);
    let (name, insensitive) = match raw.strip_suffix('~') {
        Some(base) => (base, true),
        None => (raw, false),
    };
    let name_span = span(name_node.syntax());
    match catalog.function(name) {
        Some(row) if insensitive && !row.case_insensitive => {
            out.push(Diagnostic::error(
                codes::EQL_UNKNOWN_FUNCTION,
                format!("function `{name}` has no case-insensitive `{name}~` form"),
                range(source, name_span),
            ));
            false
        }
        Some(row) => {
            let args = call.exprs().count();
            let too_many = row.max_args.is_some_and(|m| args > m);
            if args < row.min_args || too_many {
                let expected = match row.max_args {
                    Some(m) if m == row.min_args => format!("{m}"),
                    Some(m) => format!("{} to {m}", row.min_args),
                    None => format!("at least {}", row.min_args),
                };
                out.push(Diagnostic::error(
                    codes::EQL_FUNCTION_ARITY,
                    format!("`{}` takes {expected} arguments, found {args}", row.name),
                    range(source, span(call.syntax())),
                ));
                return false;
            }
            true
        }
        None => {
            let mut d = Diagnostic::error(
                codes::EQL_UNKNOWN_FUNCTION,
                format!("unknown EQL function `{name}`"),
                range(source, name_span),
            );
            if let Some(s) =
                suggest::closest(name, catalog.functions.iter().map(|f| f.name.as_str()))
            {
                d = d.with_suggestion(s);
            }
            out.push(d);
            false
        }
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "check_runs returns 1..=MAX_RUNS (100)"
)]
pub(crate) fn check_sequence(sequence: &ast::Sequence, source: &str, out: &mut Vec<Diagnostic>) {
    // `sequence with maxspan=... by k` is rejected: `by` must come first.
    let params = sequence.params().next();
    if let (Some(p), Some(b)) = (&params, sequence.by().next())
        && p.syntax().text_range().start() < b.syntax().text_range().start()
    {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "specify sequence `by` before `with maxspan`, not after",
            range(source, span(b.syntax())),
        ));
    }
    let maxspan = params.and_then(|p| p.maxspan());
    if let Some(unit) = &maxspan {
        check_maxspan(unit, source, out);
    }
    // `LogicalPlanBuilder.visitSequence` expands `runs` over every term, the `until` term
    // included, then takes the last query as `until`.
    let (terms, until) = (sequence.terms(), sequence.until());
    let mut expanded: Vec<bool> = Vec::new();
    for term in &terms {
        let runs = check_runs(term.term_option(), source, out);
        expanded.extend(std::iter::repeat_n(
            is_missing_term(term.subquery()),
            runs as usize,
        ));
    }
    if let Some(until) = &until {
        let runs = check_runs(until.term_option(), source, out);
        expanded.extend(std::iter::repeat_n(
            is_missing_term(until.subquery()),
            runs as usize,
        ));
        check_until(until, runs, source, out);
    }
    let keyword = range(source, first_child_span(sequence.syntax()));
    let queries = expanded.len() as u64;
    if queries < 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!("a sequence requires a minimum of 2 queries, found [{queries}]"),
            keyword,
        ));
    } else if until.is_some() && queries == 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sequence requires a minimum of 2 queries besides `until`, found [1]",
            keyword,
        ));
    }
    if queries > MAX_SEQUENCE_QUERIES {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sequence cannot contain more than {MAX_SEQUENCE_QUERIES} queries after `runs`, found [{queries}]"
            ),
            keyword,
        ));
    }
    let keys = terms.iter().chain(&until).map(|t| (t.by(), t.syntax()));
    check_key_counts(keys, source, out);
    if until.is_some() {
        expanded.pop();
    }
    let missing = expanded.iter().filter(|m| **m).count();
    if missing > 0 && maxspan.is_none() {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "`maxspan` is required for sequences with missing events",
            keyword,
        ));
    }
    if !expanded.is_empty() && missing == expanded.len() {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sequence requires at least one positive event query",
            keyword,
        ));
    }
    if maxspan.is_none() && missing == 0 {
        out.push(Diagnostic {
            severity: Severity::Hint,
            ..Diagnostic::warning(
                codes::EQL_MAXSPAN_MISSING,
                "sequence has no `with maxspan=`: its events can be any distance apart within the search window. A maxspan bounds matches and the partial sequences Elasticsearch keeps",
                keyword,
            )
        });
    }
}

/// `until [...] with runs=n` repeats the `until` query: only the last copy ends sequences, the
/// other copies become ordinary steps. `until ![...]` parses, but Elasticsearch documents no
/// meaning for it.
fn check_until(until: &ast::SequenceTerm, runs: u64, source: &str, out: &mut Vec<Diagnostic>) {
    if let Some(option) = until.term_option()
        && runs > 1
    {
        out.push(Diagnostic::warning(
            codes::EQL_UNTIL_TERM,
            format!(
                "`runs` on the `until` term adds {} copies of it as ordinary sequence steps before the real `until`; remove `with runs`",
                runs - 1
            ),
            range(source, span(option.syntax())),
        ));
    }
    if let Some(subquery) = until.subquery()
        && opens_missing(&subquery)
    {
        let open = subquery
            .open()
            .map_or_else(|| span(until.syntax()), |open| span(open.syntax()));
        out.push(Diagnostic::warning(
            codes::EQL_UNTIL_TERM,
            "a missing event (`![`) as the `until` term parses, but Elasticsearch documents no behaviour for it; use `[`",
            range(source, open),
        ));
    }
}

/// Number of queries a term contributes (`with runs=n` repeats it).
fn check_runs(option: Option<ast::TermOption>, source: &str, out: &mut Vec<Diagnostic>) -> u64 {
    let Some(option) = option else {
        return 1;
    };
    let key = option.key().map_or("", |k| text(k.syntax(), source));
    let at = range(source, span(option.syntax()));
    if key != "runs" {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!("unrecognized option [{key}], expecting [runs]"),
            at,
        ));
        return 1;
    }
    let value = option.value().map_or("", |v| text(v.syntax(), source));
    // Only an integer literal is read; a decimal leaves `runs` at 1.
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        out.push(Diagnostic::warning(
            codes::EQL_RUNS_IGNORED,
            format!(
                "Elasticsearch ignores a decimal `runs` value: [{value}] runs the query once; use an integer from 1 to {MAX_RUNS}"
            ),
            at,
        ));
        return 1;
    }
    match value.parse::<u64>() {
        Ok(n) if (1..=MAX_RUNS).contains(&n) => n,
        Ok(0) => {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                "a positive `runs` value is required; found [0]",
                at,
            ));
            1
        }
        // Larger than a long reads as a double, whose long value is still over the limit.
        _ => {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!("a query cannot be repeated more than {MAX_RUNS} times; found [{value}]"),
                at,
            ));
            1
        }
    }
}

/// `maxspan=<value><unit>`.
fn check_maxspan(unit: &ast::TimeUnit, source: &str, out: &mut Vec<Diagnostic>) {
    let value = unit.value().map_or("", |v| text(v.syntax(), source));
    let suffix = unit.unit().map(|u| text(u.syntax(), source));
    let at = range(source, span(unit.syntax()));
    match value.parse::<u64>() {
        Ok(0) => out.push(Diagnostic::error(
            codes::EQL_MAXSPAN_UNIT,
            "a positive `maxspan` value is required; found [0]",
            at,
        )),
        Ok(_) => {}
        Err(_) => out.push(Diagnostic::error(
            codes::EQL_MAXSPAN_UNIT,
            format!("decimal time interval [{value}] is not supported; use a positive integer"),
            at,
        )),
    }
    match suffix {
        None => out.push(
            Diagnostic::error(
                codes::EQL_MAXSPAN_UNIT,
                format!("no time unit in `maxspan={value}`; use one of ms, s, m, h, d"),
                at,
            )
            .with_suggestion(format!("{value}s")),
        ),
        Some(u) if !MAXSPAN_UNITS.iter().any(|(name, _)| *name == u) => {
            out.push(Diagnostic::error(
                codes::EQL_MAXSPAN_UNIT,
                format!("unrecognized time unit [{u}] in `maxspan`; use one of ms, s, m, h, d"),
                at,
            ));
        }
        Some(_) => {}
    }
}

pub(crate) fn check_sample(sample: &ast::Sample, source: &str, out: &mut Vec<Diagnostic>) {
    let terms: Vec<ast::JoinTerm> = sample.join_terms().collect();
    let keyword = range(source, first_child_span(sample.syntax()));
    if terms.len() < 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sample requires a minimum of 2 queries, found [{}]",
                terms.len()
            ),
            keyword,
        ));
    }
    if let Some(over) = terms.get(MAX_SAMPLE_QUERIES) {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sample cannot contain more than {MAX_SAMPLE_QUERIES} queries, found [{}]",
                terms.len()
            ),
            range(source, span(over.syntax())),
        ));
    }
    check_key_counts(terms.iter().map(|t| (t.by(), t.syntax())), source, out);
    if sample.by().is_none() && terms.iter().any(|t| t.by().is_none()) {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sample must have at least one join key, found none",
            keyword,
        ));
    }
}

/// Every term of a sequence or sample (and `until`) names the same number of join keys: each
/// term's `by`, with the term itself for a finding where it has none.
fn check_key_counts<'a>(
    terms: impl Iterator<Item = (Option<ast::JoinKeys>, &'a SyntaxNode)>,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let mut expected: Option<usize> = None;
    for (by, term) in terms {
        let keys = by.as_ref().map_or(0, |b| b.exprs().count());
        match expected {
            None => expected = Some(keys),
            Some(e) if e != keys => {
                let at = by.map_or_else(|| span(term), |b| span(b.syntax()));
                out.push(Diagnostic::error(
                    codes::EQL_PARSE_ERROR,
                    format!("inconsistent number of join keys specified; expected [{e}] but found [{keys}]"),
                    range(source, at),
                ));
                return;
            }
            _ => {}
        }
    }
}

/// `| head n` and `| tail n` only, with one non-negative integer; a sample takes no pipe.
pub(crate) fn check_pipes(
    root: &ast::SourceFile,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    let is_sample = matches!(root.query(), Some(ast::Query::Sample(_)));
    for pipe in root.pipe_stages() {
        let Some(name_node) = pipe.name() else {
            continue;
        };
        let name = text(name_node.syntax(), source);
        if is_sample {
            out.push(Diagnostic::error(
                codes::EQL_UNSUPPORTED,
                "samples do not support pipes",
                range(source, span(pipe.syntax())),
            ));
            continue;
        }
        if catalog.pipe(name).is_none() {
            let endgame = matches!(
                name,
                "count" | "filter" | "sort" | "unique" | "unique_count"
            );
            let message = if endgame {
                format!(
                    "Elasticsearch EQL does not support the `{name}` pipe; only `head` and `tail`"
                )
            } else {
                format!("unrecognized pipe [{name}]; Elasticsearch EQL supports `head` and `tail`")
            };
            out.push(unsupported(source, &message, span(name_node.syntax())));
            continue;
        }
        let args: Vec<ast::Expr> = pipe.exprs().collect();
        // A Java `int`: Elasticsearch rejects `head 2147483648`.
        let positive_int = matches!(args.as_slice(), [ast::Expr::Number(n)]
            if text(n.syntax(), source).parse::<i32>().is_ok_and(|n| n >= 0));
        if !positive_int {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!("pipe [{name}] expects exactly one positive integer argument"),
                range(source, span(pipe.syntax())),
            ));
        }
    }
}

pub(crate) fn unsupported(source: &str, message: &str, at: ByteSpan) -> Diagnostic {
    Diagnostic::error(codes::EQL_UNSUPPORTED, message, range(source, at))
}

/// `join`, lineage, an index, and a missing event outside a sequence: Elasticsearch rejects
/// each.
pub(crate) fn check_shape(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    if ast::Index::can_cast(node.kind()) {
        out.push(Diagnostic::error(
            codes::EQL_UNSUPPORTED,
            "array indexes are not supported in Elasticsearch EQL",
            range(source, span(node)),
        ));
    } else if ast::Join::can_cast(node.kind()) {
        out.push(unsupported(
            source,
            "Elasticsearch EQL does not support `join`; use `sequence` or `sample`",
            first_child_span(node),
        ));
    } else if let Some(lineage) = ast::Relationship::cast(node.clone()) {
        let relation = lineage
            .relation()
            .map_or("of", |n| text(n.syntax(), source));
        out.push(unsupported(
            source,
            &format!("Elasticsearch EQL does not support the lineage keyword `{relation} of`"),
            span(node),
        ));
    } else if let Some(subquery) = ast::Subquery::cast(node.clone()) {
        let in_sequence = node
            .parent()
            .and_then(|p| p.parent())
            .is_some_and(|g| ast::Sequence::can_cast(g.kind()));
        if opens_missing(&subquery) && !in_sequence {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                "missing events (`![ ... ]`) are supported only in sequences",
                range(source, span(node)),
            ));
        }
    }
}
