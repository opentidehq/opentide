//! The checks Elasticsearch's EQL builder makes after its grammar accepts a query
//! (`LogicalPlanBuilder`, `AbstractBuilder`), on the rowan tree: string escapes, keyword and
//! category case, literal wildcards, function names and arity, sequence and sample shapes
//! (`by`, `maxspan`, `runs`, `until`, join keys, missing events), and pipes.

use crate::nav::{first_child_span, opens_missing, span, text, token_in};
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use crate::{
    Catalog, KEYWORD_WORDS, MAX_RUNS, MAX_SAMPLE_QUERIES, MAX_SEQUENCE_QUERIES, MAXSPAN_UNITS,
    codes, range,
};
use opentide_core::{ByteSpan, Diagnostic, Severity, suggest};

/// The child nodes of `node` of kind `kind`.
fn children_of(node: &SyntaxNode, kind: K) -> impl Iterator<Item = SyntaxNode> {
    node.children().filter(move |c| c.kind() == kind)
}

/// The terms of a sequence or sample before `until`, and the one after it.
fn terms(node: &SyntaxNode) -> (Vec<SyntaxNode>, Option<SyntaxNode>) {
    let mut before = Vec::new();
    let mut after_until = false;
    for child in node.children_with_tokens() {
        match child {
            rowan::NodeOrToken::Token(t) if t.kind() == K::UNTIL_KW => after_until = true,
            rowan::NodeOrToken::Node(n) if matches!(n.kind(), K::SEQUENCE_TERM | K::JOIN_TERM) => {
                if after_until {
                    return (before, Some(n));
                }
                before.push(n);
            }
            rowan::NodeOrToken::Node(_) | rowan::NodeOrToken::Token(_) => {}
        }
    }
    (before, None)
}

pub(crate) fn check_string(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
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
pub(crate) fn check_field_case(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
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
pub(crate) fn check_category_case(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
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

/// `==`, `!=`, `in`, and `in~` do not expand wildcards, so `"*.exe"` is matched literally. A
/// `*` next to a backslash (`\\*\\ADMIN$`) is left alone. `node` is a comparison or a
/// predicate.
pub(crate) fn check_literal_wildcard(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    let comparison = node.kind() == K::COMPARISON;
    let operator = if comparison {
        node.children_with_tokens()
            .filter_map(rowan::NodeOrToken::into_token)
            .find(|t| !t.kind().is_trivia())
    } else {
        token_in(
            node,
            &[
                K::IN_KW,
                K::IN_TILDE,
                K::COLON,
                K::LIKE_KW,
                K::LIKE_TILDE,
                K::REGEX_KW,
                K::REGEX_TILDE,
            ],
        )
    };
    let operator = operator.map(|t| t.text().to_owned()).unwrap_or_default();
    if !matches!(operator.as_str(), "==" | "!=" | "in" | "in~") {
        return;
    }
    // A comparison's right side, or a predicate's values: every node after the first.
    let candidates: Vec<SyntaxNode> = if comparison {
        node.children().nth(1).into_iter().collect()
    } else {
        node.children().skip(1).collect()
    };
    for value in candidates {
        if value.kind() != K::STRING {
            continue;
        }
        let t = text(&value, source);
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
                    range(source, span(&value)),
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
    node: &SyntaxNode,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) -> bool {
    // The name is the call's first node, its arguments the others.
    let Some(name_node) = node.first_child() else {
        return false;
    };
    let raw = text(&name_node, source);
    let (name, insensitive) = match raw.strip_suffix('~') {
        Some(base) => (base, true),
        None => (raw, false),
    };
    let name_span = span(&name_node);
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
            let args = node.children().count() - 1;
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
                    range(source, span(node)),
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
pub(crate) fn check_sequence(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    let children: Vec<SyntaxNode> = node.children().collect();
    // `sequence with maxspan=... by k` is rejected: `by` must come first.
    let params_pos = children.iter().position(|c| c.kind() == K::SEQUENCE_PARAMS);
    let by_pos = children.iter().position(|c| c.kind() == K::JOIN_KEYS);
    if let (Some(p), Some(b)) = (params_pos, by_pos)
        && p < b
    {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "specify sequence `by` before `with maxspan`, not after",
            range(source, span(&children[b])),
        ));
    }
    let maxspan = params_pos.and_then(|p| children[p].first_child());
    if let Some(unit) = &maxspan {
        check_maxspan(unit, source, out);
    }
    // `LogicalPlanBuilder.visitSequence` expands `runs` over every term, the `until` term
    // included, then takes the last query as `until`.
    let (before, until) = terms(node);
    let mut expanded: Vec<bool> = Vec::new();
    for term in &before {
        let runs = check_runs(term, source, out);
        expanded.extend(std::iter::repeat_n(is_missing_term(term), runs as usize));
    }
    if let Some(until) = &until {
        let runs = check_runs(until, source, out);
        expanded.extend(std::iter::repeat_n(is_missing_term(until), runs as usize));
        check_until(until, runs, source, out);
    }
    let keyword = first_child_span(node);
    let queries = expanded.len() as u64;
    if queries < 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!("a sequence requires a minimum of 2 queries, found [{queries}]"),
            range(source, keyword),
        ));
    } else if until.is_some() && queries == 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sequence requires a minimum of 2 queries besides `until`, found [1]",
            range(source, keyword),
        ));
    }
    if queries > MAX_SEQUENCE_QUERIES {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sequence cannot contain more than {MAX_SEQUENCE_QUERIES} queries after `runs`, found [{queries}]"
            ),
            range(source, keyword),
        ));
    }
    check_key_counts(&before, until.as_ref(), source, out);
    if until.is_some() {
        expanded.pop();
    }
    let missing = expanded.iter().filter(|m| **m).count();
    if missing > 0 && maxspan.is_none() {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "`maxspan` is required for sequences with missing events",
            range(source, keyword),
        ));
    }
    if !expanded.is_empty() && missing == expanded.len() {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sequence requires at least one positive event query",
            range(source, keyword),
        ));
    }
    if maxspan.is_none() && missing == 0 {
        out.push(Diagnostic {
            severity: Severity::Hint,
            ..Diagnostic::warning(
                codes::EQL_MAXSPAN_MISSING,
                "sequence has no `with maxspan=`: its events can be any distance apart within the search window. A maxspan bounds matches and the partial sequences Elasticsearch keeps",
                range(source, keyword),
            )
        });
    }
}

/// Whether a term's subquery (its first node) opens with `![`.
fn is_missing_term(term: &SyntaxNode) -> bool {
    term.first_child().is_some_and(|s| opens_missing(&s))
}

/// `until [...] with runs=n` repeats the `until` query: only the last copy ends sequences, the
/// other copies become ordinary steps. `until ![...]` parses, but Elasticsearch documents no
/// meaning for it.
fn check_until(until: &SyntaxNode, runs: u64, source: &str, out: &mut Vec<Diagnostic>) {
    if let Some(option) = children_of(until, K::TERM_OPTION).next()
        && runs > 1
    {
        out.push(Diagnostic::warning(
            codes::EQL_UNTIL_TERM,
            format!(
                "`runs` on the `until` term adds {} copies of it as ordinary sequence steps before the real `until`; remove `with runs`",
                runs - 1
            ),
            range(source, span(&option)),
        ));
    }
    if is_missing_term(until) {
        let open = until
            .first_child()
            .and_then(|s| children_of(&s, K::MISSING_EVENT_OPEN).next())
            .unwrap_or_else(|| until.clone());
        out.push(Diagnostic::warning(
            codes::EQL_UNTIL_TERM,
            "a missing event (`![`) as the `until` term parses, but Elasticsearch documents no behaviour for it; use `[`",
            range(source, span(&open)),
        ));
    }
}

/// A term option's key (its first node that is not a number) and value (its first number).
fn option_parts(option: &SyntaxNode) -> (Option<SyntaxNode>, Option<SyntaxNode>) {
    let key = option.children().find(|c| c.kind() != K::NUMBER);
    let value = children_of(option, K::NUMBER).next();
    (key, value)
}

/// Number of queries a term contributes (`with runs=n` repeats it).
fn check_runs(term: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) -> u64 {
    let Some(option) = children_of(term, K::TERM_OPTION).next() else {
        return 1;
    };
    let (key, value) = option_parts(&option);
    let key = key.map(|k| text(&k, source)).unwrap_or("");
    let at = range(source, span(&option));
    if key != "runs" {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!("unrecognized option [{key}], expecting [runs]"),
            at,
        ));
        return 1;
    }
    let value = value.map(|v| text(&v, source)).unwrap_or("");
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

/// `maxspan=<value><unit>`: the value is the time unit's first number, the unit its first
/// node that is not one.
fn check_maxspan(unit: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    let (suffix, value) = option_parts(unit);
    let value = value.map(|v| text(&v, source)).unwrap_or("");
    let suffix = suffix.map(|u| text(&u, source));
    let at = span(unit);
    match value.parse::<u64>() {
        Ok(0) => out.push(Diagnostic::error(
            codes::EQL_MAXSPAN_UNIT,
            "a positive `maxspan` value is required; found [0]",
            range(source, at),
        )),
        Ok(_) => {}
        Err(_) => out.push(Diagnostic::error(
            codes::EQL_MAXSPAN_UNIT,
            format!("decimal time interval [{value}] is not supported; use a positive integer"),
            range(source, at),
        )),
    }
    match suffix {
        None => out.push(
            Diagnostic::error(
                codes::EQL_MAXSPAN_UNIT,
                format!("no time unit in `maxspan={value}`; use one of ms, s, m, h, d"),
                range(source, at),
            )
            .with_suggestion(format!("{value}s")),
        ),
        Some(u) if !MAXSPAN_UNITS.iter().any(|(name, _)| *name == u) => {
            out.push(Diagnostic::error(
                codes::EQL_MAXSPAN_UNIT,
                format!("unrecognized time unit [{u}] in `maxspan`; use one of ms, s, m, h, d"),
                range(source, at),
            ));
        }
        Some(_) => {}
    }
}

pub(crate) fn check_sample(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    let (terms, until) = terms(node);
    let keyword = first_child_span(node);
    if terms.len() < 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sample requires a minimum of 2 queries, found [{}]",
                terms.len()
            ),
            range(source, keyword),
        ));
    }
    if terms.len() > MAX_SAMPLE_QUERIES {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sample cannot contain more than {MAX_SAMPLE_QUERIES} queries, found [{}]",
                terms.len()
            ),
            range(source, span(&terms[MAX_SAMPLE_QUERIES])),
        ));
    }
    check_key_counts(&terms, until.as_ref(), source, out);
    let shared_keys = children_of(node, K::JOIN_KEYS).next().is_some();
    if !shared_keys
        && terms
            .iter()
            .any(|t| children_of(t, K::JOIN_KEYS).next().is_none())
    {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sample must have at least one join key, found none",
            range(source, keyword),
        ));
    }
}

/// Every term of a sequence or sample (and `until`) names the same number of join keys.
fn check_key_counts(
    terms: &[SyntaxNode],
    until: Option<&SyntaxNode>,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let mut expected: Option<usize> = None;
    for term in terms.iter().chain(until) {
        let by = children_of(term, K::JOIN_KEYS).next();
        let keys = by.as_ref().map_or(0, |b| b.children().count());
        match expected {
            None => expected = Some(keys),
            Some(e) if e != keys => {
                let at = by.unwrap_or_else(|| term.clone());
                out.push(Diagnostic::error(
                    codes::EQL_PARSE_ERROR,
                    format!("inconsistent number of join keys specified; expected [{e}] but found [{keys}]"),
                    range(source, span(&at)),
                ));
                return;
            }
            _ => {}
        }
    }
}

/// `| head n` and `| tail n` only, with one non-negative integer; a sample takes no pipe.
pub(crate) fn check_pipes(
    root: &SyntaxNode,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    let is_sample = root
        .children()
        .find(|c| c.kind() != K::PIPE_STAGE)
        .is_some_and(|q| q.kind() == K::SAMPLE);
    for pipe in children_of(root, K::PIPE_STAGE) {
        // The pipe's name is its first node, its arguments the others.
        let Some(name_node) = pipe.first_child() else {
            continue;
        };
        let name = text(&name_node, source);
        if is_sample {
            out.push(Diagnostic::error(
                codes::EQL_UNSUPPORTED,
                "samples do not support pipes",
                range(source, span(&pipe)),
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
            out.push(unsupported(source, &message, span(&name_node)));
            continue;
        }
        let args: Vec<SyntaxNode> = pipe.children().skip(1).collect();
        let positive_int = args.len() == 1
            && args[0].kind() == K::NUMBER
            // A Java `int`: Elasticsearch rejects `head 2147483648`.
            && text(&args[0], source).parse::<i32>().is_ok_and(|n| n >= 0);
        if !positive_int {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!("pipe [{name}] expects exactly one positive integer argument"),
                range(source, span(&pipe)),
            ));
        }
    }
}

pub(crate) fn unsupported(source: &str, message: &str, at: ByteSpan) -> Diagnostic {
    Diagnostic::error(codes::EQL_UNSUPPORTED, message, range(source, at))
}

/// The diagnostics of a node with no rule of its own above: `join`, lineage, an index, and a
/// missing event outside a sequence.
pub(crate) fn check_shape(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    match node.kind() {
        K::INDEX => out.push(Diagnostic::error(
            codes::EQL_UNSUPPORTED,
            "array indexes are not supported in Elasticsearch EQL",
            range(source, span(node)),
        )),
        K::JOIN => out.push(unsupported(
            source,
            "Elasticsearch EQL does not support `join`; use `sequence` or `sample`",
            first_child_span(node),
        )),
        K::RELATIONSHIP => {
            let relation = node
                .children()
                .find(|c| c.kind() != K::SUBQUERY)
                .map_or("of", |n| text(&n, source));
            out.push(unsupported(
                source,
                &format!("Elasticsearch EQL does not support the lineage keyword `{relation} of`"),
                span(node),
            ));
        }
        K::SUBQUERY => {
            let in_sequence = node
                .parent()
                .and_then(|p| p.parent())
                .is_some_and(|g| g.kind() == K::SEQUENCE);
            if opens_missing(node) && !in_sequence {
                out.push(Diagnostic::error(
                    codes::EQL_PARSE_ERROR,
                    "missing events (`![ ... ]`) are supported only in sequences",
                    range(source, span(node)),
                ));
            }
        }
        _ => {}
    }
}
