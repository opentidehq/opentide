//! A tabular expression: a source and the operators after its pipes.
//! `kql.ungram` has each operator's shape.

use super::{P, expr, statement};
use crate::syntax::SyntaxKind as K;

/// `item, item, ...`
fn list(p: &mut P<'_>, item: fn(&mut P<'_>)) {
    loop {
        item(p);
        if !p.eat(K::COMMA) {
            break;
        }
    }
}

/// `item, item,` up to `close`, a trailing comma allowed.
fn list_until(p: &mut P<'_>, close: K, item: fn(&mut P<'_>)) {
    loop {
        item(p);
        if !p.eat(K::COMMA) || p.at(close) {
            break;
        }
    }
}

/// `source | operator | operator`
pub(super) fn tabular_expression(p: &mut P<'_>) {
    let m = p.start();
    if p.enter() {
        let s = p.start();
        source(p);
        p.done(s, K::TABULAR_SOURCE);
        while p.at(K::PIPE) {
            p.bump();
            operator(p);
        }
        p.exit();
    }
    p.done(m, K::TABULAR_EXPRESSION);
}

/// The operators after `mv-apply ... on (`, and in `fork`, `facet` and
/// `partition`: no source table.
fn subquery(p: &mut P<'_>) {
    let m = p.start();
    if p.enter() {
        operator(p);
        while p.at(K::PIPE) {
            p.bump();
            operator(p);
        }
        p.exit();
    }
    p.done(m, K::SUBQUERY);
}

/// `( subquery )`
fn paren_subquery(p: &mut P<'_>) {
    p.expect(K::L_PAREN);
    subquery(p);
    p.expect(K::R_PAREN);
}

/// A table, a call, a parenthesised pipeline, or a source operator.
/// Also what a `join` or `lookup` reads on its right.
fn source(p: &mut P<'_>) {
    let next = p.nth(1);
    match p.current() {
        K::L_PAREN => {
            let m = p.start();
            p.bump();
            tabular_expression(p);
            p.expect(K::R_PAREN);
            p.done(m, K::PAREN_TABULAR);
        }
        K::PRINT_KW => print_operator(p),
        K::UNION_KW => union_operator(p),
        K::DATATABLE_KW => datatable(p),
        K::EXTERNALDATA_KW | K::EXTERNAL_DATA_KW => externaldata(p),
        K::RANGE_KW if next != K::L_PAREN => range_operator(p),
        K::MATERIALIZE_KW => {
            let m = p.start();
            p.bump();
            p.expect(K::L_PAREN);
            tabular_expression(p);
            p.expect(K::R_PAREN);
            p.done(m, K::MATERIALIZE_EXPRESSION);
        }
        K::SEARCH_KW | K::FIND_KW => search_source(p),
        _ if p.name_at(0) && next == K::L_PAREN => call_or_qualified_table(p, false),
        _ => table_name(p),
    }
}

/// A table by name, quoted (`['My Table']`) or not, or "expected a name".
fn table_name(p: &mut P<'_>) {
    let m = p.start();
    let touching = |p: &P<'_>, n: usize| {
        p.0.nth_range(n)
            .zip(p.0.nth_range(n + 1))
            .is_some_and(|(a, b)| a.end() == b.start())
    };
    if p.at(K::L_BRACKET)
        && p.nth(1) == K::STRING
        && p.nth(2) == K::R_BRACKET
        && touching(p, 0)
        && touching(p, 1)
        && p.0.nth_text(1).starts_with(['\'', '"'])
    {
        // `.['My Table']` after a scope: the lexer reads a `[` after a dot
        // as an index, so the quoted name comes as its three tokens.
        p.bump();
        p.bump();
        p.bump();
    } else if !p.eat(K::QUOTED_IDENT) {
        p.expect_name();
    }
    p.done(m, K::TABLE_REF);
}

/// A call (`f(x)`), or a table in another scope: a scope call, then a
/// dot and the table's name (`database("d").SecurityEvent`,
/// `workspace("w").['T']`, `app("a").requests`), with `cluster("c")`
/// before a `database(...)` (`cluster("c").database("d").T`). A pattern
/// (`database("d").Sec*`) only where a union takes one (`patterns`). Kusto's
/// scope functions are spelled in lower case; a scope call with no dot after
/// it stays a call, and one with a dot but no table after it is an error.
fn call_or_qualified_table(p: &mut P<'_>, patterns: bool) {
    let scope = |p: &P<'_>| {
        if !(p.name_at(0) && p.nth(1) == K::L_PAREN) {
            return None;
        }
        ["cluster", "database", "workspace", "app"]
            .into_iter()
            .find(|scope| p.0.nth_text(0) == *scope)
    };
    let Some(first) = scope(p) else {
        expr::function_call(p);
        return;
    };
    let call = expr::function_call(p);
    if !p.at(K::DOT) {
        return;
    }
    let m = p.precede(call);
    p.bump();
    // `cluster(...)` names the cluster a `database(...)` is in.
    if first == "cluster" {
        if scope(p) == Some("database") {
            expr::function_call(p);
        } else {
            p.error("expected `database(...)` after `cluster(...)`");
        }
        if !p.eat(K::DOT) {
            p.error("expected `.` and a table name");
            p.done(m, K::QUALIFIED_TABLE);
            return;
        }
    }
    if !(patterns && table_run(p, Some(K::TABLE_REF))) {
        table_name(p);
    }
    p.done(m, K::QUALIFIED_TABLE);
}

/// One operator after a pipe.
fn operator(p: &mut P<'_>) {
    // These two are nodes of their own, not wrapped.
    if p.current() == K::UNION_KW {
        return union_operator(p);
    }
    if p.current() == K::RANGE_KW {
        return range_operator(p);
    }
    let m = p.start();
    let kind = match p.current() {
        K::WHERE_KW => predicate(p, K::WHERE_OPERATOR),
        K::FILTER_KW => predicate(p, K::FILTER_OPERATOR),
        K::PROJECT_KW => {
            p.bump();
            list(p, assignment_or_expr);
            K::PROJECT_OPERATOR
        }
        K::PROJECT_AWAY_KW | K::PROJECT_KEEP_KW => {
            let kind = if p.current() == K::PROJECT_AWAY_KW {
                K::PROJECT_AWAY_OPERATOR
            } else {
                K::PROJECT_KEEP_OPERATOR
            };
            p.bump();
            list(p, column_ref);
            kind
        }
        K::PROJECT_REORDER_KW => {
            p.bump();
            list(p, reorder_item);
            K::PROJECT_REORDER_OPERATOR
        }
        K::PROJECT_RENAME_KW => {
            p.bump();
            list(p, rename_item);
            K::PROJECT_RENAME_OPERATOR
        }
        K::EXTEND_KW => {
            p.bump();
            list(p, assignment_or_expr);
            K::EXTEND_OPERATOR
        }
        K::SUMMARIZE_KW => summarize(p),
        K::JOIN_KW | K::LOOKUP_KW => join(p),
        K::PARSE_KW | K::PARSE_WHERE_KW => parse_operator(p),
        // `parse-kv Message as (Level: string, Host: string)
        // with (pair_delimiter = " ", kv_delimiter = "=")`
        // (https://learn.microsoft.com/kusto/query/parse-kv-operator).
        K::PARSE_KV_KW => {
            p.bump();
            if expr::at_expr_start(p) {
                expr::expr(p);
            }
            if p.eat(K::AS_KW) {
                typed_columns(p);
            }
            with_options(p);
            K::PARSE_KV_OPERATOR
        }
        K::TAKE_KW | K::LIMIT_KW => {
            let kind = if p.current() == K::TAKE_KW {
                K::TAKE_OPERATOR
            } else {
                K::LIMIT_OPERATOR
            };
            p.bump();
            p.expect(K::NUMBER);
            kind
        }
        K::TOP_KW => {
            p.bump();
            p.expect(K::NUMBER);
            if p.eat(K::BY_KW) {
                list(p, sort_item);
            }
            K::TOP_OPERATOR
        }
        K::COUNT_KW => {
            p.bump();
            K::COUNT_OPERATOR
        }
        K::SORT_KW | K::ORDER_KW => {
            p.bump();
            p.eat(K::BY_KW);
            list(p, sort_item);
            K::SORT_OPERATOR
        }
        K::MV_EXPAND_KW | K::MVEXPAND_KW => mv_expand(p),
        K::MV_APPLY_KW => mv_apply(p),
        K::MAKE_SERIES_KW => make_series(p),
        K::EVALUATE_KW => {
            p.bump();
            hint_options(p);
            if p.name_at(0) && p.nth(1) == K::L_PAREN {
                expr::function_call(p);
            } else {
                p.error("expected a plugin call");
            }
            K::EVALUATE_OPERATOR
        }
        K::DISTINCT_KW => {
            p.bump();
            hint_options(p);
            if p.at(K::STAR) {
                let star = p.start();
                p.bump();
                p.done(star, K::STAR_ARG);
            } else if expr::at_expr_start(p) {
                list(p, assignment_or_expr);
            }
            K::DISTINCT_OPERATOR
        }
        K::RENDER_KW => {
            p.bump();
            p.expect_name();
            if p.at(K::WITH_KW) {
                render_with(p);
            }
            K::RENDER_OPERATOR
        }
        K::SERIALIZE_KW => {
            p.bump();
            if expr::at_expr_start(p) {
                list(p, assignment_or_expr);
            }
            K::SERIALIZE_OPERATOR
        }
        K::AS_KW => {
            p.bump();
            // `hint.materialized` is the one hint `as` takes.
            while p.at(K::HINT_NAME) && p.nth_text(0) == "hint.materialized" && p.nth(1) == K::EQ {
                option_after_name(p, K::HINT_OPTION);
            }
            p.expect_name();
            K::AS_OPERATOR
        }
        K::TOP_HITTERS_KW => {
            p.bump();
            expr::expr(p);
            p.expect(K::OF_KW);
            expr::expr(p);
            if p.at(K::BY_KW) {
                let by = p.start();
                p.bump();
                expr::expr(p);
                p.done(by, K::TOP_HITTERS_BY);
            }
            K::TOP_HITTERS_OPERATOR
        }
        K::REDUCE_KW => reduce(p),
        K::TOP_NESTED_KW => {
            list(p, top_nested_clause);
            K::TOP_NESTED_OPERATOR
        }
        K::SAMPLE_DISTINCT_KW => {
            p.bump();
            hint_options(p);
            expr::expr(p);
            p.expect(K::OF_KW);
            expr::expr(p);
            K::SAMPLE_DISTINCT_OPERATOR
        }
        K::FORK_KW => {
            p.bump();
            fork_branch(p);
            while p.at(K::L_PAREN) || (p.name_at(0) && p.nth(1) == K::EQ) {
                fork_branch(p);
            }
            K::FORK_OPERATOR
        }
        K::FACET_KW => facet(p),
        K::PARTITION_KW => partition(p),
        K::SCAN_KW => scan(p),
        K::SEARCH_KW
        | K::FIND_KW
        | K::INVOKE_KW
        | K::GETSCHEMA_KW
        | K::SAMPLE_KW
        | K::EXTERNALDATA_KW
        | K::CONSUME_KW
        | K::MAKE_GRAPH_KW
        | K::GRAPH_MATCH_KW
        | K::GRAPH_SHORTEST_PATHS_KW
        | K::GRAPH_TO_TABLE_KW
        | K::GRAPH_MARK_COMPONENTS_KW => {
            p.bump();
            if expr::at_expr_start(p) {
                expr::expr(p);
            }
            K::KEYWORD_OPERATOR
        }
        _ => {
            if p.name_at(0) {
                p.bump_as(K::IDENT);
            } else {
                p.error("expected an operator");
            }
            if expr::at_expr_start(p) {
                expr::expr(p);
            }
            K::UNKNOWN_OPERATOR
        }
    };
    p.done(m, kind);
}

/// `where predicate`
fn predicate(p: &mut P<'_>, kind: K) -> K {
    p.bump();
    expr::expr(p);
    kind
}

// ------------------------------------------------------------------ items

/// `name = value` or an expression.
fn assignment_or_expr(p: &mut P<'_>) {
    // `dynamic` and `toscalar` name no column (see `expr::primary`).
    let named = ((p.name_at(0) && !matches!(p.current(), K::DYNAMIC_KW | K::TOSCALAR_KW))
        || p.at(K::QUOTED_IDENT))
        && p.nth(1) == K::EQ;
    let tuple = p.at(K::L_PAREN) && p.nth(p.after_group(0)) == K::EQ;
    if named || tuple {
        assignment(p);
    } else {
        expr::expr(p);
    }
}

/// `Name = expr`, or `(A, B) = expr` (a tuple assignment).
fn assignment(p: &mut P<'_>) {
    let m = p.start();
    let kind = if p.at(K::L_PAREN) {
        let tuple = p.start();
        p.bump();
        list(p, name_ref);
        p.expect(K::R_PAREN);
        p.done(tuple, K::NAME_TUPLE);
        K::TUPLE_ASSIGNMENT
    } else {
        name_ref(p);
        K::ASSIGNMENT
    };
    p.expect(K::EQ);
    expr::expr(p);
    p.done(m, kind);
}

/// A plain or quoted name.
fn name_ref(p: &mut P<'_>) {
    if p.at(K::QUOTED_IDENT) || p.name_at(0) {
        expr::name_ref(p);
    } else {
        let m = p.start();
        p.error("expected a name");
        p.done(m, K::NAME_REF);
    }
}

/// Whether the current token can be part of a column pattern.
fn gluable(p: &P<'_>) -> bool {
    matches!(p.current(), K::NUMBER | K::TIMESPAN | K::STAR) || p.name_at(0)
}

/// A name, or a pattern (`User*`, `*Id`, `*`): a run of touching words,
/// numbers and stars with a star in it. A single token is a name.
fn column_ref(p: &mut P<'_>) {
    if p.at(K::QUOTED_IDENT) {
        expr::name_ref(p);
        return;
    }
    if !gluable(p) {
        name_ref(p);
        return;
    }
    let m = p.start();
    let mut star = false;
    let mut end = None;
    loop {
        let range = p.current_range();
        if end.is_some() && range.map(|r| r.start()) != end {
            break;
        }
        end = range.map(|r| r.end());
        match p.current() {
            K::STAR => {
                star = true;
                p.bump();
            }
            K::NUMBER | K::TIMESPAN => p.bump(),
            _ => p.bump_as(K::IDENT),
        }
        if !gluable(p) {
            break;
        }
    }
    p.done(m, if star { K::COLUMN_PATTERN } else { K::NAME_REF });
}

/// `a`, `a desc`, `*`.
fn reorder_item(p: &mut P<'_>) {
    let m = p.start();
    column_ref(p);
    if matches!(
        p.current(),
        K::ASC_KW | K::DESC_KW | K::GRANNY_ASC_KW | K::GRANNY_DESC_KW
    ) {
        p.bump();
    }
    p.done(m, K::REORDER_ITEM);
}

/// `new = old`
fn rename_item(p: &mut P<'_>) {
    let m = p.start();
    name_ref(p);
    p.expect(K::EQ);
    name_ref(p);
    p.done(m, K::RENAME_ITEM);
}

/// `expr asc nulls first`
fn sort_item(p: &mut P<'_>) {
    let m = p.start();
    expr::expr(p);
    if matches!(p.current(), K::ASC_KW | K::DESC_KW) {
        p.bump();
    }
    nulls(p);
    p.done(m, K::SORT_ITEM);
}

/// `nulls first`, `nulls last`
fn nulls(p: &mut P<'_>) {
    if p.eat(K::NULLS_KW) && !p.eat(K::FIRST_KW) {
        p.expect(K::LAST_KW);
    }
}

// ---------------------------------------------------------------- options

/// Whether `name = value` starts here, the name being a word or a hint.
fn at_option(p: &P<'_>) -> bool {
    (p.name_at(0) || p.current() == K::HINT_NAME) && p.nth(1) == K::EQ
}

/// `name = value`: the value is a word, a boolean, a number or a string.
fn option_value(p: &mut P<'_>) {
    let v = p.start();
    match p.current() {
        K::BOOLEAN | K::NUMBER | K::STRING => p.bump(),
        _ if p.name_at(0) => p.bump_as(K::IDENT),
        _ => p.error("expected an option value"),
    }
    p.done(v, K::OPTION_VALUE);
}

fn option_after_name(p: &mut P<'_>, kind: K) {
    let m = p.start();
    if p.at(K::HINT_NAME) {
        p.bump();
    } else {
        p.bump_as(K::IDENT);
    }
    p.expect(K::EQ);
    option_value(p);
    p.done(m, kind);
}

/// `kind=inner isfuzzy=true hint.strategy=shuffle`: any name.
fn options(p: &mut P<'_>) {
    while at_option(p) {
        option_after_name(p, K::OPERATOR_OPTION);
    }
}

/// The options of `mv-expand`: a fixed set of names.
/// The option names are keywords here, as in the old grammar: `bagexpansion`
/// without `=` is an error, not a column.
fn mv_options(p: &mut P<'_>) {
    while matches!(
        p.current(),
        K::KIND_KW | K::BAGEXPANSION_KW | K::WITH_ITEMINDEX_KW | K::HINT_NAME
    ) {
        let m = p.start();
        p.bump();
        p.expect(K::EQ);
        option_value(p);
        p.done(m, K::MV_OPTION);
    }
}

/// `hint.*` options only.
fn hint_options(p: &mut P<'_>) {
    while p.current() == K::HINT_NAME && p.nth(1) == K::EQ {
        option_after_name(p, K::HINT_OPTION);
    }
}

// -------------------------------------------------------------- operators

fn summarize(p: &mut P<'_>) -> K {
    p.bump();
    hint_options(p);
    if !p.at(K::BY_KW) && expr::at_expr_start(p) {
        list(p, assignment_or_expr);
    }
    if p.eat(K::BY_KW) {
        list(p, assignment_or_expr);
    }
    K::SUMMARIZE_OPERATOR
}

/// `join` and `lookup`: options, the right side, `on`, conditions.
fn join(p: &mut P<'_>) -> K {
    let kind = if p.current() == K::JOIN_KW {
        K::JOIN_OPERATOR
    } else {
        K::LOOKUP_OPERATOR
    };
    p.bump();
    options(p);
    let s = p.start();
    source(p);
    p.done(s, K::TABULAR_SOURCE);
    p.expect(K::ON_KW);
    list(p, expr_item);
    kind
}

fn expr_item(p: &mut P<'_>) {
    expr::expr(p);
}

fn union_operator(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    options(p);
    list(p, union_leg);
    p.done(m, K::UNION_OPERATOR);
}

fn union_leg(p: &mut P<'_>) {
    if p.at(K::L_PAREN) {
        let m = p.start();
        p.bump();
        tabular_expression(p);
        p.expect(K::R_PAREN);
        p.done(m, K::PAREN_TABULAR);
    } else if p.name_at(0) && p.nth(1) == K::L_PAREN {
        call_or_qualified_table(p, true);
    } else if !table_run(p, Some(K::TABLE_REF)) {
        table_name(p);
    }
}

/// A table or a table pattern (`Sec*`, `*Events`, `Sec*Events`, `*`): a run
/// of touching words, numbers, timespans and stars that starts with a word or
/// a star, consumed as it is read, as [`column_ref`] reads a column pattern.
/// With a star it is a pattern, as Kusto takes in a union and a search's `in`
/// list; without one it is a single name, closed as `plain`, or left a bare
/// token when `plain` is `None`. Returns false, consuming nothing, at
/// anything else.
fn table_run(p: &mut P<'_>, plain: Option<K>) -> bool {
    if !(p.at(K::STAR) || p.name_at(0)) {
        return false;
    }
    let m = p.start();
    let mut star = false;
    let mut end = None;
    loop {
        let range = p.current_range();
        if end.is_some()
            && (range.map(|r| r.start()) != end
                || !(matches!(p.current(), K::STAR | K::NUMBER | K::TIMESPAN) || p.name_at(0)))
        {
            break;
        }
        end = range.map(|r| r.end());
        match p.current() {
            K::STAR => {
                star = true;
                p.bump();
            }
            K::NUMBER | K::TIMESPAN => p.bump(),
            _ => p.bump_as(K::IDENT),
        }
    }
    match (star, plain) {
        (true, _) => {
            p.done(m, K::TABLE_PATTERN);
        }
        (false, Some(kind)) => {
            p.done(m, kind);
        }
        (false, None) => p.abandon(m),
    }
    true
}

/// One table of a search's `in` list: a name, or a pattern.
fn search_table(p: &mut P<'_>) {
    if !table_run(p, None) && !p.eat(K::QUOTED_IDENT) {
        p.expect_name();
    }
}

fn parse_operator(p: &mut P<'_>) -> K {
    let kind = if p.current() == K::PARSE_KW {
        K::PARSE_OPERATOR
    } else {
        K::PARSE_WHERE_OPERATOR
    };
    p.bump();
    options(p);
    expr::expr(p);
    p.expect(K::WITH_KW);
    let mut pieces = 0;
    while matches!(p.current(), K::STRING | K::STAR) || p.name_at(0) {
        parse_piece(p);
        pieces += 1;
    }
    if pieces == 0 {
        p.error("expected a pattern");
    }
    kind
}

/// `"text"`, `*` or `name:type`.
fn parse_piece(p: &mut P<'_>) {
    let m = p.start();
    if matches!(p.current(), K::STRING | K::STAR) {
        p.bump();
        p.done(m, K::PARSE_PIECE);
    } else {
        p.bump_as(K::IDENT);
        if p.eat(K::COLON) {
            statement::type_(p);
        }
        p.done(m, K::PARSE_COLUMN);
    }
}

fn mv_expand(p: &mut P<'_>) -> K {
    p.bump();
    mv_options(p);
    list(p, mv_expand_item);
    if p.eat(K::LIMIT_KW) {
        expr::expr(p);
    }
    K::MV_EXPAND_OPERATOR
}

/// `col`, `x = col`, `col to typeof(int)`.
fn mv_expand_item(p: &mut P<'_>) {
    let m = p.start();
    assignment_or_expr(p);
    if p.eat(K::TO_KW) {
        p.expect(K::TYPEOF_KW);
        p.expect(K::L_PAREN);
        statement::type_(p);
        p.expect(K::R_PAREN);
    }
    p.done(m, K::MV_EXPAND_ITEM);
}

fn mv_apply(p: &mut P<'_>) -> K {
    p.bump();
    mv_options(p);
    list(p, mv_expand_item);
    if p.eat(K::LIMIT_KW) {
        expr::expr(p);
    }
    p.expect(K::ON_KW);
    paren_subquery(p);
    K::MV_APPLY_OPERATOR
}

fn make_series(p: &mut P<'_>) -> K {
    p.bump();
    mv_options(p);
    list(p, series_aggregate);
    p.expect(K::ON_KW);
    expr::expr(p);
    if p.eat(K::IN_KW) {
        if p.name_at(0) && p.nth(1) == K::L_PAREN {
            expr::function_call(p);
        } else {
            p.error("expected a call such as range(start, stop, step)");
        }
    } else {
        if p.eat(K::FROM_KW) {
            expr::expr(p);
        }
        if p.eat(K::TO_KW) {
            expr::expr(p);
        }
        if p.expect(K::STEP_KW) {
            expr::expr(p);
        }
    }
    if p.eat(K::BY_KW) {
        list(p, assignment_or_expr);
    }
    K::MAKE_SERIES_OPERATOR
}

/// `x = avg(y) default = 0`
fn series_aggregate(p: &mut P<'_>) {
    let m = p.start();
    assignment_or_expr(p);
    if p.at(K::DEFAULT_KW) {
        let d = p.start();
        p.bump();
        p.expect(K::EQ);
        expr::expr(p);
        p.done(d, K::SERIES_DEFAULT);
    }
    p.done(m, K::SERIES_AGGREGATE);
}

/// `range x from 1 to 10 step 1`
fn range_operator(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    p.expect_name();
    p.expect(K::FROM_KW);
    expr::expr(p);
    p.expect(K::TO_KW);
    expr::expr(p);
    p.expect(K::STEP_KW);
    expr::expr(p);
    p.done(m, K::RANGE_OPERATOR);
}

/// `top-nested 3 of x with others = "o" by count() desc nulls last`
fn top_nested_clause(p: &mut P<'_>) {
    let m = p.start();
    p.expect(K::TOP_NESTED_KW);
    if !p.at(K::OF_KW) {
        expr::expr(p);
    }
    let of = p.start();
    p.expect(K::OF_KW);
    assignment_or_expr(p);
    p.done(of, K::TOP_NESTED_OF);
    if p.at(K::WITH_KW) {
        let others = p.start();
        p.bump();
        p.expect(K::OTHERS_KW);
        p.expect(K::EQ);
        expr::expr(p);
        p.done(others, K::TOP_NESTED_OTHERS);
    }
    let by = p.start();
    p.expect(K::BY_KW);
    assignment_or_expr(p);
    if matches!(p.current(), K::ASC_KW | K::DESC_KW) {
        p.bump();
    }
    nulls(p);
    p.done(by, K::TOP_NESTED_BY);
    p.done(m, K::TOP_NESTED_CLAUSE);
}

/// `name = (subquery)` or `(subquery)`.
fn fork_branch(p: &mut P<'_>) {
    let m = p.start();
    if p.name_at(0) && p.nth(1) == K::EQ {
        p.bump_as(K::IDENT);
        p.bump();
    }
    paren_subquery(p);
    p.done(m, K::FORK_BRANCH);
}

fn facet(p: &mut P<'_>) -> K {
    p.bump();
    p.expect(K::BY_KW);
    list(p, ident);
    if p.eat(K::WITH_KW) {
        if p.at(K::L_PAREN) {
            paren_subquery(p);
        } else if p.enter() {
            operator(p);
            p.exit();
        }
    }
    K::FACET_OPERATOR
}

fn ident(p: &mut P<'_>) {
    p.expect_name();
}

fn partition(p: &mut P<'_>) -> K {
    p.bump();
    hint_options(p);
    p.expect(K::BY_KW);
    p.expect_name();
    if p.eat(K::IN_KW) {
        if p.at(K::DYNAMIC_KW) {
            expr::dynamic_literal(p);
        } else if p.name_at(0) && p.nth(1) == K::L_PAREN {
            expr::function_call(p);
        } else {
            p.error("expected a call or a dynamic list");
        }
    }
    if p.at(K::L_BRACE) {
        p.bump();
        tabular_expression(p);
        p.expect(K::R_BRACE);
    } else {
        paren_subquery(p);
    }
    K::PARTITION_OPERATOR
}

fn scan(p: &mut P<'_>) -> K {
    p.bump();
    options(p);
    if p.at(K::ORDER_KW) {
        p.bump();
        p.expect(K::BY_KW);
        list(p, sort_item);
    }
    if p.at(K::PARTITION_KW) {
        p.bump();
        p.expect(K::BY_KW);
        list(p, expr_item);
    }
    if p.eat(K::DECLARE_KW) {
        p.expect(K::L_PAREN);
        if !p.at(K::R_PAREN) {
            list(p, statement::parameter);
        }
        p.expect(K::R_PAREN);
    }
    p.expect(K::WITH_KW);
    p.expect(K::L_PAREN);
    scan_step(p);
    while p.at(K::STEP_KW) {
        scan_step(p);
    }
    p.expect(K::R_PAREN);
    K::SCAN_OPERATOR
}

/// `step s optional output = last: predicate => n = s.n + 1;`
fn scan_step(p: &mut P<'_>) {
    let m = p.start();
    if !p.expect(K::STEP_KW) {
        p.done(m, K::SCAN_STEP);
        return;
    }
    p.expect_name();
    p.eat(K::OPTIONAL_KW);
    if p.eat(K::OUTPUT_KW) {
        p.expect(K::EQ);
        if matches!(p.current(), K::ALL_KW | K::LAST_KW | K::NONE_KW) {
            p.bump();
        } else {
            p.error("expected `all`, `last` or `none`");
        }
    }
    p.expect(K::COLON);
    expr::expr(p);
    if p.eat(K::FAT_ARROW) {
        list(p, assignment);
    }
    p.expect(K::SEMICOLON);
    p.done(m, K::SCAN_STEP);
}

/// `print a = 1, 2`
fn print_operator(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    list(p, assignment_or_expr);
    p.done(m, K::PRINT_OPERATOR);
}

/// `datatable (a: string, b: int) [ "x", 1 ]`
fn datatable(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    typed_columns(p);
    p.expect(K::L_BRACKET);
    if !p.at(K::R_BRACKET) {
        list_until(p, K::R_BRACKET, expr_item);
    }
    p.expect(K::R_BRACKET);
    p.done(m, K::DATATABLE_EXPRESSION);
}

/// `(a: string, b: int, ...)`, with an optional trailing comma.
fn typed_columns(p: &mut P<'_>) {
    p.expect(K::L_PAREN);
    loop {
        let c = p.start();
        p.expect_name();
        p.expect(K::COLON);
        statement::type_(p);
        p.done(c, K::DATATABLE_COLUMN);
        if !p.eat(K::COMMA) || p.at(K::R_PAREN) {
            break;
        }
    }
    p.expect(K::R_PAREN);
}

/// `externaldata (c: string) [@"https://..."] with (format = "csv")`
fn externaldata(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    options(p);
    typed_columns(p);
    p.expect(K::L_BRACKET);
    list_until(p, K::R_BRACKET, expr_item);
    p.expect(K::R_BRACKET);
    with_options(p);
    p.done(m, K::EXTERNALDATA_EXPRESSION);
}

/// `with (format = "csv", ignoreFirstRecord = true)`, when `with` comes.
fn with_options(p: &mut P<'_>) {
    if p.eat(K::WITH_KW) {
        p.expect(K::L_PAREN);
        loop {
            if at_option(p) {
                option_after_name(p, K::OPERATOR_OPTION);
            } else {
                p.error("expected an option");
                break;
            }
            if !p.eat(K::COMMA) {
                break;
            }
        }
        p.expect(K::R_PAREN);
    }
}

/// `search "x"`, `search in (A, B) where x`, `find in (T) where x`.
fn search_source(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    options(p);
    // `in` after `search` starts the table list, as in the old grammar.
    if p.at(K::IN_KW) {
        p.bump();
        if p.expect(K::L_PAREN) {
            list(p, search_table);
            p.expect(K::R_PAREN);
        }
    }
    p.eat(K::WHERE_KW);
    expr::expr(p);
    p.done(m, K::SEARCH_SOURCE);
}

// ------------------------------------------------- render, reduce

/// `with (title = "x", ycolumns = a, b)`: a property's value is an expression,
/// and a bare name after it continues its column list.
fn render_with(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    p.expect(K::L_PAREN);
    if !p.at(K::R_PAREN) {
        // Whether a bare name may come: only after a property whose value is
        // a list of columns, as Kusto.Language reads them.
        let mut in_list = false;
        loop {
            if p.name_at(0) && p.nth(1) == K::EQ {
                in_list = matches!(p.nth_text(0), "ycolumns" | "series" | "anomalycolumns");
                let property = p.start();
                p.bump_as(K::IDENT);
                p.bump();
                expr::expr(p);
                p.done(property, K::NAMED_ARGUMENT);
            } else if in_list && p.name_at(0) {
                name_ref(p);
            } else {
                p.error("expected `name = value`");
                break;
            }
            if !p.eat(K::COMMA) {
                break;
            }
        }
    }
    p.expect(K::R_PAREN);
    p.done(m, K::RENDER_WITH);
}

/// Whether `name = value` starts here with one of `names`, spelt exactly.
fn at_named_option(p: &P<'_>, names: &[&str]) -> bool {
    p.name_at(0) && p.nth(1) == K::EQ && names.contains(&p.nth_text(0))
}

/// `reduce kind=source by x with threshold=0.1, characters="ab"`
fn reduce(p: &mut P<'_>) -> K {
    const WITH: &[&str] = &["kind", "threshold", "characters"];
    p.bump();
    while at_named_option(p, &["kind"]) {
        option_after_name(p, K::OPERATOR_OPTION);
    }
    p.expect(K::BY_KW);
    expr::expr(p);
    // Kusto.Language accepts a `with` that no option follows.
    if p.eat(K::WITH_KW) && p.name_at(0) && p.nth(1) == K::EQ {
        loop {
            if !at_named_option(p, WITH) {
                p.error("expected `threshold`, `characters` or `kind`");
                break;
            }
            option_after_name(p, K::OPERATOR_OPTION);
            if !p.eat(K::COMMA) {
                break;
            }
        }
    }
    K::REDUCE_OPERATOR
}
