//! The stats family (`stats`, `chart`, `geostats`, ...) and `tstats`: options,
//! aggregates (each with an optional `as` alias, separated by spaces or
//! commas), then `over` and `by` clauses that may carry options. Which option
//! a command takes is the analysis's business (`command-options.toml`); the
//! grammar accepts any `name=value`.

use super::expr;
use super::kind::SyntaxKind as K;
use super::parser::leaf;
use super::search;
use opentide_parse::Parser;

/// Whether the current token is the word `word` (any case), the way the
/// grammar's `kw()` tokens read.
pub(super) fn kw(p: &Parser<'_>, word: &str) -> bool {
    let kind = p.current();
    (kind == K::IDENT.raw() || kind == K::FIELD_WORD.raw())
        && p.current_text().eq_ignore_ascii_case(word)
}

pub(super) fn at_stage_end(p: &Parser<'_>) -> bool {
    let kind = p.current();
    p.at_eof() || kind == K::PIPE.raw() || kind == K::R_BRACKET.raw() || kind == K::R_PAREN.raw()
}

/// `AND`, `OR` and `NOT` are reserved: they are no name, field or value.
pub(super) fn reserved(p: &Parser<'_>) -> bool {
    p.current() == K::IDENT.raw() && matches!(p.current_text(), "AND" | "OR" | "NOT")
}

/// A name that is no number: a name, or a field word (`a-b`, `{}.Id`).
pub(super) fn at_name(p: &Parser<'_>) -> bool {
    let kind = p.current();
    (kind == K::IDENT.raw() || kind == K::FIELD_WORD.raw()) && !reserved(p)
}

/// `true`, `false`, `TRUE` or `FALSE` with no `(`: where a call can start,
/// the boolean keyword is only the name of one, so it wants its `(`.
pub(super) fn at_bare_boolean(p: &Parser<'_>) -> bool {
    p.current() == K::IDENT.raw()
        && matches!(p.current_text(), "true" | "false" | "TRUE" | "FALSE")
        && p.nth(1) != K::L_PAREN.raw()
}

/// A plain name (`identifier` in the grammar): no field word, no number.
fn at_ident(p: &Parser<'_>) -> bool {
    p.current() == K::IDENT.raw() && !reserved(p)
}

/// A field name, which Splunk lets start with a digit (`0=f`, `sort 0 a`).
pub(super) fn at_field(p: &Parser<'_>) -> bool {
    at_name(p) || p.current() == K::NUMBER_TOKEN.raw()
}

pub(super) fn at_option(p: &Parser<'_>) -> bool {
    at_field(p) && p.nth(1) == K::EQ.raw()
}

/// An option in a stats command, where `by`, `over`, `from` and `where` are
/// keywords: `by=1` is not an option.
fn at_stats_option(p: &Parser<'_>) -> bool {
    at_option(p) && !(kw(p, "by") || kw(p, "over") || kw(p, "from") || kw(p, "where"))
}

pub(super) fn at_call(p: &Parser<'_>) -> bool {
    p.current() == K::IDENT.raw() && p.nth(1) == K::L_PAREN.raw()
}

/// The keyword `PREFIX`, which wants its `(`.
fn at_prefix(p: &Parser<'_>) -> bool {
    p.current() == K::IDENT.raw() && p.current_text() == "PREFIX"
}

pub(super) fn commas(p: &mut Parser<'_>) {
    while p.eat(K::COMMA.raw()) {}
}

/// The current field name as an identifier node.
pub(super) fn name_leaf(p: &mut Parser<'_>) {
    let kind = p.current();
    let m = p.start();
    p.bump_as(kind);
    m.complete(p, K::IDENTIFIER.raw());
}

/// `PREFIX(dst=)`.
pub(super) fn prefix_clause(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::PREFIX_KW.raw());
    if p.eat(K::L_PAREN.raw()) {
        if p.current() == K::TERM_TEXT_TOKEN.raw() {
            leaf(p, K::TERM_TEXT, K::TERM_TEXT_TOKEN);
        }
        p.eat(K::R_PAREN.raw());
    } else {
        p.error("expected `(` after `PREFIX`");
    }
    m.complete(p, K::PREFIX_CLAUSE.raw());
}

/// What follows `name=`: a call, string, number, boolean, name, wildcard,
/// search word, macro or value list.
pub(super) fn option_value(p: &mut Parser<'_>) -> bool {
    let kind = p.current();
    let is = |k: K| k.raw() == kind;
    if is(K::L_PAREN) {
        search::value_list(p);
    } else if is(K::MACRO_TOKEN) {
        search::macro_call(p);
    } else if reserved(p) {
        return false;
    } else if is(K::IDENT) {
        expr::name_or_call(p);
    } else if is(K::FIELD_WORD) {
        name_leaf(p);
    } else if is(K::NUMBER_TOKEN) {
        leaf(p, K::NUMBER, K::NUMBER_TOKEN);
    } else if is(K::STRING_TOKEN) {
        leaf(p, K::STR, K::STRING_TOKEN);
    } else if is(K::GLOB_TOKEN) {
        leaf(p, K::GLOB, K::GLOB_TOKEN);
    } else if is(K::SEARCH_WORD_TOKEN) || is(K::CALL_WORD) {
        leaf(p, K::SEARCH_WORD, kind_of(kind));
    } else {
        return false;
    }
    true
}

fn kind_of(raw: rowan::SyntaxKind) -> K {
    if raw == K::CALL_WORD.raw() {
        K::CALL_WORD
    } else {
        K::SEARCH_WORD_TOKEN
    }
}

/// `name=value`.
pub(super) fn command_option(p: &mut Parser<'_>) {
    let m = p.start();
    name_leaf(p);
    p.bump();
    if !option_value(p) {
        p.error("missing the value of the option");
    }
    m.complete(p, K::COMMAND_OPTION.raw());
}

/// One argument of an aggregate call.
fn aggregate_argument(p: &mut Parser<'_>) -> bool {
    let kind = p.current();
    if at_prefix(p) {
        prefix_clause(p);
    } else if at_call(p) {
        expr::name_or_call(p);
    } else if at_field(p) {
        name_leaf(p);
    } else if kind == K::GLOB_TOKEN.raw() {
        leaf(p, K::GLOB, K::GLOB_TOKEN);
    } else if kind == K::STRING_TOKEN.raw() {
        leaf(p, K::STR, K::STRING_TOKEN);
    } else if kind == K::NUMBER_TOKEN.raw() {
        leaf(p, K::NUMBER, K::NUMBER_TOKEN);
    } else {
        return false;
    }
    true
}

/// `count`, `dc(src) as c`, `values(*) as *`, `min(eval(if(...))) as e`.
fn aggregate_item(p: &mut Parser<'_>) -> bool {
    let m = p.start();
    if at_call(p) {
        let call = p.start();
        name_leaf(p);
        p.bump();
        if p.current() != K::R_PAREN.raw() {
            loop {
                if !aggregate_argument(p) {
                    p.error("expected an argument");
                    break;
                }
                if !p.eat(K::COMMA.raw()) {
                    break;
                }
            }
        }
        if !p.eat(K::R_PAREN.raw()) {
            p.error("missing `)`");
        }
        call.complete(p, K::FUNCTION_CALL.raw());
    } else if at_ident(p) {
        name_leaf(p);
    } else {
        m.abandon(p);
        return false;
    }
    if kw(p, "as") {
        p.bump_as(K::AS_KW.raw());
        let kind = p.current();
        if at_field(p) {
            name_leaf(p);
        } else if kind == K::GLOB_TOKEN.raw() {
            leaf(p, K::GLOB, K::GLOB_TOKEN);
        } else if kind == K::STRING_TOKEN.raw() {
            leaf(p, K::STR, K::STRING_TOKEN);
        } else {
            p.error("expected a name after `as`");
        }
    }
    m.complete(p, K::AGGREGATE_ITEM.raw());
    true
}

fn at_by_field(p: &Parser<'_>) -> bool {
    let kind = p.current();
    at_field(p)
        || kind == K::STRING_TOKEN.raw()
        || kind == K::MACRO_TOKEN.raw()
        || kind == K::L_BRACKET.raw()
}

fn by_field(p: &mut Parser<'_>) -> bool {
    let kind = p.current();
    if at_prefix(p) {
        prefix_clause(p);
    } else if at_field(p) {
        name_leaf(p);
    } else if kind == K::STRING_TOKEN.raw() {
        leaf(p, K::STR, K::STRING_TOKEN);
    } else if kind == K::MACRO_TOKEN.raw() {
        search::macro_call(p);
    } else if kind == K::L_BRACKET.raw() {
        search::subsearch(p);
    } else {
        return false;
    }
    true
}

/// `by a, b span=1h`: fields, with options among or after them. In a chart,
/// a `where` ends it.
fn by_clause(p: &mut Parser<'_>, chart: bool) {
    let m = p.start();
    p.bump_as(K::BY_KW.raw());
    if !by_field(p) {
        p.error("expected a field after `by`");
    }
    loop {
        if at_stats_option(p) {
            command_option(p);
        } else if p.current() == K::COMMA.raw() {
            commas(p);
            if (at_by_field(p) || at_prefix(p)) && !(chart && kw(p, "where")) {
                by_field(p);
            }
        } else if (at_by_field(p) || at_prefix(p)) && !(chart && kw(p, "where")) {
            by_field(p);
        } else {
            break;
        }
    }
    m.complete(p, K::BY_CLAUSE.raw());
}

/// Options, then `over` and `by`, after the aggregates.
fn tail(p: &mut Parser<'_>, chart: bool) {
    while at_stats_option(p) {
        command_option(p);
    }
    if kw(p, "over") {
        let m = p.start();
        p.bump_as(K::OVER_KW.raw());
        if !by_field(p) {
            p.error("expected a field after `over`");
        }
        while at_stats_option(p) {
            command_option(p);
        }
        m.complete(p, K::OVER_CLAUSE.raw());
    }
    if kw(p, "by") {
        by_clause(p, chart);
    }
}

/// `where count in top5`, `where count > 10`, at the end of a chart.
fn chart_where(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::WHERE_KW.raw());
    if at_call(p) {
        expr::name_or_call(p);
    } else if at_field(p) {
        name_leaf(p);
    } else {
        p.error("expected a field after `where`");
    }
    let kind = p.current();
    if kw(p, "in") || kw(p, "notin") {
        let word = if kw(p, "in") {
            K::IN_LOWER_KW
        } else {
            K::NOTIN_KW
        };
        p.bump_as(word.raw());
        if at_field(p) {
            name_leaf(p);
        } else {
            p.error("expected a name");
        }
    } else if [K::EQ, K::NE, K::LT, K::GT, K::LE, K::GE]
        .iter()
        .any(|k| k.raw() == kind)
    {
        p.bump();
        if p.current() == K::NUMBER_TOKEN.raw() {
            leaf(p, K::NUMBER, K::NUMBER_TOKEN);
        } else {
            p.error("expected a number");
        }
    } else {
        p.error("expected `in`, `notin` or a comparison");
    }
    m.complete(p, K::CHART_WHERE.raw());
}

/// The aggregates of a stats-family command; `false` when there are none.
fn aggregates(p: &mut Parser<'_>, chart: bool) -> bool {
    let mut any = false;
    loop {
        // A comma separates aggregates; one may not lead the list, and what
        // follows one is an aggregate even if it is spelt `by` (as it is first).
        if any {
            commas(p);
        }
        // Once an aggregate precedes (a comma or not), `by`, `over` and a
        // chart's `where` are the clauses, not more aggregates.
        if at_stage_end(p)
            || (any && (kw(p, "by") || kw(p, "over")))
            || at_stats_option(p)
            || (any && chart && kw(p, "where"))
        {
            break;
        }
        if p.current() == K::MACRO_TOKEN.raw() {
            search::macro_call(p);
        } else if !aggregate_item(p) {
            break;
        }
        any = true;
    }
    any
}

/// `stats`, `chart`, `geostats` and their variants.
pub(super) fn stats_command(p: &mut Parser<'_>) {
    let m = p.start();
    let (word, keyword) = match p.current_text() {
        "chart" | "timechart" | "sichart" | "sitimechart" => (Family::Chart, K::CHART_KW),
        "geostats" => (Family::Geostats, K::GEOSTATS_KW),
        _ => (Family::Stats, K::STATS_KW),
    };
    p.bump_as(keyword.raw());
    // `stats` with no arguments at all is accepted (it keeps every row).
    if !(word == Family::Stats && at_stage_end(p)) {
        let mut options = false;
        while at_stats_option(p) {
            command_option(p);
            options = true;
        }
        let any = aggregates(p, word == Family::Chart);
        // geostats takes options and no aggregate at all.
        if !(any || word == Family::Geostats && options) {
            p.error("expected an aggregate");
        }
        tail(p, word == Family::Chart);
        if word == Family::Chart && kw(p, "where") {
            chart_where(p);
        }
    }
    m.complete(p, K::STATS_COMMAND.raw());
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Stats,
    Chart,
    Geostats,
}

/// The options only tstats has: keywords, so they want their `=`.
fn tstats_keyword(p: &Parser<'_>) -> Option<K> {
    if p.current() != K::IDENT.raw() {
        return None;
    }
    match p.current_text() {
        "summariesonly" => Some(K::SUMMARIESONLY_KW),
        "prestats" => Some(K::PRESTATS_KW),
        "allow_old_summaries" => Some(K::ALLOW_OLD_SUMMARIES_KW),
        "fillnull_value" => Some(K::FILLNULL_VALUE_KW),
        _ => None,
    }
}

/// Macros and options before or after tstats's aggregates.
fn tstats_preamble(p: &mut Parser<'_>) {
    loop {
        if p.current() == K::MACRO_TOKEN.raw() {
            search::macro_call(p);
        } else if let Some(keyword) = tstats_keyword(p) {
            let m = p.start();
            p.bump_as(keyword.raw());
            if p.eat(K::EQ.raw()) {
                if !option_value(p) {
                    p.error("missing the value of the option");
                }
            } else {
                p.error("expected `=`");
            }
            m.complete(p, K::TSTATS_OPTION.raw());
        } else if at_stats_option(p) {
            command_option(p);
        } else {
            break;
        }
    }
}

/// `tstats [options] aggregates [from datamodel=x] [where terms] [by ...]`.
pub(super) fn tstats_command(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::TSTATS_KW.raw());
    tstats_preamble(p);
    let mut any = false;
    loop {
        // One comma at most between aggregates, none leading or trailing.
        let comma = any && p.eat(K::COMMA.raw());
        if at_stage_end(p)
            || at_stats_option(p)
            || tstats_keyword(p).is_some()
            || (any && !comma && (kw(p, "from") || kw(p, "where") || kw(p, "by")))
            || p.current() == K::MACRO_TOKEN.raw()
        {
            if comma {
                p.error("expected an aggregate after the comma");
            }
            break;
        }
        if !aggregate_item(p) {
            if comma {
                p.error("expected an aggregate after the comma");
            }
            break;
        }
        any = true;
    }
    if !any {
        p.error("expected an aggregate");
    }
    tstats_preamble(p);
    if kw(p, "from") {
        p.bump_as(K::FROM_KW.raw());
        // `datamodel` is a keyword here, and wants its `=`.
        if p.current() == K::IDENT.raw() && p.current_text() == "datamodel" {
            p.bump_as(K::DATAMODEL_KW.raw());
            if !p.eat(K::EQ.raw()) {
                p.error("expected `=`");
            }
        }
        if at_field(p) {
            name_leaf(p);
        } else if p.current() == K::STRING_TOKEN.raw() {
            leaf(p, K::STR, K::STRING_TOKEN);
        } else {
            p.error("expected a data model");
        }
    }
    if kw(p, "where") {
        p.bump_as(K::WHERE_KW.raw());
        if !search::starts_expression(p) {
            p.error("expected a search term");
        }
        search::search_expression_before_by(p);
    }
    if kw(p, "by") {
        by_clause(p, false);
    }
    m.complete(p, K::TSTATS_COMMAND.raw());
}

#[cfg(test)]
mod tests {
    use super::super::parser::tests::render;

    #[test]
    fn stats_with_options_aliases_and_by() {
        let out = render("| stats count, dc(src) as c values(*) as * by host span=1h");
        assert!(out.ends_with("--\n"), "{out}");
        assert_eq!(out.matches("AGGREGATE_ITEM@").count(), 3, "{out}");
        assert_eq!(out.matches("BY_CLAUSE@").count(), 1, "{out}");
        assert!(render("| stats").ends_with("--\n"));
        assert!(render("| stats limit=5").contains("expected an aggregate"));
        // `by` first is the aggregate, as in Splunk.
        assert!(render("| stats by x").ends_with("--\n"));
    }

    #[test]
    fn chart_where_and_geostats() {
        assert!(render("| timechart span=1h count by host where count in top5").ends_with("--\n"));
        assert!(render("| chart count over a by b where count > 10").ends_with("--\n"));
        assert!(render("| geostats latfield=lat count").ends_with("--\n"));
        assert!(render("| geostats").contains("expected an aggregate"));
    }

    #[test]
    fn tstats_preamble_from_where_and_prefix() {
        let q =
            "| tstats `m` summariesonly=t count where index=a x=1 by PREFIX(dst=), _time span=1h";
        let out = render(q);
        assert!(out.ends_with("--\n"), "{out}");
        for node in [
            "TSTATS_OPTION",
            "SEARCH_EXPRESSION",
            "PREFIX_CLAUSE",
            "BY_CLAUSE",
        ] {
            assert!(out.contains(node), "{node}: {out}");
        }
        assert!(render("| tstats count from datamodel=Endpoint.Processes").ends_with("--\n"));
    }
}
