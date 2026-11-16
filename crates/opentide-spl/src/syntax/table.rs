//! The commands that take field lists and options: `table`, `fields`,
//! `rename`, `dedup`, `sort`, `head`, `tail`, `rex`, `fillnull`, `mvexpand`
//! and `makemv`. A list is entries separated by spaces or commas; Splunk
//! reads a comma as a separator, so it takes a doubled or trailing one.

use super::expr;
use super::kind::SyntaxKind as K;
use super::parser::leaf;
use super::search;
use super::stats::{
    at_bare_boolean, at_call, at_field, at_option, at_stage_end, command_option, commas, kw,
    name_leaf,
};
use opentide_parse::Parser;

/// Whether `word` names a command of this module.
pub(super) fn is_table_command(word: &str) -> bool {
    matches!(
        word,
        "table"
            | "fields"
            | "rename"
            | "dedup"
            | "sort"
            | "head"
            | "tail"
            | "rex"
            | "fillnull"
            | "mvexpand"
            | "makemv"
    )
}

/// Reads the command at the current token.
pub(super) fn command(p: &mut Parser<'_>) {
    let name = p.current_text();
    let (node, keyword) = match name {
        "table" => (K::TABLE_COMMAND, K::TABLE_KW),
        "fields" => (K::FIELDS_COMMAND, K::FIELDS_KW),
        "rename" => (K::RENAME_COMMAND, K::RENAME_KW),
        "dedup" => (K::DEDUP_COMMAND, K::DEDUP_KW),
        "sort" => (K::SORT_COMMAND, K::SORT_KW),
        "head" => (K::HEAD_COMMAND, K::HEAD_KW),
        "tail" => (K::TAIL_COMMAND, K::TAIL_KW),
        "rex" => (K::REX_COMMAND, K::REX_KW),
        "fillnull" => (K::FILLNULL_COMMAND, K::FILLNULL_KW),
        "mvexpand" => (K::MVEXPAND_COMMAND, K::MVEXPAND_KW),
        _ => (K::MAKEMV_COMMAND, K::MAKEMV_KW),
    };
    let m = p.start();
    p.bump_as(keyword.raw());
    match node {
        K::TABLE_COMMAND => {
            if !field_list(p) {
                p.error("expected a field");
            }
        }
        K::FIELDS_COMMAND => {
            if p.current() == K::MINUS.raw() || p.current() == K::PLUS.raw() {
                p.bump();
            }
            field_list(p);
        }
        K::RENAME_COMMAND => rename(p),
        K::DEDUP_COMMAND => dedup(p),
        K::SORT_COMMAND => sort(p),
        K::HEAD_COMMAND => {
            number(p);
            while at_option(p) {
                command_option(p);
            }
        }
        K::TAIL_COMMAND => number(p),
        K::REX_COMMAND => rex(p),
        K::FILLNULL_COMMAND => fillnull(p),
        K::MVEXPAND_COMMAND => mvexpand(p),
        _ => makemv(p),
    }
    m.complete(p, node.raw());
}

fn number(p: &mut Parser<'_>) {
    if p.current() == K::NUMBER_TOKEN.raw() {
        leaf(p, K::NUMBER, K::NUMBER_TOKEN);
    }
}

/// A name, wildcard, quoted name or macro, as a node. `false` when the
/// current token is none.
fn field_name(p: &mut Parser<'_>) -> bool {
    let kind = p.current();
    if at_field(p) {
        name_leaf(p);
    } else if kind == K::GLOB_TOKEN.raw() {
        leaf(p, K::GLOB, K::GLOB_TOKEN);
    } else if kind == K::STRING_TOKEN.raw() {
        leaf(p, K::STR, K::STRING_TOKEN);
    } else if kind == K::MACRO_TOKEN.raw() {
        search::macro_call(p);
    } else {
        return false;
    }
    true
}

/// `a, b*, "c"`: one or more fields, a comma (or several, or a trailing
/// one) between them but none leading.
fn field_list(p: &mut Parser<'_>) -> bool {
    let mut any = false;
    loop {
        if any {
            commas(p);
        }
        if at_stage_end(p) || !field_name(p) {
            break;
        }
        any = true;
    }
    any
}

/// `rename a as b, DNS.* as *`.
fn rename(p: &mut Parser<'_>) {
    let mut any = false;
    loop {
        if any {
            commas(p);
        }
        if at_stage_end(p) {
            break;
        }
        let item = p.start();
        let kind = p.current();
        if p.current() == K::PREFIX_FIELD.raw() {
            name_leaf(p);
        } else if at_bare_boolean(p) {
            p.err_and_bump("expected `(` after the name");
        } else if at_call(p) {
            expr::name_or_call(p);
        } else if kind == K::MACRO_TOKEN.raw() || !field_name(p) {
            if kind != K::MACRO_TOKEN.raw() {
                item.abandon(p);
                break;
            }
            // A macro stands for a field in a list, not in a rename.
            item.abandon(p);
            break;
        }
        p.eat(K::COMMA.raw());
        if kw(p, "as") {
            p.bump_as(K::AS_KW.raw());
            if !field_name(p) || p.current() == K::MACRO_TOKEN.raw() {
                p.error("expected a new name after `as`");
            }
        } else {
            p.error("expected `as`");
        }
        item.complete(p, K::RENAME_ITEM.raw());
        any = true;
    }
    if !any {
        p.error("expected a field to rename");
    }
}

const DEDUP_OPTIONS: [(&str, K); 3] = [
    ("keepevents", K::KEEPEVENTS_KW),
    ("keepempty", K::KEEPEMPTY_KW),
    ("consecutive", K::CONSECUTIVE_KW),
];

/// `keepevents`, `keepempty` and `consecutive` are keywords of `dedup`.
fn at_dedup_option(p: &Parser<'_>) -> bool {
    p.current() == K::IDENT.raw() && DEDUP_OPTIONS.iter().any(|(n, _)| *n == p.current_text())
}

fn dedup_option(p: &mut Parser<'_>) {
    let m = p.start();
    let keyword = DEDUP_OPTIONS
        .iter()
        .find(|(n, _)| *n == p.current_text())
        .map_or(K::KEEPEVENTS_KW, |(_, k)| *k);
    p.bump_as(keyword.raw());
    if p.eat(K::EQ.raw()) {
        // `choice($.boolean, $.identifier)` in grammar.js: a name, not a
        // number or a field word (`keepevents=1` is an error there).
        if p.current() == K::IDENT.raw() {
            expr::name_or_call(p);
        } else {
            p.error("expected a value");
        }
    } else {
        p.error("expected `=`");
    }
    m.complete(p, K::DEDUP_OPTION.raw());
}

/// `dedup [n] options fields options [sortby keys]`.
fn dedup(p: &mut Parser<'_>) {
    number(p);
    while at_dedup_option(p) {
        dedup_option(p);
    }
    let mut any = false;
    loop {
        // One comma at most between fields, none leading or trailing.
        let comma = any && p.eat(K::COMMA.raw());
        if at_stage_end(p) || at_word(p, "sortby") || at_dedup_option(p) {
            if comma {
                p.error("expected a field after the comma");
            }
            break;
        }
        if !field_name(p) {
            if comma {
                p.error("expected a field after the comma");
            }
            break;
        }
        any = true;
    }
    if !any {
        p.error("expected a field");
    }
    while at_dedup_option(p) {
        dedup_option(p);
    }
    if at_word(p, "sortby") {
        p.bump_as(K::SORTBY_KW.raw());
        let mut keys = false;
        loop {
            let comma = keys && p.eat(K::COMMA.raw());
            if !sort_item(p) {
                if comma {
                    p.error("expected a sort key after the comma");
                }
                break;
            }
            keys = true;
        }
        if !keys {
            p.error("expected a sort key");
        }
    }
}

/// The case-sensitive word `word`.
fn at_word(p: &Parser<'_>, word: &str) -> bool {
    p.current() == K::IDENT.raw() && p.current_text() == word
}

/// `+x`, `-x`, `x`, `num(x)`; a sign wants its key.
fn sort_item(p: &mut Parser<'_>) -> bool {
    let m = p.start();
    let signed = p.current() == K::PLUS.raw() || p.current() == K::MINUS.raw();
    if signed {
        p.bump();
    }
    if at_bare_boolean(p) {
        p.err_and_bump("expected `(` after the name");
    } else if at_call(p) {
        expr::name_or_call(p);
    } else if at_field(p) {
        name_leaf(p);
    } else if signed {
        p.error("expected a field after the sign");
    } else {
        m.abandon(p);
        return false;
    }
    m.complete(p, K::SORT_ITEM.raw());
    true
}

/// `sort [n] options keys options [desc]`: the options come before or after
/// the keys, not among them.
fn sort(p: &mut Parser<'_>) {
    number(p);
    while at_option(p) {
        command_option(p);
    }
    let mut keys = 0;
    loop {
        // One comma at most between keys, none leading or trailing.
        let comma = keys > 0 && p.eat(K::COMMA.raw());
        if at_stage_end(p)
            || at_option(p)
            // After a key, `desc` and `d` are the order, not more keys.
            || (keys > 0 && (kw(p, "desc") || kw(p, "d")))
            || !sort_item(p)
        {
            if comma {
                p.error("expected a sort key after the comma");
            }
            break;
        }
        keys += 1;
    }
    if keys == 0 {
        p.error("expected a sort key");
    }
    while at_option(p) {
        command_option(p);
    }
    if kw(p, "desc") {
        p.bump_as(K::DESC_KW.raw());
    } else if kw(p, "d") {
        p.bump_as(K::D_KW.raw());
    }
}

/// `rex [options] "pattern" [options]`.
fn rex(p: &mut Parser<'_>) {
    let mut pattern = false;
    loop {
        // Options may be comma-separated before the pattern, not after it.
        if !pattern && p.eat(K::COMMA.raw()) {
            continue;
        }
        if at_option(p) && p.current_text() == "field" {
            // `field=` names a field: a name or a quoted name.
            let m = p.start();
            name_leaf(p);
            p.bump();
            if super::stats::at_name(p) {
                name_leaf(p);
            } else if p.current() == K::STRING_TOKEN.raw() {
                leaf(p, K::STR, K::STRING_TOKEN);
            } else {
                p.error("expected a field name");
            }
            m.complete(p, K::COMMAND_OPTION.raw());
        } else if at_option(p) {
            command_option(p);
        } else if !pattern && p.current() == K::STRING_TOKEN.raw() {
            leaf(p, K::STR, K::STRING_TOKEN);
            pattern = true;
        } else {
            break;
        }
    }
    if !pattern {
        p.error("expected a regular expression");
    }
}

/// `fillnull [value=x] [fields]`: everything optional.
fn fillnull(p: &mut Parser<'_>) {
    loop {
        if at_option(p) {
            command_option(p);
        } else if p.eat(K::COMMA.raw()) {
        } else if at_stage_end(p) || !field_name(p) {
            break;
        }
    }
}

/// `mvexpand [options] field [options]`, `mvexpand(field)`.
fn mvexpand(p: &mut Parser<'_>) {
    while at_option(p) {
        command_option(p);
    }
    if p.current() == K::L_PAREN.raw() {
        p.bump();
        if at_field(p) {
            name_leaf(p);
        } else {
            p.error("expected a field");
        }
        if !p.eat(K::R_PAREN.raw()) {
            p.error("missing `)`");
        }
    } else if at_field(p) {
        name_leaf(p);
    } else {
        p.error("expected a field");
    }
    while at_option(p) {
        command_option(p);
    }
}

/// `makemv [delim="x"] [options] field`; `delim` is a keyword.
fn makemv(p: &mut Parser<'_>) {
    loop {
        if at_word(p, "delim") {
            p.bump_as(K::DELIM_KW.raw());
            if p.eat(K::EQ.raw()) {
                if p.current() == K::STRING_TOKEN.raw() {
                    leaf(p, K::STR, K::STRING_TOKEN);
                } else {
                    p.error("expected a string");
                }
            } else {
                p.error("expected `=`");
            }
        } else if at_option(p) {
            command_option(p);
        } else {
            break;
        }
    }
    if at_field(p) {
        name_leaf(p);
    } else {
        p.error("expected a field");
    }
}

#[cfg(test)]
mod tests {
    use super::super::parser::tests::render;

    #[test]
    fn field_lists_take_commas_anywhere() {
        assert!(render("| table a, , b*, \"c\" `m`,").ends_with("--\n"));
        assert!(render("| table").contains("expected a field"));
        assert!(render("| fields - a, b").ends_with("--\n"));
        assert!(render("| fields").ends_with("--\n"));
    }

    #[test]
    fn rename_dedup_sort_and_the_small_ones() {
        assert!(render("| rename a as b, DNS.* as *").ends_with("--\n"));
        assert!(render("| rename a").contains("expected `as`"));
        assert!(render("| dedup 2 keepempty=true a b sortby -c").ends_with("--\n"));
        // An option's value is a name or a boolean, as in grammar.js.
        assert!(render("| dedup keepevents=x a").ends_with("--\n"));
        assert!(render("| dedup keepevents=1 a").contains("expected a value"));
        assert!(render("| dedup keepevents=a-b a").contains("expected a value"));
        assert!(render("| sort 0 -a, +b num(c) desc").ends_with("--\n"));
        assert!(render("| sort limit=0 a d").ends_with("--\n"));
        assert!(render("| head 5 keeplast=t").ends_with("--\n"));
        assert!(render("| rex field=_raw max_match=0 \"(?<x>.)\"").ends_with("--\n"));
        assert!(render("| rex field=_raw").contains("expected a regular expression"));
        assert!(render("| fillnull value=0 a b").ends_with("--\n"));
        assert!(render("| mvexpand(x)").ends_with("--\n"));
        assert!(render("| makemv delim=\",\" x").ends_with("--\n"));
    }
}
