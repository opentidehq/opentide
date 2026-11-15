//! The rest of the commands: `join`, `lookup`, `inputlookup`, `outputlookup`,
//! `foreach`, `spath`, `tojson`, the commands the catalog knows and the grammar
//! has no rule for, and the commands it does not know at all (an unknown
//! command is a diagnostic of the analysis, never a syntax error). Their
//! arguments are permissive on purpose: a known command must never be a
//! syntax error because its arguments are not modelled; command-specific
//! checks belong to the analysis (`command-options.toml`).

use super::expr;
use super::kind::SyntaxKind as K;
use super::parser::leaf;
use super::search;
use super::stats::{
    at_call, at_field, at_option, at_stage_end, command_option, commas, kw, name_leaf, option_value,
};
use opentide_parse::Parser;

/// Whether `word` has a rule of its own in this module.
pub(super) fn is_rest_command(word: &str) -> bool {
    matches!(
        word,
        "join" | "lookup" | "inputlookup" | "outputlookup" | "foreach" | "spath" | "tojson"
    )
}

/// A name, quoted name or macro (a lookup table).
fn table_name(p: &mut Parser<'_>) -> bool {
    let kind = p.current();
    if at_field(p) {
        name_leaf(p);
    } else if kind == K::STRING_TOKEN.raw() {
        leaf(p, K::STR, K::STRING_TOKEN);
    } else if kind == K::MACRO_TOKEN.raw() {
        search::macro_call(p);
    } else {
        return false;
    }
    true
}

/// A field list entry: a name, wildcard, quoted name or macro.
fn field_entry(p: &mut Parser<'_>) -> bool {
    if p.current() == K::GLOB_TOKEN.raw() {
        leaf(p, K::GLOB, K::GLOB_TOKEN);
        true
    } else {
        table_name(p)
    }
}

fn options(p: &mut Parser<'_>) {
    while at_option(p) {
        command_option(p);
    }
}

/// `join [options and fields] [ subsearch ]`.
fn join(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::JOIN_KW.raw());
    loop {
        if at_option(p) {
            command_option(p);
        } else if p.eat(K::COMMA.raw()) {
        } else if at_field(p) {
            name_leaf(p);
        } else {
            break;
        }
    }
    if p.current() == K::L_BRACKET.raw() {
        search::subsearch(p);
    } else {
        p.error("expected a subsearch");
    }
    m.complete(p, K::JOIN_COMMAND.raw());
}

/// `lookup [options] table field [as alias], ... [output|outputnew fields]`:
/// no argument at all keeps every row.
fn lookup(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::LOOKUP_KW.raw());
    if !at_stage_end(p) {
        options(p);
        if !table_name(p) {
            p.error("expected a lookup table");
        }
        if !lookup_fields(p) {
            p.error("expected a lookup field");
        }
        if kw(p, "output") || kw(p, "outputnew") {
            let word = if kw(p, "output") {
                K::OUTPUT_KW
            } else {
                K::OUTPUTNEW_KW
            };
            p.bump_as(word.raw());
            lookup_fields(p);
        }
    }
    m.complete(p, K::LOOKUP_COMMAND.raw());
}

/// `a as b, c`: lookup fields with commas anywhere; stops at `output`.
fn lookup_fields(p: &mut Parser<'_>) -> bool {
    let mut any = false;
    loop {
        commas(p);
        if at_stage_end(p) || kw(p, "output") || kw(p, "outputnew") {
            break;
        }
        let kind = p.current();
        if !(at_field(p) || kind == K::STRING_TOKEN.raw()) {
            break;
        }
        let item = p.start();
        if at_field(p) {
            name_leaf(p);
        } else {
            leaf(p, K::STR, K::STRING_TOKEN);
        }
        if kw(p, "as") {
            let alias = p.start();
            p.bump_as(K::AS_KW.raw());
            if at_field(p) {
                name_leaf(p);
            } else if p.current() == K::STRING_TOKEN.raw() {
                leaf(p, K::STR, K::STRING_TOKEN);
            } else {
                p.error("expected a name after `as`");
            }
            alias.complete(p, K::LOOKUP_ALIAS.raw());
        }
        item.complete(p, K::LOOKUP_FIELD.raw());
        any = true;
    }
    any
}

/// `inputlookup [options] table [options|subsearch]* [where terms]`. With
/// no table it is accepted only as the first stage of a search, and only
/// when nothing follows it in the stage.
fn inputlookup(p: &mut Parser<'_>, first: bool) {
    let m = p.start();
    p.bump_as(K::INPUTLOOKUP_KW.raw());
    options(p);
    if !table_name(p) && (!first || !at_stage_end(p)) {
        p.error("expected a lookup table");
    }
    loop {
        if at_option(p) {
            command_option(p);
        } else if p.current() == K::L_BRACKET.raw() {
            search::subsearch(p);
        } else {
            break;
        }
    }
    if kw(p, "where") {
        p.bump_as(K::WHERE_KW.raw());
        search::search_expression_before_by(p);
    }
    m.complete(p, K::INPUTLOOKUP_COMMAND.raw());
}

/// `outputlookup [options] table [options]`.
fn outputlookup(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::OUTPUTLOOKUP_KW.raw());
    options(p);
    if !table_name(p) {
        p.error("expected a lookup table");
    }
    options(p);
    m.complete(p, K::OUTPUTLOOKUP_COMMAND.raw());
}

/// `foreach fields [options] [ body ]`.
fn foreach(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::FOREACH_KW.raw());
    let mut any = false;
    loop {
        if at_option(p) {
            command_option(p);
        } else if p.eat(K::COMMA.raw()) || field_entry(p) {
        } else {
            break;
        }
        any = true;
    }
    if !any {
        p.error("expected a field");
    }
    if p.current() == K::L_BRACKET.raw() {
        search::subsearch(p);
    } else {
        p.error("expected a subsearch");
    }
    m.complete(p, K::FOREACH_COMMAND.raw());
}

/// `spath [options, paths, macros, subsearches]`.
fn spath(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::SPATH_KW.raw());
    loop {
        if at_option(p) {
            command_option(p);
        } else if p.current() == K::L_BRACKET.raw() {
            search::subsearch(p);
        } else if !table_name(p) {
            break;
        }
    }
    m.complete(p, K::SPATH_COMMAND.raw());
}

/// `tojson [options, fields, calls]`.
fn tojson(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::TOJSON_KW.raw());
    loop {
        if at_option(p) {
            command_option(p);
        } else if p.eat(K::COMMA.raw()) {
        } else if at_call(p) {
            expr::name_or_call(p);
        } else if !field_entry(p) {
            break;
        }
    }
    m.complete(p, K::TOJSON_COMMAND.raw());
}

/// The commands with a rule of their own here.
pub(super) fn command(p: &mut Parser<'_>, first: bool) {
    match p.current_text() {
        "join" => join(p),
        "lookup" => lookup(p),
        "inputlookup" => inputlookup(p, first),
        "outputlookup" => outputlookup(p),
        "foreach" => foreach(p),
        "spath" => spath(p),
        _ => tojson(p),
    }
}

/// Whether the current token starts an argument of a command with no rule.
fn at_argument(p: &Parser<'_>) -> bool {
    let kind = p.current();
    [
        K::IDENT,
        K::FIELD_WORD,
        K::NUMBER_TOKEN,
        K::STRING_TOKEN,
        K::GLOB_TOKEN,
        K::SEARCH_WORD_TOKEN,
        K::CALL_WORD,
        K::MACRO_TOKEN,
        K::L_BRACKET,
        K::COMMA,
    ]
    .iter()
    .any(|k| k.raw() == kind)
}

fn at_comparison(p: &Parser<'_>) -> bool {
    at_field(p)
        && [K::NE, K::LT, K::GT, K::LE, K::GE]
            .iter()
            .any(|k| k.raw() == p.nth(1))
}

/// The arguments of a command with no rule: any run of the loose forms, as
/// one node. `false` when there are none.
fn argument_list(p: &mut Parser<'_>) -> bool {
    if !at_argument(p) {
        return false;
    }
    let m = p.start();
    while at_argument(p) {
        let kind = p.current();
        if kind == K::L_BRACKET.raw() {
            search::subsearch(p);
        } else if kind == K::MACRO_TOKEN.raw() {
            search::macro_call(p);
        } else if kind == K::COMMA.raw() {
            p.bump();
        } else if at_option(p) {
            command_option(p);
        } else if at_comparison(p) {
            comparison(p);
        } else if at_call(p) {
            expr::name_or_call(p);
        } else if kind == K::STRING_TOKEN.raw() {
            leaf(p, K::STR, K::STRING_TOKEN);
        } else if kind == K::GLOB_TOKEN.raw() {
            leaf(p, K::GLOB, K::GLOB_TOKEN);
        } else if kind == K::NUMBER_TOKEN.raw() {
            leaf(p, K::NUMBER, K::NUMBER_TOKEN);
        } else if kind == K::IDENT.raw() && matches!(p.current_text(), "AND" | "OR" | "NOT") {
            let word = match p.current_text() {
                "AND" => K::AND_KW,
                "OR" => K::OR_KW,
                _ => K::NOT_KW,
            };
            leaf(p, K::SEARCH_BOOLEAN, word);
        } else if kind == K::IDENT.raw() || kind == K::FIELD_WORD.raw() {
            name_leaf(p);
        } else {
            let token = if kind == K::CALL_WORD.raw() {
                K::CALL_WORD
            } else {
                K::SEARCH_WORD_TOKEN
            };
            leaf(p, K::SEARCH_WORD, token);
        }
    }
    m.complete(p, K::ARGUMENT_LIST.raw());
    true
}

fn comparison(p: &mut Parser<'_>) {
    let m = p.start();
    name_leaf(p);
    p.bump();
    if !option_value(p) {
        p.error("missing the value of the comparison");
    }
    m.complete(p, K::COMPARISON.raw());
}

/// A command the catalog knows, or none it knows: the name and loose
/// arguments. The commands that need arguments say so when there are none.
pub(super) fn catalog_or_unknown(p: &mut Parser<'_>) {
    let name = p.current_text();
    let known = CATALOG.contains(&name);
    let needs_arguments = CATALOG_WITH_ARGUMENTS.contains(&name);
    let m = p.start();
    if known || needs_arguments {
        let n = p.start();
        p.bump_as(K::CATALOG_COMMAND_WORD.raw());
        n.complete(p, K::CATALOG_COMMAND_NAME.raw());
    } else {
        name_leaf(p);
    }
    if !argument_list(p) && needs_arguments {
        p.error("this command needs arguments");
    }
    // What no argument takes (`| a=b`: a name, then `=`) is left to the
    // pipeline, which reports it once and skips to the next pipe.
    let node = if known || needs_arguments {
        K::CATALOG_COMMAND
    } else {
        K::UNKNOWN_COMMAND
    };
    m.complete(p, node.raw());
}

const CATALOG: [&str; 71] = [
    "makeresults",
    "datamodel",
    "loadjob",
    "metasearch",
    "mpreview",
    "pivot",
    "eventcount",
    "dbinspect",
    "walklex",
    "searchtxn",
    "addtotals",
    "anomalydetection",
    "filldown",
    "convert",
    "reltime",
    "addinfo",
    "xmlkv",
    "extract",
    "kv",
    "erex",
    "kvform",
    "multikv",
    "untable",
    "tags",
    "xpath",
    "xmlunescape",
    "format",
    "union",
    "reverse",
    "cluster",
    "outlier",
    "fieldsummary",
    "transpose",
    "uniq",
    "localop",
    "noop",
    "redistribute",
    "require",
    "collect",
    "delete",
    "sendemail",
    "outputcsv",
    "kmeans",
    "highlight",
    "history",
    "geom",
    "makecontinuous",
    "localize",
    "scrub",
    "abstract",
    "addcoltotals",
    "anomalies",
    "anomalousvalue",
    "associate",
    "bucketdir",
    "correlate",
    "diff",
    "findtypes",
    "folderize",
    "geomfilter",
    "iconify",
    "meventcollect",
    "msearch",
    "outputtext",
    "overlap",
    "predict",
    "rtorder",
    "sendalert",
    "tscollect",
    "typelearner",
    "typer",
];

const CATALOG_WITH_ARGUMENTS: [&str; 47] = [
    "metadata",
    "from",
    "rest",
    "inputcsv",
    "gentimes",
    "mstats",
    "savedsearch",
    "multisearch",
    "set",
    "top",
    "rare",
    "transaction",
    "xyseries",
    "contingency",
    "mvcombine",
    "sitop",
    "sirare",
    "timewrap",
    "regex",
    "replace",
    "setfields",
    "fieldformat",
    "nomv",
    "strcat",
    "bin",
    "bucket",
    "rangemap",
    "iplocation",
    "fromjson",
    "append",
    "appendcols",
    "appendpipe",
    "selfjoin",
    "return",
    "map",
    "concurrency",
    "script",
    "mcollect",
    "accum",
    "analyzefields",
    "arules",
    "autoregress",
    "cofilter",
    "delta",
    "gauge",
    "trendline",
    "typeahead",
];
