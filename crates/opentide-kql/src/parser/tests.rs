//! Tree snapshots of the productions, error recovery and depth. The corpus
//! tests are in `tests/parser_corpus.rs`.

use super::parse;
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_parse::{ErrorKind, debug_errors, debug_tree};

/// The tree and the errors of `source`, as the snapshots show them.
fn show(source: &str) -> String {
    let parsed = parse(source);
    let tree = SyntaxNode::new_root(parsed.green);
    assert_eq!(tree.to_string(), source, "the tree is lossless");
    let mut out = debug_tree(&tree, |k| format!("{k:?}"));
    let errors = debug_errors(&parsed.errors, |k| K::from_raw(k).describe());
    if !errors.is_empty() {
        out.push_str("errors:\n");
        out.push_str(&errors);
    }
    out
}

fn errors(source: &str) -> Vec<String> {
    parse(source)
        .errors
        .into_iter()
        .map(|e| e.message)
        .collect()
}

macro_rules! snapshots {
    ($($name:ident: $source:expr;)*) => {$(
        #[test]
        fn $name() {
            insta::assert_snapshot!(show($source));
        }
    )*};
}

snapshots! {
    let_scalar: "let x = 1;\nlet y = a + 1;\nT";
    let_table_and_call: "let x = T;\nlet y = f(1);\nlet z = (T | take 1);\nT";
    let_function: "let f = (a: int, t: (*), u: (c: string, d: dynamic) = 1) { let y = 2; T | take 5 };\nf(1, 2)";
    control_command: ".show tables details";
    precedence: "T | where a or b and not c has \"x\" or d == 1 + 2 * 3 - 4";
    flat_chain: "T | where a or b or c or d";
    sign_and_literals: "T | where x == -1 and y == 5m and z == datetime(2024-01-01) and w == null and v == True";
    member_and_index: "T | where a.b[0].c == d[\"k\"] and e.[\"x.y\"] == f['q']['r']";
    calls: "T | where f(a, b = 1, *) and g() and count() > 0 and not(a == b)";
    sets_and_ranges: "T | where a in (1, 2) and b !in~ (\"x\") and c between (1 .. 3) and d matches regex \"x\" and e in (T2 | project x)";
    dynamic_and_toscalar: "T | where a == dynamic([1, -2, \"x\", {\"k\": [true, null],}]) and b == toscalar(U | count) and c == dynamic(null)";
    keywords_are_names: "T | where by == on and has != count and kind has_any (1)";
    unknown_operator: "T | frobnicate a";
    quoted_names: "let n = 1;\nT | where ['a b'] == n";
}

snapshots! {
    error_missing_operand: "T | where a ==";
    error_missing_semicolon: "let x = 1\nT";
    error_unclosed_paren: "T | where (a";
    error_not_not: "T | where not not a";
    error_double_sign: "T | where --a";
    error_comparison_chain: "T | where a == b == c";
    error_trailing_input: "T | take 5 )";
    error_empty_call_argument: "T | where f(a,)";
    error_unclosed_function: "let f = () { T ;\nf()";
}

snapshots! {
    op_project_family: "T | project a, b = 1, (c, d) = f() | project-away Foo*, *Bar, ['x y'], * | project-keep a* | project-reorder a desc, *, b granny-asc | project-rename n = o | extend e = 1, f(x)";
    op_summarize: "T | summarize hint.strategy = shuffle count(), c = dcount(a) by bin(t, 1h), k = b | summarize by x | summarize count()";
    op_join_lookup: "T | join kind = inner (U | project a) on $left.a == $right.a, b | join U on a | lookup kind=leftouter V on k";
    op_union_parse: "T | union withsource = S A, (B | take 1), f(\"a\") | parse Msg with \"id=\" id:long * \"x\" rest | parse-where Msg with * \"a\" b | parse-kv Msg";
    op_take_top_sort: "T | take 5 | limit 3 | top 5 by a desc nulls last, b | count | sort by a asc nulls first, b | order a";
    op_mv: "T | mv-expand kind = array a, b = c to typeof(int) limit 10 | mvexpand x | mv-apply e = a on (where e > 1 | take 2)";
    op_make_series: "T | make-series c = count() default = 0 on t from ago(1d) to now() step 1h by k | make-series s = sum(v) on t in range(a, b, 1h)";
    op_evaluate_distinct_render: "T | evaluate hint.distribution = single bag_unpack(x) | distinct a, b = c | distinct * | render timechart";
    op_range_and_sources: "let r = range(1, 5, 1);\nrange x from 1 to 3 step 1 | extend y = x";
    op_print_and_datatable: "let d = datatable (a: string, b: int) [\"x\", 1, ];\nprint a = 1, 2 | union d";
    op_externaldata: "externaldata (c: string, d: dynamic,) [@\"https://e/x.csv\", \"b\"] with (format = \"csv\") | take 1";
    op_search_source: "search kind = case_sensitive \"x\" | search \"y\" | take 1";
    op_search_in: "search in (A, B) where c == 1";
    op_find_in: "find in (T) where a == 1 | take 1";
    op_top_nested_sample: "T | top-nested 3 of x with others = \"o\" by count() desc, top-nested of y by sum(z) asc nulls last | sample-distinct 10 of a";
    op_fork_facet_partition: "T | fork a = (where x > 1 | take 5) (count) | facet by a, b with (where x > 1 | take 5) | facet by c with take 5 | partition hint.strategy = native by k (top 1 by t) | partition by k in dynamic([1]) { U | take 1 }";
    op_scan: "T | scan order by t partition by k declare (n: long = 0) with (step s output = last: x == 1 => n = s.n + 1; step t optional: y == 2;)";
    op_keyword_operators: "T | getschema | invoke f() | as R | serialize | sample 10 | consume";
    op_hyphen_names_in_expressions: "T | extend d = a - parse - b";
    op_parenthesised_pipelines: "let x = materialize(T | take 1);\nlet y = (U | take 2);\n(x | take 1) | union y, (print 1)";
}

snapshots! {
    error_pipe_without_operator: "T | | take 1";
    error_trailing_pipe: "T |";
    error_join_without_on: "T | join U a";
    error_unclosed_subquery: "T | mv-apply e = a on (take 1";
    error_unclosed_fork: "T | fork (take 1";
    error_missing_top_count: "T | top by a";
    error_parse_without_pattern: "T | parse Msg with";
    error_scan_without_step: "T | scan with ()";
    error_make_series_without_step: "T | make-series c = count() on t";
}

#[test]
fn a_column_pattern_is_the_touching_tokens_only() {
    // `a *` is a name and a star (an error after project-away: a second item needs a comma).
    assert!(errors("T | project-away Foo*, *Bar, *").is_empty());
    assert!(!errors("T | project-away a *").is_empty());
    let tree = SyntaxNode::new_root(parse("T | project-away User*Id1").green);
    let patterns = tree
        .descendants()
        .filter(|n| n.kind() == K::COLUMN_PATTERN)
        .count();
    assert_eq!(patterns, 1);
}

#[test]
fn deep_pipelines_stop_at_the_limit_with_one_error() {
    let nested = format!("{}T | take 1{}", "(".repeat(5_000), ")".repeat(5_000));
    let deep = parse(&nested);
    assert_eq!(deep.errors.len(), 1, "{:?}", deep.errors);
    let forks = format!("T | {}take 1{}", "fork (".repeat(5_000), ")".repeat(5_000));
    assert_eq!(parse(&forks).errors.len(), 1);
}

#[test]
fn a_long_pipeline_is_not_deep() {
    let source = format!("T{}", " | take 1".repeat(20_000));
    let parsed = parse(&source);
    assert!(parsed.errors.is_empty());
    assert!(parsed.depth < 20, "{} levels", parsed.depth);
}

/// Found by the differential: a lone name, call or group in a list is a
/// table, as tree-sitter read it; a member, index or literal is a value.
#[test]
fn a_lone_name_in_a_list_is_a_table() {
    let tabular = |source: &str| {
        let tree = SyntaxNode::new_root(parse(source).green);
        tree.descendants()
            .find(|n| n.kind() == K::EXPRESSION_LIST)
            .is_some_and(|list| list.children().any(|c| c.kind() == K::TABULAR_EXPRESSION))
    };
    for source in [
        "T | where a in (b)",
        "T | where a in (f(1))",
        "T | where a in ((b))",
    ] {
        assert!(tabular(source), "{source}");
    }
    for source in [
        "T | where a in (b.c)",
        "T | where a in (b[0])",
        "T | where a in (1)",
    ] {
        assert!(!tabular(source), "{source}");
    }
}

/// Found by the differential: a source keyword with nothing after it, and a
/// hint that is not an option, are errors (tree-sitter took the keyword and
/// the `hint.` token whatever followed).
#[test]
fn a_bare_source_keyword_is_an_error() {
    for source in [
        "range",
        "range ",
        "datatable",
        "materialize",
        "T | summarize hint.shuffle",
    ] {
        assert!(!errors(source).is_empty(), "{source}");
    }
}

#[test]
fn an_empty_source_and_a_comment_are_valid() {
    assert!(errors("").is_empty());
    assert!(errors("// nothing\n").is_empty());
}

#[test]
fn a_long_chain_is_flat_and_parses() {
    let source = format!("T | where {}", vec!["a == 1"; 20_000].join(" or "));
    let parsed = parse(&source);
    assert!(parsed.errors.is_empty());
    assert!(parsed.depth < 20, "{} levels", parsed.depth);
}

#[test]
fn nesting_up_to_the_limit_parses_and_past_it_is_one_error() {
    let nest = |n: usize| format!("T | where {}a == 1{}", "(".repeat(n), ")".repeat(n));
    assert!(parse(&nest(200)).errors.is_empty());
    let deep = parse(&nest(5_000));
    assert_eq!(deep.errors.len(), 1, "{:?}", deep.errors);
    assert!(matches!(deep.errors[0].kind, ErrorKind::TooDeep { .. }));
}

#[test]
fn a_long_member_chain_does_not_overflow() {
    let source = format!("T | where {}", vec!["a"; 10_000].join("."));
    let _ = parse(&source);
}

/// Runs `run` on a 1 MB stack, as the browser's WASM module has: a recursion
/// the nesting guard misses aborts the test process.
fn on_small_stack<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(run)
        .expect("spawn")
        .join()
        .expect("the parser panicked")
}

/// Found by review (#1314): function definitions nest through `let` without
/// the nesting guard; 15,000 of them aborted on a 1 MB stack, and 2,000 gave
/// 6,000 errors. Now: one `TooDeep`.
#[test]
fn nested_function_definitions_stop_at_the_limit() {
    let errors = on_small_stack(|| {
        let source = "let f = () { ".repeat(15_000);
        parse(&source).errors
    });
    assert_eq!(errors.len(), 1, "{:?}", &errors[..errors.len().min(3)]);
    assert!(matches!(errors[0].kind, ErrorKind::TooDeep { .. }));
}

/// Found by review (#1361): deciding whether `((...(T)...))` is a table read
/// the group once per level and recursed once per level, so 3,000 balanced
/// levels in a `let` or an `in` list burnt the fuel (a `Stalled` panic in a
/// debug build) instead of reaching the nesting limit. One scan now: one
/// `TooDeep`, on a 1 MB stack.
#[test]
fn a_deep_balanced_group_is_one_nesting_error() {
    for n in [3_000, 50_000] {
        for source in [
            format!("let x = {}T{};\nx", "(".repeat(n), ")".repeat(n)),
            format!("T | where a in {}b{}", "(".repeat(n), ")".repeat(n)),
        ] {
            let errors = on_small_stack(move || parse(&source).errors);
            assert_eq!(errors.len(), 1, "{n}: {:?}", &errors[..errors.len().min(3)]);
            assert!(matches!(errors[0].kind, ErrorKind::TooDeep { .. }), "{n}");
        }
    }
    // Read through, level by level, as before.
    let tabular = |source: &str| {
        let tree = SyntaxNode::new_root(parse(source).green);
        tree.descendants()
            .find(|n| n.kind() == K::EXPRESSION_LIST)
            .is_some_and(|list| list.children().any(|c| c.kind() == K::TABULAR_EXPRESSION))
    };
    for (source, is_tabular) in [
        ("T | where a in (((b)))", true),
        ("T | where a in (((b) | take 1))", true),
        ("T | where a in (((b), c))", false),
        ("T | where a in (((b) + 1))", false),
        ("T | where a in ((((f(1)))))", true),
        ("T | where a in (((1)))", false),
    ] {
        assert_eq!(tabular(source), is_tabular, "{source}");
    }
}

/// Found by review (#1314): a long run of unexpected tokens is one error, not
/// one per token (`-` x200,000 then `a` gave 100,000).
#[test]
fn a_run_of_unexpected_tokens_is_one_error() {
    for source in [
        format!("{}a", "-".repeat(200_000)),
        format!("T | where {}a", "-".repeat(200_000)),
        format!("T | where a == {}", "+".repeat(200_000)),
        format!("T | project {}", ",".repeat(200_000)),
        format!("T {}", ")".repeat(200_000)),
    ] {
        let errors = on_small_stack(move || parse(&source).errors.len());
        assert!(errors <= 3, "{errors} errors");
    }
}

/// Found by the differential at four times its scale: `search in` and an
/// mv-expand option name without `=` are errors, as tree-sitter read them.
#[test]
fn keywords_that_start_a_clause_need_the_clause() {
    for source in [
        "search in ",
        "search in x",
        "T | mv-expand bagexpansion ",
        "T | mv-expand kind",
    ] {
        assert!(!errors(source).is_empty(), "{source}");
    }
    for source in [
        "search in (T) x",
        "T | mv-expand kind = array x",
        "T | mv-expand x",
    ] {
        assert!(errors(source).is_empty(), "{source}");
    }
}

/// Found by the differential at four times its scale: a keyword used as a
/// column and indexed (`step ['x']`) is an index, as tree-sitter read it; the
/// lexer reads `['x']` as a quoted name, so the parser has it lexed again.
#[test]
fn a_quoted_name_after_an_expression_is_an_index() {
    for source in [
        "T | where step ['ResultType'] == \"0\"",
        "T | where by ['a'] == 1 and on [\"b\"] == 2",
    ] {
        assert!(errors(source).is_empty(), "{source}: {:?}", errors(source));
        let tree = SyntaxNode::new_root(parse(source).green);
        assert!(
            tree.descendants().any(|n| n.kind() == K::INDEX_EXPR),
            "{source}"
        );
    }
    // A quoted name where a name is wanted stays one.
    let tree = SyntaxNode::new_root(parse("T | project ['a b'], c").green);
    assert!(tree.descendants().all(|n| n.kind() != K::INDEX_EXPR));
}

/// Found by the differential: `with` starts an operator only in `facet`;
/// elsewhere it is a name, and `project-reorder` after it a subtraction.
#[test]
fn a_hyphen_keyword_after_with_is_an_operator_only_in_facet() {
    assert!(errors("SigninLogs | with project-reorder * asc").is_empty());
    assert!(errors("T | facet by a with project-away b").is_empty());
}

/// Found by the switch's full differential (seed 2, scale 2): after the `(`
/// of a call or a parenthesised expression, a hyphen keyword is a
/// subtraction of names, as tree-sitter read it; the lexer takes it for an
/// operator after any `(`, so the parser has it lexed again.
#[test]
fn a_hyphen_keyword_that_starts_an_expression_is_a_subtraction() {
    for source in [
        "SecurityEvent | summarize count(project-away ) by bin(TimeGenerated, 1h), Computer",
        "T | extend z = strlen(mv-expand)",
        "T | extend a = (project-away)",
        "T | extend a = f(b, parse-where)",
    ] {
        assert!(errors(source).is_empty(), "{source}: {:?}", errors(source));
        let tree = SyntaxNode::new_root(parse(source).green);
        assert!(
            tree.descendants().any(|n| n.kind() == K::ADDITIVE_EXPR),
            "{source}"
        );
    }
    // Where a sub-pipeline starts, it is still an operator.
    for source in [
        "T | fork (project-away y) (take 1)",
        "T | mv-apply x on (project-away y)",
        "T | partition by x (project-away y)",
    ] {
        assert!(errors(source).is_empty(), "{source}: {:?}", errors(source));
        let tree = SyntaxNode::new_root(parse(source).green);
        assert!(
            tree.descendants()
                .any(|n| n.kind() == K::PROJECT_AWAY_OPERATOR),
            "{source}"
        );
    }
}

/// Found by the switch's full differential (seed 3): in an expression or as
/// the name an assignment makes, and as a `let` value, `dynamic` and
/// `toscalar` are no column or table, as the old grammar read them
/// (`split(a, "b", dynamic -1)` is broken); they still open their literal
/// and call, and `dynamic` is still a table name elsewhere.
#[test]
fn dynamic_and_toscalar_are_not_columns() {
    for source in [
        "T | where dynamic == 1",
        "T | where toscalar == 1",
        "T | project dynamic",
        "T | extend dynamic = 1",
        "T | extend x = split(a, \"b\", dynamic -1)[-1]",
        "let t = (\ndynamic\n| where a == 1);\nt",
        "let t = dynamic;\nt",
        "let t = toscalar;\nt",
    ] {
        assert!(!errors(source).is_empty(), "{source}");
    }
    for source in [
        "dynamic",
        "(dynamic | take 1)",
        "T | join (dynamic | take 1) on a",
        "let t = dynamic([1]);\nprint t",
        "T | extend x = dynamic([1]), y = toscalar(T | count)",
        "datatable(a: dynamic) [dynamic(1)]",
    ] {
        assert!(errors(source).is_empty(), "{source}: {:?}", errors(source));
    }
}

/// Class (b), an old-engine false error kept fixed (#1230): Kusto's
/// multi-line string literals, ```` ```…``` ```` and `~~~…~~~`, are string
/// literals wherever a string is
/// (<https://learn.microsoft.com/kusto/query/scalar-data-types/string#multi-line-string-literals>);
/// tree-sitter rejected them everywhere (the full differential's seed-3
/// verdict difference).
#[test]
fn fenced_multi_line_strings_are_string_literals() {
    for source in [
        "print s = ```a\nmulti-line\nstring```",
        "T | where a == ~~~x~~~",
        "T | extend b = strlen(```y```) | where c has ```z```",
    ] {
        assert!(errors(source).is_empty(), "{source}: {:?}", errors(source));
        let tree = SyntaxNode::new_root(parse(source).green);
        assert!(
            tree.descendants_with_tokens()
                .any(|t| t.kind() == K::STRING && t.to_string().starts_with(['`', '~'])),
            "{source}"
        );
    }
}

/// Found by review (#1411's coverage follow-up): `parse-kv` took an
/// expression only, so its documented form
/// (<https://learn.microsoft.com/kusto/query/parse-kv-operator>), with the
/// keys `as (...)` and the delimiters `with (...)`, was a syntax error.
#[test]
fn parse_kv_takes_its_keys_and_options() {
    for source in [
        "Syslog | parse-kv SyslogMessage as (Level: string, Host: string) with (pair_delimiter = \" \", kv_delimiter = \"=\")",
        "T | parse-kv Text as (a: long) with (quote = '\"', greedy = true)",
        "T | parse-kv Text as (a: long, b: string,)",
        "T | parse-kv Text",
    ] {
        assert!(errors(source).is_empty(), "{source}: {:?}", errors(source));
        let tree = SyntaxNode::new_root(parse(source).green);
        let op = tree
            .descendants()
            .find(|n| n.kind() == K::PARSE_KV_OPERATOR)
            .expect("a parse-kv operator");
        assert_eq!(
            op.to_string().trim_end(),
            source[source.find("parse-kv").unwrap_or(0)..].trim_end()
        );
    }
    assert!(!errors("T | parse-kv Text as (a long)").is_empty());
    assert!(!errors("T | parse-kv Text with (pair_delimiter)").is_empty());
}

// The operator forms Kusto.Language 12.4.1 accepts that were syntax errors.
snapshots! {
    serialize_assignment: "T | serialize rn = row_number(), x";
    render_with_properties: "T | render timechart with (title=\"x\", ycolumns=a, b, ymin=-1)";
    as_hint_materialized: "T | as hint.materialized=true T2 | take 1";
    top_hitters_of_by: "T | top-hitters 5 of x by y";
    reduce_kind_by_with: "T | reduce kind=source by x with threshold=0.1, characters=\"ab\"";
    declare_query_parameters: "declare query_parameters(p:string = \"x\", n:int);\nlet y = 1;\nT | where c == p";
}

#[test]
fn operator_forms_parse_and_their_broken_twins_do_not() {
    for source in [
        "T | serialize",
        "T | as T2",
        "T | render barchart",
        "T | render barchart with ()",
        "T | reduce by x",
        "T | top-hitters 5 of x",
        "T | reduce by x with",
        "T | reduce by x with kind=source, characters=\"a\", threshold=0.2",
        "T | render barchart with (ycolumns=a, b, title=\"x\", series=c, d)",
    ] {
        assert_eq!(errors(source), Vec::<String>::new(), "{source}");
    }
    for source in [
        "T | top-hitters 5",
        "T | top-hitters 5 of x by",
        "T | reduce x",
        "T | reduce by x with threshold=0.1,",
        "T | render barchart with (title=\"x\",)",
        "T | render barchart with title=\"x\"",
        "T | as hint.materialized=true",
        "declare query_parameters(p:string)\nT",
        "declare query_parameters(p);\nT",
        "declare query_parameters();\nT",
        "T | reduce foo=1 by x",
        "T | reduce Kind=source by x",
        "T | reduce by x with foo=1",
        "T | reduce by x with Threshold=0.1",
        "T | render barchart with (a)",
        "T | render barchart with (title=\"x\", a)",
        "T | as hint.progressive_fetch=true T2",
    ] {
        assert!(!errors(source).is_empty(), "{source} parses");
    }
}

// Forms Kusto.Language 12.4.1 accepts that were syntax errors after #1646.
snapshots! {
    render_legacy_properties: "T | render barchart kind=stacked title=\"x\" accumulate=true with (ymin=0)";
    option_signed_number: "T | reduce by x with threshold=-0.1, characters=\"a\"";
    statement_without_semicolon: "declare query_parameters(p:string = \"x\");\nlet y = 1";
}

#[test]
fn legacy_render_signed_options_and_a_last_statement_without_semicolon() {
    for source in [
        "T | render timechart kind=stacked",
        "T | render barchart title=strcat(\"a\") | take 1",
        "T | reduce by x with threshold=+0.1",
        "T | join kind=-1 (U) on x",
        "declare query_parameters(p:string = \"x\")",
        "let x = 1",
        "let x = 1;\nlet y = 2",
        "T | render timechart kind=-1 accumulate=true title=a.b[0]",
        "T | render timechart title=strcat(\"a\", \"b\") kind=1h",
        "T | reduce by x with threshold=-1h",
        "T | join kind=1h (U) on x",
    ] {
        assert_eq!(errors(source), Vec::<String>::new(), "{source}");
    }
    for source in [
        "T | render barchart ytitle=\"y\"",
        "T | render barchart Kind=stacked",
        "T | render barchart kind=stacked, title=\"x\"",
        "T | render barchart with (title=\"x\") kind=stacked",
        "T | reduce by x with threshold=- 0.1",
        "T | reduce by x with threshold=-x",
        "declare query_parameters(p:string = \"x\")\nT",
        "let x = 1\nT",
        "let f = () { let y = 1 y };\nT",
        "T | render timechart title=\"a\" + \"b\"",
        "T | render timechart kind=1+2",
        "T | render timechart kind=strcat(\"a\")",
        "T | render timechart accumulate=f(1)",
        "T | render timechart title=-1",
        "T | render timechart title=a==b",
        "T | render timechart title=a has \"b\"",
    ] {
        assert!(!errors(source).is_empty(), "{source} parses");
    }
}
