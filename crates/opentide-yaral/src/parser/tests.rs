//! Tree snapshots of the productions, error recovery and depth. The corpus
//! and verdict tests are in `tests/`.

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

macro_rules! snapshots {
    ($($name:ident: $source:expr;)*) => {$(
        #[test]
        fn $name() {
            insta::assert_snapshot!(show($source));
        }
    )*};
}

snapshots! {
    precedence: "not $a or $b and $c = 1 + 2 * 3 - 4";
    flat_chains: "$a or $b or $c\n$a and $b and $c and $d";
    comparisons_nest_to_the_left: "$a = 1 != 2 nocase";
    not_takes_a_comparison: "not $e.a = 1 and not not $b";
    signs: "-$a * -$b + !$c";
    udm_paths: "$e.network.dhcp.options = $e.additional.fields[\"k\"] $e.target.ip[0]";
    bare_paths: "principal.hostname = labels[\"k\"] ip";
    quantifiers: "any $e.ip = \"x\" all c.d != 1 any of [$a, $b,] 2 of [$c] all of []";
    in_lists: "$a in %l $b in regex %l nocase $c in cidr %t.col";
    calls: "strings.to_lower($e.a) = \"x\" nocase count($e) re.regex($e.f, `x`) nocase";
    named_arguments: "m.f(period: 1d, principal.user.userid: $u, g: *, 3)";
    tables: "%t %t.col %t.write_row(a: $v)";
    if_and_arrays: "if($a, $b, $c) = if ($a, $b) [1, 2]";
    literals: "$a = \"s\" or $b = `r` or $c = /x\\/y/ or $d = 1.5 or $e = 10m or $f = true or window_start";
    cross_join: "cross join $a, $b\nCROSS JOIN $c";
    keywords_in_any_case: "$a AnD $b oR NOT $c";
    division_is_a_regex_between_operands: "$a / $b / $c";
}

snapshots! {
    error_missing_operand: "$a = ";
    error_trailing_operator: "$a or";
    error_unclosed_paren: "($a = 1";
    error_empty_paren: "()";
    error_double_nocase: "$a = 1 nocase nocase";
    error_comma_between_terms: "$a, $b";
    error_star_argument: "f(*)";
    error_trailing_argument_comma: "f(a,)";
    error_named_udm_argument: "f($e.a: 1)";
    error_array_without_commas: "[\"a\" \"b\"]";
    error_in_without_list: "$a in $b";
    error_keyword_segment_after_blank: "$e . a";
    error_table_keyword_column: "%l.options";
    error_if_arity: "if($a)";
    error_quantifier_alone: "any [$a]";
    error_cross_without_join: "cross $a";
}

#[test]
fn a_thousand_parentheses_nest_on_a_small_stack() {
    let source = format!("{}$a{}", "(".repeat(1_000), ")".repeat(1_000));
    let parsed = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || parse(&source))
        .unwrap()
        .join()
        .unwrap();
    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
}

#[test]
fn past_the_limit_there_is_one_error_and_no_overflow() {
    let source = format!("{}$a", "not ".repeat(200_000));
    let parsed = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || parse(&source))
        .unwrap()
        .join()
        .unwrap();
    assert!(matches!(
        parsed.errors.as_slice(),
        [e] if matches!(e.kind, ErrorKind::TooDeep { .. })
    ));
}

#[test]
fn long_chains_are_flat() {
    let n = 20_000;
    let source = vec!["$e.a = \"x\""; n].join(" or ");
    let parsed = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || parse(&source))
        .unwrap()
        .join()
        .unwrap();
    assert!(parsed.errors.is_empty());
    assert!(parsed.depth < 20, "depth {}", parsed.depth);
}
