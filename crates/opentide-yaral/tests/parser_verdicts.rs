//! The statements and expressions the new parser takes, against the verdict
//! of the tree-sitter grammar on the same text: a text that parses without an
//! error there parses without an error here, and the other way round.
//!
//! The texts are searches (statements with no `events:` label), the one root
//! both engines take statements at. The sections come with the next PR.

use opentide_core::LanguageId;
use opentide_yaral::testing::{parse_error_count, parse_is_lossless};

/// Valid and broken statements, in the shapes the grammar has.
const TEXTS: &[&str] = &[
    // Precedence and chains.
    "not $e.a = 1 and $e.b = 2",
    "-$a * $b + $c / $d",
    "$a / $b / $c",
    "$e.a = 1 $e.b = 2",
    "$a = 1 + 2 * 3 - 4",
    "not $a or $b",
    "not not $a",
    "!!$a",
    "- - $a",
    "$a ! $b",
    "$a !",
    "$a = not $b",
    "$a = - $b",
    "1 + ",
    "$a = 1 = 2 = 3",
    "$a = \"x\" nocase = 1",
    "$a = \"x\" nocase nocase",
    "f(1) nocase nocase",
    "$a = f(1) nocase nocase",
    "f(1) = 1 nocase",
    // Quantifiers and lists.
    "any $e.ip = \"x\"",
    "all c.d != 1",
    "any $a",
    "any any $a",
    "any [$a]",
    "any of [$a, $b,]",
    "2 of [$a] and all of []",
    "1 of [$a] = 1",
    "1.5 of [$a]",
    "- 1 of [$a]",
    "[1, 2]",
    "[,]",
    "[\"a\" \"b\"]",
    "$a in %l",
    "$a in regex %l nocase",
    "$a in cidr %t.col",
    "$a in %l regex",
    "$a in $b",
    "$a in [1]",
    "in %l",
    "$a in %l.c",
    "%l.c.d",
    "%l .c",
    "%l. c",
    "%l.options",
    "%t.write_row(a: $v)",
    "%t.c %t",
    // Paths.
    "$e.network.dhcp.options = $e.b.c.d[0]",
    "$e.a[\"x\"] $e.a[0] $e.a[$x]",
    "$e . a",
    "$e.a.window_start",
    "principal.hostname = labels[\"k\"]",
    "a.b.c(d)",
    "a.b(d) = a.b",
    "strings .to_lower($a)",
    "strings.options($a)",
    "$a.b = 1.5 and $c = 1h and $d = 1",
    // Calls.
    "count(x) count (x)",
    "re.regex($e.a, `x`) nocase",
    "f(a: 1, $b) and g(a: *) and h(*)",
    "f(a,)",
    "f(a:)",
    "f($e.a: 1)",
    "f(a.b: 1)",
    "f(a.b.c: *)",
    "$a:1",
    "a: 1",
    "if($a, $b, $c) = if ($a, $b)",
    "if()",
    "if($a)",
    "if($a,)",
    // Literals, windows, joins.
    "$a = /x/ nocase or $b = /y\\/z/",
    "$a = /x/ /y/",
    "window_start window_end",
    "first every",
    "cross join $a, $b",
    "cross join $a",
    "cross $a",
    "cross = 1",
    "cross join",
    "graph_append = 1",
    "(($a))",
    "()",
    "($a",
    "$a)",
    "$a = ",
    "$a or",
    "$a, $b",
    "$a and and $b",
    "= $a",
    "AnD",
    "$a AnD $b oR NOT $c",
    "# $a",
    "$a ?",
    "\"unclosed",
    "`unclosed",
    "/* unclosed",
    "$a // comment\n= 1",
    "$a /* c */ = 1",
    "",
    "   \n",
    "// only a comment",
];

#[test]
fn the_verdicts_are_tree_sitters() {
    let mut different = Vec::new();
    for text in TEXTS {
        let old = opentide_syntax::parse(LanguageId::Yaral, text).expect("tree-sitter parses");
        let old_broken = old.root_node().has_error();
        let new_broken = parse_error_count(text) > 0;
        if old_broken != new_broken {
            different.push(format!(
                "{text:?}: tree-sitter {} here {}",
                if old_broken { "errors" } else { "accepts" },
                if new_broken { "errors" } else { "accepts" }
            ));
        }
        assert!(parse_is_lossless(text), "{text:?} is not lossless");
    }
    assert!(different.is_empty(), "{}", different.join("\n"));
}
