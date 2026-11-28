//! What the parser's tree highlights: the rules of the tree-sitter
//! `highlights.scm` it replaces, a few cases each.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

use opentide_exabeam::highlight_captures;

/// `text=capture` of every span.
fn spans(source: &str) -> Vec<String> {
    highlight_captures(source)
        .into_iter()
        .map(|(span, capture)| format!("{}={capture}", &source[span.start..span.end]))
        .collect()
}

#[test]
fn field_terms_and_their_values() {
    assert_eq!(
        spans(r#"a:"x" b:true c:NULL d:@e f:10.0.0.1 g:fe80::1 h:word i:-1.5 j!=k"#),
        [
            "a=property",
            ":=operator",
            "\"x\"=string",
            "b=property",
            ":=operator",
            "true=boolean",
            "c=property",
            ":=operator",
            "NULL=constant",
            "d=property",
            ":=operator",
            "@e=variable",
            "f=property",
            ":=operator",
            "10.0.0.1=constant",
            "g=property",
            ":=operator",
            "fe80::1=constant",
            "h=property",
            ":=operator",
            "word=string",
            "i=property",
            ":=operator",
            "-1.5=number",
            "j=property",
            "!==error",
            "k=string",
        ]
    );
}

#[test]
fn lists_ranges_and_context_tables() {
    assert_eq!(
        spans(r#"a:(1, x, @y) b:[1 TO z} c IN "T"."C""#),
        [
            "a=property",
            ":=operator",
            "(=punctuation.bracket",
            "1=number",
            ",=punctuation.delimiter",
            "x=string",
            ",=punctuation.delimiter",
            "@y=variable",
            ")=punctuation.bracket",
            "b=property",
            ":=operator",
            "[=punctuation.bracket",
            "1=number",
            "TO=keyword",
            "z=constant",
            "}=punctuation.bracket",
            "c=property",
            "IN=keyword",
            "\"T\"=type",
            ".=punctuation.delimiter",
            "\"C\"=type",
        ]
    );
}

#[test]
fn calls_and_free_text() {
    assert_eq!(
        spans(r#"a:WLDi("x", 1) nope(b) web* * "p""#),
        [
            "a=property",
            ":=operator",
            "WLDi=function.builtin",
            "(=punctuation.bracket",
            "\"x\"=string",
            ",=punctuation.delimiter",
            "1=error",
            ")=punctuation.bracket",
            "nope=error",
            "(=punctuation.bracket",
            "b=error",
            ")=punctuation.bracket",
            "web*=string",
            "*=string",
            "\"p\"=string",
        ]
    );
}

#[test]
fn the_advanced_operators() {
    assert_eq!(
        spans(
            "SELECT count(*) AS n, a, bad(b) FROM t WHERE x GROUP-BY a ORDER-BY n desc LIMIT 5 | FOREACH a [b]"
        ),
        [
            "SELECT=keyword",
            "count=function.builtin",
            "(=punctuation.bracket",
            "*=operator",
            ")=punctuation.bracket",
            "AS=keyword",
            "n=variable",
            ",=punctuation.delimiter",
            "a=property",
            ",=punctuation.delimiter",
            "bad=error",
            "(=punctuation.bracket",
            "b=property",
            ")=punctuation.bracket",
            "FROM=keyword",
            "t=type",
            "WHERE=keyword",
            "x=string",
            "GROUP-BY=keyword",
            "a=property",
            "ORDER-BY=keyword",
            "n=property",
            "desc=keyword",
            "LIMIT=keyword",
            "5=number",
            "|=operator.pipe",
            "FOREACH=keyword",
            "a=property",
            "[=punctuation.bracket",
            "b=string",
            "]=punctuation.bracket",
        ]
    );
}
