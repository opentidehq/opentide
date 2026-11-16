//! What the parser's tree highlights, and the fields it finds: the rules of
//! the tree-sitter `highlights.scm` it replaces, one case each.

use opentide_falco::{highlight_captures, tree_fields};

/// `text=capture` of every span.
fn spans(source: &str) -> Vec<String> {
    highlight_captures(source)
        .into_iter()
        .map(|(span, capture)| format!("{}={capture}", &source[span.start..span.end]))
        .collect()
}

#[test]
fn a_comparison() {
    assert_eq!(
        spans("proc.name in (bash, \"su do\") and not evt.dir = <"),
        [
            "proc.name=property",
            "in=keyword",
            "(=punctuation.bracket",
            "bash=string",
            ",=punctuation.delimiter",
            "\"su do\"=string",
            ")=punctuation.bracket",
            "and=keyword",
            "not=keyword",
            "evt.dir=property",
            "==operator",
            "<=string",
        ]
    );
}

#[test]
fn bare_strings_are_booleans_numbers_or_strings() {
    assert_eq!(
        spans("a.b in (true, 0x1F, -1.5e+3, 10.0.0.1, false1)"),
        [
            "a.b=property",
            "in=keyword",
            "(=punctuation.bracket",
            "true=boolean",
            ",=punctuation.delimiter",
            "0x1F=number",
            ",=punctuation.delimiter",
            "-1.5e+3=number",
            ",=punctuation.delimiter",
            "10.0.0.1=string",
            ",=punctuation.delimiter",
            "false1=string",
            ")=punctuation.bracket",
        ]
    );
}

#[test]
fn names_modifiers_and_references() {
    assert_eq!(
        spans(
            "spawned_process and a.b = anyof (c) and d.e startswith oneof f_list and g.h in shell_events"
        ),
        [
            "spawned_process=macro",
            "and=keyword",
            "a.b=property",
            "==operator",
            "anyof=keyword",
            "(=punctuation.bracket",
            "c=string",
            ")=punctuation.bracket",
            "and=keyword",
            "d.e=property",
            "startswith=operator",
            "oneof=keyword",
            "f_list=variable",
            "and=keyword",
            "g.h=property",
            "in=keyword",
            "shell_events=variable",
        ]
    );
}

#[test]
fn transformers_and_field_arguments() {
    assert_eq!(
        spans(r#"getopt(proc.args, "nt:")[t] = val(a.b)[/x] and len(()) > 1"#),
        [
            "getopt(=function.builtin",
            "proc.args=property",
            ",=punctuation.delimiter",
            "\"nt:\"=string",
            ")=punctuation.bracket",
            "[=punctuation.bracket",
            "t=string",
            "]=punctuation.bracket",
            "==operator",
            "val(=function.builtin",
            "a.b=property",
            ")=punctuation.bracket",
            "[=punctuation.bracket",
            "/x=string",
            "]=punctuation.bracket",
            "and=keyword",
            "len(=function.builtin",
            "(=punctuation.bracket",
            ")=punctuation.bracket",
            ")=punctuation.bracket",
            ">=operator",
            "1=number",
        ]
    );
}

#[test]
fn fields_in_source_order_once() {
    assert_eq!(
        tree_fields(
            "proc.name = a and (fd.name in (b) or proc.name = c) and join(\",\", (user.name, proc.pname)) = d"
        ),
        ["proc.name", "fd.name", "user.name", "proc.pname"]
    );
    assert!(tree_fields("a_macro and other_macro").is_empty());
}
