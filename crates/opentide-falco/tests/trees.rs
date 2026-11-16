//! The parser's trees as snapshots: a few hand-picked conditions and one tree
//! per corpus file, valid and invalid alike. A corpus file's first line is its
//! `prod:` tag, not part of the condition.

use opentide_falco::debug_parse;

#[test]
fn trees() {
    insta::assert_snapshot!(
        "rule",
        debug_parse(
            "spawned_process and not proc.name in (sshd, \"su do\") and fd.name startswith /etc or evt.type = open"
        )
    );
    insta::assert_snapshot!(
        "transformers",
        debug_parse(
            r#"getopt(proc.args, "nt:")[t] = value and join(",", (proc.name, 1)) = a and fd.name = val(proc.cwd)[x]"#
        )
    );
    insta::assert_snapshot!(
        "modifier_and_list",
        debug_parse(
            "proc.name = anyof (bash, sh) and evt.type in shell_events and proc.pname exists"
        )
    );
    insta::assert_snapshot!(
        "operators",
        debug_parse("a.b <= 1 and a.c != x and a.d == y and a.e > z")
    );
    insta::assert_snapshot!(
        "append_fragment",
        debug_parse("and not proc.pname in (a, b)")
    );
    insta::assert_snapshot!("unclosed", debug_parse("(a.b = c and (d.e in (f, g)"));
    insta::assert_snapshot!("stray_paren", debug_parse("a.b = c) and d"));
    insta::assert_snapshot!("unclosed_quote", debug_parse("a.b = \"c and d.e = f"));
}

#[test]
fn corpus_trees() {
    insta::glob!("../../testdata/corpus/falco", "*.falco", |path| {
        let text = std::fs::read_to_string(path).expect("a corpus file");
        let body: Vec<&str> = text.lines().skip(1).collect();
        insta::assert_snapshot!(debug_parse(&body.join("\n")));
    });
}
