//! The two Elastic query string engines together: each tells a rule written
//! for the other language partly by whether the other grammar accepts the
//! text (`opentide_kuery::parses`, `opentide_lucene::parses`). The Lucene
//! engine depends on the KQL one, so the KQL engine takes the Lucene verdict
//! as an argument; these tests run both with the real verdicts.

use opentide_core::{Diagnostic, codes};

fn kuery(source: &str) -> Vec<Diagnostic> {
    opentide_kuery::analyze(source, opentide_lucene::parses).diagnostics
}

fn lucene(source: &str) -> Vec<Diagnostic> {
    opentide_lucene::analyze(source).diagnostics
}

fn find<'a>(found: &'a [Diagnostic], code: &str) -> Option<&'a Diagnostic> {
    found.iter().find(|d| d.code == code)
}

#[test]
fn each_grammar_gives_its_own_verdict() {
    assert!(opentide_kuery::parses("a:1 and b:2"));
    assert!(!opentide_kuery::parses("a:1 b:2 AND _exists_:c"));
    // No masking: Kibana reads a trailing `or` as text, the grammar does not.
    assert!(!opentide_kuery::parses("f:a or"));
    assert!(opentide_lucene::parses("a:1 b:2 AND _exists_:c"));
    assert!(!opentide_lucene::parses("a:(1"));
}

#[test]
fn a_kql_error_that_lucene_accepts_is_a_sign_of_lucene() {
    // Implicit AND is a KQL error that Lucene accepts; `_exists_` is the
    // second sign.
    let found = kuery("a:1 b:2 AND _exists_:c");
    let d = find(&found, codes::KUERY_LOOKS_LIKE_LUCENE).expect("two signals");
    assert!(
        d.message.contains("text only Lucene parses"),
        "{}",
        d.message
    );
    // Without the Lucene verdict only one sign is left.
    let alone = opentide_kuery::analyze("a:1 b:2 AND _exists_:c", |_| false).diagnostics;
    assert!(find(&alone, codes::KUERY_LOOKS_LIKE_LUCENE).is_none());
}

#[test]
fn no_lucene_advice_past_a_kql_syntax_error() {
    // Kibana reads nothing past the first error: recovery fragments give no
    // Lucene advice, whatever the Lucene grammar says of the text.
    for src in [
        r"process\-name:cmd.exe",
        "} or x\" and not  and :b}",
        r"\ not  and 1 :ba:",
    ] {
        let found = kuery(src);
        for code in [codes::KUERY_LUCENE_SYNTAX, codes::KUERY_LOOKS_LIKE_LUCENE] {
            assert!(find(&found, code).is_none(), "{src}: {found:?}");
        }
    }
}

#[test]
fn a_lucene_error_that_kql_accepts_is_a_sign_of_kql() {
    // KQL's nested field query is a Lucene error; the lower-case `and` is the
    // second sign.
    let found = lucene("user:{ name:x } and host.name:y");
    let d = find(&found, codes::LUCENE_LOOKS_LIKE_KUERY).expect("two signals");
    assert!(d.message.contains("text only KQL parses"), "{}", d.message);
    // Text both grammars accept gets no KQL verdict sign.
    let found = lucene("process.name:cmd.exe and user.name:x");
    assert!(find(&found, codes::LUCENE_LOOKS_LIKE_KUERY).is_none());
}
