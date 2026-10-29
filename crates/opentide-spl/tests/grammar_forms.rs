//! SPL forms from deployed detections that the grammar must accept, and the
//! faults next to them it must still reject (opentidehq/language-server#117).

use opentide_core::codes;
use opentide_spl::analyze;

fn parse_errors(src: &str) -> usize {
    analyze(src)
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::SPL_PARSE_ERROR)
        .count()
}

fn assert_parses(forms: &[&str]) {
    let failing: Vec<&str> = forms
        .iter()
        .copied()
        .filter(|src| parse_errors(src) > 0)
        .collect();
    assert!(failing.is_empty(), "should parse: {failing:#?}");
}

fn assert_rejected(faults: &[&str]) {
    let accepted: Vec<&str> = faults
        .iter()
        .copied()
        .filter(|src| parse_errors(src) == 0)
        .collect();
    assert!(
        accepted.is_empty(),
        "should be a syntax error: {accepted:#?}"
    );
}

/// #120: search clauses and comments.
#[test]
fn search_clauses_parse() {
    assert_parses(&[
        "index=a TERM(EventID=4688)",
        "`m` TERM(user=)",
        "index=a TERM(TERMSRV/*)",
        "index=a (TERM(N1*) OR TERM(N2*)) CASE(Admin)",
        "| tstats count where index=a by PREFIX(src=)",
        "| tstats count where index=a by _time PREFIX(dst=) span=1s",
        "index=a TERM(EventID=4688",
        "index=a TERM(\"a-b\"\n| stats count",
        "index=a TERM(\"a b\") TERM(x",
        "index=a \"http_request.user_agent\"=x",
        "index=a | search \"{}.Id\"=\"x\"",
        "index=a earliest=-1h@h latest=now",
        "index=a earliest=-15m@m latest=now()",
        "_index_earliest=-7m@m _index_latest=@m",
        "index=a app IN (\"a\" \"b\")",
        "index=a app IN (\"a\", \"b\")",
        "index=a version=2.0.0",
        "index=a host=S-RC*",
        "index=a domain_rank=-1",
        "index=a user=svc-x",
        "index=a alert.attack-time=x",
        "index=a severity >= 2 AND x!=y",
        "\"Accepted\" index=a",
        "NOT `m` index=a",
        "`m` NOT title=\"a - *\" status=new",
        "| tstats count as c, values(tag) as tag where index=a earliest=-1h by _time span=1h",
        "index=a [| inputlookup t.csv | fields x]",
        "index=a and or not",
    ]);
}

#[test]
fn search_clause_faults_are_rejected() {
    assert_rejected(&[
        "index=a (TERM(EventID=4688)",
        "index=a app IN (\"a\" \"b\"",
        "index=a OR",
        "OR index=a",
        "index=a AND OR b=1",
        "index=a NOT",
        "index=a (x=1",
        "index=a x=1)",
        // Splunk: "Comparator '=' is missing a term on the right hand side".
        "| tstats count where index=a PREFIX(src=) by host",
    ]);
}

#[test]
fn comments_span_lines_and_take_any_backtick_run() {
    assert_parses(&[
        "index=a\n``` multi\nline ```\n| stats count",
        "index=a ```` four ```\n| stats count",
        "index=a ``````\n| stats count",
        "index=a | join host ``` why ``` [| search index=b]",
        "index=a ``` `m` is not expanded here ```",
    ]);
    // The comment ends at the first run of three backticks.
    assert_rejected(&[
        "index=a ``` unclosed\n| stats count",
        "index=a (\n``` multi\nline ```\n| stats count",
    ]);
}

/// Reserving `AND`, `OR` and `NOT` must not break commands that take them.
#[test]
fn reserved_booleans_are_arguments() {
    assert_parses(&[
        "| metasearch index=a OR index=b",
        "| metasearch NOT index=a",
        "| metasearch index=a AND sourcetype=b",
        "| mpreview index=a OR index=b",
        "| eventcount index=a OR index=b",
        "| metadata type=hosts index=a OR index=b",
        "| searchtxn t max_terms=10 a OR b",
        "index=a | bogus a OR b",
        "index=a | bogus NOT b",
    ]);
}

#[test]
fn leading_bare_word_is_still_a_command() {
    let r = analyze("index=main | bogus foo=bar");
    assert!(
        r.diagnostics
            .iter()
            .any(|d| d.code == codes::SPL_UNKNOWN_COMMAND),
        "{:?}",
        r.diagnostics
    );
    let r = analyze("bogus foo=bar");
    assert!(
        r.diagnostics
            .iter()
            .any(|d| d.code == codes::SPL_UNKNOWN_COMMAND),
        "{:?}",
        r.diagnostics
    );
}
