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

/// #121: eval and where expressions.
#[test]
fn eval_expressions_parse() {
    assert_parses(&[
        "index=a | eval k=a.\"-\".b",
        "index=a | eval k = \"x\" . b",
        "index=a | eval s=case(x>1, 1, true(), 0)",
        "index=a | eval s=if(x, false(), null())",
        "index=a | eval s=if(x like \"a%\", 1, 0)",
        "index=a | where x like \"a%\"",
        "index=a | where like(x, \"a%\") OR x LIKE \"b%\"",
        "index=a | eval \"a.b\"='c.d'",
        "index=a | eval {f}=v",
        "index=a | eval x=mvindex('a{}.b', 0)",
        "index=a | eval x=a*2, y=-abs(z), w=a%2",
        "index=a | eval x=Processes.user",
        "index=a | eval s=case(\n    x>1, 1,\n    true(), 0)",
        "index=a | eval x=if(!match(a, \"-\") AND isnotnull(b), 1, 0)",
        "index=a | where isnull(x) AND NOT y!=2",
        "index=a | where n > $threshold$",
        "index=a | where NOT [| inputlookup t.csv | fields x]",
        "index=a | join x [| eval <<FIELD>>=mvdedup('<<FIELD>>')]",
        "index=a | join x [| eval r<<MATCHSTR>>=lower('<<FIELD>>')]",
        "index=a | join x [| eval y=\"<<FIELD>>=\".mvjoin('<<FIELD>>', \" | \")]",
    ]);
}

#[test]
fn eval_expression_faults_are_rejected() {
    assert_rejected(&[
        "index=a | eval k=a.",
        "index=a | eval k=.a",
        "index=a | eval x=a*",
        "index=a | eval x=*",
        "index=a | eval {f=v",
        "index=a | eval x=true(",
        "index=a | where x like",
        "index=a | eval \"a.b\"=",
        "index=a | eval x=!",
    ]);
}

/// #122: field names, wildcards and command arguments.
#[test]
fn command_arguments_parse() {
    assert_parses(&[
        "index=a | rename a as b",
        "index=a | rename DNS.* as *",
        "index=a | rename a AS b, c As d,\n| eval x=1",
        "index=a | rename IsOutlier(x) as o, f, as g",
        "| tstats count where index=a by PREFIX(dst=) | rename dst= as dest, *= as *",
        "index=a | rename a.$date as d",
        "index=a | stats values(*) as * by user",
        "index=a | stats earliest(_time) as \"earliest\"",
        "index=a | stats count, dc(x) as y BY a, , b",
        "index=a | stats values(*) as *,\n| eval x=1",
        "index=a | lookup t ip as src OUTPUT x",
        "index=a | lookup t ip AS src OUTPUTNEW x AS y, z",
        "index=a | lookup t-include.csv ip OUTPUT x",
        "index=a | lookup local=t t a as b OUTPUTNEW\n| stats count",
        "index=a | eventstats dc(src) as c by user",
        "index=a | eventstats values(dns_*) as dns_* by dest",
        "index=a | eventstats min(eval(if(t==\"a\", _time, null()))) as e",
        "index=a | fillnull value=\"-\" a, b",
        "index=a | fillnull a value=-1",
        "index=a | fillnull",
        "index=a | foreach * [ eval <<FIELD>>=mvdedup(<<FIELD>>) ]",
        "index=a | foreach user* [| eval r<<MATCHSTR>>=lower('<<FIELD>>') ]",
        "index=a | foreach a, b mode=multifield [ eval <<FIELD>>=1 ]",
        "| tstats count, values(a) as a\n    values(b) as b fillnull_value=\"-\" from datamodel=X.Y where index=a by _time host span=1h",
        "| tstats count from datamodel=\"Web\" by _time PREFIX(dst=) span=1s",
        "index=a | sort -lt limit=0",
        "index=a | sort 0 host _time",
        "index=a | sort limit=0 + src, _time",
        "index=a | sort - et limit=0",
        "index=a | sort num(x) desc",
        "index=a | tojson * output_field=j",
        "index=a | tojson fill_null=true a, b* output_field=j",
        "index=a | spath a{}",
        "index=a | spath input=x path=a{}.b output=y",
        "index=a | spath path={}",
        "index=a | rex mode=sed field=x \"s/a/b/g\"",
        "index=a | rex field=x max_match=0 \"(?<y>.)\"",
        "index=a | rex field=x, \"(?<y>.)\"",
        "index=a | streamstats window=1 current=f values(_time) as t by user",
        "index=a | streamstats count by user reset_on_change=true",
        "index=a | streamstats time_window=3h count by user",
        "index=a | streamstats count by src reset_after=\"(\"action==\\\"success\\\"\")\"",
        "index=a | fields a{}.b",
        "index=a | fields InsightData{}.Details{}.Name",
        "index=a | fields alert.attack-time",
        "index=a | fields a, , b",
        "index=a | table a, \"b c\", d*",
        "index=a | join type=left k [ search index=b | fields k ]",
        "index=a | join type=left a, b [ search index=b ]",
        "index=a | mvexpand a{}",
        "index=a | mvexpand x limit=10",
        "index=a | mvexpand(x)",
        "| inputlookup append=t t where (x=\"a\" OR x=\"b\") AND y <= 60",
        "index=a | outputlookup append=true t-x.csv",
        "| rest /services/data/indexes count=0",
        "index=a | convert timeformat=\"%Y\" ctime(_time) AS t",
        "index=a | fromjson x prefix=y_",
        "index=a | timechart span=1h count by host limit=0 useother=f",
        "index=a | chart count over a by b",
        "index=a | stats values(PREFIX(dpt=)) as p",
        "index=a | dedup host user keepempty=true sortby -_time",
        "index=a | bin _time span=1h",
        "index=a | top limit=10 x by y showperc=f",
        "index=a | regex _raw!=\"a\"",
        "index=a | strcat a \"-\" b c",
        "index=a | makemv delim=\",\" allowempty=t x",
        "index=a | iplocation src",
    ]);
}

#[test]
fn command_argument_faults_are_rejected() {
    assert_rejected(&[
        "index=a | rename a as",
        "index=a | rename a b",
        "index=a | lookup t",
        "index=a | lookup t a OUTPUT x AS",
        "index=a | stats values(",
        "index=a | stats count by",
        "index=a | eventstats dc(src as c",
        "index=a | foreach * eval x=1",
        "index=a | sort",
        "index=a | rex field=x",
        "index=a | join type=left k",
        "index=a | mvexpand",
        "| inputlookup",
    ]);
}

#[test]
fn known_command_arguments_never_make_an_unknown_command() {
    let r = analyze("index=a | bin _time span=1h | xyseries a b c | notacommand x");
    let unknown: Vec<&str> = r
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::SPL_UNKNOWN_COMMAND)
        .map(|d| d.message.as_str())
        .collect();
    assert_eq!(
        unknown,
        ["unknown SPL command 'notacommand'"],
        "{r:?}",
        r = r.diagnostics
    );
}

#[test]
fn keywords_highlight_whatever_their_case() {
    let src = "index=a | lookup t ip AS src OUTPUT x | rename a as b | stats count BY h";
    let r = analyze(src);
    let keywords: Vec<&str> = r
        .tokens
        .iter()
        .filter(|t| t.capture == "keyword")
        .map(|t| &src[t.span.start..t.span.end])
        .collect();
    for word in ["lookup", "AS", "OUTPUT", "rename", "as", "stats", "BY"] {
        assert!(
            keywords.contains(&word),
            "{word} not a keyword: {keywords:?}"
        );
    }
}
