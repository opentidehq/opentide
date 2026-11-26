//! Unit tests of the grammar and the checks: every code of RFC §6.7 with its example, the
//! constructs of §6.6, the precedence, and the single walk's work count.

use crate::check::{self, Profile};
use crate::{Context, analyze_with, findings, parser, syntax::SyntaxKind as K};
use opentide_core::{Severity, codes};

/// The codes of `source` under `profile`, in order.
fn codes_of(source: &str, profile: Profile) -> Vec<&'static str> {
    findings(source, profile)
        .into_iter()
        .map(|f| f.code)
        .collect()
}

fn search(source: &str) -> Vec<&'static str> {
    codes_of(source, Profile::Search)
}

fn rule(source: &str) -> Vec<&'static str> {
    codes_of(source, Profile::Rule)
}

/// The tree of `source` as nested kinds, trivia left out: `(OR_EXPR TERM (AND_EXPR TERM TERM))`.
fn shape(source: &str) -> String {
    fn node(n: &crate::SyntaxNode, out: &mut String) {
        let children: Vec<_> = n.children().collect();
        if children.is_empty() {
            out.push_str(&format!("{:?}", n.kind()));
            return;
        }
        out.push_str(&format!("({:?}", n.kind()));
        for c in children {
            out.push(' ');
            node(&c, out);
        }
        out.push(')');
    }
    let (root, parse) = parser::parse(source);
    assert!(parse.errors.is_empty(), "{source}: {:?}", parse.errors);
    let mut out = String::new();
    node(&root, &mut out);
    out
}

fn parses(source: &str) -> bool {
    crate::parses(source)
}

// ---- Grammar -------------------------------------------------------------------------------

#[test]
fn the_tree_is_lossless() {
    for source in [
        "",
        "  ",
        "a OR b c",
        "service:(web OR api",
        "@x:[1 TO",
        "\"unclosed",
        "CIDR(@ip, fc00::/7) -@a:* NOT(b)",
        "a\\",
        "\u{feff}a",
    ] {
        let (root, _) = parser::parse(source);
        assert_eq!(root.to_string(), source);
    }
}

#[test]
fn and_binds_tighter_than_or() {
    assert_eq!(
        shape("a OR b c"),
        "(QUERY (OR_EXPR TERM (AND_EXPR TERM TERM)))"
    );
    assert_eq!(
        shape("a b OR c"),
        "(QUERY (OR_EXPR (AND_EXPR TERM TERM) TERM))"
    );
    assert_eq!(
        shape("a AND b OR c AND d"),
        "(QUERY (OR_EXPR (AND_EXPR TERM TERM) (AND_EXPR TERM TERM)))"
    );
    assert_eq!(
        shape("env:(a OR b c)"),
        "(QUERY (FIELD_CLAUSE TAG_KEY (VALUE_GROUP (VALUE_OR_EXPR TERM (VALUE_AND_EXPR TERM TERM)))))"
    );
}

#[test]
fn chains_are_flat() {
    assert_eq!(shape("a b c d"), "(QUERY (AND_EXPR TERM TERM TERM TERM))");
    assert_eq!(shape("a OR b OR c"), "(QUERY (OR_EXPR TERM TERM TERM))");
}

#[test]
fn a_modifier_binds_tightest() {
    assert_eq!(shape("-a b"), "(QUERY (AND_EXPR (NOT_EXPR TERM) TERM))");
    assert_eq!(
        shape("NOT(CIDR(@ip, 10.0.0.0/8))"),
        "(QUERY (NOT_EXPR (GROUP (CIDR_CALL ATTRIBUTE CIDR_BLOCK))))"
    );
    assert_eq!(
        shape("+@a:1"),
        "(QUERY (NOT_EXPR (FIELD_CLAUSE ATTRIBUTE TERM)))"
    );
}

#[test]
fn fields_are_told_apart_by_their_first_character() {
    assert_eq!(
        shape("@evt.outcome:FAILURE"),
        "(QUERY (FIELD_CLAUSE ATTRIBUTE TERM))"
    );
    assert_eq!(
        shape("#duration_ms:>500"),
        "(QUERY (FIELD_CLAUSE CALCULATED_FIELD (COMPARISON TERM)))"
    );
    assert_eq!(shape("source:okta"), "(QUERY (FIELD_CLAUSE TAG_KEY TERM))");
    assert_eq!(
        shape("*:hello"),
        "(QUERY (FIELD_CLAUSE ALL_ATTRIBUTES TERM))"
    );
    assert_eq!(shape("*:*"), "(QUERY MATCH_ALL)");
    assert_eq!(
        shape("*:*abcd*"),
        "(QUERY (FIELD_CLAUSE ALL_ATTRIBUTES TERM))"
    );
    assert_eq!(
        shape(r#""service.status":disabled"#),
        "(QUERY (FIELD_CLAUSE QUOTED_FIELD TERM))"
    );
    assert_eq!(
        shape(r"@user.first\ name:x"),
        "(QUERY (FIELD_CLAUSE ATTRIBUTE TERM))"
    );
}

#[test]
fn values_take_comparisons_ranges_phrases_and_groups() {
    assert_eq!(
        shape("@d:>=100ms"),
        "(QUERY (FIELD_CLAUSE ATTRIBUTE (COMPARISON TERM)))"
    );
    assert_eq!(
        shape("@x:>-1"),
        "(QUERY (FIELD_CLAUSE ATTRIBUTE (COMPARISON TERM)))"
    );
    assert_eq!(
        shape("@code:[400 TO 499]"),
        "(QUERY (FIELD_CLAUSE ATTRIBUTE (RANGE RANGE_BOUND RANGE_BOUND)))"
    );
    assert_eq!(
        shape(r#"@a:"b c""#),
        "(QUERY (FIELD_CLAUSE ATTRIBUTE PHRASE))"
    );
    assert_eq!(
        shape("@code:(>=400 <500)"),
        "(QUERY (FIELD_CLAUSE ATTRIBUTE (VALUE_GROUP (VALUE_AND_EXPR (COMPARISON TERM) (COMPARISON TERM)))))"
    );
    assert_eq!(
        shape("@a:(-*)"),
        "(QUERY (FIELD_CLAUSE ATTRIBUTE (VALUE_GROUP (VALUE_NOT_EXPR TERM))))"
    );
    assert_eq!(shape("env: prod"), "(QUERY (FIELD_CLAUSE TAG_KEY TERM))");
    assert_eq!(
        shape("@data.message:+*"),
        "(QUERY (FIELD_CLAUSE ATTRIBUTE TERM))"
    );
    assert_eq!(
        shape(r#"tags:service\:"web-store""#),
        "(QUERY (FIELD_CLAUSE TAG_KEY TERM))"
    );
}

#[test]
fn numbers_are_read_where_they_are_a_whole_value() {
    let kinds = |s: &str| crate::debug_kinds(s).1;
    assert!(kinds("@d:>=100ms").contains(&"number".to_owned()));
    assert_eq!(
        kinds("@x:[1 TO 5]")
            .iter()
            .filter(|k| *k == "number")
            .count(),
        2
    );
    assert!(kinds("404").contains(&"number".to_owned()));
    assert!(!kinds("10.0.0.0/8").contains(&"number".to_owned()));
    assert!(!kinds("web-1").contains(&"number".to_owned()));
}

#[test]
fn what_does_not_parse() {
    for broken in [
        "service:(web OR api",
        "@user:",
        "@user: )",
        "--a",
        "NOT NOT a",
        "-NOT a",
        "a OR",
        "AND a",
        "()",
        "a)",
        "\"open",
        "@x:>",
        "@session.view.count :> 3",
        "rule:[A-Invalid",
        "a\\",
        "CIDR(@ip",
        "CIDR(@ip,)",
    ] {
        assert!(!parses(broken), "{broken:?} parses");
        let expected = if broken.contains('[') {
            codes::DATADOG_RANGE
        } else {
            codes::DATADOG_PARSE_ERROR
        };
        assert_eq!(search(broken), vec![expected], "{broken:?}");
    }
}

#[test]
fn a_query_that_does_not_parse_gets_its_first_error_only() {
    let result = analyze_with("@a:1 and @b:2 (", &Context::SEARCH);
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].code, codes::DATADOG_PARSE_ERROR);
    assert!(
        !result.tokens.is_empty(),
        "the highlight survives the error"
    );
}

#[test]
fn a_range_fault_is_datadog_range() {
    assert_eq!(search("@x:[1 5]"), vec![codes::DATADOG_RANGE]);
    assert_eq!(search("models.litellm[.]cloud"), vec![codes::DATADOG_RANGE]);
}

#[test]
fn deep_nesting_is_one_error() {
    let deep = format!("{}a{}", "(".repeat(1_001), ")".repeat(1_001));
    let (_, parse) = parser::parse(&deep);
    assert_eq!(parse.errors.len(), 1);
    let ok = format!("{}a{}", "(".repeat(1_000), ")".repeat(1_000));
    assert!(parses(&ok));
}

// ---- The codes of §6.7 ---------------------------------------------------------------------

#[test]
fn unescaped_special() {
    assert_eq!(search("foo!bar"), vec![codes::DATADOG_UNESCAPED_SPECIAL]);
    assert_eq!(
        search("message:*!*"),
        vec![codes::DATADOG_UNESCAPED_SPECIAL]
    );
    assert_eq!(search("@x:-1"), vec![codes::DATADOG_UNESCAPED_SPECIAL]);
    assert_eq!(search("a<b>c"), vec![codes::DATADOG_UNESCAPED_SPECIAL]);
    assert!(search(r"@x:\-1").is_empty());
    assert!(search(r"foo\!bar").is_empty());
    assert!(search("@x:>-1").is_empty());
}

#[test]
fn regex() {
    assert_eq!(search("@msg:foo~2"), vec![codes::DATADOG_REGEX]);
    assert_eq!(search("a^2"), vec![codes::DATADOG_REGEX]);
    assert!(search(r"a\~2").is_empty());
}

#[test]
fn cidr() {
    assert!(search("CIDR(@network.client.ip, 10.0.0.0/8, fc00::/7)").is_empty());
    assert!(search("CIDR(@ip,13.0.0.0/8)").is_empty());
    assert_eq!(
        search("CIDR(network.client.ip, 10.0.0.0/8)"),
        vec![codes::DATADOG_CIDR]
    );
    assert_eq!(search("CIDR(@ip, 10.0.0.300)"), vec![codes::DATADOG_CIDR]);
    assert_eq!(search("CIDR(@ip, 10.0.0.0/33)"), vec![codes::DATADOG_CIDR]);
    assert_eq!(search("CIDR(@ip, fc00::/129)"), vec![codes::DATADOG_CIDR]);
    assert_eq!(search("CIDR(@ip)"), vec![codes::DATADOG_CIDR]);
    assert!(check::is_cidr_block("10.0.0.1"));
}

#[test]
fn range() {
    assert!(search("@x:[1 TO 5]").is_empty());
    assert!(search("@x:{1 TO 5}").is_empty());
    assert!(search("@x:[* TO 5]").is_empty());
    assert!(search("@t:[2024-01-01T00:00:00 TO now]").is_empty());
    assert_eq!(search("@x:[1 to 5]"), vec![codes::DATADOG_RANGE]);
    let mixed = findings("@x:[1 TO 5}", Profile::Search);
    assert_eq!(mixed.len(), 1);
    assert_eq!(mixed[0].code, codes::DATADOG_RANGE);
    assert_eq!(mixed[0].severity, Severity::Warning);
    let lower = findings("@x:[1 to 5]", Profile::Search);
    assert_eq!(lower[0].severity, Severity::Error);
}

#[test]
fn mixed_boolean() {
    assert_eq!(
        search("service:x status:error OR warning"),
        vec![codes::DATADOG_MIXED_BOOLEAN]
    );
    assert_eq!(search("a OR b AND c"), vec![codes::DATADOG_MIXED_BOOLEAN]);
    assert_eq!(
        search("@SourceFileName:(*.exe OR *.rar *.7z OR *.tar)"),
        vec![codes::DATADOG_MIXED_BOOLEAN]
    );
    assert!(search("(a b) OR c").is_empty());
    assert!(search("a OR b OR c").is_empty());
    assert!(search("a b c").is_empty());
    let message = &findings("a OR b c", Profile::Search)[0].message;
    assert!(
        message.contains("`b c`") && message.contains("unverified"),
        "{message}"
    );
}

#[test]
fn lowercase_operator() {
    assert_eq!(
        search("@a:1 and @b:2"),
        vec![codes::DATADOG_LOWERCASE_OPERATOR]
    );
    assert_eq!(
        search("@t:(k OR n or E)"),
        vec![
            codes::DATADOG_MIXED_BOOLEAN,
            codes::DATADOG_LOWERCASE_OPERATOR
        ]
    );
    // Between free-text words it is just a word.
    assert!(search("not enough attributes").is_empty());
    assert!(search(r#"@p:("Anti-Spam and Email Security" OR IPS)"#).is_empty());
}

#[test]
fn curly_quote() {
    assert_eq!(
        search("@evt.name:“Console Login”"),
        vec![codes::DATADOG_CURLY_QUOTE]
    );
    assert_eq!(search("“hello world”"), vec![codes::DATADOG_CURLY_QUOTE]);
}

#[test]
fn wildcard_in_phrase() {
    assert_eq!(
        search(r#""*mimikatz*""#),
        vec![codes::DATADOG_WILDCARD_IN_PHRASE]
    );
    assert_eq!(
        search(r#"@a:"a?b""#),
        vec![codes::DATADOG_WILDCARD_IN_PHRASE]
    );
    assert!(search(r#"@db.statement:"SELECT *""#).is_empty());
    assert!(search(r#"@redis.severity: "*""#).is_empty());
}

#[test]
fn unescaped_colon() {
    assert_eq!(
        search("@usr.id:system:serviceaccount:x"),
        vec![codes::DATADOG_UNESCAPED_COLON]
    );
    assert!(search(r"@my_attribute:hello\:world").is_empty());
    // A tag is `key:value` by definition, as Datadog's docs search them.
    assert!(search("tags:(security-group:sg-123 AND role:common-node)").is_empty());
    assert!(search("tags:env:prod").is_empty());
}

#[test]
fn symbol_operator() {
    assert_eq!(search("a && b"), vec![codes::DATADOG_SYMBOL_OPERATOR]);
    assert_eq!(search("a || b"), vec![codes::DATADOG_SYMBOL_OPERATOR]);
    assert_eq!(
        shape("a && b || c"),
        "(QUERY (OR_EXPR (AND_EXPR TERM TERM) TERM))"
    );
    assert!(search("a&&b").is_empty());
}

#[test]
fn detached_operator() {
    assert_eq!(
        search("- @login_type:k"),
        vec![codes::DATADOG_DETACHED_OPERATOR]
    );
    assert!(search("-@login_type:k").is_empty());
}

#[test]
fn full_text_and_calculated_fields_in_a_rule() {
    assert_eq!(rule("*:mimikatz"), vec![codes::DATADOG_FULL_TEXT_IN_RULE]);
    assert!(search("*:mimikatz").is_empty());
    assert!(rule("*:*").is_empty());
    assert_eq!(
        rule("#duration_ms:>500"),
        vec![codes::DATADOG_CALCULATED_FIELD_IN_RULE]
    );
    assert!(search("#duration_ms:>500").is_empty());
}

#[test]
fn pipelines_only() {
    assert_eq!(
        search("_exists_:service"),
        vec![codes::DATADOG_PIPELINES_ONLY]
    );
    assert_eq!(
        search("_missing_:service"),
        vec![codes::DATADOG_PIPELINES_ONLY]
    );
    assert_eq!(
        search(r#""service.status":disabled"#),
        vec![codes::DATADOG_PIPELINES_ONLY]
    );
}

#[test]
fn unknown_attribute_is_a_hint() {
    let found = findings("evt.name:ConsoleLogin", Profile::Search);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].code, codes::DATADOG_UNKNOWN_ATTRIBUTE);
    assert_eq!(found[0].severity, Severity::Hint);
    assert!(search(r"evt\.name:x").is_empty());
    assert!(search("source:okta").is_empty());
}

#[test]
fn the_documented_examples_are_clean() {
    for clean in [
        "authentication",
        "\"hello world\"",
        "\"\"",
        "@evt.outcome:FAILURE",
        "source:okta",
        "service:web-api AND @http.status_code:[200 TO 299]",
        "@http.url:/api\\-v1/*",
        "waiting\\ un*",
        "web* a?b a**b",
        "-@level:Error -(a OR b) -\"x y\"",
        "@user_perms:(4 6)",
        "@attr:* -@attr:*",
        "NOT (status:debug)",
        "env:production NOT service:background-worker",
        "@network.ip.attributes.ip:2a02\\:1810*",
        "@http.status_code:[200 TO 299]-updated",
    ] {
        let found = search(clean);
        assert!(found.is_empty(), "{clean:?}: {found:?}");
    }
}

// ---- The single walk -----------------------------------------------------------------------

/// The walk visits each element of the tree once (ADR 0014 §5a): checks and highlight share it.
#[test]
fn one_walk_visits_each_element_once() {
    let source = "service:web (a OR b c) -@x:[1 TO 5] CIDR(@ip, 10.0.0.0/8) \"p\" @d:>=1ms";
    let (root, _) = parser::parse(source);
    let elements = root.descendants_with_tokens().count();
    let before = check::visits();
    let mut tokens = 0;
    check::walk(&root, source, Profile::Rule, |_, _| tokens += 1);
    assert_eq!(check::visits() - before, elements);
    assert!(tokens > 0);
    // `analyze_with` walks once too: the highlight is not a second walk.
    let before = check::visits();
    let result = analyze_with(source, &Context::RULE);
    assert_eq!(check::visits() - before, elements);
    assert!(!result.tokens.is_empty());
}

#[test]
fn the_highlight_has_the_captures_of_the_rfc() {
    let spec = opentide_highlight::HighlightSpec::shared().expect("spec");
    let source = "@evt.outcome:FAILURE source:x #d:>1 NOT a OR b @x:[1 TO 5] CIDR(@ip, 10.0.0.0/8) \"p\" w* \\:";
    let tokens = crate::highlight(spec, source);
    let capture_of = |text: &str| {
        let start = source.find(text).expect(text);
        tokens
            .iter()
            .find(|t| t.span.start == start)
            .map(|t| spec.legend[t.token_type as usize].clone())
    };
    assert_eq!(capture_of("@evt.outcome").as_deref(), Some("property"));
    assert_eq!(capture_of("source").as_deref(), Some("property"));
    assert_eq!(capture_of("#d").as_deref(), Some("variable"));
    assert_eq!(capture_of("NOT").as_deref(), Some("keyword"));
    assert_eq!(capture_of("OR").as_deref(), Some("keyword"));
    assert_eq!(capture_of("TO").as_deref(), Some("keyword"));
    assert_eq!(capture_of("CIDR").as_deref(), Some("function.builtin"));
    assert_eq!(capture_of("10.0.0.0").as_deref(), Some("constant"));
    assert_eq!(capture_of("\"p\"").as_deref(), Some("string"));
    assert_eq!(capture_of("[").as_deref(), Some("punctuation.bracket"));
    assert_eq!(capture_of(", 10").as_deref(), Some("punctuation.delimiter"));
    assert_eq!(capture_of("*").as_deref(), Some("operator"));
    assert_eq!(capture_of("\\:").as_deref(), Some("constant"));
    assert_eq!(capture_of(">1").as_deref(), Some("operator"));
    assert_eq!(capture_of("1 TO").as_deref(), Some("number"));
    let _ = K::QUERY;
}
