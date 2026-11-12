use super::*;
use opentide_core::Severity;

fn codes_of(text: &str, profile: Profile) -> Vec<&'static str> {
    check(text, profile)
        .findings
        .iter()
        .map(|f| f.code)
        .collect()
}

#[test]
fn profiles() {
    let query = r#"SELECT user WHERE activity_type:"app-login""#;
    assert_eq!(
        codes_of(query, Profile::Rule),
        [codes::EXABEAM_ADVANCED_IN_RULE]
    );
    assert!(codes_of(query, Profile::Search).is_empty());
    assert!(check(r#"vendor:"a" | SELECT vendor"#, Profile::Search).advanced);
    assert!(!check(r#"vendor:"a" AND NOT b:"c""#, Profile::Search).advanced);
    // An empty search queries every log; an empty sequence is an error.
    assert!(codes_of("", Profile::Search).is_empty());
    assert_eq!(codes_of(" \n", Profile::Rule), [codes::EXABEAM_PARSE_ERROR]);
    // A `.exabeam` file is a search.
    assert!(analyze(query).diagnostics.is_empty());
}

#[test]
fn unknown_fields_are_warnings() {
    let r = analyze_with(
        r#"ScriptBlockText:"Invoke-Mimikatz" AND src_ipp:"10.0.0.1""#,
        &Context::RULE,
    );
    let unknown: Vec<&Diagnostic> = r
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::EXABEAM_UNKNOWN_FIELD)
        .collect();
    assert_eq!(unknown.len(), 2, "{:?}", r.diagnostics);
    assert!(unknown.iter().all(|d| d.severity == Severity::Warning));
    assert!(unknown[1].message.contains("did you mean `src_ip`"));
    assert_eq!(unknown[0].range.start.character, 0);
    assert_eq!(unknown[0].range.end.character, 15);
}

#[test]
fn known_fields_are_case_insensitive_prefixed_platform_or_aliases() {
    for query in [
        r#"SRC_IP:"10.0.0.1""#,
        r#"c_custom:"x" AND m_ingest_host:"y""#,
        "approxLogTime:[1730000000000 TO *] AND ingest_time:[* TO 1730000000000]",
        r#"raw_log_time:[2026-11-01T00:00:00Z TO *] AND rawLogIds:"a""#,
        r#"src_ip.country:"FR""#,
    ] {
        let found: Vec<&str> = codes_of(query, Profile::Rule)
            .into_iter()
            .filter(|c| *c == codes::EXABEAM_UNKNOWN_FIELD)
            .collect();
        assert!(found.is_empty(), "{query}: {found:?}");
    }
    // An `AS` name defined earlier is a field; one defined later is not.
    let query = r#"SELECT user, COUNT(*) AS failures GROUP-BY user ORDER-BY failures DESC"#;
    assert!(codes_of(query, Profile::Search).is_empty());
    let query = r#"SELECT failures WHERE vendor:"a" | SELECT user AS failures"#;
    assert!(
        codes_of(query, Profile::Search).contains(&codes::EXABEAM_UNKNOWN_FIELD),
        "{:?}",
        codes_of(query, Profile::Search)
    );
}

#[test]
fn numbers_on_string_fields() {
    let r = analyze_with("event_code:4625 AND dest_port:445", &Context::RULE);
    let found: Vec<(&str, Severity)> = r
        .diagnostics
        .iter()
        .map(|d| (d.code.as_str(), d.severity))
        .collect();
    assert_eq!(
        found,
        [(codes::EXABEAM_STRING_FIELD_NUMBER, Severity::Warning)]
    );
    assert!(r.diagnostics[0].message.contains("\"4625\""));
    assert!(
        codes_of(r#"event_code:("4625", 4771)"#, Profile::Rule)
            .contains(&codes::EXABEAM_STRING_FIELD_NUMBER)
    );
    // A comparison is numeric: no quote is asked for.
    assert!(codes_of("event_code > 4000", Profile::Rule).is_empty());
}

#[test]
fn foreign_functions_name_the_exabeam_form() {
    for (query, form) in [
        (r#"cmd: contains("-enc")"#, "WLD(\"*x*\")"),
        (r#"cmd: startswith("ps")"#, "RGX(\"^x\")"),
        (r#"cmd: endswith("ps")"#, "RGX(\"x$\")"),
        (r#"src_ip: cidr("10.0.0.0/8")"#, "[a.b.c.d/n]"),
        ("src_ip: exists()", "NOT field:null"),
    ] {
        let r = analyze_with(query, &Context::RULE);
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::EXABEAM_UNKNOWN_FUNCTION)
            .unwrap_or_else(|| panic!("{query}: {:?}", r.diagnostics));
        assert!(d.message.contains(form), "{query}: {}", d.message);
    }
    let r = analyze_with(r#"user != "SYSTEM""#, &Context::RULE);
    assert!(r.diagnostics[0].message.contains("NOT user:value"));
}

#[test]
fn deep_nesting_is_a_parse_error_not_a_crash() {
    let deep = format!("{}a:\"b\"{}", "(".repeat(5000), ")".repeat(5000));
    let found = codes_of(&deep, Profile::Rule);
    assert!(found.contains(&codes::EXABEAM_PARSE_ERROR), "{found:?}");
    let nots = format!("{}a:\"b\"", "NOT ".repeat(5000));
    assert!(codes_of(&nots, Profile::Rule).contains(&codes::EXABEAM_PARSE_ERROR));
    // A long flat query is fine.
    let wide = vec![r#"process_name:"a.exe""#; 3000].join(" OR ");
    assert!(codes_of(&wide, Profile::Rule).is_empty());
}

#[test]
fn ranges_never_split_a_character() {
    for query in [
        "é",
        "user:\"é",
        "日本 AND",
        "src_ip:[😀 TO 1]",
        "a:RGX(\"\\😀\")",
        "(((",
        "user != é",
    ] {
        for profile in [Profile::Rule, Profile::Search] {
            let r = analyze_with(query, &Context { profile });
            for d in &r.diagnostics {
                assert!(
                    (d.range.start.line, d.range.start.character)
                        <= (d.range.end.line, d.range.end.character),
                    "{query}: {d:?}"
                );
            }
            for f in check(query, profile).findings {
                assert!(
                    query.is_char_boundary(f.start.min(query.len())),
                    "{query}: {f:?}"
                );
                assert!(
                    query.is_char_boundary(f.end.min(query.len())),
                    "{query}: {f:?}"
                );
            }
        }
    }
}

#[test]
fn highlighting_uses_the_spec_captures() {
    let spec = HighlightSpec::load().unwrap();
    let text = r#"user IN "Admins"."Name" AND src_ip:[10.0.0.0/8] AND a:RGXi("x") AND parsed:true AND dest_port:null AND user != "x" | SELECT COUNT(*) AS n"#;
    let caps: Vec<(String, String)> = highlight(&spec, text)
        .into_iter()
        .map(|t| (text[t.span.start..t.span.end].to_string(), t.capture))
        .collect();
    for (token, capture) in [
        ("user", "property"),
        ("IN", "keyword"),
        ("\"Admins\"", "type"),
        (".", "punctuation.delimiter"),
        ("10.0.0.0/8", "constant"),
        ("RGXi", "function.builtin"),
        ("true", "boolean"),
        ("null", "constant"),
        ("!=", "error"),
        ("|", "operator.pipe"),
        ("COUNT", "function.builtin"),
        ("*", "operator"),
        ("n", "variable"),
    ] {
        assert!(
            caps.contains(&(token.to_string(), capture.to_string())),
            "{token} {capture}: {caps:?}"
        );
    }
}

#[test]
fn hover_and_completion_from_the_catalogue() {
    let h = hover(r#"src_ip:"10.0.0.1""#, 2).unwrap();
    assert!(h.contains("ipv4/ipv6"), "{h}");
    let h = hover(r#"activity_type:"process-create""#, 18).unwrap();
    assert!(h.contains("process"), "{h}");
    let h = hover(r#"subject:"process""#, 10).unwrap();
    assert!(h.contains("`subject`"), "{h}");
    let h = hover(r#"a:RGXi("x")"#, 3).unwrap();
    assert!(h.contains("case-insensitively"), "{h}");
    let h = hover(r#"a:"x" AND b:"y""#, 7).unwrap();
    assert!(h.starts_with("`AND`"), "{h}");
    let h = hover(r#"approxLogTime:[1 TO *]"#, 3).unwrap();
    assert!(h.contains("platform field"), "{h}");
    assert!(hover(r#"c_my_field:"x""#, 3).unwrap().contains("custom"));
    assert!(
        hover("src_host: @dest_host", 13)
            .unwrap()
            .contains("dest_host")
    );

    let items = completions(r#"activity_type:""#, 15);
    assert!(items.iter().any(|i| i.label == "process-create"));
    let items = completions("outcome:", 8);
    assert_eq!(
        items.iter().map(|i| i.label.as_str()).collect::<Vec<_>>(),
        ["fail", "success"]
    );
    let items = completions("src", 3);
    assert!(items.iter().any(|i| i.label == "src_ip"));
    assert!(items.iter().any(|i| i.label == "RGXi"));
    assert!(items.iter().any(|i| i.label == "GROUP-BY"));
}

#[test]
fn every_language_code_is_described_and_classified() {
    for code in check::LANGUAGE_CODES {
        assert!(codes::describe(code).is_some(), "{code}");
    }
    assert_eq!(
        WARNINGS
            .iter()
            .filter(|w| check::LANGUAGE_CODES.contains(w))
            .count(),
        WARNINGS.len()
    );
}
