use opentide_analysis::highlight;
use opentide_core::LanguageId;
use opentide_highlight::tokens_to_html;

#[test]
fn kql_keyword_tokens_and_html_spans() {
    let src = "SecurityEvent | where EventID == 1 | take 1";
    let r = highlight(LanguageId::Kql, src);
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "keyword" && &src[t.span.start..t.span.end] == "where"),
        "{:?}",
        r.tokens
    );
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "keyword" && &src[t.span.start..t.span.end] == "take"),
        "{:?}",
        r.tokens
    );
    let html = tokens_to_html(src, &r.tokens);
    assert!(
        html.contains("<span class=\"keyword\">where</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"keyword\">take</span>"),
        "{html}"
    );
    assert!(html.contains("#c586c0"), "{html}");
    assert!(html.contains("#ff79c6"), "{html}");
}

#[test]
fn spl_keyword_tokens_and_html_spans() {
    let src = "index=main | stats count by host | head 1";
    let r = highlight(LanguageId::Spl, src);
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "keyword" && &src[t.span.start..t.span.end] == "stats"),
        "{:?}",
        r.tokens
    );
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "keyword" && &src[t.span.start..t.span.end] == "head"),
        "{:?}",
        r.tokens
    );
    let html = tokens_to_html(src, &r.tokens);
    assert!(
        html.contains("<span class=\"keyword\">stats</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"keyword\">head</span>"),
        "{html}"
    );
}

#[test]
fn tide_html_colors_object_values() {
    let src = r#"
name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
status: STAGING
configurations:
  sentinel:
    enabled: true
    query: |
      SecurityEvent
      | take 1
"#;
    let r = highlight(LanguageId::TideYaml, src);
    let html = tokens_to_html(src, &r.tokens);
    assert!(
        html.contains("<span class=\"tide-uuid\">00000000-0000-4000-8003-000000000001</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"tide-schema\">rule::1.0</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"boolean\">true</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"constant\">STAGING</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"keyword\">take</span>"),
        "{html}"
    );
}

#[test]
fn tide_markdown_text_fields_are_multi_tier() {
    let src = "name: X\ndescription: |-\n  #### Heading\n  use `DeviceFileEvents`\n  - list item\n";
    let r = highlight(LanguageId::TideYaml, src);
    let html = tokens_to_html(src, &r.tokens);
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "markdown.heading"
                && src[t.span.start..t.span.end].contains("####")),
        "{:?}",
        r.tokens
    );
    assert!(html.contains("markdown-heading"), "{html}");
    assert!(
        html.contains("markdown-code") || html.contains("`DeviceFileEvents`"),
        "{html}"
    );
}
