//! Graylog queries are Lucene in the Graylog dialect (graylog-1.0): a query
//! file under `--platform graylog`. The `configurations.graylog` block's
//! query, hover and completion come with the Graylog block port.

use opentide_analysis::{LanguageId, QueryRequest, analyze_query, codes};

#[test]
fn a_query_file_takes_the_platform_dialect() {
    let request = |platform: Option<&str>| QueryRequest {
        language: LanguageId::Lucene,
        platform: platform.map(str::to_string),
        stack: None,
        text: "message:/(?i)fail.*/".into(),
    };
    let graylog: Vec<String> = analyze_query(&request(Some("graylog")))
        .into_iter()
        .map(|d| d.code)
        .collect();
    assert!(
        graylog.contains(&codes::GRAYLOG_REGEX_UNSUPPORTED.to_string())
            && graylog.contains(&codes::GRAYLOG_ANALYZED_FIELD.to_string()),
        "{graylog:?}"
    );
    let elastic: Vec<String> = analyze_query(&request(None))
        .into_iter()
        .map(|d| d.code)
        .collect();
    assert!(
        !elastic.iter().any(|c| c.starts_with("graylog_")),
        "{elastic:?}"
    );
}
