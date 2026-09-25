use opentide_analysis::highlight;
use opentide_core::LanguageId;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn golden(dir: &str, name: &str, language: LanguageId, src: &str) {
    let result = highlight(language, src);
    let captures: Vec<&str> = result.tokens.iter().map(|t| t.capture.as_str()).collect();
    let path = repo_root()
        .join("testdata/highlight")
        .join(dir)
        .join(format!("{name}.json"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    if std::env::var("UPDATE_GOLDENS").ok().as_deref() == Some("1") || !path.exists() {
        fs::write(&path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    }
    let expected: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let expected_captures: Vec<&str> = expected["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["capture"].as_str().unwrap())
        .collect();
    for cap in &expected_captures {
        assert!(
            captures.contains(cap),
            "{dir}/{name}: missing capture {cap} in {captures:?}"
        );
    }
}

#[test]
fn kql_golden() {
    golden(
        "kql",
        "pipeline",
        LanguageId::Kql,
        "SecurityEvent | where EventID == 4688 | take 1",
    );
}

#[test]
fn spl_golden() {
    golden(
        "spl",
        "pipeline",
        LanguageId::Spl,
        "index=main | stats count by host | head 1",
    );
}

#[test]
fn tide_golden_includes_host_and_injected_captures() {
    let src = r#"
name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
configurations:
  sentinel:
    query: |
      SecurityEvent
      | where EventID == 4688
"#;
    golden("tide", "sentinel_injection", LanguageId::TideYaml, src);
    let result = highlight(LanguageId::TideYaml, src);
    assert!(result.tokens.iter().any(|t| t.capture == "tide.property"));
    assert!(
        result
            .tokens
            .iter()
            .any(|t| t.capture == "keyword" || t.capture == "type" || t.capture == "operator.pipe")
    );
}
