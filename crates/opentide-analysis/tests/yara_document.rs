//! An editor's analysis of a `.yar` file builds one YARA AST for its
//! diagnostics and its outline (ADR 0014, rule 7): it built one for each.

use opentide_analysis::{AnalyzeRequest, LanguageId, MemoryWorkspace, analyze};

#[cfg(debug_assertions)]
#[test]
fn a_yara_file_is_parsed_once_per_analysis() {
    let host = MemoryWorkspace::default();
    let text = "rule a { strings: $s = \"x\" condition: $s }\nrule b { condition: a }";
    let before = opentide_yara::asts_built();
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: "/w/rules.yar".into(),
            language: LanguageId::Yara,
            text: text.into(),
        },
    );
    assert_eq!(opentide_yara::asts_built() - before, 1);
    let names: Vec<&str> = response.symbols.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["a", "$s", "b"]);
}
