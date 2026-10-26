//! Public ES|QL, EQL, and Lucene queries, plus the same queries with one
//! injected fault.
//!
//! Sources and licences: `testdata/conformance/external/SOURCES.md` (SigmaHQ
//! rules under the Detection Rule License 1.1, converted with pySigma). Unlike
//! the v1 KQL and SPL sets, the Elastic grammars accept every public query
//! whole, so no prefix is taken: a public query must produce no error, and its
//! `.broken.` twin must produce one.

use opentide_core::{Diagnostic, LanguageId, Severity};
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn analyze(language: LanguageId, text: &str) -> Vec<Diagnostic> {
    match language {
        LanguageId::Esql => opentide_esql::analyze(text).diagnostics,
        LanguageId::Eql => opentide_eql::analyze(text).diagnostics,
        LanguageId::Lucene => opentide_lucene::analyze(text).diagnostics,
        _ => unreachable!(),
    }
}

/// Public queries that Elasticsearch itself rejects, with the error the
/// engine must report. pySigma's EQL backend writes numbers as `field:4624`;
/// `:` takes only strings, and every release rejects it on a keyword or
/// numeric field (testdata/oracles/elasticsearch/eql-argument-types).
const REJECTED: &[(&str, &str)] = &[(
    "eql/win_security_access_token_abuse.eql",
    "eql_argument_type",
)];

fn errors(diagnostics: &[Diagnostic]) -> Vec<&str> {
    diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.code.as_str())
        .collect()
}

#[test]
fn public_elastic_queries_and_fault_twins() {
    for (id, language) in [
        ("esql", LanguageId::Esql),
        ("eql", LanguageId::Eql),
        ("lucene", LanguageId::Lucene),
    ] {
        let dir = repo_root().join("testdata/conformance/external").join(id);
        let mut checked = 0;
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.contains(".broken.") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            let found = analyze(language, &text);
            let key = format!("{id}/{name}");
            match REJECTED.iter().find(|(k, _)| *k == key) {
                Some((_, code)) => assert!(
                    errors(&found).iter().all(|c| c == code) && !errors(&found).is_empty(),
                    "{key}: Elasticsearch rejects it; expected only {code} errors: {found:?}"
                ),
                None => assert!(
                    errors(&found).is_empty(),
                    "{key} is a public query and must not error: {found:?}"
                ),
            }
            let broken_name = name.replacen(&format!(".{id}"), &format!(".broken.{id}"), 1);
            let broken = fs::read_to_string(dir.join(&broken_name))
                .unwrap_or_else(|_| panic!("missing {id}/{broken_name}"));
            assert_ne!(broken, text, "{id}/{broken_name} has no injected fault");
            assert!(
                !errors(&analyze(language, &broken)).is_empty(),
                "{id}/{broken_name}: the injected fault was not diagnosed"
            );
            checked += 1;
        }
        assert!(
            checked >= 10,
            "expected a public {id} corpus, found {checked}"
        );
    }
}
