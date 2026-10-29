//! The engines against recorded live-Elasticsearch verdicts.
//!
//! `testdata/oracles/elasticsearch/<topic>/*` are probes run against real
//! clusters, 8.19 through 9.5 (`scripts/oracles/elasticsearch/probes.py`);
//! `expected.tsv` records the verdict per release line. This test needs no
//! cluster. It holds the engines to those verdicts:
//!
//! - rejected on every release: the engine reports an Error;
//! - accepted on every release: the engine reports no Error;
//! - accepted on some releases only: no Error, and some diagnostic naming the
//!   version gap.
//!
//! Lucene cells are `<strict>/<lenient>`. Elastic Security runs `query_string`
//! with `lenient: false` (Kibana's default `query:queryString:options`), so the
//! strict verdict counts. `EXCEPTIONS` lists the probes the engine cannot
//! decide statically, with the reason.
//!
//! The fixture index maps every ECS field with its ECS type, so the probes
//! ran against ECS documents. The second test adds the ECS checks a rule on
//! ECS indices gets (`ecs_diagnostics`): the probes that depend on the
//! mapping must then agree too, except `ECS_EXCEPTIONS`.

use opentide_core::{Diagnostic, LanguageId, Severity};
use std::fs;
use std::path::PathBuf;

/// Probes the engine cannot decide from the query text, with the reason. A
/// listed probe that the engine now agrees with fails the test, so the list
/// stays exact.
const EXCEPTIONS: &[(&str, &str)] = &[
    // The verdict follows the field's mapping. ECS types are only a
    // default: a tenant may map the field otherwise, so the engine hints.
    ("eql-argument-types/arithmetic_keyword_field.eql", MAPPING),
    ("eql-argument-types/cidrmatch_keyword_field.eql", MAPPING),
    ("eql-argument-types/colon_string_long_field.eql", MAPPING),
    ("eql-argument-types/in_number_keyword_field.eql", MAPPING),
    ("eql-argument-types/length_long_field.eql", MAPPING),
    ("eql-argument-types/like_number_long_field.eql", MAPPING),
    ("eql-argument-types/number_long_field.eql", MAPPING),
    ("eql-argument-types/startswith_long_field.eql", MAPPING),
    ("eql-field-comparison/optional_mapped_both.eql", MAPPING),
    ("eql-field-comparison/optional_mapped_left.eql", MAPPING),
    ("eql-misc/object_field.eql", MAPPING),
    ("lucene/range_type_mismatch_long.lucene", MAPPING),
    ("lucene/regexp_long.lucene", MAPPING),
    ("lucene/type_mismatch_boolean.lucene", MAPPING),
    ("lucene/type_mismatch_date.lucene", MAPPING),
    ("lucene/type_mismatch_ip.lucene", MAPPING),
    ("lucene/type_mismatch_long.lucene", MAPPING),
    ("lucene/wildcard_long.lucene", MAPPING),
    // 8.19-9.3 reject `*foo*` on the default field because the fixture maps
    // a constant_keyword field; 9.4 skips such fields.
    ("lucene/bare_leading_wildcard_default_field.lucene", MAPPING),
    // Accepted only because the fixture does not map `winlog.event_id`
    // (an `unverified:` OK). `: <number>` is rejected on every mapped type
    // and on optional fields, so the engine's error stands.
    (
        "eql-argument-types/colon_number_unmapped.eql",
        "fixture does not map the field",
    ),
    // The 9.6 grammar accepts these; no 9.6 release is recorded yet, so the
    // engine reports the version gap instead of an error.
    ("esql-syntax/eval_no_space.esql", NEWER),
    ("esql-syntax/where_no_space.esql", NEWER),
    ("esql-syntax/like_non_literal.esql", NEWER),
    // `??f` is valid syntax; the request did not bind the parameter.
    (
        "esql-syntax/identifier_parameter_unbound.esql",
        "parameters are bound per request",
    ),
    // 9.x rejects the option name `x`, not the nested map; MATCH option
    // names are not checked.
    (
        "esql-syntax/map_nested.esql",
        "MATCH option names are not checked",
    ),
];

/// Probes the ECS checks still cannot decide, with the reason.
const ECS_EXCEPTIONS: &[(&str, &str)] = &[
    // Comparing two fields is `eql_field_comparison`, not a type check: an
    // optional field stays a warning even when ECS maps it.
    (
        "eql-field-comparison/optional_mapped_both.eql",
        "an optional field compared with a field stays a warning",
    ),
    (
        "eql-field-comparison/optional_mapped_left.eql",
        "an optional field compared with a field stays a warning",
    ),
    // No field: the default field's mapping is the cluster's.
    ("lucene/bare_leading_wildcard_default_field.lucene", MAPPING),
];

const MAPPING: &str = "depends on the tenant's field mapping";
const NEWER: &str = "accepted by the 9.6 grammar";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/oracles/elasticsearch")
}

/// The engine's diagnostics; with `ecs`, plus the ECS checks a rule whose
/// indices hold ECS documents gets. ES|QL reads its indices from `FROM`.
fn analyze(language: LanguageId, text: &str, ecs: bool) -> Vec<Diagnostic> {
    let (mut found, extra) = match language {
        LanguageId::Esql => (opentide_esql::analyze(text).diagnostics, Vec::new()),
        LanguageId::Eql => (
            opentide_eql::analyze(text).diagnostics,
            if ecs {
                opentide_eql::ecs_diagnostics(text)
            } else {
                Vec::new()
            },
        ),
        _ => (
            opentide_lucene::analyze(text).diagnostics,
            if ecs {
                opentide_lucene::ecs_diagnostics(text)
            } else {
                Vec::new()
            },
        ),
    };
    opentide_ecs::merge(&mut found, extra);
    found
}

#[test]
fn engines_agree_with_live_elasticsearch() {
    disagreements(false, EXCEPTIONS);
}

#[test]
fn engines_with_ecs_agree_with_live_elasticsearch() {
    let exceptions: Vec<(&str, &str)> = EXCEPTIONS
        .iter()
        .filter(|(_, reason)| *reason != MAPPING)
        .chain(ECS_EXCEPTIONS)
        .copied()
        .collect();
    disagreements(true, &exceptions);
}

fn disagreements(ecs: bool, exceptions: &[(&str, &str)]) {
    let expected = fs::read_to_string(root().join("expected.tsv")).unwrap();
    let mut problems = Vec::new();
    let mut checked = 0;
    for line in expected.lines().skip(1) {
        let mut cells = line.split('\t');
        let probe = cells.next().unwrap();
        let verdicts: Vec<&str> = cells
            .filter(|c| !c.is_empty())
            .map(|c| c.split('/').next().unwrap())
            .collect();
        if verdicts.is_empty() {
            continue;
        }
        let language = match probe.rsplit('.').next() {
            Some("eql") => LanguageId::Eql,
            Some("esql") => LanguageId::Esql,
            Some("lucene") => LanguageId::Lucene,
            _ => continue,
        };
        let text = fs::read_to_string(root().join(probe)).unwrap();
        let found = analyze(language, text.trim_end(), ecs);
        let errors: Vec<&Diagnostic> = found
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        let all_err = verdicts.iter().all(|v| *v == "ERR");
        let all_ok = verdicts.iter().all(|v| *v == "OK");
        let summary = |ds: &[Diagnostic]| {
            ds.iter()
                .map(|d| format!("{}:{:?}", d.code, d.severity))
                .collect::<Vec<_>>()
                .join(", ")
        };
        checked += 1;
        let disagrees = (all_err && errors.is_empty())
            || (all_ok && !errors.is_empty())
            || (!all_err && !all_ok && (!errors.is_empty() || found.is_empty()));
        if let Some((_, reason)) = exceptions.iter().find(|(p, _)| *p == probe) {
            if !disagrees {
                problems.push(format!(
                    "{probe}: listed in EXCEPTIONS ({reason}) but the engine agrees; remove it"
                ));
            }
            continue;
        }
        if all_err && errors.is_empty() {
            problems.push(format!(
                "{probe}: Elasticsearch rejects it everywhere; engine: [{}]",
                summary(&found)
            ));
        } else if all_ok && !errors.is_empty() {
            problems.push(format!(
                "{probe}: Elasticsearch accepts it everywhere; engine: [{}]",
                summary(&found)
            ));
        } else if !all_err && !all_ok && (!errors.is_empty() || found.is_empty()) {
            problems.push(format!(
                "{probe}: accepted on some releases ({}); engine: [{}]",
                verdicts.join(" "),
                summary(&found)
            ));
        }
    }
    assert!(checked > 150, "expected the recorded probes");
    assert!(
        problems.is_empty(),
        "{} probes disagree:\n{}",
        problems.len(),
        problems.join("\n")
    );
}
