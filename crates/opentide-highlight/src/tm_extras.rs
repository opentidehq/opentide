//! The TextMate grammar's rules beyond the `KEYWORDS` table (a query
//! language's functions, fields, boolean operators and leading table name),
//! so the first paint, before the language server's semantic tokens arrive,
//! is not monochrome.
//!
//! Every scope is a `HighlightSpec` capture's `tm` (`function`,
//! `function.builtin`, `property`, `type`), so the themes colour them as they
//! colour the semantic tokens of the same capture; the one scope that is no
//! capture, [`LOGICAL_SCOPE`], is a standard `keyword.operator.*` scope. No
//! colour is chosen here. A rule is a heuristic over text, not a parse: what
//! it gets wrong, the server's tokens repaint.
//!
//! Order matters in TextMate (the first pattern that matches at the earliest
//! position wins): [`before_keywords`] holds the rules that must beat a
//! keyword (a field before a comparison, a built-in call, a boolean
//! operator), [`after_keywords`] those a keyword must beat (`in (`, `where (`
//! are no calls; a statement's first word may be a command).

use crate::{HighlightSpec, function_names};
use opentide_core::LanguageId;
use serde_json::{Value, json};

/// A boolean operator (`and`, `or`, `not`): not a HighlightSpec capture.
pub(crate) const LOGICAL_SCOPE: &str = "keyword.operator.logical.opentide";

fn scope(spec: &HighlightSpec, capture: &str, fallback: &str) -> String {
    spec.captures
        .get(capture)
        .map_or_else(|| fallback.to_string(), |maps| maps.tm.clone())
}

/// The built-in function names of a language's catalog.
fn builtins(language: LanguageId) -> &'static [&'static str] {
    match language {
        LanguageId::Kql => function_names::KQL,
        LanguageId::Esql => function_names::ESQL,
        LanguageId::Eql => function_names::EQL,
        LanguageId::Cql => function_names::CQL,
        LanguageId::Yaral => function_names::YARAL,
        _ => &[],
    }
}

/// The comparison a field stands before, as a lookahead body.
fn comparison(language: LanguageId) -> String {
    let symbols = match language {
        // `field:value`; `:=` assigns in CQL.
        LanguageId::Kuery
        | LanguageId::Lucene
        | LanguageId::Cql
        | LanguageId::Exabeam
        | LanguageId::Datadog => r"==|!=|=~|!~|<=|>=|:=|=|<|>|:",
        _ => r"==|!=|=~|!~|<=|>=|:=|=|<|>",
    };
    let words = match language {
        LanguageId::Kql => {
            r"|!?(?:has(?:_any|_all|cs)?|contains(?:cs)?|startswith(?:cs)?|endswith(?:cs)?|in~?|between|like)\b|matches\s+regex\b"
        }
        LanguageId::Esql => r"|(?:not\s+)?(?:like|rlike|in)\b|is\s+(?:not\s+)?null\b",
        LanguageId::Eql => r"|(?:not\s+)?(?:in~?|like~?|regex~?|:)\b",
        LanguageId::Spl => r"|(?i:in)\b",
        LanguageId::Falco => {
            r"|(?:i?contains|i?startswith|endswith|in|pmatch|glob|exists|intersects|bcontains|bstartswith)\b"
        }
        _ => "",
    };
    format!(r"(?i:{symbols}{words})")
}

/// Whether the language has fields before a comparison worth a rule.
fn has_field_rule(language: LanguageId) -> bool {
    !matches!(language, LanguageId::TideYaml | LanguageId::Config)
}

/// Whether a call `name(` is a function in the language.
fn has_call_rule(language: LanguageId) -> bool {
    matches!(
        language,
        LanguageId::Kql
            | LanguageId::Esql
            | LanguageId::Eql
            | LanguageId::Spl
            | LanguageId::Cql
            | LanguageId::Exabeam
            | LanguageId::Yara
            | LanguageId::Yaral
    )
}

/// Rules that must win over a keyword at the same position.
pub(crate) fn before_keywords(language: LanguageId, spec: &HighlightSpec) -> Vec<Value> {
    let mut rules = Vec::new();
    let property = scope(spec, "property", "variable.other.property");
    let type_scope = scope(spec, "type", "entity.name.type");
    let builtin = scope(spec, "function.builtin", "support.function");
    let keyword = scope(spec, "keyword", "keyword.control");

    if language == LanguageId::Esql {
        // `FROM logs-*, other` and `EXPLAIN`'s subquery: the source indices.
        rules.push(json!({
            "match": r"(?i)(?<![\w.])(from)(\s+)([^\s|,()=]+(?:\s*,\s*[^\s|,()=]+)*)",
            "captures": {
                "1": { "name": keyword },
                "3": { "name": type_scope },
            },
            "comment": "tm_extras:esql-source",
        }));
    }
    let names = builtins(language);
    if !names.is_empty() {
        let mut sorted: Vec<&str> = names.to_vec();
        sorted.sort_by_key(|n| std::cmp::Reverse(n.len()));
        let alternation = sorted
            .iter()
            .map(|n| regex::escape(n))
            .collect::<Vec<_>>()
            .join("|");
        rules.push(json!({
            "name": builtin,
            "match": format!(r"(?i)(?<![\w.$@#:])(?:{alternation})(?=\s*\()"),
            "comment": "tm_extras:builtin-call",
        }));
    }
    if has_field_rule(language) {
        rules.push(json!({
            "name": property,
            "match": format!(
                r"(?<![\w.$@#])[$@#]?[A-Za-z_][\w.]*(?=\s*{})",
                comparison(language)
            ),
            "comment": "tm_extras:field",
        }));
    }
    let logical = match language {
        LanguageId::Kuery | LanguageId::Cql => Some(r"(?i)(?<![\w.])(?:and|or|not)(?![\w.])"),
        // Upper case only: a lower-case `and` is a search term.
        LanguageId::Lucene | LanguageId::Datadog => Some(r"(?<![\w.])(?:AND|OR|NOT)(?![\w.])"),
        _ => None,
    };
    if let Some(logical) = logical {
        rules.push(json!({
            "name": LOGICAL_SCOPE,
            "match": logical,
            "comment": "tm_extras:logical",
        }));
    }
    rules
}

/// Rules a keyword at the same position must win over.
pub(crate) fn after_keywords(
    language: LanguageId,
    spec: &HighlightSpec,
    pairs: &[(String, String)],
) -> Vec<Value> {
    let mut rules = Vec::new();
    let function = scope(spec, "function", "entity.name.function");
    let type_scope = scope(spec, "type", "entity.name.type");
    if language == LanguageId::Kql {
        // A statement's table: a line holding one name, alone or before a
        // pipe. A word of the keyword table is a command, not a table.
        let words: std::collections::BTreeSet<String> = pairs
            .iter()
            .filter(|(token, capture)| {
                capture == "keyword" && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
            .map(|(token, _)| regex::escape(token))
            .collect();
        let not_keyword = if words.is_empty() {
            String::new()
        } else {
            format!(
                "(?i:(?!(?:{})\\b))",
                words.iter().cloned().collect::<Vec<_>>().join("|")
            )
        };
        rules.push(json!({
            "match": format!(
                r"^(\s*)({not_keyword}[A-Za-z_]\w*)(?=\s*(?:$|\|))"
            ),
            "captures": { "2": { "name": type_scope } },
            "comment": "tm_extras:table",
        }));
    }
    let operator = scope(spec, "operator", "keyword.operator");
    let boolean = scope(spec, "boolean", "constant.language.boolean");
    let variable = scope(spec, "variable", "variable.other");
    let property = scope(spec, "property", "variable.other.property");
    if language == LanguageId::Yaral {
        // `$e.principal.hostname`: a placeholder's path is fields; a bare
        // `$name` is a variable.
        rules.push(json!({
            "name": property,
            "match": r"\$[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+",
            "comment": "tm_extras:placeholder-path",
        }));
        rules.push(json!({
            "name": variable,
            "match": r"\$[A-Za-z_]\w*",
            "comment": "tm_extras:placeholder",
        }));
    }
    let word_operators = match language {
        LanguageId::Kql => Some(r"(?i)(?<![\w.])!?(?:in|between)~?(?![\w.])"),
        LanguageId::Spl => Some(r"(?i)(?<![\w.])in(?![\w.])"),
        LanguageId::Eql => Some(r"(?i)(?<![\w.])(?:in|like|regex)~?(?![\w.])"),
        LanguageId::Esql => Some(r"(?i)(?<![\w.])(?:in|like|rlike|is)(?![\w.])"),
        LanguageId::Falco => Some(
            r"(?<![\w.])(?:i?contains|bcontains|i?startswith|bstartswith|endswith|exists|intersects|pmatch|i?glob|in)(?![\w.])",
        ),
        _ => None,
    };
    if let Some(words) = word_operators {
        rules.push(json!({
            "name": operator,
            "match": words,
            "comment": "tm_extras:word-operator",
        }));
    }
    if !matches!(
        language,
        LanguageId::Kuery
            | LanguageId::Lucene
            | LanguageId::Exabeam
            | LanguageId::Datadog
            | LanguageId::TideYaml
            | LanguageId::Config
    ) {
        rules.push(json!({
            "name": boolean,
            "match": r"(?i)(?<![\w.$@#])(?:true|false)(?![\w.])",
            "comment": "tm_extras:boolean",
        }));
    }
    if has_call_rule(language) {
        let name = if language == LanguageId::Cql {
            r"[A-Za-z_][\w.]*(?::\w+)?"
        } else {
            r"[A-Za-z_][\w.]*"
        };
        rules.push(json!({
            "name": function,
            "match": format!(r"(?<![\w.$@#:]){name}(?=\s*\()"),
            "comment": "tm_extras:call",
        }));
    }
    if language == LanguageId::Datadog {
        // What is left of a Datadog search is a term: a value, as the semantic tokens colour
        // it (a run of term characters; wildcards, escapes and punctuation stay their own).
        rules.push(json!({
            "name": scope(spec, "string", "string.quoted"),
            "match": r#"[^\s()\[\]{}":\\!~^<>*?,=+\-][^\s()\[\]{}":\\!~^<>*?,]*"#,
            "comment": "tm_extras:term",
        }));
    }
    if has_identifier_fallback(language) {
        // What is left: a name no rule above placed. The semantic tokens
        // call such a name a variable too.
        rules.push(json!({
            "name": variable,
            "match": r"(?<![\w.$@#])[A-Za-z_]\w*(?![\w(])",
            "comment": "tm_extras:identifier",
        }));
    }
    rules
}

/// Languages whose bare names are columns, fields or macros (not values).
fn has_identifier_fallback(language: LanguageId) -> bool {
    matches!(
        language,
        LanguageId::Kql
            | LanguageId::Spl
            | LanguageId::Eql
            | LanguageId::Cql
            | LanguageId::Falco
            | LanguageId::Yaral
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_tm_language;

    fn comments(language: LanguageId) -> Vec<String> {
        let spec = HighlightSpec::load().expect("spec");
        generate_tm_language(language, &spec)["patterns"]
            .as_array()
            .expect("patterns")
            .iter()
            .filter_map(|p| p["comment"].as_str())
            .filter(|c| c.starts_with("tm_extras:"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn each_query_language_gets_its_rules() {
        let has = |language, rule: &str| comments(language).iter().any(|c| c == rule);
        for language in [
            LanguageId::Kql,
            LanguageId::Esql,
            LanguageId::Eql,
            LanguageId::Cql,
            LanguageId::Yaral,
        ] {
            assert!(has(language, "tm_extras:builtin-call"), "{language}");
        }
        for language in LanguageId::QUERY_LANGUAGES {
            assert!(has(language, "tm_extras:field"), "{language}");
        }
        assert!(has(LanguageId::Kql, "tm_extras:table"));
        assert!(has(LanguageId::Esql, "tm_extras:esql-source"));
        for language in [
            LanguageId::Kuery,
            LanguageId::Lucene,
            LanguageId::Cql,
            LanguageId::Datadog,
        ] {
            assert!(has(language, "tm_extras:logical"), "{language}");
        }
        // Not query languages: no extras at all.
        assert!(comments(LanguageId::TideYaml).is_empty());
        assert!(comments(LanguageId::Config).is_empty());
    }

    #[test]
    fn every_extra_scope_is_a_spec_scope_or_the_logical_one() {
        let spec = HighlightSpec::load().expect("spec");
        let allowed: Vec<&str> = spec
            .captures
            .values()
            .map(|maps| maps.tm.as_str())
            .chain([LOGICAL_SCOPE])
            .collect();
        for language in LanguageId::QUERY_LANGUAGES {
            let grammar = generate_tm_language(language, &spec);
            for pattern in grammar["patterns"].as_array().expect("patterns") {
                if !pattern["comment"]
                    .as_str()
                    .is_some_and(|c| c.starts_with("tm_extras:"))
                {
                    continue;
                }
                let mut names = vec![pattern["name"].as_str()];
                if let Some(captures) = pattern["captures"].as_object() {
                    names.extend(captures.values().map(|c| c["name"].as_str()));
                }
                for name in names.into_iter().flatten() {
                    assert!(
                        allowed.contains(&name),
                        "{language}: {name} is no spec scope"
                    );
                }
            }
        }
    }

    #[test]
    fn function_names_are_the_catalogs_and_unique() {
        for names in [
            function_names::KQL,
            function_names::ESQL,
            function_names::EQL,
            function_names::CQL,
            function_names::YARAL,
        ] {
            assert!(names.len() > 15);
            let mut sorted = names.to_vec();
            sorted.dedup();
            assert_eq!(sorted.len(), names.len());
        }
        assert!(function_names::KQL.contains(&"tolower"));
        assert!(function_names::ESQL.contains(&"to_lower"));
    }
}
