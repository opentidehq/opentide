//! Which values of a Tide object are queries, and in which language.
//!
//! A key is a query only at a path opentide models as one, read from the
//! YAML structure ([`crate::yaml_scalar`]), never from a line that happens to
//! say `query:` or `search:`:
//!
//! | Path | Language | Platform |
//! | --- | --- | --- |
//! | `configurations.<platform>.query` | [`language_for_field_path`] | `<platform>` |
//! | `configurations.splunk.search` (legacy splunk::2.x) | SPL | `splunk` |
//! | `configurations.elastic.query`, `configurations.elastic.threat.query` | [`elastic_query_language`] | `elastic` |
//! | `response.procedure.searches.<n>.query` | the entry's `system`, in any key order | the `system` |
//!
//! A hunt's `system` is free text in opentide. It names a language only when
//! it is a platform identifier, spelled as a `configurations` key
//! (`sentinel`, `defender_for_endpoint`, `splunk`, `carbon_black_cloud`, or
//! `elastic` with the entry's `language`). Any other `system` (`Sentinel`,
//! `Splunk ES`, `MDE`) is not analysed: the language is never guessed
//! (specifications#58).
//!
//! Nothing else is a query. A Splunk notable's drilldown search
//! (`configurations.splunk.actions.notable.drilldown.search`) is a template
//! Splunk fills with `$token$` values when an analyst opens the notable: its
//! text is not what runs, and it is not the rule's query.

use crate::elastic::{elastic_query_language, elastic_search_language};
use crate::yaml_scalar::{YamlKey, mapping_keys, scalar_at, scalar_text};
use crate::{InjectedQuery, language_for_field_path};
use opentide_core::{ByteSpan, LanguageId};

/// Every query a Tide object carries, in source order.
pub(crate) fn extract_injections(source: &str) -> Vec<InjectedQuery> {
    let keys = mapping_keys(source);
    let mut out: Vec<InjectedQuery> = keys
        .iter()
        .filter_map(|key| {
            let (language, platform) = query_language(source, &keys, key)?;
            injected(source, key, language, platform)
        })
        .collect();
    out.sort_by_key(|query| query.host_span.start);
    out
}

/// The language of a hunt's query (`response.procedure.searches[].query`),
/// from the entry's `system` and, for Elastic, its `language`. `None` when
/// `system` is not a platform identifier whose queries are checked.
pub fn hunt_query_language(system: &str, language: Option<&str>) -> Option<LanguageId> {
    if system == "elastic" {
        return elastic_search_language(language);
    }
    language_for_field_path(&["configurations", system, "query"])
}

/// The language and platform of the query `key` holds, if it holds one.
fn query_language(source: &str, keys: &[YamlKey], key: &YamlKey) -> Option<(LanguageId, String)> {
    let value = |path: &[&str]| {
        keys.iter()
            .find(|k| k.path_is(path))
            .and_then(|k| scalar_text(source, k))
    };
    let path: Vec<&str> = key.path.iter().map(String::as_str).collect();
    match path.as_slice() {
        ["configurations", "elastic", "query"] => {
            let rule_type = value(&["configurations", "elastic", "type"]);
            let language = value(&["configurations", "elastic", "language"]);
            elastic_query_language(rule_type.as_deref(), language.as_deref())
                .map(|l| (l, "elastic".into()))
        }
        ["configurations", "elastic", "threat", "query"] => {
            let rule_type = value(&["configurations", "elastic", "type"]);
            if rule_type.as_deref() != Some("threat_match") {
                return None;
            }
            let language = value(&["configurations", "elastic", "threat", "language"]);
            elastic_query_language(Some("threat_match"), language.as_deref())
                .map(|l| (l, "elastic".into()))
        }
        ["configurations", platform, "query" | "search"] => {
            language_for_field_path(&path).map(|l| (l, (*platform).to_string()))
        }
        ["response", "procedure", "searches", item, "query"] if is_index(item) => {
            let sibling = |name: &str| value(&["response", "procedure", "searches", item, name]);
            let system = sibling("system")?;
            let language = hunt_query_language(&system, sibling("language").as_deref())?;
            Some((language, system))
        }
        _ => None,
    }
}

fn is_index(segment: &str) -> bool {
    !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit())
}

/// The query `key` holds as an injection: its value, without the line breaks
/// around it, mapped back onto the source.
fn injected(
    source: &str,
    key: &YamlKey,
    language: LanguageId,
    platform: String,
) -> Option<InjectedQuery> {
    let scalar = scalar_at(source, key.scalar?, key.column)?;
    let text = scalar.text.as_str();
    let lead = text.len() - text.trim_start_matches(['\n', '\r']).len();
    let trail = text.len() - text.trim_end_matches(['\n', '\r']).len();
    if lead + trail >= text.len() || text.trim().is_empty() {
        return None;
    }
    let inner = text[lead..text.len() - trail].to_string();
    let host_map = scalar.map[lead..scalar.map.len() - trail].to_vec();
    let start = *host_map.first()?;
    let end = scalar.end.max(host_map.last()? + 1);
    Some(InjectedQuery {
        language,
        platform,
        field_path: key.path.clone(),
        inner,
        host_map,
        host_span: ByteSpan::new(start, end),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnalyzeInput, analyze};
    use opentide_core::{Diagnostic, codes};

    const HEAD: &str = "name: Rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n";

    /// `(field path, language, platform, inner text)` of each query.
    fn queries(source: &str) -> Vec<(String, LanguageId, String, String)> {
        extract_injections(source)
            .into_iter()
            .map(|q| {
                assert_eq!(q.host_map.len(), q.inner.len(), "{source}");
                (q.field_path.join("."), q.language, q.platform, q.inner)
            })
            .collect()
    }

    fn row(
        path: &str,
        language: LanguageId,
        platform: &str,
        inner: &str,
    ) -> (String, LanguageId, String, String) {
        (path.into(), language, platform.into(), inner.into())
    }

    fn diagnostics(source: &str) -> Vec<Diagnostic> {
        analyze(AnalyzeInput {
            path: "objects/rules/rule.yaml",
            source,
            workspace: &[],
            elastic_tenants: &[],
        })
        .diagnostics
    }

    /// The source text a diagnostic's range starts at (UTF-16 columns).
    fn text_at<'a>(source: &'a str, d: &Diagnostic) -> &'a str {
        let line = source.lines().nth(d.range.start.line as usize).unwrap();
        let mut units = 0;
        for (i, c) in line.char_indices() {
            if units >= d.range.start.character as usize {
                return &line[i..];
            }
            units += c.len_utf16();
        }
        ""
    }

    #[test]
    fn a_drilldown_search_is_not_the_rule_query() {
        let source = format!(
            "{HEAD}configurations:
  splunk:
    query: |
      index=a | stats count by user
    actions:
      notable:
        drilldown:
          name: Drilldown
          search: '| from datamodel:\"Risk.All_Risk\" | search user=$user|s$'
"
        );
        assert_eq!(
            queries(&source),
            vec![row(
                "configurations.splunk.query",
                LanguageId::Spl,
                "splunk",
                "index=a | stats count by user"
            )]
        );
        let found = diagnostics(&source);
        assert!(
            !found.iter().any(|d| d.code == codes::SPL_UNKNOWN_COMMAND
                || d.code == codes::SPL_PARSE_ERROR
                || d.field_path
                    .as_ref()
                    .is_some_and(|p| p.join(".") == "configurations.splunk.search")),
            "{found:?}"
        );
    }

    #[test]
    fn the_legacy_search_key_is_a_query_only_directly_under_splunk() {
        let source = format!(
            "{HEAD}configurations:\n  splunk:\n    search: index=a | head 1\n  sentinel:\n    search: SecurityEvent\n    query: SecurityEvent | take 1\n"
        );
        assert_eq!(
            queries(&source),
            vec![
                row(
                    "configurations.splunk.search",
                    LanguageId::Spl,
                    "splunk",
                    "index=a | head 1"
                ),
                row(
                    "configurations.sentinel.query",
                    LanguageId::Kql,
                    "sentinel",
                    "SecurityEvent | take 1"
                ),
            ]
        );
    }

    #[test]
    fn a_hunt_takes_its_system_whatever_the_key_order() {
        let source = format!(
            "{HEAD}response:
  procedure:
    searches:
      - purpose: a
        system: sentinel
        query: |
          SigninLogs | where TimeGenerated > ago(1d)
      - purpose: b
        query: |
          index=a | stats count
        system: splunk
      - query: DeviceProcessEvents | take 1
        purpose: c
        system: defender_for_endpoint
configurations:
  sentinel:
    query: SecurityEvent | take 1
"
        );
        assert_eq!(
            queries(&source),
            vec![
                row(
                    "response.procedure.searches.0.query",
                    LanguageId::Kql,
                    "sentinel",
                    "SigninLogs | where TimeGenerated > ago(1d)"
                ),
                row(
                    "response.procedure.searches.1.query",
                    LanguageId::Spl,
                    "splunk",
                    "index=a | stats count"
                ),
                row(
                    "response.procedure.searches.2.query",
                    LanguageId::Kql,
                    "defender_for_endpoint",
                    "DeviceProcessEvents | take 1"
                ),
                row(
                    "configurations.sentinel.query",
                    LanguageId::Kql,
                    "sentinel",
                    "SecurityEvent | take 1"
                ),
            ]
        );
    }

    #[test]
    fn a_hunt_finding_is_reported_at_the_hunt() {
        let source = format!(
            "{HEAD}response:\n  procedure:\n    searches:\n    - purpose: b\n      query: |\n        index=a | statz count\n      system: splunk\n"
        );
        let found = diagnostics(&source);
        let unknown = found
            .iter()
            .find(|d| d.code == codes::SPL_UNKNOWN_COMMAND)
            .unwrap_or_else(|| panic!("{found:?}"));
        assert_eq!(
            unknown.field_path.as_ref().map(|p| p.join(".")).as_deref(),
            Some("response.procedure.searches.0.query")
        );
        assert!(
            text_at(&source, unknown).starts_with("statz"),
            "{unknown:?}"
        );
    }

    #[test]
    fn a_hunt_without_a_platform_system_is_not_analysed() {
        // `system` is free text: only a platform identifier names a language.
        let source = format!(
            "{HEAD}response:
  procedure:
    searches:
      - system: Sentinel
        query: SecurityEvent | take 1
      - purpose: no system
        query: SecurityEvent | take 1
      - system: crowdstrike
        query: anything
      - system: elastic
        query: process.name:cmd.exe
"
        );
        assert_eq!(queries(&source), vec![]);
    }

    #[test]
    fn a_query_key_anywhere_else_is_not_a_query() {
        let source = format!(
            "{HEAD}description: |
  query: SecurityEvent
configurations:
  sentinel:
    entity_mapping:
      query: x
    query: SecurityEvent | take 1
    alert:
      search: y
objective:
  query: z
"
        );
        assert_eq!(
            queries(&source),
            vec![row(
                "configurations.sentinel.query",
                LanguageId::Kql,
                "sentinel",
                "SecurityEvent | take 1"
            )]
        );
    }

    #[test]
    fn block_scalars_of_every_style_are_their_value() {
        let cases = [
            ("|", "SigninLogs\n| take 1"),
            ("|-", "SigninLogs\n| take 1"),
            ("|+", "SigninLogs\n| take 1"),
            (">", "SigninLogs | take 1"),
            (">-", "SigninLogs | take 1"),
            (">+", "SigninLogs | take 1"),
            ("|2", "  SigninLogs\n| take 1"),
            (">-2", "  SigninLogs\n| take 1"),
            ("|2-", "  SigninLogs\n| take 1"),
        ];
        for (header, expected) in cases {
            let body = if header.contains('2') {
                "        SigninLogs\n      | take 1\n"
            } else {
                "      SigninLogs\n      | take 1\n"
            };
            let source = format!(
                "{HEAD}configurations:\n  sentinel:\n    query: {header}\n{body}\n    status: x\n"
            );
            assert_eq!(
                queries(&source),
                vec![row(
                    "configurations.sentinel.query",
                    LanguageId::Kql,
                    "sentinel",
                    expected
                )],
                "{header}"
            );
            let found = diagnostics(&source);
            assert!(
                !found.iter().any(|d| d.code.starts_with("kql_")),
                "{header}: {found:?}"
            );
        }
    }

    #[test]
    fn a_finding_in_a_folded_scalar_lands_on_its_source_line_and_column() {
        // `>` folds the lines into one; `|2` keeps the deeper line's spaces.
        for header in [">", ">-", "|2", "|"] {
            let source = format!(
                "{HEAD}configurations:\n  sentinel:\n    query: {header}\n      SecurityEvent\n      | where Account == \"é🔥\"\n      | wher EventID == 1\n    status: x\n"
            );
            let found = diagnostics(&source);
            let d = found
                .iter()
                .find(|d| d.code == codes::KQL_UNKNOWN_OPERATOR)
                .unwrap_or_else(|| panic!("{header}: {found:?}"));
            assert_eq!(d.range.start.line, 9, "{header}: {d:?}");
            assert_eq!(d.range.start.character, 8, "{header}: {d:?}");
            assert!(text_at(&source, d).starts_with("wher"), "{header}");
            assert_eq!(d.range.start.line, d.range.end.line, "{header}");
        }
    }

    #[test]
    fn a_quoted_query_is_its_value() {
        // #105: what `yaml.safe_dump` writes for a multi-line string.
        let source = format!(
            "{HEAD}configurations:\n  sentinel:\n    query: \"SecurityEvent\\n| where EventID == 4688\\n| take 1\\n\"\n"
        );
        assert_eq!(
            queries(&source),
            vec![row(
                "configurations.sentinel.query",
                LanguageId::Kql,
                "sentinel",
                "SecurityEvent\n| where EventID == 4688\n| take 1"
            )]
        );
        assert!(
            !diagnostics(&source)
                .iter()
                .any(|d| d.code.starts_with("kql_"))
        );

        let source = format!(
            "{HEAD}configurations:\n  sentinel:\n    query: \"SecurityEvent\\n| wher EventID == 4688\"\n  splunk:\n    query: 'index=a\n      | statz count by ''user'''\n"
        );
        let found = diagnostics(&source);
        let wher = found
            .iter()
            .find(|d| d.code == codes::KQL_UNKNOWN_OPERATOR)
            .expect("wher");
        assert!(
            text_at(&source, wher).starts_with("wher EventID"),
            "{wher:?}"
        );
        let statz = found
            .iter()
            .find(|d| d.code == codes::SPL_UNKNOWN_COMMAND)
            .expect("statz");
        assert_eq!(statz.range.start.line, 9, "{statz:?}");
        assert!(text_at(&source, statz).starts_with("statz"), "{statz:?}");
    }

    #[test]
    fn a_query_on_the_line_below_its_key_is_its_value() {
        let source = format!(
            "{HEAD}configurations:\n  sentinel:\n    query:\n      SecurityEvent\n      | take 1\n"
        );
        assert_eq!(
            queries(&source),
            vec![row(
                "configurations.sentinel.query",
                LanguageId::Kql,
                "sentinel",
                "SecurityEvent | take 1"
            )]
        );
    }

    #[test]
    fn elastic_queries_keep_their_platform() {
        let source = "configurations:\n  elastic:\n    type: eql\n    query: >-\n      process where\n      true\n";
        assert_eq!(
            queries(source),
            vec![row(
                "configurations.elastic.query",
                LanguageId::Eql,
                "elastic",
                "process where true"
            )]
        );
    }
}
