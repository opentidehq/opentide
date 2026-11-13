//! What the pages know about each platform (`documentation/facts/platforms.py`):
//! the name a page shows, and the language of each block setting that holds
//! code, so a query is fenced and captioned in its own language (KQL, SPL,
//! ES|QL, YARA) rather than as text.
//!
//! The labels are the workspace's ([`opentide_workspace::info::PLATFORMS`]);
//! `every_platform_has_a_profile` fails when the rule model gains a platform
//! this table does not name.

use crate::json::Json;

/// A query or rule language: its name and its code-fence info string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeLanguage {
    /// The name a caption shows.
    pub name: &'static str,
    /// The fence's info string.
    pub fence: &'static str,
}

const fn language(name: &'static str, fence: &'static str) -> CodeLanguage {
    CodeLanguage { name, fence }
}

/// KQL.
pub const KQL: CodeLanguage = language("KQL", "kql");
/// SPL.
pub const SPL: CodeLanguage = language("SPL", "spl");
/// `SentinelOne`'s S1QL.
pub const S1QL: CodeLanguage = language("S1QL", "sql");
/// `CrowdStrike`'s CQL.
pub const CQL: CodeLanguage = language("CQL", "cql");
/// Lucene.
pub const LUCENE: CodeLanguage = language("Lucene", "lucene");
/// Kibana's KQL.
pub const KUERY: CodeLanguage = language("Kibana KQL", "kql");
/// EQL.
pub const EQL: CodeLanguage = language("EQL", "eql");
/// ES|QL.
pub const ESQL: CodeLanguage = language("ES|QL", "esql");
/// YARA.
pub const YARA: CodeLanguage = language("YARA", "yara");
/// A Falco condition.
pub const FALCO: CodeLanguage = language("Falco condition", "text");
/// A Graylog search.
pub const GRAYLOG: CodeLanguage = language("Graylog search", "lucene");
/// The Exabeam Query Language.
pub const EXABEAM: CodeLanguage = language("Exabeam Query Language", "text");
/// YARA-L.
pub const YARAL: CodeLanguage = language("YARA-L", "yaral");
/// Markdown.
pub const MARKDOWN: CodeLanguage = language("Markdown", "markdown");
/// Anything else.
pub const TEXT: CodeLanguage = language("Text", "text");

/// The code languages of a platform's settings, by path (list indices
/// removed: `exclusions.query`).
fn languages(platform: &str) -> &'static [(&'static str, CodeLanguage)] {
    match platform {
        "sentinel" | "defender_for_endpoint" => &[("query", KQL), ("exclusions.query", KQL)],
        "splunk" => &[("query", SPL), ("actions.notable.drilldown.search", SPL)],
        "sentinel_one" => &[
            ("condition.single_event.query", S1QL),
            ("condition.correlation.sub_queries.query", S1QL),
        ],
        "crowdstrike" => &[("query", CQL)],
        "harfanglab" | "bitdefender" => &[("yara.signature", YARA)],
        "carbon_black_cloud" => &[("query", LUCENE)],
        "sysdig" => &[("condition", FALCO), ("macros.condition", FALCO)],
        "graylog" => &[("query", GRAYLOG)],
        "exabeam" => &[("sequences.query", EXABEAM)],
        "google_secops" => &[
            ("setup", YARAL),
            ("events", YARAL),
            ("outcome", YARAL),
            ("condition", YARAL),
            ("export", YARAL),
        ],
        _ => &[],
    }
}

/// The language of Elastic's settings, which depends on the rule's `type`
/// and `language`.
fn elastic_language(path: &str, block: &Json) -> Option<CodeLanguage> {
    match path {
        "query" => Some(match block.get("type").and_then(Json::as_str) {
            Some("eql") => EQL,
            Some("esql") => ESQL,
            _ if block.get("language").and_then(Json::as_str) == Some("lucene") => LUCENE,
            _ => KUERY,
        }),
        "filters.query" | "threat.query" => Some(KUERY),
        _ if path.starts_with("guide.") => Some(MARKDOWN),
        _ => None,
    }
}

/// The language of the setting at `path` of `platform`'s `block`, if it
/// holds code.
pub fn code_language(platform: &str, path: &str, block: &Json) -> Option<CodeLanguage> {
    if platform == "elastic"
        && let Some(found) = elastic_language(path, block)
    {
        return Some(found);
    }
    languages(platform)
        .iter()
        .find(|(pattern, _)| *pattern == path)
        .map(|(_, language)| *language)
}

/// The language of `platform`'s `query` setting, when the platform has one
/// whatever the block says (not Elastic's, which depends on the rule type).
pub fn query_language(platform: &str) -> Option<CodeLanguage> {
    languages(platform)
        .iter()
        .find(|(pattern, _)| *pattern == "query")
        .map(|(_, language)| *language)
}

/// The labels of the platforms the workspace does not list yet (the train's
/// platforms arrive with their ports).
const LABELS: [(&str, &str); 4] = [
    ("bitdefender", "Bitdefender GravityZone"),
    ("graylog", "Graylog"),
    ("exabeam", "Exabeam New-Scale SIEM"),
    ("google_secops", "Google Security Operations"),
];

/// `sentinel` as `Microsoft Sentinel`; a platform no table names, title-cased.
pub fn platform_label(platform: &str) -> String {
    if let Some(found) = opentide_workspace::info::PLATFORMS
        .iter()
        .find(|entry| entry.name == platform)
    {
        return found.label.to_owned();
    }
    if let Some((_, label)) = LABELS.iter().find(|(key, _)| *key == platform) {
        return (*label).to_owned();
    }
    super::text::title_case(&platform.replace('_', " "))
}

/// A response search's language, from the system it names: a platform's
/// key or label, or the start of one.
pub fn search_language(system: &str) -> CodeLanguage {
    let wanted = system.trim().to_lowercase().replace(' ', "_");
    let keys = opentide_schema::objects::RuleConfigurations::PLATFORMS
        .iter()
        .copied()
        .chain(LABELS.iter().map(|(key, _)| *key));
    for key in keys {
        let names = [
            key.to_owned(),
            platform_label(key).to_lowercase().replace(' ', "_"),
        ];
        if names
            .iter()
            .any(|name| *name == wanted || name.starts_with(&wanted))
            && let Some(found) = query_language(key)
        {
            return found;
        }
    }
    TEXT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn every_platform_has_a_profile() {
        for platform in opentide_schema::objects::RuleConfigurations::PLATFORMS {
            assert!(
                opentide_workspace::info::PLATFORMS
                    .iter()
                    .any(|entry| entry.name == platform),
                "{platform} has no label"
            );
            assert!(
                platform == "elastic" || !languages(platform).is_empty(),
                "{platform} names no code setting"
            );
        }
    }

    #[test]
    fn labels() {
        assert_eq!(platform_label("sentinel"), "Microsoft Sentinel");
        assert_eq!(platform_label("graylog"), "Graylog");
        assert_eq!(platform_label("my_plugin"), "My Plugin");
    }

    #[test]
    fn elastic_languages_follow_the_rule_type() {
        let eql = json(r#"{"type": "eql"}"#);
        assert_eq!(code_language("elastic", "query", &eql), Some(EQL));
        let as_esql = json(r#"{"type": "esql"}"#);
        assert_eq!(code_language("elastic", "query", &as_esql), Some(ESQL));
        let lucene = json(r#"{"type": "query", "language": "lucene"}"#);
        assert_eq!(code_language("elastic", "query", &lucene), Some(LUCENE));
        assert_eq!(code_language("elastic", "query", &json("{}")), Some(KUERY));
        assert_eq!(
            code_language("elastic", "guide.note", &json("{}")),
            Some(MARKDOWN)
        );
        assert_eq!(code_language("elastic", "name", &json("{}")), None);
        assert_eq!(
            code_language("sentinel", "exclusions.query", &json("{}")),
            Some(KQL)
        );
        assert_eq!(code_language("sentinel", "name", &json("{}")), None);
    }

    #[test]
    fn search_languages_from_the_system() {
        assert_eq!(search_language("Microsoft Sentinel"), KQL);
        assert_eq!(search_language("splunk"), SPL);
        assert_eq!(search_language("Elastic"), TEXT);
        assert_eq!(search_language("Graylog"), GRAYLOG);
        assert_eq!(search_language("SIEM"), TEXT);
    }
}
