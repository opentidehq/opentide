//! The MISP Event of one Tide object (`sharing/payload.py`) and the galaxy
//! cluster tags it carries (`sharing/galaxy.py`).
//!
//! The event is plain JSON built key by key in the oracle's order. Galaxy
//! tags come from a read-only lookup of the instance's clusters; a preview
//! passes none.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use opentide_compile::json::{Json, Object};
use opentide_connectors::misp::{
    GALAXY_ACTOR, GALAXY_ATTACK, GalaxyCluster, Kind, Misp, MispCallError, OPENTIDE_TEMPLATE_UUID,
};
use opentide_schema::node::Value;
use regex::Regex;

use super::document::TideDocument;

/// The object template's name.
pub const TEMPLATE_NAME: &str = "opentide";
/// The object template's version.
pub const TEMPLATE_VERSION: i64 = 5;
/// The relations the template must have.
pub const REQUIRED_RELATIONS: [&str; 6] = [
    "name",
    "opentide-object",
    "opentide-type",
    "uuid",
    "version",
    "schema",
];
/// The longest `info` MISP takes.
const INFO_LIMIT: usize = 255;

/// A canonical UUID (`CANONICAL_UUID_PATTERN`).
#[expect(
    clippy::expect_used,
    reason = "a literal pattern, compiled once; it cannot fail"
)]
pub fn uuid_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .expect("a valid pattern")
    })
}

/// A vocabulary's `misp` tags by name (`_vocab_misp`).
fn vocab_misp(field: &str) -> &'static BTreeMap<String, String> {
    static TLP: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    static PAP: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    let cell = if field == "tlp" { &TLP } else { &PAP };
    cell.get_or_init(|| {
        let mut mapping = BTreeMap::new();
        let Some((_, text)) = opentide_schema::vocab::bundled::FILES
            .iter()
            .find(|(name, _)| *name == field)
        else {
            return mapping;
        };
        let Ok(document) = opentide_schema::configuration::toml::parse(text) else {
            return mapping;
        };
        if let Some(Value::Seq(keys)) = document.get("keys").map(|keys| &keys.value) {
            for entry in keys {
                if let (Some(Value::Str(name)), Some(Value::Str(tag))) = (
                    entry.get("name").map(|node| &node.value),
                    entry.get("misp").map(|node| &node.value),
                ) {
                    mapping.insert(name.clone(), tag.clone());
                }
            }
        }
        mapping
    })
}

/// An event, or the field that kept it from being built (`BuiltEvent`).
#[derive(Clone, Debug, Default)]
pub struct Built {
    /// `{"Event": ...}`.
    pub event: Option<Json>,
    /// Why there is none.
    pub reason: Option<&'static str>,
    /// The objects it relates to.
    pub relations: Vec<String>,
    /// `technique:<id>` and `actor:<name>` to look up.
    pub cluster_sources: Vec<String>,
}

impl Built {
    fn failed(reason: &'static str) -> Self {
        Self {
            reason: Some(reason),
            ..Self::default()
        }
    }
}

/// MISP's distribution for a TLP (`distribution_for`).
fn distribution(tlp: &str) -> i64 {
    i64::from(matches!(tlp, "clear" | "green"))
}

fn object(members: Vec<(&str, Json)>) -> Json {
    Json::Object(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn attribute(relation: &str, value: &str, correlate: bool) -> Json {
    object(vec![
        ("object_relation", Json::Str(relation.into())),
        ("type", Json::Str("text".into())),
        ("category", Json::Str("Other".into())),
        ("to_ids", Json::Bool(false)),
        ("distribution", Json::Int(5)),
        ("disable_correlation", Json::Bool(!correlate)),
        ("value", Json::Str(value.into())),
    ])
}

/// The event of `document`, with `cluster_tags` after the TLP and PAP tags
/// (`build_event`).
pub fn build(document: &TideDocument, cluster_tags: &[String]) -> Built {
    let Some(family) = document.family().filter(|_| document.parse_error.is_none()) else {
        return Built::failed("invalid_document");
    };
    let Some(name) = document.name().filter(|name| !name.trim().is_empty()) else {
        return Built::failed("name");
    };
    let Some(created) = created(document.meta("created")) else {
        return Built::failed("metadata.created");
    };
    let Some(uuid) = document.uuid() else {
        return Built::failed("metadata.uuid");
    };
    let schema = document.schema_id().unwrap_or_default();
    let Some(version) = version(document.meta("version")) else {
        return Built::failed("metadata.version");
    };
    let tlp_tags = vocab_misp("tlp");
    let Some((tlp, tlp_tag)) = document
        .meta("tlp")
        .and_then(Json::as_str)
        .and_then(|tlp| tlp_tags.get(tlp).map(|tag| (tlp, tag)))
    else {
        return Built::failed("unmapped_tlp");
    };
    let pap_tag = match document.meta("pap") {
        None | Some(Json::Null) => None,
        Some(Json::Str(pap)) => match vocab_misp("pap").get(pap) {
            Some(tag) => Some(tag),
            None => return Built::failed("unmapped_pap"),
        },
        Some(_) => return Built::failed("unmapped_pap"),
    };
    let relations = match relations(document, family) {
        Ok(relations) => relations,
        Err(reason) => return Built::failed(reason),
    };
    let mut tags: Vec<String> = vec![tlp_tag.clone()];
    if let Some(pap) = pap_tag {
        tags.push(pap.clone());
    }
    for tag in cluster_tags {
        if !tags.contains(tag) {
            tags.push(tag.clone());
        }
    }
    let mut attributes = vec![
        attribute("name", name, true),
        attribute("uuid", uuid, true),
        attribute("version", &version, false),
        attribute("opentide-type", family, false),
        attribute("schema", schema, false),
        attribute("opentide-object", &document.text, true),
    ];
    attributes.extend(
        relations
            .iter()
            .map(|relation| attribute("opentide-relation", relation, true)),
    );
    let info: String = name.chars().take(INFO_LIMIT).collect();
    let event = object(vec![
        ("info", Json::Str(info)),
        ("date", Json::Str(created)),
        ("distribution", Json::Int(distribution(tlp))),
        ("sharing_group_id", Json::Int(0)),
        ("threat_level_id", Json::Int(threat_level(family, document))),
        ("analysis", Json::Int(2)),
        ("published", Json::Bool(false)),
        ("Attribute", Json::Array(Vec::new())),
        (
            "Tag",
            Json::Array(
                tags.into_iter()
                    .map(|tag| object(vec![("name", Json::Str(tag))]))
                    .collect(),
            ),
        ),
        (
            "Object",
            Json::Array(vec![object(vec![
                ("name", Json::Str(TEMPLATE_NAME.into())),
                ("meta-category", Json::Str("misc".into())),
                ("template_uuid", Json::Str(OPENTIDE_TEMPLATE_UUID.into())),
                ("template_version", Json::Int(TEMPLATE_VERSION)),
                ("distribution", Json::Int(5)),
                ("Attribute", Json::Array(attributes)),
            ])]),
        ),
    ]);
    Built {
        event: Some(object(vec![("Event", event)])),
        reason: None,
        cluster_sources: cluster_sources(document, family),
        relations,
    }
}

/// `metadata.created` as `YYYY-MM-DD` (`_created`).
fn created(value: Option<&Json>) -> Option<String> {
    let text = value?.as_str()?.trim();
    let head = text.get(..10)?;
    let date: jiff::civil::Date = head.parse().ok()?;
    // `date.fromisoformat` takes `YYYY-MM-DD` only.
    let bytes = head.as_bytes();
    (bytes.get(4) == Some(&b'-') && bytes.get(7) == Some(&b'-')).then(|| date.to_string())
}

/// `metadata.version` as text (`_version`).
fn version(value: Option<&Json>) -> Option<String> {
    match value? {
        Json::Int(number) if *number >= 0 => Some(number.to_string()),
        Json::Str(text) if !text.is_empty() && text.chars().all(|c| c.is_ascii_digit()) => {
            let digits = text.trim_start_matches('0');
            Some(if digits.is_empty() { "0" } else { digits }.to_owned())
        }
        _ => None,
    }
}

/// The objects `document` relates to (`_relations`).
fn relations(document: &TideDocument, family: &str) -> Result<Vec<String>, &'static str> {
    let pattern = uuid_pattern();
    match family {
        "threat" => Ok(Vec::new()),
        "rule" => match document.body.get("detection_model") {
            None | Some(Json::Null) => Ok(Vec::new()),
            Some(Json::Str(text)) if text.is_empty() => Ok(Vec::new()),
            Some(Json::Str(text)) if pattern.is_match(text) => Ok(vec![text.clone()]),
            Some(_) => Err("relation_uuid"),
        },
        _ => {
            let threats = document
                .body
                .get("objective")
                .and_then(Json::as_object)
                .and_then(|objective| objective.get("threats"))
                .filter(|threats| threats.truthy());
            let items = match threats {
                None => return Ok(Vec::new()),
                Some(Json::Array(items)) => items,
                Some(_) => return Err("relation_uuid"),
            };
            let mut found: Vec<String> = Vec::new();
            for item in items {
                match item {
                    Json::Null => {}
                    Json::Str(text) if text.is_empty() => {}
                    Json::Str(text) if pattern.is_match(text) => {
                        if !found.contains(text) {
                            found.push(text.clone());
                        }
                    }
                    _ => return Err("relation_uuid"),
                }
            }
            found.sort();
            Ok(found)
        }
    }
}

fn techniques(document: &TideDocument, family: &str) -> Vec<String> {
    let raw = match family {
        "rule" => document.body.get("techniques"),
        "objective" => document
            .body
            .get("objective")
            .and_then(Json::as_object)
            .and_then(|objective| objective.get("mitre_attack")),
        _ => document
            .body
            .get("threat")
            .and_then(Json::as_object)
            .and_then(|threat| threat.get("mitre_attack")),
    };
    let Some(Json::Array(items)) = raw else {
        return Vec::new();
    };
    let mut found: Vec<String> = Vec::new();
    for item in items {
        if let Json::Str(text) = item {
            let trimmed = python_strip(text);
            if !trimmed.is_empty() && !found.iter().any(|seen| seen == trimmed) {
                found.push(trimmed.to_owned());
            }
        }
    }
    found
}

/// `str.strip()`: Python's whitespace.
fn python_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// The identifiers that need a galaxy lookup (`_cluster_sources`).
fn cluster_sources(document: &TideDocument, family: &str) -> Vec<String> {
    let mut sources: Vec<String> = techniques(document, family)
        .into_iter()
        .map(|technique| format!("technique:{technique}"))
        .collect();
    if family == "threat"
        && let Some(Json::Array(actors)) = document
            .body
            .get("threat")
            .and_then(Json::as_object)
            .and_then(|threat| threat.get("actors"))
    {
        for actor in actors {
            if let Some(Json::Str(name)) = actor.get("name")
                && !name.is_empty()
            {
                sources.push(format!("actor:{name}"));
            }
        }
    }
    sources
}

/// MISP's threat level of an object (`_threat_level`).
fn threat_level(family: &str, document: &TideDocument) -> i64 {
    const CRITICALITY: [(&str, i64); 7] = [
        ("Emergency", 1),
        ("Severe", 1),
        ("High", 1),
        ("Medium", 2),
        ("Low", 3),
        ("Baseline - Minor", 3),
        ("Baseline - Negligible", 3),
    ];
    const SEVERITY: [(&str, i64); 6] = [
        ("National cyber emergency", 1),
        ("Highly significant incident", 1),
        ("Significant incident", 1),
        ("Substantial incident", 2),
        ("Moderate incident", 2),
        ("Localised incident", 3),
    ];
    const ALERT_SEVERITY: [(&str, i64); 5] = [
        ("Critical", 1),
        ("High", 1),
        ("Medium", 2),
        ("Low", 3),
        ("Informational", 3),
    ];
    type Table = [(&'static str, i64)];
    let (value, tables): (Option<&Json>, &[&Table]) = match family {
        "objective" => return 4,
        "threat" => (document.body.get("criticality"), &[&CRITICALITY]),
        _ => (document.body.get("severity"), &[&SEVERITY, &ALERT_SEVERITY]),
    };
    let Some(Json::Str(value)) = value else {
        return 4;
    };
    for table in tables {
        if let Some((_, level)) = table.iter().find(|(name, _)| name == value) {
            return *level;
        }
    }
    let folded = value.to_lowercase();
    for table in tables {
        if let Some((_, level)) = table.iter().find(|(name, _)| name.to_lowercase() == folded) {
            return *level;
        }
    }
    4
}

/// Tags to emit and notes (`GalaxyResolution`).
#[derive(Clone, Debug, Default)]
pub struct Resolution {
    /// The tags, actors then techniques, each sorted.
    pub tags: Vec<String>,
    /// Informational notes.
    pub notes: Vec<String>,
}

/// Maps technique and actor identifiers to cluster tags
/// (`resolve_clusters`).
///
/// # Errors
///
/// A lookup failed: `galaxy_lookup_failed`, of the lookup's kind.
pub fn resolve_clusters(
    client: &dyn Misp,
    sources: &[String],
) -> Result<Resolution, MispCallError> {
    if sources.is_empty() {
        return Ok(Resolution::default());
    }
    let mut attack: Option<Vec<GalaxyCluster>> = None;
    let mut actors: Option<Vec<GalaxyCluster>> = None;
    let (mut actor_tags, mut attack_tags): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut notes = Vec::new();
    let failed = |error: MispCallError| MispCallError {
        reason: "galaxy_lookup_failed".to_owned(),
        ..error
    };
    for source in sources {
        let (kind, ident) = source.split_once(':').unwrap_or((source.as_str(), ""));
        let (tag, note, bucket) = if kind == "technique" {
            if attack.is_none() {
                attack = Some(client.galaxy_clusters(GALAXY_ATTACK).map_err(failed)?);
            }
            let (tag, note) = technique(attack.as_deref().unwrap_or_default(), ident);
            (tag, note, &mut attack_tags)
        } else {
            if actors.is_none() {
                actors = Some(client.galaxy_clusters(GALAXY_ACTOR).map_err(failed)?);
            }
            let (tag, note) = actor(actors.as_deref().unwrap_or_default(), ident);
            (tag, note, &mut actor_tags)
        };
        if let Some(note) = note {
            notes.push(note);
        }
        if let Some(tag) = tag
            && !bucket.contains(&tag)
        {
            bucket.push(tag);
        }
    }
    actor_tags.sort();
    attack_tags.sort();
    actor_tags.extend(attack_tags);
    Ok(Resolution {
        tags: actor_tags,
        notes,
    })
}

/// `_same`: equal once stripped and case-folded.
fn same(left: &str, right: &str) -> bool {
    python_strip(left).to_lowercase() == python_strip(right).to_lowercase()
}

fn tag(galaxy: &str, value: &str) -> String {
    format!("misp-galaxy:{galaxy}=\"{value}\"")
}

fn one(
    matched: &[&GalaxyCluster],
    missing: String,
    galaxy: &str,
) -> (Option<String>, Option<String>) {
    match matched {
        [only] => (Some(tag(galaxy, &only.value)), None),
        [] => (None, Some(missing)),
        many => {
            let mut uuids: Vec<&str> = many.iter().map(|cluster| cluster.uuid.as_str()).collect();
            uuids.sort_unstable();
            (None, Some(format!("cluster_ambiguous:{}", uuids.join(","))))
        }
    }
}

fn technique(clusters: &[GalaxyCluster], technique: &str) -> (Option<String>, Option<String>) {
    let matched: Vec<&GalaxyCluster> = clusters
        .iter()
        .filter(|cluster| cluster.external_ids.iter().any(|id| same(id, technique)))
        .collect();
    one(
        &matched,
        format!("cluster_not_found:{technique}"),
        GALAXY_ATTACK,
    )
}

fn actor(clusters: &[GalaxyCluster], name: &str) -> (Option<String>, Option<String>) {
    let Some((scope, ident)) = name
        .split_once("::")
        .filter(|(scope, ident)| matches!(*scope, "att&ck" | "misp") && !ident.is_empty())
    else {
        return (None, Some(format!("actor_unscoped:{name}")));
    };
    if scope == "misp" {
        let matched: Vec<&GalaxyCluster> = clusters
            .iter()
            .filter(|cluster| cluster.uuid.to_lowercase() == ident.to_lowercase())
            .collect();
        return one(&matched, format!("cluster_not_found:{name}"), GALAXY_ACTOR);
    }
    let predicates: [&dyn Fn(&GalaxyCluster) -> bool; 3] = [
        &|cluster| cluster.external_ids.iter().any(|id| same(id, ident)),
        &|cluster| cluster.ref_tails.iter().any(|tail| tail == ident),
        &|cluster| cluster.synonyms.iter().any(|synonym| same(synonym, ident)),
    ];
    for predicate in predicates {
        let matched: Vec<&GalaxyCluster> = clusters.iter().filter(|c| predicate(c)).collect();
        match matched.as_slice() {
            [only] => return (Some(tag(GALAXY_ACTOR, &only.value)), None),
            [] => {}
            many => {
                let mut uuids: Vec<&str> = many.iter().map(|c| c.uuid.as_str()).collect();
                uuids.sort_unstable();
                return (None, Some(format!("cluster_ambiguous:{}", uuids.join(","))));
            }
        }
    }
    (None, Some(format!("cluster_not_found:{name}")))
}

/// The kind of a failure no call made (`MispCallError("other", reason)`).
pub fn other(reason: &str) -> MispCallError {
    MispCallError::new(Kind::Other, reason, None)
}

/// An event's `Object`s merged for `events/edit` (`_edit_body`): the
/// instance's own objects kept, this object's replaced.
pub fn is_ours(object: &Object, tide_uuid: &str) -> bool {
    let name = object.get("name").and_then(Json::as_str);
    let template = object.get("template_uuid").and_then(Json::as_str);
    if name != Some(TEMPLATE_NAME) && template != Some(OPENTIDE_TEMPLATE_UUID) {
        return false;
    }
    let Some(Json::Array(attributes)) = object.get("Attribute") else {
        return false;
    };
    attributes.iter().any(|attribute| {
        attribute.get("object_relation").and_then(Json::as_str) == Some("uuid")
            && attribute.get("value").and_then(Json::as_str) == Some(tide_uuid)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::share::document::load;

    const RULE: &str = "name: Suspicious\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  schema: rule::1.0\n  version: 2\n  created: 2026-01-02\n  tlp: green\n  pap: amber\nseverity: high\ntechniques: [' T1059 ', T1059]\ndetection_model: 22222222-2222-4222-8222-222222222222\n";

    #[test]
    fn a_rule_builds_its_event() {
        let document = load(RULE.as_bytes(), None);
        let built = build(
            &document,
            &["misp-galaxy:x=\"y\"".to_owned(), "tlp:green".into()],
        );
        let event = built.event.unwrap();
        let text = event.to_compact();
        assert!(text.starts_with("{\"Event\":{\"info\":\"Suspicious\",\"date\":\"2026-01-02\",\"distribution\":1,\"sharing_group_id\":0,\"threat_level_id\":1,"), "{text}");
        assert!(text.contains("\"Tag\":[{\"name\":\"tlp:green\"},{\"name\":\"PAP:AMBER\"},{\"name\":\"misp-galaxy:x=\\\"y\\\"\"}]"), "{text}");
        assert_eq!(built.relations, ["22222222-2222-4222-8222-222222222222"]);
        assert_eq!(built.cluster_sources, ["technique:T1059"]);
    }

    #[test]
    fn fields_that_block_the_event_are_named() {
        let reason = |text: &str| build(&load(text.as_bytes(), None), &[]).reason;
        let with = |old: &str, new: &str| RULE.replace(old, new);
        assert_eq!(reason("a: 1"), Some("invalid_document"));
        assert_eq!(reason(&with("name: Suspicious", "name: ' '")), Some("name"));
        assert_eq!(
            reason(&with("created: 2026-01-02", "created: 2026/01/02")),
            Some("metadata.created")
        );
        assert_eq!(
            reason(&with("version: 2", "version: -1")),
            Some("metadata.version")
        );
        assert_eq!(
            reason(&with("tlp: green", "tlp: blue")),
            Some("unmapped_tlp")
        );
        assert_eq!(reason(&with("pap: amber", "pap: 3")), Some("unmapped_pap"));
        assert_eq!(
            reason(&with("detection_model: 2", "detection_model: X2")),
            Some("relation_uuid")
        );
        assert_eq!(
            version(Some(&Json::Str("007".into()))).as_deref(),
            Some("7")
        );
        assert_eq!(
            version(Some(&Json::Str("000".into()))).as_deref(),
            Some("0")
        );
        assert_eq!(
            created(Some(&Json::Str("2026-01-02T10:00:00Z".into()))).as_deref(),
            Some("2026-01-02")
        );
    }

    #[test]
    fn objectives_and_threats_relate_and_rank() {
        let objective = load(
            b"name: O\nmetadata: {uuid: o, schema: objective::1.0, version: 1, created: 2026-01-01, tlp: clear}\nobjective:\n  threats: [bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb, aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa, '', null]\n  mitre_attack: [T1]\n",
            None,
        );
        let built = build(&objective, &[]);
        assert_eq!(built.relations.len(), 2);
        assert!(built.relations[0].starts_with('a'));
        assert_eq!(threat_level("objective", &objective), 4);
        let threat = load(
            b"name: T\ncriticality: severe\nmetadata: {uuid: t, schema: threat::1.0, version: 1, created: 2026-01-01, tlp: red}\nthreat:\n  actors: [{name: 'att&ck::G0001'}, {name: ''}]\n",
            None,
        );
        assert_eq!(threat_level("threat", &threat), 1);
        assert_eq!(build(&threat, &[]).cluster_sources, ["actor:att&ck::G0001"]);
    }

    fn cluster(
        uuid: &str,
        value: &str,
        ids: &[&str],
        refs: &[&str],
        synonyms: &[&str],
    ) -> GalaxyCluster {
        GalaxyCluster {
            uuid: uuid.into(),
            value: value.into(),
            external_ids: ids.iter().map(|s| (*s).to_owned()).collect(),
            synonyms: synonyms.iter().map(|s| (*s).to_owned()).collect(),
            ref_tails: refs.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn clusters_resolve_to_tags_and_notes() {
        let attack = [
            cluster("a1", "Command", &["T1059"], &[], &[]),
            cluster("a2", "Dup", &["T2"], &[], &[]),
            cluster("a3", "Dup", &["t2 "], &[], &[]),
        ];
        assert_eq!(
            technique(&attack, "t1059").0.unwrap(),
            "misp-galaxy:mitre-attack-pattern=\"Command\""
        );
        assert_eq!(
            technique(&attack, "T2").1.unwrap(),
            "cluster_ambiguous:a2,a3"
        );
        assert_eq!(technique(&attack, "T9").1.unwrap(), "cluster_not_found:T9");
        let actors = [
            cluster("u1", "APT1", &["G0006"], &["G0006"], &["Comment Crew"]),
            cluster("u2", "APT2", &[], &["G0007"], &["comment crew"]),
        ];
        assert_eq!(
            actor(&actors, "att&ck::G0006").0.unwrap(),
            "misp-galaxy:threat-actor=\"APT1\""
        );
        assert_eq!(
            actor(&actors, "att&ck::G0007").0.unwrap(),
            "misp-galaxy:threat-actor=\"APT2\""
        );
        assert_eq!(
            actor(&actors, "att&ck::Comment Crew").1.unwrap(),
            "cluster_ambiguous:u1,u2"
        );
        assert_eq!(
            actor(&actors, "misp::U1").0.unwrap(),
            "misp-galaxy:threat-actor=\"APT1\""
        );
        assert_eq!(
            actor(&actors, "misp::zz").1.unwrap(),
            "cluster_not_found:misp::zz"
        );
        assert_eq!(actor(&actors, "APT1").1.unwrap(), "actor_unscoped:APT1");
        assert_eq!(
            actor(&actors, "att&ck::nope").1.unwrap(),
            "cluster_not_found:att&ck::nope"
        );
    }
}
