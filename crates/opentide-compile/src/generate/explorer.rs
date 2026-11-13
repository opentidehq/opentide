//! `opentide generate explorer` (`export/explorer_export.py`): the static
//! explorer site's two documents, `explorer.bundle.json` (every object, a
//! summary of each, the threat chains and the deployment statuses) and
//! `explorer.search.json` (one search document per summary), and, when asked
//! for, `explorer.visibility.json` ([`super::visibility`]).
//!
//! The explorer reads them as data: each is serde_json's compact line.

use std::path::Path;

use indexmap::IndexMap;
use opentide_workspace::Index;

use super::json_text::line;
use super::{Cause, Output, PhaseError};
use crate::json::{Json, Object};

/// The bundle's file name.
pub const BUNDLE: &str = "explorer.bundle.json";
/// The search index's file name.
pub const SEARCH: &str = "explorer.search.json";
/// The visibility export's file name, written only when asked for.
pub const VISIBILITY: &str = "explorer.visibility.json";
/// The marking of the visibility export unless one is given.
pub const DEFAULT_TLP: &str = "amber";
/// The markings `--visibility-tlp` takes.
pub const TLP_CHOICES: [&str; 5] = ["clear", "green", "amber", "amber+strict", "red"];

/// How much of an object's JSON a search document carries.
const CONTENT_LIMIT: usize = 4000;

/// The families of the bundle's `models`, in its order.
const FAMILIES: [&str; 4] = ["threat", "objective", "signal", "rule"];

/// Every object of `index` as the bundle holds it: by family, then by UUID
/// in index order. A signal is its mapping with `owner`, the objective it is
/// defined in.
fn models(index: &Index) -> IndexMap<&'static str, Object> {
    let mut models: IndexMap<&'static str, Object> = IndexMap::new();
    for family in FAMILIES {
        let mut bucket = Object::new();
        if family == "signal" {
            for (uuid, signal) in &index.signals {
                let Json::Object(mut body) = Json::from_node(&signal.node) else {
                    continue;
                };
                body.insert("owner".into(), Json::Str(signal.owner.clone()));
                bucket.insert(uuid.clone(), Json::Object(body));
            }
        } else if let Some(objects) = index.objects.get(family) {
            for (uuid, object) in objects {
                if let Some(root) = object.root() {
                    bucket.insert(uuid.clone(), Json::from_node(root));
                }
            }
        }
        models.insert(family, bucket);
    }
    models
}

/// `body.get(key) or {}` as an object: anything else is empty.
fn section<'j>(body: &'j Json, key: &str) -> Option<&'j Object> {
    body.get(key).and_then(Json::as_object)
}

/// The type an object's body says it is (`_infer_type`): its schema's prefix,
/// else the first section it has.
fn infer_type(body: &Json) -> Option<String> {
    if let Some(Json::Str(schema)) = section(body, "metadata").and_then(|m| m.get("schema")) {
        return Some(schema.split("::").next().unwrap_or_default().to_owned());
    }
    let has = |key: &str| body.get(key).is_some_and(Json::truthy);
    if has("configurations") {
        Some("rule".into())
    } else if has("objective") {
        Some("objective".into())
    } else if has("threat") {
        Some("threat".into())
    } else if has("signal") || has("owner") {
        Some("signal".into())
    } else {
        None
    }
}

/// A JSON value as text: a string as it is, anything else as its JSON.
fn text(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => line(other),
    }
}

/// A rule's deployment status (`_status`): `PRODUCTION` when one platform
/// says so, else `STAGING`, else the first platform's.
fn status(body: &Json) -> Json {
    let statuses: Vec<String> = section(body, "configurations")
        .into_iter()
        .flat_map(|configurations| configurations.values())
        .map(|configuration| {
            configuration
                .get("status")
                .map(text)
                .unwrap_or_default()
                .to_uppercase()
        })
        .collect();
    for wanted in ["PRODUCTION", "STAGING"] {
        if statuses.iter().any(|status| status == wanted) {
            return Json::from(wanted);
        }
    }
    statuses.into_iter().next().map_or(Json::Null, Json::Str)
}

/// A threat's actors' names (`_actors`), as written.
fn actors(body: &Json) -> Vec<Json> {
    let from_threat = section(body, "threat")
        .and_then(|threat| threat.get("actors"))
        .filter(|actors| actors.truthy());
    let list = from_threat.or_else(|| body.get("actors").filter(|actors| actors.truthy()));
    let Some(Json::Array(items)) = list else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|actor| match actor.get("name") {
            Some(Json::Str(name)) if !name.is_empty() => Some(Json::Str(name.clone())),
            _ => None,
        })
        .collect()
}

/// `len(value)` of what a section holds: a list's items, a string's
/// characters, a mapping's keys.
fn length(value: Option<&Json>) -> usize {
    match value {
        Some(Json::Array(items)) => items.len(),
        Some(Json::Str(text)) => text.chars().count(),
        Some(Json::Object(object)) => object.len(),
        _ => 0,
    }
}

/// Whether `list` holds the string `uuid`.
fn holds(list: Option<&Json>, uuid: &str) -> bool {
    match list {
        Some(Json::Array(items)) => items.iter().any(|item| item.as_str() == Some(uuid)),
        Some(Json::Str(text)) => text.contains(uuid),
        Some(Json::Object(object)) => object.contains_key(uuid),
        _ => false,
    }
}

/// How many objects `uuid` is linked to (`_count_relations`): the threats an
/// objective names, a signal's or rule's parent, and every object that names
/// it as one of those.
fn related_count(uuid: &str, flat: &Object) -> i64 {
    let Some(body) = flat.get(uuid) else {
        return 0;
    };
    let parent = |body: &Json| -> [Option<String>; 2] {
        [
            body.get("owner")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            body.get("detection_model")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        ]
    };
    let mut count = 0i64;
    match infer_type(body).as_deref() {
        Some("objective") => {
            let threats = section(body, "objective").and_then(|o| o.get("threats"));
            count += i64::try_from(length(threats.filter(|t| t.truthy()))).unwrap_or(i64::MAX);
        }
        Some("signal" | "rule") => {
            let owner = body.get("owner").filter(|v| v.truthy());
            if owner
                .or_else(|| body.get("detection_model"))
                .is_some_and(Json::truthy)
            {
                count += 1;
            }
        }
        _ => {}
    }
    for other in flat.values() {
        let named = match infer_type(other).as_deref() {
            Some("objective") => holds(
                section(other, "objective").and_then(|o| o.get("threats")),
                uuid,
            ),
            Some("signal" | "rule") => parent(other).iter().flatten().any(|parent| parent == uuid),
            _ => false,
        };
        count += i64::from(named);
    }
    count
}

/// The deployment status of every rule on every platform
/// (`build_staging_index`).
fn staging_index(rules: &Object) -> Json {
    let mut deployments = Object::new();
    let mut summary: IndexMap<String, [i64; 3]> = IndexMap::new();
    let mut staging: Vec<String> = Vec::new();
    let mut production: Vec<String> = Vec::new();
    for (uuid, body) in rules {
        let mut statuses = Object::new();
        for (platform, configuration) in section(body, "configurations").into_iter().flatten() {
            let status = configuration
                .get("status")
                .map_or_else(|| "UNKNOWN".to_owned(), text)
                .to_uppercase();
            let counts = summary.entry(platform.clone()).or_insert([0; 3]);
            match status.as_str() {
                "PRODUCTION" => {
                    counts[0] += 1;
                    production.push(uuid.clone());
                }
                "STAGING" => {
                    counts[1] += 1;
                    staging.push(uuid.clone());
                }
                _ => counts[2] += 1,
            }
            statuses.insert(platform.clone(), Json::Str(status));
        }
        deployments.insert(uuid.clone(), Json::Object(statuses));
    }
    let sorted_unique = |mut list: Vec<String>| -> Json {
        list.sort();
        list.dedup();
        Json::Array(list.into_iter().map(Json::Str).collect())
    };
    let mut platform_summary = Object::new();
    for (platform, [production, staging, other]) in summary {
        let mut counts = Object::new();
        counts.insert("production".into(), Json::Int(production));
        counts.insert("staging".into(), Json::Int(staging));
        counts.insert("other".into(), Json::Int(other));
        platform_summary.insert(platform, Json::Object(counts));
    }
    let mut index = Object::new();
    index.insert("deployments".into(), Json::Object(deployments));
    index.insert("platformSummary".into(), Json::Object(platform_summary));
    index.insert("stagingObjects".into(), sorted_unique(staging));
    index.insert("productionObjects".into(), sorted_unique(production));
    Json::Object(index)
}

/// `{threat: {relation: [vector, ...]}}` from each threat's
/// `threat.chaining` (`build_chaining_index`), keyed by its
/// `metadata.uuid`.
fn chaining(threats: &Object) -> Json {
    let mut chains: IndexMap<String, IndexMap<String, Vec<Json>>> = IndexMap::new();
    for threat in threats.values() {
        let Some(uuid) = section(threat, "metadata")
            .and_then(|metadata| metadata.get("uuid"))
            .filter(|uuid| uuid.truthy())
        else {
            continue;
        };
        let Some(Json::Array(links)) = section(threat, "threat")
            .and_then(|section| section.get("chaining"))
            .filter(|links| links.truthy())
        else {
            continue;
        };
        let relations = chains.entry(text(uuid)).or_default();
        for link in links {
            let (Some(relation), Some(vector)) = (
                link.get("relation").filter(|value| value.truthy()),
                link.get("vector").filter(|value| value.truthy()),
            ) else {
                continue;
            };
            let vectors = relations.entry(text(relation)).or_default();
            if !vectors.contains(vector) {
                vectors.push(vector.clone());
            }
        }
    }
    Json::Object(
        chains
            .into_iter()
            .map(|(uuid, relations)| {
                (
                    uuid,
                    Json::Object(
                        relations
                            .into_iter()
                            .map(|(relation, vectors)| (relation, Json::Array(vectors)))
                            .collect(),
                    ),
                )
            })
            .collect(),
    )
}

fn strings(items: Vec<String>) -> Json {
    Json::Array(items.into_iter().map(Json::Str).collect())
}

/// One object's summary, its fields in the oracle's order.
fn summary(
    index: &Index,
    uuid: &str,
    body: &Json,
    kind: &str,
    flat: &Object,
) -> Result<Json, Cause> {
    let metadata = |key: &str| {
        section(body, "metadata")
            .and_then(|metadata| metadata.get(key))
            .cloned()
            .unwrap_or(Json::Null)
    };
    let name = body
        .get("name")
        .filter(|name| name.truthy())
        .cloned()
        .unwrap_or_else(|| Json::from(uuid));
    let techniques = crate::attack::techniques(index, uuid).map_err(Cause::from)?;
    let platforms = if kind == "rule" {
        section(body, "configurations")
            .into_iter()
            .flat_map(|configurations| configurations.keys())
            .map(|key| key.replace('_', " "))
            .collect()
    } else {
        Vec::new()
    };
    let mut entry = Object::new();
    entry.insert("uuid".into(), Json::from(uuid));
    entry.insert("type".into(), Json::from(kind));
    entry.insert("name".into(), name);
    entry.insert("schema".into(), metadata("schema"));
    entry.insert("version".into(), metadata("version"));
    entry.insert("tlp".into(), metadata("tlp"));
    entry.insert(
        "status".into(),
        if kind == "rule" {
            status(body)
        } else {
            Json::Null
        },
    );
    entry.insert("techniques".into(), strings(techniques));
    entry.insert(
        "actors".into(),
        Json::Array(if kind == "threat" {
            actors(body)
        } else {
            Vec::new()
        }),
    );
    entry.insert("relatedCount".into(), Json::Int(related_count(uuid, flat)));
    entry.insert("platforms".into(), strings(platforms));
    Ok(Json::Object(entry))
}

/// The bundle (`ExplorerExport.build_bundle`), made at `generated_at`.
///
/// # Errors
///
/// An object whose techniques cannot be resolved (an objective without its
/// `objective` section), named as the oracle names it.
pub fn bundle(index: &Index, generated_at: &str) -> Result<Json, PhaseError> {
    let models = models(index);
    let mut flat = Object::new();
    for bucket in models.values() {
        for (uuid, body) in bucket {
            flat.insert(uuid.clone(), body.clone());
        }
    }
    let empty = Object::new();
    let bucket = |family: &str| models.get(family).unwrap_or(&empty);
    let chains = chaining(bucket("threat"));
    let staging = staging_index(bucket("rule"));
    let mut summaries = Vec::new();
    for (uuid, body) in &flat {
        let Some(kind) = infer_type(body) else {
            continue;
        };
        summaries.push(
            summary(index, uuid, body, &kind, &flat)
                .map_err(|cause| PhaseError::rendering(uuid, &cause))?,
        );
    }
    let signals: Object = bucket("signal")
        .iter()
        .filter(|(_, body)| body.as_object().is_some())
        .map(|(uuid, body)| (uuid.clone(), body.clone()))
        .collect();
    let mut document = Object::new();
    document.insert("version".into(), Json::from("0.1.0"));
    document.insert("generatedAt".into(), Json::from(generated_at));
    document.insert(
        "models".into(),
        Json::Object(
            models
                .into_iter()
                .map(|(family, bucket)| (family.to_owned(), Json::Object(bucket)))
                .collect(),
        ),
    );
    document.insert("flatIndex".into(), Json::Object(flat));
    document.insert("chaining".into(), chains);
    document.insert("signals".into(), Json::Object(signals));
    document.insert("summaries".into(), Json::Array(summaries));
    document.insert("stagingIndex".into(), staging);
    Ok(Json::Object(document))
}

/// The search documents of a bundle (`build_search_documents`): each
/// summary's fields and the first 4000 characters of its object's JSON.
pub fn search(bundle: &Json) -> Json {
    let empty = Object::new();
    let flat = bundle
        .get("flatIndex")
        .and_then(Json::as_object)
        .unwrap_or(&empty);
    let summaries = match bundle.get("summaries") {
        Some(Json::Array(items)) => items.as_slice(),
        _ => &[],
    };
    let documents = summaries
        .iter()
        .map(|summary| {
            let field = |key: &str| summary.get(key).cloned().unwrap_or(Json::Null);
            let uuid = field("uuid");
            let body = uuid
                .as_str()
                .and_then(|uuid| flat.get(uuid))
                .cloned()
                .unwrap_or_else(|| Json::Object(Object::new()));
            let content: String = line(&body).chars().take(CONTENT_LIMIT).collect();
            let status = summary
                .get("status")
                .filter(|status| status.truthy())
                .cloned()
                .unwrap_or_else(|| Json::from(""));
            let mut document = Object::new();
            document.insert("id".into(), uuid.clone());
            document.insert("uuid".into(), uuid);
            document.insert("type".into(), field("type"));
            document.insert("name".into(), field("name"));
            document.insert("techniques".into(), field("techniques"));
            document.insert("actors".into(), field("actors"));
            document.insert("platforms".into(), field("platforms"));
            document.insert("status".into(), status);
            document.insert("relatedCount".into(), field("relatedCount"));
            document.insert("content".into(), Json::Str(content));
            Json::Object(document)
        })
        .collect();
    let mut index = Object::new();
    index.insert("documents".into(), Json::Array(documents));
    Json::Object(index)
}

/// The visibility export: `report` (a JSON object) after its marking and
/// when it was made.
pub fn visibility(report: Json, generated_at: &str, tlp: &str) -> Json {
    let mut document = Object::new();
    document.insert("version".into(), Json::from("1.0"));
    document.insert("generatedAt".into(), Json::from(generated_at));
    document.insert("tlp".into(), Json::from(tlp));
    if let Json::Object(report) = report {
        document.extend(report);
    }
    Json::Object(document)
}

/// The bundle and the search index, in `dir`, in the order they are written.
///
/// # Errors
///
/// See [`bundle`].
pub fn outputs(index: &Index, dir: &Path, generated_at: &str) -> Result<Vec<Output>, PhaseError> {
    let bundle = bundle(index, generated_at)?;
    let search = search(&bundle);
    Ok(vec![
        Output::text(dir.join(BUNDLE), bundle.to_compact()),
        Output::text(dir.join(SEARCH), search.to_compact()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn index_of(objects: &[(&str, &str, &str)]) -> Index {
        let mut index = Index::default();
        for (family, uuid, text) in objects {
            index
                .objects
                .entry((*family).to_owned())
                .or_default()
                .insert(
                    (*uuid).to_owned(),
                    opentide_workspace::Object {
                        uuid: (*uuid).to_owned(),
                        family: (*family).to_owned(),
                        path: PathBuf::from(format!("{uuid}.yaml")),
                        document: std::sync::Arc::new(opentide_schema::node::load(text).unwrap()),
                    },
                );
        }
        let objectives: Vec<String> = index
            .objects
            .get("objective")
            .map(|objects| objects.keys().cloned().collect())
            .unwrap_or_default();
        index.reindex_signals(&objectives);
        index
    }

    fn corpus() -> Index {
        index_of(&[
            (
                "threat",
                "t1",
                concat!(
                    "name: Threat\nmetadata: {uuid: t1, schema: 'threat::1.0', version: 1, tlp: clear}\n",
                    "threat: {mitre_attack: [T1059], actors: [{name: 'att&ck::G0006'}, {name: ''}, x], ",
                    "chaining: [{relation: leads_to, vector: t9}, {relation: leads_to, vector: t9}, {vector: t8}]}\n",
                ),
            ),
            (
                "objective",
                "o1",
                "name: Objective\nmetadata: {uuid: o1, schema: 'objective::1.0'}\n\
                 objective: {threats: [t1], signals: [{uuid: s1, name: Signal}]}\n",
            ),
            (
                "rule",
                "r1",
                "name: Rule é\nmetadata: {uuid: r1, schema: 'rule::1.0'}\ndetection_model: o1\n\
                 configurations: {sentinel: {status: staging}, carbon_black_cloud: {status: PRODUCTION}}\n",
            ),
            (
                "rule",
                "r2",
                "metadata: {uuid: r2}\ndetection_model: s1\nconfigurations: {splunk: {}}\n",
            ),
        ])
    }

    #[test]
    fn the_bundle_summarises_every_object_and_links() {
        let bundle = bundle(&corpus(), "now").unwrap();
        let summaries = match bundle.get("summaries") {
            Some(Json::Array(items)) => items.clone(),
            _ => panic!("no summaries"),
        };
        let uuids: Vec<&str> = summaries
            .iter()
            .map(|s| s.get("uuid").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(uuids, ["t1", "o1", "s1", "r1", "r2"]);
        let by = |uuid: &str| summaries[uuids.iter().position(|u| *u == uuid).unwrap()].clone();
        assert_eq!(
            by("t1").get("actors"),
            Some(&Json::Array(vec![Json::from("att&ck::G0006")]))
        );
        // t1: named by o1's threats.
        assert_eq!(by("t1").get("relatedCount"), Some(&Json::Int(1)));
        // o1: its threat, s1's owner, r1's model.
        assert_eq!(by("o1").get("relatedCount"), Some(&Json::Int(3)));
        assert_eq!(by("s1").get("type"), Some(&Json::from("signal")));
        assert_eq!(
            by("s1").get("techniques"),
            Some(&strings(vec!["T1059".into()]))
        );
        assert_eq!(by("r1").get("status"), Some(&Json::from("PRODUCTION")));
        assert_eq!(
            by("r1").get("platforms"),
            Some(&strings(vec![
                "sentinel".into(),
                "carbon black cloud".into()
            ]))
        );
        assert_eq!(by("r2").get("name"), Some(&Json::from("r2")));
        assert_eq!(by("r2").get("status"), Some(&Json::from("")));
        let chains = bundle.get("chaining").unwrap();
        assert_eq!(line(chains), "{\"t1\": {\"leads_to\": [\"t9\"]}}");
        let staging = bundle.get("stagingIndex").unwrap();
        assert_eq!(
            line(staging),
            "{\"deployments\": {\"r1\": {\"sentinel\": \"STAGING\", \"carbon_black_cloud\": \"PRODUCTION\"}, \"r2\": {\"splunk\": \"UNKNOWN\"}}, \
             \"platformSummary\": {\"sentinel\": {\"production\": 0, \"staging\": 1, \"other\": 0}, \"carbon_black_cloud\": {\"production\": 1, \"staging\": 0, \"other\": 0}, \"splunk\": {\"production\": 0, \"staging\": 0, \"other\": 1}}, \
             \"stagingObjects\": [\"r1\"], \"productionObjects\": [\"r1\"]}"
        );
        let signal = bundle.get("signals").unwrap().get("s1").unwrap();
        assert_eq!(signal.get("owner"), Some(&Json::from("o1")));
    }

    #[test]
    fn a_search_document_carries_the_start_of_its_object() {
        let bundle = bundle(&corpus(), "now").unwrap();
        let search = search(&bundle);
        let Some(Json::Array(documents)) = search.get("documents") else {
            panic!("no documents");
        };
        let rule = &documents[3];
        assert_eq!(rule.get("id"), Some(&Json::from("r1")));
        let content = rule.get("content").unwrap().as_str().unwrap();
        assert!(
            content.starts_with("{\"name\": \"Rule \u{e9}\", \"metadata\": "),
            "{content}"
        );
        let long = "x".repeat(5000);
        let index = index_of(&[(
            "rule",
            "r",
            &format!("name: {long}\nconfigurations: {{a: {{}}}}\n"),
        )]);
        let search = super::search(&super::bundle(&index, "now").unwrap());
        let content = search.get("documents").and_then(|d| match d {
            Json::Array(items) => items[0].get("content").cloned(),
            _ => None,
        });
        assert_eq!(
            content.unwrap().as_str().unwrap().chars().count(),
            CONTENT_LIMIT
        );
    }

    #[test]
    fn an_objective_without_its_section_fails_on_the_key() {
        let index = index_of(&[(
            "objective",
            "o1",
            "name: Broken\nmetadata: {uuid: o1, schema: 'objective::1.0'}\n",
        )]);
        assert_eq!(
            bundle(&index, "now").unwrap_err().detail,
            "KeyError: 'objective' while rendering o1"
        );
    }

    #[test]
    fn the_visibility_export_leads_with_its_marking() {
        let mut report = Object::new();
        report.insert("present".into(), Json::Bool(false));
        assert_eq!(
            line(&visibility(Json::Object(report), "t", "red")),
            "{\"version\": \"1.0\", \"generatedAt\": \"t\", \"tlp\": \"red\", \"present\": false}"
        );
    }
}
