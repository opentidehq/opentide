//! `opentide info`: the counts, the platforms with their tenants, and the
//! vocabularies (`cli/services/info.py`). The tenants are the VS Code
//! extension's contract (`docs/CONTRACTS.md`): name, description,
//! strategies, manual, and the variables each tenant's `setup` names with
//! whether they are set, never a value.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use opentide_schema::node::{Node, Value};
use opentide_schema::objects::fields::{model_schema, newest_model_schema, property};
use opentide_schema::pins::PinTable;
use opentide_schema::vocab::{Version, Vocabularies, Vocabulary};
use regex::Regex;
use serde::Serialize;

use crate::fields::{get, mapping};

/// Every platform, by name ([`opentide_schema::platforms`]).
fn by_name() -> Vec<&'static opentide_schema::platforms::Platform> {
    opentide_schema::platforms::select(opentide_schema::platforms::Order::Name, |_| true)
}

/// The strategies a run deploys, in order.
pub const DEPLOYABLE_STRATEGIES: [&str; 2] = ["PREVIEW", "RELEASE"];

/// A variable a tenant's `setup` names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Variable {
    /// Its name.
    pub name: String,
    /// Whether the environment sets it to something.
    pub set: bool,
}

/// A tenant as written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tenant {
    /// Its name, else `tenant <n>`.
    pub name: String,
    /// Its description.
    pub description: String,
    /// The strategies it accepts.
    pub strategies: Vec<String>,
    /// Whether it is deployed by hand.
    pub manual: bool,
    /// The variables its `setup` names.
    pub variables: Vec<Variable>,
}

/// One platform's row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the document's four flags (vscode-extension docs/CONTRACTS.md)"
)]
pub struct PlatformInfo {
    /// Its key.
    pub name: String,
    /// Whether `[platform] enabled = true`.
    pub enabled: bool,
    /// Whether rules deploy to it.
    pub can_deploy: bool,
    /// Whether `validate --live` checks its queries.
    pub can_validate: bool,
    /// Whether `opentide query` runs on it.
    pub can_query: bool,
    /// Its tenants.
    pub tenants: Vec<Tenant>,
}

#[expect(clippy::expect_used, reason = "a regex literal")]
fn env_reference_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})$")
            .expect("a valid pattern")
    })
}

/// The variable a value names when it is `$NAME` or `${NAME}` as a whole.
pub fn env_reference(value: &str) -> Option<&str> {
    let found = env_reference_pattern().captures(value)?;
    found.get(1).or_else(|| found.get(2)).map(|m| m.as_str())
}

/// The strategies a tenant's `strategies` names: those it lists in
/// deployable order, or every one when absent; as written when one is not
/// a deployable strategy (`validate` reports it).
fn strategies(raw: Option<&Node>) -> Vec<String> {
    let values: Vec<&Node> = match raw.map(|node| (node, &node.value)) {
        None => {
            return DEPLOYABLE_STRATEGIES
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
        }
        Some((node, Value::Str(_))) => vec![node],
        Some((_, Value::Seq(items))) => items.iter().map(AsRef::as_ref).collect(),
        Some(_) => Vec::new(),
    };
    let mut chosen = Vec::new();
    for value in &values {
        for part in value.value.to_string().split(',') {
            let name = part.trim().to_uppercase();
            if name.is_empty() {
                continue;
            }
            if !DEPLOYABLE_STRATEGIES.contains(&name.as_str()) {
                return values.iter().map(|value| value.value.to_string()).collect();
            }
            chosen.push(name);
        }
    }
    DEPLOYABLE_STRATEGIES
        .iter()
        .filter(|strategy| chosen.iter().any(|c| c == *strategy))
        .map(|s| (*s).to_owned())
        .collect()
}

fn truthy_text(node: Option<&Node>) -> Option<String> {
    node.filter(|node| crate::index::truthy(node))
        .map(|node| node.value.to_string())
}

/// Each `[[tenants]]` entry as written. `is_set` says whether the
/// environment sets a variable to something; its value is never read here.
pub fn tenants(configured: Option<&Node>, is_set: &dyn Fn(&str) -> bool) -> Vec<Tenant> {
    let Some(Value::Seq(items)) = configured.map(|node| &node.value) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (position, tenant) in items.iter().enumerate() {
        if !matches!(tenant.value, Value::Map(_)) {
            continue;
        }
        let mut variables: Vec<Variable> = Vec::new();
        if let Some(Value::Map(entries)) = get(tenant, "setup").map(|n| &n.value) {
            for entry in entries {
                if let Value::Str(value) = &entry.value.value
                    && let Some(name) = env_reference(value)
                    && !variables.iter().any(|v| v.name == name)
                {
                    variables.push(Variable {
                        name: name.to_owned(),
                        set: is_set(name),
                    });
                }
            }
        }
        out.push(Tenant {
            name: truthy_text(get(tenant, "name"))
                .unwrap_or_else(|| format!("tenant {}", position + 1)),
            description: truthy_text(get(tenant, "description")).unwrap_or_default(),
            strategies: strategies(get(tenant, "strategies")),
            manual: matches!(
                get(tenant, "manual").map(|n| &n.value),
                Some(Value::Bool(true))
            ),
            variables,
        });
    }
    out
}

/// The platforms, all or the one `only` names, with their tenants, from the
/// resolved `systems` table.
pub fn platforms(
    systems: Option<&Node>,
    only: Option<&str>,
    is_set: &dyn Fn(&str) -> bool,
) -> Vec<PlatformInfo> {
    by_name()
        .into_iter()
        .filter(|platform| only.is_none_or(|only| only == platform.id))
        .map(|platform| {
            let config = systems.and_then(|systems| get(systems, platform.id));
            let enabled = config
                .and_then(|config| mapping(config, "platform"))
                .and_then(|block| get(block, "enabled"))
                .is_some_and(|enabled| matches!(enabled.value, Value::Bool(true)));
            PlatformInfo {
                name: platform.id.to_owned(),
                enabled,
                can_deploy: platform.deploys,
                can_validate: platform.live_check,
                can_query: platform.query_runner,
                tenants: tenants(config.and_then(|c| get(c, "tenants")), is_set),
            }
        })
        .collect()
}

/// The label of a platform key, or the key.
pub fn label(name: &str) -> &str {
    opentide_schema::platforms::get(name).map_or(name, |platform| platform.label)
}

/// One row of `info vocab`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VocabOverview {
    /// Its field name.
    pub name: String,
    /// Its title.
    pub title: String,
    /// How many entries.
    pub entries: usize,
    /// How many of them are removed.
    pub removed: usize,
    /// The newest revision its keys define.
    pub latest_revision: Option<String>,
    /// Whether it has stages.
    pub staged: bool,
}

/// A revision a vocabulary's key lifecycle defines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revision {
    /// `M.m`.
    pub revision: String,
    /// Keys it introduces.
    pub introduced: usize,
    /// Keys it retires.
    pub removed: usize,
    /// Keys a pin to it admits.
    pub admitted: usize,
}

/// An object schema's pin of a vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pin {
    /// The schema revision.
    pub schema: String,
    /// The field.
    pub field: String,
    /// The pinned revision.
    pub revision: String,
    /// Whether the vocabulary defines that revision.
    pub defined: bool,
    /// Keys the pin admits.
    pub admitted: usize,
    /// Whether the model declares the field scoped; `None` when no model
    /// has the field.
    pub scoped: Option<bool>,
}

/// `info vocab <name>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VocabDetail {
    /// The overview's fields.
    #[serde(flatten)]
    pub overview: VocabOverview,
    /// What entries are keyed by.
    pub key: &'static str,
    /// The stages, by id, else name.
    pub stages: Vec<String>,
    /// Each revision, oldest first.
    pub revisions: Vec<Revision>,
    /// Each pin.
    pub pins: Vec<Pin>,
}

fn admitted(vocabulary: &Vocabulary, revision: Version) -> usize {
    vocabulary
        .entries
        .values()
        .filter(|entry| entry.active_at(revision))
        .count()
}

fn revisions(vocabulary: &Vocabulary) -> Vec<Revision> {
    let mut counts: BTreeMap<Version, (usize, usize)> = BTreeMap::new();
    for entry in vocabulary.entries.values() {
        counts.entry(entry.version).or_default().0 += 1;
        if let Some(removed) = entry.removed {
            counts.entry(removed).or_default().1 += 1;
        }
    }
    counts
        .into_iter()
        .map(|(revision, (introduced, removed))| Revision {
            revision: revision.to_string(),
            introduced,
            removed,
            admitted: admitted(vocabulary, revision),
        })
        .collect()
}

fn stages(vocabulary: &Vocabulary) -> Vec<String> {
    vocabulary
        .metadata
        .stages
        .iter()
        .map(|stage| {
            stage
                .id
                .clone()
                .filter(|id| !id.is_empty())
                .or_else(|| stage.name.clone())
                .unwrap_or_default()
        })
        .collect()
}

/// The overview of one vocabulary.
pub fn overview(vocabulary: &Vocabulary) -> VocabOverview {
    VocabOverview {
        name: vocabulary.field().to_owned(),
        title: vocabulary.metadata.name.clone(),
        entries: vocabulary.entries.len(),
        removed: vocabulary
            .entries
            .values()
            .filter(|entry| entry.removed.is_some())
            .count(),
        latest_revision: revisions(vocabulary).last().map(|r| r.revision.clone()),
        staged: !vocabulary.metadata.stages.is_empty(),
    }
}

/// Whether the model of `schema` (or its family's newest) declares the
/// field at `path` scoped.
fn scoped(schema: &str, path: &str) -> Option<bool> {
    let model = model_schema(schema).or_else(|| {
        let family = schema.split_once("::").map_or(schema, |(family, _)| family);
        newest_model_schema(family)
    })?;
    let parts: Vec<&str> = path.split('.').collect();
    let field = property(model, &parts)?;
    Some(
        field
            .get("tide.vocab.scoped")
            .is_some_and(|value| value.as_bool() == Some(true)),
    )
}

/// Everything `info vocab <name>` reports.
pub fn detail(vocabulary: &Vocabulary) -> VocabDetail {
    let revisions = revisions(vocabulary);
    let mut pins = Vec::new();
    type Fields<'a> = Vec<(&'a str, String, Version)>;
    let mut table: Vec<(&str, Fields<'_>)> = PinTable::bundled()
        .iter()
        .map(|(schema, pins)| {
            let mut fields: Vec<(&str, String, Version)> = pins
                .contracts()
                .map(|(path, contract)| (path, contract.field.clone(), contract.version))
                .collect();
            fields.sort_by(|a, b| a.0.cmp(b.0));
            (schema, fields)
        })
        .collect();
    table.sort_by(|a, b| a.0.cmp(b.0));
    for (schema, fields) in table {
        for (path, field, version) in fields {
            if field != vocabulary.field() {
                continue;
            }
            let revision = version.to_string();
            pins.push(Pin {
                schema: schema.to_owned(),
                field: path.to_owned(),
                defined: revisions.iter().any(|r| r.revision == revision),
                revision,
                admitted: admitted(vocabulary, version),
                scoped: scoped(schema, path),
            });
        }
    }
    VocabDetail {
        overview: overview(vocabulary),
        key: match vocabulary.metadata.key {
            opentide_schema::vocab::KeyKind::Name => "name",
            opentide_schema::vocab::KeyKind::Id => "id",
        },
        stages: stages(vocabulary),
        revisions,
        pins,
    }
}

/// The vocabularies loaded from `*.vocab.toml` files, sorted by name,
/// without the object families' own (`families`).
pub fn file_vocabularies(
    vocabularies: &Vocabularies,
    families: &[String],
) -> Vec<std::sync::Arc<Vocabulary>> {
    vocabularies
        .fields()
        .into_iter()
        .filter(|name| !families.iter().any(|family| family == name))
        .filter_map(|name| vocabularies.get(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_schema::node;

    fn root(text: &str) -> Node {
        node::load(text).unwrap().root().unwrap().as_ref().clone()
    }

    #[test]
    fn tenants_name_their_variables_never_a_value() {
        let systems = root(
            "elastic:\n  platform: {enabled: true}\n  tenants:\n    - name: prod\n      strategies: release\n      manual: true\n      setup: {key: $API_KEY, url: '${URL}', secret: '$uP3r-S3cret!', again: $API_KEY}\n    - strategies: [preview, STAGING]\n      description: two\n    - 5\n    - {}\n",
        );
        let set = |name: &str| name == "API_KEY";
        let all = platforms(Some(&systems), None, &set);
        assert_eq!(all.len(), opentide_schema::platforms::COUNT);
        let elastic = platforms(Some(&systems), Some("elastic"), &set).remove(0);
        assert!(elastic.enabled);
        let tenants = elastic.tenants;
        assert_eq!(tenants.len(), 3);
        assert_eq!(tenants[0].name, "prod");
        assert_eq!(tenants[0].strategies, ["RELEASE"]);
        assert!(tenants[0].manual);
        assert_eq!(
            tenants[0].variables,
            [
                Variable {
                    name: "API_KEY".into(),
                    set: true
                },
                Variable {
                    name: "URL".into(),
                    set: false
                }
            ]
        );
        assert_eq!(tenants[1].name, "tenant 2");
        assert_eq!(tenants[1].description, "two");
        assert_eq!(tenants[1].strategies, ["preview", "STAGING"]);
        assert_eq!(tenants[2].name, "tenant 4");
        assert_eq!(tenants[2].strategies, ["PREVIEW", "RELEASE"]);
        assert!(!platforms(None, Some("sentinel"), &set)[0].enabled);
    }

    #[test]
    fn strategies_come_in_deployable_order_once_each() {
        let strategies_of = |text: &str| -> Vec<String> {
            let node = root(text);
            strategies(get(&node, "strategies"))
        };
        // Out of order, repeated, in any case: each once, in deployable order.
        assert_eq!(
            strategies_of("strategies: 'release, preview, PREVIEW'\n"),
            ["PREVIEW", "RELEASE"]
        );
        assert_eq!(
            strategies_of("strategies: [Release, ' preview', release]\n"),
            ["PREVIEW", "RELEASE"]
        );
        assert_eq!(strategies_of("strategies: 'release,,'\n"), ["RELEASE"]);
        // Absent: every one; not a list or text: none.
        assert_eq!(strategies_of("other: 1\n"), ["PREVIEW", "RELEASE"]);
        assert!(strategies_of("strategies: {a: 1}\n").is_empty());
        // One that is not deployable: every value as written.
        assert_eq!(
            strategies_of("strategies: [release, true]\n"),
            ["release", "true"]
        );
    }

    #[test]
    fn references_are_whole_values() {
        assert_eq!(env_reference("$A_1"), Some("A_1"));
        assert_eq!(env_reference("${B}"), Some("B"));
        assert_eq!(env_reference("$1A"), None);
        assert_eq!(env_reference("x$A"), None);
        assert_eq!(label("sysdig"), "Sysdig Secure");
        assert_eq!(label("other"), "other");
    }

    #[test]
    fn the_surface_vocabulary() {
        let vocabularies = Vocabularies::bundled();
        let surface = vocabularies.get("surface").unwrap();
        let detail = detail(&surface);
        assert_eq!(detail.overview.entries, 895);
        assert_eq!(detail.key, "name");
        assert_eq!(detail.pins.len(), 1);
        assert_eq!(detail.pins[0].schema, "threat::1.0");
        assert_eq!(detail.pins[0].scoped, Some(true));
        let names: Vec<String> = file_vocabularies(&vocabularies, &["threat".into()])
            .iter()
            .map(|v| v.field().to_owned())
            .collect();
        assert_eq!(names.len(), 35);
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
