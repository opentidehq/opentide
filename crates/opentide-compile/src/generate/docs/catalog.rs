//! The objects a documentation run writes pages for, read into their models,
//! and the relations between them the pages show
//! (`documentation/catalog.py`, `generation/framework.py` `relations_list`,
//! `keep_active_rules`, `chain_resolver`).

use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use opentide_schema::error::{ErrorKind, PathSegment, SchemaError};
use opentide_schema::from_node::{Invalid, validate};
use opentide_schema::node::{Node, Value};
use opentide_schema::objects::{
    ObjectiveV1_0, RuleV1_0, RuleV1_1, ThreatVector, threat::Killchain,
};
use opentide_schema::{PinTable, Pins};
use opentide_workspace::Index;

use super::flavor::slugify;
use super::vocab::Vocab;
use crate::generate::relations::Relations;
use crate::generate::{Cause, PhaseError};
use crate::strategy::{StatusError, StatusStrategy, Statuses};

/// A rule, in the revision its `metadata.schema` names.
#[derive(Debug, Clone)]
pub enum RuleModel {
    /// `rule::1.0`.
    V1_0(Box<RuleV1_0>),
    /// `rule::1.1`.
    V1_1(Box<RuleV1_1>),
}

/// The model of a catalogue object.
#[derive(Debug, Clone)]
pub enum Model {
    /// A detection rule.
    Rule(RuleModel),
    /// A detection objective.
    Objective(Box<ObjectiveV1_0>),
    /// A threat vector.
    Threat(Box<ThreatVector>),
}

/// An object family that has pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// Rule pages, `rules/`.
    Rules,
    /// Objective pages, `objectives/`.
    Objectives,
    /// Threat pages, `threats/`.
    Threats,
}

impl Scope {
    /// Every object scope, in the order a full run writes them.
    pub const ALL: [Self; 3] = [Self::Rules, Self::Objectives, Self::Threats];

    /// The folder of its pages, and its name in a run's counts.
    pub fn folder(self) -> &'static str {
        match self {
            Self::Rules => "rules",
            Self::Objectives => "objectives",
            Self::Threats => "threats",
        }
    }

    /// The scope of an object type (`rule`).
    pub fn of_type(object_type: &str) -> Option<Self> {
        match object_type {
            "rule" => Some(Self::Rules),
            "objective" => Some(Self::Objectives),
            "threat" => Some(Self::Threats),
            _ => None,
        }
    }
}

/// One object of the catalogue.
#[derive(Debug, Clone)]
pub struct Record {
    /// Its family.
    pub scope: Scope,
    /// Its UUID.
    pub uuid: String,
    /// Its name.
    pub name: String,
    /// Its page's file name stem, unique in its folder.
    pub slug: String,
    /// Its model.
    pub model: Model,
}

/// A signal, which lives on its objective's page.
#[derive(Debug, Clone)]
pub struct SignalRecord {
    /// Its UUID.
    pub uuid: String,
    /// Its name.
    pub name: String,
    /// Its objective.
    pub owner: String,
}

/// Relations walked one way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Parents, up to the threats.
    Upstream,
    /// Children, down to the rules.
    Downstream,
    /// Both.
    Both,
}

impl Direction {
    /// Its name in `documentation.toml`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Downstream => "downstream",
            Self::Both => "both",
        }
    }
}

/// Related objects by type, in the order the walk met each type.
pub type Flat = IndexMap<String, Vec<String>>;

/// A related object of a page's table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Related {
    /// Its UUID.
    pub uuid: String,
    /// Its type (`objective`).
    pub object_type: String,
    /// Which walk found it.
    pub direction: Direction,
    /// Its name.
    pub name: String,
}

/// A link of a threat's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEntry {
    /// The threat it names.
    pub uuid: String,
    /// The relation, if any.
    pub relation: Option<String>,
    /// The description, or the relation's.
    pub description: Option<String>,
    /// The threat's name.
    pub name: String,
}

/// A node of a coverage or chaining graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    /// Its UUID.
    pub uuid: String,
    /// Its name.
    pub name: String,
    /// Its type.
    pub object_type: &'static str,
    /// A threat's first kill chain stage.
    pub killchain: Option<String>,
}

/// An edge of a coverage or chaining graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    /// From.
    pub source: String,
    /// To.
    pub target: String,
    /// The label.
    pub label: Option<String>,
    /// Drawn both ways.
    pub both_ways: bool,
}

/// A small typed graph.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Graph {
    /// Nodes, in order.
    pub nodes: Vec<GraphNode>,
    /// Edges, in order.
    pub edges: Vec<GraphEdge>,
}

impl Graph {
    /// Nothing worth drawing: no edge and at most one node.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty() && self.nodes.len() <= 1
    }

    fn add_node(&mut self, uuid: &str, name: &str, object_type: &'static str) {
        if !self.nodes.iter().any(|node| node.uuid == uuid) {
            self.nodes.push(GraphNode {
                uuid: uuid.to_owned(),
                name: name.to_owned(),
                object_type,
                killchain: None,
            });
        }
    }

    fn has(&self, uuid: &str) -> bool {
        self.nodes.iter().any(|node| node.uuid == uuid)
    }

    fn add_edge(&mut self, source: &str, target: &str, label: Option<&str>, both_ways: bool) {
        if !self.has(source) || !self.has(target) {
            return;
        }
        let duplicate = self.edges.iter().any(|edge| {
            edge.source == source
                && edge.target == target
                && edge.label.as_deref().unwrap_or_default() == label.unwrap_or_default()
        });
        if !duplicate {
            self.edges.push(GraphEdge {
                source: source.to_owned(),
                target: target.to_owned(),
                label: label.map(str::to_owned),
                both_ways,
            });
        }
    }
}

/// The catalogue: every rule, objective and threat, by name.
pub struct Catalog<'i> {
    /// Rules, by name.
    pub rules: Vec<Record>,
    /// Objectives, by name.
    pub objectives: Vec<Record>,
    /// Threats, by name.
    pub threats: Vec<Record>,
    /// Signals, objective by objective.
    pub signals: Vec<SignalRecord>,
    by_uuid: HashMap<String, (Scope, usize)>,
    signal_by_uuid: HashMap<String, usize>,
    relations: Relations<'i>,
    statuses: Statuses,
    /// Each rule's `configurations` as written, by UUID.
    written: HashMap<String, crate::json::Json>,
}

impl<'i> Catalog<'i> {
    /// The catalogue of `index`.
    ///
    /// # Errors
    ///
    /// An object that does not read into its model, as the oracle's
    /// `ValidationError` names the first error of the first such object:
    /// rules first, then threats, then objectives.
    pub fn build(index: &'i Index, statuses: Statuses) -> Result<Self, PhaseError> {
        let mut rules = Vec::new();
        let mut written = HashMap::new();
        for object in index.family("rule") {
            let model = rule_model(&object.document)?;
            if let Some(configurations) = object
                .document
                .root()
                .and_then(|root| root.get("configurations"))
            {
                written
                    .entry(object.uuid.clone())
                    .or_insert_with(|| crate::json::Json::from_node(configurations));
            }
            let name = match &model {
                RuleModel::V1_0(rule) => rule.name.clone(),
                RuleModel::V1_1(rule) => rule.name.clone(),
            };
            rules.push((object.uuid.clone(), name, Model::Rule(model)));
        }
        let mut threats = Vec::new();
        for object in index.family("threat") {
            let threat: ThreatVector = typed(&object.document)?;
            threats.push((
                object.uuid.clone(),
                threat.name.clone(),
                Model::Threat(Box::new(threat)),
            ));
        }
        let mut objectives = Vec::new();
        for object in index.family("objective") {
            let objective: ObjectiveV1_0 = typed(&object.document)?;
            objectives.push((
                object.uuid.clone(),
                objective.name.clone(),
                Model::Objective(Box::new(objective)),
            ));
        }
        let rules = records(Scope::Rules, rules);
        let objectives = records(Scope::Objectives, objectives);
        let threats = records(Scope::Threats, threats);
        let mut signals = Vec::new();
        for record in &objectives {
            if let Model::Objective(objective) = &record.model {
                for signal in &objective.objective.signals {
                    signals.push(SignalRecord {
                        uuid: signal.uuid.clone(),
                        name: signal.name.clone(),
                        owner: record.uuid.clone(),
                    });
                }
            }
        }
        let mut by_uuid = HashMap::new();
        for (scope, list) in [
            (Scope::Rules, &rules),
            (Scope::Objectives, &objectives),
            (Scope::Threats, &threats),
        ] {
            for (position, record) in list.iter().enumerate() {
                by_uuid
                    .entry(record.uuid.clone())
                    .or_insert((scope, position));
            }
        }
        let mut signal_by_uuid = HashMap::new();
        for (position, signal) in signals.iter().enumerate() {
            signal_by_uuid
                .entry(signal.uuid.clone())
                .or_insert(position);
        }
        Ok(Self {
            rules,
            objectives,
            threats,
            signals,
            by_uuid,
            signal_by_uuid,
            relations: Relations::new(index),
            statuses,
            written,
        })
    }

    /// A rule's `configurations` as its file writes them: what the author
    /// set, beside the defaults its model fills in.
    pub fn written_configurations(&self, uuid: &str) -> Option<&crate::json::Json> {
        self.written.get(uuid)
    }

    /// The records of `scope`.
    pub fn records(&self, scope: Scope) -> &[Record] {
        match scope {
            Scope::Rules => &self.rules,
            Scope::Objectives => &self.objectives,
            Scope::Threats => &self.threats,
        }
    }

    /// The record `uuid` names.
    pub fn record(&self, uuid: &str) -> Option<&Record> {
        let (scope, position) = self.by_uuid.get(uuid)?;
        self.records(*scope).get(*position)
    }

    /// The signal `uuid` names.
    pub fn signal(&self, uuid: &str) -> Option<&SignalRecord> {
        self.signal_by_uuid
            .get(uuid)
            .and_then(|position| self.signals.get(*position))
    }

    /// The name of `uuid`, else the UUID itself.
    pub fn name(&self, uuid: &str) -> String {
        if let Some(record) = self.record(uuid) {
            return record.name.clone();
        }
        if let Some(signal) = self.signal(uuid) {
            return signal.name.clone();
        }
        uuid.to_owned()
    }

    /// The type of `uuid` (`get_type`).
    ///
    /// # Errors
    ///
    /// The object is not in the index or has no type.
    pub fn kind(&self, uuid: &str) -> Result<String, Cause> {
        self.relations.kind(uuid)
    }

    /// The related objects of `uuid` by type (`relations_list(…, "flat")`).
    ///
    /// # Errors
    ///
    /// An object of the walk the index cannot type, a broken detection
    /// model, or a rule status deployment.toml does not define.
    pub fn flat(&self, uuid: &str, direction: Direction) -> Result<Flat, Cause> {
        let mut flat = match direction {
            Direction::Both => {
                let mut flat = self.flat_one(uuid, Direction::Downstream)?;
                for (kind, ids) in self.flat_one(uuid, Direction::Upstream)? {
                    flat.insert(kind, ids);
                }
                flat
            }
            one => self.flat_one(uuid, one)?,
        };
        for ids in flat.values_mut() {
            let mut seen = HashSet::new();
            ids.retain(|id| seen.insert(id.clone()));
        }
        Ok(flat)
    }

    fn flat_one(&self, uuid: &str, direction: Direction) -> Result<Flat, Cause> {
        let tree = if direction == Direction::Upstream {
            self.upstream(uuid)?
        } else {
            self.downstream(uuid)?
        };
        let mut flat = Flat::new();
        match &tree {
            Tree::List(list) => {
                if let Some(first) = list.first() {
                    flat.insert(self.kind(first)?, list.clone());
                }
            }
            Tree::Map(entries) => self.flatten(entries, &mut flat)?,
            Tree::Leaf => {}
        }
        if let Some(rules) = flat.get("rule").cloned() {
            let active = self.active_rules(&rules)?;
            flat.insert("rule".to_owned(), active);
        }
        Ok(flat)
    }

    fn flatten(&self, entries: &[(String, Tree)], flat: &mut Flat) -> Result<(), Cause> {
        for (key, value) in entries {
            if !key.is_empty() {
                flat.entry(self.kind(key)?).or_default().push(key.clone());
            }
            match value {
                Tree::List(list) => {
                    if let Some(first) = list.first() {
                        flat.entry(self.kind(first)?)
                            .or_default()
                            .extend(list.iter().cloned());
                    }
                }
                Tree::Map(inner) => self.flatten(inner, flat)?,
                Tree::Leaf => {}
            }
        }
        Ok(())
    }

    /// `relations_downstream`.
    fn downstream(&self, uuid: &str) -> Result<Tree, Cause> {
        let kind = self.kind(uuid)?;
        if kind == "signal" {
            return Ok(Tree::List(
                self.active_rules(&self.relations.children(uuid)?)?,
            ));
        }
        let mut entries: Vec<(String, Tree)> = Vec::new();
        for child in self.relations.children(uuid)? {
            let value = if kind == "objective" {
                match self.kind(&child)?.as_str() {
                    "signal" => self.downstream(&child)?,
                    "rule" => Tree::Leaf,
                    _ => continue,
                }
            } else {
                self.downstream(&child)?
            };
            insert(&mut entries, child, value);
        }
        Ok(Tree::Map(entries))
    }

    /// `relations_upstream`.
    fn upstream(&self, uuid: &str) -> Result<Tree, Cause> {
        if self.kind(uuid)? == "threat" {
            return Ok(Tree::List(Vec::new()));
        }
        let mut entries: Vec<(String, Tree)> = Vec::new();
        for parent in self.relations.parents(uuid)? {
            let value = self.upstream(&parent)?;
            insert(&mut entries, parent, value);
        }
        Ok(Tree::Map(entries))
    }

    /// The rules of `rules` none of whose platform blocks has a status
    /// deploying to remove or disable it (`keep_active_rules`).
    fn active_rules(&self, rules: &[String]) -> Result<Vec<String>, Cause> {
        let mut active = Vec::new();
        for uuid in rules {
            let Some(body) = self
                .relations
                .index()
                .get("rule", uuid)
                .and_then(|object| object.root())
            else {
                continue;
            };
            let mut deprecated = false;
            if let Some(Value::Map(blocks)) = body.get("configurations").map(|node| &node.value) {
                for block in blocks {
                    let status = match &block.value.value {
                        Value::Map(_) => block
                            .value
                            .get("status")
                            .ok_or_else(|| Cause::MissingKey("status".to_owned()))?,
                        _ => {
                            return Err(Cause::Other(
                                "a platform block is not a mapping".to_owned(),
                            ));
                        }
                    };
                    let status = crate::generate::relations::node_text(status);
                    let strategy =
                        self.statuses
                            .strategy(&status)
                            .map_err(|error| match error {
                                StatusError::Unknown(message) => Cause::MissingKey(message),
                                StatusError::Invalid(message) => Cause::Other(message),
                            })?;
                    if matches!(
                        strategy,
                        StatusStrategy::Deletion | StatusStrategy::Disablement
                    ) {
                        deprecated = true;
                    }
                }
            }
            if !deprecated {
                active.push(uuid.clone());
            }
        }
        Ok(active)
    }

    /// The related objects of `uuid`, upstream then downstream, each type's
    /// sorted by UUID (`related_entries`). A walk that fails shows nothing.
    pub fn related(&self, uuid: &str, direction: Direction) -> Vec<Related> {
        let walks: &[Direction] = match direction {
            Direction::Both => &[Direction::Upstream, Direction::Downstream],
            Direction::Upstream => &[Direction::Upstream],
            Direction::Downstream => &[Direction::Downstream],
        };
        let mut out = Vec::new();
        for walk in walks {
            let Ok(flat) = self.flat(uuid, *walk) else {
                continue;
            };
            for (object_type, ids) in flat {
                let mut ids = ids;
                ids.sort();
                ids.dedup();
                for id in ids {
                    if id == uuid {
                        continue;
                    }
                    let name = self.name(&id);
                    out.push(Related {
                        uuid: id,
                        object_type: object_type.clone(),
                        direction: *walk,
                        name,
                    });
                }
            }
        }
        out
    }

    /// How many objects `uuid` relates to, for the index (`relations_list`).
    ///
    /// # Errors
    ///
    /// [`Self::flat`]'s.
    pub fn relation_count(&self, uuid: &str, direction: Direction) -> Result<usize, Cause> {
        let flat = self.flat(uuid, direction)?;
        let unique: HashSet<&String> = flat.values().flatten().collect();
        Ok(unique.len())
    }

    /// The rules implementing the signal `uuid`, sorted (`rules_for_signal`).
    pub fn rules_for_signal(&self, uuid: &str) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        match self.kind(uuid) {
            Ok(kind) if kind != "signal" => return Vec::new(),
            Ok(_) => {
                if let Ok(children) = self.relations.children(uuid) {
                    for child in children {
                        match self.kind(&child) {
                            Ok(kind) if kind == "rule" => found.push(child),
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
            Err(_) => {}
        }
        if let Ok(flat) = self.flat(uuid, Direction::Downstream)
            && let Some(rules) = flat.get("rule")
        {
            found.extend(rules.iter().cloned());
        }
        found.sort();
        found.dedup();
        let known: Vec<String> = found
            .iter()
            .filter(|uuid| self.record(uuid).is_some_and(|r| r.scope == Scope::Rules))
            .cloned()
            .collect();
        if known.is_empty() { found } else { known }
    }

    /// The links of the threat `uuid`'s own `chaining` (`chaining_entries`).
    pub fn chaining_entries(&self, uuid: &str, vocab: &Vocab<'_>) -> Vec<ChainEntry> {
        let Some(Model::Threat(threat)) = self.record(uuid).map(|record| &record.model) else {
            return Vec::new();
        };
        let mut chain = Vec::new();
        for entry in threat.threat.chaining.iter().flatten() {
            let Some(target) = chain_target(entry) else {
                continue;
            };
            let relation = entry
                .get("relation")
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty());
            let mut description = entry
                .get("description")
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty());
            if let Some(relation) = &relation
                && description.is_none()
            {
                description = Some(vocab.description("chaining_relations", relation))
                    .map(|text| text.trim().to_owned())
                    .filter(|text| !text.is_empty());
            }
            chain.push(ChainEntry {
                uuid: target.to_owned(),
                relation,
                description,
                name: self.name(target),
            });
        }
        chain
    }

    /// The threats chained to and from the threat `uuid` (`chaining_network`).
    pub fn chaining_network(&self, uuid: &str, vocab: &Vocab<'_>) -> Graph {
        let index = &self.relations.index().chaining;
        let mut chain: IndexMap<String, IndexMap<String, Vec<String>>> = IndexMap::new();
        for (vector, links) in index {
            for (relation, targets) in links {
                if !targets.iter().any(|target| target == uuid) {
                    continue;
                }
                let list = chain
                    .entry(vector.clone())
                    .or_default()
                    .entry(relation.clone())
                    .or_default();
                if !list.iter().any(|target| target == uuid) {
                    list.push(uuid.to_owned());
                }
            }
        }
        let vectors: Vec<String> = chain.keys().cloned().collect();
        for vector in vectors {
            resolve_chain(index, &vector, &mut chain);
        }
        resolve_chain(index, uuid, &mut chain);
        for entry in self.chaining_entries(uuid, vocab) {
            let relation = entry.relation.unwrap_or_else(|| "related".to_owned());
            let list = chain
                .entry(uuid.to_owned())
                .or_default()
                .entry(relation)
                .or_default();
            if !list.contains(&entry.uuid) {
                list.push(entry.uuid);
            }
        }
        let mut graph = Graph::default();
        let add_threat = |graph: &mut Graph, id: &str| {
            if id.is_empty() || graph.has(id) {
                return;
            }
            let record = self.record(id);
            let name = record.map_or_else(|| self.name(id), |record| record.name.clone());
            let killchain = record.and_then(|record| match &record.model {
                Model::Threat(threat) => match &threat.threat.killchain {
                    Some(Killchain::One(stage)) if !stage.is_empty() => Some(stage.clone()),
                    Some(Killchain::Many(stages)) => stages.first().cloned(),
                    _ => None,
                },
                _ => None,
            });
            graph.nodes.push(GraphNode {
                uuid: id.to_owned(),
                name,
                object_type: "threat",
                killchain,
            });
        };
        add_threat(&mut graph, uuid);
        for (source, links) in &chain {
            add_threat(&mut graph, source);
            for (relation, targets) in links {
                let key = relation.rsplit("::").next().unwrap_or_default();
                let both_ways = vocab
                    .extra("chaining_relations", key, "tide.vocab.relation.type")
                    .trim()
                    == "bidirectional";
                for target in targets {
                    add_threat(&mut graph, target);
                    graph.add_edge(source, target, Some(key), both_ways);
                }
            }
        }
        graph
    }

    /// The threat → objective → signal → rule graph around `uuid`
    /// (`coverage_graph`).
    pub fn coverage_graph(&self, uuid: &str) -> Graph {
        let mut graph = Graph::default();
        let Some(record) = self.record(uuid) else {
            return graph;
        };
        match record.scope {
            Scope::Threats => {
                graph.add_node(uuid, &record.name, "threat");
                for objective in &self.objectives {
                    if let Model::Objective(model) = &objective.model
                        && model
                            .objective
                            .threats
                            .iter()
                            .flatten()
                            .any(|threat| threat == uuid)
                    {
                        self.add_objective(&mut graph, &objective.uuid);
                    }
                }
            }
            Scope::Objectives => self.add_objective(&mut graph, uuid),
            Scope::Rules => {
                graph.add_node(uuid, &record.name, "rule");
                if let Some(model) = rule_detection_model(&record.model)
                    && !model.is_empty()
                {
                    self.add_rule_lineage(&mut graph, uuid, model);
                }
            }
        }
        graph
    }

    /// A rule page's own path (`_add_rule_lineage`): the threats, its
    /// objective, its signal, the rule. Sibling rules of the objective are
    /// left out: they belong on the objective's page, and on a rule page
    /// they buried the rule itself.
    fn add_rule_lineage(&self, graph: &mut Graph, rule: &str, model: &str) {
        let signal = self.signal(model);
        let objective = signal.map_or(model, |signal| signal.owner.as_str());
        let Some(record) = self.record(objective) else {
            return;
        };
        let Model::Objective(body) = &record.model else {
            return;
        };
        graph.add_node(objective, &record.name, "objective");
        for threat in body.objective.threats.iter().flatten() {
            let Some(threat_record) = self.record(threat) else {
                continue;
            };
            graph.add_node(threat, &threat_record.name, "threat");
            graph.add_edge(threat, objective, Some("covers"), false);
        }
        if let Some(signal) = signal {
            graph.add_node(&signal.uuid, &signal.name, "signal");
            graph.add_edge(objective, &signal.uuid, None, false);
            graph.add_edge(&signal.uuid, rule, Some("implements"), false);
        } else {
            graph.add_edge(objective, rule, Some("implements"), false);
        }
    }

    fn add_objective(&self, graph: &mut Graph, uuid: &str) {
        let uuid = self
            .signal(uuid)
            .map_or(uuid, |signal| signal.owner.as_str());
        let Some(record) = self.record(uuid).filter(|r| r.scope == Scope::Objectives) else {
            return;
        };
        let Model::Objective(objective) = &record.model else {
            return;
        };
        graph.add_node(uuid, &record.name, "objective");
        for threat in objective.objective.threats.iter().flatten() {
            let Some(threat_record) = self.record(threat) else {
                continue;
            };
            graph.add_node(threat, &threat_record.name, "threat");
            graph.add_edge(threat, uuid, Some("covers"), false);
        }
        let mut linked: HashSet<String> = HashSet::new();
        for signal in &objective.objective.signals {
            graph.add_node(&signal.uuid, &signal.name, "signal");
            graph.add_edge(uuid, &signal.uuid, None, false);
            for rule in self.rules_for_signal(&signal.uuid) {
                let Some(rule_record) = self.record(&rule) else {
                    continue;
                };
                graph.add_node(&rule, &rule_record.name, "rule");
                graph.add_edge(&signal.uuid, &rule, Some("implements"), false);
                linked.insert(rule);
            }
        }
        for rule in &self.rules {
            if rule_detection_model(&rule.model) != Some(uuid) {
                continue;
            }
            graph.add_node(&rule.uuid, &rule.name, "rule");
            if !linked.contains(&rule.uuid) {
                graph.add_edge(uuid, &rule.uuid, Some("implements"), false);
            }
        }
    }
}

/// The threat a `chaining` entry names: `vector`, `target`, `uuid` or `id`.
pub fn chain_target(entry: &indexmap::IndexMap<String, String>) -> Option<&str> {
    ["vector", "target", "uuid", "id"].iter().find_map(|key| {
        entry
            .get(*key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    })
}

/// A rule's `detection_model`.
pub fn rule_detection_model(model: &Model) -> Option<&str> {
    match model {
        Model::Rule(RuleModel::V1_0(rule)) => rule.detection_model.as_deref(),
        Model::Rule(RuleModel::V1_1(rule)) => rule.detection_model.as_deref(),
        _ => None,
    }
}

/// `chain_resolver`: every chain reachable from `entry`, depth first.
fn resolve_chain(
    index: &IndexMap<String, IndexMap<String, Vec<String>>>,
    entry: &str,
    chain: &mut IndexMap<String, IndexMap<String, Vec<String>>>,
) {
    let Some(links) = index.get(entry) else {
        return;
    };
    for (link, targets) in links {
        chain
            .entry(entry.to_owned())
            .or_default()
            .entry(link.clone())
            .or_default();
        for target in targets {
            let list = chain
                .entry(entry.to_owned())
                .or_default()
                .entry(link.clone())
                .or_default();
            if !list.contains(target) {
                list.push(target.clone());
                resolve_chain(index, target, chain);
            }
        }
    }
}

/// A walk's result before it is flattened: a mapping keyed by UUID, a list
/// of UUIDs, or nothing.
enum Tree {
    Map(Vec<(String, Tree)>),
    List(Vec<String>),
    Leaf,
}

/// Sets `key` as a dict does: a key met again keeps its place, its value
/// replaced.
fn insert(entries: &mut Vec<(String, Tree)>, key: String, value: Tree) {
    if let Some(slot) = entries.iter_mut().find(|(existing, _)| *existing == key) {
        slot.1 = value;
    } else {
        entries.push((key, value));
    }
}

/// Records sorted by name (case-insensitive, stable), each with a slug no
/// other record of the folder shares: the lowest UUID keeps the plain slug,
/// the others get the first 8 characters of their UUID (`unique_slugs`).
fn records(scope: Scope, mut objects: Vec<(String, String, Model)>) -> Vec<Record> {
    objects.sort_by_cached_key(|(_, name, _)| name.to_lowercase());
    let mut groups: IndexMap<String, Vec<usize>> = IndexMap::new();
    for (position, (_, name, _)) in objects.iter().enumerate() {
        groups.entry(slugify(name)).or_default().push(position);
    }
    let mut taken: HashSet<String> = groups.keys().cloned().collect();
    let mut slugs = vec![String::new(); objects.len()];
    for (slug, positions) in &groups {
        let mut positions = positions.clone();
        positions.sort_by(|a, b| objects[*a].0.cmp(&objects[*b].0));
        let mut positions = positions.into_iter();
        if let Some(first) = positions.next() {
            slugs[first].clone_from(slug);
        }
        for position in positions {
            let uuid = &objects[position].0;
            let suffix: String = if uuid.is_empty() {
                "object".to_owned()
            } else {
                uuid.chars().take(8).collect()
            };
            let mut candidate = format!("{slug}-{suffix}");
            let mut counter = 1;
            while taken.contains(&candidate) {
                candidate = format!("{slug}-{suffix}-{counter}");
                counter += 1;
            }
            taken.insert(candidate.clone());
            slugs[position] = candidate;
        }
    }
    objects
        .into_iter()
        .zip(slugs)
        .map(|((uuid, name, model), slug)| Record {
            scope,
            uuid,
            name,
            slug,
            model,
        })
        .collect()
}

/// The rule's model, by the revision `metadata.schema` names.
fn rule_model(document: &opentide_schema::node::Document) -> Result<RuleModel, PhaseError> {
    let schema = document
        .root()
        .and_then(|root| root.get("metadata"))
        .and_then(|metadata| metadata.get("schema"))
        .and_then(|schema| schema.value.as_str())
        .unwrap_or_default();
    if schema == "rule::1.0" {
        typed::<RuleV1_0>(document).map(|rule| RuleModel::V1_0(Box::new(rule)))
    } else {
        typed::<RuleV1_1>(document).map(|rule| RuleModel::V1_1(Box::new(rule)))
    }
}

/// The document's model, read and then checked against the model's
/// constraints (garde, with the pins of the revision `metadata.schema`
/// names), as the oracle's pydantic model validates both.
fn typed<T>(document: &opentide_schema::node::Document) -> Result<T, PhaseError>
where
    T: opentide_schema::FromNode + garde::Validate<Context = Pins>,
{
    let root = document.root().map(AsRef::as_ref);
    let revision = root
        .and_then(|root| root.get("metadata"))
        .and_then(|metadata| metadata.get("schema"))
        .and_then(|schema| schema.value.as_str())
        .unwrap_or_default();
    let pins = PinTable::bundled()
        .get(revision)
        .cloned()
        .unwrap_or_default();
    validate::<T>(document, &pins).map_err(|invalid| {
        PhaseError::new(match invalid {
            Invalid::Structure(errors) => describe(&errors, root),
            Invalid::Constraints(report) => describe_constraints(&report, root),
        })
    })
}

/// One line for a model's failed constraints, worded as [`describe`] words
/// a structure error: the first, where and what, and how many more.
fn describe_constraints(report: &garde::Report, root: Option<&Node>) -> String {
    let errors: Vec<_> = report.iter().collect();
    let Some((path, error)) = errors.first() else {
        return "an object does not validate; opentide validate shows each finding".to_owned();
    };
    let location = path.to_string();
    let location = if location.is_empty() {
        "the object".to_owned()
    } else {
        location
    };
    let mut message = error.message().to_owned();
    if let Some(head) = message.chars().next() {
        message = head.to_lowercase().collect::<String>() + &message[head.len_utf8()..];
    }
    let subject = root
        .and_then(|root| root.get("name"))
        .and_then(|name| name.value.as_str())
        .filter(|name| !name.is_empty())
        .map_or_else(
            || "an object".to_owned(),
            opentide_schema::configuration::repr::quote,
        );
    let more = if errors.len() > 1 {
        format!(" (and {} more)", errors.len() - 1)
    } else {
        String::new()
    };
    format!(
        "{subject} does not validate: {location}: {message}{more}; opentide validate shows each finding"
    )
}

/// One line for a model's errors, as the oracle words a `ValidationError`
/// (`describe_validation_error`): the first error, where and what, the
/// object's name when the input has one, and how many more. A rule's platform
/// blocks and response are read on their own first, so their errors are
/// placed in the block.
fn describe(errors: &[SchemaError], root: Option<&Node>) -> String {
    let mut group: Vec<&SchemaError> = Vec::new();
    let mut strip = 0;
    if let Some(Value::Map(blocks)) = root
        .and_then(|root| root.get("configurations"))
        .map(|node| &node.value)
    {
        for block in blocks {
            let Some(name) = block.key.value.as_str() else {
                continue;
            };
            let prefix = [
                PathSegment::Key("configurations".to_owned()),
                PathSegment::Key(name.to_owned()),
            ];
            group = errors
                .iter()
                .filter(|error| error.path.starts_with(&prefix))
                .collect();
            if !group.is_empty() {
                strip = 2;
                break;
            }
        }
    }
    if group.is_empty() {
        let prefix = [PathSegment::Key("response".to_owned())];
        group = errors
            .iter()
            .filter(|error| error.path.starts_with(&prefix))
            .collect();
        strip = 1;
    }
    if group.is_empty() {
        group = errors.iter().collect();
        strip = 0;
    }
    let Some(first) = group.first() else {
        return "an object does not validate; opentide validate shows each finding".to_owned();
    };
    let location = first.path[strip.min(first.path.len())..]
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".");
    let location = if location.is_empty() {
        "the object".to_owned()
    } else {
        location
    };
    let mut message = first.message.clone();
    if let Some(head) = message.chars().next() {
        message = head.to_lowercase().collect::<String>() + &message[head.len_utf8()..];
    }
    // Pydantic's input: the mapping a missing field is missing from, else the value.
    let input_path = if first.kind == ErrorKind::Missing && !first.path.is_empty() {
        &first.path[..first.path.len() - 1]
    } else {
        &first.path[..]
    };
    let subject = root
        .and_then(|root| at(root, input_path))
        .and_then(|input| input.get("name"))
        .and_then(|name| name.value.as_str())
        .filter(|name| !name.is_empty())
        .map_or_else(
            || "an object".to_owned(),
            opentide_schema::configuration::repr::quote,
        );
    let more = if group.len() > 1 {
        format!(" (and {} more)", group.len() - 1)
    } else {
        String::new()
    };
    format!(
        "{subject} does not validate: {location}: {message}{more}; opentide validate shows each finding"
    )
}

fn at<'n>(node: &'n Node, path: &[PathSegment]) -> Option<&'n Node> {
    let mut current = node;
    for segment in path {
        current = match (segment, &current.value) {
            (PathSegment::Key(key), Value::Map(_)) => current.get(key)?,
            (PathSegment::Index(position), Value::Seq(items)) => items.get(*position)?,
            _ => return None,
        };
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(uuid: &str, name: &str) -> (String, String, Model) {
        let threat: ThreatVector = opentide_schema::from_node::from_document(
            &opentide_schema::node::load(&format!(
                "name: {name}\ncriticality: High\nmetadata:\n  uuid: {uuid}\n  schema: threat::1.0\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-01\n  tlp: clear\nthreat:\n  description: d\n  severity: s\n  impact: [i]\n  leverage: [l]\n  viability: v\n  terrain: t\n  surface: [s]\n  mitre_attack: [T1059]\n"
            ))
            .unwrap(),
        )
        .unwrap();
        (
            uuid.to_owned(),
            name.to_owned(),
            Model::Threat(Box::new(threat)),
        )
    }

    #[test]
    fn records_sort_by_name_and_get_unique_slugs() {
        let list = records(
            Scope::Threats,
            vec![
                record("bbbbbbbb-2", "Sentinel-KQL rule"),
                record("aaaaaaaa-1", "sentinel KQL Rule"),
                record("cccccccc-3", "Alpha"),
            ],
        );
        let slugs: Vec<(&str, &str)> = list
            .iter()
            .map(|r| (r.uuid.as_str(), r.slug.as_str()))
            .collect();
        assert_eq!(
            slugs,
            [
                ("cccccccc-3", "alpha"),
                ("aaaaaaaa-1", "sentinel-kql-rule"),
                ("bbbbbbbb-2", "sentinel-kql-rule-bbbbbbbb"),
            ]
        );
    }

    #[test]
    fn a_platform_block_error_is_placed_in_the_block() {
        let document = opentide_schema::node::load(
            "name: R\nmetadata:\n  uuid: u\n  schema: rule::1.1\n  version: 1\n  created: x\n  modified: x\n  tlp: clear\nconfigurations:\n  sentinel:\n    query: q\n",
        )
        .unwrap();
        let error = typed::<RuleV1_1>(&document).unwrap_err().detail;
        assert!(
            error.starts_with("an object does not validate: status: field required"),
            "{error}"
        );
        assert!(error.ends_with("; opentide validate shows each finding"));
        let document = opentide_schema::node::load(
            "name: R\nmetadata:\n  uuid: u\n  schema: rule::1.1\n  version: 1\n  created: x\n  modified: x\n  tlp: clear\n",
        )
        .unwrap();
        let error = typed::<RuleV1_1>(&document).unwrap_err().detail;
        assert_eq!(
            error,
            "\"R\" does not validate: description: field required; opentide validate shows each finding"
        );
    }

    /// A document that reads into its model but breaks one of the model's
    /// constraints fails the catalogue, as the oracle's pydantic model does.
    #[test]
    fn a_failed_constraint_fails_the_catalogue() {
        let rule = |version: &str| {
            opentide_schema::node::load(&format!(
                "name: Sysdig rule\nmetadata:\n  uuid: u\n  schema: rule::1.0\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: d\nstatus: STAGING\nseverity: Medium\ntechniques: [T1059.004]\ndetection_model: m\nresponse:\n  alert_severity: Medium\nconfigurations:\n  sysdig:\n    enabled: true\n    schema: platform::sysdig::1.0\n    status: STAGING\n    condition: spawned_process\n    minimum_engine_version: {version}\n"
            ))
            .unwrap()
        };
        assert!(typed::<RuleV1_0>(&rule("1")).is_ok());
        // The conversion places the constraint in the block.
        let error = typed::<RuleV1_0>(&rule("-1")).unwrap_err().detail;
        assert_eq!(
            error,
            "an object does not validate: minimum_engine_version: input should be greater than \
             or equal to 0; opentide validate shows each finding"
        );
    }

    /// garde's report of a model is worded as a structure error is: the
    /// first failed constraint, where, and how many more.
    #[test]
    fn a_constraint_report_names_the_first_failure() {
        use garde::Validate as _;
        let (_, _, model) = record("u-1", "Threat");
        let Model::Threat(mut threat) = model else {
            unreachable!("a threat record");
        };
        threat.threat.impact = vec!["a; b".to_owned()];
        threat.threat.leverage = Vec::new();
        let report = threat.validate_with(&Pins::default()).unwrap_err();
        let root = opentide_schema::node::load("name: Threat\n").unwrap();
        let line = describe_constraints(&report, root.root().map(AsRef::as_ref));
        assert!(
            line.starts_with(
                "\"Threat\" does not validate: threat.impact[0]: \"a; b\" packs several"
            ),
            "{line}"
        );
        assert!(
            line.ends_with(" (and 1 more); opentide validate shows each finding"),
            "{line}"
        );
    }

    /// A `chaining` entry (an insertion-ordered map since the models moved to
    /// `IndexMap`) names its threat by the first non-empty key of `vector`,
    /// `target`, `uuid` and `id`, in that order, whatever order its keys were
    /// written in.
    #[test]
    fn a_chaining_entry_names_its_threat_by_key_priority() {
        let entry = |pairs: &[(&str, &str)]| -> indexmap::IndexMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        assert_eq!(
            chain_target(&entry(&[
                ("id", "i"),
                ("uuid", "u"),
                ("target", "t"),
                ("vector", "v")
            ])),
            Some("v")
        );
        assert_eq!(
            chain_target(&entry(&[("id", "i"), ("uuid", "u"), ("target", "t")])),
            Some("t")
        );
        assert_eq!(
            chain_target(&entry(&[("id", "i"), ("uuid", "u")])),
            Some("u")
        );
        assert_eq!(
            chain_target(&entry(&[("vector", ""), ("relation", "r"), ("id", "i")])),
            Some("i")
        );
        assert_eq!(
            chain_target(&entry(&[("vector", ""), ("relation", "r")])),
            None
        );
    }
}
