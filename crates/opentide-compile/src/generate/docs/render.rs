//! Pages from the catalogue: what each section shows, worked out here from
//! the models, then written by the minijinja templates of `templates/`
//! (`documentation/objects/`, `parts/sections.py`, `publish/index.py`).
//!
//! The templates hold the layout: headings, lists, tables, folds, the order of
//! the sections. This module gives them their data: rows of text, links
//! already made for the flavour, diagrams as nodes and edges.

use minijinja::value::Value as JinjaValue;
use minijinja::{AutoEscape, Environment, Error, ErrorKind};
use serde::Serialize;
use serde_json::Value as JsonValue;

use super::Settings;
use super::catalog::{Catalog, Direction, Graph, Model, Record, RuleModel, Scope};
use super::cve;
use super::flavor::Flavor;
use super::mermaid::{Edge, Flowchart, Node as ChartNode, Shape};
use super::vocab::{Enriched, Vocab};
use crate::json::Json;

const TEMPLATES: [(&str, &str); 6] = [
    ("macros.md.j2", include_str!("templates/macros.md.j2")),
    ("rule.md.j2", include_str!("templates/rule.md.j2")),
    ("objective.md.j2", include_str!("templates/objective.md.j2")),
    ("threat.md.j2", include_str!("templates/threat.md.j2")),
    ("index.md.j2", include_str!("templates/index.md.j2")),
    ("mermaid.md.j2", include_str!("templates/mermaid.md.j2")),
];

/// The template environment: the templates, with the filters they use.
pub struct Templates {
    env: Environment<'static>,
}

impl Default for Templates {
    fn default() -> Self {
        Self::new()
    }
}

impl Templates {
    /// The bundled templates.
    ///
    /// # Panics
    ///
    /// Never: the bundled templates parse (`templates_parse` tests them).
    #[expect(
        clippy::expect_used,
        reason = "the bundled templates are tested to parse"
    )]
    pub fn new() -> Self {
        let mut env = Environment::new();
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.set_keep_trailing_newline(true);
        env.set_auto_escape_callback(|_| AutoEscape::None);
        env.add_filter("cell", |text: String| cell(&text));
        env.add_filter("table_cell", |text: String| table_cell(&text));
        env.add_filter("join_blocks", join_blocks);
        for (name, source) in TEMPLATES {
            env.add_template(name, source)
                .expect("the bundled templates parse");
        }
        Self { env }
    }

    /// Renders the template `name` with `context`.
    ///
    /// # Errors
    ///
    /// The template failed: a bug, reported as the phase's error.
    pub fn render(&self, name: &str, context: impl Serialize) -> Result<String, String> {
        self.env
            .get_template(name)
            .and_then(|template| template.render(context))
            .map_err(|error| format!("template {name}: {error:#}"))
    }
}

/// One table cell: a line break would end the row and a bare `|` the cell
/// (`_cell`).
pub fn cell(text: &str) -> String {
    let normalised = text.replace("\r\n", "\n");
    let mut lines: Vec<&str> = normalised.split(['\n', '\r']).collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let joined = lines.join(" ");
    let mut out = String::with_capacity(joined.len());
    let mut previous = '\0';
    for c in joined.chars() {
        if c == '|' && previous != '\\' {
            out.push('\\');
        }
        out.push(c);
        previous = c;
    }
    out
}

/// A free-text value as a cell: one line, pipes escaped, `-` when empty
/// (`_table_cell`).
pub fn table_cell(text: &str) -> String {
    let out = text.replace('\n', " ").replace('|', "\\|");
    let out = out.trim();
    if out.is_empty() {
        "-".to_owned()
    } else {
        out.to_owned()
    }
}

/// The non-blank blocks, each trimmed, a blank line between them
/// (`join_blocks`).
fn join_blocks(blocks: Vec<JinjaValue>) -> Result<String, Error> {
    let mut out: Vec<String> = Vec::new();
    for block in blocks {
        if block.is_none() || block.is_undefined() {
            continue;
        }
        let text = block
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::new(ErrorKind::InvalidOperation, "a block is not text"))?;
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_owned());
        }
    }
    Ok(out.join("\n\n"))
}

/// What renders pages: the catalogue, the settings, the vocabularies.
pub struct Pages<'a, 'i> {
    /// The objects.
    pub catalog: &'a Catalog<'i>,
    /// The run's settings.
    pub settings: &'a Settings,
    /// The vocabularies.
    pub vocab: Vocab<'a>,
    /// The templates.
    pub templates: &'a Templates,
}

#[derive(Serialize)]
struct Title {
    frontmatter: bool,
    text: String,
}

#[derive(Serialize)]
struct References {
    public: Vec<(String, String)>,
    internal: Vec<(String, String)>,
    reports: Vec<String>,
}

#[derive(Serialize)]
struct Coverage {
    heading: &'static str,
    diagram: String,
    related: Vec<[String; 4]>,
}

#[derive(Serialize)]
struct Search {
    purpose: String,
    system: String,
    query: String,
}

#[derive(Serialize)]
struct Procedure {
    analysis: String,
    containment: Option<String>,
    searches: Vec<Search>,
}

#[derive(Serialize)]
struct Response {
    alert_severity: String,
    playbook: Option<String>,
    responders: Option<String>,
    procedure: Option<Procedure>,
}

#[derive(Serialize)]
struct Platform {
    name: &'static str,
    enabled: String,
    status: Option<String>,
    alert_title: Option<String>,
    entity_mappings: Vec<String>,
    query: Option<String>,
    language: &'static str,
}

#[derive(Serialize)]
struct RulePage {
    flavor: &'static str,
    title: Title,
    metadata: Vec<(String, String)>,
    references: Option<References>,
    description: String,
    status: Vec<(String, String)>,
    techniques: Vec<[String; 3]>,
    detection_model: Option<String>,
    response: Option<Response>,
    platforms: Vec<Platform>,
    coverage: Option<Coverage>,
}

#[derive(Serialize)]
struct Detector {
    name: String,
    technology: String,
    description: String,
    link: Option<String>,
}

#[derive(Serialize)]
struct Example {
    description: String,
    link: String,
    language: String,
    query: Option<String>,
}

#[derive(Serialize)]
struct Signal {
    name: String,
    description: String,
    severity: String,
    methodology: String,
    effort: Option<i64>,
    availability: String,
    requirements: String,
    logsources: Vec<String>,
    entities: Vec<String>,
    detectors: Vec<Detector>,
    examples: Vec<Example>,
}

#[derive(Serialize)]
struct ObjectivePage {
    flavor: &'static str,
    title: Title,
    metadata: Vec<(String, String)>,
    references: Option<References>,
    description: String,
    priority: String,
    objective_type: String,
    investment: Option<String>,
    composition: String,
    rationale: String,
    signals: Vec<Signal>,
    signal_coverage: Vec<(String, String)>,
    coverage: Option<Coverage>,
}

#[derive(Serialize)]
struct Surface {
    label: String,
    description: String,
}

#[derive(Serialize)]
struct Cve {
    links: Vec<String>,
    /// With `[cve] retrieve_details` on: a row per identifier.
    rows: Option<Vec<[String; 4]>>,
    /// The identifiers the instance does not know.
    missing: Vec<String>,
    /// Whether the instance could not be asked for one.
    unreachable: bool,
}

#[derive(Serialize)]
struct ChainDetail {
    heading: String,
    description: String,
    target: String,
}

#[derive(Serialize)]
struct ThreatPage {
    flavor: &'static str,
    title: Title,
    metadata: Vec<(String, String)>,
    references: Option<References>,
    description: String,
    criticality: String,
    terrain: String,
    surface: Vec<Surface>,
    assessment: Vec<[String; 3]>,
    actors: Vec<[String; 4]>,
    cve: Option<Cve>,
    techniques: Vec<[String; 3]>,
    chaining_diagram: String,
    chaining_listed: bool,
    chaining: Vec<ChainDetail>,
    coverage: Option<Coverage>,
}

#[derive(Serialize)]
struct IndexPage {
    title: String,
    toc: &'static str,
    table: String,
}

/// The metadata fields every object has.
struct Meta<'m> {
    uuid: &'m str,
    schema: &'m str,
    version: String,
    created: &'m str,
    modified: &'m str,
    tlp: &'m str,
    author: Option<&'m str>,
    contributors: Option<&'m [String]>,
    organisation: Option<(&'m str, &'m str)>,
}

macro_rules! meta {
    ($metadata:expr) => {{
        let metadata = $metadata;
        Meta {
            uuid: &metadata.uuid,
            schema: &metadata.schema_id,
            version: match &metadata.version {
                opentide_schema::objects::Version::Str(text) => text.clone(),
                opentide_schema::objects::Version::Int(number) => number.to_string(),
            },
            created: &metadata.created,
            modified: &metadata.modified,
            tlp: &metadata.tlp,
            author: metadata.author.as_deref(),
            contributors: metadata.contributors.as_deref(),
            organisation: metadata
                .organisation
                .as_ref()
                .map(|org| (org.name.as_str(), org.uuid.as_str())),
        }
    }};
}

/// What a rule page reads, whatever the rule's revision.
struct RuleView<'r> {
    name: &'r str,
    meta: Meta<'r>,
    references: Option<&'r opentide_schema::objects::ObjectReferences>,
    description: &'r str,
    statuses: Vec<(&'static str, &'r str)>,
    severity: Option<&'r str>,
    techniques: &'r [String],
    detection_model: Option<&'r str>,
    response: Option<&'r opentide_schema::objects::RuleResponse>,
    configurations: Option<&'r opentide_schema::objects::RuleConfigurations>,
}

macro_rules! rule_view {
    ($rule:expr) => {{
        let rule = $rule;
        RuleView {
            name: &rule.name,
            meta: meta!(&rule.metadata),
            references: rule.references.as_ref(),
            description: &rule.description,
            statuses: rule
                .configurations
                .as_ref()
                .map(|configurations| configurations.platform_statuses())
                .unwrap_or_default(),
            severity: rule.displayed_severity(),
            techniques: &rule.techniques,
            detection_model: rule.detection_model.as_deref(),
            response: rule.response.as_ref(),
            configurations: rule.configurations.as_ref(),
        }
    }};
}

impl Pages<'_, '_> {
    fn flavor(&self) -> Flavor {
        self.settings.flavor
    }

    fn wiki(&self) -> bool {
        self.flavor().wiki_links()
    }

    fn title(&self, text: &str) -> Title {
        Title {
            frontmatter: self.settings.uuid_permalinks && self.wiki(),
            text: text.to_owned(),
        }
    }

    /// The file name of `record`'s page.
    pub fn filename(&self, record: &Record) -> String {
        self.flavor().page_filename(
            &record.slug,
            self.settings
                .uuid_permalinks
                .then_some(record.uuid.as_str()),
        )
    }

    /// A relative link from a page in `from` to a page in `to`.
    fn href(from: &str, to: &str, filename: &str, anchor: Option<&str>) -> String {
        let mut href = if from == to {
            filename.to_owned()
        } else if from.is_empty() || from == "." {
            format!("{to}/{filename}")
        } else {
            format!("../{to}/{filename}")
        };
        if let Some(anchor) = anchor.filter(|anchor| !anchor.is_empty()) {
            href.push('#');
            href.push_str(anchor);
        }
        href
    }

    /// A link to `uuid`'s page, or to its signal's heading, with the UUID
    /// after it (`object_link`).
    fn object_link(&self, uuid: &str, from: &str) -> String {
        if let Some(signal) = self.catalog.signal(uuid) {
            let Some(parent) = self.catalog.record(&signal.owner) else {
                return format!("{} (`{uuid}`)", signal.name);
            };
            let anchor = self.flavor().heading_anchor(&signal.name);
            let href = Self::href(from, "objectives", &self.filename(parent), Some(&anchor));
            let link = self.flavor().render_link(&signal.name, &href, self.wiki());
            return format!("{link} (`{uuid}`)");
        }
        let Some(record) = self.catalog.record(uuid) else {
            let name = self.catalog.name(uuid);
            if name != uuid {
                return format!("{name} (`{uuid}`)");
            }
            return format!("`{uuid}`");
        };
        let href = Self::href(from, record.scope.folder(), &self.filename(record), None);
        let link = self.flavor().render_link(&record.name, &href, self.wiki());
        format!("{link} (`{uuid}`)")
    }

    fn metadata(&self, meta: &Meta<'_>) -> Vec<(String, String)> {
        let tlp = self.vocab.enrich("tlp", meta.tlp);
        let mut tlp_value = tlp.label.clone();
        if !tlp.id.is_empty() && tlp.id != tlp_value {
            tlp_value = format!("{tlp_value} (`{}`)", tlp.id);
        }
        let mut rows = vec![
            ("UUID".to_owned(), format!("`{}`", meta.uuid)),
            ("Schema".to_owned(), format!("`{}`", meta.schema)),
            ("Version".to_owned(), format!("`{}`", meta.version)),
            ("Created".to_owned(), format!("`{}`", meta.created)),
            ("Modified".to_owned(), format!("`{}`", meta.modified)),
            ("TLP".to_owned(), tlp_value),
        ];
        if let Some(author) = meta.author.filter(|author| !author.is_empty()) {
            rows.push(("Author".to_owned(), author.to_owned()));
        }
        if let Some(contributors) = meta.contributors.filter(|list| !list.is_empty()) {
            rows.push(("Contributors".to_owned(), contributors.join(", ")));
        }
        if let Some((name, uuid)) = meta.organisation {
            rows.push(("Organisation".to_owned(), format!("{name} (`{uuid}`)")));
        }
        rows
    }

    fn references(
        references: Option<&opentide_schema::objects::ObjectReferences>,
    ) -> Option<References> {
        let references = references?;
        let value = |text: &str| {
            if text.starts_with("http://") || text.starts_with("https://") {
                Flavor::link(text, text)
            } else {
                text.to_owned()
            }
        };
        let public: Vec<(String, String)> = references
            .public
            .iter()
            .flatten()
            .map(|(key, text)| (key.to_string(), value(text)))
            .collect();
        let mut internal: Vec<(String, String)> = references
            .internal
            .iter()
            .flatten()
            .map(|(key, text)| (key.clone(), value(text)))
            .collect();
        internal.sort();
        let reports: Vec<String> = references
            .reports
            .iter()
            .flatten()
            .map(|text| value(text))
            .collect();
        if public.is_empty() && internal.is_empty() && reports.is_empty() {
            return None;
        }
        Some(References {
            public,
            internal,
            reports,
        })
    }

    /// An entry's label, linked when it has a web link (`_entry_link`).
    fn entry_link(entry: &Enriched, fallback: &str) -> String {
        let label = table_cell(if entry.label.is_empty() {
            fallback
        } else {
            &entry.label
        });
        if entry.link.starts_with("http://") || entry.link.starts_with("https://") {
            Flavor::link(&label, &entry.link)
        } else {
            label
        }
    }

    fn techniques(&self, techniques: &[String]) -> Vec<[String; 3]> {
        techniques
            .iter()
            .map(|technique| {
                let entry = self.vocab.enrich("att&ck", technique);
                [
                    format!("`{technique}`"),
                    Self::entry_link(&entry, technique),
                    table_cell(&entry.description),
                ]
            })
            .collect()
    }

    fn vocab_label(&self, field: &str, key: &str) -> String {
        let entry = self.vocab.enrich(field, key);
        if entry.label == key {
            key.to_owned()
        } else {
            format!("{} (`{key}`)", entry.label)
        }
    }

    /// The Coverage diagram, else the Relations diagram, and the table of
    /// related objects (`coverage_block`).
    fn coverage(&self, uuid: &str, name: &str, from: &str) -> Result<Option<Coverage>, String> {
        let graph = self.catalog.coverage_graph(uuid);
        let direction = self.settings.direction;
        let related = self.catalog.related(uuid, direction);
        let mut heading = "";
        let mut diagram = String::new();
        if !graph.is_empty() {
            heading = "Coverage";
            diagram = self.typed_graph(&graph, uuid, "TB", true)?;
        } else if !related.is_empty() {
            heading = "Relations";
            let mut nodes = vec![ChartNode::new(uuid, name, Shape::Rect)];
            let mut edges = Vec::new();
            let mut groups: Vec<(String, Vec<String>)> = Vec::new();
            for entry in &related {
                nodes.push(ChartNode::new(
                    &entry.uuid,
                    &entry.name,
                    Shape::of(Some(&entry.object_type)),
                ));
                if entry.direction == Direction::Upstream {
                    edges.push(Edge::new(
                        &entry.uuid,
                        uuid,
                        Some(&entry.object_type),
                        false,
                    ));
                } else {
                    edges.push(Edge::new(
                        uuid,
                        &entry.uuid,
                        Some(&entry.object_type),
                        false,
                    ));
                }
                let title = title_case(&entry.object_type);
                match groups.iter_mut().find(|(existing, _)| *existing == title) {
                    Some((_, members)) => members.push(entry.uuid.clone()),
                    None => groups.push((title, vec![entry.uuid.clone()])),
                }
            }
            let chart = Flowchart::new(
                self.flavor().diagram_type(),
                "TB",
                nodes,
                edges,
                self.flavor().subgraphs().then_some(groups),
            );
            diagram = self.fence(&chart)?;
        }
        let rows: Vec<[String; 4]> = related
            .iter()
            .map(|entry| {
                [
                    title_case(&entry.object_type),
                    self.object_link(&entry.uuid, from),
                    title_case(entry.direction.name()),
                    entry.object_type.clone(),
                ]
            })
            .collect();
        if diagram.is_empty() && rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(Coverage {
            heading,
            diagram,
            related: rows,
        }))
    }

    /// A coverage or chaining graph as a flowchart, its nodes grouped by
    /// type (`by_type`, the page's own object left out) or by kill chain.
    fn typed_graph(
        &self,
        graph: &Graph,
        current: &str,
        direction: &'static str,
        by_type: bool,
    ) -> Result<String, String> {
        let nodes = graph
            .nodes
            .iter()
            .map(|node| ChartNode::new(&node.uuid, &node.name, Shape::of(Some(node.object_type))))
            .collect();
        let edges = graph
            .edges
            .iter()
            .map(|edge| {
                Edge::new(
                    &edge.source,
                    &edge.target,
                    edge.label.as_deref(),
                    edge.both_ways,
                )
            })
            .collect();
        let groups = self.flavor().subgraphs().then(|| {
            let mut groups: Vec<(String, Vec<String>)> = Vec::new();
            for node in &graph.nodes {
                if by_type && node.uuid == current {
                    continue;
                }
                let title = if by_type {
                    match node.object_type {
                        "threat" => "Threats".to_owned(),
                        "objective" => "Objectives".to_owned(),
                        "rule" => "Rules".to_owned(),
                        "signal" => "Signals".to_owned(),
                        other => title_case(other),
                    }
                } else {
                    node.killchain.clone().unwrap_or_default()
                };
                if title.is_empty() {
                    continue;
                }
                match groups.iter_mut().find(|(existing, _)| *existing == title) {
                    Some((_, members)) => members.push(node.uuid.clone()),
                    None => groups.push((title, vec![node.uuid.clone()])),
                }
            }
            groups
        });
        let groups = groups.filter(|groups| !groups.is_empty());
        let kind = self.flavor().diagram_type();
        self.fence(&Flowchart::new(kind, direction, nodes, edges, groups))
    }

    /// The flowchart in the flavour's Mermaid fence.
    fn fence(&self, chart: &Flowchart) -> Result<String, String> {
        let body = self.templates.render("mermaid.md.j2", chart)?;
        let body = self.flavor().diagram(body.trim_end_matches('\n'));
        Ok(if self.flavor() == Flavor::AzureDevops {
            format!("::: mermaid\n{body}\n:::\n")
        } else {
            format!("```mermaid\n{body}\n```\n")
        })
    }

    /// The page of a rule.
    ///
    /// # Errors
    ///
    /// A template failed.
    pub fn rule(&self, record: &Record) -> Result<String, String> {
        let Model::Rule(model) = &record.model else {
            return Err("not a rule".to_owned());
        };
        let rule = match model {
            RuleModel::V1_0(rule) => rule_view!(rule.as_ref()),
            RuleModel::V1_1(rule) => rule_view!(rule.as_ref()),
        };
        let mut status: Vec<(String, String)> = rule
            .statuses
            .iter()
            .map(|(platform, status)| (format!("Status ({platform})"), format!("`{status}`")))
            .collect();
        if let Some(severity) = rule.severity.filter(|severity| !severity.is_empty()) {
            status.push(("Severity".to_owned(), format!("`{severity}`")));
        }
        let response = rule.response.map(|response| Response {
            alert_severity: self.vocab_label("alert_severity", &response.alert_severity),
            playbook: response.playbook.clone().filter(|text| !text.is_empty()),
            responders: response.responders.clone().filter(|text| !text.is_empty()),
            procedure: response.procedure.as_ref().map(|procedure| Procedure {
                analysis: procedure.analysis.clone(),
                containment: procedure
                    .containment
                    .clone()
                    .filter(|text| !text.is_empty()),
                searches: procedure
                    .searches
                    .iter()
                    .flatten()
                    .map(|search| Search {
                        purpose: search.purpose.clone(),
                        system: search.system.clone(),
                        query: search.query.clone(),
                    })
                    .collect(),
            }),
        });
        let page = RulePage {
            flavor: self.flavor().name(),
            title: self.title(rule.name),
            metadata: self.metadata(&rule.meta),
            references: Self::references(rule.references),
            description: rule.description.to_owned(),
            status,
            techniques: self.techniques(rule.techniques),
            detection_model: rule
                .detection_model
                .filter(|model| !model.is_empty())
                .map(|model| self.object_link(model, "rules")),
            response,
            platforms: rule.configurations.map(platforms).unwrap_or_default(),
            coverage: self.coverage(&record.uuid, &record.name, "rules")?,
        };
        self.templates.render("rule.md.j2", page)
    }

    /// The page of an objective.
    ///
    /// # Errors
    ///
    /// A template failed.
    pub fn objective(&self, record: &Record) -> Result<String, String> {
        let Model::Objective(objective) = &record.model else {
            return Err("not an objective".to_owned());
        };
        let body = &objective.objective;
        let signals = body
            .signals
            .iter()
            .map(|signal| Signal {
                name: signal.name.clone(),
                description: signal.description.clone(),
                severity: self.vocab.enrich("alert_severity", &signal.severity).label,
                methodology: self
                    .vocab
                    .enrich("detection.methodology", &signal.methodology)
                    .label,
                effort: signal.effort,
                availability: signal.data.availability.clone(),
                requirements: signal.data.requirements.clone(),
                logsources: signal.data.logsources.clone().unwrap_or_default(),
                entities: signal
                    .entities
                    .iter()
                    .map(|entity| self.vocab.enrich("signal.entities", entity).label)
                    .collect(),
                detectors: signal
                    .detectors
                    .iter()
                    .flatten()
                    .map(|detector| Detector {
                        name: detector.name.clone(),
                        technology: detector.technology.clone(),
                        description: detector.description.clone(),
                        link: detector.link.clone().filter(|link| !link.is_empty()),
                    })
                    .collect(),
                examples: signal
                    .examples
                    .iter()
                    .flatten()
                    .map(|example| Example {
                        description: example.description.clone(),
                        link: example.link.clone(),
                        language: example
                            .language
                            .clone()
                            .filter(|language| !language.is_empty())
                            .unwrap_or_else(|| "text".to_owned()),
                        query: example.query.clone().filter(|query| !query.is_empty()),
                    })
                    .collect(),
            })
            .collect();
        let signal_coverage = body
            .signals
            .iter()
            .map(|signal| {
                let rules = self.catalog.rules_for_signal(&signal.uuid);
                if rules.is_empty() {
                    return (signal.name.clone(), "_None_".to_owned());
                }
                let shown: Vec<String> = rules
                    .iter()
                    .map(|rule| {
                        if self.catalog.record(rule).is_some() {
                            self.object_link(rule, "objectives")
                        } else {
                            format!("`{rule}`")
                        }
                    })
                    .collect();
                (signal.name.clone(), shown.join("<br>"))
            })
            .collect();
        let page = ObjectivePage {
            flavor: self.flavor().name(),
            title: self.title(&objective.name),
            metadata: self.metadata(&meta!(&objective.metadata)),
            references: Self::references(objective.references.as_ref()),
            description: body.description.clone(),
            priority: body.priority.clone(),
            objective_type: self.vocab.enrich("detection.types", &body.r#type).label,
            investment: body.investment.clone().filter(|text| !text.is_empty()),
            composition: self
                .vocab
                .enrich("detection.composition", &body.composition.strategy)
                .label,
            rationale: body.composition.description.clone(),
            signals,
            signal_coverage,
            coverage: self.coverage(&record.uuid, &record.name, "objectives")?,
        };
        self.templates.render("objective.md.j2", page)
    }

    /// The page of a threat.
    ///
    /// # Errors
    ///
    /// A template failed.
    pub fn threat(&self, record: &Record) -> Result<String, String> {
        let Model::Threat(threat) = &record.model else {
            return Err("not a threat".to_owned());
        };
        let body = &threat.threat;
        let criticality = self.vocab.enrich("criticality", &threat.criticality);
        let mut criticality_text = format!("**{}**", criticality.label);
        if !criticality.description.is_empty() {
            criticality_text = format!("{criticality_text} - {}", criticality.description);
        }
        let surface = body
            .surface
            .iter()
            .map(|value| match self.vocab.stage("surface", value) {
                Some((label, description)) => Surface { label, description },
                None => {
                    let entry = self.vocab.enrich("surface", value);
                    Surface {
                        label: entry.label,
                        description: entry.description,
                    }
                }
            })
            .collect();
        let assessment_row = |title: &str, field: &str, values: &[String]| -> [String; 3] {
            let entries: Vec<Enriched> = values
                .iter()
                .map(|value| self.vocab.enrich(field, value))
                .collect();
            [
                title.to_owned(),
                entries
                    .iter()
                    .map(|entry| Self::entry_link(entry, &entry.key))
                    .collect::<Vec<_>>()
                    .join("<br>"),
                entries
                    .iter()
                    .map(|entry| {
                        table_cell(if entry.description.is_empty() {
                            "-"
                        } else {
                            &entry.description
                        })
                    })
                    .collect::<Vec<_>>()
                    .join("<br>"),
            ]
        };
        let mut assessment = vec![
            assessment_row("Severity", "severity", std::slice::from_ref(&body.severity)),
            assessment_row("Impact", "impact", &body.impact),
            assessment_row("Leverage", "leverage", &body.leverage),
            assessment_row(
                "Viability",
                "viability",
                std::slice::from_ref(&body.viability),
            ),
        ];
        let killchain: Vec<String> = match &body.killchain {
            Some(opentide_schema::objects::Killchain::One(stage)) => vec![stage.clone()],
            Some(opentide_schema::objects::Killchain::Many(stages)) => stages.clone(),
            None => Vec::new(),
        };
        if !killchain.is_empty() {
            assessment.push(assessment_row("Kill Chain", "killchain", &killchain));
        }
        let actors = body
            .actors
            .iter()
            .flatten()
            .map(|actor| {
                let entry = self.vocab.enrich("actors", &actor.name);
                let source = entry.stages.join(", ");
                let description = actor
                    .sighting
                    .clone()
                    .filter(|text| !text.is_empty())
                    .unwrap_or_else(|| entry.description.clone());
                [
                    Self::entry_link(&entry, &entry.label),
                    format!("`{}`", actor.name),
                    table_cell(&source),
                    table_cell(&description),
                ]
            })
            .collect();
        let ids = cve::identifiers(body.cve.as_deref().unwrap_or_default());
        let cve = (!ids.is_empty()).then(|| self.cve_section(&ids));
        let network = self.catalog.chaining_network(&record.uuid, &self.vocab);
        let chaining_diagram = if network.is_empty() {
            let chain = self.catalog.chaining_entries(&record.uuid, &self.vocab);
            if chain.is_empty() {
                String::new()
            } else {
                let mut nodes = vec![ChartNode::new(&record.uuid, &threat.name, Shape::Hex)];
                let mut edges = Vec::new();
                let mut previous = record.uuid.clone();
                for entry in &chain {
                    nodes.push(ChartNode::new(&entry.uuid, &entry.name, Shape::Hex));
                    edges.push(Edge::new(
                        &previous,
                        &entry.uuid,
                        entry.relation.as_deref(),
                        false,
                    ));
                    previous.clone_from(&entry.uuid);
                }
                self.fence(&Flowchart::new(
                    self.flavor().diagram_type(),
                    "LR",
                    nodes,
                    edges,
                    None,
                ))?
            }
        } else {
            self.typed_graph(&network, &record.uuid, "LR", false)?
        };
        let chaining = body
            .chaining
            .iter()
            .flatten()
            .filter_map(|entry| {
                let target = super::catalog::chain_target(entry)?;
                let key = entry
                    .get("relation")
                    .map(|text| text.trim().to_owned())
                    .unwrap_or_default();
                let relation =
                    (!key.is_empty()).then(|| self.vocab.enrich("chaining_relations", &key));
                let label = relation
                    .as_ref()
                    .map_or_else(|| "Related".to_owned(), |relation| relation.label.clone());
                let mut heading = format!("{label} -> {}", self.object_link(target, "threats"));
                if !key.is_empty() && key != label {
                    heading = format!("{heading} (`{key}`)");
                }
                let mut description = entry
                    .get("description")
                    .map(|text| text.trim().to_owned())
                    .unwrap_or_default();
                if description.is_empty()
                    && let Some(relation) = &relation
                {
                    description.clone_from(&relation.description);
                }
                Some(ChainDetail {
                    heading,
                    description,
                    target: target.to_owned(),
                })
            })
            .collect();
        let page = ThreatPage {
            flavor: self.flavor().name(),
            title: self.title(&threat.name),
            metadata: self.metadata(&meta!(&threat.metadata)),
            references: Self::references(threat.references.as_ref()),
            description: body.description.clone(),
            criticality: criticality_text,
            terrain: body.terrain.clone(),
            surface,
            assessment,
            actors,
            cve,
            techniques: self.techniques(&body.mitre_attack),
            chaining_diagram,
            chaining_listed: body.chaining.as_ref().is_some_and(|list| !list.is_empty()),
            chaining,
            coverage: self.coverage(&record.uuid, &record.name, "threats")?,
        };
        self.templates.render("threat.md.j2", page)
    }

    /// A threat's CVE section (`render_cve`): links, or with `[cve]
    /// retrieve_details` on a row of each record's details.
    fn cve_section(&self, ids: &[String]) -> Cve {
        let links = &self.settings.cve;
        let link = |id: &str| Flavor::link(id, &links.page_url(id));
        let mut section = Cve {
            links: ids.iter().map(|id| link(id)).collect(),
            rows: None,
            missing: Vec::new(),
            unreachable: false,
        };
        if !self.settings.cve_details {
            return section;
        }
        let mut rows = Vec::new();
        for id in ids {
            match self.settings.cve_source.get(id) {
                cve::CveDetail::Unavailable => {
                    section.unreachable = true;
                    rows.push([
                        link(id),
                        "-".to_owned(),
                        "-".to_owned(),
                        "Details unavailable from Vulnerability-Lookup.".to_owned(),
                    ]);
                }
                cve::CveDetail::NotFound => {
                    section.missing.push(id.clone());
                    rows.push([
                        link(id),
                        "-".to_owned(),
                        "-".to_owned(),
                        "Not found in Vulnerability-Lookup.".to_owned(),
                    ]);
                }
                cve::CveDetail::Found(record) => {
                    let ident = if record.identifier.is_empty() {
                        id.as_str()
                    } else {
                        record.identifier.as_str()
                    };
                    let url = if record.page_url.is_empty() {
                        links.page_url(ident)
                    } else {
                        record.page_url.clone()
                    };
                    let mut label = Flavor::link(ident, &url);
                    let aliases: Vec<String> = record
                        .aliases
                        .iter()
                        .filter(|alias| alias.as_str() != ident)
                        .map(|alias| link(alias))
                        .collect();
                    if !aliases.is_empty() {
                        label = format!("{label}<br>{}", aliases.join(", "));
                    }
                    let summary = record
                        .title
                        .as_deref()
                        .filter(|text| !text.is_empty())
                        .or(record
                            .description
                            .as_deref()
                            .filter(|text| !text.is_empty()))
                        .unwrap_or("-");
                    rows.push([
                        label,
                        record.published.clone().unwrap_or_else(|| "-".to_owned()),
                        record
                            .severity
                            .clone()
                            .or_else(|| record.state.clone())
                            .unwrap_or_else(|| "-".to_owned()),
                        table_cell(&cve::truncate(summary, 280)),
                    ]);
                }
            }
        }
        section.rows = Some(rows);
        section
    }

    /// A table as an index page writes it: Markdown, or on GitLab a sortable,
    /// filterable `json:table` (`index_table`).
    fn index_table(&self, headers: &[&str], rows: &[Vec<String>]) -> Result<String, String> {
        if self.flavor() != Flavor::Gitlab {
            #[derive(Serialize)]
            struct Table<'t> {
                headers: &'t [&'t str],
                rows: &'t [Vec<String>],
            }
            return self.templates.render(
                "index.md.j2",
                minijinja::context! { table_only => Table { headers, rows } },
            );
        }
        let keys: Vec<String> = (0..headers.len())
            .map(|position| {
                char::from_u32(u32::from(b'a') + u32::try_from(position).unwrap_or(0))
                    .unwrap_or('a')
                    .to_string()
            })
            .collect();
        let fields = headers
            .iter()
            .zip(&keys)
            .map(|(header, key)| {
                Json::Object(
                    [
                        ("key".to_owned(), Json::Str(key.clone())),
                        ("label".to_owned(), Json::Str((*header).to_owned())),
                        ("sortable".to_owned(), Json::Str("true".to_owned())),
                    ]
                    .into_iter()
                    .collect(),
                )
            })
            .collect();
        let items = rows
            .iter()
            .map(|row| {
                Json::Object(
                    keys.iter()
                        .zip(row)
                        .map(|(key, value)| (key.clone(), Json::Str(value.clone())))
                        .collect(),
                )
            })
            .collect();
        let payload = Json::Object(
            [
                ("fields".to_owned(), Json::Array(fields)),
                ("items".to_owned(), Json::Array(items)),
                ("filter".to_owned(), Json::Str("true".to_owned())),
                ("markdown".to_owned(), Json::Str("true".to_owned())),
                ("sortable".to_owned(), Json::Str("true".to_owned())),
            ]
            .into_iter()
            .collect(),
        );
        Ok(format!("```json:table\n{}\n```\n", payload.to_compact()))
    }

    /// The index page of a folder (`render_index`).
    ///
    /// # Errors
    ///
    /// A relation walk or a template failed: `(uuid, cause)`.
    pub fn folder_index(&self, scope: Scope, title: &str) -> Result<String, (String, String)> {
        let records = self.catalog.records(scope);
        let from = scope.folder();
        let mut rows = Vec::new();
        for record in records {
            let filename = self.filename(record);
            let href = Self::href(from, scope.folder(), &filename, None);
            let mut name = record.name.clone();
            if self.settings.icons {
                format!("{} {}", icon(scope), record.name)
                    .trim()
                    .clone_into(&mut name);
            }
            let link = self.flavor().render_link(&name, &href, self.wiki());
            let mut row = vec![link, record.uuid.clone()];
            match &record.model {
                Model::Rule(rule) => {
                    let (statuses, severity) = match rule {
                        RuleModel::V1_0(rule) => rule_status_cells(
                            rule.configurations.as_ref(),
                            rule.displayed_severity(),
                        ),
                        RuleModel::V1_1(rule) => rule_status_cells(
                            rule.configurations.as_ref(),
                            rule.displayed_severity(),
                        ),
                    };
                    row.push(statuses);
                    row.push(severity);
                }
                Model::Objective(objective) => row.push(objective.objective.priority.clone()),
                Model::Threat(threat) => row.push(threat.criticality.clone()),
            }
            if self.settings.relation_counts {
                let count = self
                    .catalog
                    .relation_count(&record.uuid, self.settings.direction)
                    .map_err(|cause| (record.uuid.clone(), cause.to_string()))?;
                row.push(count.to_string());
            }
            rows.push(row);
        }
        let mut headers = vec!["Name", "UUID"];
        headers.extend_from_slice(match scope {
            Scope::Rules => &["Status", "Severity"],
            Scope::Objectives => &["Priority"],
            Scope::Threats => &["Criticality"],
        });
        if self.settings.relation_counts {
            headers.push("Related");
        }
        let table = self
            .index_table(&headers, &rows)
            .map_err(|error| (String::new(), error))?;
        self.index_page(title, &table)
            .map_err(|error| (String::new(), error))
    }

    fn index_page(&self, title: &str, table: &str) -> Result<String, String> {
        self.templates.render(
            "index.md.j2",
            IndexPage {
                title: title.to_owned(),
                toc: if self.flavor() == Flavor::AzureDevops {
                    "[[_TOC_]]"
                } else {
                    ""
                },
                table: table.to_owned(),
            },
        )
    }

    /// The root README: a row per folder.
    ///
    /// # Errors
    ///
    /// A template failed.
    pub fn root_index(&self) -> Result<String, String> {
        let mut rows = Vec::new();
        for (scope, title) in SECTIONS {
            let mut section = title.to_owned();
            if self.settings.icons {
                section = format!("{} {title}", icon(scope));
            }
            let mut row = vec![
                Flavor::link(&section, &format!("{}/README.md", scope.folder())),
                scope.folder().to_owned(),
            ];
            if self.settings.relation_counts {
                row.push(self.catalog.records(scope).len().to_string());
            }
            rows.push(row);
        }
        let mut headers = vec!["Section", "Folder"];
        if self.settings.relation_counts {
            headers.push("Objects");
        }
        let table = self.index_table(&headers, &rows)?;
        let page = self.templates.render(
            "index.md.j2",
            IndexPage {
                title: "opentide Documentation".to_owned(),
                toc: "",
                table,
            },
        )?;
        Ok(page)
    }

    /// GitLab's `.order` of a folder: README, then each page.
    pub fn order(&self, scope: Scope) -> String {
        let mut entries = vec!["README".to_owned()];
        for record in self.catalog.records(scope) {
            let filename = self.filename(record);
            entries.push(filename.strip_suffix(".md").unwrap_or(&filename).to_owned());
        }
        entries.join("\n") + "\n"
    }
}

/// The folders, in the order the root README lists them.
pub const SECTIONS: [(Scope, &str); 3] = [
    (Scope::Rules, "Detection Rules"),
    (Scope::Objectives, "Detection Objectives"),
    (Scope::Threats, "Threat Vectors"),
];

fn icon(scope: Scope) -> &'static str {
    match scope {
        Scope::Rules => ":shield:",
        Scope::Objectives => ":dart:",
        Scope::Threats => ":warning:",
    }
}

/// A rule's index cells: its statuses, sorted and each once, and the severity
/// it shows.
fn rule_status_cells(
    configurations: Option<&opentide_schema::objects::RuleConfigurations>,
    severity: Option<&str>,
) -> (String, String) {
    let mut statuses: Vec<&str> = configurations
        .map(opentide_schema::objects::RuleConfigurations::platform_statuses)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, status)| status)
        .collect();
    statuses.sort_unstable();
    statuses.dedup();
    (statuses.join(", "), severity.unwrap_or_default().to_owned())
}

/// `str.title()` for the type and direction words the tables show.
fn title_case(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut start = true;
    for c in text.chars() {
        if c.is_alphabetic() {
            if start {
                out.extend(c.to_uppercase());
            } else {
                out.extend(c.to_lowercase());
            }
            start = false;
        } else {
            out.push(c);
            start = true;
        }
    }
    out
}

/// Each platform block a rule configures, in the container's order
/// (`render_rule_queries`).
fn platforms(configurations: &opentide_schema::objects::RuleConfigurations) -> Vec<Platform> {
    let Ok(JsonValue::Object(blocks)) = serde_json::to_value(configurations) else {
        return Vec::new();
    };
    let text = |value: Option<&JsonValue>| -> Option<String> {
        match value? {
            JsonValue::String(text) if !text.is_empty() => Some(text.clone()),
            JsonValue::Null | JsonValue::String(_) => None,
            other => Some(other.to_string()),
        }
    };
    let mut out = Vec::new();
    for name in opentide_schema::objects::RuleConfigurations::PLATFORMS {
        let Some(block) = blocks.get(name).filter(|block| !block.is_null()) else {
            continue;
        };
        let enabled = match block.get("enabled") {
            Some(JsonValue::Bool(true)) => "True".to_owned(),
            Some(JsonValue::Bool(false)) => "False".to_owned(),
            Some(JsonValue::Null) | None => "None".to_owned(),
            Some(other) => other.to_string(),
        };
        let alert_title = text(block.get("alert").and_then(|alert| alert.get("title")))
            .or_else(|| text(block.get("details").and_then(|details| details.get("name"))));
        let entity_mappings = match block.get("entities") {
            Some(JsonValue::Array(entities)) => entities
                .iter()
                .map(|entity| {
                    let pairs: Vec<String> = match entity.get("mappings") {
                        Some(JsonValue::Array(mappings)) => mappings
                            .iter()
                            .map(|mapping| {
                                format!(
                                    "{} -> {}",
                                    text(mapping.get("identifier")).unwrap_or_default(),
                                    text(mapping.get("column")).unwrap_or_default()
                                )
                            })
                            .collect(),
                        _ => Vec::new(),
                    };
                    let entity_name = text(entity.get("entity")).unwrap_or_else(|| "None".into());
                    if pairs.is_empty() {
                        entity_name
                    } else {
                        format!("{entity_name}: {}", pairs.join(", "))
                    }
                })
                .collect(),
            _ => Vec::new(),
        };
        let has_query = matches!(block.get("query"), Some(JsonValue::String(q)) if !q.is_empty());
        out.push(Platform {
            name,
            enabled,
            status: text(block.get("status")),
            alert_title,
            entity_mappings,
            query: block_query(block),
            language: if has_query { "sql" } else { "spl" },
        });
    }
    out
}

/// The query a block shows: `query`, `search`, a single event's query or a
/// correlation's sub-queries (`_platform_query`).
fn block_query(block: &JsonValue) -> Option<String> {
    let nonblank = |value: Option<&JsonValue>| -> Option<String> {
        value
            .and_then(JsonValue::as_str)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_owned)
    };
    if let Some(query) = nonblank(block.get("query")) {
        return Some(query);
    }
    if let Some(search) = nonblank(block.get("search")) {
        return Some(search);
    }
    let condition = block.get("condition").filter(|value| value.is_object())?;
    if let Some(query) = nonblank(
        condition
            .get("single_event")
            .and_then(|event| event.get("query")),
    ) {
        return Some(query);
    }
    let fragments: Vec<String> = condition
        .get("correlation")
        .and_then(|correlation| correlation.get("sub_queries"))
        .and_then(JsonValue::as_array)
        .map(|queries| {
            queries
                .iter()
                .filter_map(|query| nonblank(query.get("query")))
                .collect()
        })
        .unwrap_or_default();
    (!fragments.is_empty()).then(|| fragments.join("\n\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_parse() {
        let _ = Templates::new();
    }

    #[test]
    fn cells() {
        assert_eq!(cell("a|b\\|c\nd\r\ne\n"), "a\\|b\\|c d e");
        assert_eq!(table_cell(" a|b\n "), "a\\|b");
        assert_eq!(table_cell("  "), "-");
    }

    #[test]
    fn blocks_join_with_a_blank_line() {
        let blocks = vec![
            JinjaValue::from(" a \n"),
            JinjaValue::from(""),
            JinjaValue::from("\n\n"),
            JinjaValue::from("b"),
        ];
        assert_eq!(join_blocks(blocks).unwrap(), "a\n\nb");
    }

    #[test]
    fn titles() {
        assert_eq!(title_case("objective"), "Objective");
        assert_eq!(title_case("downstream"), "Downstream");
        assert_eq!(title_case("a-b c"), "A-B C");
    }

    #[test]
    fn queries_of_blocks() {
        let block = serde_json::json!({"condition": {"correlation": {"sub_queries": [
            {"query": "a"}, {"query": " "}, {"query": "b"}
        ]}}});
        assert_eq!(block_query(&block).as_deref(), Some("a\n\nb"));
        let block = serde_json::json!({"search": "s", "query": ""});
        assert_eq!(block_query(&block).as_deref(), Some("s"));
        assert_eq!(block_query(&serde_json::json!({"condition": "x"})), None);
    }
}
