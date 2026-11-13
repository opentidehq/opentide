//! Pages from the catalogue (`documentation/objects/`, `parts/`,
//! `publish/index.py`).
//!
//! Every page has one layout ([`super::page`]): a breadcrumb, the title, a
//! subtitle (kind, schema, version, modification date, TLP), a TLP banner
//! above `TLP:CLEAR`, the description, an overview table, a contents line,
//! the sections in reading order, and the Metadata last. This module works
//! out each section's body from the models; the facts a rule's Deployment
//! section states come from [`super::facts`], and every platform setting
//! from [`super::settings`].
//!
//! Diagrams are built by [`super::diagrams`] and written as Mermaid by
//! [`super::mermaid`]. The root README is the catalogue overview: the
//! sections, the threat landscape, the deployment status and the coverage
//! by kill-chain phase and ATT&CK tactic.

use std::collections::HashSet;

use super::Settings;
use super::catalog::{Catalog, Graph, Model, Record, RuleModel, Scope};
use super::cve;
use super::diagrams;
use super::facts::{
    Block, Environment as Deployment, PlatformDeployment, TenantScope, TenantTarget,
    rule_deployments,
};
use super::flavor::Flavor;
use super::mermaid::NodeKind;
use super::page::{Callout, Page, Section, callout, code_block, key_value_table, paragraph, table};
use super::platforms::{self, TEXT, platform_label};
use super::settings::{Settings as BlockSettings, flatten};
use super::text::{first_sentence, inline_code, join, join_lines, plural, table_cell, title_case};
use super::vocab::{Enriched, Vocab};
use crate::json::Json;
use crate::strategy::StatusStrategy;

/// What renders pages: the catalogue, the settings, the vocabularies and
/// the deployment facts.
pub struct Pages<'a, 'i> {
    /// The objects.
    pub catalog: &'a Catalog<'i>,
    /// The run's settings.
    pub settings: &'a Settings,
    /// The vocabularies.
    pub vocab: Vocab<'a>,
    /// The workspace's statuses, tenants and deployment state.
    pub deployment: &'a Deployment,
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
            severity: rule.displayed_severity(),
            techniques: &rule.techniques,
            detection_model: rule.detection_model.as_deref(),
            response: rule.response.as_ref(),
            configurations: rule.configurations.as_ref(),
        }
    }};
}

/// What a page is about: its noun in the subtitle and its folder index's
/// title.
#[derive(Clone, Copy)]
struct Kind {
    noun: &'static str,
    index_title: &'static str,
    node: NodeKind,
}

const RULE: Kind = Kind {
    noun: "Detection rule",
    index_title: "Detection rules",
    node: NodeKind::Rule,
};
const OBJECTIVE: Kind = Kind {
    noun: "Detection objective",
    index_title: "Detection objectives",
    node: NodeKind::Objective,
};
const THREAT: Kind = Kind {
    noun: "Threat vector",
    index_title: "Threat vectors",
    node: NodeKind::Threat,
};

/// Block keys the Deployment table and each platform's summary line already
/// state.
const DEPLOYMENT_KEYS: [&str; 4] = ["enabled", "status", "tenants", "schema"];

/// The platform blocks a rule configures, in the model's order: each as the
/// model holds it and as its file writes it.
fn blocks(
    configurations: Option<&opentide_schema::objects::RuleConfigurations>,
    written: Option<&Json>,
) -> Vec<(&'static str, Json, Option<Json>)> {
    let Some(configurations) = configurations else {
        return Vec::new();
    };
    let Ok(Json::Object(all)) = Json::from_serialize(configurations) else {
        return Vec::new();
    };
    opentide_schema::objects::RuleConfigurations::PLATFORMS
        .iter()
        .filter_map(|platform| {
            let block = all.get(*platform).filter(|block| !block.is_null())?;
            let given = written.and_then(|written| written.get(platform)).cloned();
            Some((*platform, block.clone(), given))
        })
        .collect()
}

impl Pages<'_, '_> {
    fn flavor(&self) -> Flavor {
        self.settings.flavor
    }

    fn wiki(&self) -> bool {
        self.flavor().wiki_links()
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

    /// A link to `uuid`'s page, or to its signal's heading on its objective's
    /// page; with `with_uuid`, the UUID after it (`object_link`).
    fn link_to(&self, uuid: &str, from: &str, with_uuid: bool) -> String {
        let suffix = if with_uuid {
            format!(" (`{uuid}`)")
        } else {
            String::new()
        };
        if let Some(signal) = self.catalog.signal(uuid) {
            let Some(parent) = self.catalog.record(&signal.owner) else {
                return format!("{}{suffix}", signal.name);
            };
            let anchor = self.flavor().heading_anchor(&signal.name);
            let href = Self::href(from, "objectives", &self.filename(parent), Some(&anchor));
            let link = self.flavor().render_link(&signal.name, &href, self.wiki());
            return format!("{link}{suffix}");
        }
        let Some(record) = self.catalog.record(uuid) else {
            let name = self.catalog.name(uuid);
            if name != uuid {
                return format!("{name}{suffix}");
            }
            return format!("`{uuid}`");
        };
        let href = Self::href(from, record.scope.folder(), &self.filename(record), None);
        let link = self.flavor().render_link(&record.name, &href, self.wiki());
        format!("{link}{suffix}")
    }

    // ---- the page frame -------------------------------------------------

    /// A page with its header: breadcrumb, title, subtitle, TLP banner and
    /// description.
    fn page(&self, kind: Kind, title: &str, meta: &Meta<'_>, description: &str) -> Page {
        let frontmatter = self.settings.uuid_permalinks && self.wiki();
        let mut page = Page::new(self.flavor(), title, frontmatter, self.breadcrumb(kind));
        page.add_lead([
            self.subtitle(kind, meta),
            self.tlp_banner(meta.tlp),
            prose(description),
        ]);
        page
    }

    /// `Catalogue / Detection rules`: the way back to the indexes. Azure
    /// DevOps names every index page `README`, so its pages go without one.
    fn breadcrumb(&self, kind: Kind) -> String {
        if self.flavor() == Flavor::AzureDevops {
            return String::new();
        }
        let root = self
            .flavor()
            .render_link("Catalogue", "../README.md", self.wiki());
        let index = self
            .flavor()
            .render_link(kind.index_title, "README.md", self.wiki());
        paragraph(&format!("{root} / {index}"))
    }

    /// `*Detection rule · `rule::1.0` · version 3 · modified 2026-01-02 · TLP:CLEAR*`.
    fn subtitle(&self, kind: Kind, meta: &Meta<'_>) -> String {
        let parts = [
            kind.noun.to_owned(),
            inline_code(meta.schema),
            format!("version {}", meta.version),
            format!("modified {}", meta.modified),
            self.tlp_marking(meta.tlp),
        ];
        let kept: Vec<&str> = parts
            .iter()
            .map(String::as_str)
            .filter(|part| !part.is_empty())
            .collect();
        paragraph(&format!("*{}*", kept.join(" · ")))
    }

    /// The marking id of `tlp` (`TLP:AMBER`), or the value as written.
    fn tlp_marking(&self, tlp: &str) -> String {
        let entry = self.vocab.enrich("tlp", tlp);
        if entry.id.is_empty() {
            tlp.to_owned()
        } else {
            entry.id
        }
    }

    /// `clear (`TLP:CLEAR`)`: the label and its marking id.
    fn tlp_label(&self, tlp: &str) -> String {
        let entry = self.vocab.enrich("tlp", tlp);
        if !entry.id.is_empty() && entry.id != entry.label {
            format!("{} ({})", entry.label, inline_code(&entry.id))
        } else {
            entry.label
        }
    }

    /// A warning for any marking that limits who may read the page.
    fn tlp_banner(&self, tlp: &str) -> String {
        let marking = self.tlp_marking(tlp);
        if matches!(marking.as_str(), "" | "TLP:CLEAR" | "TLP:WHITE") {
            return String::new();
        }
        let entry = self.vocab.enrich("tlp", tlp);
        let mut text = format!("**{marking}**");
        if !entry.description.is_empty() {
            text = format!("{text}: {}", first_sentence(&entry.description, 240));
        }
        callout(self.flavor(), Callout::Warning, &text)
    }

    /// Provenance: identifiers, versions, dates, marking and authorship. The
    /// UUID row comes first: a generated page is recognised by it.
    fn metadata_section(&self, meta: &Meta<'_>) -> Section {
        let mut rows = vec![
            ("UUID", inline_code(meta.uuid)),
            ("Schema", inline_code(meta.schema)),
            ("Version", inline_code(&meta.version)),
            ("Created", inline_code(meta.created)),
            ("Modified", inline_code(meta.modified)),
            ("TLP", self.tlp_label(meta.tlp)),
            ("Author", table_cell(meta.author.unwrap_or_default())),
            (
                "Contributors",
                meta.contributors.unwrap_or_default().join(", "),
            ),
        ];
        if let Some((name, uuid)) = meta.organisation {
            rows.push(("Organisation", format!("{name} ({})", inline_code(uuid))));
        }
        Section::new("Metadata", [key_value_table(&rows, ["Field", "Value"])])
    }

    /// Public, internal and report references as one table.
    fn references_section(
        &self,
        references: Option<&opentide_schema::objects::ObjectReferences>,
    ) -> Section {
        let Some(references) = references else {
            return Section::default();
        };
        let mut rows: Vec<[String; 3]> = Vec::new();
        for (key, value) in references.public.iter().flatten() {
            rows.push([
                "Public".to_owned(),
                table_cell(&key.to_string()),
                reference_value(value),
            ]);
        }
        let mut internal: Vec<(&String, &String)> = references.internal.iter().flatten().collect();
        internal.sort();
        for (key, value) in internal {
            rows.push([
                "Internal".to_owned(),
                table_cell(key),
                reference_value(value),
            ]);
        }
        for value in references.reports.iter().flatten() {
            rows.push(["Report".to_owned(), "-".to_owned(), reference_value(value)]);
        }
        if rows.is_empty() {
            return Section::default();
        }
        Section::new("References", [table(&["Kind", "Key", "Reference"], &rows)])
    }

    // ---- shared tables -------------------------------------------------

    /// The vocabulary label of `key`, with the key itself when they differ.
    fn vocab_label(&self, field: &str, key: &str) -> String {
        let entry = self.vocab.enrich(field, key);
        if entry.label == key {
            key.to_owned()
        } else {
            format!("{} ({})", entry.label, inline_code(key))
        }
    }

    /// Technique ids as links, one line each, for an overview cell.
    fn technique_links(&self, techniques: &[String]) -> String {
        let mut lines = Vec::new();
        for technique in unique(techniques) {
            let entry = self.vocab.enrich("att&ck", technique);
            let name = if entry.label == *technique {
                String::new()
            } else {
                format!(" {}", entry.label)
            };
            lines.push(entry_link(&entry, technique, Some(&inline_code(technique))) + &name);
        }
        join_lines(lines)
    }

    /// ATT&CK techniques in matrix order, with their tactics and opening
    /// sentence; with `detections` (technique to the rule links that detect
    /// it), a Detected by column.
    fn attack_table(
        &self,
        techniques: &[String],
        detections: Option<&[(String, Vec<String>)]>,
    ) -> String {
        let order = self.vocab.attack_tactics();
        let position = |technique: &str| {
            let tactics = self.vocab.technique_tactics(technique, &order);
            let at = tactics
                .first()
                .and_then(|first| order.iter().position(|tactic| tactic == first))
                .unwrap_or(order.len());
            (at, technique.to_owned())
        };
        let mut sorted: Vec<&String> = unique(techniques);
        sorted.sort_by_key(|technique| position(technique));
        let mut rows: Vec<Vec<String>> = Vec::new();
        for technique in sorted {
            let entry = self.vocab.enrich("att&ck", technique);
            let mut row = vec![
                entry_link(&entry, technique, Some(&inline_code(technique))),
                table_cell(if entry.label == *technique {
                    ""
                } else {
                    &entry.label
                }),
                table_cell(&self.vocab.technique_tactics(technique, &order).join(", ")),
            ];
            if let Some(detections) = detections {
                let rules = detections
                    .iter()
                    .find(|(wanted, _)| wanted == technique)
                    .map(|(_, rules)| rules.as_slice())
                    .unwrap_or_default();
                row.push(if rules.is_empty() {
                    "*No rule*".to_owned()
                } else {
                    join_lines(rules)
                });
            }
            row.push(table_cell(&first_sentence(&entry.description, 240)));
            rows.push(row);
        }
        if rows.is_empty() {
            return String::new();
        }
        let mut headers = vec!["Technique", "Name", "Tactics"];
        if detections.is_some() {
            headers.push("Detected by");
        }
        headers.push("Summary");
        table(&headers, &rows)
    }

    /// Each technique to links to the rules that detect it, or a
    /// sub-technique of it.
    fn technique_detections(
        &self,
        techniques: &[String],
        from: &str,
    ) -> Vec<(String, Vec<String>)> {
        unique(techniques)
            .into_iter()
            .map(|technique| {
                let rules = self
                    .catalog
                    .rules
                    .iter()
                    .filter(|record| {
                        rule_techniques(&record.model)
                            .iter()
                            .any(|found| covers_technique(found, technique))
                    })
                    .map(|record| self.link_to(&record.uuid, from, false))
                    .collect();
                (technique.clone(), rules)
            })
            .collect()
    }

    /// Every object related to `uuid`, linked: Mermaid nodes are not
    /// clickable on GitHub.
    fn related_table(&self, uuid: &str, from: &str) -> String {
        let mut related = self.catalog.related(uuid, self.settings.direction);
        if related.is_empty() {
            return String::new();
        }
        let order = |object_type: &str| match object_type {
            "threat" => 0,
            "objective" => 1,
            "signal" => 2,
            "rule" => 3,
            _ => 4,
        };
        related.sort_by_key(|entry| (order(&entry.object_type), entry.name.to_lowercase()));
        let rows: Vec<[String; 3]> = related
            .iter()
            .map(|entry| {
                [
                    title_case(if entry.object_type.is_empty() {
                        "object"
                    } else {
                        &entry.object_type
                    }),
                    self.link_to(&entry.uuid, from, false),
                    title_case(entry.direction.name()),
                ]
            })
            .collect();
        table(&["Type", "Object", "Direction"], &rows)
    }

    /// The coverage diagram, else the relations diagram, and the table of
    /// related objects.
    fn coverage_section(&self, kind: Kind, uuid: &str, name: &str, from: &str) -> Section {
        let coverage =
            diagrams::coverage(self.catalog, uuid, name).filter(|diagram| !diagram.is_trivial());
        let (title, diagram) = match coverage {
            Some(diagram) => ("Detection coverage", Some(diagram)),
            None => (
                "Relations",
                diagrams::relations(self.catalog, uuid, name, kind.node, self.settings.direction),
            ),
        };
        Section::new(title, [diagrams::fenced(self.flavor(), diagram.as_ref())]).with_children(
            vec![Section::new(
                "Related objects",
                [self.related_table(uuid, from)],
            )],
        )
    }

    // ---- rules ---------------------------------------------------------

    /// The page of a rule.
    ///
    /// Reading order: what the rule is (overview, description), where it
    /// runs (Deployment), what it runs (Platform configuration), what an
    /// analyst does with its alert (Response), then context.
    ///
    /// # Errors
    ///
    /// A diagram failed to render.
    pub fn rule(&self, record: &Record) -> Result<String, String> {
        let Model::Rule(model) = &record.model else {
            return Err("not a rule".to_owned());
        };
        let rule = match model {
            RuleModel::V1_0(rule) => rule_view!(rule.as_ref()),
            RuleModel::V1_1(rule) => rule_view!(rule.as_ref()),
        };
        let blocks = blocks(
            rule.configurations,
            self.catalog.written_configurations(&record.uuid),
        );
        let deployments = rule_deployments(
            &record.uuid,
            &blocks
                .iter()
                .map(|(platform, json, _)| Block { platform, json })
                .collect::<Vec<_>>(),
            self.deployment,
        );
        let mut page = self.page(RULE, rule.name, &rule.meta, rule.description);
        page.add_lead([self.rule_overview(&rule, &deployments)]);
        let map = diagrams::deployment(&record.uuid, rule.name, &deployments);
        page.add(
            Section::new(
                "Deployment",
                [
                    deployment_body(self.flavor(), &deployments),
                    diagrams::fenced(self.flavor(), map.as_ref()),
                ],
            )
            .with_children(vec![Section::new(
                "Tenant targeting",
                [tenants_body(&deployments)],
            )]),
        );
        let configurations = blocks
            .iter()
            .map(|(platform, json, written)| {
                let deployment = deployments
                    .iter()
                    .find(|deployment| deployment.platform == *platform);
                platform_section(platform, json, written.as_ref(), deployment)
            })
            .collect();
        page.add(Section::new("Platform configuration", [""]).with_children(configurations));
        page.add(Section::new(
            "Response",
            [self.response_body(rule.response)],
        ));
        page.add(Section::new(
            "ATT&CK techniques",
            [self.attack_table(rule.techniques, None)],
        ));
        page.add(self.coverage_section(RULE, &record.uuid, &record.name, "rules"));
        page.add(self.references_section(rule.references));
        page.add(self.metadata_section(&rule.meta));
        Ok(page.render())
    }

    /// The facts a reader needs first: severity, model, techniques, where it
    /// runs, who handles it.
    fn rule_overview(&self, rule: &RuleView<'_>, deployments: &[PlatformDeployment]) -> String {
        let response = rule.response;
        let rows = [
            (
                "Severity",
                self.vocab_label("alert_severity", rule.severity.unwrap_or_default()),
            ),
            (
                "Detection model",
                rule.detection_model
                    .filter(|model| !model.is_empty())
                    .map(|model| self.link_to(model, "rules", false))
                    .unwrap_or_default(),
            ),
            ("ATT&CK", self.technique_links(rule.techniques)),
            (
                "Platforms",
                join_lines(deployments.iter().map(|deployment| {
                    format!(
                        "{}: {} ({})",
                        deployment.label,
                        inline_code(&deployment.status),
                        runs_text(deployment)
                    )
                })),
            ),
            (
                "Playbook",
                response
                    .and_then(|response| response.playbook.as_deref())
                    .filter(|text| !text.is_empty())
                    .map(table_cell)
                    .unwrap_or_default(),
            ),
            (
                "Responders",
                response
                    .map(|response| table_cell(&self.responders(response)))
                    .unwrap_or_default(),
            ),
        ];
        key_value_table(&rows, ["Property", "Value"])
    }

    /// The team that handles the rule's alerts: its own, else
    /// `[deployment] default_responders` (`resolve_responders`).
    fn responders(&self, response: &opentide_schema::objects::RuleResponse) -> String {
        response
            .responders
            .clone()
            .filter(|team| !team.is_empty())
            .unwrap_or_else(|| self.deployment.default_responders.clone())
    }

    /// Alert severity, playbook, responders and the analyst procedure.
    fn response_body(&self, response: Option<&opentide_schema::objects::RuleResponse>) -> String {
        let Some(response) = response else {
            return String::new();
        };
        let rows = [
            (
                "Alert severity",
                self.vocab_label("alert_severity", &response.alert_severity),
            ),
            (
                "Playbook",
                table_cell(response.playbook.as_deref().unwrap_or_default()),
            ),
            ("Responders", table_cell(&self.responders(response))),
        ];
        let mut parts = vec![key_value_table(&rows, ["Property", "Value"])];
        if let Some(procedure) = &response.procedure {
            parts.push(format!("**Analysis**\n\n{}", procedure.analysis.trim()));
            if let Some(containment) = procedure
                .containment
                .as_deref()
                .filter(|text| !text.is_empty())
            {
                parts.push(format!("**Containment**\n\n{}", containment.trim()));
            }
            for search in procedure.searches.iter().flatten() {
                let language = platforms::search_language(&search.system);
                parts.push(format!(
                    "**Search: {}** ({}, {})",
                    search.purpose, search.system, language.name
                ));
                parts.push(code_block(
                    language.fence,
                    search.query.trim_end_matches('\n'),
                ));
            }
        }
        join(parts)
    }

    // ---- objectives ----------------------------------------------------

    /// The page of an objective.
    ///
    /// Reading order: the goal (overview, description, composition), the
    /// threats it answers, its signals, how far rules implement them, then
    /// context.
    ///
    /// # Errors
    ///
    /// A diagram failed to render.
    pub fn objective(&self, record: &Record) -> Result<String, String> {
        let Model::Objective(objective) = &record.model else {
            return Err("not an objective".to_owned());
        };
        let body = &objective.objective;
        let meta = meta!(&objective.metadata);
        let mut page = self.page(OBJECTIVE, &objective.name, &meta, &body.description);
        let rules = self.implementing_rules(objective, &record.uuid);
        page.add_lead([
            self.objective_overview(objective, &rules),
            self.unimplemented_signals(objective),
        ]);
        page.add(Section::new(
            "Composition",
            [self.composition_body(objective)],
        ));
        page.add(Section::new(
            "Threats addressed",
            [self.threats_body(objective)],
        ));
        let signals: Vec<Section> = body
            .signals
            .iter()
            .map(|signal| self.signal_section(signal))
            .collect();
        let had_signals = !signals.is_empty();
        page.add(Section::new("Signals", [""]).with_children(signals));
        let techniques = body.mitre_attack.clone().unwrap_or_default();
        let detections = self.technique_detections(&techniques, "objectives");
        page.add(Section::new(
            "ATT&CK techniques",
            [self.attack_table(&techniques, Some(&detections))],
        ));
        page.add(self.coverage_section(OBJECTIVE, &record.uuid, &record.name, "objectives"));
        page.add(self.references_section(objective.references.as_ref()));
        page.add(self.metadata_section(&meta));
        // The summary links each signal's heading, so it is written once the
        // page knows every anchor, a repeated title's `-1` included.
        if had_signals
            && let Some(index) = page
                .sections()
                .iter()
                .position(|section| section.title == "Signals")
        {
            let anchors = page.child_anchors(index);
            page.set_body(
                index,
                self.signals_summary(objective, &record.uuid, &anchors),
            );
        }
        Ok(page.render())
    }

    /// Rules implementing the objective itself or one of its signals, in
    /// catalogue order.
    fn implementing_rules(
        &self,
        objective: &opentide_schema::objects::ObjectiveV1_0,
        uuid: &str,
    ) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for signal in &objective.objective.signals {
            for rule in self.catalog.rules_for_signal(&signal.uuid) {
                if !found.contains(&rule) {
                    found.push(rule);
                }
            }
        }
        for record in &self.catalog.rules {
            if super::catalog::rule_detection_model(&record.model) == Some(uuid)
                && !found.contains(&record.uuid)
            {
                found.push(record.uuid.clone());
            }
        }
        let mut ordered: Vec<String> = self
            .catalog
            .rules
            .iter()
            .filter(|record| found.contains(&record.uuid))
            .map(|record| record.uuid.clone())
            .collect();
        let mut rest: Vec<String> = found
            .into_iter()
            .filter(|uuid| !ordered.contains(uuid))
            .collect();
        rest.sort();
        ordered.extend(rest);
        ordered
    }

    fn objective_overview(
        &self,
        objective: &opentide_schema::objects::ObjectiveV1_0,
        rules: &[String],
    ) -> String {
        let body = &objective.objective;
        let mut platforms: Vec<String> = Vec::new();
        for uuid in rules {
            for (platform, _) in self.rule_statuses(uuid) {
                let label = platform_label(platform);
                if !platforms.contains(&label) {
                    platforms.push(label);
                }
            }
        }
        platforms.sort();
        let rows = [
            ("Priority", table_cell(&body.priority)),
            (
                "Type",
                self.vocab.enrich("detection.types", &body.r#type).label,
            ),
            (
                "Composition",
                self.vocab
                    .enrich("detection.composition", &body.composition.strategy)
                    .label,
            ),
            (
                "Investment",
                table_cell(body.investment.as_deref().unwrap_or_default()),
            ),
            (
                "Threats addressed",
                join_lines(
                    body.threats
                        .iter()
                        .flatten()
                        .map(|uuid| self.link_to(uuid, "objectives", false)),
                ),
            ),
            ("Signals", plural(body.signals.len(), "signal")),
            ("Detection rules", plural(rules.len(), "rule")),
            ("Platforms", platforms.join(", ")),
            (
                "ATT&CK",
                self.technique_links(body.mitre_attack.as_deref().unwrap_or_default()),
            ),
        ];
        key_value_table(&rows, ["Property", "Value"])
    }

    /// A warning naming the signals no rule implements yet.
    fn unimplemented_signals(&self, objective: &opentide_schema::objects::ObjectiveV1_0) -> String {
        let signals = &objective.objective.signals;
        let missing: Vec<String> = signals
            .iter()
            .filter(|signal| self.catalog.rules_for_signal(&signal.uuid).is_empty())
            .map(|signal| format!("*{}*", table_cell(&signal.name)))
            .collect();
        if missing.is_empty() {
            return String::new();
        }
        callout(
            self.flavor(),
            Callout::Warning,
            &format!(
                "{} of {} {} no implementing rule yet: {}.",
                missing.len(),
                plural(signals.len(), "signal"),
                if missing.len() == 1 { "has" } else { "have" },
                missing.join(", ")
            ),
        )
    }

    fn composition_body(&self, objective: &opentide_schema::objects::ObjectiveV1_0) -> String {
        let composition = &objective.objective.composition;
        let entry = self
            .vocab
            .enrich("detection.composition", &composition.strategy);
        let mut lead = format!("**{}**", entry.label);
        if !entry.description.is_empty() {
            lead = format!("{lead}: {}", super::text::collapse(&entry.description));
        }
        join([paragraph(&lead), prose(&composition.description)])
    }

    fn threats_body(&self, objective: &opentide_schema::objects::ObjectiveV1_0) -> String {
        let mut rows: Vec<[String; 3]> = Vec::new();
        for uuid in objective.objective.threats.iter().flatten() {
            match self.catalog.record(uuid).map(|record| &record.model) {
                Some(Model::Threat(threat)) => {
                    let criticality = self.vocab.enrich("criticality", &threat.criticality).label;
                    let phases = killchain_phases(threat.threat.killchain.as_ref());
                    rows.push([
                        self.link_to(uuid, "objectives", false),
                        criticality,
                        if phases.is_empty() {
                            "-".to_owned()
                        } else {
                            phases.join(", ")
                        },
                    ]);
                }
                _ => rows.push([
                    self.link_to(uuid, "objectives", true),
                    "-".to_owned(),
                    "-".to_owned(),
                ]),
            }
        }
        if rows.is_empty() {
            return String::new();
        }
        table(&["Threat vector", "Criticality", "Kill chain"], &rows)
    }

    /// A signal's description and the facts the summary table has no room
    /// for; its heading is the anchor rule pages link to.
    fn signal_section(&self, signal: &opentide_schema::objects::DetectionSignal) -> Section {
        let rules = self.catalog.rules_for_signal(&signal.uuid);
        let data = &signal.data;
        let logsources = data.logsources.as_deref().unwrap_or_default();
        let facts = [
            format!(
                "**Data:** {}. {}",
                table_cell(&data.availability),
                data.requirements.trim()
            ),
            if logsources.is_empty() {
                String::new()
            } else {
                format!(
                    "**Log sources:** {}",
                    logsources
                        .iter()
                        .map(|source| inline_code(source))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
            format!(
                "**Entities:** {}",
                signal
                    .entities
                    .iter()
                    .map(|entity| self.vocab.enrich("signal.entities", entity).label)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            format!(
                "**Implemented by:** {}",
                if rules.is_empty() {
                    "*no rule yet*".to_owned()
                } else {
                    rules
                        .iter()
                        .map(|uuid| self.link_to(uuid, "objectives", false))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
            format!("**UUID:** {}", inline_code(&signal.uuid)),
        ];
        let list: Vec<String> = facts
            .iter()
            .filter(|fact| !fact.is_empty())
            .map(|fact| format!("- {fact}"))
            .collect();
        Section::new(
            &signal.name,
            [
                prose(&signal.description),
                list.join("\n") + "\n",
                detectors_body(signal.detectors.as_deref().unwrap_or_default()),
                examples_body(signal.examples.as_deref().unwrap_or_default()),
            ],
        )
    }

    /// Every signal at a glance: how it detects, and the rules and
    /// platforms implementing it. `anchors` are the signal headings'
    /// anchors as the page assigns them.
    fn signals_summary(
        &self,
        objective: &opentide_schema::objects::ObjectiveV1_0,
        uuid: &str,
        anchors: &[String],
    ) -> String {
        let signals = &objective.objective.signals;
        let mut rows: Vec<[String; 6]> = Vec::new();
        let mut listed: Vec<String> = Vec::new();
        for (index, signal) in signals.iter().enumerate() {
            let rules = self.catalog.rules_for_signal(&signal.uuid);
            listed.extend(rules.iter().cloned());
            let anchor = anchors
                .get(index)
                .cloned()
                .unwrap_or_else(|| self.flavor().heading_anchor(&signal.name));
            rows.push([
                Flavor::link(&table_cell(&signal.name), &format!("#{anchor}")),
                self.vocab.enrich("alert_severity", &signal.severity).label,
                self.vocab
                    .enrich("detection.methodology", &signal.methodology)
                    .label,
                signal
                    .effort
                    .map_or_else(|| "-".to_owned(), |effort| effort.to_string()),
                or_dash(
                    join_lines(
                        rules
                            .iter()
                            .map(|rule| self.link_to(rule, "objectives", false)),
                    ),
                    "*None yet*",
                ),
                or_dash(
                    join_lines(rules.iter().map(|rule| self.rule_platforms(rule))),
                    "-",
                ),
            ]);
        }
        let direct: Vec<&Record> = self
            .catalog
            .rules
            .iter()
            .filter(|record| {
                super::catalog::rule_detection_model(&record.model) == Some(uuid)
                    && !listed.contains(&record.uuid)
            })
            .collect();
        if !direct.is_empty() {
            rows.push([
                "*Objective as a whole*".to_owned(),
                "-".to_owned(),
                "-".to_owned(),
                "-".to_owned(),
                join_lines(
                    direct
                        .iter()
                        .map(|record| self.link_to(&record.uuid, "objectives", false)),
                ),
                join_lines(
                    direct
                        .iter()
                        .map(|record| self.rule_platforms(&record.uuid)),
                ),
            ]);
        }
        table(
            &[
                "Signal",
                "Severity",
                "Methodology",
                "Effort",
                "Rules",
                "Platforms and status",
            ],
            &rows,
        )
    }

    /// A rule's statuses, by platform: what deploy reads.
    fn rule_statuses(&self, uuid: &str) -> Vec<(&'static str, String)> {
        let Some(Model::Rule(rule)) = self.catalog.record(uuid).map(|record| &record.model) else {
            return Vec::new();
        };
        let configurations = match rule {
            RuleModel::V1_0(rule) => rule.configurations.as_ref(),
            RuleModel::V1_1(rule) => rule.configurations.as_ref(),
        };
        configurations
            .map(opentide_schema::objects::RuleConfigurations::platform_statuses)
            .unwrap_or_default()
            .into_iter()
            .map(|(platform, status)| (platform, status.to_owned()))
            .collect()
    }

    /// `Microsoft Sentinel `STAGING``, one line per platform.
    fn rule_platforms(&self, uuid: &str) -> String {
        if !matches!(
            self.catalog.record(uuid).map(|record| &record.model),
            Some(Model::Rule(_))
        ) {
            return "-".to_owned();
        }
        let statuses = self.rule_statuses(uuid);
        if statuses.is_empty() {
            return "-".to_owned();
        }
        join_lines(statuses.iter().map(|(platform, status)| {
            format!("{} {}", platform_label(platform), inline_code(status))
        }))
    }

    // ---- threats -------------------------------------------------------

    /// The page of a threat.
    ///
    /// Reading order: the threat (overview, description, assessment), who
    /// and what it involves, how it chains with other threats, and how it
    /// is detected.
    ///
    /// # Errors
    ///
    /// A diagram failed to render.
    pub fn threat(&self, record: &Record) -> Result<String, String> {
        let Model::Threat(threat) = &record.model else {
            return Err("not a threat".to_owned());
        };
        let body = &threat.threat;
        let meta = meta!(&threat.metadata);
        let (objectives, rules) = coverage_counts(&self.catalog.coverage_graph(&record.uuid));
        let cves = cve::CveFindings::lookup(
            cve::identifiers(body.cve.as_deref().unwrap_or_default()),
            self.settings.cve_details,
            &self.settings.cve_source,
        );
        let mut page = self.page(THREAT, &threat.name, &meta, &body.description);
        page.add_lead([self.threat_overview(threat, objectives, rules, &cves)]);
        if let Some(warning) = cves.exploited_warning() {
            page.add_lead([callout(self.flavor(), Callout::Warning, &warning)]);
        }
        if objectives == 0 {
            page.add_lead([callout(
                self.flavor(),
                Callout::Warning,
                "No detection objective addresses this threat vector yet.",
            )]);
        }
        let criticality = self.vocab.enrich("criticality", &threat.criticality);
        let mut criticality_text = format!("**Criticality: {}**", criticality.label);
        if !criticality.description.is_empty() {
            criticality_text = format!(
                "{criticality_text}. {}",
                super::text::collapse(&criticality.description)
            );
        }
        page.add(Section::new(
            "Assessment",
            [
                paragraph(&criticality_text),
                if body.terrain.trim().is_empty() {
                    String::new()
                } else {
                    paragraph(&format!("**Terrain:** {}", body.terrain.trim()))
                },
                self.killchain_strip(&killchain_phases(body.killchain.as_ref())),
                self.killchain_map(&record.uuid, &killchain_phases(body.killchain.as_ref())),
                self.assessment_table(body),
            ],
        ));
        page.add(Section::new("Surface", [self.surface_table(&body.surface)]));
        page.add(Section::new("Actors", [self.actors_table(body)]));
        let detections = self.technique_detections(&body.mitre_attack, "threats");
        page.add(Section::new(
            "ATT&CK techniques",
            [self.attack_table(&body.mitre_attack, Some(&detections))],
        ));
        page.add(Section::new("CVE", [self.cve_body(&cves)]));
        page.add(
            Section::new(
                "Chaining",
                [diagrams::fenced(
                    self.flavor(),
                    diagrams::chaining(self.catalog, &self.vocab, &record.uuid, &threat.name)
                        .as_ref(),
                )],
            )
            .with_children(vec![Section::new(
                "Chaining relations",
                [self.chaining_table(threat)],
            )]),
        );
        page.add(self.coverage_section(THREAT, &record.uuid, &record.name, "threats"));
        page.add(self.references_section(threat.references.as_ref()));
        page.add(self.metadata_section(&meta));
        Ok(page.render())
    }

    fn threat_overview(
        &self,
        threat: &opentide_schema::objects::ThreatVector,
        objectives: usize,
        rules: usize,
        cves: &cve::CveFindings,
    ) -> String {
        let body = &threat.threat;
        let detection = if objectives == 0 {
            "None".to_owned()
        } else {
            format!(
                "{}, {}",
                plural(objectives, "objective"),
                plural(rules, "rule")
            )
        };
        let actors: Vec<String> = body
            .actors
            .iter()
            .flatten()
            .map(|actor| self.vocab.enrich("actors", &actor.name).label)
            .collect();
        let rows = [
            (
                "Criticality",
                self.vocab.enrich("criticality", &threat.criticality).label,
            ),
            (
                "Severity",
                self.vocab.enrich("severity", &body.severity).label,
            ),
            (
                "Kill chain",
                killchain_phases(body.killchain.as_ref()).join(", "),
            ),
            (
                "Surface",
                body.surface
                    .iter()
                    .map(|value| self.surface_label(value).0)
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            ("Actors", table_cell(&actors.join(", "))),
            ("ATT&CK", self.technique_links(&body.mitre_attack)),
            ("CVE", cves.overview()),
            ("Detection coverage", detection),
        ];
        key_value_table(&rows, ["Property", "Value"])
    }

    /// Where the threat sits on the kill chain: its phases in bold, with two
    /// neighbours on each side.
    fn killchain_strip(&self, phases: &[String]) -> String {
        const CONTEXT: usize = 2;
        let order = self.vocab.order("killchain");
        let mut positions: Vec<usize> = phases
            .iter()
            .filter_map(|phase| order.iter().position(|known| known == phase))
            .collect();
        if positions.is_empty() {
            return String::new();
        }
        positions.sort_unstable();
        let first = positions[0].saturating_sub(CONTEXT);
        let last = (positions[positions.len() - 1] + CONTEXT).min(order.len() - 1);
        let steps: Vec<String> = order[first..=last]
            .iter()
            .map(|phase| {
                if phases.contains(phase) {
                    format!("**{phase}**")
                } else {
                    phase.clone()
                }
            })
            .collect();
        let mut window = steps.join(" → ");
        if first > 0 {
            window = format!("… {window}");
        }
        if last < order.len() - 1 {
            window.push_str(" …");
        }
        let place = positions
            .iter()
            .map(|position| (position + 1).to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let noun = if positions.len() == 1 {
            "phase"
        } else {
            "phases"
        };
        let mut stages: Vec<String> = Vec::new();
        for phase in phases {
            let stage = self.vocab.killchain_stage(phase);
            if !stage.is_empty() && !stages.contains(&stage) {
                stages.push(stage);
            }
        }
        let mut context = format!("{noun} {place} of {}", order.len());
        if !stages.is_empty() {
            context = format!("{context}, stage {}", stages.join(", "));
        }
        paragraph(&format!("**Kill chain** ({context}): {window}"))
    }

    fn assessment_table(&self, body: &opentide_schema::objects::ThreatBody) -> String {
        let row = |title: &str, field: &str, values: &[String]| -> [String; 3] {
            let entries: Vec<Enriched> = values
                .iter()
                .map(|value| self.vocab.enrich(field, value))
                .collect();
            [
                title.to_owned(),
                join_lines(
                    entries
                        .iter()
                        .map(|entry| entry_link(entry, &entry.key, None)),
                ),
                join_lines(entries.iter().map(|entry| {
                    table_cell(if entry.description.is_empty() {
                        "-"
                    } else {
                        &entry.description
                    })
                })),
            ]
        };
        let mut rows = vec![
            row("Severity", "severity", std::slice::from_ref(&body.severity)),
            row("Impact", "impact", &body.impact),
            row("Leverage", "leverage", &body.leverage),
            row(
                "Viability",
                "viability",
                std::slice::from_ref(&body.viability),
            ),
        ];
        let phases = killchain_phases(body.killchain.as_ref());
        if !phases.is_empty() {
            rows.push(row("Kill chain", "killchain", &phases));
        }
        table(&["Dimension", "Assessment", "Description"], &rows)
    }

    /// A surface value's label and description: its stage's, else its
    /// entry's.
    fn surface_label(&self, value: &str) -> (String, String) {
        if let Some(found) = self.vocab.stage("surface", value) {
            return found;
        }
        let entry = self.vocab.enrich("surface", value);
        (entry.label, entry.description)
    }

    fn surface_table(&self, surface: &[String]) -> String {
        if surface.is_empty() {
            return String::new();
        }
        let rows: Vec<[String; 2]> = surface
            .iter()
            .map(|value| {
                let (label, description) = self.surface_label(value);
                [table_cell(&label), table_cell(&description)]
            })
            .collect();
        table(&["Surface", "Description"], &rows)
    }

    fn actors_table(&self, body: &opentide_schema::objects::ThreatBody) -> String {
        /// Aliases shown under a group's name; the rest are counted.
        const SHOWN: usize = 4;
        let Some(actors) = body.actors.as_ref().filter(|actors| !actors.is_empty()) else {
            return String::new();
        };
        let rows: Vec<[String; 4]> = actors
            .iter()
            .map(|actor| {
                let entry = self.vocab.enrich("actors", &actor.name);
                let mut name = entry_link(&entry, &entry.label, None);
                let aliases = self.vocab.actor_aliases(&actor.name);
                if !aliases.is_empty() {
                    let shown: Vec<String> = aliases
                        .iter()
                        .take(SHOWN)
                        .map(|alias| table_cell(alias))
                        .collect();
                    let more = aliases.len().saturating_sub(SHOWN);
                    let more = if more > 0 {
                        format!(" and {more} more")
                    } else {
                        String::new()
                    };
                    name = format!("{name}<br>*also {}{more}*", shown.join(", "));
                }
                let description = actor
                    .sighting
                    .clone()
                    .filter(|text| !text.is_empty())
                    .unwrap_or_else(|| first_sentence(&entry.description, 240));
                [
                    name,
                    inline_code(&actor.name),
                    table_cell(&entry.stages.join(", ")),
                    table_cell(&description),
                ]
            })
            .collect();
        table(&["Actor", "ID", "Source", "Description"], &rows)
    }

    /// Each chaining relation the threat declares, with what it means.
    fn chaining_table(&self, threat: &opentide_schema::objects::ThreatVector) -> String {
        let mut rows: Vec<[String; 4]> = Vec::new();
        for entry in threat.threat.chaining.iter().flatten() {
            let Some(target) = super::catalog::chain_target(entry) else {
                continue;
            };
            let key = entry
                .get("relation")
                .map(|text| text.trim().to_owned())
                .unwrap_or_default();
            let relation = (!key.is_empty()).then(|| self.vocab.enrich("chaining_relations", &key));
            let mut description = entry
                .get("description")
                .map(|text| text.trim().to_owned())
                .unwrap_or_default();
            if description.is_empty()
                && let Some(relation) = &relation
            {
                description.clone_from(&relation.description);
            }
            rows.push([
                relation.as_ref().map_or_else(
                    || "related".to_owned(),
                    |relation| inline_code(&relation.label),
                ),
                self.link_to(target, "threats", self.catalog.record(target).is_none()),
                relation
                    .as_ref()
                    .and_then(|relation| relation.stages.first().cloned())
                    .filter(|family| !family.is_empty())
                    .unwrap_or_else(|| "-".to_owned()),
                table_cell(&description.replace("**", "")),
            ]);
        }
        if rows.is_empty() {
            return String::new();
        }
        table(&["Relation", "Threat vector", "Family", "Meaning"], &rows)
    }

    /// The kill-chain map: the threat's own phases, and those of the threats
    /// chained to it.
    fn killchain_map(&self, uuid: &str, phases: &[String]) -> String {
        let network = self.catalog.chaining_network(uuid, &self.vocab);
        let mut related: Vec<(String, Vec<String>)> = Vec::new();
        for node in &network.nodes {
            let Some(phase) = node.killchain.as_ref().filter(|_| node.uuid != uuid) else {
                continue;
            };
            match related.iter_mut().find(|(known, _)| known == phase) {
                Some((_, names)) => names.push(node.name.clone()),
                None => related.push((phase.clone(), vec![node.name.clone()])),
            }
        }
        diagrams::fenced(
            self.flavor(),
            diagrams::threat_killchain(&self.vocab, phases, &related).as_ref(),
        )
    }

    /// The CVE section (`render_cves`): each identifier as a link to its
    /// record page, or, with `[cve] retrieve_details` on, a row of each
    /// record's severity, exploit likelihood, exploitation and weakness, and
    /// a line of what it is, affects and scores. Empty without identifiers.
    fn cve_body(&self, findings: &cve::CveFindings) -> String {
        if findings.identifiers.is_empty() {
            return String::new();
        }
        let links = &self.settings.cve;
        let link = |id: &str| Flavor::link(id, &links.page_url(id));
        let note = paragraph(
            "Identifiers link to [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu), \
             which aggregates CVE, GHSA, CSAF, NVD, and related feeds.",
        );
        if !findings.enriched() {
            let bullets = findings
                .identifiers
                .iter()
                .fold(String::new(), |mut out, id| {
                    use std::fmt::Write as _;
                    let _ = writeln!(out, "- {}", link(id));
                    out
                });
            return note + &bullets;
        }
        let mut rows: Vec<[String; 6]> = Vec::new();
        let mut details: Vec<String> = Vec::new();
        for (id, detail) in findings.identifiers.iter().zip(&findings.details) {
            let cve::CveDetail::Found(record) = detail else {
                let text = if matches!(detail, cve::CveDetail::NotFound) {
                    "Not found in Vulnerability-Lookup."
                } else {
                    "Details unavailable from Vulnerability-Lookup."
                };
                let dash = || "-".to_owned();
                rows.push([link(id), dash(), dash(), dash(), dash(), text.to_owned()]);
                continue;
            };
            rows.push(Self::cve_row(record, id, &link));
            details.push(cve::detail_line(record));
        }
        let mut parts = vec![
            note,
            table(
                &[
                    "Identifier",
                    "Severity",
                    "EPSS",
                    "Exploitation",
                    "Weakness",
                    "Published",
                ],
                &rows,
            ),
        ];
        if !details.is_empty() {
            parts.push(details.join("\n") + "\n");
        }
        let missing = findings.missing();
        if !missing.is_empty() {
            parts.push(paragraph(&format!(
                "Could not resolve: {}.",
                missing
                    .iter()
                    .map(|id| format!("`{id}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if findings.unreachable() {
            parts.push(paragraph(
                "Vulnerability-Lookup was unreachable for at least one identifier; links still \
                 point at the CIRCL record page.",
            ));
        }
        if findings.epss_unavailable() {
            parts.push(paragraph(
                "Vulnerability-Lookup returned no EPSS score for at least one identifier; those \
                 rows show none.",
            ));
        }
        parts.push(paragraph(
            "*EPSS: FIRST's probability of exploitation in the next 30 days. Exploitation: \
             CISA's Known Exploited Vulnerabilities catalog, else its SSVC assessment.*",
        ));
        join(parts)
    }

    /// One record's row of the CVE table (`_cve_row`).
    fn cve_row(record: &cve::CveRecord, id: &str, link: &dyn Fn(&str) -> String) -> [String; 6] {
        let ident = if record.identifier.is_empty() {
            id
        } else {
            record.identifier.as_str()
        };
        let mut label = if record.page_url.is_empty() {
            link(ident)
        } else {
            Flavor::link(ident, &record.page_url)
        };
        let aliases: Vec<String> = record
            .aliases
            .iter()
            .filter(|alias| alias.as_str() != ident)
            .map(|alias| link(alias))
            .collect();
        if !aliases.is_empty() {
            label = format!("{label}<br>{}", aliases.join(", "));
        }
        let severity = match &record.cvss {
            Some(cvss) => format!(
                "{}<br>CVSS {}",
                format!("**{:.1}** {}", cvss.score, cvss.severity).trim(),
                cvss.version
            ),
            None => table_cell(
                record
                    .severity
                    .as_deref()
                    .or(record.state.as_deref())
                    .unwrap_or("-"),
            ),
        };
        let likelihood = match &record.epss {
            cve::EpssDetail::Score(epss) => format!(
                "{}<br>top {}",
                cve::share(epss.probability),
                cve::share(1.0 - epss.percentile)
            ),
            _ => "-".to_owned(),
        };
        let weakness = join_lines(record.weaknesses.iter().map(|weakness| {
            let url = weakness.url();
            let mut cell = if url.is_empty() {
                weakness.identifier.clone()
            } else {
                Flavor::link(&weakness.identifier, &url)
            };
            if !weakness.name.is_empty() {
                cell = format!("{cell} {}", table_cell(&weakness.name));
            }
            cell
        }));
        [
            label,
            severity,
            likelihood,
            cve::exploitation(record),
            if weakness.is_empty() {
                "-".to_owned()
            } else {
                weakness
            },
            record.published.clone().unwrap_or_else(|| "-".to_owned()),
        ]
    }

    // ---- indexes -------------------------------------------------------

    /// A table as an index page writes it: Markdown, or on GitLab a sortable,
    /// filterable `json:table` (`index_table`).
    fn index_table(&self, headers: &[&str], rows: &[Vec<String>]) -> String {
        if self.flavor() != Flavor::Gitlab {
            return table(headers, rows);
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
        format!("```json:table\n{}\n```\n", payload.to_compact())
    }

    /// The index page of a folder (`render_index`): an introduction, then a
    /// table of its objects. The rules index opens with rules per platform
    /// and status; the threats index groups its table by kill-chain phase,
    /// in kill-chain order.
    ///
    /// # Errors
    ///
    /// A relation walk failed: `(uuid, cause)`.
    pub fn folder_index(&self, scope: Scope, title: &str) -> Result<String, (String, String)> {
        let records = self.catalog.records(scope);
        let mut headers = vec!["Name"];
        headers.extend_from_slice(match scope {
            Scope::Rules => &["Severity", "Platforms and status", "ATT&CK"],
            Scope::Objectives => &["Priority", "Signals", "Threats"],
            Scope::Threats => &["Criticality", "Kill chain", "ATT&CK"],
        });
        headers.push("UUID");
        if self.settings.relation_counts {
            headers.push("Related");
        }
        let mut rows = Vec::with_capacity(records.len());
        for record in records {
            rows.push(self.index_row(record)?);
        }
        let (noun, plural_noun, introduction) = match scope {
            Scope::Rules => (
                "rule",
                "rules",
                "Detection rules: the queries opentide deploys, with the status each platform \
                 block carries.",
            ),
            Scope::Objectives => (
                "objective",
                "objectives",
                "Detection objectives: what to detect about a threat, broken into signals that \
                 rules implement.",
            ),
            Scope::Threats => (
                "threat vector",
                "threat vectors",
                "Threat vectors: adversary behaviours, assessed and chained, with the detection \
                 coverage they have.",
            ),
        };
        let count = super::text::plural_as(records.len(), noun, plural_noun);
        let mut page = Page::new(self.flavor(), title, false, self.index_breadcrumb());
        page.add_lead([paragraph(&format!("{introduction} {count}."))]);
        let mut sections = Vec::new();
        let mut lead_table = String::new();
        match scope {
            Scope::Rules => {
                let matrix = self.status_matrix(records);
                if matrix.is_empty() {
                    lead_table = self.index_table(&headers, &rows);
                } else {
                    sections.push(Section::new("Status by platform", [matrix]));
                    sections.push(Section::new(
                        "All rules",
                        [self.index_table(&headers, &rows)],
                    ));
                }
            }
            Scope::Threats
                if records
                    .iter()
                    .any(|record| !record_phases(record).is_empty()) =>
            {
                sections = self.threats_by_phase(records, &headers, &rows);
            }
            _ => lead_table = self.index_table(&headers, &rows),
        }
        page.add_lead([lead_table]);
        for section in sections {
            page.add(Section {
                in_contents: false,
                ..section
            });
        }
        Ok(page.render())
    }

    /// The way back to the catalogue; Azure DevOps names every index
    /// `README` alike.
    fn index_breadcrumb(&self) -> String {
        if self.flavor() == Flavor::AzureDevops {
            return String::new();
        }
        paragraph(&self.flavor().render_link(
            "Catalogue",
            "../README.md",
            self.flavor() == Flavor::Gitlab,
        ))
    }

    fn index_row(&self, record: &Record) -> Result<Vec<String>, (String, String)> {
        let filename = self.filename(record);
        let href = Self::href(
            record.scope.folder(),
            record.scope.folder(),
            &filename,
            None,
        );
        let mut name = record.name.clone();
        if self.settings.icons {
            format!("{} {}", icon(record.scope), record.name)
                .trim()
                .clone_into(&mut name);
        }
        let mut row = vec![self.flavor().render_link(&name, &href, self.wiki())];
        match &record.model {
            Model::Rule(rule) => {
                let (severity, techniques) = match rule {
                    RuleModel::V1_0(rule) => (rule.displayed_severity(), &rule.techniques),
                    RuleModel::V1_1(rule) => (rule.displayed_severity(), &rule.techniques),
                };
                row.push(
                    severity
                        .filter(|severity| !severity.is_empty())
                        .map_or_else(|| "-".to_owned(), table_cell),
                );
                row.push(self.rule_platforms(&record.uuid));
                row.push(codes(techniques));
            }
            Model::Objective(objective) => {
                let body = &objective.objective;
                row.push(if body.priority.is_empty() {
                    "-".to_owned()
                } else {
                    table_cell(&body.priority)
                });
                row.push(body.signals.len().to_string());
                row.push(body.threats.as_ref().map_or(0, Vec::len).to_string());
            }
            Model::Threat(threat) => {
                row.push(self.vocab.enrich("criticality", &threat.criticality).label);
                let phases = killchain_phases(threat.threat.killchain.as_ref());
                row.push(if phases.is_empty() {
                    "-".to_owned()
                } else {
                    phases.join(", ")
                });
                row.push(codes(&threat.threat.mitre_attack));
            }
        }
        row.push(inline_code(&record.uuid));
        if self.settings.relation_counts {
            let count = self
                .catalog
                .relation_count(&record.uuid, self.settings.direction)
                .map_err(|cause| (record.uuid.clone(), cause.to_string()))?;
            row.push(count.to_string());
        }
        Ok(row)
    }

    /// Rules per platform and status: what each platform runs and at which
    /// maturity. Statuses in `deployment.toml` order, the others after.
    fn status_matrix(&self, records: &[Record]) -> String {
        let mut counts: Vec<(&'static str, Vec<(String, usize)>)> = Vec::new();
        for record in records {
            for (platform, status) in self.rule_statuses(&record.uuid) {
                let per = match counts.iter_mut().position(|(known, _)| *known == platform) {
                    Some(at) => &mut counts[at].1,
                    None => {
                        counts.push((platform, Vec::new()));
                        let last = counts.len() - 1;
                        &mut counts[last].1
                    }
                };
                match per.iter_mut().find(|(known, _)| *known == status) {
                    Some((_, count)) => *count += 1,
                    None => per.push((status, 1)),
                }
            }
        }
        if counts.is_empty() {
            return String::new();
        }
        let mut seen: Vec<String> = counts
            .iter()
            .flat_map(|(_, per)| per.iter().map(|(status, _)| status.clone()))
            .collect();
        seen.sort();
        seen.dedup();
        let mut columns: Vec<String> = self
            .deployment
            .statuses
            .iter()
            .map(|status| status.name.clone())
            .filter(|name| seen.contains(name))
            .collect();
        columns.dedup();
        for status in seen {
            if !columns.contains(&status) {
                columns.push(status);
            }
        }
        counts.sort_by_key(|(platform, _)| platform_label(platform));
        let rows: Vec<Vec<String>> = counts
            .iter()
            .map(|(platform, per)| {
                let mut row = vec![platform_label(platform)];
                for status in &columns {
                    let count = per
                        .iter()
                        .find(|(known, _)| known == status)
                        .map_or(0, |(_, count)| *count);
                    row.push(if count == 0 {
                        "-".to_owned()
                    } else {
                        count.to_string()
                    });
                }
                row.push(
                    per.iter()
                        .map(|(_, count)| count)
                        .sum::<usize>()
                        .to_string(),
                );
                row
            })
            .collect();
        let mut headers = vec!["Platform".to_owned()];
        headers.extend(columns.iter().map(|status| inline_code(status)));
        headers.push("Total".to_owned());
        table(&headers, &rows)
    }

    /// Threats under their first kill-chain phase, the phases in kill-chain
    /// order under their stage, the threats with none last.
    fn threats_by_phase(
        &self,
        records: &[Record],
        headers: &[&str],
        rows: &[Vec<String>],
    ) -> Vec<Section> {
        let order = self.vocab.order("killchain");
        let mut groups: Vec<(String, Vec<Vec<String>>)> = Vec::new();
        for (record, row) in records.iter().zip(rows) {
            let phase = record_phases(record).into_iter().next().unwrap_or_default();
            match groups.iter_mut().find(|(known, _)| *known == phase) {
                Some((_, members)) => members.push(row.clone()),
                None => groups.push((phase, vec![row.clone()])),
            }
        }
        groups.sort_by_key(|(phase, _)| {
            (
                phase.is_empty(),
                order
                    .iter()
                    .position(|known| known == phase)
                    .unwrap_or(order.len()),
                phase.clone(),
            )
        });
        let mut sections: Vec<Section> = Vec::new();
        let mut stage = String::new();
        for (phase, members) in groups {
            let phase_stage = if phase.is_empty() {
                String::new()
            } else {
                self.vocab.killchain_stage(&phase)
            };
            let table = self.index_table(headers, &members);
            let title = if phase.is_empty() {
                "No kill-chain phase".to_owned()
            } else {
                phase
            };
            if phase_stage.is_empty() {
                sections.push(Section::new(&title, [table]));
                continue;
            }
            if phase_stage != stage {
                sections.push(Section::new(&phase_stage, [""]));
                stage.clone_from(&phase_stage);
            }
            if let Some(parent) = sections.last_mut() {
                parent.children.push(Section::new(&title, [table]));
            }
        }
        sections
    }

    /// The root README, the catalogue overview (`render_root_index`): the
    /// folders, the threat landscape, the platform blocks by status, and the
    /// coverage, by kill-chain phase and by ATT&CK tactic.
    ///
    /// # Errors
    ///
    /// None yet: the result keeps room for a failing section.
    pub fn root_index(&self) -> Result<String, String> {
        let summaries = [
            (
                Scope::Rules,
                "Deployable queries, where they run and at which status",
            ),
            (
                Scope::Objectives,
                "What to detect about a threat, as signals rules implement",
            ),
            (
                Scope::Threats,
                "Adversary behaviours, assessed, chained and covered",
            ),
        ];
        let mut rows = Vec::new();
        for ((scope, title), (_, summary)) in FOLDER_TITLES.iter().zip(summaries) {
            let label = if self.settings.icons {
                format!("{} {title}", icon(*scope))
            } else {
                (*title).to_owned()
            };
            let mut row = vec![self.flavor().render_link(
                &label,
                &format!("{}/README.md", scope.folder()),
                false,
            )];
            if self.settings.relation_counts {
                row.push(self.catalog.records(*scope).len().to_string());
            }
            row.push(summary.to_owned());
            rows.push(row);
        }
        let mut headers = vec!["Section"];
        if self.settings.relation_counts {
            headers.push("Objects");
        }
        headers.push("Holds");
        let mut page = Page::new(self.flavor(), "Detection catalogue", false, String::new());
        page.add_lead([
            paragraph(&format!(
                "{}, {} and {}, documented by opentide from the catalogue's YAML.",
                plural(self.catalog.threats.len(), "threat vector"),
                plural(self.catalog.objectives.len(), "detection objective"),
                plural(self.catalog.rules.len(), "detection rule"),
            )),
            self.index_table(&headers, &rows),
        ]);
        page.add(Section::new("Threat landscape", [self.landscape()]));
        page.add(Section::new(
            "Deployment status",
            [self.status_pie(), self.status_matrix(&self.catalog.rules)],
        ));
        page.add(
            Section::new("Coverage", [self.coverage_summary()]).with_children(vec![
                Section::new("Kill-chain coverage", [self.killchain_coverage()]),
                Section::new("ATT&CK coverage", [self.attack_coverage()]),
            ]),
        );
        Ok(page.render())
    }

    /// The threat vectors at least one objective names.
    fn addressed(&self) -> HashSet<String> {
        self.catalog
            .objectives
            .iter()
            .filter_map(|record| match &record.model {
                Model::Objective(objective) => objective.objective.threats.as_ref(),
                _ => None,
            })
            .flatten()
            .cloned()
            .collect()
    }

    fn landscape(&self) -> String {
        let threats: Vec<diagrams::LandscapeThreat<'_>> = self
            .catalog
            .threats
            .iter()
            .filter_map(|record| {
                let Model::Threat(threat) = &record.model else {
                    return None;
                };
                let phase = match &threat.threat.killchain {
                    Some(opentide_schema::objects::Killchain::One(phase)) => phase.as_str(),
                    Some(opentide_schema::objects::Killchain::Many(phases)) => {
                        phases.first().map_or("", String::as_str)
                    }
                    None => "",
                };
                let chaining = threat
                    .threat
                    .chaining
                    .iter()
                    .flatten()
                    .filter_map(|entry| {
                        let target = super::catalog::chain_target(entry)?;
                        let relation = entry
                            .get("relation")
                            .map(|text| text.trim().to_owned())
                            .unwrap_or_default();
                        Some((target, relation))
                    })
                    .collect();
                Some(diagrams::LandscapeThreat {
                    uuid: &threat.metadata.uuid,
                    name: &threat.name,
                    phase,
                    chaining,
                })
            })
            .collect();
        diagrams::fenced(
            self.flavor(),
            diagrams::landscape(&self.vocab, &threats, &self.addressed()).as_ref(),
        )
    }

    /// Platform blocks by status, as a Mermaid pie chart: the slices
    /// largest first, each coloured by its status's strategy.
    fn status_pie(&self) -> String {
        let mut counts: Vec<(String, usize)> = Vec::new();
        for record in &self.catalog.rules {
            for (_, status) in self.rule_statuses(&record.uuid) {
                match counts.iter_mut().find(|(known, _)| *known == status) {
                    Some((_, count)) => *count += 1,
                    None => counts.push((status, 1)),
                }
            }
        }
        if counts.is_empty() {
            return String::new();
        }
        let count_of = |name: &str| {
            counts
                .iter()
                .find(|(known, _)| known == name)
                .map_or(0, |(_, count)| *count)
        };
        let definitions = &self.deployment.statuses;
        let mut ordered: Vec<String> = Vec::new();
        for definition in definitions {
            if count_of(&definition.name) > 0 && !ordered.contains(&definition.name) {
                ordered.push(definition.name.clone());
            }
        }
        let mut rest: Vec<String> = counts
            .iter()
            .map(|(name, _)| name.clone())
            .filter(|name| !ordered.contains(name))
            .collect();
        rest.sort();
        ordered.extend(rest);
        // Mermaid draws slices largest first, in a stable order, and colours
        // them pie1, pie2… in that order: sort the same way.
        ordered.sort_by_key(|name| std::cmp::Reverse(count_of(name)));
        let colours = status_colours(definitions);
        let mut theme = crate::json::Object::new();
        for (index, name) in ordered.iter().enumerate() {
            let colour = colours
                .iter()
                .find(|(known, _)| known == name)
                .map_or(UNKNOWN_COLOUR, |(_, colour)| *colour);
            theme.insert(format!("pie{}", index + 1), Json::from(colour));
        }
        theme.insert("pieStrokeColor".into(), Json::from("#ffffff"));
        theme.insert("pieOuterStrokeWidth".into(), Json::from("0px"));
        let mut pie = crate::json::Object::new();
        pie.insert("useWidth".into(), Json::Int(640));
        let mut init = crate::json::Object::new();
        init.insert("themeVariables".into(), Json::Object(theme));
        init.insert("pie".into(), Json::Object(pie));
        let mut lines = vec![
            format!("%%{{init: {}}}%%", Json::Object(init).to_compact()),
            "pie showData title Platform blocks by status".to_owned(),
        ];
        for name in &ordered {
            lines.push(format!(
                "    \"{}\" : {}",
                name.replace('"', "'"),
                count_of(name)
            ));
        }
        self.flavor().mermaid_fence(&lines.join("\n"))
    }

    /// How much of the catalogue is detected, from the objects' own links.
    fn coverage_summary(&self) -> String {
        let rules = &self.catalog.rules;
        let objectives = &self.catalog.objectives;
        let threats = &self.catalog.threats;
        if rules.is_empty() && objectives.is_empty() && threats.is_empty() {
            return String::new();
        }
        let implemented: HashSet<&str> = rules
            .iter()
            .filter_map(|record| super::catalog::rule_detection_model(&record.model))
            .filter(|model| !model.is_empty())
            .collect();
        let addressed = self.addressed();
        let objective_models: Vec<&opentide_schema::objects::ObjectiveV1_0> = objectives
            .iter()
            .filter_map(|record| match &record.model {
                Model::Objective(objective) => Some(objective.as_ref()),
                _ => None,
            })
            .collect();
        let signals: Vec<&str> = objective_models
            .iter()
            .flat_map(|objective| objective.objective.signals.iter())
            .map(|signal| signal.uuid.as_str())
            .collect();
        let objectives_done = objective_models
            .iter()
            .filter(|objective| {
                implemented.contains(objective.metadata.uuid.as_str())
                    || objective
                        .objective
                        .signals
                        .iter()
                        .any(|signal| implemented.contains(signal.uuid.as_str()))
            })
            .count();
        let mut techniques: Vec<&String> = rules
            .iter()
            .flat_map(|record| rule_techniques(&record.model))
            .collect();
        techniques.sort();
        techniques.dedup();
        let ratio = |done: usize, total: usize| {
            if total == 0 {
                format!("{done} of {total}")
            } else {
                format!("{done} of {total} ({}%)", percent(done, total))
            }
        };
        let rows = [
            [
                "Threat vectors addressed by an objective".to_owned(),
                ratio(
                    threats
                        .iter()
                        .filter(|record| addressed.contains(&record.uuid))
                        .count(),
                    threats.len(),
                ),
            ],
            [
                "Objectives implemented by a rule".to_owned(),
                ratio(objectives_done, objective_models.len()),
            ],
            [
                "Signals implemented by a rule".to_owned(),
                ratio(
                    signals
                        .iter()
                        .filter(|signal| implemented.contains(**signal))
                        .count(),
                    signals.len(),
                ),
            ],
            [
                "ATT&CK techniques detected by rules".to_owned(),
                techniques.len().to_string(),
            ],
        ];
        table(&["Measure", "Value"], &rows)
    }

    /// Per kill-chain phase: its threat vectors, and how many an objective
    /// addresses; a threat counts in every phase it lists.
    fn killchain_coverage(&self) -> String {
        let addressed = self.addressed();
        let mut flags: Vec<(String, Vec<bool>)> = Vec::new();
        let mut unphased: Vec<bool> = Vec::new();
        for record in &self.catalog.threats {
            let phases = record_phases(record);
            let done = addressed.contains(&record.uuid);
            if phases.is_empty() {
                unphased.push(done);
            }
            for phase in phases {
                match flags.iter_mut().find(|(known, _)| *known == phase) {
                    Some((_, group)) => group.push(done),
                    None => flags.push((phase, vec![done])),
                }
            }
        }
        if !unphased.is_empty() {
            flags.push((String::new(), unphased));
        }
        let order = self.vocab.order("killchain");
        flags.sort_by_key(|(phase, _)| {
            (
                phase.is_empty(),
                order
                    .iter()
                    .position(|known| known == phase)
                    .unwrap_or(order.len()),
                phase.clone(),
            )
        });
        if flags.is_empty() {
            return String::new();
        }
        let rows: Vec<[String; 5]> = flags
            .iter()
            .map(|(phase, group)| {
                let done = group.iter().filter(|flag| **flag).count();
                let stage = if phase.is_empty() {
                    String::new()
                } else {
                    self.vocab.killchain_stage(phase)
                };
                [
                    if phase.is_empty() {
                        "*No phase*".to_owned()
                    } else {
                        phase.clone()
                    },
                    if stage.is_empty() {
                        "-".to_owned()
                    } else {
                        stage
                    },
                    group.len().to_string(),
                    done.to_string(),
                    format!("{}%", percent(done, group.len())),
                ]
            })
            .collect();
        let table = table(
            &[
                "Kill-chain phase",
                "Stage",
                "Threat vectors",
                "Addressed by an objective",
                "Coverage",
            ],
            &rows,
        );
        join([
            diagrams::fenced(
                self.flavor(),
                diagrams::killchain_coverage(&self.vocab, &flags).as_ref(),
            ),
            table,
        ])
    }

    /// Per ATT&CK tactic, in matrix order: the techniques threat vectors
    /// use, and how many rules detect, a sub-technique counting for its
    /// parent.
    fn attack_coverage(&self) -> String {
        let mut used: Vec<&String> = Vec::new();
        for record in &self.catalog.threats {
            if let Model::Threat(threat) = &record.model {
                for technique in &threat.threat.mitre_attack {
                    if !used.contains(&technique) {
                        used.push(technique);
                    }
                }
            }
        }
        let detected: Vec<&String> = self
            .catalog
            .rules
            .iter()
            .flat_map(|record| rule_techniques(&record.model))
            .collect();
        let order = self.vocab.attack_tactics();
        let mut by_tactic: Vec<(String, Vec<&String>)> = Vec::new();
        for technique in used {
            let mut tactics = self.vocab.technique_tactics(technique, &order);
            if tactics.is_empty() {
                tactics.push("Unmapped".to_owned());
            }
            for tactic in tactics {
                match by_tactic.iter_mut().find(|(known, _)| *known == tactic) {
                    Some((_, list)) => list.push(technique),
                    None => by_tactic.push((tactic, vec![technique])),
                }
            }
        }
        if by_tactic.is_empty() {
            return String::new();
        }
        by_tactic.sort_by_key(|(tactic, _)| {
            (
                order
                    .iter()
                    .position(|known| known == tactic)
                    .unwrap_or(order.len()),
                tactic.clone(),
            )
        });
        let rows: Vec<[String; 5]> = by_tactic
            .iter_mut()
            .map(|(tactic, techniques)| {
                techniques.sort();
                let gaps: Vec<String> = techniques
                    .iter()
                    .filter(|technique| {
                        !detected
                            .iter()
                            .any(|found| covers_technique(found, technique))
                    })
                    .map(|technique| inline_code(technique))
                    .collect();
                let done = techniques.len() - gaps.len();
                [
                    tactic.clone(),
                    techniques.len().to_string(),
                    done.to_string(),
                    format!("{}%", percent(done, techniques.len())),
                    if gaps.is_empty() {
                        "-".to_owned()
                    } else {
                        gaps.join(", ")
                    },
                ]
            })
            .collect();
        table(
            &[
                "Tactic",
                "Techniques in threat vectors",
                "Detected by a rule",
                "Coverage",
                "Not detected",
            ],
            &rows,
        )
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

/// The folder indexes' titles.
pub const FOLDER_TITLES: [(Scope, &str); 3] = [
    (Scope::Rules, "Detection rules"),
    (Scope::Objectives, "Detection objectives"),
    (Scope::Threats, "Threat vectors"),
];

/// The colour of a status no strategy colours.
const UNKNOWN_COLOUR: &str = "#475467";

/// A colour per configured status: its strategy's hue, lightest first,
/// deeper later in the lifecycle (grey never deploys, amber is preview,
/// blue both runs, green release, red retiring).
fn status_colours(definitions: &[super::facts::StatusDefinition]) -> Vec<(String, &'static str)> {
    let palettes: [(StatusStrategy, &[&str]); 6] = [
        (StatusStrategy::Inert, &["#d0d5dd", "#98a2b3", "#667085"]),
        (
            StatusStrategy::Preview,
            &["#fedf89", "#fec84b", "#fdb022", "#f79009"],
        ),
        (StatusStrategy::Universal, &["#84caff", "#2e90fa"]),
        (StatusStrategy::Release, &["#6ce9a6", "#12b76a", "#039855"]),
        (StatusStrategy::Disablement, &["#fda29b", "#f97066"]),
        (StatusStrategy::Deletion, &["#d92d20", "#b42318"]),
    ];
    let mut colours: Vec<(String, &'static str)> = Vec::new();
    for (strategy, palette) in palettes {
        let names: Vec<&String> = definitions
            .iter()
            .filter(|definition| definition.strategy == strategy)
            .map(|definition| &definition.name)
            .collect();
        let offset = palette.len().saturating_sub(names.len());
        for (index, name) in names.into_iter().enumerate() {
            let colour = palette[(offset + index).min(palette.len() - 1)];
            match colours.iter_mut().find(|(known, _)| known == name) {
                Some((_, existing)) => *existing = colour,
                None => colours.push((name.clone(), colour)),
            }
        }
    }
    colours
}

/// `done` of `total` as a whole percentage, rounded half to even as
/// Python's `round` rounds it.
fn percent(done: usize, total: usize) -> String {
    if total == 0 {
        return "0".to_owned();
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "catalogue counts are far below 2^52"
    )]
    let share = 100.0 * done as f64 / total as f64;
    format!("{}", share.round_ties_even())
}

fn icon(scope: Scope) -> &'static str {
    match scope {
        Scope::Rules => ":shield:",
        Scope::Objectives => ":dart:",
        Scope::Threats => ":warning:",
    }
}

/// Author text as written: its own paragraphs, lists and emphasis.
fn prose(text: &str) -> String {
    if text.trim().is_empty() {
        String::new()
    } else {
        paragraph(text)
    }
}

/// A URL as a link, anything else as text.
fn reference_value(value: &str) -> String {
    if value.starts_with("http://") || value.starts_with("https://") {
        Flavor::link(value, value)
    } else {
        table_cell(value)
    }
}

/// An entry's label (or `label`), linked when it has a web link.
fn entry_link(entry: &Enriched, fallback: &str, label: Option<&str>) -> String {
    let text = label.map_or_else(
        || {
            table_cell(if entry.label.is_empty() {
                fallback
            } else {
                &entry.label
            })
        },
        str::to_owned,
    );
    if entry.link.starts_with("http://") || entry.link.starts_with("https://") {
        Flavor::link(&text, &entry.link)
    } else {
        text
    }
}

/// `values` each once, in order.
fn unique(values: &[String]) -> Vec<&String> {
    let mut out: Vec<&String> = Vec::new();
    for value in values {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

/// Whether detecting `detected` detects `wanted`: the same technique, or
/// one of its sub-techniques.
fn covers_technique(detected: &str, wanted: &str) -> bool {
    detected == wanted
        || detected
            .strip_prefix(wanted)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// A rule's techniques.
fn rule_techniques(model: &Model) -> &[String] {
    match model {
        Model::Rule(RuleModel::V1_0(rule)) => &rule.techniques,
        Model::Rule(RuleModel::V1_1(rule)) => &rule.techniques,
        _ => &[],
    }
}

/// Codes as code spans, comma-separated; `-` when there are none.
fn codes(values: &[String]) -> String {
    let text: Vec<String> = values
        .iter()
        .map(|value| inline_code(value))
        .filter(|value| !value.is_empty())
        .collect();
    if text.is_empty() {
        "-".to_owned()
    } else {
        text.join(", ")
    }
}

fn or_dash(text: String, empty: &str) -> String {
    if text.is_empty() {
        empty.to_owned()
    } else {
        text
    }
}

/// A threat's kill-chain phases.
fn killchain_phases(killchain: Option<&opentide_schema::objects::Killchain>) -> Vec<String> {
    match killchain {
        Some(opentide_schema::objects::Killchain::One(stage)) => vec![stage.clone()],
        Some(opentide_schema::objects::Killchain::Many(stages)) => stages.clone(),
        None => Vec::new(),
    }
}

fn record_phases(record: &Record) -> Vec<String> {
    match &record.model {
        Model::Threat(threat) => killchain_phases(threat.threat.killchain.as_ref()),
        _ => Vec::new(),
    }
}

/// `(objectives, rules)` on a threat's coverage graph.
fn coverage_counts(graph: &Graph) -> (usize, usize) {
    let count = |kind: &str| {
        graph
            .nodes
            .iter()
            .filter(|node| node.object_type == kind)
            .count()
    };
    (count("objective"), count("rule"))
}

/// What a run does to a rule, by the strategy its status maps to.
fn run_verb(strategy: StatusStrategy) -> Option<&'static str> {
    match strategy {
        StatusStrategy::Disablement => Some("disable"),
        StatusStrategy::Deletion => Some("delete"),
        _ => None,
    }
}

/// `PREVIEW and RELEASE runs`, or why no run deploys the block.
fn runs_text(deployment: &PlatformDeployment) -> String {
    if deployment.platform_enabled == Some(false) {
        return "never deployed: platform not enabled".to_owned();
    }
    let Some(definition) = &deployment.definition else {
        return "unknown status".to_owned();
    };
    if deployment.runs.is_empty() {
        return "never deployed".to_owned();
    }
    let runs = run_names(&deployment.runs);
    match run_verb(definition.strategy) {
        Some(verb) => format!("{runs} runs, which {verb} it"),
        None => format!("{runs} runs"),
    }
}

fn run_names(runs: &[StatusStrategy]) -> String {
    runs.iter()
        .map(|run| run.name())
        .collect::<Vec<_>>()
        .join(" and ")
}

/// The tenants a block reaches, as the Deployment table names them.
fn tenants_text(deployment: &PlatformDeployment) -> String {
    match deployment.scope {
        TenantScope::Unknown => {
            return "every tenant that is not manual (not configured here)".to_owned();
        }
        TenantScope::None => return "no tenant configured".to_owned(),
        TenantScope::Listed | TenantScope::All => {}
    }
    let mut names: Vec<String> = deployment
        .reached()
        .map(|target| inline_code(&target.name))
        .collect();
    if deployment.scope == TenantScope::Listed && names.is_empty() {
        names = deployment
            .targets
            .iter()
            .map(|target| inline_code(&target.name))
            .collect();
    }
    if names.is_empty() {
        return "none".to_owned();
    }
    let prefix = if deployment.scope == TenantScope::Listed {
        "listed: "
    } else {
        ""
    };
    format!("{prefix}{}", names.join(", "))
}

/// Per platform: status, the runs that act on it and the tenants they
/// reach; each status's strategy; and what keeps a block from deploying.
fn deployment_body(flavor: Flavor, deployments: &[PlatformDeployment]) -> String {
    if deployments.is_empty() {
        return callout(
            flavor,
            Callout::Note,
            "This rule has no platform configuration: no run deploys it anywhere.",
        );
    }
    let intro = paragraph(
        "What `opentide deploy` does with this rule: each platform block's status, the runs that \
         act on it, and the tenants they reach.",
    );
    let rows: Vec<[String; 5]> = deployments
        .iter()
        .map(|deployment| {
            [
                deployment.label.clone(),
                inline_code(&deployment.status),
                runs_text(deployment),
                tenants_text(deployment),
                if deployment.enabled { "yes" } else { "no" }.to_owned(),
            ]
        })
        .collect();
    let mut parts = vec![
        intro,
        table(
            &[
                "Platform",
                "Status",
                "Deployed by",
                "Tenants",
                "Block enabled",
            ],
            &rows,
        ),
        status_reference(deployments),
    ];
    parts.extend(warnings(flavor, deployments));
    join(parts)
}

/// Each status the table uses: its strategy in `deployment.toml`, and what
/// it means.
fn status_reference(deployments: &[PlatformDeployment]) -> String {
    let mut seen: Vec<(&str, &super::facts::StatusDefinition)> = Vec::new();
    for deployment in deployments {
        if let Some(definition) = &deployment.definition
            && !seen.iter().any(|(status, _)| *status == deployment.status)
        {
            seen.push((&deployment.status, definition));
        }
    }
    seen.iter()
        .map(|(status, definition)| {
            let mut line = format!(
                "- {} (strategy {})",
                inline_code(status),
                inline_code(definition.strategy.name())
            );
            if !definition.description.is_empty() {
                line = format!("{line}: {}", super::text::collapse(&definition.description));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// What keeps a block from deploying: its platform is not enabled, its
/// status is not defined, the platform has no tenant, a listed tenant does
/// not exist.
fn warnings(flavor: Flavor, deployments: &[PlatformDeployment]) -> Vec<String> {
    let mut notes = Vec::new();
    for deployment in deployments {
        let label = &deployment.label;
        if deployment.platform_enabled == Some(false) {
            notes.push(format!(
                "{label} is not enabled in this workspace: no run deploys this block."
            ));
        }
        if deployment.definition.is_none() {
            notes.push(format!(
                "{label}: status {} is not defined in `deployment.toml`, so no run deploys this \
                 block.",
                inline_code(&deployment.status)
            ));
        }
        if deployment.scope == TenantScope::None && !deployment.runs.is_empty() {
            notes.push(format!(
                "{label} configures no tenant: a run that deploys this block fails until one is \
                 added to the platform file."
            ));
        } else if !deployment.unknown_tenants.is_empty() {
            let names: Vec<String> = deployment
                .unknown_tenants
                .iter()
                .map(|name| inline_code(name))
                .collect();
            notes.push(format!("{label} has no tenant named {}.", names.join(", ")));
        }
    }
    notes
        .iter()
        .map(|note| callout(flavor, Callout::Warning, note))
        .collect()
}

/// Every candidate tenant, the runs that reach it, and the remote id it
/// holds.
fn tenants_body(deployments: &[PlatformDeployment]) -> String {
    let mut rows: Vec<[String; 4]> = Vec::new();
    for deployment in deployments {
        for target in &deployment.targets {
            rows.push(tenant_row(deployment, target));
        }
        for (tenant, remote_id) in &deployment.orphaned_ids {
            rows.push([
                deployment.label.clone(),
                inline_code(tenant),
                "not targeted".to_owned(),
                inline_code(remote_id),
            ]);
        }
    }
    if rows.is_empty() {
        return String::new();
    }
    table(&["Platform", "Tenant", "Reached by", "Remote ID"], &rows)
}

fn tenant_row(deployment: &PlatformDeployment, target: &TenantTarget) -> [String; 4] {
    let reached = if !target.runs.is_empty() {
        target
            .runs
            .iter()
            .map(|run| format!("{} runs", run.name()))
            .collect::<Vec<_>>()
            .join(", ")
    } else if !deployment.runs.is_empty() && !target.accepts.is_empty() {
        format!(
            "no run: the tenant takes {} runs only",
            run_names(&target.accepts)
        )
    } else if !deployment.runs.is_empty() {
        "no run: the tenant takes none of the rule's runs".to_owned()
    } else if deployment.platform_enabled == Some(false) {
        "no run: the platform is not enabled".to_owned()
    } else {
        "no run: no run deploys this status".to_owned()
    };
    let mut name = inline_code(&target.name);
    if !target.description.is_empty() {
        name = format!("{name}<br>{}", table_cell(&target.description));
    }
    let remote = inline_code(&target.remote_id);
    [
        deployment.label.clone(),
        name,
        reached,
        if remote.is_empty() {
            "-".to_owned()
        } else {
            remote
        },
    ]
}

/// One platform block: a line on where it stands, then every setting it
/// holds.
fn platform_section(
    platform: &str,
    block: &Json,
    written: Option<&Json>,
    deployment: Option<&PlatformDeployment>,
) -> Section {
    let settings = flatten(platform, block, written, &DEPLOYMENT_KEYS);
    Section::new(
        &platform_label(platform),
        [block_summary(block, deployment), settings_body(&settings)],
    )
}

/// `Status `STAGING` · deployed by PREVIEW runs · tenants: … · schema …`.
fn block_summary(block: &Json, deployment: Option<&PlatformDeployment>) -> String {
    let text = |key: &str| match block.get(key) {
        Some(Json::Str(text)) => text.clone(),
        _ => String::new(),
    };
    let mut parts = vec![format!("Status {}", inline_code(&text("status")))];
    if let Some(deployment) = deployment {
        let runs = runs_text(deployment);
        parts.push(if deployment.runs.is_empty() {
            runs
        } else {
            format!("deployed by {runs}")
        });
        parts.push(format!("tenants: {}", tenants_text(deployment)));
    }
    let schema = text("schema");
    if !schema.is_empty() {
        parts.push(format!("schema {}", inline_code(&schema)));
    }
    if !matches!(block.get("enabled"), Some(Json::Bool(true))) {
        parts.push("block disabled".to_owned());
    }
    paragraph(&parts.join(" · "))
}

/// Code first (what the rule detects), then the settings table and the
/// tables of lists.
fn settings_body(settings: &BlockSettings) -> String {
    let mut parts: Vec<String> = Vec::new();
    for item in &settings.code {
        let language = item.language.unwrap_or(TEXT);
        let mut caption = format!("**{}** ({})", inline_code(&item.path), language.name);
        if !item.description.is_empty() && item.description.trim_end_matches('.') != language.name {
            caption = format!("{caption}: {}", item.description);
        }
        parts.push(caption);
        parts.push(code_block(language.fence, &item.code));
    }
    if !settings.rows.is_empty() {
        let rows: Vec<[String; 3]> = settings
            .rows
            .iter()
            .map(|row| {
                [
                    inline_code(&row.path),
                    if row.default {
                        format!("{} *(default)*", row.value)
                    } else {
                        row.value.clone()
                    },
                    if row.description.is_empty() {
                        String::new()
                    } else {
                        table_cell(&row.description)
                    },
                ]
            })
            .collect();
        parts.push(table(&["Setting", "Value", "Description"], &rows));
    }
    for item in &settings.tables {
        let mut caption = format!("**{}**", inline_code(&item.path));
        if !item.description.is_empty() {
            caption = format!("{caption}: {}", item.description);
        }
        parts.push(caption);
        let headers: Vec<String> = item
            .columns
            .iter()
            .map(|column| inline_code(column))
            .collect();
        parts.push(table(&headers, &item.rows));
    }
    if parts.is_empty() {
        return paragraph("The block sets nothing beyond its deployment status.");
    }
    join(parts)
}

/// A signal's existing detectors as a table.
fn detectors_body(detectors: &[opentide_schema::objects::ExternalDetector]) -> String {
    if detectors.is_empty() {
        return String::new();
    }
    let rows: Vec<[String; 4]> = detectors
        .iter()
        .map(|detector| {
            [
                table_cell(&detector.name),
                table_cell(&detector.technology),
                table_cell(&detector.description),
                detector
                    .link
                    .as_deref()
                    .filter(|link| !link.is_empty())
                    .map_or_else(|| "-".to_owned(), |link| Flavor::link("Reference", link)),
            ]
        })
        .collect();
    join([
        "**Existing detectors**".to_owned(),
        table(&["Detector", "Technology", "Description", "Link"], &rows),
    ])
}

/// A signal's examples, numbered, each query fenced.
fn examples_body(examples: &[opentide_schema::objects::DetectionExample]) -> String {
    if examples.is_empty() {
        return String::new();
    }
    let mut parts = vec!["**Examples**".to_owned()];
    for (index, example) in examples.iter().enumerate() {
        parts.push(format!(
            "{}. {} ({})",
            index + 1,
            super::text::collapse(&example.description),
            Flavor::link("source", &example.link)
        ));
        if let Some(query) = example.query.as_deref().filter(|query| !query.is_empty()) {
            let language = example
                .language
                .as_deref()
                .filter(|language| !language.is_empty())
                .unwrap_or("text");
            parts.push(code_block(language, query.trim_end_matches('\n')));
        }
    }
    join(parts)
}

#[cfg(test)]
mod tests;
