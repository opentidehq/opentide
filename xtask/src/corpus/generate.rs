//! The heavy workspace generator: a seed and three counts in, a workspace
//! the oracle validates with zero findings out (plan §5.3).
//!
//! Every draw comes from [`Rng`] streams forked per family, and nothing
//! reads the clock, the environment or the file system, so a seed and its
//! options always give the same bytes (`tests/corpus_generate.rs` records the
//! digest).

use super::rng::Rng;
use super::vocab::{
    self, ADJECTIVES, ALERT_SEVERITY, CHAINING, COMPOSITION, CRITICALITY, DETECTION_TYPES,
    ENTITIES, GROUPS, IMPACT, KILLCHAIN, LEVERAGE, METHODOLOGY, NOUNS, PRIORITY, PROCESSES,
    RESPONDERS, SEVERITY, SHELLS, STATUSES, SURFACE, TECHNIQUES, TLP, VIABILITY,
};
use super::workspace::{Body, Family, File, Workspace};
use super::yaml::Yaml;

/// The default counts (plan §5.3): 300 threats, 300 objectives, 500 rules.
pub const DEFAULT_COUNTS: Counts = Counts {
    threats: 300,
    objectives: 300,
    rules: 500,
};

/// How many objects of each family to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// Threat vectors.
    pub threats: usize,
    /// Detection objectives.
    pub objectives: usize,
    /// Detection rules.
    pub rules: usize,
}

impl Counts {
    /// The default counts multiplied by `factor`, each at least 1.
    pub fn scaled(factor: f64) -> Option<Self> {
        if !factor.is_finite() || factor <= 0.0 || factor > 1000.0 {
            return None;
        }
        let scale = |n: usize| -> usize {
            let n = u32::try_from(n).unwrap_or(u32::MAX);
            let scaled = (f64::from(n) * factor).round();
            // The bound above keeps the product far inside u32.
            let scaled = format!("{scaled:.0}").parse::<usize>().unwrap_or(1);
            scaled.max(1)
        };
        Some(Self {
            threats: scale(DEFAULT_COUNTS.threats),
            objectives: scale(DEFAULT_COUNTS.objectives),
            rules: scale(DEFAULT_COUNTS.rules),
        })
    }
}

/// Where the workspace keeps its objects: the `paths.toml` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// No `paths.toml`: the default folders (`objects/rules/`, ...).
    Standard,
    /// A `paths.toml` that restates the defaults.
    Explicit,
    /// A `paths.toml` that moves every object family and the docs.
    Custom,
}

impl Layout {
    /// Every variant, for the fault runner and tests.
    pub const ALL: [Self; 3] = [Self::Standard, Self::Explicit, Self::Custom];

    /// The option value: `standard`, `explicit`, `custom`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Explicit => "explicit",
            Self::Custom => "custom",
        }
    }

    /// The variant an option value names.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.name() == name)
    }

    /// The folder of each object family, relative to the root, with a
    /// trailing slash.
    pub fn folder(self, family: Family) -> &'static str {
        match (self, family) {
            (Self::Custom, Family::Threat) => "detection/threat-vectors/",
            (Self::Custom, Family::Objective) => "detection/objectives/",
            (Self::Custom, Family::Rule) => "detection/rules/",
            (_, Family::Threat) => "objects/threats/",
            (_, Family::Objective) => "objects/objectives/",
            (_, Family::Rule) => "objects/rules/",
            (_, Family::Config) => ".opentide/configurations/",
            (_, Family::Other) => "",
        }
    }
}

/// The generator's options.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Options {
    /// The seed every draw derives from.
    pub seed: u64,
    /// How many objects of each family.
    pub counts: Counts,
    /// The `paths.toml` variant.
    pub layout: Layout,
}

impl Options {
    /// The default counts and layout for `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            counts: DEFAULT_COUNTS,
            layout: Layout::Explicit,
        }
    }
}

/// The platforms with tenants in the generated configuration, and their
/// tenant names (each platform's configuration declares them).
pub const TENANTS: &[(&str, &[&str])] = &[
    ("sentinel", &["sentinel-staging", "sentinel-production"]),
    ("defender_for_endpoint", &["mde-production"]),
    ("splunk", &["splunk-es"]),
    ("elastic", &["elastic-staging", "elastic-production"]),
    ("sysdig", &["sysdig-production"]),
    ("exabeam", &["exabeam-production"]),
];

fn tenants_of(platform: &str) -> &'static [&'static str] {
    TENANTS
        .iter()
        .find(|(p, _)| *p == platform)
        .map_or(&[], |(_, t)| t)
}

/// What later objects refer to.
#[derive(Default)]
struct Ids {
    threats: Vec<String>,
    objectives: Vec<String>,
    signals: Vec<String>,
    organisation: String,
}

/// Generates the workspace `options` describe.
pub fn generate(options: &Options) -> Workspace {
    let root = Rng::new(options.seed);
    let mut ids = Ids {
        organisation: root.fork("organisation").uuid(),
        ..Ids::default()
    };
    let mut files = Vec::new();
    files.extend(configuration_files(options.layout));
    let mut threats = root.fork("threats");
    for index in 0..options.counts.threats {
        files.push(threat(&mut threats, index, options.layout, &mut ids));
    }
    let mut objectives = root.fork("objectives");
    for index in 0..options.counts.objectives {
        files.push(objective(&mut objectives, index, options.layout, &mut ids));
    }
    mark_referenced_threats(&mut files);
    let mut rules = root.fork("rules");
    for index in 0..options.counts.rules {
        files.push(rule(&mut rules, index, options.layout, &ids));
    }
    mark_referenced_objectives(&mut files);
    files.push(File {
        path: "README.md".to_string(),
        family: Family::Other,
        platforms: Vec::new(),
        tags: Vec::new(),
        body: Body::Text(format!(
            "# Generated corpus\n\nWritten by `cargo xtask corpus generate --seed {} \
             --threats {} --objectives {} --rules {} --layout {}`; \
             see tests/corpora/README.md. Every secret is a placeholder.\n",
            options.seed,
            options.counts.threats,
            options.counts.objectives,
            options.counts.rules,
            options.layout.name()
        )),
    });
    Workspace { files }
}

/// Tags every threat another object refers to (an objective's `threats`, a
/// threat's `chaining`) as `referenced`: a fault that breaks such a
/// threat's identity also breaks the references, which other kinds cover.
fn mark_referenced_threats(files: &mut [File]) {
    let mut referenced = std::collections::BTreeSet::new();
    for file in files.iter() {
        let Body::Yaml(doc) = &file.body else {
            continue;
        };
        for list in ["objective.threats", "threat.chaining"] {
            if let Some(Yaml::Seq(items)) = doc.at(list) {
                for item in items {
                    let id = item
                        .as_str()
                        .or_else(|| item.get("vector").and_then(Yaml::as_str));
                    if let Some(id) = id {
                        referenced.insert(id.to_string());
                    }
                }
            }
        }
    }
    for file in files.iter_mut() {
        if file.family == Family::Threat && file.uuid().is_some_and(|u| referenced.contains(u)) {
            file.tags.push("referenced".to_string());
        }
    }
}

/// Tags every objective a rule's `detection_model` names (itself or one of
/// its signals) as `referenced`.
fn mark_referenced_objectives(files: &mut [File]) {
    let models: std::collections::BTreeSet<String> = files
        .iter()
        .filter_map(|f| match &f.body {
            Body::Yaml(doc) if f.family == Family::Rule => doc
                .get("detection_model")
                .and_then(Yaml::as_str)
                .map(str::to_string),
            _ => None,
        })
        .collect();
    for file in files.iter_mut().filter(|f| f.family == Family::Objective) {
        let Body::Yaml(doc) = &file.body else {
            continue;
        };
        let mut ids: Vec<&str> = doc
            .at("metadata.uuid")
            .and_then(Yaml::as_str)
            .into_iter()
            .collect();
        if let Some(Yaml::Seq(signals)) = doc.at("objective.signals") {
            ids.extend(
                signals
                    .iter()
                    .filter_map(|s| s.get("uuid").and_then(Yaml::as_str)),
            );
        }
        if ids.iter().any(|id| models.contains(*id)) {
            file.tags.push("referenced".to_string());
        }
    }
}

/// `slugify` as opentide's lint applies it: runs of anything but ASCII
/// letters and digits become one `-`, trimmed, lowercased.
pub fn slugify(name: &str) -> String {
    let mut slug = String::new();
    let mut dash = false;
    for c in name.trim().chars() {
        if c.is_ascii_alphanumeric() {
            if dash && !slug.is_empty() {
                slug.push('-');
            }
            dash = false;
            slug.push(c.to_ascii_lowercase());
        } else {
            dash = true;
        }
    }
    if slug.is_empty() {
        "object".to_string()
    } else {
        slug
    }
}

fn object_name(rng: &mut Rng, kind: &str, index: usize) -> String {
    format!(
        "{} {} {kind} {:04}",
        rng.pick(ADJECTIVES),
        rng.pick(NOUNS),
        index + 1
    )
}

/// A date in 2025 or the first half of 2026, as `YYYY-MM-DD`; `day` counts
/// from 2025-01-01 (0..=545).
fn date(day: usize) -> String {
    const MONTHS: [usize; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut day = day.min(545);
    let mut year = 2025;
    let mut month = 0;
    loop {
        let length = MONTHS[month];
        if day < length {
            break;
        }
        day -= length;
        month += 1;
        if month == 12 {
            month = 0;
            year += 1;
        }
    }
    format!("{year}-{:02}-{:02}", month + 1, day + 1)
}

fn metadata(rng: &mut Rng, uuid: &str, schema: &str, ids: &Ids) -> (Yaml, usize) {
    let created = rng.range(0, 360);
    let modified = created + rng.range(0, 120);
    let mut pairs = vec![
        ("uuid", Yaml::s(uuid)),
        ("schema", Yaml::s(schema)),
        ("version", Yaml::raw(rng.range(1, 9))),
        ("created", Yaml::raw(date(created))),
        ("modified", Yaml::raw(date(modified))),
        ("tlp", Yaml::s(rng.pick(TLP))),
        ("author", Yaml::s("Corpus Generator")),
    ];
    if rng.chance(40) {
        pairs.push((
            "contributors",
            Yaml::strs(&["Detection Engineering", "Threat Intelligence"][..rng.range(1, 2)]),
        ));
    }
    pairs.push((
        "organisation",
        Yaml::map(vec![
            ("uuid", Yaml::s(ids.organisation.clone())),
            ("name", Yaml::s("Example Detection Team")),
        ]),
    ));
    (Yaml::map(pairs), modified)
}

fn references(rng: &mut Rng, slug: &str) -> Yaml {
    let mut pairs = vec![(
        "public",
        Yaml::map(vec![
            (
                "1",
                Yaml::s(format!("https://attack.mitre.org/techniques/{}/", "T1059")),
            ),
            ("2", Yaml::s(format!("https://example.org/research/{slug}"))),
        ]),
    )];
    if rng.chance(50) {
        pairs.push((
            "internal",
            Yaml::map(vec![(
                "wiki",
                Yaml::s(format!("https://wiki.example.internal/detections/{slug}")),
            )]),
        ));
    }
    if rng.chance(40) {
        pairs.push((
            "reports",
            Yaml::strs(&[format!("https://example.org/reports/{slug}.pdf")]),
        ));
    }
    Yaml::map(pairs)
}

fn file(layout: Layout, family: Family, name: &str) -> String {
    format!("{}{}.yaml", layout.folder(family), slugify(name))
}

fn threat(rng: &mut Rng, index: usize, layout: Layout, ids: &mut Ids) -> File {
    let uuid = rng.uuid();
    let name = object_name(rng, "Threat", index);
    let slug = slugify(&name);
    let (meta, _) = metadata(rng, &uuid, "threat::1.0", ids);
    let mut tags = Vec::new();
    let mut body = vec![
        (
            "description",
            Yaml::s(format!(
                "Generated threat vector {}.\nAn adversary uses {} to reach its objective.\n",
                index + 1,
                rng.pick(PROCESSES)
            )),
        ),
        ("severity", Yaml::s(rng.pick(SEVERITY))),
        (
            "impact",
            Yaml::strs(&{
                let n = rng.range(1, 3);
                rng.sample(IMPACT, n)
            }),
        ),
        ("leverage", Yaml::strs(&rng.sample(LEVERAGE, 2))),
        ("viability", Yaml::s(rng.pick(VIABILITY))),
        (
            "terrain",
            Yaml::s("Endpoint workstations and servers joined to the domain."),
        ),
        (
            "surface",
            Yaml::strs(&{
                let n = rng.range(1, 2);
                rng.sample(SURFACE, n)
            }),
        ),
        ("mitre_attack", Yaml::strs(&rng.sample(TECHNIQUES, 2))),
    ];
    if rng.chance(60) {
        tags.push("actors".to_string());
        let mut actors = vec![Yaml::map(vec![(
            "name",
            Yaml::s(format!("att&ck::{}", rng.pick(GROUPS))),
        )])];
        if rng.chance(50) {
            actors.push(Yaml::map(vec![
                ("name", Yaml::s(format!("att&ck::{}", rng.pick(GROUPS)))),
                ("sighting", Yaml::s("Observed in a 2025 intrusion.")),
                (
                    "references",
                    Yaml::strs(&["https://attack.mitre.org/groups/"]),
                ),
            ]));
        }
        body.push(("actors", Yaml::Seq(actors)));
    }
    if rng.chance(30) {
        body.push(("killchain", Yaml::s(rng.pick(KILLCHAIN))));
    }
    if !ids.threats.is_empty() && rng.chance(50) {
        tags.push("chaining".to_string());
        let mut chain = Vec::new();
        for _ in 0..rng.range(1, 2) {
            let target = ids.threats[rng.below(ids.threats.len())].clone();
            chain.push(Yaml::map(vec![
                ("vector", Yaml::s(target)),
                ("relation", Yaml::s(rng.pick(CHAINING))),
            ]));
        }
        body.push(("chaining", Yaml::Seq(chain)));
    }
    let mut doc = vec![
        ("name", Yaml::s(name.clone())),
        ("criticality", Yaml::s(rng.pick(CRITICALITY))),
        ("metadata", meta),
        ("threat", Yaml::map(body)),
    ];
    if rng.chance(70) {
        tags.push("references".to_string());
        doc.push(("references", references(rng, &slug)));
    }
    ids.threats.push(uuid);
    File {
        path: file(layout, Family::Threat, &name),
        family: Family::Threat,
        platforms: Vec::new(),
        tags,
        body: Body::Yaml(Yaml::map(doc)),
    }
}

fn signal(rng: &mut Rng, objective: usize, index: usize, parent: Option<&str>) -> (Yaml, String) {
    let uuid = rng.uuid();
    let mut pairs = vec![
        (
            "name",
            Yaml::s(format!(
                "Signal {} of objective {:04}",
                index + 1,
                objective + 1
            )),
        ),
        ("uuid", Yaml::s(uuid.clone())),
        (
            "description",
            Yaml::s(format!(
                "Execution of {} with an unusual parent.\n",
                rng.pick(PROCESSES)
            )),
        ),
        ("severity", Yaml::s(rng.pick(ALERT_SEVERITY))),
        (
            "data",
            Yaml::map(vec![
                ("availability", Yaml::s("Complete")),
                ("requirements", Yaml::s("Process creation events")),
            ]),
        ),
        ("methodology", Yaml::s(rng.pick(METHODOLOGY))),
        ("entities", Yaml::strs(&rng.sample(ENTITIES, 2))),
    ];
    if rng.chance(50) {
        pairs.push(("effort", Yaml::raw(rng.range(1, 10))));
    }
    if rng.chance(30) {
        pairs.push((
            "detectors",
            Yaml::Seq(vec![Yaml::map(vec![
                ("name", Yaml::s("Vendor analytic")),
                ("technology", Yaml::s("EDR")),
                ("description", Yaml::s("The vendor's built-in analytic.\n")),
                ("link", Yaml::s("https://example.org/detectors/edr")),
            ])]),
        ));
    }
    if rng.chance(30) {
        pairs.push((
            "examples",
            Yaml::Seq(vec![Yaml::map(vec![
                ("description", Yaml::s("A hunting query for the signal.\n")),
                ("link", Yaml::s("https://example.org/hunting/query")),
                ("language", Yaml::s("kql")),
                (
                    "query",
                    Yaml::s(format!(
                        "SecurityEvent\n| where EventID == {}\n",
                        4600 + rng.below(100)
                    )),
                ),
            ])]),
        ));
    }
    if let Some(parent) = parent {
        pairs.push(("parent", Yaml::s(parent)));
    }
    (Yaml::map(pairs), uuid)
}

fn objective(rng: &mut Rng, index: usize, layout: Layout, ids: &mut Ids) -> File {
    let uuid = rng.uuid();
    let name = object_name(rng, "Objective", index);
    let slug = slugify(&name);
    let (meta, _) = metadata(rng, &uuid, "objective::1.0", ids);
    let mut tags = Vec::new();
    let mut signals = Vec::new();
    let mut signal_ids: Vec<String> = Vec::new();
    for position in 0..rng.range(1, 3) {
        let parent = if position > 0 && rng.chance(30) {
            tags.push("signal-parent".to_string());
            signal_ids.first().cloned()
        } else {
            None
        };
        let (node, id) = signal(rng, index, position, parent.as_deref());
        signals.push(node);
        signal_ids.push(id);
    }
    let mut body = vec![
        ("priority", Yaml::s(rng.pick(PRIORITY))),
        ("type", Yaml::s(rng.pick(DETECTION_TYPES))),
        (
            "description",
            Yaml::s(format!("Detect the activity of objective {}.\n", index + 1)),
        ),
        ("signals", Yaml::Seq(signals)),
        (
            "composition",
            Yaml::map(vec![
                ("strategy", Yaml::s(rng.pick(COMPOSITION))),
                (
                    "description",
                    Yaml::s("The signals are combined into one detection.\n"),
                ),
            ]),
        ),
    ];
    if !ids.threats.is_empty() {
        tags.push("threats".to_string());
        let mut threats: Vec<String> = Vec::new();
        for _ in 0..rng.range(1, 3) {
            let id = ids.threats[rng.below(ids.threats.len())].clone();
            if !threats.contains(&id) {
                threats.push(id);
            }
        }
        body.push(("threats", Yaml::strs(&threats)));
    }
    if rng.chance(50) {
        body.push(("mitre_attack", Yaml::strs(&rng.sample(TECHNIQUES, 2))));
    }
    let mut doc = vec![
        ("name", Yaml::s(name.clone())),
        ("metadata", meta),
        ("objective", Yaml::map(body)),
    ];
    if rng.chance(50) {
        tags.push("references".to_string());
        doc.push(("references", references(rng, &slug)));
    }
    ids.objectives.push(uuid);
    ids.signals.extend(signal_ids);
    File {
        path: file(layout, Family::Objective, &name),
        family: Family::Objective,
        platforms: Vec::new(),
        tags,
        body: Body::Yaml(Yaml::map(doc)),
    }
}

/// The platforms rule `index` configures: one primary in rotation, and a
/// second (and third) on some rules, so that every platform has many rules
/// even in a small workspace.
fn rule_platforms(rng: &mut Rng, index: usize) -> Vec<&'static str> {
    let all = vocab::generated_platforms();
    let primary = all[index % all.len()];
    let mut platforms = vec![primary];
    if index % 3 != 2 {
        let second = all[(index * 4 + 3) % all.len()];
        if second != primary {
            platforms.push(second);
        }
    }
    if rng.chance(15) {
        let third = all[rng.below(all.len())];
        if !platforms.contains(&third) {
            platforms.push(third);
        }
    }
    platforms
}

fn rule(rng: &mut Rng, index: usize, layout: Layout, ids: &Ids) -> File {
    let uuid = rng.uuid();
    let name = object_name(rng, "Rule", index);
    let slug = slugify(&name);
    let revision_1_1 = index % 2 == 1;
    let schema = if revision_1_1 {
        "rule::1.1"
    } else {
        "rule::1.0"
    };
    let (mut meta, modified) = metadata(rng, &uuid, schema, ids);
    let mut tags = vec![schema.to_string()];
    if revision_1_1 && rng.chance(70) {
        tags.push("reviewed".to_string());
        let reviewed = date(modified + rng.range(0, 30));
        if let Yaml::Map(pairs) = &mut meta {
            let at = pairs
                .iter()
                .position(|(k, _)| k == "tlp")
                .unwrap_or(pairs.len());
            pairs.insert(at, ("reviewed".to_string(), Yaml::raw(reviewed)));
        }
    }
    let platforms = rule_platforms(rng, index);
    let variant = index / vocab::generated_platforms().len();
    let mut configurations = Vec::new();
    for (position, platform) in platforms.iter().enumerate() {
        let (block, block_tags) = platform_block(rng, platform, variant + position, &name);
        tags.extend(block_tags);
        configurations.push((platform.to_string(), block));
    }
    let mut doc = vec![
        ("name", Yaml::s(name.clone())),
        ("metadata", meta),
        (
            "description",
            Yaml::s(format!(
                "Generated detection rule {}.\nIt looks for {} launched in an unusual way.\n",
                index + 1,
                rng.pick(PROCESSES)
            )),
        ),
    ];
    if rng.chance(50) {
        doc.push(("status", Yaml::s(rng.pick(STATUSES))));
    }
    if rng.chance(50) {
        doc.push(("severity", Yaml::s(rng.pick(ALERT_SEVERITY))));
    }
    let count = rng.range(1, 3);
    doc.push(("techniques", Yaml::strs(&rng.sample(TECHNIQUES, count))));
    if rng.chance(50) {
        tags.push("references".to_string());
        doc.push(("references", references(rng, &slug)));
    }
    // Every other rule implements a signal, the rest an objective.
    if index % 4 == 1 && !ids.signals.is_empty() {
        tags.push("model:signal".to_string());
        doc.push((
            "detection_model",
            Yaml::s(ids.signals[rng.below(ids.signals.len())].clone()),
        ));
    } else if index % 4 != 3 && !ids.objectives.is_empty() {
        tags.push("model:objective".to_string());
        doc.push((
            "detection_model",
            Yaml::s(ids.objectives[rng.below(ids.objectives.len())].clone()),
        ));
    }
    doc.push(("response", response(rng, &mut tags)));
    doc.push(("configurations", Yaml::Map(configurations)));
    File {
        path: file(layout, Family::Rule, &name),
        family: Family::Rule,
        platforms: platforms.iter().map(|p| (*p).to_string()).collect(),
        tags,
        body: Body::Yaml(Yaml::map(doc)),
    }
}

fn response(rng: &mut Rng, tags: &mut Vec<String>) -> Yaml {
    let mut pairs = vec![("alert_severity", Yaml::s(rng.pick(ALERT_SEVERITY)))];
    if rng.chance(50) {
        pairs.push((
            "playbook",
            Yaml::s("https://wiki.example.internal/playbooks/execution"),
        ));
    }
    if rng.chance(60) {
        tags.push("responders".to_string());
        pairs.push(("responders", Yaml::s(rng.pick(RESPONDERS))));
    }
    if rng.chance(60) {
        tags.push("hunt".to_string());
        let process = rng.pick(PROCESSES);
        pairs.push((
            "procedure",
            Yaml::map(vec![
                (
                    "analysis",
                    Yaml::s("Review the process tree and the account that ran it.\n"),
                ),
                (
                    "searches",
                    Yaml::Seq(vec![
                        Yaml::map(vec![
                            ("purpose", Yaml::s("Other executions on the host")),
                            ("system", Yaml::s("sentinel")),
                            (
                                "query",
                                Yaml::s(format!(
                                    "DeviceProcessEvents\n| where FileName =~ \"{process}\"\n"
                                )),
                            ),
                        ]),
                        Yaml::map(vec![
                            ("purpose", Yaml::s("Logons of the account")),
                            ("system", Yaml::s("splunk")),
                            (
                                "query",
                                Yaml::s("index=main sourcetype=\"WinEventLog:Security\" EventCode=4624\n"),
                            ),
                        ]),
                    ]),
                ),
                ("containment", Yaml::s("Isolate the host if the activity is confirmed.")),
            ]),
        ));
    }
    Yaml::map(pairs)
}

/// The fields every platform block starts with.
fn block_head(
    rng: &mut Rng,
    platform: &str,
    name: &str,
    tags: &mut Vec<String>,
) -> Vec<(String, Yaml)> {
    let mut pairs = vec![
        ("enabled".to_string(), Yaml::raw("true")),
        ("name".to_string(), Yaml::s(name)),
    ];
    if rng.chance(50) {
        pairs.push((
            "schema".to_string(),
            Yaml::s(format!("platform::{platform}::1.0")),
        ));
    }
    pairs.push(("status".to_string(), Yaml::s(rng.pick(STATUSES))));
    let tenants = tenants_of(platform);
    if !tenants.is_empty() && rng.chance(50) {
        tags.push(format!("{platform}:tenants"));
        pairs.push((
            "tenants".to_string(),
            Yaml::strs(&tenants[..rng.range(1, tenants.len())]),
        ));
    }
    if rng.chance(20) {
        pairs.push((
            "contributors".to_string(),
            Yaml::strs(&["Detection Engineering"]),
        ));
    }
    pairs
}

fn kv(pairs: Vec<(&str, Yaml)>) -> Vec<(String, Yaml)> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

/// One platform's block of a rule, and the tags it adds.
fn platform_block(
    rng: &mut Rng,
    platform: &str,
    variant: usize,
    name: &str,
) -> (Yaml, Vec<String>) {
    let mut tags = vec![format!("platform:{platform}")];
    let mut pairs = block_head(rng, platform, name, &mut tags);
    let process = rng.pick(PROCESSES);
    let number = 4600 + rng.below(100);
    match platform {
        "sentinel" => pairs.extend(sentinel(rng, variant, process, number, name, &mut tags)),
        "defender_for_endpoint" => pairs.extend(defender(rng, variant, process, &mut tags)),
        "splunk" => pairs.extend(splunk(rng, variant, number, name, &mut tags)),
        "sentinel_one" => pairs.extend(sentinel_one(rng, variant, process, name, &mut tags)),
        "carbon_black_cloud" => pairs.extend(kv(vec![(
            "query",
            Yaml::s(format!(
                "process_name:{process} AND process_cmdline:*encoded*"
            )),
        )])),
        "crowdstrike" => pairs.extend(crowdstrike(rng, process, name)),
        "harfanglab" => pairs.extend(harfanglab(rng, variant, process, name, &mut tags)),
        "elastic" => pairs.extend(elastic(rng, variant, process, &mut tags)),
        "sysdig" => pairs.extend(sysdig(rng, variant, &mut tags)),
        "exabeam" => pairs.extend(exabeam(rng, variant, process, &mut tags)),
        _ => {}
    }
    (Yaml::Map(pairs), tags)
}

fn sentinel(
    rng: &mut Rng,
    variant: usize,
    process: &str,
    number: usize,
    name: &str,
    tags: &mut Vec<String>,
) -> Vec<(String, Yaml)> {
    let query = match variant % 3 {
        0 => format!(
            "SecurityEvent\n| where EventID == {number}\n| project TimeGenerated, Computer, Account, EventID\n"
        ),
        1 => format!(
            "SigninLogs\n| where ResultType != \"0\"\n| summarize Failures = count() by UserPrincipalName, IPAddress\n| where Failures > {}\n",
            number % 50 + 5
        ),
        _ => format!(
            "DeviceProcessEvents\n| where FileName =~ \"{process}\"\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine\n"
        ),
    };
    let nrt = variant % 5 == 4;
    let scheduling = if nrt {
        tags.push("sentinel:nrt".to_string());
        Yaml::map(vec![("nrt", Yaml::raw("true"))])
    } else {
        tags.push("sentinel:scheduled".to_string());
        Yaml::map(vec![
            ("frequency", Yaml::s(rng.pick(&["PT1H", "PT30M", "PT4H"]))),
            ("lookback", Yaml::s(rng.pick(&["PT4H", "PT8H", "P1D"]))),
        ])
    };
    let mut alert = vec![
        ("title", Yaml::s(name)),
        ("severity", Yaml::s(rng.pick(&["Low", "Medium", "High"]))),
        ("suppression", Yaml::raw("false")),
    ];
    if rng.chance(50) {
        alert.push(("description", Yaml::s(format!("{name} raised an alert.\n"))));
    }
    let mut pairs = kv(vec![
        ("query", Yaml::s(query)),
        ("scheduling", scheduling),
        ("alert", Yaml::map(alert)),
        (
            "grouping",
            Yaml::map(vec![
                ("event", Yaml::s("SingleAlert")),
                ("alert", Yaml::map(vec![("enabled", Yaml::raw("false"))])),
            ]),
        ),
    ]);
    if variant % 3 == 0 && rng.chance(50) {
        tags.push("sentinel:entities".to_string());
        pairs.push((
            "entities".to_string(),
            Yaml::Seq(vec![Yaml::map(vec![
                ("entity", Yaml::s("Host")),
                (
                    "mappings",
                    Yaml::Seq(vec![Yaml::map(vec![
                        ("identifier", Yaml::s("HostName")),
                        ("column", Yaml::s("Computer")),
                    ])]),
                ),
            ])]),
        ));
    }
    pairs
}

fn defender(
    rng: &mut Rng,
    variant: usize,
    process: &str,
    tags: &mut Vec<String>,
) -> Vec<(String, Yaml)> {
    let query = if variant % 2 == 0 {
        format!(
            "DeviceProcessEvents\n| where FileName =~ \"{process}\"\n| project Timestamp, DeviceId, ReportId, DeviceName, AccountName\n"
        )
    } else {
        tags.push("defender:network".to_string());
        format!(
            "DeviceNetworkEvents\n| where RemotePort == {}\n| project Timestamp, DeviceId, ReportId, RemoteIP, RemotePort\n",
            rng.pick(&["4444", "8080", "3389"])
        )
    };
    kv(vec![
        ("query", Yaml::s(query)),
        ("scheduling", Yaml::s(rng.pick(&["1H", "3H", "12H", "24H"]))),
        (
            "alert",
            Yaml::map(vec![
                ("category", Yaml::s("Execution")),
                ("severity", Yaml::s(rng.pick(&["Low", "Medium", "High"]))),
            ]),
        ),
        (
            "impacted_entities",
            Yaml::map(vec![("device", Yaml::s("DeviceId"))]),
        ),
        ("scope", Yaml::map(vec![("selection", Yaml::s("All"))])),
    ])
}

fn splunk(
    rng: &mut Rng,
    variant: usize,
    number: usize,
    name: &str,
    tags: &mut Vec<String>,
) -> Vec<(String, Yaml)> {
    let query = if variant % 2 == 0 {
        format!(
            "index=main sourcetype=\"WinEventLog:Security\" EventCode={number}\n| stats count by host, Account_Name\n"
        )
    } else {
        "index=main sourcetype=\"WinEventLog:Security\" EventCode=4688\n| table _time, host, New_Process_Name\n".to_string()
    };
    let mut pairs = kv(vec![
        ("query", Yaml::s(query)),
        (
            "scheduling",
            Yaml::map(vec![(
                "schedule",
                Yaml::map(vec![(
                    "cron",
                    Yaml::s(rng.pick(&["0 * * * *", "*/15 * * * *"])),
                )]),
            )]),
        ),
    ]);
    if variant % 3 == 1 {
        tags.push("splunk:notable".to_string());
        pairs.push((
            "actions".to_string(),
            Yaml::map(vec![(
                "notable",
                Yaml::map(vec![(
                    "event",
                    Yaml::map(vec![
                        ("title", Yaml::s(name)),
                        ("description", Yaml::s(format!("{name} matched.\n"))),
                    ]),
                )]),
            )]),
        ));
    }
    pairs
}

fn sentinel_one(
    rng: &mut Rng,
    variant: usize,
    process: &str,
    name: &str,
    tags: &mut Vec<String>,
) -> Vec<(String, Yaml)> {
    let condition = if variant % 2 == 0 {
        tags.push("sentinel_one:single".to_string());
        Yaml::map(vec![
            ("type", Yaml::s("Single Event")),
            (
                "single_event",
                Yaml::map(vec![(
                    "query",
                    Yaml::s(format!(
                        "EventType = \"Process Creation\" AND SrcProcName = \"{process}\""
                    )),
                )]),
            ),
        ])
    } else {
        tags.push("sentinel_one:correlation".to_string());
        Yaml::map(vec![
            ("type", Yaml::s("Correlation")),
            (
                "correlation",
                Yaml::map(vec![
                    ("entity", Yaml::s("host")),
                    ("match_in_order", Yaml::raw("true")),
                    ("time_window", Yaml::s("1h")),
                    (
                        "sub_queries",
                        Yaml::Seq(vec![Yaml::map(vec![
                            ("query", Yaml::s("EventType = \"Process Creation\"")),
                            ("matches_required", Yaml::raw(rng.range(1, 3))),
                        ])]),
                    ),
                ]),
            ),
        ])
    };
    kv(vec![
        ("condition", condition),
        (
            "response",
            Yaml::map(vec![
                (
                    "treat_as_threat",
                    Yaml::s(rng.pick(&["Malicious", "Suspicious"])),
                ),
                ("network_quarantine", Yaml::raw("false")),
            ]),
        ),
        (
            "details",
            Yaml::map(vec![
                ("name", Yaml::s(name)),
                ("severity", Yaml::s(rng.pick(&["Low", "Medium", "High"]))),
            ]),
        ),
    ])
}

fn crowdstrike(rng: &mut Rng, process: &str, name: &str) -> Vec<(String, Yaml)> {
    kv(vec![
        (
            "query",
            Yaml::s(format!(
                "#event_simpleName=ProcessRollup2 FileName=\"{process}\""
            )),
        ),
        (
            "details",
            Yaml::map(vec![
                ("trigger", Yaml::s("event")),
                ("outcome", Yaml::s("detection")),
                ("name", Yaml::s(name)),
                ("severity", Yaml::s(rng.pick(&["low", "medium", "high"]))),
            ]),
        ),
        (
            "schedule",
            Yaml::map(vec![
                ("frequency", Yaml::s("1h")),
                ("lookback", Yaml::s("2h")),
            ]),
        ),
    ])
}

fn harfanglab(
    rng: &mut Rng,
    variant: usize,
    process: &str,
    name: &str,
    tags: &mut Vec<String>,
) -> Vec<(String, Yaml)> {
    let mut pairs = kv(vec![("action", Yaml::s("Alert"))]);
    if variant % 2 == 0 {
        tags.push("harfanglab:sigma".to_string());
        pairs.push((
            "sigma".to_string(),
            Yaml::map(vec![
                (
                    "logsource",
                    Yaml::map(vec![
                        ("category", Yaml::s("process_creation")),
                        ("product", Yaml::s("windows")),
                    ]),
                ),
                (
                    "selections",
                    Yaml::Seq(vec![Yaml::map(vec![
                        ("name", Yaml::s("selection")),
                        ("field", Yaml::s("Image")),
                        ("value", Yaml::s(format!("\\{process}"))),
                        ("modifiers", Yaml::strs(&["endswith"])),
                    ])]),
                ),
                ("condition", Yaml::s("selection")),
            ]),
        ));
    } else {
        tags.push("harfanglab:yara".to_string());
        let marker = rng.pick(NOUNS).to_ascii_lowercase();
        pairs.push((
            "yara".to_string(),
            Yaml::map(vec![
                (
                    "meta",
                    Yaml::map(vec![
                        ("context", Yaml::strs(&["file"])),
                        ("os", Yaml::s(rng.pick(&["Windows", "Linux"]))),
                        ("score", Yaml::s(rng.pick(&["Low", "Medium", "High"]))),
                    ]),
                ),
                (
                    "strings",
                    Yaml::s(format!("$a = \"{marker}\" ascii wide\n")),
                ),
                ("condition", Yaml::s("$a")),
            ]),
        ));
    }
    let _ = name;
    pairs
}

fn elastic(
    rng: &mut Rng,
    variant: usize,
    process: &str,
    tags: &mut Vec<String>,
) -> Vec<(String, Yaml)> {
    let index = Yaml::strs(&["logs-endpoint.events.*"]);
    let mut pairs = match variant % 5 {
        0 => {
            tags.push("elastic:kuery".to_string());
            kv(vec![
                ("type", Yaml::s("query")),
                ("language", Yaml::s("kuery")),
                ("query", Yaml::s(format!("process.name: \"{process}\"\n"))),
                ("index", index),
            ])
        }
        1 => {
            tags.push("elastic:eql".to_string());
            kv(vec![
                ("type", Yaml::s("eql")),
                (
                    "query",
                    Yaml::s(format!("process where process.name == \"{process}\"\n")),
                ),
                ("index", index),
            ])
        }
        2 => {
            tags.push("elastic:lucene".to_string());
            kv(vec![
                ("type", Yaml::s("query")),
                ("language", Yaml::s("lucene")),
                ("query", Yaml::s(format!("process.name:\"{process}\"\n"))),
                ("index", index),
            ])
        }
        3 => {
            tags.push("elastic:esql".to_string());
            kv(vec![
                ("type", Yaml::s("esql")),
                (
                    "query",
                    Yaml::s(format!(
                        "FROM logs-endpoint.events.* METADATA _id, _index, _version\n| WHERE process.name == \"{process}\"\n| KEEP @timestamp, host.name, process.name\n"
                    )),
                ),
            ])
        }
        _ => {
            tags.push("elastic:threshold".to_string());
            kv(vec![
                ("type", Yaml::s("threshold")),
                ("language", Yaml::s("kuery")),
                ("query", Yaml::s(format!("process.name: \"{process}\"\n"))),
                ("index", index),
                (
                    "threshold",
                    Yaml::map(vec![
                        ("field", Yaml::strs(&["host.name"])),
                        ("value", Yaml::raw(rng.range(2, 20))),
                    ]),
                ),
            ])
        }
    };
    pairs.push((
        "scheduling".to_string(),
        Yaml::map(vec![
            ("interval", Yaml::s(rng.pick(&["5m", "10m"]))),
            ("lookback", Yaml::s("1m")),
        ]),
    ));
    pairs.push((
        "severity".to_string(),
        // `default` alone fails the oracle's compile with KeyError 'mapping'
        // (KNOWN_GAPS.md): the mapping is written with it.
        Yaml::map(vec![
            ("default", Yaml::s(rng.pick(&["low", "medium", "high"]))),
            (
                "mapping",
                Yaml::Seq(vec![Yaml::map(vec![
                    ("field", Yaml::s("host.os.type")),
                    ("value", Yaml::s("windows")),
                    ("operator", Yaml::s("equals")),
                    ("severity", Yaml::s("high")),
                ])]),
            ),
        ]),
    ));
    pairs
}

fn sysdig(rng: &mut Rng, variant: usize, tags: &mut Vec<String>) -> Vec<(String, Yaml)> {
    let list = format!("corpus_shells_{}", rng.below(1000));
    let shells = rng.sample(SHELLS, 3);
    let mut pairs = kv(vec![
        (
            "condition",
            Yaml::s(format!(
                "spawned_process and container and proc.name in ({list})\n"
            )),
        ),
        (
            "lists",
            Yaml::Seq(vec![Yaml::map(vec![
                ("name", Yaml::s(list.clone())),
                ("items", Yaml::strs(&shells)),
            ])]),
        ),
        (
            "output",
            Yaml::s("Shell spawned in a container (proc.name=%proc.name)"),
        ),
        (
            "priority",
            Yaml::s(rng.pick(&["WARNING", "NOTICE", "ERROR"])),
        ),
        ("tags", Yaml::strs(&["container", "shell"])),
    ]);
    if variant % 2 == 1 {
        tags.push("sysdig:macro".to_string());
        pairs.push((
            "macros".to_string(),
            Yaml::Seq(vec![Yaml::map(vec![
                ("name", Yaml::s(format!("{list}_macro"))),
                ("condition", Yaml::s("container.id != host\n")),
            ])]),
        ));
    }
    pairs
}

/// An Exabeam block: one or two sequences of filter queries, the second with
/// a threshold and grouping (exabeam-1.0, Sequences).
fn exabeam(
    rng: &mut Rng,
    variant: usize,
    process: &str,
    tags: &mut Vec<String>,
) -> Vec<(String, Yaml)> {
    let mut sequences = vec![Yaml::map(vec![
        ("name", Yaml::s("Suspicious process start")),
        (
            "query",
            Yaml::s(format!(
                "activity_type:\"process-create\" AND process_name:\"{process}\"\n"
            )),
        ),
        ("group_by", Yaml::strs(&["host"])),
    ])];
    if variant % 2 == 1 {
        tags.push("exabeam:correlation".to_string());
        sequences.push(Yaml::map(vec![
            ("name", Yaml::s("Then connects out")),
            (
                "query",
                Yaml::s("activity_type:\"network-session\" AND NOT dest_ip:[10.0.0.0/8]\n"),
            ),
            (
                "threshold",
                Yaml::map(vec![
                    ("function", Yaml::s("count")),
                    ("operator", Yaml::s("more_than")),
                    (
                        "value",
                        Yaml::Seq(vec![Yaml::raw(format!("{}", 2 + rng.below(5)))]),
                    ),
                    ("within", Yaml::s("10m")),
                ]),
            ),
            ("group_by", Yaml::strs(&["host"])),
        ]));
    }
    let mut pairs = kv(vec![("sequences", Yaml::Seq(sequences))]);
    if variant % 2 == 1 {
        pairs.push((
            "correlation".to_string(),
            Yaml::map(vec![
                ("within", Yaml::s("30m")),
                ("group_by", Yaml::strs(&["host"])),
            ]),
        ));
    }
    pairs.push((
        "severity".to_string(),
        Yaml::s(rng.pick(&["low", "medium", "high"])),
    ));
    pairs
}

/// A tenant's `[tenants.setup]`: endpoints on reserved example domains and
/// `$VARIABLE` references, never a literal secret.
fn tenant_setup(platform: &str, tenant: &str) -> String {
    let var = tenant.to_ascii_uppercase().replace('-', "_");
    match platform {
        "sentinel" => format!(
            "ssl = true\nresource_group = \"rg-{tenant}\"\nworkspace_name = \"law-{tenant}\"\n\
             workspace_id = \"${var}_WORKSPACE_ID\"\nazure_tenant_id = \"${var}_TENANT_ID\"\n\
             azure_subscription_id = \"${var}_SUBSCRIPTION_ID\"\nazure_client_id = \"${var}_CLIENT_ID\"\n\
             azure_client_secret = \"${var}_CLIENT_SECRET\"\n"
        ),
        "defender_for_endpoint" => format!(
            "ssl = true\ntenant_id = \"${var}_TENANT_ID\"\nclient_id = \"${var}_CLIENT_ID\"\n\
             client_secret = \"${var}_CLIENT_SECRET\"\n"
        ),
        "splunk" => format!(
            "ssl = true\nurl = \"https://{tenant}.splunk.example\"\nport = \"8089\"\n\
             token = \"${var}_TOKEN\"\napp = \"SplunkEnterpriseSecuritySuite\"\n\
             correlation_searches = true\nenterprise_security = true\n"
        ),
        "sysdig" => format!(
            "ssl = true\nurl = \"https://{tenant}.sysdig.example\"\n\
             api_token = \"${var}_API_TOKEN\"\n"
        ),
        "elastic" => format!(
            "ssl = true\nurl = \"https://kibana.{tenant}.example\"\n\
             elasticsearch_url = \"https://es.{tenant}.example\"\n\
             api_key = \"${var}_API_KEY\"\nspace = \"{tenant}\"\n"
        ),
        "exabeam" => format!(
            "ssl = true\nregion = \"us-east\"\n\
             client_id = \"${var}_CLIENT_ID\"\nclient_secret = \"${var}_CLIENT_SECRET\"\n"
        ),
        _ => String::new(),
    }
}

fn platform_config(platform: &str) -> String {
    let title =
        opentide_schema::platforms::get(platform).map_or(platform, |row| row.configuration_name);
    let mut text = format!(
        "# Generated by cargo xtask corpus generate. Secrets are $VARIABLE placeholders.\n\
         [platform]\nenabled = true\nname = \"{title}\"\n\
         description = \"The {title} platform of the generated corpus.\"\n"
    );
    for (position, tenant) in tenants_of(platform).iter().enumerate() {
        let strategies = if tenants_of(platform).len() > 1 {
            if position == 0 {
                "[\"PREVIEW\"]"
            } else {
                "[\"RELEASE\"]"
            }
        } else {
            "[\"PREVIEW\", \"RELEASE\"]"
        };
        text.push_str(&format!(
            "\n[[tenants]]\nname = \"{tenant}\"\ndescription = \"Generated tenant {tenant}\"\n\
             strategies = {strategies}\n[tenants.setup]\n{}",
            tenant_setup(platform, tenant)
        ));
    }
    text
}

fn config_file(name: &str, text: String) -> File {
    let platform = name
        .strip_prefix("platforms/")
        .and_then(|n| n.strip_suffix(".toml"))
        .map(str::to_string);
    let mut tags = vec![format!("config:{name}")];
    if platform.is_some() {
        tags.push("config:platforms".to_string());
    }
    if platform
        .as_deref()
        .is_some_and(|p| !tenants_of(p).is_empty())
    {
        tags.push("tenants".to_string());
    }
    File {
        path: format!(".opentide/configurations/{name}"),
        family: Family::Config,
        platforms: platform.into_iter().collect(),
        tags,
        body: Body::Text(text),
    }
}

fn paths_toml(layout: Layout) -> String {
    let objects = |family| layout.folder(family);
    let docs = if layout == Layout::Custom {
        "documentation/"
    } else {
        "docs/"
    };
    format!(
        "# Generated by cargo xtask corpus generate (layout: {}).\n\
         objects = [\"threat\", \"objective\", \"rule\"]\n\n\
         [paths.objects]\nthreat = \"{}\"\nobjective = \"{}\"\nrule = \"{}\"\n\n\
         [paths.docs]\nroot = \"{docs}\"\nrules = \"{docs}rules/\"\n\
         objectives = \"{docs}objectives/\"\nthreats = \"{docs}threats/\"\n",
        layout.name(),
        objects(Family::Threat),
        objects(Family::Objective),
        objects(Family::Rule),
    )
}

const VISIBILITY: &str = "\
# Generated by cargo xtask corpus generate: the log sources the rules read.

[[assets]]
name = \"Domain workstations\"
description = \"Windows endpoints joined to the corporate domain\"
criticality = \"High\"

[[logsources]]
name = \"SecurityEvent\"
description = \"Windows security events in the Sentinel workspace\"
system = \"sentinel\"
assets = [\"Domain workstations\"]

[[logsources]]
name = \"SigninLogs\"
description = \"Entra ID sign-ins\"
system = \"sentinel\"

[[logsources]]
name = \"DeviceProcessEvents\"
description = \"Defender process events in the Sentinel workspace\"
system = \"sentinel\"

[[logsources]]
name = \"DeviceProcessEvents\"
description = \"Defender process events in advanced hunting\"
system = \"defender_for_endpoint\"

[[logsources]]
name = \"DeviceNetworkEvents\"
description = \"Defender network events in advanced hunting\"
system = \"defender_for_endpoint\"

[[logsources]]
name = \"WinEventLog:Security\"
description = \"Windows security log\"
system = \"splunk\"

[[logsources]]
name = \"logs-endpoint.events.*\"
description = \"Endpoint telemetry\"
system = \"elastic\"
";

fn configuration_files(layout: Layout) -> Vec<File> {
    let mut files: Vec<File> = vocab::generated_platforms()
        .iter()
        .map(|platform| {
            config_file(
                &format!("platforms/{platform}.toml"),
                platform_config(platform),
            )
        })
        .collect();
    let mut deployment = String::from(
        "# Generated by cargo xtask corpus generate.\n[promotion]\nenabled = true\npromotion_target = \"PRODUCTION\"\n",
    );
    for responder in RESPONDERS {
        deployment.push_str(&format!(
            "\n[[responders]]\nname = \"{responder}\"\ndescription = \"The {responder} team\"\n"
        ));
    }
    files.push(config_file("deployment.toml", deployment));
    files.push(config_file("visibility.toml", VISIBILITY.to_string()));
    if layout != Layout::Standard {
        files.push(config_file("paths.toml", paths_toml(layout)));
    }
    files
}

#[cfg(test)]
mod tests {
    use super::super::vocab;
    use super::{Counts, date, slugify};

    #[test]
    fn the_generated_corpus_leaves_out_platforms_the_oracle_lacks() {
        let generated = vocab::generated_platforms();
        for id in opentide_schema::platforms::SINCE_ORACLE {
            assert!(
                !generated.contains(id),
                "the generated corpus must leave {id} out (SINCE_ORACLE): a registry row on the \
                 train would otherwise reshuffle the seeded corpus"
            );
        }
        // Without SINCE_ORACLE the list is the whole connector order.
        if opentide_schema::platforms::SINCE_ORACLE.is_empty() {
            assert_eq!(generated, vocab::PLATFORMS);
        }
    }

    #[test]
    fn dates_walk_the_calendar() {
        assert_eq!(date(0), "2025-01-01");
        assert_eq!(date(31), "2025-02-01");
        assert_eq!(date(364), "2025-12-31");
        assert_eq!(date(365), "2026-01-01");
        assert_eq!(date(545), "2026-06-30");
        assert_eq!(date(9999), "2026-06-30");
    }

    #[test]
    fn slugify_matches_opentide() {
        assert_eq!(
            slugify("Silent Loader Rule 0001"),
            "silent-loader-rule-0001"
        );
        assert_eq!(slugify("  a--b  C "), "a-b-c");
        assert_eq!(slugify("***"), "object");
    }

    #[test]
    fn scale() {
        assert_eq!(
            Counts::scaled(0.1),
            Some(Counts {
                threats: 30,
                objectives: 30,
                rules: 50
            })
        );
        assert_eq!(Counts::scaled(10.0).map(|c| c.rules), Some(5000));
        assert_eq!(Counts::scaled(0.0), None);
        assert_eq!(Counts::scaled(f64::NAN), None);
    }
}
