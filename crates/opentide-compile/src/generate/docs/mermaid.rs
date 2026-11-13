//! Diagrams as a flavour-neutral model, written as Mermaid within what each
//! flavour's Mermaid renders (`documentation/diagram/{model,mermaid,sanitize}.py`).
//!
//! A builder ([`super::diagrams`]) says *what* a diagram shows: typed nodes,
//! typed links, ordered lanes. [`render`] decides *how*, from the flavour's
//! [`Dialect`]. GitHub and GitLab render subgraphs, `classDef` styles and the
//! `accTitle` / `accDescr` lines; Azure DevOps fails the whole diagram on
//! some of them. Everything a style conveys (a node's kind, the page's own
//! object) is also carried by shape, label and the [`legend`], so a plain
//! dialect loses colour, not meaning.

use indexmap::IndexMap;

/// The Mermaid features a Markdown flavour renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one switch per Mermaid feature, as the flavours differ"
)]
pub struct Dialect {
    /// `flowchart` (Mermaid 8.6+), else the older `graph`.
    pub flowchart: bool,
    /// `subgraph` lanes.
    pub lanes: bool,
    /// `classDef` / `class` colours and the focus outline.
    pub styles: bool,
    /// `accTitle` / `accDescr` (Mermaid 9.4+).
    pub accessibility: bool,
}

impl Dialect {
    /// Everything: GitHub's and GitLab's Mermaid.
    pub const FULL: Self = Self {
        flowchart: true,
        lanes: true,
        styles: true,
        accessibility: true,
    };
    /// A CommonMark site, whose Mermaid release is unknown: no accessibility
    /// lines, which a release before 9.4 refuses.
    pub const COMMONMARK: Self = Self {
        accessibility: false,
        ..Self::FULL
    };
    /// Azure DevOps' wiki, which fails a whole diagram on `flowchart`, on
    /// subgraphs and on styles.
    pub const AZURE_DEVOPS: Self = Self {
        flowchart: false,
        lanes: false,
        styles: false,
        accessibility: false,
    };
}

/// What a node stands for. Each kind has one shape and one style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKind {
    /// A threat vector.
    Threat,
    /// A detection objective.
    Objective,
    /// A detection signal.
    Signal,
    /// A detection rule.
    Rule,
    /// A platform a rule deploys to.
    Platform,
    /// A platform tenant.
    Tenant,
    /// A kill-chain phase.
    Phase,
}

impl NodeKind {
    /// Every kind, in legend order.
    pub const ALL: [Self; 7] = [
        Self::Threat,
        Self::Objective,
        Self::Signal,
        Self::Rule,
        Self::Platform,
        Self::Tenant,
        Self::Phase,
    ];

    /// The kind of an object type (`threat`).
    pub fn of(object_type: &str) -> Option<Self> {
        Some(match object_type {
            "threat" => Self::Threat,
            "objective" => Self::Objective,
            "signal" => Self::Signal,
            "rule" => Self::Rule,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Threat => "threat",
            Self::Objective => "objective",
            Self::Signal => "signal",
            Self::Rule => "rule",
            Self::Platform => "platform",
            Self::Tenant => "tenant",
            Self::Phase => "phase",
        }
    }

    /// `(id prefix, opening, closing, shape, noun, classDef)`.
    fn style(
        self,
    ) -> (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    ) {
        match self {
            Self::Threat => (
                "thr",
                "{{",
                "}}",
                "hexagon",
                "threat vector",
                "fill:#fdecea,stroke:#b42318,color:#3d0c09",
            ),
            Self::Objective => (
                "obj",
                "([",
                "])",
                "stadium",
                "detection objective",
                "fill:#fff4e5,stroke:#b54708,color:#3d1d02",
            ),
            Self::Signal => (
                "sig",
                "((",
                "))",
                "circle",
                "detection signal",
                "fill:#eaf2fd,stroke:#1d4ed8,color:#0b1f4d",
            ),
            Self::Rule => (
                "rul",
                "[",
                "]",
                "rectangle",
                "detection rule",
                "fill:#e9f7ef,stroke:#067647,color:#053321",
            ),
            Self::Platform => (
                "plt",
                "[(",
                ")]",
                "cylinder",
                "platform",
                "fill:#f2f4f7,stroke:#475467,color:#101828",
            ),
            Self::Tenant => (
                "ten",
                "[[",
                "]]",
                "subroutine box",
                "tenant",
                "fill:#f4f3ff,stroke:#5925dc,color:#21125a",
            ),
            Self::Phase => (
                "kc",
                "([",
                "])",
                "stadium",
                "kill-chain phase",
                "fill:#f9fafb,stroke:#d0d5dd,color:#475467",
            ),
        }
    }
}

/// A status colour laid over a node's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tone {
    /// Every threat in it is addressed by a detection objective.
    Covered,
    /// Some are.
    Partial,
    /// None are.
    Uncovered,
    /// No threat vector sits there.
    Idle,
    /// Where the page's own object sits.
    Current,
    /// Where an object related to the page's sits.
    Related,
}

impl Tone {
    /// Every tone, in legend order.
    pub const ALL: [Self; 6] = [
        Self::Covered,
        Self::Partial,
        Self::Uncovered,
        Self::Idle,
        Self::Current,
        Self::Related,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Partial => "partial",
            Self::Uncovered => "uncovered",
            Self::Idle => "idle",
            Self::Current => "current",
            Self::Related => "related",
        }
    }

    /// `(classDef, the colour the legend names)`.
    fn style(self) -> (&'static str, &'static str) {
        match self {
            Self::Covered => ("fill:#ecfdf3,stroke:#079455,color:#053321", "green"),
            Self::Partial => ("fill:#fffaeb,stroke:#dc6803,color:#4e1d09", "amber"),
            Self::Uncovered => ("fill:#fef3f2,stroke:#d92d20,color:#55160c", "red"),
            Self::Idle => ("fill:#f9fafb,stroke:#d0d5dd,color:#667085", "grey"),
            Self::Current => (
                "fill:#eff8ff,stroke:#1570ef,color:#102a56,stroke-width:3px",
                "blue",
            ),
            Self::Related => ("fill:#f5faff,stroke:#84caff,color:#194185", "light blue"),
        }
    }
}

/// How a link is drawn: the line carries meaning, not only the label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum LinkStyle {
    /// A plain dependency or sequence.
    #[default]
    Solid,
    /// A strong, structural link (one object composes the other).
    Thick,
    /// A weak or inactive link (support, a status no run deploys).
    Dotted,
}

impl LinkStyle {
    /// Every style, in legend order.
    pub const ALL: [Self; 3] = [Self::Solid, Self::Thick, Self::Dotted];

    /// `(one way, both ways, the legend's noun)`.
    fn arrows(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Solid => ("-->", "<-->", "solid line"),
            Self::Thick => ("==>", "<==>", "thick line"),
            Self::Dotted => ("-.->", "<-.->", "dotted line"),
        }
    }
}

/// One box. `key` is its identity (a UUID); [`render`] gives the Mermaid id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The identity.
    pub key: String,
    /// The label.
    pub label: String,
    /// What it stands for.
    pub kind: NodeKind,
    /// A second line under the label (a status, a kill-chain phase).
    pub caption: String,
    /// The object the page is about.
    pub focus: bool,
    /// A gap: drawn with a dashed outline (a threat no objective addresses).
    pub gap: bool,
    /// A status colour, drawn where the flavour takes styles.
    pub tone: Option<Tone>,
}

impl Node {
    /// A plain node.
    pub fn new(key: &str, label: &str, kind: NodeKind) -> Self {
        Self {
            key: key.to_owned(),
            label: label.to_owned(),
            kind,
            caption: String::new(),
            focus: false,
            gap: false,
            tone: None,
        }
    }

    /// With `focus`.
    #[must_use]
    pub fn focused(mut self, focus: bool) -> Self {
        self.focus = focus;
        self
    }

    /// With a caption.
    #[must_use]
    pub fn captioned(mut self, caption: &str) -> Self {
        caption.clone_into(&mut self.caption);
        self
    }
}

/// A directed link between two node keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Link {
    /// The source's key.
    pub source: String,
    /// The target's key.
    pub target: String,
    /// The label, if any.
    pub label: String,
    /// The line.
    pub style: LinkStyle,
    /// Drawn both ways.
    pub bidirectional: bool,
}

impl Link {
    /// A plain link.
    pub fn new(source: &str, target: &str) -> Self {
        Self {
            source: source.to_owned(),
            target: target.to_owned(),
            ..Self::default()
        }
    }
}

/// A titled group of nodes, a subgraph where the flavour draws one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lane {
    /// The title.
    pub title: String,
    /// The member keys.
    pub members: Vec<String>,
    /// Where lanes cannot be drawn, show the title under each member's
    /// label, for lanes that say what the shape does not (a phase).
    pub caption_fallback: bool,
    /// Lay the members out this way, whatever the diagram's direction.
    pub direction: Option<&'static str>,
}

impl Lane {
    /// A lane of `members`.
    pub fn new(title: &str, members: Vec<String>) -> Self {
        Self {
            title: title.to_owned(),
            members,
            caption_fallback: false,
            direction: None,
        }
    }
}

/// An ordered, de-duplicated graph: insertion order is render order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagram {
    /// What it is (`accTitle`).
    pub title: String,
    /// What it shows (`accDescr`).
    pub description: String,
    /// `LR` or `TB`.
    pub direction: &'static str,
    /// The nodes, by key.
    pub nodes: IndexMap<String, Node>,
    /// The links.
    pub links: Vec<Link>,
    /// The lanes.
    pub lanes: Vec<Lane>,
    /// What each line style means, for the legend.
    pub link_legend: Vec<(LinkStyle, String)>,
    /// What each tone means, for the legend.
    pub tone_legend: Vec<(Tone, String)>,
    /// The lanes follow one another (a lane-to-lane arrow), as kill-chain
    /// stages do.
    pub chain_lanes: bool,
}

impl Diagram {
    /// An empty diagram, left to right.
    pub fn new(title: &str, description: &str) -> Self {
        Self {
            title: title.to_owned(),
            description: description.to_owned(),
            direction: "LR",
            nodes: IndexMap::new(),
            links: Vec::new(),
            lanes: Vec::new(),
            link_legend: Vec::new(),
            tone_legend: Vec::new(),
            chain_lanes: false,
        }
    }

    /// Adds `node` unless its key is there; a focus node wins over a plain
    /// one, at the first one's place.
    pub fn add_node(&mut self, node: Node) {
        match self.nodes.get_mut(&node.key) {
            None => {
                self.nodes.insert(node.key.clone(), node);
            }
            Some(existing) if node.focus && !existing.focus => *existing = node,
            Some(_) => {}
        }
    }

    /// Adds `link` between known nodes, once: not a loop, not the same link
    /// again, nor a link a two-way link already draws.
    pub fn add_link(&mut self, link: Link) {
        if !self.nodes.contains_key(&link.source)
            || !self.nodes.contains_key(&link.target)
            || link.source == link.target
        {
            return;
        }
        let known = self.links.iter().any(|existing| {
            let same = existing.source == link.source && existing.target == link.target;
            let mirrored = existing.source == link.target && existing.target == link.source;
            (same || (mirrored && existing.bidirectional)) && existing.label == link.label
        });
        if !known {
            self.links.push(link);
        }
    }

    /// The legend's text for `style`, the first one set.
    pub fn set_link_legend(&mut self, style: LinkStyle, text: &str) {
        if !self.link_legend.iter().any(|(known, _)| *known == style) {
            self.link_legend.push((style, text.to_owned()));
        }
    }

    /// Nothing worth drawing: no link.
    pub fn is_trivial(&self) -> bool {
        self.links.is_empty()
    }

    fn kinds(&self) -> Vec<NodeKind> {
        NodeKind::ALL
            .into_iter()
            .filter(|kind| self.nodes.values().any(|node| node.kind == *kind))
            .collect()
    }

    fn tones(&self) -> Vec<Tone> {
        Tone::ALL
            .into_iter()
            .filter(|tone| self.nodes.values().any(|node| node.tone == Some(*tone)))
            .collect()
    }

    fn link_styles(&self) -> Vec<LinkStyle> {
        LinkStyle::ALL
            .into_iter()
            .filter(|style| self.links.iter().any(|link| link.style == *style))
            .collect()
    }
}

/// Characters per label line before it wraps.
pub const LABEL_WIDTH: usize = 26;

/// `text` on one line, Mermaid's reserved characters as entity codes (`#`
/// first: it starts every code after it); in an edge label a pipe too.
fn escape(text: &str, edge: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for c in super::text::collapse(text).chars() {
        match c {
            '#' => out.push_str("#35;"),
            '"' => out.push_str("#quot;"),
            '<' => out.push_str("#lt;"),
            '>' => out.push_str("#gt;"),
            '`' => out.push_str("#96;"),
            '|' if edge => out.push_str("#124;"),
            other => out.push(other),
        }
    }
    out
}

/// Greedy word wrap at `width` characters; a word longer than the width
/// keeps its own line.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// A quoted label's body: escaped, wrapped with `<br>` every `width`
/// characters (`0`: one line); `-` when empty.
pub fn node_label(text: &str, width: usize) -> String {
    let lines = if width == 0 {
        vec![super::text::collapse(text)]
    } else {
        wrap(text, width)
    };
    let joined = lines
        .iter()
        .map(|line| escape(line, false))
        .collect::<Vec<_>>()
        .join("<br>");
    if joined.is_empty() {
        "-".to_owned()
    } else {
        joined
    }
}

/// Short, stable Mermaid ids (`thr1`, `rul3`) in insertion order: a UUID
/// can start with a digit, and a reserved word (`end`) breaks the parser.
fn ids(diagram: &Diagram) -> IndexMap<&str, String> {
    let mut counters: IndexMap<NodeKind, usize> = IndexMap::new();
    let mut out = IndexMap::new();
    for node in diagram.nodes.values() {
        let count = counters.entry(node.kind).or_insert(0);
        *count += 1;
        out.insert(node.key.as_str(), format!("{}{count}", node.kind.style().0));
    }
    out
}

fn node_line(node: &Node, ids: &IndexMap<&str, String>) -> String {
    let (_, opening, closing, ..) = node.kind.style();
    let mut label = node_label(&node.label, LABEL_WIDTH);
    if !node.caption.is_empty() {
        label = format!("{label}<br>{}", node_label(&node.caption, LABEL_WIDTH));
    }
    format!("{}{opening}\"{label}\"{closing}", ids[node.key.as_str()])
}

fn link_line(link: &Link, ids: &IndexMap<&str, String>) -> String {
    let (one_way, two_way, _) = link.style.arrows();
    let arrow = if link.bidirectional { two_way } else { one_way };
    let middle = if link.label.is_empty() {
        arrow.to_owned()
    } else {
        format!("{arrow}|\"{}\"|", escape(&link.label, true))
    };
    format!(
        "{} {middle} {}",
        ids[link.source.as_str()],
        ids[link.target.as_str()]
    )
}

/// The Mermaid source of `diagram`, without its fence.
pub fn render(diagram: &Diagram, dialect: Dialect) -> String {
    let ids = ids(diagram);
    let keyword = if dialect.flowchart {
        "flowchart"
    } else {
        "graph"
    };
    let mut lines = vec![format!("{keyword} {}", diagram.direction)];
    if dialect.accessibility {
        lines.push(format!(
            "    accTitle: {}",
            super::text::collapse(&diagram.title)
        ));
        if !diagram.description.is_empty() {
            lines.push(format!(
                "    accDescr: {}",
                super::text::collapse(&diagram.description)
            ));
        }
    }
    let mut placed: Vec<&str> = Vec::new();
    let mut lane_ids: Vec<String> = Vec::new();
    let mut lane_members: Vec<Vec<&Node>> = Vec::new();
    let drawn = diagram.lanes.iter().filter(|lane| {
        lane.members
            .iter()
            .any(|key| diagram.nodes.contains_key(key))
    });
    for (index, lane) in drawn.enumerate() {
        let mut members: Vec<&Node> = Vec::new();
        for key in &lane.members {
            if let Some(node) = diagram.nodes.get(key)
                && !placed.contains(&key.as_str())
                && !members.iter().any(|member| member.key == node.key)
            {
                members.push(node);
            }
        }
        if members.is_empty() {
            continue;
        }
        if dialect.lanes {
            let lane_id = format!("lane{}", index + 1);
            lines.push(format!(
                "    subgraph {lane_id}[\"{}\"]",
                node_label(&lane.title, 0)
            ));
            if let Some(direction) = lane.direction {
                lines.push(format!("        direction {direction}"));
            }
            for node in &members {
                lines.push(format!("        {}", node_line(node, &ids)));
            }
            lines.push("    end".to_owned());
            lane_ids.push(lane_id);
        } else {
            for node in &members {
                if lane.caption_fallback && node.caption.is_empty() {
                    let captioned = (*node).clone().captioned(&lane.title);
                    lines.push(format!("    {}", node_line(&captioned, &ids)));
                } else {
                    lines.push(format!("    {}", node_line(node, &ids)));
                }
            }
        }
        placed.extend(members.iter().map(|node| node.key.as_str()));
        lane_members.push(members);
    }
    for node in diagram.nodes.values() {
        if !placed.contains(&node.key.as_str()) {
            lines.push(format!("    {}", node_line(node, &ids)));
        }
    }
    for link in &diagram.links {
        lines.push(format!("    {}", link_line(link, &ids)));
    }
    if diagram.chain_lanes && dialect.lanes && lane_ids.len() > 1 {
        lines.push(format!("    {}", lane_ids.join(" --> ")));
    } else if diagram.chain_lanes {
        // No lanes to link: each lane's last member leads to the next's first.
        for pair in lane_members.windows(2) {
            if let (Some(last), Some(first)) = (pair[0].last(), pair[1].first()) {
                lines.push(format!(
                    "    {} --> {}",
                    ids[last.key.as_str()],
                    ids[first.key.as_str()]
                ));
            }
        }
    }
    if dialect.styles {
        lines.extend(style_lines(diagram, &ids, &lane_ids));
    }
    lines.join("\n")
}

fn style_lines(
    diagram: &Diagram,
    ids: &IndexMap<&str, String>,
    lane_ids: &[String],
) -> Vec<String> {
    let members = |keep: &dyn Fn(&Node) -> bool| -> Vec<&str> {
        diagram
            .nodes
            .values()
            .filter(|node| keep(node))
            .map(|node| ids[node.key.as_str()].as_str())
            .collect()
    };
    let mut lines = Vec::new();
    let kinds = diagram.kinds();
    for kind in &kinds {
        lines.push(format!("    classDef {} {}", kind.name(), kind.style().5));
    }
    let focus = members(&|node| node.focus);
    if !focus.is_empty() {
        lines.push("    classDef focus stroke-width:3px".to_owned());
    }
    for kind in &kinds {
        lines.push(format!(
            "    class {} {}",
            members(&|node| node.kind == *kind).join(","),
            kind.name()
        ));
    }
    if !focus.is_empty() {
        lines.push(format!("    class {} focus", focus.join(",")));
    }
    for tone in diagram.tones() {
        lines.push(format!("    classDef {} {}", tone.name(), tone.style().0));
        lines.push(format!(
            "    class {} {}",
            members(&|node| node.tone == Some(tone)).join(","),
            tone.name()
        ));
    }
    let gaps = members(&|node| node.gap);
    if !gaps.is_empty() {
        lines.push("    classDef gap stroke-dasharray:5 3".to_owned());
        lines.push(format!("    class {} gap", gaps.join(",")));
    }
    for lane_id in lane_ids {
        lines.push(format!(
            "    style {lane_id} fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4"
        ));
    }
    lines
}

/// One Markdown line naming each shape, line and colour the diagram uses.
pub fn legend(diagram: &Diagram, dialect: Dialect) -> String {
    let mut shapes: Vec<String> = diagram
        .kinds()
        .iter()
        .map(|kind| {
            let (_, _, _, shape, noun, _) = kind.style();
            format!("{shape} = {noun}")
        })
        .collect();
    if dialect.styles && diagram.nodes.values().any(|node| node.focus) {
        shapes.push("bold outline = this page".to_owned());
    }
    if dialect.styles && diagram.nodes.values().any(|node| node.gap) {
        shapes.push("dashed outline = no detection objective".to_owned());
    }
    let mut parts = vec![format!("*Shapes:* {}.", shapes.join("; "))];
    let lines: Vec<String> = diagram
        .link_styles()
        .into_iter()
        .filter_map(|style| {
            let text = diagram
                .link_legend
                .iter()
                .find(|(known, _)| *known == style)
                .map(|(_, text)| text.as_str())
                .filter(|text| !text.is_empty())?;
            Some(format!("{} = {text}", style.arrows().2))
        })
        .collect();
    if !lines.is_empty() {
        parts.push(format!("*Lines:* {}.", lines.join("; ")));
    }
    let tones: Vec<String> = diagram
        .tones()
        .into_iter()
        .filter_map(|tone| {
            let text = diagram
                .tone_legend
                .iter()
                .find(|(known, _)| *known == tone)
                .map(|(_, text)| text.as_str())
                .filter(|text| !text.is_empty())?;
            Some(format!("{} = {text}", tone.style().1))
        })
        .collect();
    if dialect.styles && !tones.is_empty() {
        parts.push(format!("*Colours:* {}.", tones.join("; ")));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Diagram {
        let mut diagram = Diagram::new("Detection coverage of R", "Threats to rules.");
        diagram.add_node(Node::new("t", "Simulated Actor", NodeKind::Threat));
        diagram.add_node(Node::new(
            "o",
            "Credential Access Objective",
            NodeKind::Objective,
        ));
        diagram.add_node(Node::new("r", "Rule \"x\" <a> #1", NodeKind::Rule).focused(true));
        diagram.add_node(Node::new("r", "Again", NodeKind::Rule));
        diagram.add_link(Link::new("t", "o"));
        diagram.add_link(Link::new("o", "r"));
        diagram.add_link(Link::new("o", "r"));
        diagram.add_link(Link::new("o", "missing"));
        diagram.add_link(Link::new("o", "o"));
        diagram.lanes = vec![
            Lane::new("Threat vectors", vec!["t".into()]),
            Lane::new("Detection objectives", vec!["o".into()]),
            Lane::new("Detection rules", vec!["r".into()]),
        ];
        diagram
    }

    #[test]
    fn labels_are_escaped_and_wrapped() {
        assert_eq!(
            node_label("Credential Access Objective", LABEL_WIDTH),
            "Credential Access<br>Objective"
        );
        assert_eq!(
            node_label("a \"b\" <c> #d `e`", 0),
            "a #quot;b#quot; #lt;c#gt; #35;d #96;e#96;"
        );
        assert_eq!(escape("a|b", true), "a#124;b");
        assert_eq!(node_label("  ", LABEL_WIDTH), "-");
        assert_eq!(
            wrap("averyveryveryverylongwordindeed x", 10),
            ["averyveryveryverylongwordindeed", "x"]
        );
    }

    #[test]
    fn a_full_dialect_draws_lanes_styles_and_titles() {
        let text = render(&sample(), Dialect::FULL);
        assert_eq!(
            text,
            "flowchart LR\n    accTitle: Detection coverage of R\n    accDescr: Threats to rules.\n    \
             subgraph lane1[\"Threat vectors\"]\n        thr1{{\"Simulated Actor\"}}\n    end\n    \
             subgraph lane2[\"Detection objectives\"]\n        obj1([\"Credential Access<br>Objective\"])\n    end\n    \
             subgraph lane3[\"Detection rules\"]\n        rul1[\"Rule #quot;x#quot; #lt;a#gt; #35;1\"]\n    end\n    \
             thr1 --> obj1\n    obj1 --> rul1\n    \
             classDef threat fill:#fdecea,stroke:#b42318,color:#3d0c09\n    \
             classDef objective fill:#fff4e5,stroke:#b54708,color:#3d1d02\n    \
             classDef rule fill:#e9f7ef,stroke:#067647,color:#053321\n    \
             classDef focus stroke-width:3px\n    class thr1 threat\n    class obj1 objective\n    \
             class rul1 rule\n    class rul1 focus\n    \
             style lane1 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4\n    \
             style lane2 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4\n    \
             style lane3 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4"
        );
        assert_eq!(
            legend(&sample(), Dialect::FULL),
            "*Shapes:* hexagon = threat vector; stadium = detection objective; rectangle = \
             detection rule; bold outline = this page."
        );
    }

    #[test]
    fn azure_devops_gets_a_plain_graph() {
        let mut diagram = sample();
        diagram.lanes[0].caption_fallback = true;
        diagram.chain_lanes = true;
        let text = render(&diagram, Dialect::AZURE_DEVOPS);
        assert_eq!(
            text,
            "graph LR\n    thr1{{\"Simulated Actor<br>Threat vectors\"}}\n    \
             obj1([\"Credential Access<br>Objective\"])\n    rul1[\"Rule #quot;x#quot; #lt;a#gt; #35;1\"]\n    \
             thr1 --> obj1\n    obj1 --> rul1\n    thr1 --> obj1\n    obj1 --> rul1"
        );
        assert_eq!(
            legend(&diagram, Dialect::AZURE_DEVOPS),
            "*Shapes:* hexagon = threat vector; stadium = detection objective; rectangle = \
             detection rule."
        );
    }

    #[test]
    fn links_tones_gaps_and_chained_lanes() {
        let mut diagram = Diagram::new("T", "");
        diagram.direction = "TB";
        diagram.chain_lanes = true;
        let mut a = Node::new("a", "A", NodeKind::Phase);
        a.tone = Some(Tone::Covered);
        let mut b = Node::new("b", "B", NodeKind::Threat);
        b.gap = true;
        b.tone = Some(Tone::Uncovered);
        diagram.add_node(a);
        diagram.add_node(b);
        diagram.add_link(Link {
            label: "pre|ceeds".into(),
            style: LinkStyle::Thick,
            bidirectional: true,
            ..Link::new("a", "b")
        });
        // The mirror of a two-way link with the same label is the same link.
        diagram.add_link(Link {
            label: "pre|ceeds".into(),
            ..Link::new("b", "a")
        });
        diagram.add_link(Link {
            style: LinkStyle::Dotted,
            ..Link::new("b", "a")
        });
        diagram.set_link_legend(LinkStyle::Thick, "composition");
        diagram.set_link_legend(LinkStyle::Thick, "ignored");
        diagram.tone_legend = vec![
            (Tone::Covered, "all".into()),
            (Tone::Uncovered, "none".into()),
        ];
        diagram.lanes = vec![
            Lane {
                direction: Some("LR"),
                ..Lane::new("One", vec!["a".into()])
            },
            Lane::new("Two", vec!["b".into()]),
        ];
        let text = render(&diagram, Dialect::COMMONMARK);
        assert!(
            text.starts_with("flowchart TB\n    subgraph lane1[\"One\"]\n        direction LR\n")
        );
        assert!(text.contains(
            "    kc1 <==>|\"pre#124;ceeds\"| thr1\n    thr1 -.-> kc1\n    lane1 --> lane2\n"
        ));
        assert!(text.contains("    classDef covered fill:#ecfdf3,stroke:#079455,color:#053321\n    class kc1 covered\n"));
        assert!(text.contains("    classDef gap stroke-dasharray:5 3\n    class thr1 gap\n"));
        assert_eq!(
            legend(&diagram, Dialect::COMMONMARK),
            "*Shapes:* hexagon = threat vector; stadium = kill-chain phase; dashed outline = no \
             detection objective. *Lines:* thick line = composition. *Colours:* green = all; red \
             = none."
        );
        assert!(Diagram::new("x", "").is_trivial());
        let plain = render(&diagram, Dialect::AZURE_DEVOPS);
        assert!(
            plain.ends_with("thr1 -.-> kc1\n    kc1 --> thr1"),
            "{plain}"
        );
    }
}
