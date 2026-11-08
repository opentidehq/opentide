//! The structure of a Tide object for an editor (#185 P3): its outline
//! (sections, each `configurations.<platform>` block, each query), its links
//! (ATT&CK ids to attack.mitre.org, UUIDs to the object they name), and the
//! objects that reference it. Byte spans are in the text after a leading
//! byte-order mark ([`opentide_core::strip_bom`]).

use crate::{IndexedObject, extract_injections, find_refs};
use opentide_core::ByteSpan;
use regex::Regex;
use std::sync::OnceLock;

/// What an [`OutlineNode`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutlineKind {
    /// The whole object, named by its `name`.
    Object,
    /// A top-level key (`metadata`, `configurations`, `response`).
    Section,
    /// A platform block under `configurations`.
    Platform,
    /// A query the object carries.
    Query,
}

/// One node of a Tide object's outline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutlineNode {
    pub name: String,
    pub detail: Option<String>,
    pub kind: OutlineKind,
    /// The node's whole extent.
    pub span: ByteSpan,
    /// The part to select or reveal: the key, or the object's name.
    pub selection: ByteSpan,
    pub children: Vec<OutlineNode>,
}

struct Line<'a> {
    start: usize,
    text: &'a str,
}

fn lines(source: &str) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let mut start = 0;
    for text in source.split_inclusive('\n') {
        out.push(Line {
            start,
            text: text.trim_end_matches(['\n', '\r']),
        });
        start += text.len();
    }
    out
}

fn indent(text: &str) -> usize {
    text.len() - text.trim_start_matches(' ').len()
}

fn is_content(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

/// The key a mapping line names, and its span within the line.
fn line_key(text: &str) -> Option<(String, usize, usize)> {
    let start = indent(text);
    let rest = &text[start..];
    if rest.starts_with(['#', '-']) || rest.starts_with("---") {
        return None;
    }
    let colon = rest.find(':')?;
    let after = &rest[colon + 1..];
    if !(after.is_empty() || after.starts_with([' ', '\t'])) {
        return None;
    }
    let key = rest[..colon].trim_end();
    let key = key.trim_matches(['"', '\'']);
    if key.is_empty() {
        return None;
    }
    Some((key.to_string(), start, start + colon))
}

/// The keys at the shallowest indentation within `lines[from..to]`, deeper
/// than `parent` (any depth for `None`), each with the index of its line and
/// of the line after its last content line.
fn child_keys(
    lines: &[Line<'_>],
    from: usize,
    to: usize,
    parent: Option<usize>,
) -> Vec<(usize, usize)> {
    let depth = lines[from..to]
        .iter()
        .filter(|l| is_content(l.text) && parent.is_none_or(|p| indent(l.text) > p))
        .map(|l| indent(l.text))
        .min();
    let Some(depth) = depth else {
        return Vec::new();
    };
    let starts: Vec<usize> = (from..to)
        .filter(|&i| {
            is_content(lines[i].text)
                && indent(lines[i].text) == depth
                && line_key(lines[i].text).is_some()
        })
        .collect();
    starts
        .iter()
        .enumerate()
        .map(|(n, &start)| {
            let next = starts.get(n + 1).copied().unwrap_or(to);
            // Up to the last content line before the next key.
            let end = (start..next)
                .rev()
                .find(|&i| is_content(lines[i].text))
                .map_or(start + 1, |i| i + 1);
            (start, end)
        })
        .collect()
}

fn line_span(lines: &[Line<'_>], start: usize, end: usize) -> ByteSpan {
    let last = &lines[end - 1];
    ByteSpan::new(lines[start].start, last.start + last.text.len())
}

/// A Tide object's outline: the object (named by `name`) holding its
/// top-level sections; `configurations` holds a node per platform block, and
/// each platform block, like `response`, holds the queries under it.
pub fn outline(source: &str) -> Vec<OutlineNode> {
    let source = opentide_core::strip_bom(source);
    let lines = lines(source);
    let injections = extract_injections(source);
    let mut sections = Vec::new();
    let mut object_name: Option<(String, ByteSpan)> = None;
    let mut uuid = None;
    for (start, end) in child_keys(&lines, 0, lines.len(), None) {
        // A document whose keys are all indented has no sections.
        if indent(lines[start].text) != 0 {
            break;
        }
        let Some((key, from, to)) = line_key(lines[start].text) else {
            continue;
        };
        let at = lines[start].start;
        let selection = ByteSpan::new(at + from, at + to);
        let span = line_span(&lines, start, end);
        if key == "name" {
            let value = lines[start].text[to + 1..].trim();
            let value = value.trim_matches(['"', '\'']);
            if !value.is_empty() {
                let offset = lines[start].text.find(value).unwrap_or(to + 1);
                object_name = Some((
                    value.to_string(),
                    ByteSpan::new(at + offset, at + offset + value.len()),
                ));
            }
        }
        if key == "metadata" {
            uuid = (start..end).find_map(|i| {
                let (k, _, to) = line_key(lines[i].text)?;
                (k == "uuid").then(|| {
                    lines[i].text[to + 1..]
                        .trim()
                        .trim_matches(['"', '\''])
                        .to_string()
                })
            });
        }
        let mut children = Vec::new();
        if key == "configurations" {
            for (p_start, p_end) in child_keys(&lines, start + 1, end, Some(0)) {
                let Some((platform, p_from, p_to)) = line_key(lines[p_start].text) else {
                    continue;
                };
                let p_at = lines[p_start].start;
                let p_span = line_span(&lines, p_start, p_end);
                let queries = queries_under(&injections, &["configurations", &platform], p_span);
                children.push(OutlineNode {
                    name: platform,
                    detail: None,
                    kind: OutlineKind::Platform,
                    span: p_span,
                    selection: ByteSpan::new(p_at + p_from, p_at + p_to),
                    children: queries,
                });
            }
        } else {
            children = queries_under(&injections, &[&key], span);
        }
        sections.push(OutlineNode {
            name: key,
            detail: None,
            kind: OutlineKind::Section,
            span,
            selection,
            children,
        });
    }
    let Some((name, selection)) = object_name else {
        return sections;
    };
    let end = sections.last().map_or(source.len(), |s| s.span.end);
    vec![OutlineNode {
        name,
        detail: uuid.filter(|u| !u.is_empty()),
        kind: OutlineKind::Object,
        span: ByteSpan::new(0, end.max(selection.end)),
        selection,
        children: sections,
    }]
}

/// The queries whose YAML path starts with `prefix`, named by the rest of it.
/// A query's span ends inside `within`: a block scalar's trailing newline
/// is not part of the block holding it.
fn queries_under(
    injections: &[crate::InjectedQuery],
    prefix: &[&str],
    within: ByteSpan,
) -> Vec<OutlineNode> {
    injections
        .iter()
        .filter(|q| {
            q.field_path.len() > prefix.len()
                && q.field_path.iter().zip(prefix).all(|(a, b)| a == b)
        })
        .map(|q| {
            let start = q.host_span.start.clamp(within.start, within.end);
            let span = ByteSpan::new(start, q.host_span.end.clamp(start, within.end));
            OutlineNode {
                name: q.field_path[prefix.len()..].join("."),
                detail: Some(q.language.as_str().to_string()),
                kind: OutlineKind::Query,
                span,
                selection: span,
                children: Vec::new(),
            }
        })
        .collect()
}

/// Where a [`TideLink`] goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkTarget {
    Url(String),
    /// The file of the object a UUID names.
    Object {
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TideLink {
    pub span: ByteSpan,
    pub target: LinkTarget,
    pub tooltip: String,
}

#[expect(
    clippy::expect_used,
    reason = "a regex literal: an invalid pattern fails every test that reaches it"
)]
fn attack_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"\b(?:TA\d{4}|T\d{4}(?:\.\d{3})?)\b").expect("ATT&CK id"))
}

#[expect(
    clippy::expect_used,
    reason = "a regex literal: an invalid pattern fails every test that reaches it"
)]
fn uuid_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
            .expect("UUID")
    })
}

/// The ATT&CK page of a technique (`T1059`, `T1059.001`) or tactic
/// (`TA0002`) id.
pub fn attack_url(id: &str) -> Option<String> {
    if let Some(rest) = id.strip_prefix("TA") {
        return (rest.len() == 4).then(|| format!("https://attack.mitre.org/tactics/{id}/"));
    }
    let rest = id.strip_prefix('T')?;
    Some(match rest.split_once('.') {
        Some((technique, sub)) => {
            format!("https://attack.mitre.org/techniques/T{technique}/{sub}/")
        }
        None => format!("https://attack.mitre.org/techniques/{id}/"),
    })
}

/// The links in a Tide object: each ATT&CK technique or tactic id to its
/// page, and each UUID of another object in `workspace` to that object's
/// file. The object's own UUID is not a link.
pub fn document_links(source: &str, workspace: &[IndexedObject]) -> Vec<TideLink> {
    let source = opentide_core::strip_bom(source);
    let own = own_uuid(source).map(|(uuid, _)| uuid);
    let mut out = Vec::new();
    for m in attack_pattern().find_iter(source) {
        if let Some(url) = attack_url(m.as_str()) {
            out.push(TideLink {
                span: ByteSpan::new(m.start(), m.end()),
                tooltip: format!("MITRE ATT&CK {}", m.as_str()),
                target: LinkTarget::Url(url),
            });
        }
    }
    for m in uuid_pattern().find_iter(source) {
        if own.as_deref() == Some(m.as_str()) {
            continue;
        }
        if let Some(object) = workspace.iter().find(|o| o.uuid == m.as_str()) {
            out.push(TideLink {
                span: ByteSpan::new(m.start(), m.end()),
                tooltip: format!("{} {}", object.object_type, object.name),
                target: LinkTarget::Object {
                    path: object.path.clone(),
                },
            });
        }
    }
    out.sort_by_key(|link| link.span.start);
    out
}

/// The object's own UUID (`metadata.uuid`) and its span.
fn own_uuid(source: &str) -> Option<(String, ByteSpan)> {
    let lines = lines(source);
    let mut in_metadata = false;
    for line in &lines {
        if indent(line.text) == 0 && is_content(line.text) {
            in_metadata = line_key(line.text).is_some_and(|(k, _, _)| k == "metadata");
            continue;
        }
        if !in_metadata {
            continue;
        }
        let Some((key, _, to)) = line_key(line.text) else {
            continue;
        };
        if key != "uuid" {
            continue;
        }
        let m = uuid_pattern().find(&line.text[to..])?;
        let start = line.start + to + m.start();
        return Some((
            m.as_str().to_string(),
            ByteSpan::new(start, start + m.len()),
        ));
    }
    None
}

/// The objects that reference a Tide object, for a "N rules use this" lens
/// on its UUID.
#[derive(Debug, Clone)]
pub struct ReferenceLens {
    /// The object's own UUID in its `metadata`.
    pub span: ByteSpan,
    pub uuid: String,
    /// The objects of `workspace` whose YAML names the UUID, in index order.
    pub referenced_by: Vec<IndexedObject>,
}

/// Who references the object `source` defines, or `None` without a
/// `metadata.uuid`.
pub fn reference_lens(source: &str, workspace: &[IndexedObject]) -> Option<ReferenceLens> {
    let source = opentide_core::strip_bom(source);
    let (uuid, span) = own_uuid(source)?;
    let referenced_by = find_refs(workspace, &uuid)
        .into_iter()
        .filter(|o| o.uuid != uuid)
        .cloned()
        .collect();
    Some(ReferenceLens {
        span,
        uuid,
        referenced_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = "name: Suspicious PowerShell\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\ndetection_model: 00000000-0000-4000-8002-000000000001\ndescription: T1059.001 and TA0002\nconfigurations:\n  sentinel:\n    query: |\n      SecurityEvent\n      | where EventID == 4688\n\n  splunk:\n    query: index=main\n";

    #[test]
    fn the_outline_nests_sections_platforms_and_queries() {
        let tree = outline(RULE);
        assert_eq!(tree.len(), 1);
        let object = &tree[0];
        assert_eq!(object.kind, OutlineKind::Object);
        assert_eq!(object.name, "Suspicious PowerShell");
        assert_eq!(
            object.detail.as_deref(),
            Some("00000000-0000-4000-8003-000000000001")
        );
        let names: Vec<&str> = object.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "name",
                "metadata",
                "detection_model",
                "description",
                "configurations"
            ]
        );
        let configurations = object.children.last().unwrap();
        let platforms: Vec<&str> = configurations
            .children
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(platforms, ["sentinel", "splunk"]);
        let sentinel = &configurations.children[0];
        assert_eq!(sentinel.children.len(), 1);
        assert_eq!(sentinel.children[0].name, "query");
        assert_eq!(sentinel.children[0].kind, OutlineKind::Query);
        assert_eq!(sentinel.children[0].detail.as_deref(), Some("kql"));
        // Every child lies within its parent, and a blank line ends no block.
        for node in [object, configurations, sentinel] {
            for child in &node.children {
                assert!(node.span.start <= child.span.start && child.span.end <= node.span.end);
                assert!(child.span.start <= child.selection.start);
            }
        }
        assert_eq!(
            &RULE[sentinel.selection.start..sentinel.selection.end],
            "sentinel"
        );
        assert!(RULE[sentinel.span.start..sentinel.span.end].ends_with("4688"));
    }

    #[test]
    fn a_document_without_a_name_is_its_sections() {
        let tree = outline("metadata:\n  uuid: x\nconfigurations:\n  elastic:\n    query: a\n");
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[1].children[0].name, "elastic");
    }

    #[test]
    fn attack_ids_link_to_their_pages() {
        assert_eq!(
            attack_url("T1059.001").as_deref(),
            Some("https://attack.mitre.org/techniques/T1059/001/")
        );
        assert_eq!(
            attack_url("T1059").as_deref(),
            Some("https://attack.mitre.org/techniques/T1059/")
        );
        assert_eq!(
            attack_url("TA0002").as_deref(),
            Some("https://attack.mitre.org/tactics/TA0002/")
        );
        let links = document_links(RULE, &[]);
        let ids: Vec<&str> = links
            .iter()
            .map(|l| &RULE[l.span.start..l.span.end])
            .collect();
        assert_eq!(ids, ["T1059.001", "TA0002"]);
    }

    fn object(path: &str, kind: &str, uuid: &str, body: &str) -> IndexedObject {
        IndexedObject::from_body(
            path,
            kind,
            uuid,
            format!("{kind} {uuid}"),
            serde_yaml::from_str(body).unwrap(),
        )
    }

    #[test]
    fn uuids_of_other_objects_link_to_their_files_and_count_as_references() {
        let model = "00000000-0000-4000-8002-000000000001";
        let workspace = [
            object("/w/objects/models/m.yaml", "objective", model, "{}"),
            object(
                "/w/objects/rules/r.yaml",
                "rule",
                "00000000-0000-4000-8003-000000000001",
                &format!("detection_model: {model}"),
            ),
        ];
        let links = document_links(RULE, &workspace);
        let objects: Vec<&LinkTarget> = links
            .iter()
            .filter(|l| matches!(l.target, LinkTarget::Object { .. }))
            .map(|l| &l.target)
            .collect();
        // The rule's own UUID is not a link.
        assert_eq!(
            objects,
            [&LinkTarget::Object {
                path: "/w/objects/models/m.yaml".into()
            }]
        );
        let objective = format!("name: M\nmetadata:\n  uuid: {model}\n  schema: objective::1.0\n");
        let lens = reference_lens(&objective, &workspace).unwrap();
        assert_eq!(lens.uuid, model);
        assert_eq!(&objective[lens.span.start..lens.span.end], model);
        assert_eq!(lens.referenced_by.len(), 1);
        assert_eq!(lens.referenced_by[0].object_type, "rule");
        assert!(reference_lens("name: x\n", &workspace).is_none());
    }
}
