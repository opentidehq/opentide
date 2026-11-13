//! malapi.io's pages, parsed with html5ever (the WHATWG tree construction
//! browsers use) into `markup5ever_rcdom`'s tree: the front page's attack
//! categories and API names ([`front_page`]), and one API's page as a
//! vocabulary key ([`api_page`]).
//!
//! The Python scraper (`generate_malapi.py`) read the front page with lxml,
//! whose lenient tree keeps markup where the source puts it. html5ever moves
//! what a table may not hold (foster parenting), so the API names are not
//! looked for by their place in `#main-table`'s rows but by what they are:
//! the links to a `/winapi/<name>` page. A front page with no such link is an
//! error, never an empty scrape that would remove every key.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use html5ever::tendril::TendrilSink;
use html5ever::{ParseOpts, parse_document};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

use super::super::ingest::value::{Table, Value, strip};

/// The site.
pub const MALAPI_URL: &str = "https://malapi.io";

/// An API page's headings and the key fields they fill.
const FIELDS: [(&str, &str); 5] = [
    ("Function Name", "name"),
    ("Description", "description"),
    ("Library", "library"),
    ("Associated Attacks", "tide.vocab.stages"),
    ("Documentation", "link"),
];

/// A parsed HTML document.
fn parse(html: &str) -> Handle {
    parse_document(RcDom::default(), ParseOpts::default())
        .one(html)
        .document
}

/// The elements under `node`, in document order, `node` left out.
fn descendants(node: &Handle) -> Vec<Handle> {
    let mut found = Vec::new();
    let mut stack: Vec<Handle> = node.children.borrow().iter().rev().cloned().collect();
    while let Some(next) = stack.pop() {
        stack.extend(next.children.borrow().iter().rev().cloned());
        if matches!(next.data, NodeData::Element { .. }) {
            found.push(next);
        }
    }
    found
}

/// Whether `node` is a `tag` element.
fn is(node: &Handle, tag: &str) -> bool {
    match &node.data {
        NodeData::Element { name, .. } => &*name.local == tag,
        _ => false,
    }
}

/// An attribute's value.
fn attribute(node: &Handle, attribute: &str) -> Option<String> {
    let NodeData::Element { attrs, .. } = &node.data else {
        return None;
    };
    attrs
        .borrow()
        .iter()
        .find(|attr| &*attr.name.local == attribute)
        .map(|attr| attr.value.to_string())
}

/// Whether `node`'s `class` list holds `class`.
fn has_class(node: &Handle, class: &str) -> bool {
    attribute(node, "class").is_some_and(|classes| classes.split_whitespace().any(|c| c == class))
}

/// The first element under `node` that `wanted` accepts.
fn find(node: &Handle, wanted: impl Fn(&Handle) -> bool) -> Option<Handle> {
    descendants(node)
        .into_iter()
        .find(|element| wanted(element))
}

/// The text under `node`, every text node joined (BeautifulSoup's `.text`).
fn text(node: &Handle) -> String {
    let mut out = String::new();
    let mut stack = vec![node.clone()];
    while let Some(next) = stack.pop() {
        if let NodeData::Text { contents } = &next.data {
            out.push_str(&contents.borrow());
        }
        stack.extend(next.children.borrow().iter().rev().cloned());
    }
    out
}

/// Whether `name` can be an API's name: a Windows identifier. It goes into a
/// URL and a file name, so nothing else is accepted.
pub fn valid_api(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `href` points at an API's page: `/winapi/<name>`, relative or on
/// the site.
fn api_link(href: &str) -> bool {
    let path = href.strip_prefix(MALAPI_URL).unwrap_or(href);
    let path = path.strip_prefix('/').unwrap_or(path);
    path.strip_prefix("winapi/")
        .map(|rest| rest.strip_suffix('/').unwrap_or(rest))
        .is_some_and(|name| !name.is_empty() && !name.contains(['/', '?', '#']))
}

/// What the front page lists.
#[derive(Debug, Clone, PartialEq)]
pub struct FrontPage {
    /// The attack categories, `{name, description}`, in the table's order:
    /// the vocabulary's `stages`.
    pub stages: Vec<Table>,
    /// Every API name, sorted, each once.
    pub apis: Vec<String>,
}

/// The front page's categories (`#main-table`'s `th` cells: the name, and
/// the description in the icon's `title`) and API names (the text of every
/// link to an API's page).
pub fn front_page(html: &str) -> Result<FrontPage> {
    let document = parse(html);
    let table = find(&document, |node| {
        is(node, "table") && attribute(node, "id").as_deref() == Some("main-table")
    })
    .with_context(|| format!("No main-table on {MALAPI_URL}"))?;

    let mut stages = Vec::new();
    for cell in descendants(&table).iter().filter(|node| is(node, "th")) {
        let name = strip(&text(cell)).to_owned();
        let description = find(cell, |node| is(node, "img"))
            .and_then(|icon| attribute(&icon, "title"))
            .with_context(|| format!("the category `{name}` has no icon title on {MALAPI_URL}"))?;
        let mut stage = Table::new();
        stage.insert("name".to_owned(), Value::from(name));
        stage.insert("description".to_owned(), Value::from(strip(&description)));
        stages.push(stage);
    }
    ensure!(!stages.is_empty(), "No attack category on {MALAPI_URL}");

    let mut apis = BTreeSet::new();
    for link in descendants(&document).iter().filter(|node| is(node, "a")) {
        if attribute(link, "href").is_some_and(|href| api_link(&href)) {
            let name = strip(&text(link)).to_owned();
            ensure!(
                valid_api(&name),
                "the API link `{name}` on {MALAPI_URL} is not an identifier"
            );
            apis.insert(name);
        }
    }
    ensure!(!apis.is_empty(), "No API link on {MALAPI_URL}");
    Ok(FrontPage {
        stages,
        apis: apis.into_iter().collect(),
    })
}

/// One `/winapi/<api>` page as a vocabulary key: `name`, `description` (the
/// library appended as "\nLibrary : `X`"), `link`, and `tide.vocab.stages`
/// (one category as a string, several as a list).
pub fn api_page(api: &str, html: &str) -> Result<Table> {
    let document = parse(html);
    let mut details = Table::new();
    for container in descendants(&document)
        .iter()
        .filter(|node| has_class(node, "detail-container"))
    {
        let heading = find(container, |node| {
            is(node, "div") && has_class(node, "heading")
        });
        let content = find(container, |node| {
            is(node, "div") && has_class(node, "content")
        });
        let (Some(heading), Some(content)) = (heading, content) else {
            continue;
        };
        if let Some((_, field)) = FIELDS
            .iter()
            .find(|(label, _)| *label == strip(&text(&heading)))
        {
            details.insert(
                (*field).to_owned(),
                Value::from(strip(&text(&content)).to_owned()),
            );
        }
    }
    if details.is_empty() {
        bail!("Empty parsed API: {api}");
    }
    ensure!(
        details
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty()),
        "the page of {api} has no Function Name"
    );

    if let Some(Value::String(library)) = details.remove("library")
        && !library.is_empty()
    {
        let Some(Value::String(description)) = details.get_mut("description") else {
            bail!("the page of {api} names a library but has no Description");
        };
        description.push_str(&format!("\nLibrary : `{library}`"));
    }
    if let Some(Value::String(stages)) = details.get("tide.vocab.stages") {
        let mut names: Vec<Value> = stages
            .lines()
            .map(strip)
            .filter(|line| !line.is_empty())
            .map(Value::from)
            .collect();
        let stages = if names.len() == 1 {
            names.remove(0)
        } else {
            Value::Array(names)
        };
        details.insert("tide.vocab.stages".to_owned(), stages);
    }
    Ok(details)
}
