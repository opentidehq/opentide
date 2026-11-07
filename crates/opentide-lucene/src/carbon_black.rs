//! Carbon Black Cloud process search fields (#162): the catalog the Carbon
//! Black dialect checks fields against and documents them from
//! (`data/catalogs/carbon_black/fields.toml`, with its sources).

use opentide_core::{ByteSpan, CompletionItem, Diagnostic, codes, span_to_range};
use serde::Deserialize;
use std::sync::OnceLock;
use tree_sitter::Node;

const FIELDS_TOML: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/data/catalogs/carbon_black/fields.toml"
));

/// One process search field.
#[derive(Debug, Clone, Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub list: bool,
    pub description: String,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Deserialize)]
struct Catalog {
    field: Vec<Field>,
}

/// The process search fields, read once.
pub fn fields() -> &'static [Field] {
    static FIELDS: OnceLock<Vec<Field>> = OnceLock::new();
    FIELDS.get_or_init(|| {
        toml::from_str::<Catalog>(FIELDS_TOML)
            .expect("data/catalogs/carbon_black/fields.toml")
            .field
    })
}

pub fn field(name: &str) -> Option<&'static Field> {
    fields().iter().find(|f| f.name == name)
}

/// Edit distance, an adjacent swap counting one.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// The catalog field a name is a near miss of: within two edits, and closer
/// than any other. A name far from every field may be one the catalog lacks,
/// and is left alone.
pub fn near_miss(name: &str) -> Option<&'static Field> {
    if field(name).is_some() || name.contains('*') || name.len() < 4 {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    let mut best: Option<(usize, &'static Field)> = None;
    for f in fields() {
        let d = distance(&lower, &f.name);
        if d <= 2 && best.is_none_or(|(b, _)| d < b) {
            best = Some((d, f));
        }
    }
    best.map(|(_, f)| f)
}

/// `cbc_unknown_field` on a `field_name` node that misspells a catalog field.
pub fn check_field(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let name = source.get(node.start_byte()..node.end_byte()).unwrap_or("");
    let Some(f) = near_miss(name) else {
        return;
    };
    out.push(
        Diagnostic::warning(
            codes::CBC_UNKNOWN_FIELD,
            format!(
                "`{name}` is not a Carbon Black Cloud process search field; did you mean `{}`?",
                f.name
            ),
            span_to_range(source, ByteSpan::new(node.start_byte(), node.end_byte())),
        )
        .with_suggestion(f.name.clone()),
    );
}

/// A field's documentation, as hover shows it.
pub fn markdown(f: &Field) -> String {
    let kind = if f.list {
        format!("{} (several values)", f.kind)
    } else {
        f.kind.clone()
    };
    let mut out = format!(
        "**`{}`** `{kind}` (Carbon Black Cloud process search)\n\n{}",
        f.name, f.description
    );
    if !f.values.is_empty() {
        let values: Vec<String> = f.values.iter().map(|v| format!("`{v}`")).collect();
        out.push_str(&format!("\n\nValues: {}", values.join(", ")));
    }
    out
}

/// Completion in a Carbon Black query: the values of the field before the
/// cursor (`device_os:`), else every field.
pub fn completions(before: &str) -> Vec<CompletionItem> {
    let token = before
        .rsplit(|c: char| c.is_whitespace() || matches!(c, '(' | ')'))
        .next()
        .unwrap_or("")
        .trim_start_matches(['-', '+']);
    if let Some((name, _)) = token.split_once(':') {
        return field(name)
            .map(|f| {
                f.values
                    .iter()
                    .map(|v| CompletionItem::new(v.clone(), "enum").with_detail(f.name.clone()))
                    .collect()
            })
            .unwrap_or_default();
    }
    fields()
        .iter()
        .map(|f| {
            CompletionItem::new(f.name.clone(), "property")
                .with_detail(f.kind.clone())
                .with_docs(markdown(f))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_loads_and_names_each_field_once() {
        let names: std::collections::BTreeSet<&str> =
            fields().iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names.len(), fields().len());
        assert!(field("process_name").is_some());
        assert_eq!(
            field("device_os").unwrap().values,
            ["WINDOWS", "LINUX", "MAC"]
        );
    }

    #[test]
    fn near_misses_suggest_the_field() {
        assert_eq!(near_miss("process_nmae").unwrap().name, "process_name");
        assert_eq!(near_miss("parent_nme").unwrap().name, "parent_name");
        assert!(near_miss("process_name").is_none());
        assert!(near_miss("my_custom_field").is_none());
        assert!(near_miss("process_*").is_none());
    }

    #[test]
    fn completion_offers_fields_or_a_fields_values() {
        assert!(completions("").iter().any(|i| i.label == "process_cmdline"));
        let os: Vec<String> = completions("device_os:")
            .into_iter()
            .map(|i| i.label)
            .collect();
        assert_eq!(os, ["WINDOWS", "LINUX", "MAC"]);
    }
}
