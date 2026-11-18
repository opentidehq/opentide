//! The bundled catalog's lookups, built once per process (ADR 0014, rule
//! 2): an analysis looks up each command, function, field and data model it
//! meets, and each lookup scanned the catalog's rows. A lookup through the
//! index finds exactly the row the scan found: the first row that matches,
//! by the same rule (`the_indexes_find_what_a_scan_finds`). A catalog that is
//! not the bundled one keeps the scan.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

use opentide_core::suggest::Candidates;

use crate::Catalog;

pub(crate) struct Index {
    /// A command's ASCII-lower-case name → its first row.
    commands: HashMap<String, usize>,
    /// A function's ASCII-lower-case name → its rows, in catalog order.
    functions: HashMap<String, Vec<usize>>,
    /// A field's name → its first row.
    fields: HashMap<&'static str, usize>,
    /// A data model's ASCII-lower-case name or prefix → the first row with
    /// either.
    datamodels: HashMap<String, usize>,
    /// The command names, prepared for suggestions.
    pub(crate) command_names: Candidates,
    /// Each command's ASCII-lower-case name and its length in characters,
    /// in catalog order: what the typo test compares.
    pub(crate) lowered_commands: Vec<(String, usize)>,
}

#[cfg(test)]
thread_local! {
    /// Catalog rows compared by a lookup that scanned (the work the index
    /// saves).
    pub(crate) static ROWS_SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts `rows` rows compared by a scan, in tests.
pub(crate) fn scanned(rows: usize) {
    #[cfg(test)]
    ROWS_SCANNED.set(ROWS_SCANNED.get() + rows);
    let _ = rows;
}

/// `name` in ASCII lower case, borrowed when it already is.
pub(crate) fn lower(name: &str) -> Cow<'_, str> {
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    }
}

impl Index {
    /// The index of `catalog`, when it is the bundled one.
    pub(crate) fn of(catalog: &Catalog) -> Option<&'static Index> {
        static INDEX: OnceLock<Index> = OnceLock::new();
        let bundled = Catalog::cached();
        std::ptr::eq(catalog, bundled).then(|| INDEX.get_or_init(|| Index::new(bundled)))
    }

    fn new(catalog: &'static Catalog) -> Self {
        let mut commands = HashMap::new();
        for (i, c) in catalog.commands.iter().enumerate() {
            commands.entry(c.name.to_ascii_lowercase()).or_insert(i);
        }
        let mut functions: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, f) in catalog.functions.iter().enumerate() {
            functions
                .entry(f.name.to_ascii_lowercase())
                .or_default()
                .push(i);
        }
        let mut fields = HashMap::new();
        for (i, f) in catalog.fields.iter().enumerate() {
            fields.entry(f.name.as_str()).or_insert(i);
        }
        let mut datamodels = HashMap::new();
        for (i, d) in catalog.datamodels.iter().enumerate() {
            datamodels.entry(d.name.to_ascii_lowercase()).or_insert(i);
            datamodels.entry(d.prefix.to_ascii_lowercase()).or_insert(i);
        }
        Self {
            commands,
            functions,
            fields,
            datamodels,
            command_names: Candidates::new(catalog.commands.iter().map(|c| c.name.as_str())),
            lowered_commands: catalog
                .commands
                .iter()
                .map(|c| {
                    let lower = c.name.to_ascii_lowercase();
                    let length = lower.chars().count();
                    (lower, length)
                })
                .collect(),
        }
    }

    pub(crate) fn command(&self, name: &str) -> Option<usize> {
        self.commands.get(lower(name).as_ref()).copied()
    }

    pub(crate) fn functions(&self, name: &str) -> &[usize] {
        self.functions
            .get(lower(name).as_ref())
            .map_or(&[], Vec::as_slice)
    }

    /// The first row named `name` or `bare`.
    pub(crate) fn field(&self, name: &str, bare: &str) -> Option<usize> {
        let a = self.fields.get(name).copied();
        let b = self.fields.get(bare).copied();
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub(crate) fn datamodel(&self, name: &str) -> Option<usize> {
        self.datamodels.get(lower(name).as_ref()).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name of the catalog, in its own case, lower, upper and mixed,
    /// with a dotted prefix, and unknown and empty names.
    fn probes(catalog: &Catalog) -> Vec<String> {
        let mut names: Vec<String> = catalog
            .commands
            .iter()
            .map(|c| c.name.clone())
            .chain(catalog.functions.iter().map(|f| f.name.clone()))
            .chain(catalog.fields.iter().map(|f| f.name.clone()))
            .chain(
                catalog
                    .datamodels
                    .iter()
                    .flat_map(|d| [d.name.clone(), d.prefix.clone()]),
            )
            .collect();
        names.extend(
            [
                "",
                "zz",
                "nosuchname",
                "stast",
                "statz",
                "tsast",
                "evall",
                "ëval",
            ]
            .map(str::to_owned),
        );
        let mut out = Vec::new();
        for name in names {
            let mixed: String = name
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();
            out.extend([
                name.to_ascii_lowercase(),
                name.to_ascii_uppercase(),
                format!("Processes.{name}"),
                mixed,
                name,
            ]);
        }
        out
    }

    /// The position of `found` among `rows`: the row itself, not only its
    /// name.
    fn row<T>(rows: &[T], found: Option<&T>) -> Option<usize> {
        found.and_then(|f| rows.iter().position(|r| std::ptr::eq(r, f)))
    }

    /// `field`'s first row of the name or of the name after its last dot,
    /// the earlier of the two, as the scan finds it (the bundled catalog has
    /// no dotted field, so its own names never take this branch).
    #[test]
    fn a_field_lookup_takes_the_earlier_of_the_name_and_its_last_part() {
        let index = Index {
            commands: HashMap::new(),
            functions: HashMap::new(),
            fields: HashMap::from([("a.b", 3), ("b", 1), ("c", 0), ("a.c", 2)]),
            datamodels: HashMap::new(),
            command_names: Candidates::new([]),
            lowered_commands: Vec::new(),
        };
        assert_eq!(index.field("a.b", "b"), Some(1));
        assert_eq!(index.field("a.c", "c"), Some(0));
        assert_eq!(index.field("x.b", "b"), Some(1));
        assert_eq!(index.field("a.b", "z"), Some(3));
        assert_eq!(index.field("b", "b"), Some(1));
        assert_eq!(index.field("x.y", "y"), None);
    }

    /// A lookup through the index finds the row a scan finds, and a typo or
    /// a suggestion is the scan's, over every name of the catalog.
    #[test]
    fn the_indexes_find_what_a_scan_finds() {
        let bundled = Catalog::cached();
        let scanned = Catalog::load();
        assert!(Index::of(bundled).is_some() && Index::of(&scanned).is_none());
        for name in probes(bundled) {
            assert_eq!(
                bundled.command(&name).map(|r| &r.name),
                scanned.command(&name).map(|r| &r.name),
                "{name}"
            );
            assert_eq!(
                row(&bundled.functions, bundled.function(&name)),
                row(&scanned.functions, scanned.function(&name)),
                "{name}"
            );
            for aggregate in [false, true] {
                assert_eq!(
                    row(
                        &bundled.functions,
                        bundled.function_in_context(&name, aggregate)
                    ),
                    row(
                        &scanned.functions,
                        scanned.function_in_context(&name, aggregate)
                    ),
                    "{name}"
                );
            }
            assert_eq!(
                bundled.field(&name).map(|r| (&r.name, &r.kind, &r.models)),
                scanned.field(&name).map(|r| (&r.name, &r.kind, &r.models)),
                "{name}"
            );
            assert_eq!(
                bundled.datamodel(&name).map(|r| (&r.name, &r.prefix)),
                scanned.datamodel(&name).map(|r| (&r.name, &r.prefix)),
                "{name}"
            );
            assert_eq!(
                bundled.command_typos(&name),
                scanned.command_typos(&name),
                "{name}"
            );
            assert_eq!(
                bundled.suggest_command(&name),
                scanned.suggest_command(&name),
                "{name}"
            );
        }
    }

    /// The bundled catalog's lookups compare no rows, and an unrelated name
    /// measures no typo distance (ADR 0014, rule 7): each scanned the whole
    /// catalog.
    #[test]
    fn lookups_on_the_bundled_catalog_scan_no_rows() {
        let catalog = Catalog::cached();
        let rows = ROWS_SCANNED.get();
        let distances = crate::DISTANCES.get();
        for name in [
            "stats",
            "EVAL",
            "coalesce",
            "src_ip",
            "Processes.dest",
            "Endpoint",
            "nosuch",
        ] {
            let _ = (
                catalog.command(name),
                catalog.function(name),
                catalog.function_in_context(name, true),
                catalog.field(name),
                catalog.datamodel(name),
            );
        }
        assert_eq!(ROWS_SCANNED.get() - rows, 0);
        assert!(
            catalog
                .command_typos("averyunrelatedcommandname")
                .is_empty()
        );
        assert_eq!(crate::DISTANCES.get() - distances, 0);
        // A near name is still measured, and found.
        assert!(catalog.command_typos("stast").contains(&"stats"));
        assert!(crate::DISTANCES.get() - distances > 0);
    }
}
