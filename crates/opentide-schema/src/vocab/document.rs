//! One vocabulary: a `{field}.vocab.toml` document read into metadata and
//! keyed entries.

use indexmap::IndexMap;
use toml::{Table, Value};

use super::{Version, VocabError};

/// The file name suffix of a vocabulary document.
pub const SUFFIX: &str = ".vocab.toml";

/// What entries are indexed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// The entry's `name` (`tlp`: `amber`).
    Name,
    /// The entry's external `id` (`att&ck`: `T1059`).
    Id,
}

/// A stage of a vocabulary: a group of its entries (`surface`'s `OS`,
/// `att&ck`'s tactics). A stage written as a bare string has a name and no id.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Stage {
    /// The stage id, the prefix of a scoped value (`OS` in `OS::Windows`).
    pub id: Option<String>,
    /// The display name.
    pub name: Option<String>,
    /// The description.
    pub description: Option<String>,
}

/// A vocabulary's metadata: everything in the document but its entries.
#[derive(Debug, Clone, PartialEq)]
pub struct Metadata {
    /// The display name (`Traffic Light Protocol`).
    pub name: String,
    /// The field name, which is also the file name's stem (`tlp`).
    pub field: String,
    /// The description.
    pub description: String,
    /// The icon.
    pub icon: String,
    /// What entries are indexed by.
    pub key: KeyKind,
    /// The stages, in order.
    pub stages: Vec<Stage>,
    /// Every other top-level key (`source_version`, `reference`,
    /// `vocab.search_hints`, …).
    pub extra: Table,
}

/// One vocabulary entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// The key it is indexed by: its name or its id.
    pub key: String,
    /// The display name.
    pub name: String,
    /// The version that added it.
    pub version: Version,
    /// The version that removed it, if any.
    pub removed: Option<Version>,
    /// The description.
    pub description: String,
    /// The icon.
    pub icon: String,
    /// The link.
    pub link: String,
    /// The stages it belongs to (`tide.vocab.stages`), in order.
    pub stages: Vec<String>,
    /// Every other key of the entry (`id`, `alias`, `misp`, …).
    pub extra: Table,
}

impl Entry {
    /// Whether the entry belongs to a vocabulary pinned at `pin`: added at or
    /// before it, and not removed at or before it.
    pub fn active_at(&self, pin: Version) -> bool {
        self.version <= pin && self.removed.is_none_or(|removed| removed > pin)
    }
}

/// A loaded vocabulary.
#[derive(Debug, Clone, PartialEq)]
pub struct Vocabulary {
    /// The metadata.
    pub metadata: Metadata,
    /// The entries by key, in the document's order.
    pub entries: IndexMap<String, Entry>,
    /// Entries the document holds that could not be read, each with why.
    /// They are left out; the vocabulary still loads.
    pub skipped: Vec<String>,
}

impl Vocabulary {
    /// The field name.
    pub fn field(&self) -> &str {
        &self.metadata.field
    }

    /// The ids of the stages that have one, in order.
    pub fn stage_ids(&self) -> impl Iterator<Item = &str> {
        self.metadata.stages.iter().filter_map(|s| s.id.as_deref())
    }

    /// Whether editors get search hints for it (`vocab.search_hints`, on
    /// unless set to false).
    pub fn search_hints(&self) -> bool {
        !matches!(
            self.metadata.extra.get("vocab.search_hints"),
            Some(Value::Boolean(false))
        )
    }

    /// Reads the document `text` of the file `file_name`
    /// (`{field}.vocab.toml`), whose `field` must be the file name's stem.
    pub fn from_file(file_name: &str, text: &str) -> Result<Self, VocabError> {
        let stem = file_name
            .strip_suffix(SUFFIX)
            .ok_or_else(|| VocabError::NotAVocabularyFile(file_name.to_owned()))?;
        let vocabulary = Self::parse(text, file_name)?;
        if vocabulary.field() != stem {
            return Err(VocabError::FieldMismatch {
                file: file_name.to_owned(),
                field: vocabulary.field().to_owned(),
                expected: stem.to_owned(),
            });
        }
        Ok(vocabulary)
    }

    /// Reads a vocabulary document; `source` names it in errors.
    pub fn parse(text: &str, source: &str) -> Result<Self, VocabError> {
        let table: Table = toml::from_str(text).map_err(|error| VocabError::Toml {
            file: source.to_owned(),
            message: error.to_string(),
        })?;
        Self::from_table(table, source)
    }

    /// Reads a vocabulary document already parsed as TOML.
    pub fn from_table(mut table: Table, source: &str) -> Result<Self, VocabError> {
        let missing = |key: &str| VocabError::MissingKey {
            file: source.to_owned(),
            key: key.to_owned(),
        };
        let invalid = |key: &str, why: &str| VocabError::InvalidKey {
            file: source.to_owned(),
            key: key.to_owned(),
            why: why.to_owned(),
        };
        let name = table.remove("name").ok_or_else(|| missing("name"))?;
        let name = text_of(&name).ok_or_else(|| invalid("name", "not a string"))?;
        let field = table.remove("field").ok_or_else(|| missing("field"))?;
        let Value::String(field) = field else {
            return Err(invalid("field", "not a string"));
        };
        if field.is_empty() {
            return Err(invalid("field", "empty"));
        }
        let key = match (table.remove("key"), table.remove("model")) {
            (Some(Value::String(key)), _) if key == "name" => KeyKind::Name,
            (Some(Value::String(key)), _) if key == "id" => KeyKind::Id,
            (Some(_), _) => return Err(invalid("key", "neither `name` nor `id`")),
            (None, Some(Value::Boolean(true))) => KeyKind::Id,
            (None, Some(Value::Boolean(false)) | None) => KeyKind::Name,
            (None, Some(_)) => return Err(invalid("model", "not a boolean")),
        };
        let entries_raw = match table.remove("keys") {
            None => Vec::new(),
            Some(Value::Array(entries)) => entries,
            Some(_) => return Err(invalid("keys", "not a list")),
        };
        let stages = match table.remove("stages") {
            None => Vec::new(),
            Some(Value::Array(stages)) => stages
                .iter()
                .map(|stage| {
                    stage_of(stage)
                        .ok_or_else(|| invalid("stages", "a stage is neither a string nor a table"))
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(invalid("stages", "not a list")),
        };
        let description = take_text(&mut table, "description")
            .map_err(|()| invalid("description", "not a string"))?;
        let icon = take_text(&mut table, "icon").map_err(|()| invalid("icon", "not a string"))?;

        let mut entries = IndexMap::with_capacity(entries_raw.len());
        let mut skipped = Vec::new();
        for (index, raw) in entries_raw.into_iter().enumerate() {
            match entry_of(raw, key) {
                Ok(entry) => {
                    if entries.contains_key(&entry.key) {
                        return Err(VocabError::DuplicateKey {
                            file: source.to_owned(),
                            key: entry.key,
                            index,
                        });
                    }
                    entries.insert(entry.key.clone(), entry);
                }
                Err(why) => skipped.push(format!("entry {index}: {why}")),
            }
        }
        Ok(Self {
            metadata: Metadata {
                name,
                field,
                description,
                icon,
                key,
                stages,
                extra: table,
            },
            entries,
            skipped,
        })
    }
}

/// A scalar's text: a string as written, a number or a boolean in decimal
/// or `true`/`false`. Arrays, tables and dates are not text.
fn text_of(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Integer(number) => Some(number.to_string()),
        Value::Float(number) if number.fract() == 0.0 && number.is_finite() => {
            Some(format!("{number:.1}"))
        }
        Value::Float(number) => Some(number.to_string()),
        Value::Boolean(flag) => Some(flag.to_string()),
        Value::Datetime(_) | Value::Array(_) | Value::Table(_) => None,
    }
}

fn take_text(table: &mut Table, key: &str) -> Result<String, ()> {
    match table.remove(key) {
        None => Ok(String::new()),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(()),
    }
}

fn stage_of(value: &Value) -> Option<Stage> {
    match value {
        Value::String(name) => Some(Stage {
            id: None,
            name: Some(name.clone()),
            description: None,
        }),
        Value::Table(table) => {
            let text = |key: &str| table.get(key).and_then(text_of);
            Some(Stage {
                id: text("id"),
                name: text("name"),
                description: text("description"),
            })
        }
        _ => None,
    }
}

fn entry_of(raw: Value, key: KeyKind) -> Result<Entry, String> {
    let Value::Table(mut table) = raw else {
        return Err("not a table".to_owned());
    };
    let name = table.remove("name").ok_or_else(|| "no `name`".to_owned())?;
    let name = text_of(&name).ok_or_else(|| "`name` is not text".to_owned())?;
    let key_text = match key {
        KeyKind::Name => name.clone(),
        KeyKind::Id => table
            .get("id")
            .ok_or_else(|| "no `id`".to_owned())
            .and_then(|id| text_of(id).ok_or_else(|| "`id` is not text".to_owned()))?,
    };
    if key_text.is_empty() {
        return Err("an empty key".to_owned());
    }
    let version = match table.remove("version") {
        None => Version::new(1, 0),
        Some(value) => text_of(&value)
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| format!("`version` {value} is not M.m"))?,
    };
    let removed = match table.remove("removed") {
        None | Some(Value::Boolean(false)) => None,
        Some(Value::String(text)) if text.is_empty() => None,
        Some(value) => Some(
            text_of(&value)
                .and_then(|text| text.parse().ok())
                .ok_or_else(|| format!("`removed` {value} is not M.m"))?,
        ),
    };
    let mut stages_raw = table.remove("tide.vocab.stages");
    if stages_raw.is_none() {
        stages_raw = table
            .get("tide")
            .and_then(|tide| tide.get("vocab"))
            .and_then(|vocab| vocab.get("stages"))
            .cloned();
    }
    let stages = match stages_raw {
        None => Vec::new(),
        Some(Value::String(stage)) => vec![stage],
        Some(Value::Array(stages)) => stages
            .into_iter()
            .map(|stage| match stage {
                Value::String(stage) => Ok(stage),
                other => Err(format!("stage {other} is not a string")),
            })
            .collect::<Result<_, _>>()?,
        Some(other) => return Err(format!("`tide.vocab.stages` {other} is not a list")),
    };
    let mut text = |key: &str| -> Result<String, String> {
        match table.remove(key) {
            None => Ok(String::new()),
            Some(value) => text_of(&value).ok_or_else(|| format!("`{key}` is not text")),
        }
    };
    let description = text("description")?;
    let icon = text("icon")?;
    let link = text("link")?;
    Ok(Entry {
        key: key_text,
        name,
        version,
        removed,
        description,
        icon,
        link,
        stages,
        extra: table,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLP: &str = r#"
name = "Traffic Light Protocol"
field = "tlp"
key = "name"
[[keys]]
version = "1.0"
id = "TLP:CLEAR"
name = "clear"
[[keys]]
name = "amber"
version = "1.1"
removed = "2.0"
"tide.vocab.stages" = "Sharing"
[[keys]]
version = "1.0"
[[keys]]
name = "red"
version = "one"
"#;

    #[test]
    fn reads_metadata_and_entries_in_order() {
        let tlp = Vocabulary::from_file("tlp.vocab.toml", TLP).unwrap();
        assert_eq!(tlp.metadata.name, "Traffic Light Protocol");
        assert_eq!(tlp.metadata.key, KeyKind::Name);
        assert_eq!(tlp.entries.keys().collect::<Vec<_>>(), ["clear", "amber"]);
        let amber = &tlp.entries["amber"];
        assert_eq!(amber.version, Version::new(1, 1));
        assert_eq!(amber.removed, Some(Version::new(2, 0)));
        assert_eq!(amber.stages, ["Sharing"]);
        assert_eq!(tlp.entries["clear"].extra["id"].as_str(), Some("TLP:CLEAR"));
        // The entry without a name and the one with a bad version are skipped, and said so.
        assert_eq!(tlp.skipped.len(), 2, "{:?}", tlp.skipped);
        assert!(tlp.search_hints());
    }

    #[test]
    fn pins_admit_cumulative_minors_until_removal() {
        let tlp = Vocabulary::from_file("tlp.vocab.toml", TLP).unwrap();
        let amber = &tlp.entries["amber"];
        assert!(!amber.active_at(Version::new(1, 0)));
        assert!(amber.active_at(Version::new(1, 1)));
        assert!(amber.active_at(Version::new(1, 9)));
        assert!(!amber.active_at(Version::new(2, 0)));
    }

    #[test]
    fn the_field_must_match_the_file_name() {
        let error = Vocabulary::from_file("pap.vocab.toml", TLP).unwrap_err();
        assert!(matches!(error, VocabError::FieldMismatch { .. }), "{error}");
        let error = Vocabulary::from_file("tlp.toml", TLP).unwrap_err();
        assert!(matches!(error, VocabError::NotAVocabularyFile(_)));
    }

    #[test]
    fn id_keyed_and_legacy_model_flag() {
        let text = "name = \"G\"\nfield = \"g\"\nmodel = true\n[[keys]]\nid = \"G1\"\nname = \"One\"\n[[keys]]\nname = \"no id\"\n";
        let groups = Vocabulary::parse(text, "g").unwrap();
        assert_eq!(groups.metadata.key, KeyKind::Id);
        assert_eq!(groups.entries.keys().collect::<Vec<_>>(), ["G1"]);
        assert_eq!(groups.skipped, ["entry 1: no `id`"]);
    }

    #[test]
    fn stages_as_strings_or_tables_and_nested_entry_stages() {
        let text = r#"
name = "S"
field = "s"
stages = ["Execution", { id = "OS", name = "Operating Systems" }]
[[keys]]
name = "Windows"
tide = { vocab = { stages = ["OS"] } }
"#;
        let surface = Vocabulary::parse(text, "s").unwrap();
        assert_eq!(
            surface.metadata.stages[0].name.as_deref(),
            Some("Execution")
        );
        assert_eq!(surface.metadata.stages[0].id, None);
        assert_eq!(surface.stage_ids().collect::<Vec<_>>(), ["OS"]);
        assert_eq!(surface.entries["Windows"].stages, ["OS"]);
    }

    #[test]
    fn document_errors() {
        let duplicate =
            "name = \"T\"\nfield = \"t\"\n[[keys]]\nname = \"a\"\n[[keys]]\nname = \"a\"\n";
        assert!(matches!(
            Vocabulary::parse(duplicate, "t").unwrap_err(),
            VocabError::DuplicateKey { index: 1, .. }
        ));
        assert!(matches!(
            Vocabulary::parse("field = \"t\"\n", "t").unwrap_err(),
            VocabError::MissingKey { .. }
        ));
        assert!(matches!(
            Vocabulary::parse("name = \"T\"\nfield = \"t\"\nkey = \"uuid\"\n", "t").unwrap_err(),
            VocabError::InvalidKey { .. }
        ));
        assert!(matches!(
            Vocabulary::parse("name = \"T\"\nfield = \"t\"\nkeys = 3\n", "t").unwrap_err(),
            VocabError::InvalidKey { .. }
        ));
        assert!(matches!(
            Vocabulary::parse("name = [", "t").unwrap_err(),
            VocabError::Toml { .. }
        ));
    }

    #[test]
    fn scalar_text() {
        assert_eq!(text_of(&Value::Float(1.0)).as_deref(), Some("1.0"));
        assert_eq!(text_of(&Value::Float(1.5)).as_deref(), Some("1.5"));
        assert_eq!(text_of(&Value::Integer(7)).as_deref(), Some("7"));
        assert_eq!(text_of(&Value::Boolean(true)).as_deref(), Some("true"));
        assert_eq!(text_of(&Value::Array(Vec::new())), None);
    }
}
