//! The current-state ledger, `.opentide/states/sharing.jsonl`
//! (`sharing/ledger.py`): one JSON object per line, what was shared, keyed
//! by object, integration and target. A line that is not a JSON object is
//! kept where it is; a duplicate key keeps its last line. A skip or a
//! failure never writes it, and no secret goes in it.

use std::path::{Path, PathBuf};

use opentide_compile::json::{Json, Object};

/// The ledger of `workspace` (`ledger_path`).
pub fn path(workspace: &Path) -> PathBuf {
    workspace
        .join(".opentide")
        .join("states")
        .join("sharing.jsonl")
}

/// One line.
#[derive(Clone, Debug, PartialEq)]
enum Line {
    /// A JSON object.
    Record(Object),
    /// Anything else, kept as written.
    Opaque(String),
}

/// The ledger in memory (`ShareLedger`); [`Ledger::save`] rewrites the file.
#[derive(Clone, Debug)]
pub struct Ledger {
    path: PathBuf,
    entries: Vec<Line>,
}

type Triple = (String, String, String);

fn triple(record: &Object) -> Option<Triple> {
    let mut values = Vec::with_capacity(3);
    for key in ["object_uuid", "integration", "target"] {
        match record.get(key) {
            Some(Json::Str(value)) if !value.is_empty() => values.push(value.clone()),
            _ => return None,
        }
    }
    let mut values = values.into_iter();
    Some((values.next()?, values.next()?, values.next()?))
}

/// `str.splitlines()`: every line break Python knows, the breaks dropped.
fn split_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        let breaks = matches!(
            c,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !breaks {
            continue;
        }
        lines.push(&text[start..index]);
        let mut end = index + c.len_utf8();
        if c == '\r'
            && let Some((next, '\n')) = chars.peek().copied()
        {
            chars.next();
            end = next + 1;
        }
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

fn collapse(entries: Vec<Line>) -> Vec<Line> {
    let mut last: Vec<(Triple, usize)> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if let Line::Record(record) = entry
            && let Some(key) = triple(record)
        {
            match last.iter_mut().find(|(seen, _)| *seen == key) {
                Some((_, at)) => *at = index,
                None => last.push((key, index)),
            }
        }
    }
    entries
        .into_iter()
        .enumerate()
        .filter(|(index, entry)| match entry {
            Line::Record(record) => triple(record)
                .is_none_or(|key| last.iter().any(|(seen, at)| *seen == key && at == index)),
            Line::Opaque(_) => true,
        })
        .map(|(_, entry)| entry)
        .collect()
}

impl Ledger {
    /// Reads the ledger at `path`; a missing or empty file is empty (`load`).
    pub fn load(path: &Path) -> Self {
        let mut ledger = Self {
            path: path.to_path_buf(),
            entries: Vec::new(),
        };
        if !path.is_file() {
            return ledger;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return ledger;
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut entries = Vec::new();
        for line in split_lines(&text) {
            if line.trim().is_empty() {
                continue;
            }
            entries.push(match serde_json::from_str::<Json>(line) {
                Ok(Json::Object(record)) => Line::Record(record),
                _ => Line::Opaque(line.to_owned()),
            });
        }
        ledger.entries = collapse(entries);
        ledger
    }

    /// The identity lines, opaque ones left out (`records`).
    pub fn records(&self) -> Vec<&Object> {
        self.entries
            .iter()
            .filter_map(|entry| match entry {
                Line::Record(record) if triple(record).is_some() => Some(record),
                _ => None,
            })
            .collect()
    }

    /// The last line for the key (`get`).
    pub fn get(&self, object_uuid: &str, integration: &str, target: &str) -> Option<Object> {
        let wanted = (
            object_uuid.to_owned(),
            integration.to_owned(),
            target.to_owned(),
        );
        self.entries
            .iter()
            .rev()
            .find_map(|entry| match entry {
                Line::Record(record) if triple(record).as_ref() == Some(&wanted) => Some(record),
                _ => None,
            })
            .cloned()
    }

    /// Replaces every line for the record's key with it (`put`).
    pub fn put(&mut self, record: Object) {
        let Some(key) = triple(&record) else {
            return;
        };
        self.entries.retain(|entry| match entry {
            Line::Record(existing) => triple(existing).as_ref() != Some(&key),
            Line::Opaque(_) => true,
        });
        self.entries.push(Line::Record(record));
    }

    /// Removes the key's lines; whether one was there (`discard`).
    pub fn discard(&mut self, object_uuid: &str, integration: &str, target: &str) -> bool {
        let wanted = (
            object_uuid.to_owned(),
            integration.to_owned(),
            target.to_owned(),
        );
        let before = self.entries.len();
        self.entries.retain(|entry| match entry {
            Line::Record(record) => triple(record).as_ref() != Some(&wanted),
            Line::Opaque(_) => true,
        });
        self.entries.len() != before
    }

    /// Rewrites the file through a temporary one (`save`).
    ///
    /// # Errors
    ///
    /// The folder or the file cannot be written.
    pub fn save(&mut self) -> std::io::Result<()> {
        self.entries = collapse(std::mem::take(&mut self.entries));
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut payload = String::new();
        for entry in &self.entries {
            match entry {
                Line::Opaque(line) => {
                    payload.push_str(line);
                    if !line.ends_with('\n') {
                        payload.push('\n');
                    }
                }
                Line::Record(record) => {
                    payload.push_str(&Json::Object(record.clone()).to_compact());
                    payload.push('\n');
                }
            }
        }
        let mut temporary = self.path.clone().into_os_string();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        std::fs::write(&temporary, payload.as_bytes())?;
        std::fs::rename(&temporary, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(uuid: &str, state: &str) -> Object {
        let mut record = Object::new();
        record.insert("state".into(), Json::Str(state.into()));
        record.insert("object_uuid".into(), Json::Str(uuid.into()));
        record.insert("integration".into(), Json::Str("misp".into()));
        record.insert("target".into(), Json::Str("t".into()));
        record
    }

    #[test]
    fn the_ledger_keeps_the_last_line_and_opaque_ones() {
        let dir = std::env::temp_dir().join(format!("opentide-ledger-{}", std::process::id()));
        let file = path(&dir);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            &file,
            "{\"object_uuid\":\"a\",\"integration\":\"misp\",\"target\":\"t\",\"state\":\"old\"}\r\n\
             not json\n\n[1]\n\
             {\"object_uuid\":\"a\",\"integration\":\"misp\",\"target\":\"t\",\"state\":\"new\"}\n",
        )
        .unwrap();
        let mut ledger = Ledger::load(&file);
        assert_eq!(ledger.records().len(), 1);
        assert_eq!(
            ledger.get("a", "misp", "t").unwrap().get("state"),
            Some(&Json::Str("new".into()))
        );
        ledger.put(record("b", "synced"));
        assert!(ledger.discard("a", "misp", "t"));
        assert!(!ledger.discard("a", "misp", "t"));
        ledger.put(Object::new());
        ledger.save().unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "not json\n[1]\n{\"state\":\"synced\",\"object_uuid\":\"b\",\"integration\":\"misp\",\"target\":\"t\"}\n"
        );
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(Ledger::load(&file).records().is_empty());
        assert_eq!(split_lines("a\rb\u{2028}c"), ["a", "b", "c"]);
    }
}
