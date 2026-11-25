//! The Tide vocabulary model the editor reads, and the parse of a vocabulary file
//! into it. Shared by the crate and by its build script (`#[path]`), which parses
//! every bundled vocabulary once (#1743): this file depends on `serde` and `toml`
//! and on nothing else of the crate.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vocab {
    pub field: String,
    pub title: Option<String>,
    pub keys: Vec<VocabKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabKey {
    /// Token written in YAML (`clear`, `T1059`, `G0006`, …).
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
}

/// Stage ids a key belongs to: `"tide.vocab.stages"` is a string or an array of them.
pub(crate) fn key_stages(key: &toml::Value) -> Vec<String> {
    match key.get("tide.vocab.stages") {
        Some(toml::Value::String(stage)) => vec![stage.clone()],
        Some(toml::Value::Array(stages)) => stages
            .iter()
            .filter_map(|stage| stage.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

pub fn parse_vocab(toml_src: &str) -> Result<Vocab, toml::de::Error> {
    let v: toml::Value = toml::from_str(toml_src)?;
    let field = v
        .get("field")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let title = v.get("name").and_then(|v| v.as_str()).map(str::to_string);
    let token_field = v.get("key").and_then(|v| v.as_str()).unwrap_or("name");
    // A vocabulary with `[[stages]]` tables scopes its keys: the value written in YAML is
    // `<stage>::<key>` (`support::enabled`), because two stages may define the same key.
    let scoped = v
        .get("stages")
        .and_then(|v| v.as_array())
        .is_some_and(|stages| stages.iter().any(|stage| stage.is_table()));
    let keys = v
        .get("keys")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .flat_map(|k| {
            let token = k
                .get(token_field)
                .and_then(|x| x.as_str())
                .or_else(|| k.get("name").and_then(|x| x.as_str()))
                .or_else(|| k.get("id").and_then(|x| x.as_str()));
            let Some(token) = token else {
                return Vec::new();
            };
            let pretty = k.get("name").and_then(|x| x.as_str()).map(str::to_string);
            let description = k
                .get("description")
                .and_then(|d| d.as_str())
                .map(str::to_string);
            let stages = if scoped { key_stages(k) } else { Vec::new() };
            let tokens: Vec<String> = if stages.is_empty() {
                vec![token.to_string()]
            } else {
                stages
                    .iter()
                    .map(|stage| format!("{stage}::{token}"))
                    .collect()
            };
            tokens
                .into_iter()
                .map(|name| VocabKey {
                    title: pretty.clone().filter(|p| *p != name),
                    name,
                    description: description.clone(),
                })
                .collect()
        })
        .collect();
    Ok(Vocab { field, title, keys })
}
