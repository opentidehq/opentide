//! A Tide object as sharing reads it (`sharing/document.py`): the file's
//! text as it is (the `opentide-object` attribute and the ledger's content
//! hash are its bytes) and the mapping it parses to, read for the event's
//! envelope only.

use std::path::{Path, PathBuf};

use opentide_compile::json::{Json, Object};
use opentide_workspace::Workspace;
use sha2::{Digest, Sha256};

use super::OBJECT_FAMILIES;

/// One threat, objective or rule document (`TideDocument`).
#[derive(Clone, Debug)]
pub struct TideDocument {
    /// The file's text.
    pub text: String,
    /// The parsed mapping; empty when the file did not parse.
    pub body: Object,
    /// The file.
    pub path: Option<PathBuf>,
    /// Why the file did not parse: `missing`, `encoding`, `yaml` or `root`.
    pub parse_error: Option<&'static str>,
}

impl TideDocument {
    fn failed(text: String, path: Option<PathBuf>, error: &'static str) -> Self {
        Self {
            text,
            body: Object::new(),
            path,
            parse_error: Some(error),
        }
    }

    /// The SHA-256 of the text, lowercase hex (`content_hash`).
    pub fn content_hash(&self) -> String {
        use std::fmt::Write as _;
        let digest = Sha256::digest(self.text.as_bytes());
        digest.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    /// `metadata`, when it is a mapping.
    pub fn metadata(&self) -> Option<&Object> {
        self.body.get("metadata").and_then(Json::as_object)
    }

    /// A key of `metadata`.
    pub fn meta(&self, key: &str) -> Option<&Json> {
        self.metadata().and_then(|metadata| metadata.get(key))
    }

    fn meta_str(&self, key: &str) -> Option<&str> {
        self.meta(key)
            .and_then(Json::as_str)
            .filter(|value| !value.is_empty())
    }

    /// `metadata.uuid`.
    pub fn uuid(&self) -> Option<&str> {
        self.meta_str("uuid")
    }

    /// `metadata.schema`.
    pub fn schema_id(&self) -> Option<&str> {
        self.meta_str("schema")
    }

    /// The schema's family, when sharing knows it.
    pub fn family(&self) -> Option<&str> {
        let (family, _) = self.schema_id()?.split_once("::")?;
        OBJECT_FAMILIES.contains(&family).then_some(family)
    }

    /// `name`, when it is a string.
    pub fn name(&self) -> Option<&str> {
        self.body.get("name").and_then(Json::as_str)
    }
}

/// Parses `raw` without changing the text kept (`load_document`).
pub fn load(raw: &[u8], path: Option<PathBuf>) -> TideDocument {
    let Ok(text) = std::str::from_utf8(raw) else {
        return TideDocument::failed(String::new(), path, "encoding");
    };
    let text = text.to_owned();
    let Ok(document) = opentide_schema::node::load(&text) else {
        return TideDocument::failed(text, path, "yaml");
    };
    match document.root().map(|root| Json::from_node(root)) {
        Some(Json::Object(body)) => TideDocument {
            text,
            body,
            path,
            parse_error: None,
        },
        _ => TideDocument::failed(text, path, "root"),
    }
}

/// `path` resolved as `Path.resolve()` does: through its links where it
/// exists, as written where it does not.
pub fn resolve(path: &Path) -> PathBuf {
    soft_canonicalize::soft_canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn read(path: Option<&Path>) -> TideDocument {
    match path {
        Some(path) if path.is_file() => match std::fs::read(path) {
            Ok(bytes) => load(&bytes, Some(path.to_path_buf())),
            Err(_) => TideDocument::failed(String::new(), Some(path.to_path_buf()), "missing"),
        },
        other => TideDocument::failed(String::new(), other.map(Path::to_path_buf), "missing"),
    }
}

/// Every object of the workspace, then every file that did not load
/// (`_catalogue`).
pub fn catalogue(workspace: &Workspace) -> Vec<TideDocument> {
    let index = workspace.index();
    let mut documents = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for family in OBJECT_FAMILIES {
        let Some(objects) = index.objects.get(family) else {
            continue;
        };
        for uuid in objects.keys() {
            let path = index.file_paths.get(uuid).cloned();
            if let Some(path) = &path {
                seen.push(resolve(path));
            }
            documents.push(read(path.as_deref()));
        }
    }
    for failure in &index.load_errors {
        let resolved = resolve(&failure.path);
        if seen.contains(&resolved) {
            continue;
        }
        seen.push(resolved);
        documents.push(read(Some(&failure.path)));
    }
    documents
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_keep_their_text_and_read_their_envelope() {
        let text = "name: A\nmetadata:\n  uuid: u1\n  schema: rule::1.0\n";
        let document = load(text.as_bytes(), None);
        assert_eq!(document.text, text);
        assert_eq!(document.uuid(), Some("u1"));
        assert_eq!(document.family(), Some("rule"));
        assert_eq!(document.name(), Some("A"));
        assert_eq!(document.parse_error, None);
        assert_eq!(
            document.content_hash(),
            "dfba71d757f4d9f0c912dd02dcaa807a366a8742f42f04a24aaf48887dd86cb7"
        );
        assert_eq!(load(b"\xff", None).parse_error, Some("encoding"));
        assert_eq!(load(b"a: [", None).parse_error, Some("yaml"));
        assert_eq!(load(b"- a", None).parse_error, Some("root"));
        assert_eq!(load(b"", None).parse_error, Some("root"));
        let other = load(b"metadata:\n  schema: signal::1.0\n  uuid: ''\n", None);
        assert_eq!(other.family(), None);
        assert_eq!(other.uuid(), None);
        assert_eq!(read(None).parse_error, Some("missing"));
    }
}
