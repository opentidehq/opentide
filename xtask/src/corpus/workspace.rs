//! A generated workspace held in memory: its files, what each one is, and
//! how it renders. The fault catalogue mutates this model before it is
//! written, so a fault never depends on how a file was formatted.

use super::yaml::Yaml;
use std::fmt::Write as _;

/// What a file is, for target selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    /// A threat vector (`threat::1.0`).
    Threat,
    /// A detection objective (`objective::1.0`).
    Objective,
    /// A detection rule (`rule::1.0` or `rule::1.1`).
    Rule,
    /// A configuration file under `.opentide/configurations/`.
    Config,
    /// Anything else (README, `.gitignore`).
    Other,
}

impl Family {
    /// The selector name: `threat`, `objective`, `rule`, `config`, `other`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Threat => "threat",
            Self::Objective => "objective",
            Self::Rule => "rule",
            Self::Config => "config",
            Self::Other => "other",
        }
    }

    /// The family a selector names.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "threat" => Self::Threat,
            "objective" => Self::Objective,
            "rule" => Self::Rule,
            "config" => Self::Config,
            "other" => Self::Other,
            _ => return None,
        })
    }
}

/// A file's content.
#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    /// A YAML document.
    Yaml(Yaml),
    /// Text written as it is (TOML configuration, README).
    Text(String),
}

/// One file of the workspace.
#[derive(Debug, Clone, PartialEq)]
pub struct File {
    /// The path relative to the workspace root, with `/` separators.
    pub path: String,
    /// What the file is.
    pub family: Family,
    /// The platforms a rule configures, or the platform a platform
    /// configuration file is for.
    pub platforms: Vec<String>,
    /// Feature tags selectors can require (`rule::1.1`, `sentinel:nrt`,
    /// `elastic:eql`, `tenants`, `chaining`, ...).
    pub tags: Vec<String>,
    /// The content.
    pub body: Body,
}

impl File {
    /// The rendered bytes.
    pub fn render(&self) -> String {
        match &self.body {
            Body::Yaml(doc) => doc.render(),
            Body::Text(text) => text.clone(),
        }
    }

    /// The object's `metadata.uuid`, when it is a YAML object.
    pub fn uuid(&self) -> Option<&str> {
        match &self.body {
            Body::Yaml(doc) => doc.at("metadata.uuid").and_then(Yaml::as_str),
            Body::Text(_) => None,
        }
    }

    /// Whether the file carries `tag`.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

/// A whole workspace.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Workspace {
    /// Every file, in a fixed order.
    pub files: Vec<File>,
}

impl Workspace {
    /// The files of one family.
    pub fn family(&self, family: Family) -> impl Iterator<Item = &File> {
        self.files.iter().filter(move |f| f.family == family)
    }

    /// The file at `path`.
    pub fn file(&self, path: &str) -> Option<&File> {
        self.files.iter().find(|f| f.path == path)
    }

    /// Sorted `(path, bytes)` pairs: what is written to disk.
    pub fn rendered(&self) -> Vec<(String, String)> {
        let mut files: Vec<(String, String)> = self
            .files
            .iter()
            .map(|f| (f.path.clone(), f.render()))
            .collect();
        files.sort();
        files
    }

    /// A digest of every path and byte, independent of file order: the
    /// value the determinism test records. FNV-1a over a canonical listing,
    /// spelled out so that no dependency can change it.
    pub fn digest(&self) -> String {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut feed = |bytes: &[u8]| {
            for byte in bytes {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0100_0000_01b3);
            }
        };
        for (path, text) in self.rendered() {
            feed(path.as_bytes());
            feed(&[0]);
            feed(&u64::try_from(text.len()).unwrap_or(u64::MAX).to_le_bytes());
            feed(text.as_bytes());
        }
        format!("{hash:016x}")
    }

    /// Counts by family and the total size, for the generator's report.
    pub fn summary(&self) -> String {
        let count = |family| self.family(family).count();
        let bytes: usize = self.files.iter().map(|f| f.render().len()).sum();
        let mut out = String::new();
        let _ = write!(
            out,
            "{} threats, {} objectives, {} rules, {} configuration files, {} files, {} bytes",
            count(Family::Threat),
            count(Family::Objective),
            count(Family::Rule),
            count(Family::Config),
            self.files.len(),
            bytes
        );
        out
    }
}
