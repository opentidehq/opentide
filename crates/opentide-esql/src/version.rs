//! Stack versions: which Elasticsearch release lines accept a name or a form.
//!
//! The catalog records, per command, function, and cast type, the release
//! branches whose own grammar and generated definitions accept it on a release
//! build (`versions` in `catalogs/esql/*.toml`). The engine's syntax checks
//! use the same [`Availability`] sets. A query is checked either against the
//! whole supported range (elastic-1.0: Kibana 8.19 and 9.x) or against one
//! declared target ([`StackTarget`], the tenant `version` key proposed in
//! opentidehq/specifications#59).

use crate::catalog::StackVersion;

/// Release lines the catalog tracks, oldest first. 8.19 shipped beside 9.1
/// and is not a superset of 9.0, so each line is tracked on its own.
pub const RELEASES: [StackVersion; 8] = [
    StackVersion::new(8, 19),
    StackVersion::new(9, 0),
    StackVersion::new(9, 1),
    StackVersion::new(9, 2),
    StackVersion::new(9, 3),
    StackVersion::new(9, 4),
    StackVersion::new(9, 5),
    StackVersion::new(9, 6),
];

const NEWEST: usize = RELEASES.len() - 1;

/// The stack a query must run on.
///
/// `Version` takes `MAJOR.MINOR`. A version between two tracked lines, or
/// newer than the newest, is checked as the closest tracked line at or below
/// it; one older than 8.19 is checked as 8.19. `Serverless` is checked as the
/// newest tracked line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StackTarget {
    Version(StackVersion),
    Serverless,
}

impl StackTarget {
    /// Parse the spec #59 spelling: `"8.19"`, `"9.5"`, or `"serverless"`.
    /// Anything else (`"9"`, `"9.5.1"`, `"latest"`) is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.eq_ignore_ascii_case("serverless") {
            return Some(Self::Serverless);
        }
        let (major, minor) = text.split_once('.')?;
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !digits(major) || !digits(minor) {
            return None;
        }
        Some(Self::Version(StackVersion::new(
            major.parse().ok()?,
            minor.parse().ok()?,
        )))
    }

    /// Whether this target is `version` or later. Serverless is later than
    /// every `MAJOR.MINOR` (specifications#59).
    pub fn at_least(self, version: StackVersion) -> bool {
        match self {
            Self::Serverless => true,
            Self::Version(v) => v >= version,
        }
    }

    /// The lowest of several targets: the one every target reaches.
    pub fn lowest(targets: impl IntoIterator<Item = Self>) -> Option<Self> {
        targets.into_iter().min()
    }

    /// Index into [`RELEASES`] of the line this target is checked as.
    fn release(self) -> usize {
        match self {
            Self::Serverless => NEWEST,
            Self::Version(v) => RELEASES.iter().rposition(|r| *r <= v).unwrap_or(0),
        }
    }
}

impl Ord for StackTarget {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Serverless, Self::Serverless) => std::cmp::Ordering::Equal,
            (Self::Serverless, Self::Version(_)) => std::cmp::Ordering::Greater,
            (Self::Version(_), Self::Serverless) => std::cmp::Ordering::Less,
            (Self::Version(a), Self::Version(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for StackTarget {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for StackTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version(v) => write!(f, "{v}"),
            Self::Serverless => f.write_str("Serverless"),
        }
    }
}

/// A set of [`RELEASES`] lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Availability(u16);

impl Availability {
    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self((1 << RELEASES.len()) - 1);
    /// 8.19 only (forms 9.0 removed).
    pub const ONLY_8_19: Self = Self(1);

    /// Every 9.x line from `minor` on (`9.minor`), without 8.19.
    pub const fn since_9(minor: u32) -> Self {
        let mut bits = 0u16;
        let mut i = 1;
        while i < RELEASES.len() {
            if RELEASES[i].minor >= minor {
                bits |= 1 << i;
            }
            i += 1;
        }
        Self(bits)
    }

    /// 8.19 plus every 9.x line from `minor` on: what 8.19 shares with 9.1
    /// and later but 9.0 lacks.
    pub const fn with_8_19_since_9(minor: u32) -> Self {
        Self(Self::since_9(minor).0 | 1)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The lines named in a catalog `versions` list. Unknown names are ignored.
    pub fn from_versions<S: AsRef<str>>(names: &[S]) -> Self {
        let mut bits = 0u16;
        for name in names {
            let name = name.as_ref();
            if let Some(i) = RELEASES.iter().position(|r| r.to_string() == name) {
                bits |= 1 << i;
            }
        }
        Self(bits)
    }

    pub fn contains(self, version: StackVersion) -> bool {
        RELEASES
            .iter()
            .position(|r| *r == version)
            .is_some_and(|i| self.0 & (1 << i) != 0)
    }

    /// Whether `target` accepts it.
    pub fn on(self, target: StackTarget) -> bool {
        self.0 & (1 << target.release()) != 0
    }

    pub fn is_all(self) -> bool {
        self == Self::ALL
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether the newest tracked line accepts it (false for removed forms).
    pub fn on_newest(self) -> bool {
        self.0 & (1 << NEWEST) != 0
    }

    pub fn versions(self) -> Vec<StackVersion> {
        RELEASES
            .iter()
            .enumerate()
            .filter(|(i, _)| self.0 & (1 << i) != 0)
            .map(|(_, v)| *v)
            .collect()
    }

    pub fn missing(self) -> Vec<StackVersion> {
        Self(Self::ALL.0 & !self.0).versions()
    }

    /// The first 9.x line when the set is "that line and every later one"
    /// (8.19 excluded), as in "needs 9.2 or later".
    fn suffix_start(self) -> Option<StackVersion> {
        let first = (1..RELEASES.len()).find(|i| self.0 & (1 << i) != 0)?;
        let suffix = (first..RELEASES.len()).fold(0u16, |bits, i| bits | 1 << i);
        (self.0 == suffix).then_some(RELEASES[first])
    }

    /// One clause for a message: "needs Elasticsearch 9.2 or later; 8.19,
    /// 9.0 and 9.1 reject it".
    pub fn describe(self) -> String {
        let missing = self.missing();
        let verb = if missing.len() == 1 {
            "rejects"
        } else {
            "reject"
        };
        let missing_text = join_versions(&missing);
        if self.is_empty() {
            return "no Elasticsearch release accepts it".to_string();
        }
        if let Some(first) = self.suffix_start() {
            return format!("needs Elasticsearch {first} or later; {missing_text} {verb} it");
        }
        let versions = self.versions();
        let available = join_versions(&versions);
        if self.on_newest() {
            format!("Elasticsearch {missing_text} {verb} it (it works on {available})")
        } else {
            let accept = if versions.len() == 1 {
                "accepts"
            } else {
                "accept"
            };
            format!("only Elasticsearch {available} {accept} it; {missing_text} {verb} it")
        }
    }
}

/// `8.19, 9.0 to 9.2 and 9.5`, grouping consecutive 9.x lines.
pub fn join_versions(versions: &[StackVersion]) -> String {
    let mut groups: Vec<String> = Vec::new();
    let mut i = 0;
    while i < versions.len() {
        let start = versions[i];
        let mut end = start;
        while i + 1 < versions.len()
            && versions[i + 1].major == end.major
            && versions[i + 1].minor == end.minor + 1
        {
            i += 1;
            end = versions[i];
        }
        if start == end {
            groups.push(start.to_string());
        } else if end.minor == start.minor + 1 {
            groups.push(start.to_string());
            groups.push(end.to_string());
        } else {
            groups.push(format!("{start} to {end}"));
        }
        i += 1;
    }
    match groups.len() {
        0 => String::new(),
        1 => groups.remove(0),
        n => format!("{} and {}", groups[..n - 1].join(", "), groups[n - 1]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parses_the_spec_spelling() {
        assert_eq!(
            StackTarget::parse("9.5"),
            Some(StackTarget::Version(StackVersion::new(9, 5)))
        );
        assert_eq!(
            StackTarget::parse(" 8.19 "),
            Some(StackTarget::Version(StackVersion::new(8, 19)))
        );
        assert_eq!(
            StackTarget::parse("Serverless"),
            Some(StackTarget::Serverless)
        );
        for bad in ["9", "9.5.1", "latest", "9.x", ".5", ""] {
            assert_eq!(StackTarget::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn targets_map_onto_tracked_lines() {
        let rename_assign = Availability::with_8_19_since_9(1);
        let at = |s: &str| StackTarget::parse(s).unwrap();
        assert!(rename_assign.on(at("8.19")));
        assert!(!rename_assign.on(at("9.0")));
        assert!(rename_assign.on(at("9.1")));
        assert!(rename_assign.on(at("9.12")), "newer than tracked: newest");
        assert!(rename_assign.on(at("10.0")));
        assert!(rename_assign.on(at("serverless")));
        assert!(rename_assign.on(at("8.18")), "older than tracked: 8.19");
        assert!(!Availability::ONLY_8_19.on(at("9.6")));
    }

    #[test]
    fn availability_messages_name_versions() {
        assert_eq!(
            Availability::since_9(2).describe(),
            "needs Elasticsearch 9.2 or later; 8.19, 9.0 and 9.1 reject it"
        );
        assert_eq!(
            Availability::with_8_19_since_9(1).describe(),
            "Elasticsearch 9.0 rejects it (it works on 8.19 and 9.1 to 9.6)"
        );
        assert_eq!(
            Availability::from_versions(&["9.1", "9.2", "9.3"]).describe(),
            "only Elasticsearch 9.1 to 9.3 accept it; 8.19, 9.0 and 9.4 to 9.6 reject it"
        );
        assert_eq!(
            Availability::ONLY_8_19.describe(),
            "only Elasticsearch 8.19 accepts it; 9.0 to 9.6 reject it"
        );
        assert!(Availability::ALL.missing().is_empty());
        assert_eq!(
            Availability::from_versions(&["8.19", "9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6"]),
            Availability::ALL
        );
    }
}
