//! `opentide rules unreviewed`: the rules RFC 0008's review predicate
//! lists (`models/review.py`, `cli/services/rules.py`). Nothing is written.
//!
//! `rule::1.0` is always unreviewed; `rule::1.1` when `metadata.reviewed`
//! is absent or strictly earlier than the evaluation instant minus the
//! window. Dates and times are jiff's.

use std::path::Path;

use jiff::{SignedDuration, Timestamp};
use opentide_schema::node::{Node, Value};
use opentide_schema::objects::checks::{REVIEWED_SHAPE, check_reviewed};
use serde::Serialize;

use crate::fields::{get, mapping, str_at};
use crate::fs::{EntryKind, FileSystem};
use crate::index::posix;
use crate::load::{Parsed, parse};

/// The window's usage error.
pub const WINDOW_SHAPE: &str = "window must look like 90d, 12h, or 30m";
/// A window of zero.
pub const WINDOW_POSITIVE: &str = "window must be a positive duration";

/// A review window: its length and the text it was written as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// The count.
    pub count: u64,
    /// `d`, `h` or `m`.
    pub unit: char,
}

impl Window {
    /// Reads `90d`, `12h`, `30m` or `90` (days), around whitespace.
    ///
    /// # Errors
    ///
    /// [`WINDOW_SHAPE`] or [`WINDOW_POSITIVE`].
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let text = text.trim();
        let (digits, unit) = match text.chars().last() {
            Some(unit @ ('d' | 'h' | 'm')) => (&text[..text.len() - 1], unit),
            _ => (text, 'd'),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WINDOW_SHAPE);
        }
        let count: u64 = digits.parse().map_err(|_| WINDOW_SHAPE)?;
        if count == 0 {
            return Err(WINDOW_POSITIVE);
        }
        Ok(Self { count, unit })
    }

    /// Its length; `None` beyond what a duration holds.
    pub fn duration(self) -> Option<SignedDuration> {
        let seconds: i64 = match self.unit {
            'h' => 3600,
            'm' => 60,
            _ => 86_400,
        };
        i64::try_from(self.count)
            .ok()?
            .checked_mul(seconds)
            .map(SignedDuration::from_secs)
    }

    /// `90 days`, `12 hours`, `1 minute`.
    pub fn text(self) -> String {
        let word = match self.unit {
            'h' => "hour",
            'm' => "minute",
            _ => "day",
        };
        if self.count == 1 {
            format!("1 {word}")
        } else {
            format!("{} {word}s", self.count)
        }
    }
}

/// `window_text` on the option as typed: `90d` is `90 days`, `090d` is
/// `090 days`.
pub fn window_text(older_than: &str) -> String {
    let text = older_than.trim();
    let (number, unit) = match text.chars().last() {
        Some(unit @ ('d' | 'h' | 'm')) => (&text[..text.len() - 1], unit),
        _ => (text, 'd'),
    };
    let word = match unit {
        'h' => "hour",
        'm' => "minute",
        _ => "day",
    };
    if number == "1" {
        format!("1 {word}")
    } else {
        format!("{number} {word}s")
    }
}

/// One unreviewed rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unreviewed {
    /// The file, from the workspace.
    pub path: String,
    /// `metadata.schema`.
    pub schema: String,
    /// `schema`, `absent` or `stale`.
    pub reason: &'static str,
    /// `metadata.reviewed` as written, trimmed.
    pub reviewed: Option<String>,
}

/// What the rules folder holds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Findings {
    /// The unreviewed rules, in file order.
    pub rules: Vec<Unreviewed>,
    /// The files that could not be read, with why.
    pub unreadable: Vec<(String, String)>,
    /// Whether the folder holds any rule file.
    pub any_rule_files: bool,
}

/// A review instant (`parse_review_instant`): a date is midnight UTC.
///
/// # Errors
///
/// The oracle's message for a value that is neither form, or the date
/// library's for one that does not exist.
pub fn review_instant(text: &str) -> Result<Timestamp, String> {
    let text = text.trim();
    check_reviewed(text).map_err(|violation| {
        violation
            .context
            .iter()
            .find(|(key, _)| *key == "error")
            .map_or(violation.message, |(_, text)| text.clone())
    })?;
    let shaped = |_| REVIEWED_SHAPE.to_owned();
    if text.len() == 10 {
        let date: jiff::civil::Date = text.parse().map_err(shaped)?;
        return date
            .to_zoned(jiff::tz::TimeZone::UTC)
            .map(|zoned| zoned.timestamp())
            .map_err(|error| error.to_string());
    }
    text.replacen(' ', "T", 1)
        .parse::<Timestamp>()
        .map_err(|error| error.to_string())
}

/// `metadata.reviewed` as the predicate reads it: text, trimmed, `None` when
/// empty or absent.
fn reviewed_text(node: Option<&Node>) -> Option<String> {
    let node = node?;
    let text = match &node.value {
        Value::Null => return None,
        _ => node.value.to_string(),
    };
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// The rule files directly in `dir`, debug output included, sorted.
fn rule_files(fs: &dyn FileSystem, dir: &Path) -> Vec<std::path::PathBuf> {
    let Ok(mut entries) = fs.read_dir(dir) else {
        return Vec::new();
    };
    entries.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    entries
        .into_iter()
        .filter(|entry| {
            entry.kind == EntryKind::File
                // Case-sensitive, as discovery matches object files.
                && crate::discover::OBJECT_SUFFIXES
                    .iter()
                    .any(|suffix| entry.name.ends_with(suffix))
        })
        .map(|entry| dir.join(&entry.file_name))
        .collect()
}

/// The unreviewed rules of `<repo>/objects/rules` at `now`.
///
/// # Errors
///
/// A rule's `metadata.reviewed` cannot be read as a review instant, as the
/// oracle stops on it.
pub fn unreviewed(
    fs: &dyn FileSystem,
    repo: &Path,
    window: SignedDuration,
    now: Timestamp,
) -> Result<Findings, String> {
    let dir = repo.join("objects").join("rules");
    let files = rule_files(fs, &dir);
    let mut findings = Findings {
        any_rule_files: !files.is_empty(),
        ..Findings::default()
    };
    let shown = |path: &Path| path.strip_prefix(repo).map_or_else(|_| posix(path), posix);
    for path in files {
        let parsed = match fs.read(&path) {
            Ok(bytes) => parse(&bytes),
            Err(error) => crate::load::unreadable(&error),
        };
        let document = match parsed {
            Parsed::Document(document) => document,
            Parsed::Failed(failure) => {
                if matches!(failure.kind, crate::load::FailureKind::NotMapping) {
                    // Not a mapping: not a rule, and no error either.
                    continue;
                }
                let reason = failure
                    .error
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                findings.unreadable.push((shown(&path), reason));
                continue;
            }
        };
        let Some(root) = document.root() else {
            continue;
        };
        let Some(metadata) = mapping(root, "metadata") else {
            continue;
        };
        let Some(schema) = str_at(metadata, "schema").filter(|s| s.starts_with("rule::")) else {
            continue;
        };
        let reviewed = reviewed_text(get(metadata, "reviewed"));
        let reason = match schema {
            "rule::1.0" => Some("schema"),
            "rule::1.1" => match &reviewed {
                None => Some("absent"),
                Some(text) => {
                    let instant = review_instant(text)?;
                    let cutoff = now.checked_sub(window).map_err(|e| e.to_string())?;
                    (instant < cutoff).then_some("stale")
                }
            },
            _ => None,
        };
        if let Some(reason) = reason {
            findings.rules.push(Unreviewed {
                path: shown(&path),
                schema: schema.to_owned(),
                reason,
                reviewed,
            });
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryFs;

    #[test]
    fn windows() {
        assert_eq!(
            Window::parse(" 90d "),
            Ok(Window {
                count: 90,
                unit: 'd'
            })
        );
        assert_eq!(
            Window::parse("90"),
            Ok(Window {
                count: 90,
                unit: 'd'
            })
        );
        assert_eq!(Window::parse("90x"), Err(WINDOW_SHAPE));
        assert_eq!(Window::parse("d"), Err(WINDOW_SHAPE));
        assert_eq!(Window::parse("-1d"), Err(WINDOW_SHAPE));
        assert_eq!(Window::parse("0h"), Err(WINDOW_POSITIVE));
        assert_eq!(
            Window::parse("12h").unwrap().duration(),
            Some(SignedDuration::from_hours(12))
        );
        assert_eq!(Window::parse("99999999999999999999d"), Err(WINDOW_SHAPE));
        assert_eq!(
            Window::parse("999999999999999999d").unwrap().duration(),
            None
        );
        assert_eq!(window_text("90d"), "90 days");
        assert_eq!(window_text("1h"), "1 hour");
        assert_eq!(window_text("30m"), "30 minutes");
    }

    #[test]
    fn instants() {
        let at = |text: &str| review_instant(text).map(|t| t.to_string());
        assert_eq!(at("2026-01-02").unwrap(), "2026-01-02T00:00:00Z");
        assert_eq!(
            at("2026-01-02 10:00:00+02:00").unwrap(),
            "2026-01-02T08:00:00Z"
        );
        assert_eq!(
            at("2026-01-02T10:00:00.5Z").unwrap(),
            "2026-01-02T10:00:00.5Z"
        );
        assert_eq!(at("yesterday").unwrap_err(), REVIEWED_SHAPE);
        assert!(at("2026-02-30").is_err());
    }

    #[test]
    fn the_predicate() {
        let fs = MemoryFs::new();
        let rules = Path::new("/ws/objects/rules");
        let rule = |schema: &str, reviewed: &str| {
            format!("name: x\nmetadata:\n  schema: {schema}\n{reviewed}")
        };
        fs.write(rules.join("a.yaml"), rule("rule::1.0", ""));
        fs.write(rules.join("b.yml"), rule("rule::1.1", ""));
        fs.write(
            rules.join("c.yaml"),
            rule("rule::1.1", "  reviewed: 2026-01-01\n"),
        );
        fs.write(
            rules.join("d.yaml"),
            rule("rule::1.1", "  reviewed: 2026-03-01T00:00:00Z\n"),
        );
        fs.write(
            rules.join("e.debug.yaml"),
            rule("rule::1.1", "  reviewed: ''\n"),
        );
        fs.write(rules.join("f.yaml"), rule("threat::1.0", ""));
        fs.write(rules.join("g.yaml"), "- a list\n");
        fs.write(rules.join("h.yaml"), "a: [\n");
        fs.write(rules.join("nested/i.yaml"), rule("rule::1.0", ""));
        let now: Timestamp = "2026-03-31T00:00:00Z".parse().unwrap();
        // 30 days before now is 2026-03-01T00:00:00Z: equal is fresh.
        let found = unreviewed(
            &fs,
            Path::new("/ws"),
            SignedDuration::from_hours(24 * 30),
            now,
        )
        .unwrap();
        let listed: Vec<(&str, &str)> = found
            .rules
            .iter()
            .map(|rule| (rule.path.as_str(), rule.reason))
            .collect();
        assert_eq!(
            listed,
            [
                ("objects/rules/a.yaml", "schema"),
                ("objects/rules/b.yml", "absent"),
                ("objects/rules/c.yaml", "stale"),
                ("objects/rules/e.debug.yaml", "absent"),
            ]
        );
        assert_eq!(found.rules[2].reviewed.as_deref(), Some("2026-01-01"));
        assert_eq!(found.unreadable.len(), 1);
        assert_eq!(found.unreadable[0].0, "objects/rules/h.yaml");
        assert!(found.any_rule_files);
        fs.write(
            rules.join("z.yaml"),
            rule("rule::1.1", "  reviewed: soon\n"),
        );
        assert_eq!(
            unreviewed(&fs, Path::new("/ws"), SignedDuration::from_hours(1), now).unwrap_err(),
            REVIEWED_SHAPE
        );
        assert!(
            !unreviewed(
                &fs,
                Path::new("/nowhere"),
                SignedDuration::from_hours(1),
                now
            )
            .unwrap()
            .any_rule_files
        );
    }
}
