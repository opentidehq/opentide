//! The object models' validators (ADR 0001, "Validators"), each written
//! once and run by both hosts: the structural conversion
//! ([`crate::from_node`]), which reports a violation at its path among the
//! other errors in Pydantic's order, and garde ([`garde::Validate`] with the
//! [`Pins`] context), which checks a value built in memory.
//!
//! | Oracle | Here |
//! |--------|------|
//! | `ObjectMetadata._validate_schema_identifier` (after) | [`schema_identifier`] |
//! | `RuleMetadata._coerce_reviewed` (before), `_validate_reviewed` (after, `parse_review_instant`) | [`reviewed`] |
//! | `ObjectMetadata._coerce_dates` (before) | none: `created` and `modified` take a string (`tests/golden/APPROVED_DIFFS.toml`) |
//! | `ThreatBody._require_vocab_list` (before) | [`crate::from_node::require_vocab_list`] |
//! | `_single_vocab_name` (`VocabName`, after), `min_length=1` | [`check_single_vocab_name`], [`check_at_least_one`], [`vocab_names`] |
//! | `ObjectReferences.coerce_public_keys` (`from_yaml_dict`) | [`public_references`] |

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::error::ErrorKind;
use crate::from_node::{Context, FromNode, messages};
use crate::node::{Node, Value};
use crate::pins::Pins;

/// The schema identifiers the oracle's registry holds
/// (`schema_registry.registered_identifiers()`), sorted. `cargo xtask schema
/// diff --against python` fails when they differ.
pub const REGISTERED: &[&str] = &[
    "objective::1.0",
    "rule::1.0",
    "rule::1.1",
    "threat::1.0",
    "visibility::1.0",
];

/// What a validator refused: Pydantic's error type, its message and its
/// `ctx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Pydantic's error type: `value_error`, `vocab_packed_names`, `too_short`.
    pub kind: &'static str,
    /// The message the CLI prints.
    pub message: String,
    /// Pydantic's `ctx`, each value as `str()` gives it.
    pub context: Vec<(&'static str, String)>,
}

impl Violation {
    /// A `ValueError` raised in a validator: Pydantic prefixes "Value error, "
    /// and keeps the text as `ctx.error`.
    pub(crate) fn value_error(text: impl Into<String>) -> Self {
        let text = text.into();
        Self {
            kind: "value_error",
            message: format!("Value error, {text}"),
            context: vec![("error", text)],
        }
    }

    /// Reports it in `cx`, about `node`.
    pub fn report(&self, node: &Node, cx: &mut Context) {
        cx.error_with(
            ErrorKind::InvalidValue(self.kind),
            self.message.clone(),
            node,
            &self.context,
        );
    }

    pub(crate) fn into_garde(self) -> garde::Error {
        garde::Error::new(self.message)
    }
}

/// `metadata.schema` names a registered revision.
pub fn check_schema_identifier(value: &str) -> Result<(), Violation> {
    if REGISTERED.contains(&value) {
        Ok(())
    } else {
        Err(Violation::value_error(format!(
            "unknown schema identifier: {value:?}"
        )))
    }
}

/// `ThreatBody.impact` and `.leverage` items: one vocabulary name, not
/// several packed with `;` (`vocab_packed_names`).
pub fn check_single_vocab_name(value: &str) -> Result<(), Violation> {
    if value.contains(';') {
        Err(Violation {
            kind: "vocab_packed_names",
            message: format!(
                "{value:?} packs several vocabulary names into one string; list each name as \
                 its own item"
            ),
            context: vec![("value", value.to_owned())],
        })
    } else {
        Ok(())
    }
}

/// A list with `min_length=1` (`too_short`).
pub fn check_at_least_one(length: usize) -> Result<(), Violation> {
    if length >= 1 {
        Ok(())
    } else {
        Err(Violation {
            kind: "too_short",
            message: format!("List should have at least 1 item after validation, not {length}"),
            context: vec![
                ("field_type", "List".to_owned()),
                ("min_length", "1".to_owned()),
                ("actual_length", length.to_string()),
            ],
        })
    }
}

/// The message when `reviewed` is neither form (the oracle's
/// `parse_review_instant`).
pub const REVIEWED_SHAPE: &str =
    "metadata.reviewed must be an ISO 8601 date (YYYY-MM-DD) or datetime";

#[expect(
    clippy::expect_used,
    reason = "regex literals, tested by every reviewed case"
)]
fn review_patterns() -> &'static (Regex, Regex) {
    static PATTERNS: OnceLock<(Regex, Regex)> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        (
            Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})$").expect("a valid pattern"),
            Regex::new(
                r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[T ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(?:(Z)|([+-])([0-9]{2}):([0-9]{2}))$",
            )
            .expect("a valid pattern"),
        )
    })
}

/// `metadata.reviewed` (trimmed, not empty): an ISO 8601 date
/// (`2026-09-01`) or a datetime with `Z` or a numeric offset
/// (`2026-09-01T15:04:05Z`, `2026-09-01 15:04:05.5+02:00`), as the oracle's
/// `parse_review_instant` accepts them, and one that exists: jiff checks the
/// calendar, the clock and the offset. The year is 0001 to 9999, and so is
/// the instant in UTC, as Python's `datetime` holds them (the oracle refused
/// year 0, and crashed on an offset that moved the instant out of range).
pub fn check_reviewed(text: &str) -> Result<(), Violation> {
    let (date, datetime) = review_patterns();
    let number = |capture: Option<regex::Match<'_>>| -> i32 {
        capture
            .and_then(|digits| digits.as_str().parse().ok())
            .unwrap_or_default()
    };
    let invalid = |error: &dyn std::fmt::Display| {
        Violation::value_error(format!(
            "metadata.reviewed is not a valid date or time: {error}"
        ))
    };
    if let Some(parts) = date.captures(text) {
        return civil_date(
            number(parts.get(1)),
            number(parts.get(2)),
            number(parts.get(3)),
        )
        .map(drop)
        .map_err(|error| invalid(&error));
    }
    let Some(parts) = datetime.captures(text) else {
        return Err(Violation::value_error(REVIEWED_SHAPE));
    };
    let day = civil_date(
        number(parts.get(1)),
        number(parts.get(2)),
        number(parts.get(3)),
    )
    .map_err(|error| invalid(&error))?;
    let fraction = parts.get(7).map_or(0, |digits| {
        // Nanoseconds: the first nine digits, the rest dropped.
        let mut nanos: String = digits.as_str().chars().take(9).collect();
        while nanos.len() < 9 {
            nanos.push('0');
        }
        nanos.parse::<i32>().unwrap_or_default()
    });
    let time = jiff::civil::Time::new(
        to_i8(number(parts.get(4))),
        to_i8(number(parts.get(5))),
        to_i8(number(parts.get(6))),
        fraction,
    )
    .map_err(|error| invalid(&error))?;
    if parts.get(8).is_none() {
        let hours = number(parts.get(10));
        let minutes = number(parts.get(11));
        if hours > 23 || minutes > 59 {
            return Err(invalid(&format_args!(
                "the offset {}{:02}:{:02} is not between -23:59 and +23:59",
                parts.get(9).map_or("", |sign| sign.as_str()),
                hours,
                minutes
            )));
        }
        let sign = if parts.get(9).map(|sign| sign.as_str()) == Some("-") {
            -1
        } else {
            1
        };
        // The instant in UTC, on the civil calendar (years -9999 to 9999):
        // jiff's `Timestamp` stops a day short of 9999-12-31 in UTC, which
        // Python's `datetime` holds.
        let offset =
            jiff::SignedDuration::from_secs(i64::from(sign * (hours * 3600 + minutes * 60)));
        let utc = day
            .to_datetime(time)
            .checked_sub(offset)
            .ok()
            .filter(|utc| utc.year() >= 1);
        if utc.is_none() {
            return Err(invalid(
                &"the time in UTC is not between the years 0001 and 9999",
            ));
        }
    }
    Ok(())
}

/// A date of the calendar Python's `datetime` holds: years 0001 to 9999
/// (jiff's own go back to -9999, and include year 0).
fn civil_date(year: i32, month: i32, day: i32) -> Result<jiff::civil::Date, String> {
    if !(1..=9999).contains(&year) {
        return Err(format!("the year {year:04} is not between 0001 and 9999"));
    }
    jiff::civil::Date::new(
        i16::try_from(year).unwrap_or(i16::MAX),
        to_i8(month),
        to_i8(day),
    )
    .map_err(|error| error.to_string())
}

/// Two decimal digits always fit; anything else is out of every range.
fn to_i8(value: i32) -> i8 {
    i8::try_from(value).unwrap_or(i8::MAX)
}

// ---------------------------------------------------------------------------
// The structural conversion's side: `#[from_node(with = ...)]`.
// ---------------------------------------------------------------------------

/// `metadata.schema`: a string naming a registered revision.
pub fn schema_identifier(node: &Node, cx: &mut Context) -> Option<String> {
    let value = String::from_node(node, cx)?;
    match check_schema_identifier(&value) {
        Ok(()) => Some(value),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

/// `metadata.reviewed`: `null` is `None`; a string is trimmed, and an empty
/// one is `None`; what is left must be a date or a datetime. Any other value
/// is the oracle's `value_error` (it turns the value into text, which never
/// has either form).
pub fn reviewed(node: &Node, cx: &mut Context) -> Option<Option<String>> {
    let text = match &node.value {
        Value::Null => return Some(None),
        Value::Str(text) => text.trim(),
        _ => {
            Violation::value_error(REVIEWED_SHAPE).report(node, cx);
            return None;
        }
    };
    if text.is_empty() {
        return Some(None);
    }
    match check_reviewed(text) {
        Ok(()) => Some(Some(text.to_owned())),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

/// `ThreatBody.impact` and `.leverage` (after
/// [`crate::from_node::require_vocab_list`]): a list of strings, each one
/// vocabulary name, at least one.
pub fn vocab_names(node: &Node, cx: &mut Context) -> Option<Vec<String>> {
    let Value::Seq(items) = &node.value else {
        cx.error(
            ErrorKind::InvalidType("list_type"),
            messages::LIST_TYPE,
            node,
        );
        return None;
    };
    let mut names = Vec::with_capacity(items.len());
    let mut ok = true;
    for (index, item) in items.iter().enumerate() {
        if !cx.tick() {
            return None;
        }
        let name = cx.at_index(index, |cx| {
            let name = String::from_node(item, cx)?;
            match check_single_vocab_name(&name) {
                Ok(()) => Some(name),
                Err(violation) => {
                    violation.report(item, cx);
                    None
                }
            }
        });
        match name {
            Some(name) => names.push(name),
            None => ok = false,
        }
    }
    if !ok {
        return None;
    }
    match check_at_least_one(names.len()) {
        Ok(()) => Some(names),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

/// `references.public`: reference numbers to URLs. The oracle turns every
/// key into an integer with `int()` before the model sees it
/// (`coerce_public_keys`); here a key is an integer, or a string that is one
/// (`"12"`, `"-1"`, `"+3"`: ASCII digits, an optional sign, within i64). Any
/// other key is `int_parsing` (a string: a word, whitespace, `_`, other
/// digits, a number wider than i64) or `int_type` (a float, which the oracle
/// truncated, a boolean, an integer wider than i64), at the key's `[key]`, as
/// Pydantic reports a dictionary key (`public-reference-keys` in
/// tests/oracle/objects_cases.toml).
pub fn public_references(node: &Node, cx: &mut Context) -> Option<Option<BTreeMap<i64, String>>> {
    let entries = match &node.value {
        Value::Null => return Some(None),
        Value::Map(entries) => entries,
        _ => {
            cx.error(
                ErrorKind::InvalidType("dict_type"),
                messages::DICT_TYPE,
                node,
            );
            return None;
        }
    };
    let mut references = BTreeMap::new();
    let mut ok = true;
    for entry in entries {
        if !cx.tick() {
            return None;
        }
        let key = entry.key.value.to_string();
        cx.at_key(&key, |cx| {
            let number = cx.at_key("[key]", |cx| match &entry.key.value {
                Value::Int(number) => Some(*number),
                Value::Str(text) => text.parse::<i64>().ok().or_else(|| {
                    cx.error(
                        ErrorKind::InvalidType("int_parsing"),
                        "Input should be a valid integer, unable to parse string as an integer",
                        &entry.key,
                    );
                    None
                }),
                _ => {
                    cx.error(
                        ErrorKind::InvalidType("int_type"),
                        messages::INT_TYPE,
                        &entry.key,
                    );
                    None
                }
            });
            let url = String::from_node(&entry.value, cx);
            match (number, url) {
                (Some(number), Some(url)) => {
                    references.insert(number, url);
                }
                _ => ok = false,
            }
        });
    }
    ok.then_some(Some(references))
}

// ---------------------------------------------------------------------------
// garde's side: `#[garde(custom(...))]`.
// ---------------------------------------------------------------------------

/// garde: [`check_schema_identifier`].
pub fn garde_schema_identifier(value: &str, _pins: &Pins) -> garde::Result {
    check_schema_identifier(value).map_err(Violation::into_garde)
}

/// garde: [`check_reviewed`] on a present, trimmed, non-empty value.
pub fn garde_reviewed(value: &Option<String>, _pins: &Pins) -> garde::Result {
    match value {
        None => Ok(()),
        Some(text) if text.trim() != text || text.is_empty() => Err(garde::Error::new(
            "metadata.reviewed is held trimmed and not empty (an empty one is None)",
        )),
        Some(text) => check_reviewed(text).map_err(Violation::into_garde),
    }
}

/// garde: [`check_single_vocab_name`] on each item.
pub fn garde_single_vocab_name(value: &str, _pins: &Pins) -> garde::Result {
    check_single_vocab_name(value).map_err(Violation::into_garde)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_accepts_the_oracles_forms() {
        for text in [
            "2026-09-01",
            "2026-09-01T15:04:05Z",
            "2026-09-01T15:04:05+02:00",
            "2026-09-01 15:04:05-05:30",
            "2026-09-01T15:04:05.123456789123Z",
            "2024-02-29",
            "2026-01-01T23:59:59+23:59",
            // The ends of Python's calendar, in UTC too.
            "0001-01-01",
            "9999-12-31",
            "0001-01-01T00:00:00Z",
            "0001-01-01T00:00:00-01:00",
            "0001-01-01T23:58:00+23:58",
            "9999-12-31T23:59:59Z",
            "9999-12-31T23:59:59+00:00",
            "9999-12-31T23:59:59.999999999+00:00",
            "9999-12-31T00:00:00-00:00",
            "9999-12-30T00:01:00-23:59",
        ] {
            assert_eq!(check_reviewed(text), Ok(()), "{text}");
        }
    }

    #[test]
    fn reviewed_refuses_other_shapes_with_the_oracles_message() {
        for text in [
            "yesterday",
            "20260101",
            "2026-09-01T15:04:05",
            "2026-09-01T15:04Z",
            "2026-9-01",
            "2026-09-01t15:04:05Z",
            "2026-09-01T15:04:05+0200",
        ] {
            let violation = check_reviewed(text).unwrap_err();
            assert_eq!(violation.kind, "value_error");
            assert_eq!(
                violation.message,
                format!("Value error, {REVIEWED_SHAPE}"),
                "{text}"
            );
        }
    }

    /// Where the shape message is intended and the oracle's differs
    /// (`reviewed-validity-message` in tests/oracle/objects_cases.toml): a
    /// date in other digits than ASCII's (the oracle's `\d` took them, and
    /// `date.fromisoformat` refused them, `Invalid isoformat string`), and a
    /// date after a control character Python's `strip()` removes and Rust's
    /// `trim()`, Unicode's `White_Space`, keeps (U+001C to U+001F; the oracle
    /// accepted the date).
    #[test]
    fn reviewed_refuses_other_digits_and_control_padding_with_the_shape_message() {
        for text in [
            "\u{662}\u{660}\u{662}\u{666}-\u{660}\u{669}-\u{660}\u{661}",
            "\u{1c}2026-09-01",
            "2026-09-01\u{1f}",
        ] {
            let violation = check_reviewed(text).unwrap_err();
            assert_eq!(violation.kind, "value_error");
            assert_eq!(
                violation.message,
                format!("Value error, {REVIEWED_SHAPE}"),
                "{text:?}"
            );
        }
    }

    #[test]
    fn reviewed_refuses_a_year_or_an_instant_outside_0001_to_9999() {
        for (text, why) in [
            ("0000-01-01", "the year 0000 is not between 0001 and 9999"),
            (
                "0000-01-01T00:00:00Z",
                "the year 0000 is not between 0001 and 9999",
            ),
            (
                "0001-01-01T00:00:00+23:59",
                "the time in UTC is not between the years 0001 and 9999",
            ),
            (
                "0001-01-01T00:00:00+00:01",
                "the time in UTC is not between the years 0001 and 9999",
            ),
            (
                "9999-12-31T23:59:59-23:59",
                "the time in UTC is not between the years 0001 and 9999",
            ),
            (
                "9999-12-31T23:59:59-00:01",
                "the time in UTC is not between the years 0001 and 9999",
            ),
        ] {
            let violation = check_reviewed(text).unwrap_err();
            assert_eq!(violation.kind, "value_error", "{text}");
            assert_eq!(
                violation.message,
                format!("Value error, metadata.reviewed is not a valid date or time: {why}"),
                "{text}"
            );
        }
    }

    #[test]
    fn reviewed_refuses_a_date_or_time_that_cannot_exist() {
        for text in [
            "2026-02-30",
            "2026-13-01",
            "2026-00-10",
            "2025-02-29",
            "2026-01-01T25:00:00Z",
            "2026-01-01T10:60:00Z",
            "2026-01-01T10:00:60Z",
            "2026-02-30T10:00:00Z",
            "2026-01-01T10:00:00+24:00",
            "2026-01-01T10:00:00+02:60",
            "0000-01-01",
            "0000-01-01T00:00:00Z",
            "0001-01-01T00:00:00+23:59",
            "9999-12-31T23:59:59-23:59",
        ] {
            let violation = check_reviewed(text).unwrap_err();
            assert_eq!(violation.kind, "value_error", "{text}");
            assert!(
                violation
                    .message
                    .starts_with("Value error, metadata.reviewed is not a valid date or time: "),
                "{text}: {}",
                violation.message
            );
        }
    }

    #[test]
    fn packed_names_and_empty_lists() {
        assert_eq!(check_single_vocab_name("Data Breach"), Ok(()));
        let packed = check_single_vocab_name("a; b").unwrap_err();
        assert_eq!(packed.kind, "vocab_packed_names");
        assert_eq!(
            packed.message,
            "\"a; b\" packs several vocabulary names into one string; list each name as its own item"
        );
        assert_eq!(check_at_least_one(1), Ok(()));
        let short = check_at_least_one(0).unwrap_err();
        assert_eq!(short.kind, "too_short");
        assert_eq!(
            short.message,
            "List should have at least 1 item after validation, not 0"
        );
    }

    #[test]
    fn schema_identifiers() {
        assert_eq!(check_schema_identifier("rule::1.1"), Ok(()));
        let unknown = check_schema_identifier("rule:1.0").unwrap_err();
        assert_eq!(
            unknown.message,
            "Value error, unknown schema identifier: \"rule:1.0\""
        );
        assert_eq!(
            unknown.context,
            [("error", "unknown schema identifier: \"rule:1.0\"".to_owned())]
        );
    }
}
