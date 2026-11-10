//! Elastic Security durations (`platforms/elastic/durations.py`
//! `duration_seconds`): what the Elastic block's `duration` constraint
//! accepts.
//!
//! One grammar for both engines: opentide-schema's `elastic_rule_shape` (the
//! CLI's model) and opentide-tide's `duration_millis` (the language server's
//! maxspan advisories) call [`duration_seconds`].
//!
//! A duration is shorthand, one or more of `<n>d`, `<n>h`, `<n>m`, `<n>s` in
//! that order (`5m`, `1h10m`, `1d2h`), or ISO 8601 with days and a time part
//! (`PT1H`, `P14D`, `P1DT2H`). Digits are ASCII only: Kibana refuses others.
//! Zero is refused unless the caller allows it (`lookback: 0m`).

use std::sync::OnceLock;

use regex::Regex;

#[expect(
    clippy::expect_used,
    reason = "regex literals, tested by `shorthand_and_iso`"
)]
fn patterns() -> &'static (Regex, Regex) {
    static PATTERNS: OnceLock<(Regex, Regex)> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        (
            Regex::new(r"^(?:([0-9]+)d)?(?:([0-9]+)h)?(?:([0-9]+)m)?(?:([0-9]+)s)?$")
                .expect("a valid pattern"),
            // `T` must be followed by a digit: the oracle's `(?=[0-9])`,
            // checked below without look-ahead.
            Regex::new(r"^P(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?(?:([0-9]+)S)?)?$")
                .expect("a valid pattern"),
        )
    })
}

/// Why a value is not a duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurationError {
    /// Not one of the two forms.
    Format,
    /// Zero, where zero is not allowed.
    NotPositive,
}

/// The duration in seconds, saturated at `u128::MAX` (any number of digits
/// is a duration, as Python's integers are unbounded; only zero matters).
pub fn duration_seconds(value: &str, allow_zero: bool) -> Result<u128, DurationError> {
    let (short, iso) = patterns();
    let captures = if value.is_empty() {
        None
    } else if let Some(found) = short.captures(value) {
        Some(found)
    } else if value != "P"
        && value != "PT"
        && iso_time_part_ok(value)
        && let Some(found) = iso.captures(value)
    {
        Some(found)
    } else {
        None
    };
    let Some(captures) = captures else {
        return Err(DurationError::Format);
    };
    let part = |index: usize| -> u128 {
        captures.get(index).map_or(0, |digits| {
            digits.as_str().parse::<u128>().unwrap_or(u128::MAX)
        })
    };
    let total = part(1)
        .saturating_mul(24)
        .saturating_add(part(2))
        .saturating_mul(60)
        .saturating_add(part(3))
        .saturating_mul(60)
        .saturating_add(part(4));
    if total == 0 && !allow_zero {
        return Err(DurationError::NotPositive);
    }
    Ok(total)
}

/// The oracle's `T(?=[0-9])`: a `T` is followed by a digit.
fn iso_time_part_ok(value: &str) -> bool {
    match value.find('T') {
        None => true,
        Some(at) => value[at + 1..].starts_with(|ch: char| ch.is_ascii_digit()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorthand_and_iso() {
        for (text, seconds) in [
            ("5m", 300),
            ("1h10m", 4200),
            ("1d2h", 93_600),
            ("30s", 30),
            ("PT1H", 3600),
            ("P14D", 1_209_600),
            ("P1DT2H", 93_600),
            ("PT1M30S", 90),
        ] {
            assert_eq!(duration_seconds(text, false), Ok(seconds), "{text}");
        }
        for text in [
            "", "P", "PT", "5", "m", "1x", "PT", "P1DT", "PTH", "1m5h", "-1m", " 5m", "５m", "1H",
            "pt1h",
        ] {
            assert_eq!(
                duration_seconds(text, false),
                Err(DurationError::Format),
                "{text:?}"
            );
        }
        assert_eq!(
            duration_seconds("0m", false),
            Err(DurationError::NotPositive)
        );
        assert_eq!(duration_seconds("0m", true), Ok(0));
        assert_eq!(duration_seconds("P0D", true), Ok(0));
        assert!(duration_seconds("99999999999999999999999999999999999999999999d", false).is_ok());
    }
}
