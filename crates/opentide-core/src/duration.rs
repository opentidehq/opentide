//! Elastic Security durations: what the Elastic block's `duration`
//! constraint accepts, in seconds ([`duration_seconds`]).
//!
//! One grammar for both engines: opentide-schema's `elastic_rule_shape` (the
//! CLI's model) and opentide-tide's `duration_millis` (the language server's
//! maxspan advisories) call [`duration_seconds`].
//!
//! A duration is shorthand, one or more of `<n>d`, `<n>h`, `<n>m`, `<n>s` in
//! that order (`5m`, `1h10m`, `1d2h`), or ISO 8601 with days and a time part
//! (`PT1H`, `P14D`, `P1DT2H`). Digits are ASCII only: Kibana refuses others.
//! Zero is refused unless the caller allows it (`lookback: 0m`).
//!
//! [`Iso8601`] is the other grammar: ISO 8601 durations with the options a
//! platform takes (weeks, any case, the shorthand, a longest value).
//! [`SENTINEL`] is Sentinel's, the one `validate` (opentide-schema's
//! `check_duration`) and deploy (opentide-compile's `sentinel_seconds`) both
//! read (#1934).

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
            // A `T` must be followed by a digit (`PT` alone is not a
            // duration): checked by `iso_time_part_ok`, as the regex crate
            // has no look-ahead.
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

/// The longest Elastic duration opentide sends, in seconds: `i64::MAX`, the
/// largest JSON integer the payload writes (`suppression.duration.value`;
/// Elasticsearch's `long`). [`duration_seconds`] reads any number of digits
/// and saturates at `u128::MAX`; past this bound a value is refused, by
/// `validate` (the block's `duration` code) and by deploy's compiler, rather
/// than written into the payload as a saturated number (#1982). Within it,
/// every number deploy writes (`from` is `interval` plus `lookback`) is exact.
pub const ELASTIC_MAX_SECONDS: u128 = i64::MAX as u128;

/// The duration in seconds, saturated at `u128::MAX` (any number of digits
/// is a duration, however large; only zero matters). Elastic's callers bound
/// it at [`ELASTIC_MAX_SECONDS`].
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

/// Whether a `T` (the time part) is followed by a digit: `PT` and `P1DT`
/// are not durations.
fn iso_time_part_ok(value: &str) -> bool {
    value
        .split_once('T')
        .is_none_or(|(_, time)| time.starts_with(|ch: char| ch.is_ascii_digit()))
}

/// An ISO 8601 duration grammar (`P1W`, `P1DT2H`, `PT30M`): a date part
/// of weeks (when allowed) and days, a time part of hours, minutes and
/// seconds, each `<digits><designator>` written at most once and in that
/// order, at least one written. Digits are ASCII only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Iso8601 {
    /// Whether the date part takes weeks (`P2W`).
    pub weeks: bool,
    /// Whether the designators may be written in any ASCII case (`pt1h`).
    pub any_case: bool,
    /// Whether the shorthand `<n>d<n>h<n>m<n>s` (lower case, in that order:
    /// `30m`, `1h10m`) is read too, before ISO 8601.
    pub shorthand: bool,
    /// The longest duration taken, in seconds.
    pub max_seconds: u64,
}

/// Why a text is not an [`Iso8601`] duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iso8601Error {
    /// Neither the shorthand (where taken) nor ISO 8601.
    Format,
    /// Longer than the grammar's `max_seconds` (a part too long for a `u64`
    /// included).
    TooLong,
}

/// The most days a Sentinel duration holds: 999,999,999, Python's
/// `timedelta.max.days`, the bound rules were accepted under before the
/// port to Rust, kept so that none that passed then fails now. It is
/// opentide's own limit, not Microsoft's: Microsoft's documentation of
/// scheduled analytics rules bounds `queryFrequency` and `queryPeriod` to
/// 14 days, which the tenant checks at deploy. Past this bound
/// [`Iso8601::seconds`] returns [`Iso8601Error::TooLong`], so `validate`
/// reports the value and deploy refuses it.
pub const SENTINEL_MAX_DAYS: u64 = 999_999_999;

/// The longest Sentinel duration, in seconds: [`SENTINEL_MAX_DAYS`] and a day
/// less one second.
pub const SENTINEL_MAX_SECONDS: u64 = SENTINEL_MAX_DAYS * 86_400 + 86_399;

/// Sentinel's durations (`frequency`, `lookback`, `grouping_lookback`,
/// `suppression`): ISO 8601 with weeks in any case (`PT1H`, `p1w`), or the
/// shorthand older catalogues use (`30m`, `1h10m`), at most
/// [`SENTINEL_MAX_SECONDS`].
pub const SENTINEL: Iso8601 = Iso8601 {
    weeks: true,
    any_case: true,
    shorthand: true,
    max_seconds: SENTINEL_MAX_SECONDS,
};

/// Seconds in a minute, an hour, a day and a week.
const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
const DAY: u64 = 86_400;
const WEEK: u64 = 7 * DAY;

/// A run of `<digits><unit>` parts read so far.
struct Parts {
    /// The sum in seconds, `None` once it overflowed a `u64`.
    seconds: Option<u64>,
    /// Whether any part was written.
    any: bool,
}

/// Reads `text` as a run of `<digits><unit>` parts whose units appear in
/// `units` order, each at most once; `None` when it is not one. The whole
/// text is read before an overflow counts, so a malformed text is a format
/// error however long its digits.
fn parts(text: &str, units: &[(char, u64)]) -> Option<Parts> {
    let mut read = Parts {
        seconds: Some(0),
        any: false,
    };
    let mut rest = text;
    let mut next = 0;
    while !rest.is_empty() {
        let after = rest.trim_start_matches(|ch: char| ch.is_ascii_digit());
        let digits = &rest.as_bytes()[..rest.len() - after.len()];
        if digits.is_empty() {
            return None;
        }
        let mut chars = after.chars();
        let unit = chars.next()?;
        let position = units[next..].iter().position(|(name, _)| *name == unit)?;
        let size = units[next + position].1;
        next += position + 1;
        // The digits' value, `None` past `u64::MAX` as `parse` gives.
        let amount = digits.iter().try_fold(0u64, |sum, digit| {
            sum.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
        });
        read.seconds = read
            .seconds
            .zip(amount.and_then(|amount| amount.checked_mul(size)))
            .and_then(|(sum, part)| sum.checked_add(part));
        read.any = true;
        rest = chars.as_str();
    }
    Some(read)
}

impl Iso8601 {
    /// The duration `text` spells, in seconds. `text` is read as given:
    /// callers trim it where blanks are allowed.
    ///
    /// # Errors
    ///
    /// [`Iso8601Error::Format`] for a text of neither shape,
    /// [`Iso8601Error::TooLong`] for one longer than `max_seconds`.
    pub fn seconds(&self, text: &str) -> Result<u64, Iso8601Error> {
        let bounded = |seconds: Option<u64>| {
            seconds
                .filter(|seconds| *seconds <= self.max_seconds)
                .ok_or(Iso8601Error::TooLong)
        };
        if self.shorthand
            && let Some(Parts { seconds, any: true }) =
                parts(text, &[('d', DAY), ('h', HOUR), ('m', MINUTE), ('s', 1)])
        {
            return bounded(seconds);
        }
        let upper;
        let text = if self.any_case {
            upper = text.to_ascii_uppercase();
            upper.as_str()
        } else {
            text
        };
        let Some(body) = text.strip_prefix('P') else {
            return Err(Iso8601Error::Format);
        };
        if text.ends_with('T') {
            return Err(Iso8601Error::Format);
        }
        let (date, time) = match body.split_once('T') {
            Some((date, time)) => (date, Some(time)),
            None => (body, None),
        };
        let date_units: &[(char, u64)] = if self.weeks {
            &[('W', WEEK), ('D', DAY)]
        } else {
            &[('D', DAY)]
        };
        let date = parts(date, date_units).ok_or(Iso8601Error::Format)?;
        let time = match time {
            Some(time) => {
                parts(time, &[('H', HOUR), ('M', MINUTE), ('S', 1)]).ok_or(Iso8601Error::Format)?
            }
            None => Parts {
                seconds: Some(0),
                any: false,
            },
        };
        if !date.any && !time.any {
            return Err(Iso8601Error::Format);
        }
        bounded(
            date.seconds
                .zip(time.seconds)
                .and_then(|(date, time)| date.checked_add(time)),
        )
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

    #[test]
    fn sentinel_iso8601() {
        for (text, seconds) in [
            ("PT1H", 3600),
            ("pt30m", 1800),
            ("P1D", 86_400),
            ("p1w", 604_800),
            ("P1W2D", 777_600),
            ("P1DT2H", 93_600),
            ("PT90S", 90),
            ("PT0S", 0),
            ("0d", 0),
            ("1h10m", 4200),
            ("45s", 45),
            ("P999999999DT23H59M59S", SENTINEL_MAX_SECONDS),
            ("86399999999999s", SENTINEL_MAX_SECONDS),
        ] {
            assert_eq!(SENTINEL.seconds(text), Ok(seconds), "{text:?}");
        }
        for text in [
            "",
            "P",
            "PT",
            "P1DT",
            "1H",
            "h",
            "1x",
            "5",
            "-1h",
            "1h 10m",
            " PT1H",
            "PT1H1D",
            "1m1h",
            "1h1h",
            "PT1H1H",
            "P1D1D",
            "PTT1H",
            "P1H",
            "PT1D",
            "P１D",
            "é",
            "😀",
            "PT1H😀",
            // Unicode case folding (`ſ` folds to `s`) is not ASCII case.
            "PT1\u{17f}",
            "P\u{17f}",
            // A malformed text is a format error, however long its digits.
            "99999999999999999999999dx",
        ] {
            assert_eq!(
                SENTINEL.seconds(text),
                Err(Iso8601Error::Format),
                "{text:?}"
            );
        }
        for text in [
            "1000000000d",
            "P99999999999D",
            "P142857143W",
            "86400000000000s",
            "P142857142WT1000000M",
            "P999999999DT24H",
            "99999999999999999999999999999999999999999d",
            "PT99999999999999999999999999999999999999999S",
            "P99999999999999999999DT1H",
        ] {
            assert_eq!(
                SENTINEL.seconds(text),
                Err(Iso8601Error::TooLong),
                "{text:?}"
            );
        }
    }

    #[test]
    fn iso8601_options() {
        let strict = Iso8601 {
            weeks: false,
            any_case: false,
            shorthand: false,
            max_seconds: u64::MAX,
        };
        assert_eq!(strict.seconds("P1DT1H"), Ok(90_000));
        for text in ["P1W", "pt1h", "PT1h", "1h"] {
            assert_eq!(strict.seconds(text), Err(Iso8601Error::Format), "{text:?}");
        }
        let short = Iso8601 {
            max_seconds: 60,
            ..strict
        };
        assert_eq!(short.seconds("PT60S"), Ok(60));
        assert_eq!(short.seconds("PT61S"), Err(Iso8601Error::TooLong));
    }

    /// The unit after the digits, and the time part after a `T`, are read
    /// as whole characters: a multi-byte one is a format error, not a panic.
    #[test]
    fn multi_byte_text_is_a_format_error() {
        for text in [
            "1é",
            "5m😀",
            "é5m",
            "1h😀m",
            "PTé",
            "P1DTé1H",
            "PT1é",
            "😀",
            "1\u{1f600}",
        ] {
            assert_eq!(
                duration_seconds(text, false),
                Err(DurationError::Format),
                "{text:?}"
            );
        }
        assert_eq!(duration_seconds("1d2h", false), Ok(93_600));
        assert!(!iso_time_part_ok("P1DTé"));
        assert!(iso_time_part_ok("P1DT2H"));
        assert!(iso_time_part_ok("é"));
        assert!(parts("1é", &[('é', 2)]).is_some_and(|read| read.seconds == Some(2)));
        assert!(
            parts("18446744073709551616é", &[('é', 1)]).is_some_and(|read| read.seconds.is_none())
        );
    }
}
