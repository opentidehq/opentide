//! Durations as the platforms take them: Sentinel's ISO 8601 durations and
//! Elastic's date math.
//!
//! Digits are ASCII digits: Azure accepts no other script's decimal digits,
//! so a Sentinel duration with non-ASCII digits is `compile_invalid_rule`.

/// Seconds in a minute, an hour and a day.
const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
const DAY: u64 = 86_400;

/// A Sentinel rule duration in seconds: ISO 8601
/// (`PT1H`, `PT30M`, `P1D`, any case) or the shorthand older catalogues use
/// (`30m`, `1h`, `1h10m`, `1d`), around blanks; read by
/// [`opentide_core::duration::SENTINEL`], the grammar `validate` reads too
/// (#1934). The error quotes the duration and says what is accepted.
pub fn sentinel_seconds(duration: &str) -> Result<u64, String> {
    use opentide_core::duration::{Iso8601Error, SENTINEL, SENTINEL_MAX_DAYS};
    SENTINEL
        .seconds(duration.trim())
        .map_err(|error| match error {
            Iso8601Error::Format => format!(
                "Duration {duration:?} is not an ISO 8601 duration (PT1H, PT30M, P1D) or a \
                 shorthand duration (30m, 1h, 1d, 1h10m)"
            ),
            Iso8601Error::TooLong => format!(
                "Duration {duration:?} is longer than a rule can be deployed with (at most \
                 {SENTINEL_MAX_DAYS} days, 23 hours, 59 minutes and 59 seconds)"
            ),
        })
}

/// A duration as the Sentinel API takes it: whole
/// units keep their zero-padded time fields (`PT01H00M00S`, `PT30M00S`), whole
/// days stay bare (`P1D`).
pub fn sentinel_isoformat(seconds: u64) -> String {
    let days = seconds / DAY;
    let mut rest = seconds % DAY;
    let hours = rest / HOUR;
    rest %= HOUR;
    let minutes = rest / MINUTE;
    let seconds = rest % MINUTE;
    let mut text = String::from("P");
    if days > 0 {
        text.push_str(&format!("{days}D"));
    }
    if hours > 0 || minutes > 0 || seconds > 0 {
        text.push('T');
        let mut bigger = days > 0 || hours > 0;
        if bigger {
            text.push_str(&format!("{hours:02}H"));
        }
        bigger = bigger || minutes > 0;
        if bigger {
            text.push_str(&format!("{minutes:02}M"));
        }
        text.push_str(&format!("{seconds:02}S"));
    }
    if text == "P" { "PT0S".to_owned() } else { text }
}

/// A Sentinel duration rewritten as the API takes it.
pub fn sentinel(duration: &str) -> Result<String, String> {
    sentinel_seconds(duration).map(sentinel_isoformat)
}

/// An Elastic duration in seconds: `<n>s|m|h|d`, compound
/// shorthand (`1h10m`), or ISO 8601 (`PT1H`, `P14D`), read by
/// `opentide_core::duration`, the one grammar the model and the language
/// server use too. Zero only with `allow_zero`; at most
/// [`opentide_core::duration::ELASTIC_MAX_SECONDS`], as the model checks
/// (#1982): a longer duration, however many digits it has, is an error. The
/// error quotes the value.
pub fn elastic_seconds(value: &str, allow_zero: bool) -> Result<u128, String> {
    let seconds = opentide_core::duration::duration_seconds(value, allow_zero).map_err(
        |error| match error {
            opentide_core::duration::DurationError::Format => {
                format!("Invalid duration format: {value:?}")
            }
            opentide_core::duration::DurationError::NotPositive => {
                format!("Duration must be positive (or zero if allowed): {value:?}")
            }
        },
    )?;
    let max = opentide_core::duration::ELASTIC_MAX_SECONDS;
    if seconds > max {
        return Err(format!(
            "Duration {value:?} is longer than a rule can be deployed with: at most {max} seconds"
        ));
    }
    Ok(seconds)
}

/// The units Elastic writes, largest first.
const ELASTIC_UNITS: [(char, u128); 4] = [
    ('d', DAY as u128),
    ('h', HOUR as u128),
    ('m', MINUTE as u128),
    ('s', 1),
];

/// Total seconds in the largest exact unit (`format_duration`): `0s` for zero.
pub fn elastic_format(total: u128) -> String {
    if total == 0 {
        return "0s".to_owned();
    }
    for (unit, size) in ELASTIC_UNITS {
        if total.is_multiple_of(size) {
            return format!("{}{unit}", total / size);
        }
    }
    format!("{total}s")
}

/// A duration as `(amount, unit)` in the largest exact unit of `units`
/// (`elastic_duration`).
pub fn elastic_amount(value: &str, units: &str) -> Result<(u128, char), String> {
    let total = elastic_seconds(value, false)?;
    for unit in units.chars() {
        if let Some((_, size)) = ELASTIC_UNITS.iter().find(|(name, _)| *name == unit)
            && total % size == 0
        {
            return Ok((total / size, unit));
        }
    }
    Err(format!(
        "Duration {value:?} cannot be represented in units {units:?}"
    ))
}

/// A duration as Elastic date math (`date_math`): `5m`, `1h`.
pub fn elastic_date_math(value: &str) -> Result<String, String> {
    let (amount, unit) = elastic_amount(value, "dhms")?;
    Ok(format!("{amount}{unit}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_reads_iso_and_shorthand() {
        assert_eq!(sentinel("PT1H").unwrap(), "PT01H00M00S");
        assert_eq!(sentinel("1h").unwrap(), "PT01H00M00S");
        assert_eq!(sentinel("pt30m").unwrap(), "PT30M00S");
        assert_eq!(sentinel("P1D").unwrap(), "P1D");
        assert_eq!(sentinel("P1W").unwrap(), "P7D");
        assert_eq!(sentinel("1h10m").unwrap(), "PT01H10M00S");
        assert_eq!(sentinel("PT90S").unwrap(), "PT01M30S");
        assert_eq!(sentinel("P1DT2H").unwrap(), "P1DT02H00M00S");
        assert_eq!(sentinel("PT0S").unwrap(), "PT0S");
        assert_eq!(sentinel(" 5m ").unwrap(), "PT05M00S");
        assert_eq!(sentinel("PT25H").unwrap(), "P1DT01H00M00S");
        // Days with minutes and no hours: the hours field still written.
        assert_eq!(sentinel("P1DT30M").unwrap(), "P1DT00H30M00S");
    }

    #[test]
    fn sentinel_refuses_malformed_durations() {
        for text in [
            "P", "PT", "P1DT", "1H", "h", "1x", "", "PT1H1D", "1m1h", "1h1h", "PT1H1H", "P1D1D",
        ] {
            assert!(sentinel(text).is_err(), "{text}");
        }
        // Weeks and hours that each fit a u64 but not their sum: an error,
        // not an overflow.
        assert!(sentinel_seconds("P30500568904943WT8H").is_err());
        assert_eq!(
            sentinel("soon").unwrap_err(),
            "Duration \"soon\" is not an ISO 8601 duration (PT1H, PT30M, P1D) or a shorthand \
             duration (30m, 1h, 1d, 1h10m)"
        );
    }

    /// `validate` (the schema's `check_duration`) and deploy
    /// (`sentinel_seconds`) accept and refuse the same Sentinel durations
    /// (#1934): the cases where their two grammars once disagreed included.
    #[test]
    fn sentinel_validate_and_deploy_agree() {
        use opentide_schema::objects::platform::sentinel::check_duration;
        let accepted = [
            "PT1H",
            "pt30m",
            "P1D",
            "p1w",
            "P1W2D",
            "P1DT2H",
            "PT90S",
            "PT0S",
            "0d",
            "30m",
            "1h10m",
            " 5m ",
            "\u{a0}PT1H\u{3000}",
            "P999999999DT23H59M59S",
            "86399999999999s",
            "P142857142W",
        ];
        for text in accepted {
            assert_eq!(check_duration(text), Ok(()), "validate {text:?}");
            assert!(sentinel_seconds(text).is_ok(), "deploy {text:?}");
        }
        let format = [
            "hourly",
            "1H",
            "P",
            "PT",
            "P1DT",
            "1x",
            "5",
            "-1h",
            "1h 10m",
            "PT1H1D",
            "1m1h",
            "PTT1H",
            "P1H",
            "PT1D",
            "P１D",
            "é",
            "😀",
            "PT1H😀",
            // `ſ` folds to `s` in Unicode, not in ASCII: validate's
            // case-insensitive regex took it.
            "PT1\u{17f}",
            "P1DT1\u{17f}",
        ];
        let too_long = [
            "1000000000d",
            "P99999999999D",
            "P142857143W",
            "P999999999DT24H",
            "99999999999999999999999999999999999999999d",
            "P99999999999999999999DT1H",
        ];
        for (texts, words) in [
            (&format[..], "not an ISO 8601"),
            (&too_long[..], "longer than"),
        ] {
            for text in texts {
                let violation = check_duration(text).unwrap_err();
                assert!(violation.message.contains(words), "validate {text:?}");
                let refusal = sentinel_seconds(text).unwrap_err();
                assert!(refusal.contains(words), "deploy {text:?}: {refusal}");
            }
        }
    }

    #[test]
    fn elastic_durations() {
        assert_eq!(elastic_seconds("5m", false), Ok(300));
        assert_eq!(elastic_seconds("1h10m", false), Ok(4200));
        assert_eq!(elastic_seconds("PT1H", false), Ok(3600));
        assert_eq!(elastic_seconds("P14D", false), Ok(u128::from(14 * DAY)));
        assert_eq!(elastic_seconds("0s", true), Ok(0));
        assert!(elastic_seconds("0s", false).is_err());
        assert!(elastic_seconds("PT", false).is_err());
        assert!(elastic_seconds("PTH", false).is_err());
        assert!(elastic_seconds("P", false).is_err());
        assert!(elastic_seconds("", true).is_err());
        assert!(elastic_seconds("5M", false).is_err());
        assert_eq!(elastic_format(360), "6m");
        assert_eq!(elastic_format(3660), "61m");
        assert_eq!(elastic_format(0), "0s");
        assert_eq!(elastic_date_math("60m").unwrap(), "1h");
        assert_eq!(elastic_amount("90m", "hms"), Ok((90, 'm')));
    }
}
