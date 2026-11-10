//! Durations as the platforms take them: Sentinel's ISO 8601 durations
//! (`platforms/sentinel/client.py`) and Elastic's date math
//! (`platforms/elastic/durations.py`).
//!
//! Digits are ASCII digits. The oracle's Sentinel parser took any Unicode
//! decimal digit (Python's `\d`), which Azure does not accept either.

/// Seconds in a minute, an hour, a day and a week.
const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
const DAY: u64 = 86_400;
const WEEK: u64 = 7 * DAY;

/// Reads `text` as a run of `<digits><unit>` parts whose units appear in
/// `units` order, each at most once. `None` when `text` is not one; the sum of
/// the parts in seconds, and whether any part was written, otherwise.
fn parts(text: &str, units: &[(char, u64)]) -> Option<(u64, bool)> {
    let mut total: u64 = 0;
    let mut any = false;
    let mut rest = text;
    let mut next = 0;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let unit = rest[digits..].chars().next()?;
        let position = units[next..].iter().position(|(name, _)| *name == unit)?;
        let size = units[next + position].1;
        next += position + 1;
        let amount: u64 = rest[..digits].parse().ok()?;
        total = total.checked_add(amount.checked_mul(size)?)?;
        any = true;
        rest = &rest[digits + unit.len_utf8()..];
    }
    Some((total, any))
}

/// A Sentinel rule duration in seconds (`iso_duration_timedelta`): ISO 8601
/// (`PT1H`, `PT30M`, `P1D`, any case) or the shorthand older catalogues use
/// (`30m`, `1h`, `1h10m`, `1d`). The error is the oracle's message.
pub fn sentinel_seconds(duration: &str) -> Result<u64, String> {
    let text = duration.trim();
    if let Some((total, true)) = parts(text, &[('d', DAY), ('h', HOUR), ('m', MINUTE), ('s', 1)]) {
        return Ok(total);
    }
    let upper = text.to_ascii_uppercase();
    if let Some(body) = upper.strip_prefix('P')
        && !upper.ends_with('T')
    {
        let (date, time) = match body.split_once('T') {
            Some((date, time)) => (date, Some(time)),
            None => (body, None),
        };
        let date = parts(date, &[('W', WEEK), ('D', DAY)]);
        let time = match time {
            Some(time) => parts(time, &[('H', HOUR), ('M', MINUTE), ('S', 1)]),
            None => Some((0, false)),
        };
        if let (Some((days, any_date)), Some((seconds, any_time))) = (date, time)
            && (any_date || any_time)
        {
            return Ok(days + seconds);
        }
    }
    Err(format!(
        "Duration {} is not an ISO 8601 duration (PT1H, PT30M, P1D) or a shorthand duration \
         (30m, 1h, 1d, 1h10m)",
        crate::strategy::python_repr(duration)
    ))
}

/// A duration as the Sentinel API takes it (`duration_isoformat`): whole
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

/// An Elastic duration in seconds (`duration_seconds`): `<n>s|m|h|d`, compound
/// shorthand (`1h10m`), or ISO 8601 (`PT1H`, `P14D`). Zero only with
/// `allow_zero`. The error is the oracle's message.
pub fn elastic_seconds(value: &str, allow_zero: bool) -> Result<u64, String> {
    let short = parts(value, &[('d', DAY), ('h', HOUR), ('m', MINUTE), ('s', 1)]);
    let total = match short {
        Some((total, _)) if !value.is_empty() => Some(total),
        _ => elastic_iso(value),
    };
    let Some(total) = total else {
        return Err(format!(
            "Invalid duration format: {}",
            crate::strategy::python_repr(value)
        ));
    };
    if total == 0 && !allow_zero {
        return Err(format!(
            "Duration must be positive (or zero if allowed): {}",
            crate::strategy::python_repr(value)
        ));
    }
    Ok(total)
}

/// `P(nD)?(T(nH)?(nM)?(nS)?)?`, a `T` followed by a digit, not `P` alone.
fn elastic_iso(value: &str) -> Option<u64> {
    let body = value.strip_prefix('P')?;
    if body.is_empty() {
        return None;
    }
    let (date, time) = match body.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (body, None),
    };
    let (days, _) = parts(date, &[('D', DAY)])?;
    let seconds = match time {
        Some(time) if time.starts_with(|c: char| c.is_ascii_digit()) => {
            parts(time, &[('H', HOUR), ('M', MINUTE), ('S', 1)])?.0
        }
        Some(_) => return None,
        None => 0,
    };
    days.checked_add(seconds)
}

/// The units Elastic writes, largest first.
const ELASTIC_UNITS: [(char, u64); 4] = [('d', DAY), ('h', HOUR), ('m', MINUTE), ('s', 1)];

/// Total seconds in the largest exact unit (`format_duration`): `0s` for zero.
pub fn elastic_format(total: u64) -> String {
    if total == 0 {
        return "0s".to_owned();
    }
    for (unit, size) in ELASTIC_UNITS {
        if total % size == 0 {
            return format!("{}{unit}", total / size);
        }
    }
    format!("{total}s")
}

/// A duration as `(amount, unit)` in the largest exact unit of `units`
/// (`elastic_duration`).
pub fn elastic_amount(value: &str, units: &str) -> Result<(u64, char), String> {
    let total = elastic_seconds(value, false)?;
    for unit in units.chars() {
        if let Some((_, size)) = ELASTIC_UNITS.iter().find(|(name, _)| *name == unit)
            && total % size == 0
        {
            return Ok((total / size, unit));
        }
    }
    Err(format!(
        "Duration {} cannot be represented in units {}",
        crate::strategy::python_repr(value),
        crate::strategy::python_repr(units)
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
    }

    #[test]
    fn sentinel_refuses_what_the_oracle_refuses() {
        for text in ["P", "PT", "P1DT", "1H", "h", "1x", "", "PT1H1D", "1m1h"] {
            assert!(sentinel(text).is_err(), "{text}");
        }
        assert_eq!(
            sentinel("soon").unwrap_err(),
            "Duration 'soon' is not an ISO 8601 duration (PT1H, PT30M, P1D) or a shorthand \
             duration (30m, 1h, 1d, 1h10m)"
        );
    }

    #[test]
    fn elastic_durations() {
        assert_eq!(elastic_seconds("5m", false), Ok(300));
        assert_eq!(elastic_seconds("1h10m", false), Ok(4200));
        assert_eq!(elastic_seconds("PT1H", false), Ok(3600));
        assert_eq!(elastic_seconds("P14D", false), Ok(14 * DAY));
        assert_eq!(elastic_seconds("0s", true), Ok(0));
        assert!(elastic_seconds("0s", false).is_err());
        assert!(elastic_seconds("PT", false).is_err());
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
