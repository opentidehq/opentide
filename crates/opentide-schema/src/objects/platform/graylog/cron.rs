//! `schedule.cron` and `schedule.timezone` (graylog-1.0, "Schedule"):
//! `platforms/graylog/constraints.py` `cron_ok` and `timezone_ok`.
//!
//! The Quartz reader is 0.26.0's. language-server 0.16.0 checks the same
//! fields after the platform-graylog 1.1 clarifications (specifications #86)
//! and differs from it in three places, kept as 0.26.0 has them until the
//! oracle moves: it bounds an increment by the field's maximum (`*/90` in
//! minutes), takes the occurrence after `#` from 1 to 7 (0.26.0: 1 to 5), and
//! takes `L-n` in day of week (0.26.0: day of month only).
//!
//! The time zone names are the IANA database's zones and links
//! (`data/catalogs/tz/zones.txt`, the list the editor reads), where 0.26.0
//! asked Python's `zoneinfo`.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use opentide_core::falco::{is_python_space, python_strip};

const MONTHS: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
];
const DAYS: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

/// `(low, high, names)` of each Quartz field: seconds, minutes, hours, day of
/// month, month, day of week, year.
const FIELDS: [(u32, u32, &[&str]); 7] = [
    (0, 59, &[]),
    (0, 59, &[]),
    (0, 23, &[]),
    (1, 31, &[]),
    (1, 12, &MONTHS),
    (1, 7, &DAYS),
    (1970, 2099, &[]),
];
const DAY_OF_MONTH: usize = 3;
const DAY_OF_WEEK: usize = 5;

fn digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// A value of a field: one of its names, any case, or a number in bounds.
fn value(text: &str, index: usize) -> bool {
    let (low, high, names) = FIELDS[index];
    if names.iter().any(|name| name.eq_ignore_ascii_case(text)) {
        return true;
    }
    digits(text)
        && text
            .parse::<u64>()
            .is_ok_and(|number| u64::from(low) <= number && number <= u64::from(high))
}

/// `L-n` in day of month: `n` is one or two digits.
fn last_offset(base: &str) -> bool {
    base.strip_prefix("L-")
        .is_some_and(|offset| digits(offset) && offset.len() <= 2)
}

/// One comma-separated part of a field.
fn part(text: &str, index: usize) -> bool {
    let (base, step) = match text.split_once('/') {
        Some((base, step)) => (base, Some(step)),
        None => (text, None),
    };
    // An increment is a whole number greater than zero.
    if step.is_some_and(|step| !digits(step) || step.trim_start_matches('0').is_empty()) {
        return false;
    }
    if base == "*" {
        return true;
    }
    if index == DAY_OF_MONTH && step.is_none() {
        if matches!(base, "L" | "LW") || last_offset(base) {
            return true;
        }
        if let Some(day) = base.strip_suffix('W')
            && value(day, index)
        {
            return true;
        }
    }
    if index == DAY_OF_WEEK && step.is_none() {
        if base == "L" || base.strip_suffix('L').is_some_and(|day| value(day, index)) {
            return true;
        }
        if let Some((day, nth)) = base.split_once('#') {
            return value(day, index) && matches!(nth, "1" | "2" | "3" | "4" | "5");
        }
    }
    match base.split_once('-') {
        Some((start, end)) => value(start, index) && value(end, index),
        None => value(base, index),
    }
}

/// Whether `cron` is a Quartz expression of 6 or 7 fields.
///
/// Each field takes `*`, values, ranges, lists and steps in its own range
/// (names for months and days), day of month `L`, `LW`, `L-n` and `nW`, day of
/// week `L`, `nL` and `n#k`. Quartz needs `?` in exactly one of day of month
/// and day of week.
pub fn cron_ok(cron: &str) -> bool {
    let fields: Vec<&str> = cron
        .split(is_python_space)
        .filter(|field| !field.is_empty())
        .collect();
    if !(6..=7).contains(&fields.len()) {
        return false;
    }
    let question: Vec<usize> = (0..fields.len()).filter(|i| fields[*i] == "?").collect();
    if question != [DAY_OF_MONTH] && question != [DAY_OF_WEEK] {
        return false;
    }
    fields.iter().enumerate().all(|(index, field)| {
        *field == "?"
            || field
                .split(',')
                .all(|text| !text.is_empty() && part(text, index))
    })
}

/// The IANA zone and link names.
fn zones() -> &'static BTreeSet<&'static str> {
    static ZONES: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    const TEXT: &str = include_str!(concat!(
        env!("OPENTIDE_ASSETS"),
        "/data/catalogs/tz/zones.txt"
    ));
    ZONES.get_or_init(|| {
        TEXT.lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    })
}

/// Whether `name` is an IANA time zone name.
pub fn timezone_ok(name: &str) -> bool {
    !python_strip(name).is_empty() && zones().contains(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quartz_expressions() {
        for good in [
            "0 */5 * * * ?",
            "0 */10 * * * ?",
            "0 0 12 ? * MON-FRI",
            "0 15 10 ? * 6L",
            "0 15 10 ? * 6#3",
            "0 15 10 ? * L",
            "0 15 10 L * ?",
            "0 15 10 LW * ?",
            "0 15 10 L-3 * ?",
            "0 15 10 15W * ?",
            "0 0 0 1,15 jan-mar ? 2030",
            "0 0/90 * * * ?",
            "0 0 0 ? * sun",
        ] {
            assert!(cron_ok(good), "{good}");
        }
        for bad in [
            "",
            "* * * * *",
            "0 * * * * ? 2030 x",
            "0 * * * * *",
            "0 * * ? * ?",
            "? * * 1 * *",
            "60 * * * * ?",
            "0 * 24 * * ?",
            "0 * * 0 * ?",
            "0 * * * 13 ?",
            "0 * * ? * 8",
            "0 * * * * ? 1969",
            "0 */0 * * * ?",
            "0 */x * * * ?",
            "0 1,,2 * * * ?",
            "0 * * ? * 6#6",
            "0 * * ? * L-2",
            "0 * * L/2 * ?",
            "0 * * 1-x * ?",
            "0 * * ? * FOO",
            "0 * * 1L * ?",
        ] {
            assert!(!cron_ok(bad), "{bad}");
        }
    }

    #[test]
    fn time_zones() {
        for good in ["UTC", "Europe/Paris", "America/Argentina/Buenos_Aires"] {
            assert!(timezone_ok(good), "{good}");
        }
        for bad in ["", " ", "Mars/Olympus", "europe/paris", " UTC"] {
            assert!(!timezone_ok(bad), "{bad}");
        }
    }
}
