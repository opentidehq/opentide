//! YAML 1.1 as the oracle reads it: PyYAML's implicit resolvers
//! (`yaml/resolver.py`) and `SafeConstructor`'s scalar constructors
//! (`yaml/constructor.py`), with opentide's timestamp handling
//! (`opentide.core.io._construct_timestamp_text`: a date or timestamp becomes
//! its ISO 8601 text, and one that cannot exist is a YAML error).
//!
//! PyYAML 6.0.3 at the oracle (opentide 0.23.0). Every rule here is checked
//! case by case against it: `tests/yaml_table.rs` and
//! `tests/oracle/yaml_table.json`.

use std::sync::OnceLock;

use regex::Regex;

use super::integer::{Integer, is_python_space};

/// The YAML 1.1 tags PyYAML's safe loader knows, and every other one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tag {
    Null,
    Bool,
    Int,
    Float,
    Str,
    Timestamp,
    /// `<<`: merged into the mapping it is a key of.
    Merge,
    /// `=`: no constructor (an error as a value, `str` as a key).
    Value,
    Seq,
    Map,
    /// `!!binary`, `!!omap`, `!!pairs`, `!!set`: PyYAML constructs them; the
    /// Rust tree has no value for them (bytes, tuples, sets), so they are
    /// refused ([`super::LoadErrorKind::Unsupported`]).
    Unsupported(String),
    /// Any other tag: PyYAML has no constructor for it.
    Unknown(String),
}

const CORE: &str = "tag:yaml.org,2002:";

impl Tag {
    /// The tag an explicit `!!name` or `!<…>` names.
    pub(crate) fn explicit(tag: &str) -> Self {
        match tag.strip_prefix(CORE) {
            Some("null") => Self::Null,
            Some("bool") => Self::Bool,
            Some("int") => Self::Int,
            Some("float") => Self::Float,
            Some("str") => Self::Str,
            Some("timestamp") => Self::Timestamp,
            Some("merge") => Self::Merge,
            Some("value") => Self::Value,
            Some("seq") => Self::Seq,
            Some("map") => Self::Map,
            Some(name @ ("binary" | "omap" | "pairs" | "set")) => {
                Self::Unsupported(name.to_owned())
            }
            _ => Self::Unknown(tag.to_owned()),
        }
    }

    /// The tag's full name, as PyYAML's messages print it.
    pub(crate) fn name(&self) -> String {
        let short = match self {
            Self::Null => "null",
            Self::Bool => "bool",
            Self::Int => "int",
            Self::Float => "float",
            Self::Str => "str",
            Self::Timestamp => "timestamp",
            Self::Merge => "merge",
            Self::Value => "value",
            Self::Seq => "seq",
            Self::Map => "map",
            Self::Unsupported(name) => name,
            Self::Unknown(tag) => return tag.clone(),
        };
        format!("{CORE}{short}")
    }
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| {
        #[expect(
            clippy::expect_used,
            reason = "a pattern literal of this module, compiled by the tests"
        )]
        Regex::new(pattern).expect("a valid pattern literal")
    })
}

fn float_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
    )
}

fn int_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r"^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$",
    )
}

fn timestamp_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r"^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$",
    )
}

/// The constructor's pattern, with its groups (`SafeConstructor.timestamp_regexp`).
fn timestamp_parts() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r"^(?P<year>[0-9][0-9][0-9][0-9])-(?P<month>[0-9][0-9]?)-(?P<day>[0-9][0-9]?)(?:(?:[Tt]|[ \t]+)(?P<hour>[0-9][0-9]?):(?P<minute>[0-9][0-9]):(?P<second>[0-9][0-9])(?:\.(?P<fraction>[0-9]*))?(?:[ \t]*(?P<tz>Z|(?P<tz_sign>[-+])(?P<tz_hour>[0-9][0-9]?)(?::(?P<tz_minute>[0-9][0-9]))?))?)?$",
    )
}

/// The tag PyYAML's resolver gives a plain scalar (`Resolver.resolve` with
/// `implicit[0]`): the first implicit resolver registered for the value's
/// first character whose pattern matches, else `str`.
pub(crate) fn resolve_plain(value: &str) -> Tag {
    let Some(first) = value.chars().next() else {
        return Tag::Null;
    };
    // In PyYAML's registration order: bool, float, int, merge, null,
    // timestamp, value; each only for its first characters.
    if "yYnNtTfFoO".contains(first)
        && matches!(
            value,
            "yes"
                | "Yes"
                | "YES"
                | "no"
                | "No"
                | "NO"
                | "true"
                | "True"
                | "TRUE"
                | "false"
                | "False"
                | "FALSE"
                | "on"
                | "On"
                | "ON"
                | "off"
                | "Off"
                | "OFF"
        )
    {
        return Tag::Bool;
    }
    if "-+0123456789.".contains(first) && float_pattern().is_match(value) {
        return Tag::Float;
    }
    if "-+0123456789".contains(first) && int_pattern().is_match(value) {
        return Tag::Int;
    }
    if value == "<<" {
        return Tag::Merge;
    }
    if matches!(value, "~" | "null" | "Null" | "NULL") {
        return Tag::Null;
    }
    if first.is_ascii_digit() && timestamp_pattern().is_match(value) {
        return Tag::Timestamp;
    }
    if value == "=" {
        return Tag::Value;
    }
    Tag::Str
}

/// Why a scalar could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScalarError {
    /// A `yaml.YAMLError` (opentide's `InvalidDateError` for a date that
    /// cannot exist): `yaml_parse`.
    Yaml(String),
    /// An exception that is not a `YAMLError` (`ValueError`, `KeyError`,
    /// `AttributeError`, `IndexError`): the oracle's loader does not catch it.
    Python(String),
}

/// A constructed scalar.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Scalar {
    Null,
    Bool(bool),
    Int(Integer),
    Float(f64),
    Str(String),
}

/// `SafeConstructor.construct_yaml_bool`: `bool_values[value.lower()]`.
pub(crate) fn construct_bool(value: &str) -> Result<Scalar, ScalarError> {
    match value.to_lowercase().as_str() {
        "yes" | "true" | "on" => Ok(Scalar::Bool(true)),
        "no" | "false" | "off" => Ok(Scalar::Bool(false)),
        other => Err(ScalarError::Python(format!("KeyError: '{other}'"))),
    }
}

/// `SafeConstructor.construct_yaml_int`.
pub(crate) fn construct_int(value: &str) -> Result<Scalar, ScalarError> {
    let invalid =
        || ScalarError::Python(format!("ValueError: invalid literal for int(): {value:?}"));
    let cleaned: String = value.chars().filter(|&c| c != '_').collect();
    let mut rest = cleaned.as_str();
    let Some(first) = rest.chars().next() else {
        return Err(ScalarError::Python(
            "IndexError: string index out of range".to_owned(),
        ));
    };
    let negative = first == '-';
    if first == '-' || first == '+' {
        rest = &rest[1..];
    }
    let sign = |integer: Integer| if negative { integer.negated() } else { integer };
    let magnitude = if rest == "0" {
        Integer::zero()
    } else if let Some(binary) = rest.strip_prefix("0b") {
        Integer::parse_python(binary, 2).ok_or_else(invalid)?
    } else if let Some(hex) = rest.strip_prefix("0x") {
        Integer::parse_python(hex, 16).ok_or_else(invalid)?
    } else if rest.starts_with('0') {
        Integer::parse_python(rest, 8).ok_or_else(invalid)?
    } else if rest.contains(':') {
        // Σ part × 60^k, written as Horner's rule from the left.
        let mut total = Integer::zero();
        for part in rest.split(':') {
            let digit = Integer::parse_python(part, 10).ok_or_else(invalid)?;
            if digit.is_negative() {
                // Only an explicit `!!int 1:-2` gets here; Python would
                // subtract. Refused rather than computed differently.
                return Err(invalid());
            }
            total = total.times(60);
            total.add_magnitude(&digit);
        }
        total
    } else {
        Integer::parse_python(rest, 10).ok_or_else(invalid)?
    };
    // `int(value[2:], 2)` may itself carry a sign (`!!int 0b-1`): Python
    // multiplies the two.
    Ok(Scalar::Int(sign(magnitude)))
}

/// Python's `float(text)`, which `construct_yaml_float` calls.
fn python_float(text: &str) -> Option<f64> {
    let text = text.trim_matches(is_python_space);
    let lower = text.to_ascii_lowercase();
    let unsigned = lower.trim_start_matches(['+', '-']);
    // Rust accepts what Python accepts here, except that Python also takes
    // `infinity`/`inf`/`nan` (Rust does too) and refuses a sign repeated.
    if lower.len() - unsigned.len() > 1 || text.is_empty() {
        return None;
    }
    text.parse::<f64>().ok()
}

/// `SafeConstructor.construct_yaml_float`.
pub(crate) fn construct_float(value: &str) -> Result<Scalar, ScalarError> {
    let invalid = || {
        ScalarError::Python(format!(
            "ValueError: could not convert string to float: {value:?}"
        ))
    };
    let cleaned: String = value
        .chars()
        .filter(|&c| c != '_')
        .collect::<String>()
        .to_lowercase();
    let mut rest = cleaned.as_str();
    let Some(first) = rest.chars().next() else {
        return Err(ScalarError::Python(
            "IndexError: string index out of range".to_owned(),
        ));
    };
    let sign = if first == '-' { -1.0 } else { 1.0 };
    if first == '-' || first == '+' {
        rest = &rest[1..];
    }
    if rest == ".inf" {
        return Ok(Scalar::Float(sign * f64::INFINITY));
    }
    if rest == ".nan" {
        return Ok(Scalar::Float(f64::NAN));
    }
    if rest.contains(':') {
        let mut total = 0.0;
        let mut base = 1.0;
        for part in rest.split(':').rev() {
            let digit = python_float(part).ok_or_else(invalid)?;
            total += digit * base;
            base *= 60.0;
        }
        return Ok(Scalar::Float(sign * total));
    }
    Ok(Scalar::Float(
        sign * python_float(rest).ok_or_else(invalid)?,
    ))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `construct_yaml_timestamp`, then opentide's `stringify_yaml_temporals`:
/// the value's `isoformat()`, with a `+00:00` offset written `Z`.
pub(crate) fn construct_timestamp(value: &str) -> Result<Scalar, ScalarError> {
    let Some(parts) = timestamp_parts().captures(value) else {
        return Err(ScalarError::Python(
            "AttributeError: 'NoneType' object has no attribute 'groupdict'".to_owned(),
        ));
    };
    let number = |name: &str| -> u32 {
        parts
            .name(name)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0)
    };
    let invalid =
        |reason: &str| ScalarError::Yaml(format!("'{value}' is not a valid date ({reason})"));
    let (year, month, day) = (number("year"), number("month"), number("day"));
    if year == 0 {
        return Err(invalid(&format!("year {year} is out of range")));
    }
    if !(1..=12).contains(&month) {
        return Err(invalid("month must be in 1..12"));
    }
    if day == 0 || day > days_in_month(year, month) {
        return Err(invalid("day is out of range for month"));
    }
    let date = format!("{year:04}-{month:02}-{day:02}");
    if parts.name("hour").is_none() {
        return Ok(Scalar::Str(date));
    }
    let (hour, minute, second) = (number("hour"), number("minute"), number("second"));
    if hour > 23 {
        return Err(invalid("hour must be in 0..23"));
    }
    if minute > 59 {
        return Err(invalid("minute must be in 0..59"));
    }
    if second > 59 {
        return Err(invalid("second must be in 0..59"));
    }
    let mut text = format!("{date}T{hour:02}:{minute:02}:{second:02}");
    if let Some(fraction) = parts.name("fraction").map(|m| m.as_str())
        && !fraction.is_empty()
    {
        let mut digits: String = fraction.chars().take(6).collect();
        while digits.len() < 6 {
            digits.push('0');
        }
        if digits != "000000" {
            text.push('.');
            text.push_str(&digits);
        }
    }
    if let Some(sign) = parts.name("tz_sign").map(|m| m.as_str()) {
        let minutes = number("tz_hour") * 60 + number("tz_minute");
        if minutes >= 24 * 60 {
            let total = i64::from(minutes) * 60 * if sign == "-" { -1 } else { 1 };
            return Err(invalid(&format!(
                "offset must be a timedelta strictly between -timedelta(hours=24) and \
                 timedelta(hours=24), not {}.",
                timedelta_repr(total)
            )));
        }
        if minutes == 0 {
            text.push('Z');
        } else {
            text.push_str(&format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60));
        }
    } else if parts.name("tz").is_some() {
        text.push('Z');
    }
    Ok(Scalar::Str(text))
}

/// Python's `repr(timedelta(seconds=total))`.
fn timedelta_repr(total: i64) -> String {
    let days = total.div_euclid(86_400);
    let seconds = total.rem_euclid(86_400);
    match (days, seconds) {
        (0, s) => format!("datetime.timedelta(seconds={s})"),
        (d, 0) => format!("datetime.timedelta(days={d})"),
        (d, s) => format!("datetime.timedelta(days={d}, seconds={s})"),
    }
}

/// Python's `repr(float)`: the shortest text that reads back as the value,
/// in scientific notation below 1e-4 and from 1e16.
pub fn python_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        }
        .to_owned();
    }
    // `{:e}` is the shortest round-trip digits: `1.5e16`, `-1e-5`.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if negative { "-" } else { "" };
    if !(-4..16).contains(&exponent) {
        let (head, tail) = digits.split_at(1);
        let fraction = if tail.is_empty() {
            String::new()
        } else {
            format!(".{tail}")
        };
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        return format!(
            "{sign}{head}{fraction}e{exponent_sign}{:02}",
            exponent.abs()
        );
    }
    let point = exponent + 1;
    let length = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    if point <= 0 {
        let zeros = "0".repeat(usize::try_from(-point).unwrap_or(0));
        format!("{sign}0.{zeros}{digits}")
    } else if point >= length {
        let zeros = "0".repeat(usize::try_from(point - length).unwrap_or(0));
        format!("{sign}{digits}{zeros}.0")
    } else {
        let (whole, fraction) = digits.split_at(usize::try_from(point).unwrap_or(0));
        format!("{sign}{whole}.{fraction}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_is_pythons() {
        for (value, text) in [
            (1.0, "1.0"),
            (0.5, "0.5"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (123_456_789.123_456_79, "123456789.12345679"),
            (-1.5, "-1.5"),
            (1e22, "1e+22"),
            (9_999_999_999_999_998.0, "9999999999999998.0"),
            (685_230.15, "685230.15"),
        ] {
            assert_eq!(python_float_repr(value), text, "{value}");
        }
    }

    #[test]
    fn plain_resolution() {
        assert_eq!(resolve_plain(""), Tag::Null);
        assert_eq!(resolve_plain("1e3"), Tag::Str);
        assert_eq!(resolve_plain("1.0e+3"), Tag::Float);
        assert_eq!(resolve_plain("0o17"), Tag::Str);
        assert_eq!(resolve_plain("017"), Tag::Int);
        assert_eq!(resolve_plain("2026-01-01"), Tag::Timestamp);
        assert_eq!(resolve_plain("y"), Tag::Str);
        assert_eq!(resolve_plain("<<"), Tag::Merge);
        assert_eq!(resolve_plain("="), Tag::Value);
    }
}
