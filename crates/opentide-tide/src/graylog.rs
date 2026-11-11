//! The Graylog block (`configurations.graylog`, graylog-1.0): its constraint
//! codes and the `graylog_overlapping_window` advisory, reported natively so
//! the editor and `opentide validate` agree, and completion and hover for the
//! aggregation functions of `aggregation.condition`.
//!
//! The codes, their conditions, their order and their field paths follow
//! graylog-1.0 "Constraints" and `validate_graylog_block` in
//! opentidehq/specifications' `scripts/object_fixtures.py`, its reference
//! checker; the condition grammar is graylog-1.0 "Condition grammar"
//! (`parse_graylog_condition` there). Where the reference checks less than
//! the spec says, this follows the spec: a cron expression is checked as a
//! Quartz expression the way Graylog's cron-utils reads it, not only for its
//! field count, and a call's arguments are separated by commas.
//!
//! The query is Lucene in the Graylog dialect (`opentide_lucene::graylog`).
//! `graylog_all_streams` needs the tenant and `graylog_title_duplicate` the
//! workspace: both are opentide's.

use crate::yaml_path::YamlCursor;
use opentide_core::{ByteSpan, CompletionItem, Diagnostic, Range, codes, span_to_range};
use serde_yaml::Value;
use std::sync::OnceLock;

const BLOCK: [&str; 2] = ["configurations", "graylog"];
const LIST_FIELDS: [&str; 5] = [
    "tags",
    "streams",
    "stream_categories",
    "event_key",
    "notifications",
];
const PRIORITIES: [&str; 5] = ["Informational", "Low", "Medium", "High", "Critical"];
/// The default `schedule.every` (graylog-1.0, Defaults).
const DEFAULT_EVERY_SECONDS: u64 = 300;

/// Graylog's 12 aggregation functions, with what each computes and the
/// arguments it takes (graylog-1.0, "Condition grammar").
pub const FUNCTIONS: [(&str, &str, &str); 12] = [
    ("avg", "avg(field)", "The average of a numeric field."),
    (
        "card",
        "card(field)",
        "The cardinality of a field: how many distinct values it has.",
    ),
    (
        "count",
        "count() or count(field)",
        "The number of messages; with a field, of messages that have it.",
    ),
    ("latest", "latest(field)", "The field's most recent value."),
    ("max", "max(field)", "The largest value of a numeric field."),
    (
        "min",
        "min(field)",
        "The smallest value of a numeric field.",
    ),
    (
        "percentage",
        "percentage(field)",
        "The field's share of the total, as a percentage.",
    ),
    (
        "percentile",
        "percentile(field, p)",
        "The value below which `p` percent of the field's values fall, `0 < p ≤ 100`.",
    ),
    (
        "stddev",
        "stddev(field)",
        "The standard deviation of a numeric field.",
    ),
    ("sum", "sum(field)", "The sum of a numeric field."),
    (
        "sumofsquares",
        "sumofsquares(field)",
        "The sum of the squares of a numeric field.",
    ),
    (
        "variance",
        "variance(field)",
        "The variance of a numeric field.",
    ),
];

const OPERATORS: [&str; 5] = [">=", ">", "<=", "<", "=="];

fn function_names() -> String {
    FUNCTIONS
        .iter()
        .map(|(n, _, _)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `[A-Za-z0-9_.@-]+`: a Graylog field name.
pub(crate) fn field_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-'))
}

// --------------------------------------------------------------------------
// Condition grammar

/// A comparison's number, as written (`3`, `-1`, `2.5`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Number(pub String);

impl Number {
    /// As Graylog takes it: an integer when it has no fraction.
    pub(crate) fn json(&self) -> serde_json::Value {
        if !self.0.contains('.')
            && let Ok(n) = self.0.parse::<i64>()
        {
            return n.into();
        }
        self.0.parse::<f64>().map_or(serde_json::Value::Null, |f| {
            serde_json::Number::from_f64(f).map_or(serde_json::Value::Null, Into::into)
        })
    }

    fn value(&self) -> f64 {
        self.0.parse().unwrap_or(f64::NAN)
    }
}

/// A condition expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Compare {
        op: &'static str,
        series: String,
        value: Number,
    },
}

impl Expr {
    /// Graylog's condition tree (graylog-1.0, "Compilation").
    pub(crate) fn json(&self) -> serde_json::Value {
        use serde_json::json;
        match self {
            Expr::Or(a, b) => json!({"expr": "||", "left": a.json(), "right": b.json()}),
            Expr::And(a, b) => json!({"expr": "&&", "left": a.json(), "right": b.json()}),
            Expr::Not(a) => json!({"expr": "!", "left": a.json()}),
            Expr::Compare { op, series, value } => json!({
                "expr": op,
                "left": {"expr": "number-ref", "ref": series},
                "right": {"expr": "number", "value": value.json()},
            }),
        }
    }
}

/// One series: a distinct call, in order of first appearance.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Series {
    pub id: String,
    pub function: &'static str,
    pub field: Option<String>,
    pub percentile: Option<f64>,
}

impl Series {
    pub(crate) fn json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("id".into(), self.id.clone().into());
        map.insert("type".into(), self.function.into());
        if let Some(field) = &self.field {
            map.insert("field".into(), field.clone().into());
        }
        if let Some(p) = self.percentile.and_then(serde_json::Number::from_f64) {
            map.insert("percentile".into(), p.into());
        }
        map.into()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Condition {
    pub expr: Expr,
    pub series: Vec<Series>,
}

/// Why a condition does not parse, and where: a byte range of the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionError {
    pub message: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy)]
struct Token<'a> {
    text: &'a str,
    start: usize,
    word: bool,
}

impl Token<'_> {
    fn end(&self) -> usize {
        self.start + self.text.len()
    }
}

fn tokenize(text: &str) -> Result<Vec<Token<'_>>, ConditionError> {
    let mut tokens = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < text.len() {
        let c = text[i..].chars().next().unwrap_or(' ');
        if c.is_whitespace() {
            i += c.len_utf8();
            continue;
        }
        let two = text.get(i..i + 2).unwrap_or("");
        let len = if matches!(two, ">=" | "<=" | "==") {
            2
        } else if matches!(c, '>' | '<' | '(' | ')' | ',') {
            1
        } else if field_name(&c.to_string()) {
            let mut j = i;
            while j < bytes.len() && field_name(&(bytes[j] as char).to_string()) {
                j += 1;
            }
            tokens.push(Token {
                text: &text[i..j],
                start: i,
                word: true,
            });
            i = j;
            continue;
        } else {
            return Err(ConditionError {
                message: format!(
                    "unexpected `{c}`: a condition holds calls, comparisons (`>=`, `>`, `<=`, `<`, `==`), numbers, `AND`, `OR`, `NOT`, and parentheses"
                ),
                start: i,
                end: i + c.len_utf8(),
            });
        };
        tokens.push(Token {
            text: &text[i..i + len],
            start: i,
            word: false,
        });
        i += len;
    }
    Ok(tokens)
}

struct Parser<'a> {
    text: &'a str,
    tokens: Vec<Token<'a>>,
    index: usize,
    series: Vec<Series>,
}

fn number(token: &str) -> bool {
    let digits = token.strip_prefix('-').unwrap_or(token);
    let (int, frac) = match digits.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (digits, None),
    };
    let all = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    all(int) && frac.is_none_or(all)
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<Token<'a>> {
        self.tokens.get(self.index).copied()
    }

    fn peek_is(&self, text: &str) -> bool {
        self.peek().is_some_and(|t| t.text == text)
    }

    fn fail<T>(&self, message: String, at: Option<Token>) -> Result<T, ConditionError> {
        let (start, end) = match at {
            Some(t) => (t.start, t.end()),
            None => {
                // The end of the condition: its last character.
                let end = self.text.trim_end().len();
                let start = self.text[..end]
                    .char_indices()
                    .next_back()
                    .map_or(0, |(i, _)| i);
                (start, end)
            }
        };
        Err(ConditionError {
            message,
            start,
            end,
        })
    }

    fn expect(&mut self, text: &str, what: &str) -> Result<Token<'a>, ConditionError> {
        match self.peek() {
            Some(t) if t.text == text => {
                self.index += 1;
                Ok(t)
            }
            Some(t) => self.fail(format!("expected {what}, found `{}`", t.text), Some(t)),
            None => self.fail(format!("expected {what}, but the condition ends"), None),
        }
    }

    fn or(&mut self) -> Result<Expr, ConditionError> {
        let mut node = self.and()?;
        while self.peek_is("OR") {
            self.index += 1;
            node = Expr::Or(Box::new(node), Box::new(self.and()?));
        }
        Ok(node)
    }

    fn and(&mut self) -> Result<Expr, ConditionError> {
        let mut node = self.not()?;
        while self.peek_is("AND") {
            self.index += 1;
            node = Expr::And(Box::new(node), Box::new(self.not()?));
        }
        Ok(node)
    }

    fn not(&mut self) -> Result<Expr, ConditionError> {
        if self.peek_is("NOT") {
            self.index += 1;
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, ConditionError> {
        if self.peek_is("(") {
            self.index += 1;
            let node = self.or()?;
            self.expect(")", "`)`")?;
            return Ok(node);
        }
        let series = self.call()?;
        let op = match self.peek() {
            Some(t) if OPERATORS.contains(&t.text) => {
                self.index += 1;
                OPERATORS
                    .iter()
                    .copied()
                    .find(|o| *o == t.text)
                    .unwrap_or(">")
            }
            Some(t) => {
                return self.fail(
                    format!(
                        "expected a comparison (`>=`, `>`, `<=`, `<`, `==`) after the call, found `{}`",
                        t.text
                    ),
                    Some(t),
                );
            }
            None => {
                return self.fail(
                    "expected a comparison (`>=`, `>`, `<=`, `<`, `==`) after the call, but the condition ends".into(),
                    None,
                );
            }
        };
        let value = match self.peek() {
            Some(t) if t.word && number(t.text) => {
                self.index += 1;
                Number(t.text.to_string())
            }
            Some(t) => {
                return self.fail(
                    format!("`{}` is not a number (`3`, `-1`, `2.5`)", t.text),
                    Some(t),
                );
            }
            None => {
                return self.fail(
                    format!("expected a number after `{op}`, but the condition ends"),
                    None,
                );
            }
        };
        Ok(Expr::Compare { op, series, value })
    }

    /// A call: the series id it compiles to.
    fn call(&mut self) -> Result<String, ConditionError> {
        let Some(head) = self.peek() else {
            return self.fail(
                "expected an aggregation function call, but the condition ends".into(),
                None,
            );
        };
        let Some(&(function, signature, _)) = FUNCTIONS
            .iter()
            .find(|(n, _, _)| head.word && *n == head.text)
        else {
            let hint = if matches!(head.text, "and" | "or" | "not") {
                format!(
                    "; operators are upper case (`{}`)",
                    head.text.to_ascii_uppercase()
                )
            } else {
                String::new()
            };
            return self.fail(
                format!(
                    "`{}` is not an aggregation function: Graylog has {}{hint}",
                    head.text,
                    function_names()
                ),
                Some(head),
            );
        };
        self.index += 1;
        self.expect("(", &format!("`(` after `{function}`"))?;
        let mut field = None;
        let mut percentile = None;
        if !self.peek_is(")") {
            match self.peek() {
                Some(t) if t.word => {
                    self.index += 1;
                    field = Some(t);
                }
                Some(t) => {
                    return self.fail(
                        format!("`{}` is not a field name (`[A-Za-z0-9_.@-]+`)", t.text),
                        Some(t),
                    );
                }
                None => {
                    return self.fail(format!("`{function}(` is never closed"), None);
                }
            }
            if self.peek_is(",") {
                self.index += 1;
                match self.peek() {
                    Some(t) if t.word && number(t.text) => {
                        self.index += 1;
                        percentile = Some(t);
                    }
                    Some(t) => {
                        return self.fail(format!("`{}` is not a number", t.text), Some(t));
                    }
                    None => {
                        return self.fail(format!("`{function}(` is never closed"), None);
                    }
                }
            }
        }
        let close = self.expect(")", &format!("`)` to close `{function}(`"))?;
        let call = Token {
            text: &self.text[head.start..close.end()],
            start: head.start,
            word: false,
        };
        let wrong = |message: String| -> Result<String, ConditionError> {
            Err(ConditionError {
                message: format!("`{}`: {message}; write `{signature}`", call.text),
                start: call.start,
                end: call.end(),
            })
        };
        match (function, field, percentile) {
            ("count", _, Some(_)) => return wrong("count takes no field or one field".into()),
            ("count", _, None) => {}
            ("percentile", Some(_), Some(p)) => {
                let value = Number(p.text.to_string()).value();
                if !(value > 0.0 && value <= 100.0) {
                    return wrong(format!(
                        "the percentile is greater than 0 and at most 100, not {}",
                        p.text
                    ));
                }
            }
            ("percentile", _, _) => {
                return wrong("percentile takes a field and a percentile".into());
            }
            (_, Some(_), None) => {}
            (f, _, _) => return wrong(format!("{f} takes one field")),
        }
        let field_text = field.map(|f| f.text.to_string());
        let mut id = format!("{function}-{}", field_text.as_deref().unwrap_or(""));
        if let Some(p) = percentile {
            id.push('-');
            id.push_str(p.text);
        }
        if !self.series.iter().any(|s| s.id == id) {
            self.series.push(Series {
                id: id.clone(),
                function,
                field: field_text,
                percentile: percentile.map(|p| Number(p.text.to_string()).value()),
            });
        }
        Ok(id)
    }
}

/// Compile an aggregation condition the way deploy sends it (graylog-1.0,
/// "Compilation"): `{"series": [...], "conditions": {"expression": ...}}`,
/// one series per distinct call in order of first appearance.
pub fn compile_condition(text: &str) -> Result<serde_json::Value, ConditionError> {
    let c = parse_condition(text)?;
    Ok(serde_json::json!({
        "series": c.series.iter().map(Series::json).collect::<Vec<_>>(),
        "conditions": {"expression": c.expr.json()},
    }))
}

/// Parse an aggregation condition (graylog-1.0, "Condition grammar").
pub(crate) fn parse_condition(text: &str) -> Result<Condition, ConditionError> {
    let tokens = tokenize(text)?;
    let mut parser = Parser {
        text,
        tokens,
        index: 0,
        series: Vec::new(),
    };
    if parser.tokens.is_empty() {
        return parser.fail("the condition is empty".into(), None);
    }
    let expr = parser.or()?;
    if let Some(t) = parser.peek() {
        let message = if matches!(t.text, "and" | "or" | "not") {
            format!(
                "unexpected `{}`: operators are upper case (`{}`)",
                t.text,
                t.text.to_ascii_uppercase()
            )
        } else {
            format!("unexpected `{}`", t.text)
        };
        return parser.fail(message, Some(t));
    }
    Ok(Condition {
        expr,
        series: parser.series,
    })
}

// --------------------------------------------------------------------------
// Schedule

/// Seconds in a duration of elastic-1.0 "Durations"; `None` when it is not
/// one.
pub(crate) fn duration_seconds(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    if text.trim() != text {
        return None;
    }
    crate::elastic::duration_millis(text).map(|ms| ms / 1000)
}

/// The IANA zone and link names (`catalogs/tz/zones.txt`).
fn zones() -> &'static [&'static str] {
    static ZONES: OnceLock<Vec<&'static str>> = OnceLock::new();
    const TEXT: &str = include_str!(concat!(env!("OPENTIDE_ASSETS"), "/catalogs/tz/zones.txt"));
    ZONES.get_or_init(|| {
        TEXT.lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    })
}

pub(crate) fn iana_zone(name: &str) -> bool {
    zones().binary_search(&name).is_ok()
}

/// One cron field: its name, bounds, and the names it takes.
struct CronField {
    name: &'static str,
    min: u32,
    max: u32,
    names: &'static [&'static str],
}

const MONTHS: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
];
const DAYS: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

const CRON_FIELDS: [CronField; 7] = [
    CronField {
        name: "seconds",
        min: 0,
        max: 59,
        names: &[],
    },
    CronField {
        name: "minutes",
        min: 0,
        max: 59,
        names: &[],
    },
    CronField {
        name: "hours",
        min: 0,
        max: 23,
        names: &[],
    },
    CronField {
        name: "day of month",
        min: 1,
        max: 31,
        names: &[],
    },
    CronField {
        name: "month",
        min: 1,
        max: 12,
        names: &MONTHS,
    },
    CronField {
        name: "day of week",
        min: 1,
        max: 7,
        names: &DAYS,
    },
    CronField {
        name: "year",
        min: 1970,
        max: 2099,
        names: &[],
    },
];

const DAY_OF_MONTH: usize = 3;
const DAY_OF_WEEK: usize = 5;
const YEAR: usize = 6;

/// A value of a cron field: a number in bounds or one of its names.
fn cron_value(field: &CronField, text: &str) -> Result<u32, String> {
    if let Some(i) = field
        .names
        .iter()
        .position(|n| n.eq_ignore_ascii_case(text))
    {
        return Ok(field.min + i as u32);
    }
    let n: u32 = text
        .parse()
        .ok()
        .filter(|_| text.chars().all(|c| c.is_ascii_digit()))
        .ok_or_else(|| format!("`{text}` is not a {} value", field.name))?;
    if n < field.min || n > field.max {
        return Err(format!(
            "{} {n} is not in {}-{}",
            field.name, field.min, field.max
        ));
    }
    Ok(n)
}

/// One comma-separated item of a cron field.
fn cron_item(index: usize, field: &CronField, item: &str) -> Result<(), String> {
    let upper = item.to_ascii_uppercase();
    let (base, step) = match upper.split_once('/') {
        Some((b, s)) => (b, Some(s)),
        None => (upper.as_str(), None),
    };
    if let Some(step) = step {
        // cron-utils: an increment from 1 to the field's maximum (any, for
        // the year).
        let ok = !step.is_empty()
            && step.chars().all(|c| c.is_ascii_digit())
            && step
                .parse::<u32>()
                .is_ok_and(|s| s >= 1 && (index == YEAR || s <= field.max));
        if !ok {
            return Err(format!(
                "`{item}`: the increment after `/` is a whole number from 1 to {}",
                field.max
            ));
        }
    }
    if base == "*" {
        return Ok(());
    }
    let week = &CRON_FIELDS[DAY_OF_WEEK];
    if index == DAY_OF_MONTH {
        if base == "L" || base == "LW" {
            return Ok(());
        }
        if let Some(offset) = base.strip_prefix("L-") {
            return cron_value(field, offset).map(|_| ());
        }
        if let Some(day) = base.strip_suffix('W') {
            return cron_value(field, day).map(|_| ());
        }
    }
    if index == DAY_OF_WEEK {
        if base == "L" {
            return Ok(());
        }
        if let Some(offset) = base.strip_prefix("L-") {
            return cron_value(week, offset).map(|_| ());
        }
        if let Some(day) = base.strip_suffix('L') {
            return cron_value(field, day).map(|_| ());
        }
        if let Some((day, nth)) = base.split_once('#') {
            cron_value(field, day)?;
            return cron_value(week, nth)
                .map(|_| ())
                .map_err(|_| format!("`{item}`: the occurrence after `#` is 1 to 7"));
        }
    }
    match base.split_once('-') {
        Some((from, to)) => {
            cron_value(field, from)?;
            cron_value(field, to)?;
            Ok(())
        }
        None => cron_value(field, base).map(|_| ()),
    }
}

/// A Quartz cron expression as Graylog's cron-utils (Quartz definition)
/// reads it: 6 or 7 fields, each in bounds, and exactly one of day of month
/// and day of week `?`.
pub(crate) fn quartz_cron(text: &str) -> Result<(), String> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    if !(6..=7).contains(&fields.len()) {
        return Err(format!(
            "a Quartz cron has 6 or 7 fields (seconds minutes hours day-of-month month day-of-week [year]), not {}",
            fields.len()
        ));
    }
    for (index, part) in fields.iter().enumerate() {
        let field = &CRON_FIELDS[index];
        if *part == "?" {
            if index != DAY_OF_MONTH && index != DAY_OF_WEEK {
                return Err(format!(
                    "`?` is for day of month or day of week, not {}",
                    field.name
                ));
            }
            continue;
        }
        for item in part.split(',') {
            cron_item(index, field, item)?;
        }
    }
    if (fields[DAY_OF_MONTH] == "?") == (fields[DAY_OF_WEEK] == "?") {
        return Err("exactly one of day of month and day of week is `?` (`0 */5 * * * ?`)".into());
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Diagnostics

fn full_path(path: &[&str]) -> Vec<String> {
    BLOCK.iter().chain(path).map(|p| p.to_string()).collect()
}

/// The written value at `path` (a scalar), else its key, else the nearest
/// written ancestor key.
fn node_range(source: &str, path: &[String]) -> Range {
    let want: Vec<&str> = path.iter().map(String::as_str).collect();
    if let Some((scalar, _)) = scalar_of(source, &want)
        && let (Some(first), Some(last)) = (scalar.map.first(), scalar.map.last())
    {
        return span_to_range(source, ByteSpan::new(*first, after(source, *last)));
    }
    crate::elastic::path_range(source, &want)
}

/// The end of the character whose byte `last` is (a scalar's map gives
/// each byte of a character its own source byte).
fn after(source: &str, last: usize) -> usize {
    let mut end = (last + 1).min(source.len());
    while !source.is_char_boundary(end) {
        end += 1;
    }
    end
}

fn scalar_of(source: &str, path: &[&str]) -> Option<(crate::yaml_scalar::Scalar, usize)> {
    let key = crate::yaml_scalar::mapping_keys(source)
        .into_iter()
        .find(|k| k.path_is(path))?;
    let at = key.scalar?;
    Some((crate::yaml_scalar::scalar_at(source, at, key.column)?, at))
}

fn finding(source: &str, error: bool, code: &str, message: String, path: &[&str]) -> Diagnostic {
    let full = full_path(path);
    let range = node_range(source, &full);
    let d = if error {
        Diagnostic::error(code, message, range)
    } else {
        Diagnostic::warning(code, message, range)
    };
    d.with_field_path(full)
}

fn err(source: &str, code: &str, message: String, path: &[&str]) -> Diagnostic {
    finding(source, true, code, message, path)
}

fn present(v: Option<&Value>) -> Option<&Value> {
    v.filter(|v| !v.is_null())
}

fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        _ => String::new(),
    }
}

/// A list field (graylog-1.0, "List fields"): absent, one non-blank string,
/// or a list of distinct non-blank strings.
fn list_ok(value: Option<&Value>) -> bool {
    match present(value) {
        None => true,
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(Value::Sequence(items)) => {
            let mut seen = Vec::new();
            for item in items {
                match item.as_str() {
                    Some(s) if !s.trim().is_empty() && !seen.contains(&s) => seen.push(s),
                    _ => return false,
                }
            }
            true
        }
        Some(_) => false,
    }
}

fn list_items(value: Option<&Value>) -> Vec<&str> {
    match present(value) {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Sequence(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// An event field value's form: `field`, `template`, or `lookup`.
fn event_field_kind(value: &Value) -> Option<&'static str> {
    let non_blank = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty())
    };
    match value {
        Value::String(s) if s.contains("${") => Some("template"),
        Value::String(s) => field_name(s).then_some("field"),
        Value::Mapping(map) if map.len() == 1 && map.contains_key("template") => {
            non_blank(map.get("template")).then_some("template")
        }
        Value::Mapping(map) if map.len() == 1 && map.contains_key("lookup") => {
            let lookup = map.get("lookup")?.as_mapping()?;
            (lookup.len() == 2
                && non_blank(lookup.get("table"))
                && non_blank(lookup.get("key_field")))
            .then_some("lookup")
        }
        _ => None,
    }
}

fn schedule(source: &str, schedule: &Value, out: &mut Vec<Diagnostic>) {
    const S: &str = "schedule";
    let Some(map) = schedule.as_mapping() else {
        out.push(err(
            source,
            codes::GRAYLOG_SCHEDULE,
            "`schedule` is a map: `every` or `cron`, `window`, `timezone`".into(),
            &[S],
        ));
        return;
    };
    let every = present(map.get("every"));
    let cron = present(map.get("cron"));
    let window = present(map.get("window"));
    if every.is_some() && cron.is_some() {
        out.push(err(
            source,
            codes::GRAYLOG_SCHEDULE,
            "`every` and `cron` are exclusive: a definition runs on an interval or on a cron schedule"
                .into(),
            &[S],
        ));
    }
    for (key, value) in [("every", every), ("window", window)] {
        if let Some(v) = value
            && duration_seconds(v).is_none_or(|s| s == 0)
        {
            out.push(err(
                source,
                codes::GRAYLOG_SCHEDULE,
                format!(
                    "`{key}` is a duration greater than zero (`5m`, `1h10m`, `PT15M`), not `{}`",
                    text_of(v)
                ),
                &[S, key],
            ));
        }
    }
    if let Some(cron) = cron {
        let problem = match cron.as_str() {
            Some(text) => quartz_cron(text).err(),
            None => Some("`cron` is a string".into()),
        };
        if let Some(problem) = problem {
            out.push(err(
                source,
                codes::GRAYLOG_SCHEDULE,
                format!("`cron` is not a Quartz cron expression: {problem}"),
                &[S, "cron"],
            ));
        }
        if window.is_none() {
            out.push(err(
                source,
                codes::GRAYLOG_SCHEDULE,
                "`window` is required with `cron`: it is the time range each run searches".into(),
                &[S, "window"],
            ));
        }
    }
    if let Some(tz) = present(map.get("timezone"))
        && !tz.as_str().is_some_and(iana_zone)
    {
        out.push(err(
            source,
            codes::GRAYLOG_SCHEDULE,
            format!(
                "`{}` is not an IANA time zone name (`UTC`, `Europe/Paris`)",
                text_of(tz)
            ),
            &[S, "timezone"],
        ));
    }
}

fn aggregation(source: &str, aggregation: &Value, out: &mut Vec<Diagnostic>) {
    const A: &str = "aggregation";
    let Some(condition) = aggregation
        .as_mapping()
        .and_then(|m| m.get("condition"))
        .and_then(Value::as_str)
    else {
        out.push(err(
            source,
            codes::GRAYLOG_AGGREGATION,
            "an aggregation needs a `condition` (`count() >= 3`)".into(),
            &[A],
        ));
        return;
    };
    let group_by = aggregation.get("group_by");
    if !list_ok(group_by) {
        out.push(err(
            source,
            codes::GRAYLOG_LIST_SHAPE,
            "`group_by` is one field name or a list of distinct field names".into(),
            &[A, "group_by"],
        ));
    } else {
        let bad: Vec<&str> = list_items(group_by)
            .into_iter()
            .filter(|f| !field_name(f))
            .collect();
        if !bad.is_empty() {
            out.push(err(
                source,
                codes::GRAYLOG_FIELD_NAME,
                format!(
                    "not field names (`[A-Za-z0-9_.@-]+`): {}",
                    bad.iter()
                        .map(|b| format!("`{b}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                &[A, "group_by"],
            ));
        }
    }
    if let Err(e) = parse_condition(condition) {
        let mut d = err(
            source,
            codes::GRAYLOG_AGGREGATION,
            format!("the condition does not parse: {}", e.message),
            &[A, "condition"],
        );
        if let Some(range) = condition_range(source, condition, &e) {
            d.range = range;
        }
        out.push(d);
    }
}

/// The error's range inside the written condition scalar, when the scalar
/// decodes to the text that was parsed.
fn condition_range(source: &str, condition: &str, e: &ConditionError) -> Option<Range> {
    let path: Vec<&str> = BLOCK
        .iter()
        .copied()
        .chain(["aggregation", "condition"])
        .collect();
    let (scalar, _) = scalar_of(source, &path)?;
    if scalar.text != condition {
        return None;
    }
    let start = *scalar.map.get(e.start)?;
    let last = *scalar.map.get(e.end.max(e.start + 1) - 1)?;
    Some(span_to_range(
        source,
        ByteSpan::new(start, after(source, last).max(start)),
    ))
}

/// Every constraint code of the block, and `graylog_overlapping_window`.
pub(crate) fn constraint_diagnostics(source: &str, block: &Value) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if block
        .get("query")
        .and_then(Value::as_str)
        .is_none_or(|q| q.trim().is_empty())
    {
        out.push(err(
            source,
            codes::GRAYLOG_QUERY_BLANK,
            "`query` is a non-blank Graylog search query".into(),
            &["query"],
        ));
    }
    for key in LIST_FIELDS {
        if !list_ok(block.get(key)) {
            out.push(err(
                source,
                codes::GRAYLOG_LIST_SHAPE,
                format!("`{key}` is one string or a list of distinct non-blank strings"),
                &[key],
            ));
        }
    }
    let schedule_value = present(block.get("schedule"));
    if let Some(s) = schedule_value {
        schedule(source, s, &mut out);
    }
    let aggregation_value = present(block.get("aggregation"));
    if let Some(limit) = present(block.get("event_limit")) {
        let in_range = limit.as_u64().is_some_and(|n| (1..=1000).contains(&n));
        if !in_range || aggregation_value.is_some() {
            let message = if in_range {
                "`event_limit` applies to a filter only; an aggregation creates one event per group"
                    .into()
            } else {
                format!(
                    "`event_limit` is an integer from 1 to 1,000, not `{}`",
                    text_of(limit)
                )
            };
            out.push(err(
                source,
                codes::GRAYLOG_EVENT_LIMIT,
                message,
                &["event_limit"],
            ));
        }
    }
    if let Some(a) = aggregation_value {
        aggregation(source, a, &mut out);
    }
    let mut names: Vec<String> = Vec::new();
    match present(block.get("event_fields")) {
        None => {}
        Some(Value::Mapping(fields)) => {
            for (name, value) in fields {
                let label = text_of(name);
                let path = ["event_fields", label.as_str()];
                match name.as_str() {
                    Some(n) if field_name(n) => {
                        if event_field_kind(value).is_none() {
                            out.push(err(
                                source,
                                codes::GRAYLOG_EVENT_FIELD,
                                "an event field is a field name, a string with a `${…}` template, `{template: …}` for constant text, or `{lookup: {table, key_field}}`".into(),
                                &path,
                            ));
                        } else {
                            names.push(n.to_string());
                        }
                    }
                    _ => out.push(err(
                        source,
                        codes::GRAYLOG_EVENT_FIELD,
                        format!("`{label}` is not an event field name (`[A-Za-z0-9_.@-]+`)"),
                        &path,
                    )),
                }
            }
        }
        Some(_) => out.push(err(
            source,
            codes::GRAYLOG_EVENT_FIELD,
            "`event_fields` is a map of event field names to values".into(),
            &["event_fields"],
        )),
    }
    let key = block.get("event_key");
    if present(key).is_some() && list_ok(key) {
        let missing: Vec<&str> = list_items(key)
            .into_iter()
            .filter(|k| !names.iter().any(|n| n == k))
            .collect();
        if !missing.is_empty() {
            out.push(err(
                source,
                codes::GRAYLOG_EVENT_KEY,
                format!(
                    "not event fields: {}; each `event_key` item names an `event_fields` entry",
                    missing
                        .iter()
                        .map(|m| format!("`{m}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                &["event_key"],
            ));
        }
    }
    if let Some(p) = present(block.get("priority"))
        && !p.as_str().is_some_and(|s| PRIORITIES.contains(&s))
    {
        out.push(err(
            source,
            codes::GRAYLOG_PRIORITY,
            format!(
                "`{}` is not a Graylog priority: {}",
                text_of(p),
                PRIORITIES.join(", ")
            ),
            &["priority"],
        ));
    }
    if aggregation_value.is_none()
        && let Some(s) = schedule_value.and_then(Value::as_mapping)
        && present(s.get("cron")).is_none()
        && let Some(window) = present(s.get("window")).and_then(duration_seconds)
    {
        let every = match present(s.get("every")) {
            None => Some(DEFAULT_EVERY_SECONDS),
            Some(v) => duration_seconds(v).filter(|e| *e > 0),
        };
        if let Some(every) = every
            && window > every
        {
            out.push(finding(
                source,
                false,
                codes::GRAYLOG_OVERLAPPING_WINDOW,
                format!(
                    "this filter searches {window}s every {every}s, so runs overlap and each message alerts once per run that sees it; set `window` to `every`, or aggregate"
                ),
                &["schedule"],
            ));
        }
    }
    out
}

// --------------------------------------------------------------------------
// Completion and hover in `aggregation.condition`

fn in_condition(cursor: &YamlCursor) -> bool {
    cursor
        .path
        .iter()
        .map(String::as_str)
        .eq(BLOCK.iter().copied().chain(["aggregation", "condition"]))
        && !cursor.on_key
}

fn word_before(source: &str, offset: usize) -> &str {
    let before = &source[..offset.min(source.len())];
    let start = before
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
        .last()
        .map_or(before.len(), |(i, _)| i);
    &before[start..]
}

fn function_markdown(signature: &str, doc: &str) -> String {
    format!("**`{signature}`** (Graylog aggregation)\n\n{doc}")
}

/// Completion in `aggregation.condition`: the aggregation functions and the
/// operators. `None` elsewhere.
pub(crate) fn completions(
    source: &str,
    offset: usize,
    cursor: &YamlCursor,
) -> Option<Vec<CompletionItem>> {
    if !in_condition(cursor) {
        return None;
    }
    let prefix = word_before(source, offset).to_ascii_lowercase();
    let mut items: Vec<CompletionItem> = FUNCTIONS
        .iter()
        .filter(|(n, _, _)| n.starts_with(&prefix))
        .map(|(n, signature, doc)| {
            CompletionItem::new(*n, "function")
                .with_detail(*signature)
                .with_docs(function_markdown(signature, doc))
        })
        .collect();
    for kw in ["AND", "OR", "NOT"] {
        if kw.to_ascii_lowercase().starts_with(&prefix) {
            items.push(CompletionItem::new(kw, "keyword"));
        }
    }
    Some(items)
}

/// Hover on an aggregation function in `aggregation.condition`.
pub(crate) fn hover(source: &str, offset: usize, cursor: &YamlCursor) -> Option<String> {
    if !in_condition(cursor) {
        return None;
    }
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let offset = offset.min(source.len());
    let start = source[..offset]
        .char_indices()
        .rev()
        .take_while(|(_, c)| is_word(*c))
        .last()
        .map_or(offset, |(i, _)| i);
    let end = source[offset..]
        .char_indices()
        .find(|(_, c)| !is_word(*c))
        .map_or(source.len(), |(i, _)| offset + i);
    let word = &source[start..end];
    FUNCTIONS
        .iter()
        .find(|(n, _, _)| *n == word)
        .map(|(_, signature, doc)| function_markdown(signature, doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn found(block: &str) -> Vec<(String, String, bool)> {
        let source = format!("configurations:\n  graylog:\n{block}");
        found_in(&source)
    }

    fn found_in(source: &str) -> Vec<(String, String, bool)> {
        let object: Value = serde_yaml::from_str(source).unwrap();
        constraint_diagnostics(source, &object["configurations"]["graylog"])
            .into_iter()
            .map(|d| {
                (
                    d.code,
                    d.field_path.unwrap_or_default()[2..].join("."),
                    d.severity == opentide_core::Severity::Error,
                )
            })
            .collect()
    }

    fn codes_of(block: &str) -> Vec<String> {
        found(block).into_iter().map(|(c, _, _)| c).collect()
    }

    const Q: &str = "    query: EventID:1\n";

    fn with(extra: &str) -> Vec<String> {
        codes_of(&format!("{Q}{extra}"))
    }

    #[test]
    fn the_reference_checkers_block_codes() {
        // scripts/test_platform_graylog.py, CheckerTests.test_block_codes.
        assert!(with("").is_empty());
        assert_eq!(codes_of("    query: '  '\n"), ["graylog_query_blank"]);
        assert_eq!(codes_of("    status: STAGING\n"), ["graylog_query_blank"]);
        assert!(with("    streams: sysmon\n").is_empty());
        assert_eq!(with("    streams: [a, a]\n"), ["graylog_list_shape"]);
        assert_eq!(with("    notifications: ['']\n"), ["graylog_list_shape"]);
        assert_eq!(with("    priority: Urgent\n"), ["graylog_priority"]);
        assert_eq!(with("    event_limit: 0\n"), ["graylog_event_limit"]);
        assert_eq!(
            with("    event_limit: 10\n    aggregation: {condition: count() > 1}\n"),
            ["graylog_event_limit"]
        );
        assert_eq!(with("    schedule: {every: 0m}\n"), ["graylog_schedule"]);
        assert_eq!(
            with("    schedule: {cron: 0 */5 * * * ?}\n"),
            ["graylog_schedule"]
        );
        assert_eq!(
            with("    schedule: {cron: 0 */5 * * * ?, window: 5m, timezone: Mars/Base}\n"),
            ["graylog_schedule"]
        );
        assert!(
            with("    schedule: {every: PT5M, window: 1h10m}\n")
                .iter()
                .all(|c| c != "graylog_schedule")
        );
        assert_eq!(
            with("    aggregation: {group_by: source}\n"),
            ["graylog_aggregation"]
        );
        assert_eq!(
            with("    aggregation: {group_by: [src ip], condition: count() > 1}\n"),
            ["graylog_field_name"]
        );
        assert!(
            with("    event_fields:\n      host: source\n      x: ${source.a}-${source.b}\n      y: {template: LOLBin}\n")
                .is_empty()
        );
        assert!(
            with("    event_fields:\n      owner: {lookup: {table: t, key_field: source}}\n")
                .is_empty()
        );
        assert_eq!(
            with("    event_fields:\n      x: two words\n"),
            ["graylog_event_field"]
        );
        assert_eq!(
            with("    event_fields:\n      x: {lookup: {table: t}}\n"),
            ["graylog_event_field"]
        );
        assert!(with("    event_fields: {host: source}\n    event_key: host\n").is_empty());
        assert_eq!(
            with("    event_fields: {host: source}\n    event_key: [user]\n"),
            ["graylog_event_key"]
        );
    }

    #[test]
    fn field_paths_follow_the_spec_table() {
        let found = found(
            "    query: ''\n    tags: [a, a]\n    schedule:\n      every: 5m\n      cron: '0 0 * * * ?'\n      window: 0s\n    event_limit: 2000\n    aggregation:\n      group_by: [a b]\n      condition: count(\n    event_fields:\n      bad name: source\n      x: two words\n    event_key: [zz]\n    priority: urgent\n",
        );
        let paths: Vec<(&str, &str)> = found
            .iter()
            .map(|(c, p, _)| (c.as_str(), p.as_str()))
            .collect();
        assert_eq!(
            paths,
            [
                ("graylog_query_blank", "query"),
                ("graylog_list_shape", "tags"),
                ("graylog_schedule", "schedule"),
                ("graylog_schedule", "schedule.window"),
                ("graylog_event_limit", "event_limit"),
                ("graylog_field_name", "aggregation.group_by"),
                ("graylog_aggregation", "aggregation.condition"),
                ("graylog_event_field", "event_fields.bad name"),
                ("graylog_event_field", "event_fields.x"),
                ("graylog_event_key", "event_key"),
                ("graylog_priority", "priority"),
            ]
        );
        assert!(found.iter().all(|(_, _, error)| *error));
        // `aggregation` without a condition: the block path.
        assert_eq!(
            found_in("configurations:\n  graylog:\n    query: a\n    aggregation: {}\n")[0].1,
            "aggregation"
        );
        // A list field that is not a list or a string.
        assert_eq!(
            found_in(
                "configurations:\n  graylog:\n    query: a\n    aggregation:\n      group_by: {a: 1}\n      condition: count() > 1\n"
            )[0]
            .1,
            "aggregation.group_by"
        );
    }

    #[test]
    fn ranges_point_at_the_value() {
        let source = "configurations:\n  graylog:\n    query: x\n    priority: Urgént\n    aggregation:\n      condition: count() >= 3 or card(x) > 1\n";
        let object: Value = serde_yaml::from_str(source).unwrap();
        let found = constraint_diagnostics(source, &object["configurations"]["graylog"]);
        fn text(source: &str, d: &Diagnostic) -> String {
            let start = opentide_core::position_to_offset(source, d.range.start);
            let end = opentide_core::position_to_offset(source, d.range.end);
            source[start..end].to_string()
        }
        assert_eq!(text(source, &found[0]), "or", "{found:?}");
        assert_eq!(found[0].code, codes::GRAYLOG_AGGREGATION);
        assert!(
            found[0].message.contains("upper case"),
            "{}",
            found[0].message
        );
        assert_eq!(text(source, &found[1]), "Urgént");
        // A multibyte field name in a call.
        let source = "configurations:\n  graylog:\n    query: x\n    aggregation:\n      condition: 'avg(é) > 1'\n";
        let object: Value = serde_yaml::from_str(source).unwrap();
        let d = &constraint_diagnostics(source, &object["configurations"]["graylog"])[0];
        assert_eq!(text(source, d), "é");
    }

    #[test]
    fn condition_compiles_to_graylogs_tree() {
        // The aggregation fixture's golden request (6.3.5 and 7.2.2).
        let c = parse_condition("count() >= 3 OR card(parent_image_lc) >= 2").unwrap();
        assert_eq!(
            c.expr.json(),
            json!({"expr": "||",
                "left": {"expr": ">=", "left": {"expr": "number-ref", "ref": "count-"}, "right": {"expr": "number", "value": 3}},
                "right": {"expr": ">=", "left": {"expr": "number-ref", "ref": "card-parent_image_lc"}, "right": {"expr": "number", "value": 2}}})
        );
        let series: Vec<_> = c.series.iter().map(Series::json).collect();
        assert_eq!(
            series,
            [
                json!({"id": "count-", "type": "count"}),
                json!({"id": "card-parent_image_lc", "type": "card", "field": "parent_image_lc"})
            ]
        );
    }

    #[test]
    fn condition_precedence_and_series_reuse() {
        let c = parse_condition("NOT count() > 1 AND count() < 10 OR percentile(bytes, 95) > 2.5")
            .unwrap();
        let ids: Vec<&str> = c.series.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["count-", "percentile-bytes-95"]);
        assert_eq!(c.series[1].percentile, Some(95.0));
        let tree = c.expr.json();
        assert_eq!(tree["expr"], "||");
        assert_eq!(tree["left"]["expr"], "&&");
        assert_eq!(tree["left"]["left"]["expr"], "!");
        assert_eq!(
            tree["right"]["right"],
            json!({"expr": "number", "value": 2.5})
        );
        // Left-associative, parentheses only group.
        let tree =
            parse_condition("(count() > 1 OR max(x) > 2) AND min(x)<1 AND NOT NOT sum(x)==0")
                .unwrap()
                .expr
                .json();
        assert_eq!(tree["expr"], "&&");
        assert_eq!(tree["left"]["expr"], "&&");
        assert_eq!(tree["left"]["left"]["expr"], "||");
        assert_eq!(tree["right"]["left"]["left"]["expr"], "==");
        assert_eq!(
            parse_condition("count(src) > -1").unwrap().series[0].id,
            "count-src"
        );
    }

    #[test]
    fn condition_refusals() {
        for text in [
            "",
            "   ",
            "count() >= 3 or count() < 9",
            "total(bytes) > 1",
            "avg() > 1",
            "count(a, b) > 1",
            "percentile(bytes) > 1",
            "percentile(bytes, 101) > 1",
            "percentile(bytes, 0) > 1",
            "count() >= ",
            "(count() > 1",
            "count() = 1",
            "count() > 1 AND",
            "count() > x",
            "count(a b) > 1",
            "count(a,) > 1",
            "percentile(bytes 95) > 1",
            "count() > 1.",
            "COUNT() > 1",
            "count() > 1 count() > 2",
            "avg(a!) > 1",
        ] {
            assert!(parse_condition(text).is_err(), "{text:?}");
        }
        let e = parse_condition("count() >= 3 or count() < 9").unwrap_err();
        assert_eq!((e.start, e.end), (13, 15));
        let e = parse_condition("count() >= ").unwrap_err();
        assert_eq!((e.start, e.end), (9, 10));
        let e = parse_condition("x > 1 AND avg() > 1").unwrap_err();
        assert_eq!((e.start, e.end), (0, 1));
        let e = parse_condition("count() > 1 AND avg() > 1").unwrap_err();
        assert_eq!(&"count() > 1 AND avg() > 1"[e.start..e.end], "avg()");
    }

    #[test]
    fn durations_follow_elastic() {
        let s = |t: &str| duration_seconds(&Value::String(t.into()));
        assert_eq!(s("1h10m"), Some(4200));
        assert_eq!(s("PT1H10M"), Some(4200));
        assert_eq!(s("P1DT2H"), Some(93600));
        for bad in ["", "5", "1w", "m5", "PT", "P", "1.5h", "-5m", "5 m", " 5m"] {
            assert_eq!(s(bad), None, "{bad:?}");
        }
        assert_eq!(duration_seconds(&Value::Number(300.into())), None);
    }

    #[test]
    fn cron_is_quartz_as_graylog_reads_it() {
        // Verdicts from Graylog 7.2.2 and 6.3.5 (`/api/events/definitions/validate`).
        for ok in [
            "0 */5 * * * ?",
            "0 */10 * * * ?",
            "0 0 12 ? * MON-FRI",
            "0 0 12 L * ?",
            "0 0 12 ? * 6#3",
            "0 0 12 * * ? 2030",
            "0 0 12 15W * ?",
            "0 15 10 ? JAN,MAR 2L",
            "0 0/30 8-18 ? * mon-fri",
            "0 0 12 ? * 6#6",
            "0 5-1 * * * ?",
            "0 0 12 L-3 * ?",
            "0 0 12 lw * ?",
            "0 0 12 ? * l",
            "0 0 12 ? * L-7",
            "0 0 12 ? * 2l,3",
            "0 0 0/23 * * ?",
            "0 0 12 1/31 * ?",
            "0 0 12 * * ? 2030/130",
            "*/5 * * * * ? *",
            "0 0 12 ? * mon#2",
        ] {
            assert_eq!(quartz_cron(ok), Ok(()), "{ok}");
        }
        for bad in [
            "*/5 * * * *",
            "0 0 12 * * *",
            "0 0 12 ? * ?",
            "0 61 * * * ?",
            "0 0 12 * * ? 1969",
            "0 0 12 ? * 8",
            "0 0 12 ? * 0",
            "0 0 24 * * ?",
            "0 0 12 32 * ?",
            "0 0 12 * 13 ?",
            "? 0 12 * * ?",
            "0 */0 * * * ?",
            "0 0 12 ? * 1#8",
            "0 0 12 ? * 1#0",
            "0 */60 * * * ?",
            "0 0 0/24 * * ?",
            "0 0 12 ? * 1/8",
            "0 0 12 W * ?",
            "0 0 12 1-5W * ?",
            "0 0 12 L-3W * ?",
            "0 0 12 L-0 * ?",
            "0 0 12 ? * L#2",
            "0 0 12 ? * 1-3#2",
            "0 0 12 1, * ?",
            "0 0 12 ? * Monday",
            "0 0 12 * * L",
            "0 0 -1 * * ?",
            "0 0 12 * * ? 2100",
            "0 0 12 * * ? 2030 1",
        ] {
            assert!(quartz_cron(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn time_zones_are_iana_names() {
        for ok in [
            "UTC",
            "Europe/Paris",
            "America/New_York",
            "US/Eastern",
            "Etc/GMT+5",
        ] {
            assert!(iana_zone(ok), "{ok}");
        }
        for bad in ["Mars/Base", "utc", "europe/paris", "+01:00", "", "Z"] {
            assert!(!iana_zone(bad), "{bad}");
        }
        assert!(zones().windows(2).all(|w| w[0] < w[1]), "sorted");
    }

    #[test]
    fn overlapping_window_is_a_filter_advisory() {
        let warned = |extra: &str| -> Vec<(String, String, bool)> {
            found(&format!("{Q}{extra}"))
                .into_iter()
                .filter(|(c, _, _)| c == codes::GRAYLOG_OVERLAPPING_WINDOW)
                .collect()
        };
        let w = warned("    schedule: {every: 5m, window: 15m}\n");
        assert_eq!(
            w,
            [(
                "graylog_overlapping_window".into(),
                "schedule".into(),
                false
            )]
        );
        assert_eq!(
            warned("    schedule: {window: 6m}\n").len(),
            1,
            "every defaults to 5m"
        );
        assert!(warned("    schedule: {every: 15m, window: 15m}\n").is_empty());
        assert!(warned("    schedule: {cron: 0 0 * * * ?, window: 2h}\n").is_empty());
        assert!(
            warned("    schedule: {every: 5m, window: 15m}\n    aggregation: {condition: count() > 1}\n")
                .is_empty()
        );
    }

    #[test]
    fn completion_and_hover_in_the_condition() {
        let source =
            "configurations:\n  graylog:\n    aggregation:\n      condition: count() > 1 AND per";
        let cursor = crate::yaml_cursor(source, source.len());
        let items = completions(source, source.len(), &cursor).expect("in the condition");
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(labels, ["percentage", "percentile"]);
        let at = source.find("count").unwrap() + 2;
        let cursor = crate::yaml_cursor(source, at);
        assert!(hover(source, at, &cursor).unwrap().contains("count(field)"));
        let elsewhere = "configurations:\n  graylog:\n    query: count";
        let cursor = crate::yaml_cursor(elsewhere, elsewhere.len());
        assert!(completions(elsewhere, elsewhere.len(), &cursor).is_none());
    }
}
