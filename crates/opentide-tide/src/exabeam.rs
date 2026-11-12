//! The Exabeam block (`configurations.exabeam`, platform exabeam-1.0): its
//! constraint codes and advisories, reported natively so the editor and
//! `opentide validate` agree.
//!
//! The codes, their conditions and their field paths follow exabeam-1.0
//! "Constraints" and "Advisories", and `validate_exabeam_block` in
//! opentidehq/specifications' `scripts/object_fixtures.py`, its reference
//! checker. They run from the raw YAML, so they do not wait for the Tide
//! catalogue to model the block. As on the Sysdig and Bitdefender blocks, a
//! block without `status` reports only the missing field (the catalogue's).
//! Unknown block keys and legacy external ids are the catalogue's too.
//!
//! The language codes of each sequence's `query` are the Exabeam engine's
//! (`opentide-exabeam`, `rule` profile), reported where the query is
//! injected. `exabeam_name_duplicate` compares the block with the other
//! objects of the workspace.

use crate::IndexedObject;
use opentide_core::{Diagnostic, codes};
use serde_yaml::Value;

const BLOCK: [&str; 2] = ["configurations", "exabeam"];
const FUNCTIONS: [&str; 7] = [
    "count",
    "unique_count",
    "value",
    "max",
    "min",
    "sum",
    "average",
];
const NUMERIC_OPERATORS: [&str; 2] = ["more_than", "less_than"];
const VALUE_OPERATORS: [&str; 2] = ["in", "not_in"];
const SEVERITIES: [&str; 5] = ["none", "low", "medium", "high", "critical"];
const OUTCOMES: [&str; 3] = ["alert", "case", "none"];
const WEEKDAYS: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];
const MAX_NAME: usize = 128;

fn full_path<'a>(path: &[&'a str]) -> Vec<&'a str> {
    let mut full: Vec<&str> = BLOCK.to_vec();
    full.extend_from_slice(path);
    full
}

fn diagnostic(
    source: &str,
    error: bool,
    code: &'static str,
    message: String,
    path: &[&str],
) -> Diagnostic {
    let full = full_path(path);
    let range = match path {
        ["sequences" | "schedule", n] if n.parse::<usize>().is_ok() => {
            crate::bitdefender::item_range(source, &full)
                .unwrap_or_else(|| crate::elastic::path_range(source, &full))
        }
        _ => crate::elastic::path_range(source, &full),
    };
    let d = if error {
        Diagnostic::error(code, message, range)
    } else {
        Diagnostic::warning(code, message, range)
    };
    d.with_field_path(full.iter().map(|p| p.to_string()).collect())
}

fn err(source: &str, code: &'static str, message: impl Into<String>, path: &[&str]) -> Diagnostic {
    diagnostic(source, true, code, message.into(), path)
}

fn warn(source: &str, code: &'static str, message: impl Into<String>, path: &[&str]) -> Diagnostic {
    diagnostic(source, false, code, message.into(), path)
}

fn set(v: Option<&Value>) -> bool {
    !matches!(v, None | Some(Value::Null)) && v.and_then(Value::as_str) != Some("")
}

fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        _ => "a list or mapping".into(),
    }
}

/// A duration (exabeam-1.0, "Durations"): a positive whole number and one
/// unit of `units`, with no space. Its length in minutes.
pub fn duration_minutes(value: Option<&Value>, units: &str) -> Option<u64> {
    let text = value?.as_str()?;
    let unit = text.chars().last()?;
    if !units.contains(unit) {
        return None;
    }
    let number = &text[..text.len() - 1];
    if number.is_empty() || number.starts_with('0') || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = number.parse().ok()?;
    let per = match unit {
        'm' => 1,
        'h' => 60,
        'd' => 1440,
        'w' => 10080,
        _ => return None,
    };
    n.checked_mul(per)
}

/// One to three distinct non-blank strings (none at all when `allow_empty`).
fn group_by_ok(value: &Value, allow_empty: bool) -> bool {
    let Some(items) = value.as_sequence() else {
        return false;
    };
    if items.len() > 3 || (items.is_empty() && !allow_empty) {
        return false;
    }
    let mut seen = Vec::new();
    for item in items {
        match item.as_str() {
            Some(s) if !s.trim().is_empty() && !seen.contains(&s) => seen.push(s),
            _ => return false,
        }
    }
    true
}

fn is_number(v: &Value) -> bool {
    matches!(v, Value::Number(_))
}

/// The value under `key`, a null being the key left out (exabeam-1.0: null
/// is absent at every level).
fn present<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.into())).filter(|v| !v.is_null())
}

/// Whether a query looks a value up in a context table, as the engine
/// parses it: `IN "…"` inside a string is not a lookup
/// (`exabeam_context_table_trigger`).
fn uses_context_table(query: &str) -> bool {
    !opentide_exabeam::check(query, opentide_exabeam::Profile::Rule)
        .context_tables
        .is_empty()
}

fn threshold_checks(
    source: &str,
    threshold: &Value,
    index: &str,
    out: &mut Vec<Diagnostic>,
) -> Option<u64> {
    let path = ["sequences", index, "threshold"];
    // An unknown key is the Tide catalogue's (exabeam-1.0: never a constraint code).
    let Some(map) = threshold.as_mapping() else {
        out.push(err(
            source,
            codes::EXABEAM_THRESHOLD_FUNCTION,
            "a threshold has function, field, operator, value and within",
            &path,
        ));
        return None;
    };
    let get = |k: &str| present(map, k);
    let function = get("function").and_then(Value::as_str).unwrap_or("");
    if !FUNCTIONS.contains(&function) {
        out.push(err(
            source,
            codes::EXABEAM_THRESHOLD_FUNCTION,
            format!(
                "`{}` is not an Exabeam threshold function: {}",
                get("function").map(text_of).unwrap_or_default(),
                FUNCTIONS.join(", ")
            ),
            &path,
        ));
        return None;
    }
    let field = get("field");
    if let Some(f) = field
        && f.as_str().is_none_or(|s| s.trim().is_empty())
    {
        out.push(err(
            source,
            codes::EXABEAM_THRESHOLD_FUNCTION,
            "`field` is a non-blank string",
            &path,
        ));
    }
    if field.is_none() && function != "count" {
        out.push(err(
            source,
            codes::EXABEAM_THRESHOLD_FUNCTION,
            format!("`{function}` reads a field: set `field`"),
            &path,
        ));
    }
    let allowed: &[&str] = if function == "value" {
        &VALUE_OPERATORS
    } else {
        &NUMERIC_OPERATORS
    };
    let operator = get("operator").and_then(Value::as_str).unwrap_or("");
    if !allowed.contains(&operator) {
        out.push(err(
            source,
            codes::EXABEAM_THRESHOLD_OPERATOR,
            format!(
                "`{function}` takes the operator {}",
                allowed
                    .iter()
                    .map(|o| format!("`{o}`"))
                    .collect::<Vec<_>>()
                    .join(" or ")
            ),
            &path,
        ));
        return None;
    }
    let value = get("value");
    let integral = matches!(function, "count" | "unique_count");
    let ok = match value {
        Some(v) if NUMERIC_OPERATORS.contains(&operator) => {
            is_number(v) && (!integral || v.as_u64().is_some())
        }
        Some(Value::Sequence(items)) => {
            !items.is_empty()
                && items.iter().all(|v| {
                    is_number(v)
                        || v.as_str()
                            .is_some_and(|s| !s.trim().is_empty() && !s.contains(','))
                })
        }
        _ => false,
    };
    if !ok {
        let want = if NUMERIC_OPERATORS.contains(&operator) {
            if integral {
                "a non-negative integer"
            } else {
                "a number"
            }
        } else {
            "a non-empty list of strings (without `,`) or numbers"
        };
        out.push(err(
            source,
            codes::EXABEAM_THRESHOLD_VALUE,
            format!("`{operator}` compares with {want}"),
            &path,
        ));
    }
    let within = duration_minutes(get("within"), "mhd");
    if within.is_none() {
        out.push(err(
            source,
            codes::EXABEAM_DURATION,
            "`within` is a whole number of minutes, hours or days (`30m`, `4h`, `1d`)",
            &["sequences", index, "threshold", "within"],
        ));
    }
    within
}

fn schedule_checks(source: &str, schedule: &Value, out: &mut Vec<Diagnostic>) {
    let Some(items) = schedule.as_sequence().filter(|s| !s.is_empty()) else {
        out.push(err(
            source,
            codes::EXABEAM_SCHEDULE,
            "`schedule` is a non-empty list of recurrences",
            &["schedule"],
        ));
        return;
    };
    for (index, rec) in items.iter().enumerate() {
        let at = index.to_string();
        let path = ["schedule", at.as_str()];
        let Some(map) = rec.as_mapping() else {
            out.push(err(
                source,
                codes::EXABEAM_SCHEDULE,
                "a recurrence is a table",
                &path,
            ));
            continue;
        };
        let get = |k: &str| present(map, k);
        let every = get("every").and_then(Value::as_str).unwrap_or("");
        let day_keys: &[&str] = match every {
            "day" => &[],
            "week" => &["days"],
            "month" => &["days", "last_day"],
            "days" => &["first", "last"],
            _ => {
                out.push(err(
                    source,
                    codes::EXABEAM_SCHEDULE,
                    "`every` is `day`, `week`, `month`, or `days`",
                    &path,
                ));
                continue;
            }
        };
        // A day key this `every` does not take; a key that is no day key is
        // the Tide catalogue's unknown key.
        let wrong_day_key = ["days", "last_day", "first", "last"]
            .iter()
            .any(|k| !day_keys.contains(k) && get(k).is_some());
        let times = ["from", "to"]
            .iter()
            .all(|k| get(k).and_then(Value::as_str).is_some_and(utc_time));
        let mut ok = times && !wrong_day_key;
        let weekday_list = |v: Option<&Value>| {
            v.and_then(Value::as_sequence).is_some_and(|days| {
                let mut seen = Vec::new();
                !days.is_empty()
                    && days.iter().all(|d| match d.as_str() {
                        Some(d) if WEEKDAYS.contains(&d) && !seen.contains(&d) => {
                            seen.push(d);
                            true
                        }
                        _ => false,
                    })
            })
        };
        match every {
            "week" => ok = ok && weekday_list(get("days")),
            "month" => {
                let last = get("last_day").unwrap_or(&Value::Bool(false));
                let days = get("days");
                ok = ok && last.is_bool() && (days.is_some() || last.as_bool() == Some(true));
                if let Some(days) = days {
                    ok = ok
                        && days.as_sequence().is_some_and(|ds| {
                            let mut seen = Vec::new();
                            !ds.is_empty()
                                && ds.iter().all(|d| match d.as_u64() {
                                    Some(n) if (1..=31).contains(&n) && !seen.contains(&n) => {
                                        seen.push(n);
                                        true
                                    }
                                    _ => false,
                                })
                        });
                }
            }
            "days" => {
                ok = ok
                    && ["first", "last"].iter().all(|k| {
                        get(k)
                            .and_then(Value::as_str)
                            .is_some_and(|d| WEEKDAYS.contains(&d))
                    });
            }
            _ => {}
        }
        if !ok {
            out.push(err(
                source,
                codes::EXABEAM_SCHEDULE,
                format!(
                    "an invalid `{every}` recurrence: `from` and `to` are `H:MMZ` or `HH:MMZ`, and it takes {}",
                    if day_keys.is_empty() {
                        "no day keys".to_string()
                    } else {
                        day_keys
                            .iter()
                            .map(|k| format!("`{k}`"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                ),
                &path,
            ));
        }
    }
}

/// `^([01]?[0-9]|2[0-3]):[0-5][0-9]Z$`
fn utc_time(text: &str) -> bool {
    let Some(body) = text.strip_suffix('Z') else {
        return false;
    };
    let Some((h, m)) = body.split_once(':') else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    digits(h)
        && h.len() <= 2
        && h.parse::<u32>().is_ok_and(|h| h <= 23)
        && (h.len() == 1 || h.as_bytes()[0] <= b'2')
        && m.len() == 2
        && digits(m)
        && m.as_bytes()[0] <= b'5'
}

/// `local@domain.tld`, no blanks, one `@`.
fn email_ok(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    let blank_free =
        |s: &str| !s.is_empty() && !s.contains(char::is_whitespace) && !s.contains('@');
    blank_free(local)
        && blank_free(domain)
        && domain
            .split_once('.')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
}

/// The Exabeam rule name: the block's `name`, else the rule's.
pub(crate) fn rule_name<'a>(rule: &'a Value, block: &'a Value) -> Option<&'a str> {
    block
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| rule.get("name").and_then(Value::as_str))
}

fn enabled(block: &Value) -> bool {
    block.get("enabled").and_then(Value::as_bool) != Some(false)
}

pub(crate) fn constraint_diagnostics(
    source: &str,
    path: &str,
    rule: &Value,
    block: &Value,
    workspace: &[IndexedObject],
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if !set(block.get("status")) {
        return out;
    }
    // Sequences.
    let sequences: &[Value] = match block.get("sequences").and_then(Value::as_sequence) {
        Some(s) if !s.is_empty() => s,
        _ => {
            out.push(err(
                source,
                codes::EXABEAM_SEQUENCES,
                "`sequences` is a non-empty list of sequences",
                &["sequences"],
            ));
            &[]
        }
    };
    // The minutes the ordered sequences need (exabeam-1.0, `correlation`): each
    // window, one minute for an any-match sequence, and one minute between
    // sequences; `None` once a window does not parse.
    let mut needed: Option<u64> = Some(sequences.len().saturating_sub(1) as u64);
    for (index, seq) in sequences.iter().enumerate() {
        let at = index.to_string();
        let Some(map) = seq.as_mapping() else {
            out.push(err(
                source,
                codes::EXABEAM_SEQUENCES,
                "a sequence is a table with `query`, and may have `name`, `threshold` and `group_by`",
                &["sequences", at.as_str()],
            ));
            continue;
        };
        let get = |k: &str| present(map, k);
        let query = get("query").and_then(Value::as_str);
        if query.is_none_or(|q| q.trim().is_empty()) {
            out.push(err(
                source,
                codes::EXABEAM_SEQUENCES,
                "`query` is a non-blank Exabeam query",
                &["sequences", at.as_str(), "query"],
            ));
        }
        if let Some(group_by) = get("group_by")
            && !group_by_ok(group_by, false)
        {
            out.push(err(
                source,
                codes::EXABEAM_GROUP_BY,
                "`group_by` is one to three distinct non-blank fields",
                &["sequences", at.as_str(), "group_by"],
            ));
        }
        let Some(threshold) = get("threshold") else {
            needed = needed.map(|n| n + 1);
            continue;
        };
        let minutes = threshold_checks(source, threshold, &at, &mut out);
        needed = needed.zip(minutes).map(|(n, m)| n + m);
        if query.is_some_and(uses_context_table) {
            out.push(err(
                source,
                codes::EXABEAM_CONTEXT_TABLE_TRIGGER,
                "a sequence that looks up a context table triggers on the first match: Exabeam takes no threshold with it",
                &["sequences", at.as_str(), "threshold"],
            ));
        }
    }
    // Correlation.
    let correlation = block.get("correlation").filter(|v| !v.is_null());
    if sequences.iter().any(|s| !s.is_mapping()) {
        needed = None;
    }
    match (sequences.len(), correlation) {
        (n, None) if n >= 2 => out.push(err(
            source,
            codes::EXABEAM_CORRELATION,
            "two or more sequences correlate: set `correlation.within`",
            &["correlation"],
        )),
        (1, Some(_)) => out.push(err(
            source,
            codes::EXABEAM_CORRELATION,
            "one sequence has no `correlation`",
            &["correlation"],
        )),
        (_, Some(c)) => match c.as_mapping() {
            None => out.push(err(
                source,
                codes::EXABEAM_CORRELATION,
                "`correlation` has `within` and `group_by`",
                &["correlation"],
            )),
            Some(m) => {
                match duration_minutes(present(m, "within"), "mhd") {
                    None => out.push(err(
                        source,
                        codes::EXABEAM_DURATION,
                        "`within` is a whole number of minutes, hours or days (`30m`, `4h`, `1d`)",
                        &["correlation", "within"],
                    )),
                    Some(within) => {
                        if let Some(needed) = needed
                            && sequences.len() >= 2
                            && within <= needed
                        {
                            out.push(warn(
                                source,
                                codes::EXABEAM_CORRELATION_WINDOW,
                                format!(
                                    "the correlation window is not more than the {needed} minutes the ordered sequences need (their windows, a minute for each any-match sequence, a minute between sequences): make it more than {needed}m"
                                ),
                                &["correlation", "within"],
                            ));
                        }
                    }
                }
                if let Some(group_by) = present(m, "group_by")
                    && !group_by_ok(group_by, true)
                {
                    out.push(err(
                        source,
                        codes::EXABEAM_GROUP_BY,
                        "`group_by` is up to three distinct non-blank fields",
                        &["correlation", "group_by"],
                    ));
                }
            }
        },
        _ => {}
    }
    // Severity and outcome.
    if let Some(severity) = block.get("severity").filter(|v| !v.is_null())
        && !severity.as_str().is_some_and(|s| SEVERITIES.contains(&s))
    {
        out.push(err(
            source,
            codes::EXABEAM_SEVERITY,
            format!(
                "`{}` is not an Exabeam severity: {}",
                text_of(severity),
                SEVERITIES.join(", ")
            ),
            &["severity"],
        ));
    }
    let outcome = block.get("outcome").filter(|v| !v.is_null());
    if let Some(o) = outcome
        && !o.as_str().is_some_and(|s| OUTCOMES.contains(&s))
    {
        out.push(err(
            source,
            codes::EXABEAM_OUTCOME,
            format!(
                "`{}` is not an Exabeam outcome: alert, case, or none",
                text_of(o)
            ),
            &["outcome"],
        ));
    }
    // Email.
    let email = block.get("email").filter(|v| !v.is_null());
    if let Some(email) = email {
        let ok = email.as_mapping().is_some_and(|m| {
            let recipients = present(m, "recipients").and_then(Value::as_sequence);
            let subject = present(m, "subject");
            recipients.is_some_and(|r| {
                let mut seen = Vec::new();
                !r.is_empty()
                    && r.iter().all(|a| match a.as_str() {
                        Some(a) if email_ok(a) && !seen.contains(&a) => {
                            seen.push(a);
                            true
                        }
                        _ => false,
                    })
            }) && subject.is_none_or(|s| s.as_str().is_some_and(|s| !s.trim().is_empty()))
                && present(m, "attach_csv").is_none_or(Value::is_bool)
        });
        if !ok {
            out.push(err(
                source,
                codes::EXABEAM_EMAIL,
                "`email.recipients` is a non-empty list of distinct addresses; `subject` is non-blank when set",
                &["email"],
            ));
        }
    }
    if outcome.and_then(Value::as_str) == Some("none") && email.is_none() {
        out.push(warn(
            source,
            codes::EXABEAM_OUTCOME_SILENT,
            "`outcome: none` with no `email`: the rule only writes a rule-trigger event",
            &["outcome"],
        ));
    }
    // Suppression, delay, schedule.
    if let Some(suppression) = block.get("suppression").filter(|v| !v.is_null()) {
        match suppression.as_mapping() {
            None => out.push(err(
                source,
                codes::EXABEAM_DURATION,
                "`suppression` is a table with `for` and `group_by`",
                &["suppression", "for"],
            )),
            Some(m) => {
                if duration_minutes(present(m, "for"), "mhdw").is_none() {
                    out.push(err(
                        source,
                        codes::EXABEAM_DURATION,
                        "`for` is a whole number of minutes, hours, days or weeks (`30m`, `4h`, `1d`, `2w`)",
                        &["suppression", "for"],
                    ));
                }
                if let Some(group_by) = present(m, "group_by")
                    && !group_by_ok(group_by, false)
                {
                    out.push(err(
                        source,
                        codes::EXABEAM_GROUP_BY,
                        "`group_by` is one to three distinct non-blank fields",
                        &["suppression", "group_by"],
                    ));
                }
            }
        }
    }
    if let Some(delay) = block.get("delay").filter(|v| !v.is_null())
        && !duration_minutes(Some(delay), "mh").is_some_and(|m| (7..=180).contains(&m))
    {
        out.push(err(
            source,
            codes::EXABEAM_DURATION,
            "`delay` is 7 to 180 minutes (`7m` to `180m`, `1h` to `3h`)",
            &["delay"],
        ));
    }
    if let Some(schedule) = block.get("schedule").filter(|v| !v.is_null()) {
        schedule_checks(source, schedule, &mut out);
    }
    // The rule name.
    let name = rule_name(rule, block);
    if let Some(name) = name
        && name.chars().count() > MAX_NAME
    {
        out.push(err(
            source,
            codes::EXABEAM_NAME_LENGTH,
            format!(
                "the Exabeam rule name is {} characters; Exabeam takes at most {MAX_NAME}",
                name.chars().count()
            ),
            &["name"],
        ));
    }
    if let Some(name) = name
        && enabled(block)
    {
        let lower = name.to_lowercase();
        let other = workspace.iter().find(|o| {
            !crate::same_file(&o.path, path)
                && o.object_type == "rule"
                && o.body
                    .get("configurations")
                    .and_then(|c| c.get("exabeam"))
                    .filter(|b| b.is_mapping() && enabled(b))
                    .and_then(|b| rule_name(&o.body, b))
                    .is_some_and(|n| n.to_lowercase() == lower)
        });
        if let Some(other) = other {
            out.push(err(
                source,
                codes::EXABEAM_NAME_DUPLICATE,
                format!(
                    "`{name}` is also the Exabeam rule name of {} ({}): Exabeam's import refuses a second rule of one name, and deploy's name check refuses the second create",
                    other.path, other.name
                ),
                &["name"],
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        let v = |s: &str| Value::String(s.into());
        assert_eq!(duration_minutes(Some(&v("30m")), "mhd"), Some(30));
        assert_eq!(duration_minutes(Some(&v("4h")), "mhd"), Some(240));
        assert_eq!(duration_minutes(Some(&v("1d")), "mhd"), Some(1440));
        assert_eq!(duration_minutes(Some(&v("2w")), "mhd"), None);
        assert_eq!(duration_minutes(Some(&v("2w")), "mhdw"), Some(20160));
        assert_eq!(duration_minutes(Some(&v("1h30m")), "mhd"), None);
        assert_eq!(duration_minutes(Some(&v("05m")), "mhd"), None);
        assert_eq!(duration_minutes(Some(&v("0m")), "mhd"), None);
        assert_eq!(duration_minutes(Some(&v("PT5M")), "mhd"), None);
    }

    #[test]
    fn times_and_addresses() {
        assert!(utc_time("08:00Z"));
        assert!(utc_time("8:00Z"));
        assert!(utc_time("23:59Z"));
        assert!(!utc_time("24:00Z"));
        assert!(!utc_time("08:60Z"));
        assert!(!utc_time("08:00"));
        assert!(email_ok("soc@example.com"));
        assert!(!email_ok("soc@example"));
        assert!(!email_ok("soc example@example.com"));
    }

    #[test]
    fn context_tables_in_a_query() {
        assert!(uses_context_table("user IN \"Privileged Accounts\""));
        assert!(uses_context_table("user in 'A'"));
        assert!(uses_context_table("c-user IN \"A\""));
        assert!(!uses_context_table("user:\"in\" AND login:\"x\""));
        assert!(!uses_context_table("domain:\"x\""));
        // A quoted phrase that holds ` in '` is not a lookup.
        assert!(!uses_context_table("message:\"user signed in 'admin'\""));
    }
}
