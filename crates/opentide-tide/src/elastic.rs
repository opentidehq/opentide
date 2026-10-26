//! `configurations.elastic`: which query language each field holds, and the
//! advisories that compare a query with the block's schedule.
//!
//! [elastic-1.0](https://github.com/opentidehq/specifications/blob/main/specs/platforms/elastic-1.0.md):
//! the language comes from the block, not the platform. `type: esql` is ES|QL,
//! `type: eql` is EQL, `machine_learning` has no query, and the other types
//! take `language` (`kuery` when omitted, or `lucene`). The indicator query
//! `threat.query` takes `threat.language` the same way.

use crate::vocabs::bundled_vocabs;
use crate::{IndexedObject, InjectedQuery, remap_span};
use opentide_core::{ByteSpan, Diagnostic, LanguageId, Range, codes, span_to_range};

/// Query language of `configurations.elastic.query`, or of `threat.query`
/// when `rule_type` is `threat_match` and `language` is `threat.language`.
pub fn elastic_query_language(
    rule_type: Option<&str>,
    language: Option<&str>,
) -> Option<LanguageId> {
    match rule_type? {
        "esql" => Some(LanguageId::Esql),
        "eql" => Some(LanguageId::Eql),
        "query" | "threshold" | "new_terms" | "threat_match" => match language {
            None | Some("kuery") => Some(LanguageId::Kuery),
            Some("lucene") => Some(LanguageId::Lucene),
            Some(_) => None,
        },
        _ => None,
    }
}

/// One YAML line that holds a mapping key, with its full key path.
struct KeyLine {
    line: usize,
    path: Vec<String>,
    value: String,
}

/// Key paths for every mapping key outside block-scalar bodies. `- key:` list
/// items nest under their parent key with an `[]` segment.
fn key_lines(lines: &[&str]) -> Vec<KeyLine> {
    let mut out = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut block_indent: Option<usize> = None;
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(b) = block_indent {
            if indent > b {
                continue;
            }
            block_indent = None;
        }
        let (key_indent, content, list_item) = match trimmed.strip_prefix("- ") {
            Some(rest) => (indent + 2, rest.trim_start(), true),
            None => (indent, trimmed, false),
        };
        while stack.last().is_some_and(|(ind, _)| *ind >= key_indent) {
            stack.pop();
        }
        if list_item {
            // The list item itself sits under the nearest parent key.
            while stack.last().is_some_and(|(ind, _)| *ind >= indent) {
                stack.pop();
            }
            stack.push((indent, "[]".into()));
        }
        let Some((key, value)) = split_key(content) else {
            continue;
        };
        let mut path: Vec<String> = stack.iter().map(|(_, k)| k.clone()).collect();
        path.push(key.to_string());
        let value = value.trim().to_string();
        if value.starts_with('|') || value.starts_with('>') {
            block_indent = Some(key_indent);
        }
        out.push(KeyLine {
            line: i,
            path,
            value,
        });
        stack.push((key_indent, key.to_string()));
    }
    out
}

fn split_key(content: &str) -> Option<(&str, &str)> {
    let colon = content.find(':')?;
    let key = content[..colon].trim();
    let rest = &content[colon + 1..];
    if key.is_empty()
        || key.contains(' ')
        || !(rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t'))
    {
        return None;
    }
    Some((key.trim_matches(['"', '\'']), rest))
}

fn scalar(value: &str) -> Option<String> {
    let v = value.split(" #").next().unwrap_or(value).trim();
    let v = v.trim_matches(['"', '\'']);
    (!v.is_empty()).then(|| v.to_string())
}

fn path_is(path: &[String], expected: &[&str]) -> bool {
    path.len() == expected.len() && path.iter().zip(expected).all(|(a, b)| a == b)
}

/// Injected `query` and `threat.query` of a `configurations.elastic` block.
pub(crate) fn elastic_injections(source: &str) -> Vec<InjectedQuery> {
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let keys = key_lines(&lines);
    let value_at = |path: &[&str]| {
        keys.iter()
            .find(|k| path_is(&k.path, path))
            .and_then(|k| scalar(&k.value))
    };
    let rule_type = value_at(&["configurations", "elastic", "type"]);
    let language = value_at(&["configurations", "elastic", "language"]);
    let threat_language = value_at(&["configurations", "elastic", "threat", "language"]);
    let mut line_starts = Vec::with_capacity(lines.len());
    let mut byte = 0usize;
    for l in &lines {
        line_starts.push(byte);
        byte += l.len();
    }
    let mut out = Vec::new();
    for key in &keys {
        let (language, field_path) = if path_is(&key.path, &["configurations", "elastic", "query"])
        {
            (
                elastic_query_language(rule_type.as_deref(), language.as_deref()),
                vec!["configurations", "elastic", "query"],
            )
        } else if path_is(&key.path, &["configurations", "elastic", "threat", "query"])
            && rule_type.as_deref() == Some("threat_match")
        {
            (
                elastic_query_language(Some("threat_match"), threat_language.as_deref()),
                vec!["configurations", "elastic", "threat", "query"],
            )
        } else if path_is(&key.path, &SEARCH_QUERY) {
            let Some((index, system, language)) = search_item(&lines, &keys, key.line) else {
                continue;
            };
            if system.as_deref() != Some("elastic") {
                continue;
            }
            let language = match language.as_deref() {
                Some("esql") => Some(LanguageId::Esql),
                Some("eql") => Some(LanguageId::Eql),
                Some("kuery") => Some(LanguageId::Kuery),
                Some("lucene") => Some(LanguageId::Lucene),
                _ => None,
            };
            let Some(language) = language else {
                continue;
            };
            let field_path = ["response", "procedure", "searches"]
                .into_iter()
                .map(String::from)
                .chain([index.to_string(), "query".into()])
                .collect();
            if let Some(inj) = scalar_injection(
                source,
                &lines,
                key.line,
                line_starts[key.line],
                language,
                field_path,
            ) {
                out.push(inj);
            }
            continue;
        } else {
            continue;
        };
        let Some(language) = language else {
            continue;
        };
        let field_path = field_path.into_iter().map(String::from).collect();
        if let Some(inj) = scalar_injection(
            source,
            &lines,
            key.line,
            line_starts[key.line],
            language,
            field_path,
        ) {
            out.push(inj);
        }
    }
    out
}

const SEARCH_QUERY: [&str; 5] = ["response", "procedure", "searches", "[]", "query"];

/// For the `response.procedure.searches[]` entry holding the key on `line`:
/// its index and its `system` and `language` values. A search's language is
/// never guessed from its text (specifications#58): with `system: elastic`
/// and no `language`, the query is not analysed.
fn search_item(
    lines: &[&str],
    keys: &[KeyLine],
    line: usize,
) -> Option<(usize, Option<String>, Option<String>)> {
    let in_searches = |k: &KeyLine| k.path.len() == 5 && path_is(&k.path[..4], &SEARCH_QUERY[..4]);
    let starts: Vec<usize> = keys
        .iter()
        .filter(|k| in_searches(k) && lines[k.line].trim_start().starts_with("- "))
        .map(|k| k.line)
        .collect();
    let index = starts.iter().rposition(|s| *s <= line)?;
    let start = starts[index];
    let end = starts.get(index + 1).copied().unwrap_or(usize::MAX);
    let value = |name: &str| {
        keys.iter()
            .find(|k| in_searches(k) && k.line >= start && k.line < end && k.path[4] == name)
            .and_then(|k| scalar(&k.value))
    };
    Some((index, value("system"), value("language")))
}

/// The value of the `key: value` on `lines[i]`: a block scalar (`|`, `>`), or a
/// plain, single-quoted, or double-quoted flow scalar.
fn scalar_injection(
    source: &str,
    lines: &[&str],
    i: usize,
    line_start: usize,
    language: LanguageId,
    field_path: Vec<String>,
) -> Option<InjectedQuery> {
    let line = lines[i];
    let colon = line.find(':')?;
    let after = &line[colon + 1..];
    let value = after.trim();
    if value.starts_with('|') || value.starts_with('>') {
        let indent = line.len() - line.trim_start().len();
        let key_indent = if line.trim_start().starts_with("- ") {
            indent + 2
        } else {
            indent
        };
        return block_injection(lines, i, line_start, key_indent, language, field_path);
    }
    let lead = after.len() - after.trim_start().len();
    let start = line_start + colon + 1 + lead;
    let raw_end = line_start + line.trim_end_matches(['\n', '\r']).len();
    let raw = source.get(start..raw_end)?;
    let (mut inner, mut host_map) = match raw.chars().next()? {
        // A quoted scalar that does not close on its line continues on the
        // next; it is left unanalysed rather than checked in part.
        '\'' => unquote(raw, start, '\'')?,
        '"' => unquote(raw, start, '"')?,
        _ => {
            let body = raw.split(" #").next().unwrap_or(raw).trim_end();
            (body.to_string(), (start..start + body.len()).collect())
        }
    };
    // A plain scalar continues on more-indented lines; YAML folds each line
    // break into a space (and keeps a blank line as a newline).
    if !raw.starts_with(['\'', '"']) {
        let indent = line.len() - line.trim_start().len();
        let key_indent = if line.trim_start().starts_with("- ") {
            indent + 2
        } else {
            indent
        };
        let mut offset = line_start + line.len();
        let mut blank = 0;
        for next in &lines[i + 1..] {
            let content = next.trim_end_matches(['\n', '\r']);
            let trimmed = content.trim_start();
            if trimmed.is_empty() {
                blank += 1;
                offset += next.len();
                continue;
            }
            let next_indent = content.len() - trimmed.len();
            if next_indent <= key_indent || trimmed.starts_with('#') {
                break;
            }
            let body = trimmed.split(" #").next().unwrap_or(trimmed).trim_end();
            let body_start = offset + next_indent;
            let separator = if blank > 0 {
                "\n".repeat(blank)
            } else {
                " ".into()
            };
            for c in separator.chars() {
                push_char(&mut inner, &mut host_map, c, body_start.saturating_sub(1));
            }
            for (k, c) in body.char_indices() {
                push_char(&mut inner, &mut host_map, c, body_start + k);
            }
            blank = 0;
            offset += next.len();
        }
    }
    if inner.trim().is_empty() {
        return None;
    }
    let host_span = ByteSpan::new(
        host_map.first().copied().unwrap_or(start),
        host_map.last().map(|b| b + 1).unwrap_or(raw_end),
    );
    Some(InjectedQuery {
        language,
        field_path,
        inner,
        host_map,
        host_span,
    })
}

/// Strip YAML quotes. Single quotes escape `'` as `''`; double quotes use
/// YAML's `\` escapes. `None` when the scalar does not close on this line or
/// uses an escape YAML rejects.
fn unquote(raw: &str, start: usize, quote: char) -> Option<(String, Vec<usize>)> {
    let mut inner = String::new();
    let mut map = Vec::new();
    let mut chars = raw.char_indices().skip(1).peekable();
    while let Some((i, c)) = chars.next() {
        if c == quote {
            if quote == '\'' && chars.peek().map(|(_, n)| *n) == Some('\'') {
                chars.next();
                push_char(&mut inner, &mut map, '\'', start + i);
                continue;
            }
            return Some((inner, map));
        }
        if quote == '"' && c == '\\' {
            let (j, e) = chars.next()?;
            let hex = |n: usize, chars: &mut std::iter::Peekable<_>| -> Option<char> {
                let digits: String = (0..n)
                    .map(|_| chars.next().map(|(_, d): (usize, char)| d))
                    .collect::<Option<_>>()?;
                char::from_u32(u32::from_str_radix(&digits, 16).ok()?)
            };
            let decoded = match e {
                '0' => '\0',
                'a' => '\u{7}',
                'b' => '\u{8}',
                't' | '\t' => '\t',
                'n' => '\n',
                'v' => '\u{b}',
                'f' => '\u{c}',
                'r' => '\r',
                'e' => '\u{1b}',
                ' ' => ' ',
                '"' => '"',
                '/' => '/',
                '\\' => '\\',
                'N' => '\u{85}',
                '_' => '\u{a0}',
                'L' => '\u{2028}',
                'P' => '\u{2029}',
                'x' => hex(2, &mut chars)?,
                'u' => hex(4, &mut chars)?,
                'U' => hex(8, &mut chars)?,
                _ => return None,
            };
            push_char(&mut inner, &mut map, decoded, start + j - 1);
            continue;
        }
        push_char(&mut inner, &mut map, c, start + i);
    }
    None
}

fn push_char(inner: &mut String, map: &mut Vec<usize>, c: char, host: usize) {
    inner.push(c);
    for k in 0..c.len_utf8() {
        map.push(host + k);
    }
}

fn block_injection(
    lines: &[&str],
    i: usize,
    line_start: usize,
    key_indent: usize,
    language: LanguageId,
    field_path: Vec<String>,
) -> Option<InjectedQuery> {
    let mut inner = String::new();
    let mut host_map = Vec::new();
    let mut b = line_start + lines[i].len();
    let mut host_start = b;
    let mut host_end = b;
    let mut content_indent: Option<usize> = None;
    let mut pending_blank = 0usize;
    for l in &lines[i + 1..] {
        let body_line = l.trim_end_matches(['\n', '\r']);
        if body_line.trim().is_empty() {
            if content_indent.is_some() {
                pending_blank += 1;
            }
            b += l.len();
            continue;
        }
        let ind = body_line.len() - body_line.trim_start().len();
        if ind <= key_indent {
            break;
        }
        let strip = *content_indent.get_or_insert(ind);
        if inner.is_empty() {
            host_start = b;
        }
        if !inner.is_empty() {
            for _ in 0..=pending_blank {
                inner.push('\n');
                host_map.push(host_end.saturating_sub(1).max(host_start));
            }
        }
        pending_blank = 0;
        let cut = strip.min(ind);
        let body = &body_line[cut..];
        for k in 0..body.len() {
            host_map.push(b + cut + k);
        }
        inner.push_str(body);
        host_end = b + body_line.len() + 1;
        b += l.len();
    }
    if inner.is_empty() {
        return None;
    }
    Some(InjectedQuery {
        language,
        field_path,
        inner,
        host_map,
        host_span: ByteSpan::new(host_start, host_end.min(b)),
    })
}

/// A duration in the [elastic-1.0] Durations grammar, in milliseconds:
/// shorthand `[n d][n h][n m][n s]` (lower case, in that order) or ISO 8601
/// `P[nD][T[nH][nM][nS]]`. Zero is returned as `Some(0)`; the caller decides.
pub fn duration_millis(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('P') {
        let (days, time) = match rest.split_once('T') {
            Some((d, t)) => {
                if t.is_empty() {
                    return None;
                }
                (d, Some(t))
            }
            None => (rest, None),
        };
        let mut total = parts(days, &[('D', 86_400_000)])?;
        if let Some(t) = time {
            total += parts(t, &[('H', 3_600_000), ('M', 60_000), ('S', 1_000)])?;
        }
        return (!rest.is_empty()).then_some(total);
    }
    if text.is_empty() {
        return None;
    }
    parts(
        text,
        &[
            ('d', 86_400_000),
            ('h', 3_600_000),
            ('m', 60_000),
            ('s', 1_000),
        ],
    )
}

/// `1h10m`-style parts in the given unit order, each unit at most once.
fn parts(text: &str, units: &[(char, u64)]) -> Option<u64> {
    let mut total = 0u64;
    let mut next_unit = 0usize;
    let mut digits = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let pos = units[next_unit..].iter().position(|(u, _)| *u == c)? + next_unit;
        if digits.is_empty() {
            return None;
        }
        total = total.checked_add(digits.parse::<u64>().ok()?.checked_mul(units[pos].1)?)?;
        digits.clear();
        next_unit = pos + 1;
    }
    digits.is_empty().then_some(total)
}

/// `eql_maxspan_window`: an EQL `sequence ... with maxspan=` longer than the
/// rule's window (interval + lookback) cannot match. `eql_maxspan_lookback`:
/// longer than `lookback` alone, a sequence that straddles two runs is
/// missed ([elastic-1.0] Advisories). Defaults are `interval: 5m`,
/// `lookback: 1m`.
pub(crate) fn maxspan_advisories(
    source: &str,
    configurations: Option<&serde_yaml::Value>,
    injection: &InjectedQuery,
) -> Vec<Diagnostic> {
    let scheduling = configurations
        .and_then(|c| c.get("elastic"))
        .and_then(|e| e.get("scheduling"));
    let read = |key: &str, default: &str| {
        scheduling
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| default.to_string())
    };
    let interval_text = read("interval", "5m");
    let lookback_text = read("lookback", "1m");
    let (Some(interval), Some(lookback)) = (
        duration_millis(&interval_text),
        duration_millis(&lookback_text),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (span, maxspan) in opentide_eql::sequence_maxspans(&injection.inner) {
        let (code, message) = if maxspan > interval + lookback {
            (
                codes::EQL_MAXSPAN_WINDOW,
                format!(
                    "EQL maxspan exceeds the rule window, interval + lookback ({interval_text} + {lookback_text}); the sequence cannot fit one run"
                ),
            )
        } else if maxspan > lookback {
            (
                codes::EQL_MAXSPAN_LOOKBACK,
                format!(
                    "EQL maxspan exceeds scheduling.lookback ({lookback_text}); a sequence that straddles two runs is missed"
                ),
            )
        } else {
            continue;
        };
        let host = remap_span(injection, span);
        out.push(
            Diagnostic::warning(code, message, span_to_range(source, host))
                .with_field_path(injection.field_path.clone()),
        );
    }
    out
}

/// Completion docs for `configurations.elastic.type`, `language`, and
/// `threat.language` values: which engine the block's query gets.
pub(crate) fn value_docs(path: &str, value: &str) -> Option<&'static str> {
    match (path, value) {
        ("configurations.elastic.type", "query") => Some(
            "Custom query rule. `query` is Kibana KQL (`language: kuery`, the default) or Lucene (`language: lucene`).",
        ),
        ("configurations.elastic.type", "eql") => {
            Some("Event correlation rule. `query` is EQL; `language` does not apply.")
        }
        ("configurations.elastic.type", "esql") => Some(
            "ES|QL rule. `query` is ES|QL; `language` does not apply. A non-aggregating query needs `METADATA _id` before Kibana 9.4.",
        ),
        ("configurations.elastic.type", "threshold") => Some(
            "Threshold rule. `query` is Kibana KQL or Lucene per `language`; needs a `threshold` block.",
        ),
        ("configurations.elastic.type", "new_terms") => Some(
            "New terms rule. `query` is Kibana KQL or Lucene per `language`; needs `new_terms.fields` and `history_window_start`.",
        ),
        ("configurations.elastic.type", "threat_match") => Some(
            "Indicator match rule. `query` and `threat.query` are Kibana KQL or Lucene per `language` and `threat.language`.",
        ),
        ("configurations.elastic.type", "machine_learning") => Some(
            "Machine learning rule. No query: it needs `machine_learning.job_id` and `anomaly_threshold`.",
        ),
        ("configurations.elastic.language" | "configurations.elastic.threat.language", "kuery") => {
            Some(
                "Kibana Query Language (the default). `field: value`, `and`/`or`/`not`, `*` wildcards outside quotes. Not Microsoft KQL.",
            )
        }
        (
            "configurations.elastic.language" | "configurations.elastic.threat.language",
            "lucene",
        ) => Some(
            "Lucene `query_string` syntax. Upper-case `AND`/`OR`/`NOT`, `field:value`, `[a TO b]` ranges, `/regex/`.",
        ),
        _ => None,
    }
}

/// An Elastic tenant from `.opentide/configurations/platforms/elastic.toml`:
/// its name and its declared `setup.version`, if any (specifications#59).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElasticTenant {
    pub name: String,
    pub version: Option<String>,
}

/// The `[[tenants]]` of an Elastic platform configuration file. A file that
/// does not parse yields no tenants: configuration diagnostics are the
/// configuration engine's job (#64), and unknown means the 8.19 floor.
pub fn elastic_tenants(toml_text: &str) -> Vec<ElasticTenant> {
    let Ok(doc) = toml_text.parse::<toml::Table>() else {
        return Vec::new();
    };
    doc.get("tenants")
        .and_then(|t| t.as_array())
        .map(|tenants| {
            tenants
                .iter()
                .filter_map(|t| {
                    let name = t.get("name")?.as_str()?.to_string();
                    let version = t
                        .get("setup")
                        .and_then(|s| s.get("version"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    Some(ElasticTenant { name, version })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The stack an Elastic block's queries must run on: the lowest version
/// declared across its target tenants (the block's `tenants`, or every
/// tenant when omitted). `None` (the 8.19 floor) when there are no tenants,
/// a target is unknown, or a target declares no valid version.
pub(crate) fn stack_target(
    block: Option<&serde_yaml::Value>,
    tenants: &[ElasticTenant],
) -> Option<opentide_esql::StackTarget> {
    let named: Vec<&str> = block
        .and_then(|b| b.get("tenants"))
        .and_then(|t| t.as_sequence())
        .map(|s| s.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let targets: Vec<&ElasticTenant> = if named.is_empty() {
        tenants.iter().collect()
    } else {
        named
            .iter()
            .map(|n| tenants.iter().find(|t| t.name == *n))
            .collect::<Option<_>>()?
    };
    if targets.is_empty() {
        return None;
    }
    let versions: Option<Vec<_>> = targets
        .iter()
        .map(|t| {
            t.version
                .as_deref()
                .and_then(opentide_esql::StackTarget::parse)
        })
        .collect();
    opentide_esql::StackTarget::lowest(versions?)
}

/// Range of the key at `path` (`["configurations", "elastic", ...]`), or of
/// the nearest ancestor key that is written.
fn path_range(source: &str, path: &[&str]) -> Range {
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let keys = key_lines(&lines);
    for depth in (1..=path.len()).rev() {
        let want = &path[..depth];
        if let Some(k) = keys
            .iter()
            .find(|k| k.path.len() == want.len() && k.path.iter().zip(want).all(|(a, b)| a == b))
        {
            let line_start: usize = lines[..k.line].iter().map(|l| l.len()).sum();
            let key = want[depth - 1];
            let col = lines[k.line].find(key).unwrap_or(0);
            let start = line_start + col;
            return span_to_range(source, ByteSpan::new(start, start + key.len()));
        }
    }
    Range::point(0, 0)
}

/// Kibana's risk score band for an `alert_severity` value ([elastic-1.0]
/// Severity and risk): Informational and Low map to `low`.
fn risk_band(alert_severity: &str) -> Option<(&'static str, i64, i64)> {
    match alert_severity.to_ascii_lowercase().as_str() {
        "informational" | "low" => Some(("low", 0, 21)),
        "medium" => Some(("medium", 22, 47)),
        "high" => Some(("high", 48, 73)),
        "critical" => Some(("critical", 74, 100)),
        _ => None,
    }
}

/// Techniques a rule inherits through `detection_model`: the objective's
/// `mitre_attack`, else those of its threats.
fn inherited_techniques(detection_model: &str, workspace: &[IndexedObject]) -> Vec<String> {
    let strings = |v: Option<&serde_yaml::Value>| -> Vec<String> {
        v.and_then(|v| v.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let Some(objective) = workspace
        .iter()
        .find(|o| o.object_type == "objective" && o.uuid == detection_model)
    else {
        return Vec::new();
    };
    let body = objective.body.get("objective");
    let own = strings(body.and_then(|b| b.get("mitre_attack")));
    if !own.is_empty() {
        return own;
    }
    strings(body.and_then(|b| b.get("threats")))
        .iter()
        .filter_map(|id| {
            workspace
                .iter()
                .find(|o| o.object_type == "threat" && &o.uuid == id)
        })
        .flat_map(|t| strings(t.body.get("threat").and_then(|b| b.get("mitre_attack"))))
        .collect()
}

/// [elastic-1.0] Advisories that read the block, not its query: `lookback`
/// zero or over an hour, a threshold rule whose `lookback` exceeds its
/// `interval`, an explicit risk score outside its severity's band, and
/// techniques that deploy skips because they are not Enterprise ATT&CK.
pub(crate) fn block_advisories(
    source: &str,
    rule: &serde_yaml::Value,
    workspace: &[IndexedObject],
) -> Vec<Diagnostic> {
    let Some(block) = rule.get("configurations").and_then(|c| c.get("elastic")) else {
        return Vec::new();
    };
    let base = ["configurations", "elastic"];
    let at = |rest: &[&str]| -> (Range, Vec<String>) {
        let path: Vec<&str> = base.iter().chain(rest).copied().collect();
        (
            path_range(source, &path),
            path.iter().map(|s| s.to_string()).collect(),
        )
    };
    let warn = |code: &str, message: String, rest: &[&str]| {
        let (range, path) = at(rest);
        Diagnostic::warning(code, message, range).with_field_path(path)
    };
    let mut out = Vec::new();

    let scheduling = block.get("scheduling");
    let read = |key: &str| scheduling.and_then(|s| s.get(key)).and_then(|v| v.as_str());
    let lookback_text = read("lookback");
    let interval_text = read("interval").unwrap_or("5m");
    let lookback = lookback_text.map_or(Some(60_000), duration_millis);
    let interval = duration_millis(interval_text);
    if let Some(lookback) = lookback {
        if lookback_text.is_some() && lookback == 0 {
            out.push(warn(
                codes::LOOKBACK_ZERO,
                "scheduling.lookback is zero: the next run starts as this window ends, so late events are missed; Elastic recommends at least 1m".into(),
                &["scheduling", "lookback"],
            ));
        }
        if lookback > 3_600_000 {
            out.push(warn(
                codes::LOOKBACK_LONG,
                "scheduling.lookback exceeds 1h: in Elastic it is overlap added to interval, not the whole query window as in Sentinel".into(),
                &["scheduling", "lookback"],
            ));
        }
        let rule_type = block.get("type").and_then(|v| v.as_str());
        if rule_type == Some("threshold") && interval.is_some_and(|i| lookback > i) {
            out.push(warn(
                codes::THRESHOLD_LOOKBACK,
                format!(
                    "threshold rule's lookback exceeds its interval ({interval_text}): threshold counts are not de-duplicated across overlapping runs"
                ),
                &["scheduling", "lookback"],
            ));
        }
    }

    // For `esql`, deploy checks `suppression.group_by` against the query's
    // pre-flight columns ([elastic-1.0] Elasticsearch checks). Compared only
    // when the columns are statically certain.
    if block.get("type").and_then(|v| v.as_str()) == Some("esql") {
        let group_by: Vec<&str> = block
            .get("suppression")
            .and_then(|s| s.get("group_by"))
            .and_then(|g| g.as_sequence())
            .map(|s| s.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let columns = block
            .get("query")
            .and_then(|q| q.as_str())
            .filter(|_| !group_by.is_empty())
            .and_then(opentide_esql::output_columns);
        if let Some(columns) = columns {
            for field in group_by.iter().filter(|f| !columns.iter().any(|c| c == *f)) {
                out.push(warn(
                    codes::ESQL_GROUP_BY_COLUMN,
                    format!(
                        "suppression.group_by `{field}` is not an output column of the ES|QL query ({}); deploy rejects it",
                        columns.join(", ")
                    ),
                    &["suppression", "group_by"],
                ));
            }
        }
    }

    let risk = block.get("risk");
    let score = risk
        .and_then(|r| r.as_i64())
        .map(|s| (s, ["risk"].as_slice()))
        .or_else(|| {
            risk.and_then(|r| r.get("score"))
                .and_then(|s| s.as_i64())
                .map(|s| (s, ["risk", "score"].as_slice()))
        });
    if let Some((score, key)) = score {
        let severity = block.get("severity");
        let level = severity
            .and_then(|s| s.as_str())
            .or_else(|| {
                severity
                    .and_then(|s| s.get("default"))
                    .and_then(|d| d.as_str())
            })
            .or_else(|| {
                rule.get("response")
                    .and_then(|r| r.get("alert_severity"))
                    .and_then(|s| s.as_str())
            })
            .unwrap_or("Informational");
        if let Some((band, low, high)) = risk_band(level) {
            if (0..=100).contains(&score) && !(low..=high).contains(&score) {
                out.push(warn(
                    codes::RISK_BAND,
                    format!(
                        "risk score {score} is outside Kibana's {band} band ({low}–{high}) for alert severity {level}"
                    ),
                    key,
                ));
            }
        }
    }

    if let Some(att) = bundled_vocabs().get("att&ck") {
        let own: Vec<String> = rule
            .get("techniques")
            .and_then(|t| t.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let model = rule.get("detection_model").and_then(|m| m.as_str());
        let inherited = model
            .map(|m| inherited_techniques(m, workspace))
            .unwrap_or_default();
        let mut seen = std::collections::BTreeSet::new();
        for (id, is_own) in own
            .iter()
            .map(|t| (t, true))
            .chain(inherited.iter().map(|t| (t, false)))
        {
            if !seen.insert(id.clone()) {
                continue;
            }
            let Some(name) = att.get(id).and_then(|k| k.title.as_deref()) else {
                continue;
            };
            if name.starts_with("Mobile : ") || name.starts_with("Industrial : ") {
                let (key, how) = if is_own {
                    ("techniques", "")
                } else {
                    ("detection_model", ", inherited through detection_model,")
                };
                out.push(
                    Diagnostic::warning(
                        codes::TECHNIQUE_NOT_ENTERPRISE,
                        format!(
                            "{id} ({name}){how} is not Enterprise ATT&CK; Elastic deploy skips it from the rule's threat mapping"
                        ),
                        path_range(source, &[key]),
                    )
                    .with_field_path(vec![key.to_string()]),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advisory_codes(source: &str, workspace: &[IndexedObject]) -> Vec<String> {
        let rule: serde_yaml::Value = serde_yaml::from_str(source).unwrap();
        block_advisories(source, &rule, workspace)
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    fn block(extra: &str) -> String {
        format!("name: r\nconfigurations:\n  elastic:\n    type: query\n    query: x\n{extra}")
    }

    #[test]
    fn flow_scalars_fold_and_decode_like_yaml() {
        let inner = |query: &str| -> Vec<String> {
            let src = format!(
                "name: r\nconfigurations:\n  elastic:\n    type: query\n    language: kuery\n    query: {query}\n    status: STAGING\n"
            );
            elastic_injections(&src)
                .into_iter()
                .map(|q| {
                    // Every byte of the inner text maps back into the host.
                    assert_eq!(q.host_map.len(), q.inner.len());
                    assert!(q.host_map.iter().all(|&b| b < src.len()));
                    q.inner
                })
                .collect()
        };
        // A plain scalar continued on more-indented lines is one query.
        assert_eq!(
            inner("process.name:cmd.exe and\n      host.name:x # note"),
            vec!["process.name:cmd.exe and host.name:x"]
        );
        // YAML double-quoted escapes.
        assert_eq!(
            inner(r#""a\rb \x41\u0042 \"q\" \\""#),
            vec!["a\rb AB \"q\" \\"]
        );
        assert_eq!(inner("'it''s'"), vec!["it's"]);
        // An escape YAML rejects, or a quote that does not close on its
        // line, is not analysed in part.
        assert!(inner(r#""a\qb""#).is_empty());
        assert!(inner("\"a and\n      b\"").is_empty());
    }

    #[test]
    fn tenants_decide_the_stack_target() {
        let toml = r#"
[platform]
identifier = "elastic"

[[tenants]]
name = "prod"
[tenants.setup]
version = "9.5"

[[tenants]]
name = "legacy"
[tenants.setup]
version = "8.19"

[[tenants]]
name = "unknown"
[tenants.setup]
ssl = true
"#;
        let tenants = elastic_tenants(toml);
        assert_eq!(tenants.len(), 3);
        let block = |names: &str| -> serde_yaml::Value {
            serde_yaml::from_str(&format!("tenants: [{names}]")).unwrap()
        };
        let target =
            |names: &str| stack_target(Some(&block(names)), &tenants).map(|t| t.to_string());
        assert_eq!(target("prod"), Some("9.5".into()));
        assert_eq!(target("prod, legacy"), Some("8.19".into()));
        assert_eq!(
            target("prod, unknown"),
            None,
            "a tenant without a version is the floor"
        );
        assert_eq!(target("missing"), None);
        assert_eq!(
            stack_target(None, &tenants),
            None,
            "every tenant, one unknown"
        );
        assert_eq!(
            stack_target(None, &tenants[..1]).map(|t| t.to_string()),
            Some("9.5".into())
        );
        assert_eq!(stack_target(None, &[]), None);
        assert!(elastic_tenants("not toml [").is_empty());
    }

    #[test]
    fn lookback_advisories() {
        assert_eq!(advisory_codes(&block(""), &[]), Vec::<String>::new());
        let zero = block("    scheduling:\n      lookback: 0m\n");
        assert_eq!(advisory_codes(&zero, &[]), vec![codes::LOOKBACK_ZERO]);
        let long = block("    scheduling:\n      lookback: 2h\n");
        assert_eq!(advisory_codes(&long, &[]), vec![codes::LOOKBACK_LONG]);
        let threshold = "name: r\nconfigurations:\n  elastic:\n    type: threshold\n    scheduling:\n      interval: 5m\n      lookback: 10m\n";
        assert_eq!(
            advisory_codes(threshold, &[]),
            vec![codes::THRESHOLD_LOOKBACK]
        );
        let rule: serde_yaml::Value = serde_yaml::from_str(&zero).unwrap();
        let d = &block_advisories(&zero, &rule, &[])[0];
        assert_eq!(d.range.start.line, 6, "points at the lookback key");
        assert_eq!(
            d.field_path.as_deref().unwrap().join("."),
            "configurations.elastic.scheduling.lookback"
        );
    }

    #[test]
    fn esql_group_by_must_be_an_output_column() {
        let rule = |group_by: &str| {
            format!(
                "name: r\nconfigurations:\n  elastic:\n    type: esql\n    query: |\n      FROM logs-* | STATS c = COUNT(*) BY host.name\n    suppression:\n      group_by: [{group_by}]\n"
            )
        };
        assert!(advisory_codes(&rule("host.name"), &[]).is_empty());
        assert_eq!(
            advisory_codes(&rule("user.name"), &[]),
            vec![codes::ESQL_GROUP_BY_COLUMN]
        );
        // Unknown columns (no KEEP or STATS) are never guessed.
        let open = rule("user.name").replace(" | STATS c = COUNT(*) BY host.name", " METADATA _id");
        assert!(advisory_codes(&open, &[]).is_empty());
    }

    #[test]
    fn risk_score_band_follows_the_alert_severity() {
        assert!(advisory_codes(&block("    severity: High\n    risk: 73\n"), &[]).is_empty());
        assert_eq!(
            advisory_codes(&block("    severity: High\n    risk: 90\n"), &[]),
            vec![codes::RISK_BAND]
        );
        assert_eq!(
            advisory_codes(
                &block("    severity:\n      default: low\n    risk:\n      score: 50\n"),
                &[]
            ),
            vec![codes::RISK_BAND]
        );
        let from_response = format!(
            "response:\n  alert_severity: Critical\n{}",
            block("    risk: 99\n")
        );
        assert!(advisory_codes(&from_response, &[]).is_empty());
        // Informational is Kibana's low band.
        assert_eq!(
            advisory_codes(&block("    risk: 30\n"), &[]),
            vec![codes::RISK_BAND]
        );
    }

    #[test]
    fn non_enterprise_techniques_are_reported_with_their_source() {
        let own = format!("techniques:\n  - T1059\n  - T1626\n{}", block(""));
        assert_eq!(
            advisory_codes(&own, &[]),
            vec![codes::TECHNIQUE_NOT_ENTERPRISE]
        );
        let objective = IndexedObject {
            path: "objectives/o.yaml".into(),
            object_type: "objective".into(),
            uuid: "o-1".into(),
            name: "o".into(),
            body: serde_yaml::from_str("objective:\n  threats: [t-1]\n").unwrap(),
        };
        let threat = IndexedObject {
            path: "threats/t.yaml".into(),
            object_type: "threat".into(),
            uuid: "t-1".into(),
            name: "t".into(),
            body: serde_yaml::from_str("threat:\n  mitre_attack: [T1626, T1059]\n").unwrap(),
        };
        let inherited = format!("detection_model: o-1\n{}", block(""));
        let source = inherited.clone();
        let rule: serde_yaml::Value = serde_yaml::from_str(&source).unwrap();
        let found = block_advisories(&source, &rule, &[objective, threat]);
        assert_eq!(found.len(), 1);
        assert!(
            found[0].message.contains("inherited"),
            "{}",
            found[0].message
        );
        assert_eq!(found[0].range.start.line, 0);
    }

    #[test]
    fn language_follows_type_and_language() {
        assert_eq!(
            elastic_query_language(Some("esql"), None),
            Some(LanguageId::Esql)
        );
        assert_eq!(
            elastic_query_language(Some("eql"), None),
            Some(LanguageId::Eql)
        );
        assert_eq!(
            elastic_query_language(Some("query"), None),
            Some(LanguageId::Kuery)
        );
        assert_eq!(
            elastic_query_language(Some("new_terms"), Some("lucene")),
            Some(LanguageId::Lucene)
        );
        assert_eq!(elastic_query_language(Some("machine_learning"), None), None);
        assert_eq!(elastic_query_language(None, None), None);
    }

    #[test]
    fn durations_follow_the_spec() {
        assert_eq!(duration_millis("5m"), Some(300_000));
        assert_eq!(duration_millis("1h10m"), Some(4_200_000));
        assert_eq!(duration_millis("PT1H"), Some(3_600_000));
        assert_eq!(duration_millis("P1DT2H"), Some(93_600_000));
        assert_eq!(duration_millis("0m"), Some(0));
        assert_eq!(duration_millis("10m1h"), None, "units in d, h, m, s order");
        assert_eq!(duration_millis("1w"), None);
        assert_eq!(duration_millis("PT"), None);
        assert_eq!(duration_millis("1.5h"), None);
    }

    #[test]
    fn query_language_comes_from_siblings_in_any_order() {
        let src = "configurations:\n  elastic:\n    query: |\n      FROM logs-* METADATA _id\n      | LIMIT 1\n    type: esql\n";
        let inj = elastic_injections(src);
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].language, LanguageId::Esql);
        assert_eq!(inj[0].inner, "FROM logs-* METADATA _id\n| LIMIT 1");
    }

    #[test]
    fn single_quoted_kuery_is_unquoted() {
        let src = "configurations:\n  elastic:\n    type: query\n    query: 'event.category : \"process\" and x:''y'''\n";
        let inj = elastic_injections(src);
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].language, LanguageId::Kuery);
        assert_eq!(inj[0].inner, "event.category : \"process\" and x:'y'");
        let at = inj[0].host_map[0];
        assert_eq!(&src[at..at + 5], "event");
    }

    #[test]
    fn threat_query_takes_threat_language_and_osquery_is_skipped() {
        let src = "\
configurations:
  elastic:
    type: threat_match
    language: lucene
    query: 'event.category:file'
    threat:
      index: [logs-ti_*]
      language: kuery
      query: '@timestamp >= \"now-30d/d\"'
    actions:
      respond:
        - osquery:
            query: SELECT * FROM processes
";
        let inj = elastic_injections(src);
        let langs: Vec<_> = inj
            .iter()
            .map(|i| (i.field_path.join("."), i.language))
            .collect();
        assert_eq!(
            langs,
            vec![
                ("configurations.elastic.query".into(), LanguageId::Lucene),
                (
                    "configurations.elastic.threat.query".into(),
                    LanguageId::Kuery
                ),
            ]
        );
    }

    #[test]
    fn elastic_hunts_take_their_declared_language() {
        let src = "\
response:
  procedure:
    searches:
      - purpose: rare parents
        system: elastic
        language: esql
        query: |
          FROM logs-* | STATS c = COUNT(*) BY process.parent.name
      - purpose: no language, not analysed
        system: elastic
        query: process.name:cmd.exe
      - system: sentinel
        language: kuery
        query: SecurityEvent
      - query: 'event.category:process'
        language: kuery
        system: elastic
";
        let inj = elastic_injections(src);
        let found: Vec<_> = inj
            .iter()
            .map(|i| (i.field_path.join("."), i.language, i.inner.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                (
                    "response.procedure.searches.0.query".into(),
                    LanguageId::Esql,
                    "FROM logs-* | STATS c = COUNT(*) BY process.parent.name"
                ),
                (
                    "response.procedure.searches.3.query".into(),
                    LanguageId::Kuery,
                    "event.category:process"
                ),
            ]
        );
    }

    #[test]
    fn no_type_means_no_injection() {
        let src = "configurations:\n  elastic:\n    query: x\n";
        assert!(elastic_injections(src).is_empty());
    }
}
