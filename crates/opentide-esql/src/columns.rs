//! Static output columns of an ES|QL query.
//!
//! [`output_columns`] follows the pipeline command by command. `FROM` and `TS`
//! read whatever the index mappings hold, so the column list is unknown until
//! a command fixes it: `KEEP` with plain names, or `STATS`. After that,
//! commands that add, drop, or rename named columns keep it known. Anything
//! whose output depends on data the query does not show (a lookup index, an
//! enrich policy without `WITH`, a grok pattern with nested captures, an
//! unnamed expression Kibana may re-print) makes it unknown again, and the
//! function returns `None` rather than guess.

use crate::{string_value, text};
use opentide_core::LanguageId;
use opentide_syntax::parse as ts_parse;
use tree_sitter::Node;

/// Column names a query outputs, in order, when they can be known without the
/// index mappings; `None` otherwise.
///
/// `None` when:
/// - the query does not parse, or uses an unknown command;
/// - the last command that fixed the column set is followed by one whose
///   output is not in the query text: `LOOKUP JOIN`, `ENRICH` without `WITH`,
///   `FORK`, `FUSE`, `URI_PARTS` / `USER_AGENT` / `REGISTERED_DOMAIN` /
///   `IP_LOCATION`, `HIGHLIGHT`, `MMR`, `DENSE_VECTOR`, the `*_INFO` and
///   `TS_COLLAPSE` commands, `PROMQL`, `SHOW`;
/// - there is no such command at all (`FROM` without `KEEP` or `STATS`);
/// - `KEEP`, `DROP`, or `RENAME` uses a wildcard while the input columns are
///   unknown, or names a column the known input lacks;
/// - an `EVAL` or `INLINE STATS` column has no name and is not a plain field
///   (its name is the expression text, which Kibana 9.4+ may re-print);
/// - a `GROK` pattern refers to a built-in pattern that has its own captures,
///   or a custom definition; a `DISSECT` pattern uses reference keys;
/// - a name is a `?` parameter, or the same name is defined twice in one
///   `STATS`.
///
/// Unnamed `STATS` aggregates are named by their exact text, as Elasticsearch
/// does (`count(*)`); aggregating queries reach Elasticsearch unchanged.
pub fn output_columns(source: &str) -> Option<Vec<String>> {
    let tree = ts_parse(LanguageId::Esql, source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let mut cursor = root.walk();
    let query = root
        .named_children(&mut cursor)
        .find(|c| c.kind() == "query")?;
    let mut columns = source_columns(query.child_by_field_name("source")?, source)?;
    let mut cursor = query.walk();
    for command in query.children_by_field_name("command", &mut cursor) {
        columns = apply(command, source, columns)?;
    }
    columns
}

/// `Some(None)`: the pipeline goes on with unknown columns. `None`: give up.
type Columns = Option<Vec<String>>;

fn source_columns(node: Node, source: &str) -> Option<Columns> {
    match node.kind() {
        "from_command" | "ts_command" => Some(None),
        "row_command" => {
            let mut cols = Vec::new();
            let mut cursor = node.walk();
            for field in node.named_children(&mut cursor) {
                if field.kind() != "field_assignment_or_expression" {
                    continue;
                }
                define(&mut cols, field_name(field, source, false)?);
            }
            Some(Some(cols))
        }
        _ => None,
    }
}

fn apply(command: Node, source: &str, columns: Columns) -> Option<Columns> {
    match command.kind() {
        "where_command" | "sort_command" | "limit_command" | "sample_command"
        | "mv_expand_command" | "dedup_command" | "fill_null_command" => Some(columns),
        "keep_command" => keep(command, source, columns.as_deref()),
        "drop_command" => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            for pattern in name_patterns(command, source)? {
                let before = cols.len();
                cols.retain(|c| !pattern.matches(c));
                if before == cols.len() {
                    return None;
                }
            }
            Some(Some(cols))
        }
        "rename_command" => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let mut cursor = command.walk();
            for clause in command.named_children(&mut cursor) {
                if clause.kind() != "rename_clause" {
                    continue;
                }
                let old = Pattern::of(clause.child_by_field_name("old")?, source)?.literal()?;
                let new = Pattern::of(clause.child_by_field_name("new")?, source)?.literal()?;
                let mut at = cols.iter().position(|c| *c == old)?;
                if old != new {
                    // A column already called `new` is replaced; the renamed
                    // one keeps the old column's place.
                    if let Some(pos) = cols.iter().position(|c| *c == new) {
                        cols.remove(pos);
                        if pos < at {
                            at -= 1;
                        }
                    }
                    cols[at] = new;
                }
            }
            Some(Some(cols))
        }
        "eval_command" => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let mut cursor = command.walk();
            for field in command.named_children(&mut cursor) {
                if field.kind() == "field_assignment_or_expression" {
                    define(&mut cols, field_name(field, source, false)?);
                }
            }
            Some(Some(cols))
        }
        "stats_command" => {
            let mut cols: Vec<String> = Vec::new();
            let mut cursor = command.walk();
            let aggregates: Vec<Node> = command
                .children_by_field_name("aggregate", &mut cursor)
                .collect();
            for agg in aggregates {
                let name = match agg.child_by_field_name("name") {
                    Some(name) => qualified(name, source)?,
                    None => verbatim(agg, source)?,
                };
                push_unique(&mut cols, name)?;
            }
            let mut cursor = command.walk();
            let groups: Vec<Node> = command.children_by_field_name("by", &mut cursor).collect();
            for group in groups {
                push_unique(&mut cols, field_name(group, source, true)?)?;
            }
            Some(Some(cols))
        }
        "inline_stats_command" => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let mut cursor = command.walk();
            if command
                .children_by_field_name("by", &mut cursor)
                .any(|g| g.child_by_field_name("name").is_some())
            {
                return None;
            }
            let mut cursor = command.walk();
            let aggregates: Vec<Node> = command
                .children_by_field_name("aggregate", &mut cursor)
                .collect();
            for agg in aggregates {
                let name = qualified(agg.child_by_field_name("name")?, source)?;
                define(&mut cols, name);
            }
            Some(Some(cols))
        }
        "dissect_command" => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let pattern = string_value(text(command.child_by_field_name("pattern")?, source))?;
            for key in dissect_keys(&pattern)? {
                define(&mut cols, key);
            }
            Some(Some(cols))
        }
        "grok_command" => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let mut names = Vec::new();
            let mut cursor = command.walk();
            let patterns: Vec<Node> = command
                .children_by_field_name("pattern", &mut cursor)
                .collect();
            for pattern in patterns {
                names.extend(grok_names(&string_value(text(pattern, source))?)?);
            }
            // Elasticsearch adds grok columns sorted by name.
            names.sort();
            names.dedup();
            for name in names {
                define(&mut cols, name);
            }
            Some(Some(cols))
        }
        "enrich_command" => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let mut cursor = command.walk();
            let clauses: Vec<Node> = command
                .children_by_field_name("with", &mut cursor)
                .collect();
            if clauses.is_empty() {
                return Some(None);
            }
            for clause in clauses {
                let target = clause
                    .child_by_field_name("new")
                    .or_else(|| clause.child_by_field_name("field"))?;
                define(&mut cols, Pattern::of(target, source)?.literal()?);
            }
            Some(Some(cols))
        }
        "change_point_command" => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let type_name = match command.child_by_field_name("type_name") {
                Some(n) => qualified(n, source)?,
                None => "type".to_string(),
            };
            let pvalue = match command.child_by_field_name("pvalue_name") {
                Some(n) => qualified(n, source)?,
                None => "pvalue".to_string(),
            };
            define(&mut cols, type_name);
            define(&mut cols, pvalue);
            Some(Some(cols))
        }
        "completion_command" | "rerank_command" => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let name = match command.child_by_field_name("target") {
                Some(n) => qualified(n, source)?,
                None if command.kind() == "completion_command" => "completion".to_string(),
                None => "_score".to_string(),
            };
            define(&mut cols, name);
            Some(Some(cols))
        }
        "join_command"
        | "fork_command"
        | "fuse_command"
        | "uri_parts_command"
        | "registered_domain_command"
        | "user_agent_command"
        | "ip_location_command"
        | "metrics_info_command"
        | "ts_info_command"
        | "ts_collapse_command"
        | "mmr_command"
        | "highlight_command"
        | "dense_vector_command" => Some(None),
        _ => None,
    }
}

/// Drop an existing column of that name and append it (`EVAL`, `GROK`, ...).
fn define(cols: &mut Vec<String>, name: String) {
    cols.retain(|c| *c != name);
    cols.push(name);
}

fn push_unique(cols: &mut Vec<String>, name: String) -> Option<()> {
    if cols.contains(&name) {
        return None;
    }
    cols.push(name);
    Some(())
}

/// The column name of an `EVAL`/`ROW`/`BY` item: its `name =`, or a plain
/// field reference. Other unnamed expressions are named by their text, which
/// is only trusted for `STATS … BY` (`by_text`).
fn field_name(field: Node, source: &str, by_text: bool) -> Option<String> {
    if let Some(name) = field.child_by_field_name("name") {
        return qualified(name, source);
    }
    let value = field.child_by_field_name("value")?;
    if value.kind() == "qualified_name" {
        let name = qualified(value, source)?;
        // `EVAL x` names the column by its text; `` `x` `` would keep the backticks.
        if by_text || text(value, source) == name {
            return Some(name);
        }
        return None;
    }
    if by_text {
        return verbatim(field, source);
    }
    None
}

/// Exact source text, the name Elasticsearch gives an unnamed expression.
/// Comments inside would be part of it; give up on those.
fn verbatim(node: Node, source: &str) -> Option<String> {
    let t = text(node, source).trim();
    (!t.contains("/*") && !t.contains("//") && !t.is_empty()).then(|| t.to_string())
}

/// A dotted name with backquoted parts unquoted. `None` for parameters.
pub(crate) fn qualified(node: Node, source: &str) -> Option<String> {
    let mut parts = Vec::new();
    let mut cursor = node.walk();
    for part in node.named_children(&mut cursor) {
        match part.kind() {
            "identifier" | "id_pattern" => parts.push(text(part, source).to_string()),
            "quoted_identifier" => parts.push(unquote(text(part, source))),
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("."))
}

fn unquote(t: &str) -> String {
    t.get(1..t.len().saturating_sub(1))
        .unwrap_or("")
        .replace("``", "`")
}

/// A `KEEP`/`DROP`/`RENAME` name pattern: literal pieces and `*`.
#[derive(Debug, Clone)]
struct Pattern {
    pieces: Vec<Piece>,
}

#[derive(Debug, Clone, PartialEq)]
enum Piece {
    Text(String),
    Star,
}

impl Pattern {
    fn of(node: Node, source: &str) -> Option<Self> {
        let mut pieces = Vec::new();
        let mut cursor = node.walk();
        let mut first = true;
        for part in node.named_children(&mut cursor) {
            if !first {
                pieces.push(Piece::Text(".".into()));
            }
            first = false;
            match part.kind() {
                "id_pattern" | "identifier" => {
                    let t = text(part, source);
                    for (i, chunk) in t.split('*').enumerate() {
                        if i > 0 {
                            pieces.push(Piece::Star);
                        }
                        if !chunk.is_empty() {
                            pieces.push(Piece::Text(chunk.to_string()));
                        }
                    }
                }
                "quoted_identifier" => pieces.push(Piece::Text(unquote(text(part, source)))),
                _ => return None,
            }
        }
        // Merge adjacent text pieces.
        let mut merged: Vec<Piece> = Vec::new();
        for piece in pieces {
            match (merged.last_mut(), piece) {
                (Some(Piece::Text(prev)), Piece::Text(t)) => prev.push_str(&t),
                (_, p) => merged.push(p),
            }
        }
        (!merged.is_empty()).then_some(Self { pieces: merged })
    }

    fn literal(&self) -> Option<String> {
        match self.pieces.as_slice() {
            [Piece::Text(t)] => Some(t.clone()),
            _ => None,
        }
    }

    /// KEEP precedence: a full name beats a partial wildcard beats `*`.
    fn rank(&self) -> u8 {
        match self.pieces.as_slice() {
            [Piece::Text(_)] => 3,
            [Piece::Star] => 1,
            _ => 2,
        }
    }

    fn matches(&self, name: &str) -> bool {
        fn go(pieces: &[Piece], s: &str) -> bool {
            match pieces.split_first() {
                None => s.is_empty(),
                Some((Piece::Text(t), rest)) => {
                    s.strip_prefix(t.as_str()).is_some_and(|r| go(rest, r))
                }
                Some((Piece::Star, rest)) => {
                    (0..=s.len()).any(|i| s.is_char_boundary(i) && go(rest, &s[i..]))
                }
            }
        }
        go(&self.pieces, name)
    }
}

fn name_patterns(command: Node, source: &str) -> Option<Vec<Pattern>> {
    let mut cursor = command.walk();
    command
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "name_pattern")
        .map(|c| Pattern::of(c, source))
        .collect()
}

/// `KEEP`: each column goes to the highest-ranked pattern that matches it
/// (rightmost on a tie) and the output follows the pattern order.
fn keep(command: Node, source: &str, input: Option<&[String]>) -> Option<Columns> {
    let patterns = name_patterns(command, source)?;
    let Some(input) = input else {
        // Unknown input: only plain names give a known output.
        let mut names: Vec<(usize, String)> = Vec::new();
        for (i, p) in patterns.iter().enumerate() {
            let Some(name) = p.literal() else {
                return Some(None);
            };
            names.retain(|(_, n)| *n != name);
            names.push((i, name));
        }
        names.sort_by_key(|(i, _)| *i);
        return Some(Some(names.into_iter().map(|(_, n)| n).collect()));
    };
    let mut owner: Vec<Option<usize>> = vec![None; input.len()];
    for (i, pattern) in patterns.iter().enumerate() {
        let mut matched = false;
        for (c, column) in input.iter().enumerate() {
            if !pattern.matches(column) {
                continue;
            }
            matched = true;
            let better = owner[c].is_none_or(|o| pattern.rank() >= patterns[o].rank());
            if better {
                owner[c] = Some(i);
            }
        }
        if !matched && pattern.literal().is_some() {
            return None;
        }
    }
    let mut out = Vec::new();
    for i in 0..patterns.len() {
        for (c, column) in input.iter().enumerate() {
            if owner[c] == Some(i) {
                out.push(column.clone());
            }
        }
    }
    Some(Some(out))
}

/// Output keys of a dissect pattern in pattern order: `%{key}`, `%{+key}`,
/// `%{key->}`, `%{+key/2}`. `%{?key}` and `%{}` are skipped; reference keys
/// (`%{*k}`, `%{&k}`) are rejected by ES|QL.
pub(crate) fn dissect_keys(pattern: &str) -> Option<Vec<String>> {
    let mut keys: Vec<String> = Vec::new();
    let mut rest = pattern;
    while let Some(start) = rest.find("%{") {
        let after = &rest[start + 2..];
        let end = after.find('}')?;
        let raw = &after[..end];
        rest = &after[end + 1..];
        let raw = raw.strip_suffix("->").unwrap_or(raw);
        let (modifier, name) = match raw.chars().next() {
            Some(c @ ('+' | '?' | '*' | '&')) => (Some(c), &raw[1..]),
            _ => (None, raw),
        };
        let name = match modifier {
            Some('*' | '&') => return None,
            Some('?') => continue,
            Some('+') => name.rsplit_once('/').map_or(name, |(n, order)| {
                if !order.is_empty() && order.bytes().all(|b| b.is_ascii_digit()) {
                    n
                } else {
                    name
                }
            }),
            _ => name,
        };
        if !name.is_empty() && !keys.iter().any(|k| k == name) {
            keys.push(name.to_string());
        }
    }
    Some(keys)
}

/// Built-in (ECS v1) grok patterns that add no capture of their own, read off
/// Elasticsearch's `libs/grok` `ecs-v1/grok-patterns`. `%{NAME}` with one of
/// these adds no column; any other unnamed `%{NAME}` may, so it gives up.
const GROK_PLAIN: &[&str] = &[
    "BASE10NUM",
    "BASE16FLOAT",
    "BASE16NUM",
    "CISCOMAC",
    "COMMONMAC",
    "DATA",
    "DATE",
    "DATESTAMP",
    "DATESTAMP_EVENTLOG",
    "DATESTAMP_OTHER",
    "DATESTAMP_RFC2822",
    "DATESTAMP_RFC822",
    "DATE_EU",
    "DATE_US",
    "DATE_YMD",
    "DAY",
    "EMAILADDRESS",
    "EMAILLOCALPART",
    "GREEDYDATA",
    "HOSTNAME",
    "HOSTPORT",
    "HOUR",
    "HTTPDATE",
    "INT",
    "IP",
    "IPORHOST",
    "IPV4",
    "IPV6",
    "ISO8601_SECOND",
    "ISO8601_TIMEZONE",
    "LOGLEVEL",
    "MAC",
    "MINUTE",
    "MONTH",
    "MONTHDAY",
    "MONTHNUM",
    "MONTHNUM2",
    "NONNEGINT",
    "NOTSPACE",
    "NUMBER",
    "PATH",
    "POSINT",
    "PROG",
    "QS",
    "QUOTEDSTRING",
    "SECOND",
    "SPACE",
    "SYSLOGHOST",
    "SYSLOGTIMESTAMP",
    "TIME",
    "TIMESTAMP_ISO8601",
    "TIMESTAMP_YMD",
    "TTY",
    "TZ",
    "UNIXPATH",
    "URI",
    "URIHOST",
    "URIPARAM",
    "URIPATH",
    "URIPATHPARAM",
    "URIPROTO",
    "URIQUERY",
    "URN",
    "USER",
    "USERNAME",
    "UUID",
    "WINDOWSMAC",
    "WINPATH",
    "WORD",
    "YEAR",
];

/// Columns a grok pattern adds: `%{SYNTAX:name}` / `%{SYNTAX:name:type}` and
/// regex named groups `(?<name>…)`.
pub(crate) fn grok_names(pattern: &str) -> Option<Vec<String>> {
    let mut names = Vec::new();
    let mut rest = pattern;
    while let Some(start) = rest.find("%{") {
        let after = &rest[start + 2..];
        let end = after.find('}')?;
        let inner = &after[..end];
        rest = &after[end + 1..];
        if inner.contains('=') {
            return None;
        }
        let mut parts = inner.splitn(3, ':');
        let syntax = parts.next()?;
        match parts.next() {
            Some(name) if !name.is_empty() && !name.contains('[') => names.push(name.to_string()),
            Some(_) => return None,
            None if GROK_PLAIN.contains(&syntax) => {}
            None => return None,
        }
    }
    let mut rest = pattern;
    while let Some(start) = rest.find("(?<") {
        let after = &rest[start + 3..];
        rest = after;
        if after.starts_with(['=', '!']) {
            continue;
        }
        let end = after.find('>')?;
        names.push(after[..end].to_string());
    }
    Some(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cols(q: &str) -> Option<Vec<String>> {
        output_columns(q)
    }

    fn v(names: &[&str]) -> Option<Vec<String>> {
        Some(names.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn from_without_a_fixing_command_is_unknown() {
        assert_eq!(cols("FROM logs-* | WHERE a == 1"), None);
        assert_eq!(cols("FROM logs-* | EVAL x = 1"), None);
        assert_eq!(cols("FROM logs-* | KEEP host.*"), None);
        assert_eq!(cols("FROM logs-* | WHERE"), None, "parse error");
        assert_eq!(cols("FROM logs-* | frobnicate | KEEP a"), None);
    }

    #[test]
    fn keep_with_plain_names_fixes_the_columns() {
        assert_eq!(
            cols("FROM logs-* METADATA _id | KEEP @timestamp, host.name, `user`.name, _id"),
            v(&["@timestamp", "host.name", "user.name", "_id"])
        );
        assert_eq!(
            cols("FROM a | KEEP x, y, x"),
            v(&["y", "x"]),
            "rightmost wins"
        );
        assert_eq!(
            cols("FROM a | KEEP a, b, c | KEEP c, *"),
            v(&["c", "a", "b"])
        );
        assert_eq!(
            cols("FROM a | KEEP ab, ac, b | KEEP a*, b"),
            v(&["ab", "ac", "b"])
        );
        assert_eq!(cols("FROM a | KEEP a, b | KEEP z"), None, "unknown column");
    }

    #[test]
    fn stats_fixes_the_columns() {
        assert_eq!(
            cols("FROM logs-* | STATS Esql.count = COUNT(*), m = MAX(x) BY host.name, user.name"),
            v(&["Esql.count", "m", "host.name", "user.name"])
        );
        assert_eq!(
            cols("FROM logs-* | STATS count(*) BY b = BUCKET(@timestamp, 1 hour)"),
            v(&["count(*)", "b"])
        );
        assert_eq!(
            cols("FROM a | STATS c = COUNT(*) WHERE x > 1, COUNT(*) WHERE y BY h"),
            v(&["c", "COUNT(*) WHERE y", "h"])
        );
        assert_eq!(cols("FROM a | STATS c = COUNT(*), c = MAX(x)"), None);
        assert_eq!(
            cols("FROM a | STATS c = COUNT(*) BY h | EVAL d = c * 2 | DROP h"),
            v(&["c", "d"])
        );
        assert_eq!(
            cols("FROM a | STATS c = COUNT(*) BY h | RENAME c AS n"),
            v(&["n", "h"])
        );
        assert_eq!(
            cols("FROM a | STATS c = COUNT(*) BY h | RENAME c AS h"),
            v(&["h"])
        );
        assert_eq!(
            cols("FROM a | STATS c = COUNT(*) BY h | RENAME z AS y"),
            None
        );
        assert_eq!(
            cols("FROM a | STATS c = COUNT(*) BY h | DROP c*"),
            v(&["h"])
        );
    }

    #[test]
    fn eval_inline_stats_and_extractors() {
        assert_eq!(
            cols("ROW a = 1, b = 2 | EVAL a = b + 1, c = TO_STRING(a)"),
            v(&["b", "a", "c"])
        );
        assert_eq!(cols("ROW a = 1 | EVAL a + 1"), None, "unnamed expression");
        assert_eq!(
            cols("ROW msg = \"x\" | DISSECT msg \"%{a} %{?skip} %{+a} %{b->} %{}\""),
            v(&["msg", "a", "b"])
        );
        assert_eq!(cols("ROW msg = \"x\" | DISSECT msg \"%{*k} %{&k}\""), None);
        assert_eq!(
            cols("ROW msg = \"x\" | GROK msg \"%{WORD:z} %{IP:a.b} %{NUMBER:n:int} %{SPACE}\""),
            v(&["msg", "a.b", "n", "z"])
        );
        assert_eq!(cols("ROW msg = \"x\" | GROK msg \"%{SYSLOGBASE}\""), None);
        assert_eq!(
            cols("ROW msg = \"x\" | GROK msg \"\"\"(?<user>\\w+) (?<!x)%{GREEDYDATA:rest}\"\"\""),
            v(&["msg", "rest", "user"])
        );
        assert_eq!(
            cols("ROW a = 1 | INLINE STATS c = COUNT(*) BY a"),
            v(&["a", "c"])
        );
        assert_eq!(cols("ROW a = 1 | INLINE STATS COUNT(*)"), None);
        assert_eq!(
            cols("ROW ip = \"1.1.1.1\" | ENRICH p ON ip WITH city = name, country"),
            v(&["ip", "city", "country"])
        );
        assert_eq!(cols("ROW ip = \"1.1.1.1\" | ENRICH p ON ip"), None);
        assert_eq!(
            cols("ROW a = 1 | LOOKUP JOIN l ON a | KEEP a, b"),
            v(&["a", "b"])
        );
        assert_eq!(cols("ROW a = 1 | LOOKUP JOIN l ON a"), None);
        assert_eq!(
            cols("ROW a = 1 | COMPLETION a WITH {\"inference_id\": \"e\"}"),
            v(&["a", "completion"])
        );
        assert_eq!(
            cols("ROW a = 1 | CHANGE_POINT a ON a AS t, p"),
            v(&["a", "t", "p"])
        );
    }

    #[test]
    fn detection_rule_shapes() {
        let q = "from logs-endpoint.events.process-* metadata _id, _version, _index\n| where host.os.type == \"windows\"\n| keep @timestamp, host.name, process.name, _id, _version, _index";
        assert_eq!(
            cols(q),
            v(&[
                "@timestamp",
                "host.name",
                "process.name",
                "_id",
                "_version",
                "_index"
            ])
        );
        let q = "from logs-*\n| stats Esql.event_count = count(), Esql.host_values = values(host.name) by user.name\n| where Esql.event_count > 5\n| keep Esql.*, user.name";
        assert_eq!(
            cols(q),
            v(&["Esql.event_count", "Esql.host_values", "user.name"])
        );
    }

    #[test]
    fn dissect_and_strings() {
        assert_eq!(string_value("\"a\\\\b\""), Some("a\\b".into()));
        assert_eq!(string_value("\"\"\"a\\b\"\"\""), Some("a\\b".into()));
        assert_eq!(
            dissect_keys("%{+ts/2} %{+ts/1} %{a->} %{?x}"),
            Some(vec!["ts".into(), "a".into()])
        );
    }
}
