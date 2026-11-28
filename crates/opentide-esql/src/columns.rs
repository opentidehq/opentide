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

use crate::gates::{SyntaxElement, first_token, nodes_after, parts, text_of};
use crate::syntax::SyntaxKind as K;
use crate::{SyntaxNode, string_value};
use rowan::NodeOrToken;

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
    let tree = crate::tree::parse_tree(source)?;
    if tree.has_error() {
        return None;
    }
    let query = tree.syntax.children().find(|c| c.kind() == K::QUERY)?;
    let parts = parts(&query);
    let mut commands = parts.iter().filter_map(SyntaxElement::as_node);
    let mut columns = source_columns(commands.next()?, source)?;
    for command in commands {
        columns = apply(command, source, columns)?;
    }
    columns
}

/// `Some(None)`: the pipeline goes on with unknown columns. `None`: give up.
type Columns = Option<Vec<String>>;

/// The nodes of `parts` (comments aside), each with its position there.
pub(crate) fn nodes(parts: &[SyntaxElement]) -> impl Iterator<Item = (usize, &SyntaxNode)> {
    parts
        .iter()
        .enumerate()
        .filter_map(|(i, p)| Some((i, p.as_node()?)))
}

/// The nodes of `parts` before `at` (all of them without one).
fn nodes_before(parts: &[SyntaxElement], at: Option<usize>) -> impl Iterator<Item = &SyntaxNode> {
    nodes(parts)
        .take_while(move |(i, _)| at.is_none_or(|at| *i < at))
        .map(|(_, n)| n)
}

/// An assignment's (`name = value`, `agg WHERE filter`) labelled nodes.
#[derive(Default)]
pub(crate) struct Assignment {
    /// The first node before `=`.
    pub name: Option<SyntaxNode>,
    /// The first node neither before `=` nor after `WHERE`.
    pub value: Option<SyntaxNode>,
    /// The first node after `WHERE`.
    pub filter: Option<SyntaxNode>,
}

/// The [`Assignment`] of an aggregate or a field; another node (an `ERROR`)
/// has none of its parts. The parser reads an aggregate's `WHERE` after its
/// `=` (`processing.rs`, `field`).
pub(crate) fn assignment(node: &SyntaxNode) -> Assignment {
    let mut out = Assignment::default();
    if !matches!(
        node.kind(),
        K::AGGREGATE_FIELD | K::FIELD_ASSIGNMENT_OR_EXPRESSION
    ) {
        return out;
    }
    let parts = parts(node);
    let eq = first_token(&parts, &[K::EQ]);
    let filter = first_token(&parts, &[K::WHERE_KW]);
    for (i, n) in nodes(&parts) {
        let slot = if filter.is_some_and(|w| i > w) {
            &mut out.filter
        } else if eq.is_some_and(|e| i < e) {
            &mut out.name
        } else {
            &mut out.value
        };
        slot.get_or_insert_with(|| n.clone());
    }
    out
}

/// A rename clause's old and new names: `old AS new`, or `new = old`.
pub(crate) fn renamed(clause: &SyntaxNode) -> (Option<SyntaxNode>, Option<SyntaxNode>) {
    let parts = parts(clause);
    let as_first = first_token(&parts, &[K::AS_KW]).is_some();
    let mut names = nodes(&parts).map(|(_, n)| n.clone());
    let (first, second) = (names.next(), names.next());
    if as_first {
        (first, second)
    } else {
        (second, first)
    }
}

/// The nodes of `kind` among a command's nodes.
pub(crate) fn child_of(parts: &[SyntaxElement], kind: K) -> Vec<&SyntaxNode> {
    nodes(parts)
        .map(|(_, n)| n)
        .filter(|n| n.kind() == kind)
        .collect()
}

fn source_columns(node: &SyntaxNode, source: &str) -> Option<Columns> {
    match node.kind() {
        K::FROM_COMMAND | K::TS_COMMAND => Some(None),
        K::ROW_COMMAND => {
            let mut cols = Vec::new();
            for field in child_of(&parts(node), K::FIELD_ASSIGNMENT_OR_EXPRESSION) {
                define(&mut cols, field_name(field, source, false)?);
            }
            Some(Some(cols))
        }
        _ => None,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per command, as the pipeline reads them"
)]
fn apply(command: &SyntaxNode, source: &str, columns: Columns) -> Option<Columns> {
    let own = parts(command);
    match command.kind() {
        K::WHERE_COMMAND
        | K::SORT_COMMAND
        | K::LIMIT_COMMAND
        | K::SAMPLE_COMMAND
        | K::MV_EXPAND_COMMAND
        | K::DEDUP_COMMAND
        | K::FILL_NULL_COMMAND => Some(columns),
        K::KEEP_COMMAND => keep(&own, source, columns.as_deref()),
        K::DROP_COMMAND => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            for pattern in name_patterns(&own, source)? {
                let before = cols.len();
                cols.retain(|c| !pattern.matches(c));
                if before == cols.len() {
                    return None;
                }
            }
            Some(Some(cols))
        }
        K::RENAME_COMMAND => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            for clause in child_of(&own, K::RENAME_CLAUSE) {
                let (old, new) = renamed(clause);
                let old = Pattern::of(&old?, source)?.literal()?;
                let new = Pattern::of(&new?, source)?.literal()?;
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
        K::EVAL_COMMAND => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            for field in child_of(&own, K::FIELD_ASSIGNMENT_OR_EXPRESSION) {
                define(&mut cols, field_name(field, source, false)?);
            }
            Some(Some(cols))
        }
        K::STATS_COMMAND => {
            let mut cols: Vec<String> = Vec::new();
            let by = first_token(&own, &[K::BY_KW]);
            for agg in nodes_before(&own, by) {
                let name = match assignment(agg).name {
                    Some(name) => qualified_of(&name, source)?,
                    None => verbatim(agg, source)?,
                };
                push_unique(&mut cols, name)?;
            }
            for group in by.map(|by| nodes_after(&own, by)).into_iter().flatten() {
                push_unique(&mut cols, field_name(group, source, true)?)?;
            }
            Some(Some(cols))
        }
        K::INLINE_STATS_COMMAND => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let by = first_token(&own, &[K::BY_KW]);
            if by
                .map(|by| nodes_after(&own, by))
                .into_iter()
                .flatten()
                .any(|g| assignment(g).name.is_some())
            {
                return None;
            }
            for agg in nodes_before(&own, by) {
                define(&mut cols, qualified_of(&assignment(agg).name?, source)?);
            }
            Some(Some(cols))
        }
        K::DISSECT_COMMAND => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            // The input, then the pattern; the options after.
            let pattern = nodes(&own)
                .map(|(_, n)| n)
                .skip(1)
                .find(|n| n.kind() != K::COMMAND_OPTION)?;
            for key in dissect_keys(&string_value(text_of(pattern, source))?)? {
                define(&mut cols, key);
            }
            Some(Some(cols))
        }
        K::GROK_COMMAND => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            let mut names = Vec::new();
            // The input, then the patterns.
            for pattern in nodes(&own).map(|(_, n)| n).skip(1) {
                names.extend(grok_names(&string_value(text_of(pattern, source))?)?);
            }
            // Elasticsearch adds grok columns sorted by name.
            names.sort();
            names.dedup();
            for name in names {
                define(&mut cols, name);
            }
            Some(Some(cols))
        }
        K::ENRICH_COMMAND => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            // The clauses follow `WITH`; the parser reads the policy before
            // it (`processing.rs`, `enrich`).
            let clauses: Vec<&SyntaxNode> = first_token(&own, &[K::WITH_KW])
                .map(|with| nodes_after(&own, with).collect())
                .unwrap_or_default();
            if clauses.is_empty() {
                return Some(None);
            }
            for clause in clauses {
                // `new = field`, or `field`: the first name either way.
                if clause.kind() != K::ENRICH_WITH_CLAUSE {
                    return None;
                }
                let target = nodes(&parts(clause)).map(|(_, n)| n.clone()).next()?;
                define(&mut cols, Pattern::of(&target, source)?.literal()?);
            }
            Some(Some(cols))
        }
        K::CHANGE_POINT_COMMAND => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            // The two names after `AS`: the type's, the p-value's. The parser
            // reads `BY` after them (`processing.rs`, `change_point`).
            let mut names = first_token(&own, &[K::AS_KW])
                .map(|at| nodes_after(&own, at))
                .into_iter()
                .flatten();
            let type_name = match names.next() {
                Some(n) => qualified_of(n, source)?,
                None => "type".to_string(),
            };
            let pvalue = match names.next() {
                Some(n) => qualified_of(n, source)?,
                None => "pvalue".to_string(),
            };
            define(&mut cols, type_name);
            define(&mut cols, pvalue);
            Some(Some(cols))
        }
        K::COMPLETION_COMMAND | K::RERANK_COMMAND => {
            let Some(mut cols) = columns else {
                return Some(None);
            };
            // The target: a name before `=`.
            let eq = first_token(&own, &[K::EQ]);
            let target = nodes_before(&own, eq.or(Some(0))).find(|n| n.kind() != K::MAP_EXPRESSION);
            let name = match target {
                Some(n) => qualified_of(n, source)?,
                None if command.kind() == K::COMPLETION_COMMAND => "completion".to_string(),
                None => "_score".to_string(),
            };
            define(&mut cols, name);
            Some(Some(cols))
        }
        K::JOIN_COMMAND
        | K::FORK_COMMAND
        | K::FUSE_COMMAND
        | K::URI_PARTS_COMMAND
        | K::REGISTERED_DOMAIN_COMMAND
        | K::USER_AGENT_COMMAND
        | K::IP_LOCATION_COMMAND
        | K::METRICS_INFO_COMMAND
        | K::TS_INFO_COMMAND
        | K::TS_COLLAPSE_COMMAND
        | K::MMR_COMMAND
        | K::HIGHLIGHT_COMMAND
        | K::DENSE_VECTOR_COMMAND => Some(None),
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
fn field_name(field: &SyntaxNode, source: &str, by_text: bool) -> Option<String> {
    let Assignment { name, value, .. } = assignment(field);
    if let Some(name) = name {
        return qualified_of(&name, source);
    }
    let value = value?;
    if value.kind() == K::QUALIFIED_NAME {
        let name = qualified_of(&value, source)?;
        // `EVAL x` names the column by its text; `` `x` `` would keep the backticks.
        if by_text || text_of(&value, source) == name {
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
fn verbatim(node: &SyntaxNode, source: &str) -> Option<String> {
    let t = text_of(node, source).trim();
    (!t.contains("/*") && !t.contains("//") && !t.is_empty()).then(|| t.to_string())
}

/// The parts of a name (`a.b`, `a*.b`): its nodes and comments (a one-token
/// node, `Identifier`, has neither).
fn name_parts(node: &SyntaxNode) -> Vec<SyntaxElement> {
    node.children_with_tokens()
        .filter(|c| c.as_node().is_some() || c.kind() == K::COMMENT)
        .collect()
}

/// A dotted name with backquoted parts unquoted. `None` for parameters.
pub(crate) fn qualified_of(node: &SyntaxNode, source: &str) -> Option<String> {
    let mut out = Vec::new();
    for part in name_parts(node) {
        let NodeOrToken::Node(part) = part else {
            return None;
        };
        match part.kind() {
            K::IDENTIFIER | K::ID_PATTERN | K::JOIN_QUALIFIER => {
                out.push(text_of(&part, source).to_string());
            }
            K::QUOTED_IDENTIFIER => out.push(unquote(text_of(&part, source))),
            _ => return None,
        }
    }
    (!out.is_empty()).then(|| out.join("."))
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
    fn of(node: &SyntaxNode, source: &str) -> Option<Self> {
        let mut pieces = Vec::new();
        let mut first = true;
        for part in name_parts(node) {
            if !first {
                pieces.push(Piece::Text(".".into()));
            }
            first = false;
            let NodeOrToken::Node(part) = part else {
                return None;
            };
            match part.kind() {
                K::ID_PATTERN | K::IDENTIFIER | K::JOIN_QUALIFIER => {
                    let t = text_of(&part, source);
                    for (i, chunk) in t.split('*').enumerate() {
                        if i > 0 {
                            pieces.push(Piece::Star);
                        }
                        if !chunk.is_empty() {
                            pieces.push(Piece::Text(chunk.to_string()));
                        }
                    }
                }
                K::QUOTED_IDENTIFIER => pieces.push(Piece::Text(unquote(text_of(&part, source)))),
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
                    (0..=s.len()).any(|i| s.get(i..).is_some_and(|tail| go(rest, tail)))
                }
            }
        }
        go(&self.pieces, name)
    }
}

fn name_patterns(parts: &[SyntaxElement], source: &str) -> Option<Vec<Pattern>> {
    child_of(parts, K::NAME_PATTERN)
        .into_iter()
        .map(|c| Pattern::of(c, source))
        .collect()
}

/// `KEEP`: each column goes to the highest-ranked pattern that matches it
/// (rightmost on a tie) and the output follows the pattern order.
fn keep(parts: &[SyntaxElement], source: &str, input: Option<&[String]>) -> Option<Columns> {
    let patterns = name_patterns(parts, source)?;
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
    while let Some((_, after)) = rest.split_once("%{") {
        let (raw, next) = after.split_once('}')?;
        rest = next;
        let raw = raw.strip_suffix("->").unwrap_or(raw);
        let mut chars = raw.chars();
        let (modifier, name) = match chars.next() {
            Some(c @ ('+' | '?' | '*' | '&')) => (Some(c), chars.as_str()),
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
    while let Some((_, after)) = rest.split_once("%{") {
        let (inner, next) = after.split_once('}')?;
        rest = next;
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
    while let Some((_, after)) = rest.split_once("(?<") {
        rest = after;
        if after.starts_with(['=', '!']) {
            continue;
        }
        let (name, _) = after.split_once('>')?;
        names.push(name.to_string());
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

    /// A query cut short at its end does not parse: Elasticsearch rejects
    /// it, so it has no known columns, and no indices either (#1498).
    #[test]
    fn a_query_cut_short_has_no_columns() {
        for query in [
            "ROW a = 1 | EVAL b =",
            "ROW a = 1 | STATS c =",
            "ROW a = 1 | ENRICH p ON a WITH x =",
        ] {
            assert_eq!(cols(query), None, "{query}");
        }
        assert_eq!(cols("ROW a = 1 | EVAL b = 2"), v(&["a", "b"]));
        assert_eq!(crate::source_indices("FROM a | EVAL c ="), None);
        assert_eq!(
            crate::source_indices("FROM a | EVAL c = 1"),
            Some(vec!["a".to_string()])
        );
        // Nor ECS findings.
        let ecs = "FROM logs-endpoint.events.process-* | WHERE process.nmae == \"x\" | EVAL b =";
        assert!(crate::ecs_diagnostics(ecs).is_empty());
        assert!(!crate::ecs_diagnostics(&format!("{ecs} 1")).is_empty());
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
        // A named group would add a column under its new name.
        assert_eq!(cols("ROW a = 1 | INLINE STATS c = COUNT(*) BY g = a"), None);
        // A comment inside a name: its parts are not one name.
        assert_eq!(cols("ROW a = 1 | EVAL b /* c */ .d = 1"), None);
        assert_eq!(cols("ROW a = 1 | EVAL b.d = 1"), v(&["a", "b.d"]));
        // A quoted name is unquoted; `EVAL x` by its quoted text is no name.
        assert_eq!(cols("ROW a = 1 | EVAL `x y` = 1"), v(&["a", "x y"]));
        assert_eq!(cols("ROW a = 1, `b` = 2 | EVAL `b`"), None);
        // A `STATS … BY` group is named by its unquoted name.
        assert_eq!(cols("TS m | STATS BY `x``y`"), v(&["x`y"]));
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

    #[test]
    fn patterns_read_multi_byte_text() {
        assert_eq!(
            dissect_keys("é%{+é😀} %{?😀} %{é->}😀%{+😀/2}"),
            Some(vec!["é😀".to_owned(), "é".to_owned(), "😀".to_owned()])
        );
        assert_eq!(dissect_keys("%{é"), None);
        assert_eq!(
            grok_names("é%{WORD:é😀} (?<😀>é) (?=é) %{IP:😀:int}"),
            Some(vec!["é😀".to_owned(), "😀".to_owned(), "😀".to_owned()])
        );
        assert_eq!(grok_names("%{é"), None);
        assert_eq!(grok_names("(?<é"), None);
    }
}
