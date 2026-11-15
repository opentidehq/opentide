//! The `KEYWORDS` table of KQL: each keyword and punctuation with the
//! `HighlightSpec` capture that colours it (epic #1219). The TextMate,
//! Monaco and Helix generators read it instead of scraping `highlights.scm`
//! once the table interface of `opentide-highlight` lands; until then the
//! `.scm` stays the source and a test holds the table to it.

/// `(token, capture name)`: the capture names are a frozen contract
/// (`highlights/spec.toml`).
#[rustfmt::skip]
pub(crate) const KEYWORDS: &[(&str, &str)] = &[
    // @keyword
    ("let", "keyword"), ("where", "keyword"), ("filter", "keyword"), ("project", "keyword"),
    ("project-away", "keyword"), ("project-rename", "keyword"), ("project-keep", "keyword"),
    ("project-reorder", "keyword"), ("extend", "keyword"), ("summarize", "keyword"),
    ("join", "keyword"), ("union", "keyword"), ("parse", "keyword"), ("parse-where", "keyword"),
    ("parse-kv", "keyword"), ("lookup", "keyword"), ("take", "keyword"), ("limit", "keyword"),
    ("sort", "keyword"), ("order", "keyword"), ("distinct", "keyword"), ("render", "keyword"),
    ("print", "keyword"), ("top", "keyword"), ("mv-expand", "keyword"), ("mvexpand", "keyword"),
    ("search", "keyword"), ("find", "keyword"), ("invoke", "keyword"), ("evaluate", "keyword"),
    ("serialize", "keyword"), ("scan", "keyword"), ("as", "keyword"), ("getschema", "keyword"),
    ("make-series", "keyword"), ("sample", "keyword"), ("sample-distinct", "keyword"),
    ("mv-apply", "keyword"), ("datatable", "keyword"), ("externaldata", "keyword"),
    ("external_data", "keyword"), ("with", "keyword"), ("from", "keyword"), ("to", "keyword"),
    ("step", "keyword"), ("asc", "keyword"), ("desc", "keyword"), ("granny-asc", "keyword"),
    ("granny-desc", "keyword"), ("of", "keyword"), ("others", "keyword"), ("by", "keyword"),
    ("partition", "keyword"), ("declare", "keyword"), ("optional", "keyword"),
    ("output", "keyword"), ("last", "keyword"), ("range", "keyword"), ("fork", "keyword"),
    ("facet", "keyword"), ("consume", "keyword"), ("reduce", "keyword"),
    ("make-graph", "keyword"), ("graph-match", "keyword"), ("graph-shortest-paths", "keyword"),
    ("graph-to-table", "keyword"), ("graph-mark-components", "keyword"),
    ("top-hitters", "keyword"), ("top-nested", "keyword"), ("typeof", "keyword"),
    ("on", "keyword"), ("nulls", "keyword"), ("first", "keyword"), ("default", "keyword"),
    ("and", "keyword"), ("kind", "keyword"),
    // @function.builtin
    ("materialize", "function.builtin"), ("toscalar", "function.builtin"),
    // @type
    ("dynamic", "type"),
    // @error
    (".", "error"),
    // @operator.pipe
    ("|", "operator.pipe"),
    // @operator
    ("or", "operator"), ("not", "operator"), ("==", "operator"), ("!=", "operator"),
    ("=~", "operator"), ("!~", "operator"), ("<>", "operator"), ("<", "operator"),
    (">", "operator"), ("<=", "operator"), (">=", "operator"), ("+", "operator"),
    ("-", "operator"), ("*", "operator"), ("/", "operator"), ("%", "operator"),
    ("has", "operator"), ("!has", "operator"), ("has_cs", "operator"), ("!has_cs", "operator"),
    ("has_any", "operator"), ("has_all", "operator"), ("contains", "operator"),
    ("!contains", "operator"), ("contains_cs", "operator"), ("!contains_cs", "operator"),
    ("containscs", "operator"), ("notcontains", "operator"), ("notcontainscs", "operator"),
    ("=>", "operator"), ("startswith", "operator"), ("!startswith", "operator"),
    ("startswith_cs", "operator"), ("!startswith_cs", "operator"), ("endswith", "operator"),
    ("!endswith", "operator"), ("endswith_cs", "operator"), ("!endswith_cs", "operator"),
    ("hasprefix", "operator"), ("!hasprefix", "operator"), ("hasprefix_cs", "operator"),
    ("!hasprefix_cs", "operator"), ("hassuffix", "operator"), ("!hassuffix", "operator"),
    ("hassuffix_cs", "operator"), ("!hassuffix_cs", "operator"), ("has_ipv4", "operator"),
    ("has_ipv4_prefix", "operator"), ("has_any_ipv4", "operator"),
    ("has_any_ipv4_prefix", "operator"), ("in", "operator"), ("!in", "operator"),
    ("in~", "operator"), ("!in~", "operator"), ("between", "operator"),
    ("!between", "operator"), ("..", "operator"), ("matches", "operator"),
    ("regex", "operator"), ("=", "operator"),
    // @punctuation.bracket
    ("(", "punctuation.bracket"), (")", "punctuation.bracket"), ("[", "punctuation.bracket"),
    ("]", "punctuation.bracket"), ("{", "punctuation.bracket"), ("}", "punctuation.bracket"),
    // @punctuation.delimiter
    (",", "punctuation.delimiter"), (";", "punctuation.delimiter"),
];

#[cfg(test)]
mod tests {
    use super::KEYWORDS;
    use regex::Regex;
    use std::collections::{BTreeMap, BTreeSet};

    type ByCapture = BTreeMap<String, BTreeSet<String>>;

    /// The tokens of each capture, as the generators group them.
    fn grouped<'a>(pairs: impl Iterator<Item = (&'a str, &'a str)>) -> ByCapture {
        let mut out = ByCapture::new();
        for (token, capture) in pairs {
            out.entry(capture.to_owned())
                .or_default()
                .insert(token.to_owned());
        }
        out
    }

    /// The table holds exactly the `"token" @capture` pairs of `highlights.scm`,
    /// so the generators' output stays byte-identical.
    #[test]
    fn the_table_is_what_the_scm_says() {
        let scm = include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/highlights/queries/kql/highlights.scm"
        ));
        let re = Regex::new(r#""([^"\\]+)"\s+@([A-Za-z0-9_.]+)"#).expect("regex");
        let scraped: Vec<(&str, &str)> = re
            .captures_iter(scm)
            .map(|c| {
                (
                    c.get(1).map_or("", |m| m.as_str()),
                    c.get(2).map_or("", |m| m.as_str()),
                )
            })
            .collect();
        assert_eq!(
            grouped(KEYWORDS.iter().copied()),
            grouped(scraped.into_iter())
        );
    }

    #[test]
    fn every_token_of_the_table_is_a_token_of_the_lexer() {
        let known: BTreeSet<&str> = crate::syntax::TEXTS
            .iter()
            .chain(crate::syntax::OPERATOR_WORDS)
            .map(|(text, _)| *text)
            .chain(["==", "!=", "=~", "!~", "<>", "<", ">", "<=", ">="])
            .collect();
        for (token, _) in KEYWORDS {
            assert!(
                known.contains(token),
                "`{token}` is not a token of the lexer"
            );
        }
    }
}
