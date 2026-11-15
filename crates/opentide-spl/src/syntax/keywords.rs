//! SPL's `KEYWORDS`: every keyword and punctuation token the highlighter
//! colours, each with its `HighlightSpec` capture. It is what the TextMate,
//! Monaco and Helix generators read once SPL has left tree-sitter, so it
//! spells out the tokens `highlights.scm` names (a test holds them equal
//! until the `.scm` goes). Capture names are frozen
//! (`highlights/spec.toml`).
//!
//! The table moves into `opentide-highlight`'s `keywords` module, typed with
//! its `Capture`, once that interface lands (#1291).

/// `(token, capture name)`.
pub(crate) const KEYWORDS: &[(&str, &str)] = &[
    ("search", "keyword"),
    ("where", "keyword"),
    ("eval", "keyword"),
    ("stats", "keyword"),
    ("rex", "keyword"),
    ("table", "keyword"),
    ("rename", "keyword"),
    ("fields", "keyword"),
    ("dedup", "keyword"),
    ("sort", "keyword"),
    ("head", "keyword"),
    ("tail", "keyword"),
    ("join", "keyword"),
    ("lookup", "keyword"),
    ("makemv", "keyword"),
    ("mvexpand", "keyword"),
    ("tstats", "keyword"),
    ("summariesonly", "keyword"),
    ("prestats", "keyword"),
    ("datamodel", "keyword"),
    ("TERM", "function.builtin"),
    ("CASE", "function.builtin"),
    ("PREFIX", "function.builtin"),
    ("IN", "operator"),
    ("|", "operator.pipe"),
    ("AND", "operator"),
    ("OR", "operator"),
    ("NOT", "operator"),
    ("and", "operator"),
    ("or", "operator"),
    ("not", "operator"),
    ("as", "keyword"),
    ("by", "keyword"),
    ("over", "keyword"),
    ("output", "keyword"),
    ("outputnew", "keyword"),
    ("desc", "keyword"),
    ("in", "keyword"),
    ("notin", "keyword"),
    ("d", "keyword"),
    ("from", "keyword"),
    ("sortby", "keyword"),
    ("keepevents", "keyword"),
    ("keepempty", "keyword"),
    ("consecutive", "keyword"),
    ("<", "operator"),
    (">", "operator"),
    ("<=", "operator"),
    (">=", "operator"),
    ("allow_old_summaries", "keyword"),
    ("fillnull_value", "keyword"),
    ("(", "punctuation.bracket"),
    (")", "punctuation.bracket"),
    ("[", "punctuation.bracket"),
    ("]", "punctuation.bracket"),
    (",", "punctuation.delimiter"),
    ("=", "operator"),
    ("==", "operator"),
    ("!=", "operator"),
    ("LIKE", "operator"),
    ("like", "operator"),
    ("timechart", "keyword"),
    ("chart", "keyword"),
    ("eventstats", "keyword"),
    ("streamstats", "keyword"),
    ("transaction", "keyword"),
    ("spath", "keyword"),
    ("regex", "keyword"),
    ("fillnull", "keyword"),
    ("bin", "keyword"),
    ("append", "keyword"),
    ("inputlookup", "keyword"),
    ("makeresults", "keyword"),
    ("outputlookup", "keyword"),
    ("foreach", "keyword"),
    ("top", "keyword"),
    ("rare", "keyword"),
    ("extract", "keyword"),
    ("convert", "keyword"),
    ("strcat", "keyword"),
    ("metadata", "keyword"),
    ("rest", "keyword"),
    ("union", "keyword"),
    ("map", "keyword"),
    ("reverse", "keyword"),
    ("tojson", "keyword"),
    ("sistats", "keyword"),
    ("sichart", "keyword"),
    ("sitimechart", "keyword"),
    ("geostats", "keyword"),
];

#[cfg(test)]
mod tests {
    use super::KEYWORDS;
    use std::collections::BTreeSet;

    /// The `"token" @capture` pairs of a highlights query.
    fn scm_pairs(scm: &str) -> BTreeSet<(&str, &str)> {
        let parts: Vec<&str> = scm.split('"').collect();
        let mut pairs = BTreeSet::new();
        for i in (1..parts.len().saturating_sub(1)).step_by(2) {
            let (token, after) = (parts[i], parts[i + 1]);
            let Some(capture) = after
                .strip_prefix(|c: char| c.is_whitespace() && c != '\n')
                .map(|s| s.trim_start_matches(|c: char| c.is_whitespace() && c != '\n'))
                .and_then(|s| s.strip_prefix('@'))
            else {
                continue;
            };
            let end = capture
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .unwrap_or(capture.len());
            if !token.is_empty() && !token.contains('\\') {
                pairs.insert((token, &capture[..end]));
            }
        }
        pairs
    }

    #[test]
    fn the_table_spells_out_highlights_scm() {
        let from_scm = scm_pairs(opentide_highlight::SPL_HIGHLIGHTS_SCM);
        let table: BTreeSet<_> = KEYWORDS.iter().copied().collect();
        assert_eq!(table, from_scm);
        assert_eq!(table.len(), KEYWORDS.len(), "no row twice");
    }

    #[test]
    fn the_table_names_spec_captures() {
        let spec = opentide_highlight::HighlightSpec::load().expect("spec");
        for (token, capture) in KEYWORDS {
            assert!(
                spec.contains_capture(capture),
                "`{token}` names {capture}, which highlights/spec.toml does not have"
            );
        }
    }
}
