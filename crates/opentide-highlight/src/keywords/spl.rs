//! Splunk SPL: every keyword and punctuation token `highlights.scm` names,
//! each with its capture (#1229). Keywords are read out of words by
//! position in the parser, so a command name such as `search` is a keyword
//! only where the grammar puts it; the TextMate grammar lists them as the
//! `.scm` always did. A test holds the table equal to the `.scm` until the
//! `.scm` goes.

use super::{Capture, Keywords};

pub(super) const KEYWORDS: Option<Keywords> = Some(&[
    ("search", Capture::KEYWORD),
    ("where", Capture::KEYWORD),
    ("eval", Capture::KEYWORD),
    ("stats", Capture::KEYWORD),
    ("rex", Capture::KEYWORD),
    ("table", Capture::KEYWORD),
    ("rename", Capture::KEYWORD),
    ("fields", Capture::KEYWORD),
    ("dedup", Capture::KEYWORD),
    ("sort", Capture::KEYWORD),
    ("head", Capture::KEYWORD),
    ("tail", Capture::KEYWORD),
    ("join", Capture::KEYWORD),
    ("lookup", Capture::KEYWORD),
    ("makemv", Capture::KEYWORD),
    ("mvexpand", Capture::KEYWORD),
    ("tstats", Capture::KEYWORD),
    ("summariesonly", Capture::KEYWORD),
    ("prestats", Capture::KEYWORD),
    ("datamodel", Capture::KEYWORD),
    ("TERM", Capture::FUNCTION_BUILTIN),
    ("CASE", Capture::FUNCTION_BUILTIN),
    ("PREFIX", Capture::FUNCTION_BUILTIN),
    ("IN", Capture::OPERATOR),
    ("|", Capture::PIPE),
    ("AND", Capture::OPERATOR),
    ("OR", Capture::OPERATOR),
    ("NOT", Capture::OPERATOR),
    ("and", Capture::OPERATOR),
    ("or", Capture::OPERATOR),
    ("not", Capture::OPERATOR),
    ("as", Capture::KEYWORD),
    ("by", Capture::KEYWORD),
    ("over", Capture::KEYWORD),
    ("output", Capture::KEYWORD),
    ("outputnew", Capture::KEYWORD),
    ("desc", Capture::KEYWORD),
    ("in", Capture::KEYWORD),
    ("notin", Capture::KEYWORD),
    ("d", Capture::KEYWORD),
    ("from", Capture::KEYWORD),
    ("sortby", Capture::KEYWORD),
    ("keepevents", Capture::KEYWORD),
    ("keepempty", Capture::KEYWORD),
    ("consecutive", Capture::KEYWORD),
    ("<", Capture::OPERATOR),
    (">", Capture::OPERATOR),
    ("<=", Capture::OPERATOR),
    (">=", Capture::OPERATOR),
    ("allow_old_summaries", Capture::KEYWORD),
    ("fillnull_value", Capture::KEYWORD),
    ("(", Capture::BRACKET),
    (")", Capture::BRACKET),
    ("[", Capture::BRACKET),
    ("]", Capture::BRACKET),
    (",", Capture::DELIMITER),
    ("=", Capture::OPERATOR),
    ("==", Capture::OPERATOR),
    ("!=", Capture::OPERATOR),
    ("LIKE", Capture::OPERATOR),
    ("like", Capture::OPERATOR),
    ("timechart", Capture::KEYWORD),
    ("chart", Capture::KEYWORD),
    ("eventstats", Capture::KEYWORD),
    ("streamstats", Capture::KEYWORD),
    ("transaction", Capture::KEYWORD),
    ("spath", Capture::KEYWORD),
    ("regex", Capture::KEYWORD),
    ("fillnull", Capture::KEYWORD),
    ("bin", Capture::KEYWORD),
    ("append", Capture::KEYWORD),
    ("inputlookup", Capture::KEYWORD),
    ("makeresults", Capture::KEYWORD),
    ("outputlookup", Capture::KEYWORD),
    ("foreach", Capture::KEYWORD),
    ("top", Capture::KEYWORD),
    ("rare", Capture::KEYWORD),
    ("extract", Capture::KEYWORD),
    ("convert", Capture::KEYWORD),
    ("strcat", Capture::KEYWORD),
    ("metadata", Capture::KEYWORD),
    ("rest", Capture::KEYWORD),
    ("union", Capture::KEYWORD),
    ("map", Capture::KEYWORD),
    ("reverse", Capture::KEYWORD),
    ("tojson", Capture::KEYWORD),
    ("sistats", Capture::KEYWORD),
    ("sichart", Capture::KEYWORD),
    ("sitimechart", Capture::KEYWORD),
    ("geostats", Capture::KEYWORD),
]);

#[cfg(test)]
mod tests {
    use super::KEYWORDS;
    use crate::keywords::{scm_pairs, table_pairs};
    use opentide_core::LanguageId;
    use std::collections::BTreeSet;

    #[test]
    fn the_table_spells_out_highlights_scm() {
        let table = table_pairs(KEYWORDS.unwrap_or_default());
        let rows = table.len();
        let table: BTreeSet<_> = table.into_iter().collect();
        let scm: BTreeSet<_> = scm_pairs(crate::highlights_scm(LanguageId::Spl))
            .into_iter()
            .collect();
        assert_eq!(table, scm);
        assert_eq!(table.len(), rows, "no row twice");
    }
}
