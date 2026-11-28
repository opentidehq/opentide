//! Exabeam Search: exactly the quoted tokens of the `.scm` the TextMate
//! generator scraped before. The keywords match in any case; the TextMate
//! grammar lists their upper-case spelling, as it always did.

use super::{Capture, Keywords};

pub(super) const KEYWORDS: Option<Keywords> = Some(&[
    ("AND", Capture::KEYWORD),
    ("OR", Capture::KEYWORD),
    ("NOT", Capture::KEYWORD),
    ("TO", Capture::KEYWORD),
    ("IN", Capture::KEYWORD),
    ("SELECT", Capture::KEYWORD),
    ("DISTINCT", Capture::KEYWORD),
    ("FROM", Capture::KEYWORD),
    ("WHERE", Capture::KEYWORD),
    ("AS", Capture::KEYWORD),
    ("GROUP-BY", Capture::KEYWORD),
    ("ORDER-BY", Capture::KEYWORD),
    ("ASC", Capture::KEYWORD),
    ("DESC", Capture::KEYWORD),
    ("LIMIT", Capture::KEYWORD),
    ("FOREACH", Capture::KEYWORD),
    (":", Capture::OPERATOR),
    ("=", Capture::OPERATOR),
    ("==", Capture::OPERATOR),
    ("<", Capture::OPERATOR),
    (">", Capture::OPERATOR),
    ("<=", Capture::OPERATOR),
    (">=", Capture::OPERATOR),
    ("|", Capture::PIPE),
    ("(", Capture::BRACKET),
    (")", Capture::BRACKET),
    ("[", Capture::BRACKET),
    ("]", Capture::BRACKET),
    ("{", Capture::BRACKET),
    ("}", Capture::BRACKET),
    (",", Capture::DELIMITER),
    (".", Capture::DELIMITER),
]);
