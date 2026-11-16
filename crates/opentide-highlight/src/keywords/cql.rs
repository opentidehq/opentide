//! CrowdStrike Query Language: the contextual keywords, the operators, the
//! brackets and the delimiters, and the sigils of saved queries and
//! parameters. `/` is both the division and the delimiter of a regex, which
//! is a string. `and`, `or` and `not` are node patterns in the `.scm`, never
//! in the TextMate grammar: the analysis colours them from the tree.

use super::{Capture, Keywords};

pub(super) const KEYWORDS: Option<Keywords> = Some(&[
    ("$", Capture::MACRO),
    ("?", Capture::MACRO),
    ("?{", Capture::MACRO),
    ("/", Capture::STRING),
    ("case", Capture::KEYWORD),
    ("match", Capture::KEYWORD),
    ("like", Capture::KEYWORD),
    ("|", Capture::PIPE),
    ("=", Capture::OPERATOR),
    ("!=", Capture::OPERATOR),
    ("<", Capture::OPERATOR),
    ("<=", Capture::OPERATOR),
    (">", Capture::OPERATOR),
    (">=", Capture::OPERATOR),
    ("==", Capture::OPERATOR),
    ("<=>", Capture::OPERATOR),
    (":=", Capture::OPERATOR),
    ("=~", Capture::OPERATOR),
    ("=>", Capture::OPERATOR),
    ("!", Capture::OPERATOR),
    ("+", Capture::OPERATOR),
    ("-", Capture::OPERATOR),
    ("*", Capture::OPERATOR),
    ("/", Capture::OPERATOR),
    ("%", Capture::OPERATOR),
    ("(", Capture::BRACKET),
    (")", Capture::BRACKET),
    ("[", Capture::BRACKET),
    ("]", Capture::BRACKET),
    ("{", Capture::BRACKET),
    ("}", Capture::BRACKET),
    (",", Capture::DELIMITER),
    (";", Capture::DELIMITER),
    (":", Capture::DELIMITER),
]);
