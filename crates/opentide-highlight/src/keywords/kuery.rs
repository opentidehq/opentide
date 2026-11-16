//! Kibana KQL (`kuery`): the operators and brackets its lexer cuts as
//! tokens. `or`, `and` and `not` are keywords only by position (a trailing
//! one is a value, which the parser decides), so the TextMate grammar does
//! not list them, as it never did; the analysis colours them from the tree.

use super::{Capture, Keywords};

pub(super) const KEYWORDS: Option<Keywords> = Some(&[
    (":", Capture::OPERATOR),
    ("<", Capture::OPERATOR),
    ("<=", Capture::OPERATOR),
    (">", Capture::OPERATOR),
    (">=", Capture::OPERATOR),
    ("(", Capture::BRACKET),
    (")", Capture::BRACKET),
    ("{", Capture::BRACKET),
    ("}", Capture::BRACKET),
]);
