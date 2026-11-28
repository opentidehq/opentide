//! Lucene query syntax: `TO` in a range, the field separator and the
//! brackets. `AND`, `OR` and `NOT` are not listed, for kuery's reason.

use super::{Capture, Keywords};

pub(super) const KEYWORDS: Option<Keywords> = Some(&[
    ("TO", Capture::KEYWORD),
    (":", Capture::OPERATOR),
    ("(", Capture::BRACKET),
    (")", Capture::BRACKET),
    ("[", Capture::BRACKET),
    ("]", Capture::BRACKET),
    ("{", Capture::BRACKET),
    ("}", Capture::BRACKET),
]);
