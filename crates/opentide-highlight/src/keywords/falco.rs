//! Falco conditions: exactly the quoted tokens of the `.scm` the TextMate
//! generator scraped before. Operators and transformer names are words the
//! parser classifies by context, so they were never in it.

use super::{Capture, Keywords};

pub(super) const KEYWORDS: Option<Keywords> = Some(&[
    ("and", Capture::KEYWORD),
    ("or", Capture::KEYWORD),
    ("not", Capture::KEYWORD),
    ("(", Capture::BRACKET),
    (")", Capture::BRACKET),
    ("[", Capture::BRACKET),
    ("]", Capture::BRACKET),
    (",", Capture::DELIMITER),
]);
