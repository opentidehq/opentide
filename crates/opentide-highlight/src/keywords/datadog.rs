//! The Datadog search syntax (rfc-datadog-cloud-siem, §6.8): `TO` in a range, `CIDR`, the field
//! separator, the comparisons, the exclusion, the wildcards, the brackets and the comma of
//! `CIDR(…)`. `AND`, `OR` and `NOT` are not listed, for kuery's and Lucene's reason: the
//! TextMate grammar's `tm_extras:logical` rule scopes them as logical operators, in upper case
//! only.

use super::{Capture, Keywords};

pub(super) const KEYWORDS: Option<Keywords> = Some(&[
    ("TO", Capture::KEYWORD),
    ("CIDR", Capture::FUNCTION_BUILTIN),
    (":", Capture::OPERATOR),
    (">", Capture::OPERATOR),
    (">=", Capture::OPERATOR),
    ("<", Capture::OPERATOR),
    ("<=", Capture::OPERATOR),
    ("-", Capture::OPERATOR),
    ("*", Capture::OPERATOR),
    ("?", Capture::OPERATOR),
    ("(", Capture::BRACKET),
    (")", Capture::BRACKET),
    ("[", Capture::BRACKET),
    ("]", Capture::BRACKET),
    ("{", Capture::BRACKET),
    ("}", Capture::BRACKET),
    (",", Capture::DELIMITER),
]);
