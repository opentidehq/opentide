//! YARA text, as the HarfangLab compiler (opentide-compile) and the language
//! server's assembled rule (opentide-tide) both write it: one copy, so the
//! payload a deploy sends and the rule the editor checks cannot drift apart.

use std::fmt::Write as _;

/// `text` as the inside of a YARA string literal (a `meta` value):
/// `\` and `"` escaped, `\n` and `\t` as those escapes, and every other ASCII
/// control character as `\xNN`, so no raw control character reaches the
/// rule (#1939). A `\r` is dropped, as `escape_yara_string` dropped it, so a
/// rule writes the payload it wrote before (a deployed rule is unchanged).
/// Characters outside ASCII are kept as they are (YARA reads UTF-8).
#[must_use]
pub fn escape_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => {}
            c if c.is_ascii_control() => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_backslashes_and_control_characters() {
        assert_eq!(escape_string("a\"b\\c\nd\r"), "a\\\"b\\\\c\\nd");
        assert_eq!(escape_string("a\tb"), "a\\tb");
        assert_eq!(escape_string("\0\u{1}\u{1b}\u{7f}"), "\\x00\\x01\\x1b\\x7f");
        assert_eq!(escape_string("crlf\r\nline"), "crlf\\nline");
        assert_eq!(escape_string("é 😀 \u{85}"), "é 😀 \u{85}");
    }
}
