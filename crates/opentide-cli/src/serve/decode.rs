//! One line of the protocol as JSON, and the parse error it is answered with.
//!
//! `-32700`'s message is part of what a client reads (`docs/cli/serve.md`):
//! the Python host answered with `json.loads`'s own error, `Expecting value:
//! line 1 column 1 (char 0)`, and the recorded sessions hold it. serde_json
//! words and places its errors differently, so the syntax is checked first
//! by the scan below, which finds the first error where CPython's scanner
//! (3.13, the oracle's) finds it and names it as it does; the value itself
//! is then read by serde_json. Positions count characters, not bytes.

use crate::json::Json;

/// Deeper than this, the scan stops looking and serde_json's own limit
/// answers: the scan must not run out of stack on hostile input.
const MAX_DEPTH: usize = 512;

/// `text` (one line, already decoded) as JSON, or the message of
/// `-32700` without its `Parse error: ` prefix.
pub fn parse(text: &str) -> Result<Json, String> {
    let chars: Vec<char> = text.chars().collect();
    if let Err((message, position)) = check(&chars) {
        return Err(located(&chars, message, position));
    }
    Json::parse(text).map_err(|error| error.to_string())
}

/// `message: line L column C (char N)`, as `json.JSONDecodeError` prints it.
fn located(chars: &[char], message: &str, position: usize) -> String {
    let before = &chars[..position.min(chars.len())];
    let line = before.iter().filter(|c| **c == '\n').count() + 1;
    let column = match before.iter().rposition(|c| *c == '\n') {
        Some(newline) => position - newline,
        None => position + 1,
    };
    format!("{message}: line {line} column {column} (char {position})")
}

type Scan = Result<usize, (&'static str, usize)>;

/// The first syntax error in `chars`, as `json.loads` reports it.
fn check(chars: &[char]) -> Result<(), (&'static str, usize)> {
    if chars.first() == Some(&'\u{feff}') {
        return Err(("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0));
    }
    let scanner = Scanner { s: chars };
    let start = scanner.whitespace(0);
    let end = scanner.value(start, 0)?;
    let end = scanner.whitespace(end);
    if end == usize::MAX || end == chars.len() {
        Ok(())
    } else {
        Err(("Extra data", end))
    }
}

struct Scanner<'a> {
    s: &'a [char],
}

impl Scanner<'_> {
    fn at(&self, index: usize) -> Option<char> {
        self.s.get(index).copied()
    }

    fn whitespace(&self, mut index: usize) -> usize {
        if index == usize::MAX {
            return index;
        }
        while matches!(self.at(index), Some(' ' | '\t' | '\n' | '\r')) {
            index += 1;
        }
        index
    }

    fn literal(&self, index: usize, word: &str) -> bool {
        word.chars()
            .enumerate()
            .all(|(offset, c)| self.at(index + offset) == Some(c))
    }

    /// One value from `index`; where it ends. `usize::MAX`: too deep to
    /// follow, left to serde_json.
    fn value(&self, index: usize, depth: usize) -> Scan {
        if depth > MAX_DEPTH {
            return Ok(usize::MAX);
        }
        match self.at(index) {
            None => Err(("Expecting value", index)),
            Some('"') => self.string(index + 1),
            Some('{') => self.object(index + 1, depth + 1),
            Some('[') => self.array(index + 1, depth + 1),
            Some('n') if self.literal(index, "null") => Ok(index + 4),
            Some('t') if self.literal(index, "true") => Ok(index + 4),
            Some('f') if self.literal(index, "false") => Ok(index + 5),
            Some('N') if self.literal(index, "NaN") => Ok(index + 3),
            Some('I') if self.literal(index, "Infinity") => Ok(index + 8),
            Some('-') if self.literal(index, "-Infinity") => Ok(index + 9),
            Some(_) => self.number(index),
        }
    }

    fn digits(&self, mut index: usize) -> usize {
        while self.at(index).is_some_and(|c| c.is_ascii_digit()) {
            index += 1;
        }
        index
    }

    fn number(&self, start: usize) -> Scan {
        let mut index = start;
        if self.at(index) == Some('-') {
            index += 1;
        }
        match self.at(index) {
            Some('0') => index += 1,
            Some('1'..='9') => index = self.digits(index + 1),
            _ => return Err(("Expecting value", start)),
        }
        if self.at(index) == Some('.') && self.at(index + 1).is_some_and(|c| c.is_ascii_digit()) {
            index = self.digits(index + 1);
        }
        if matches!(self.at(index), Some('e' | 'E')) {
            let mut exponent = index + 1;
            if matches!(self.at(exponent), Some('+' | '-')) {
                exponent += 1;
            }
            let end = self.digits(exponent);
            if end > exponent {
                index = end;
            }
        }
        Ok(index)
    }

    fn hex4(&self, from: usize) -> Option<u32> {
        let mut value = 0;
        for offset in 0..4 {
            value = value * 16 + self.at(from + offset)?.to_digit(16)?;
        }
        Some(value)
    }

    /// A string whose opening quote is just before `start`.
    fn string(&self, start: usize) -> Scan {
        let begin = start - 1;
        let len = self.s.len();
        let mut index = start;
        loop {
            let mut next = index;
            while let Some(c) = self.at(next) {
                if c == '"' || c == '\\' {
                    break;
                }
                if u32::from(c) <= 0x1f {
                    return Err(("Invalid control character at", next));
                }
                next += 1;
            }
            match self.at(next) {
                None => return Err(("Unterminated string starting at", begin)),
                Some('"') => return Ok(next + 1),
                Some(_) => {}
            }
            // A backslash.
            next += 1;
            let Some(escaped) = self.at(next) else {
                return Err(("Unterminated string starting at", begin));
            };
            if escaped != 'u' {
                if !matches!(escaped, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') {
                    return Err(("Invalid \\escape", next - 1));
                }
                index = next + 1;
                continue;
            }
            next += 1;
            let mut end = next + 4;
            if end >= len {
                return Err(("Invalid \\uXXXX escape", next - 1));
            }
            let Some(unit) = self.hex4(next) else {
                return Err(("Invalid \\uXXXX escape", end - 5));
            };
            if (0xd800..0xdc00).contains(&unit)
                && end + 6 < len
                && self.at(end) == Some('\\')
                && self.at(end + 1) == Some('u')
            {
                let low = end + 2;
                end += 6;
                if self.hex4(low).is_none() {
                    return Err(("Invalid \\uXXXX escape", end - 5));
                }
            }
            index = end;
        }
    }

    fn object(&self, start: usize, depth: usize) -> Scan {
        let mut index = self.whitespace(start);
        if self.at(index) == Some('}') {
            return Ok(index + 1);
        }
        loop {
            if self.at(index) != Some('"') {
                return Err(("Expecting property name enclosed in double quotes", index));
            }
            index = self.whitespace(self.string(index + 1)?);
            if self.at(index) != Some(':') {
                return Err(("Expecting ':' delimiter", index));
            }
            index = self.value(self.whitespace(index + 1), depth)?;
            if index == usize::MAX {
                return Ok(index);
            }
            index = self.whitespace(index);
            match self.at(index) {
                Some('}') => return Ok(index + 1),
                Some(',') => {}
                _ => return Err(("Expecting ',' delimiter", index)),
            }
            let comma = index;
            index = self.whitespace(index + 1);
            if self.at(index) == Some('}') {
                return Err(("Illegal trailing comma before end of object", comma));
            }
        }
    }

    fn array(&self, start: usize, depth: usize) -> Scan {
        let mut index = self.whitespace(start);
        if self.at(index) == Some(']') {
            return Ok(index + 1);
        }
        loop {
            index = self.value(index, depth)?;
            if index == usize::MAX {
                return Ok(index);
            }
            index = self.whitespace(index);
            match self.at(index) {
                Some(']') => return Ok(index + 1),
                Some(',') => {}
                _ => return Err(("Expecting ',' delimiter", index)),
            }
            let comma = index;
            index = self.whitespace(index + 1);
            if self.at(index) == Some(']') {
                return Err(("Illegal trailing comma before end of array", comma));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(text: &str) -> String {
        parse(text).err().unwrap_or_default()
    }

    /// Each message as CPython 3.13's `json.loads` words and places it.
    #[test]
    fn errors_read_as_pythons() {
        let cases = [
            ("not json", "Expecting value: line 1 column 1 (char 0)"),
            ("", "Expecting value: line 1 column 1 (char 0)"),
            (
                "{not json",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            (
                "{\"a\" 1}",
                "Expecting ':' delimiter: line 1 column 6 (char 5)",
            ),
            (
                "{\"a\": 1 \"b\"}",
                "Expecting ',' delimiter: line 1 column 9 (char 8)",
            ),
            ("{\"a\": }", "Expecting value: line 1 column 7 (char 6)"),
            (
                "{\"a\": 1,}",
                "Illegal trailing comma before end of object: line 1 column 8 (char 7)",
            ),
            (
                "[1,]",
                "Illegal trailing comma before end of array: line 1 column 3 (char 2)",
            ),
            ("[1 2]", "Expecting ',' delimiter: line 1 column 4 (char 3)"),
            ("[", "Expecting value: line 1 column 2 (char 1)"),
            ("{} x", "Extra data: line 1 column 4 (char 3)"),
            (
                "\"abc",
                "Unterminated string starting at: line 1 column 1 (char 0)",
            ),
            (
                "\"a\u{1}\"",
                "Invalid control character at: line 1 column 3 (char 2)",
            ),
            ("\"\\q\"", "Invalid \\escape: line 1 column 2 (char 1)"),
            (
                "\"\\u12\"",
                "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
            ),
            (
                "\"\\u12zz\"",
                "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
            ),
            (
                "\u{feff}{}",
                "Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)",
            ),
            ("1.", "Extra data: line 1 column 2 (char 1)"),
            ("-", "Expecting value: line 1 column 1 (char 0)"),
            ("é x", "Expecting value: line 1 column 1 (char 0)"),
            ("[\"é\", x]", "Expecting value: line 1 column 7 (char 6)"),
            (
                "\"\\ud800\\uzzzz\"",
                "Invalid \\uXXXX escape: line 1 column 9 (char 8)",
            ),
            (
                "{\n\"a\" 1}",
                "Expecting ':' delimiter: line 2 column 5 (char 6)",
            ),
        ];
        for (text, message) in cases {
            assert_eq!(error(text), message, "{text:?}");
        }
    }

    #[test]
    fn valid_lines_are_read() {
        for text in [
            "{}",
            " {\"a\": [1, 2.5e3, -0, true, false, null, \"\\u00e9\\n\"]} ",
            "\"\\ud83d\\ude00\"",
            "1e5",
        ] {
            assert!(parse(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_crash() {
        let text = "[".repeat(100_000);
        assert!(parse(&text).is_err());
        let text = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(parse(&text).is_err());
    }
}
