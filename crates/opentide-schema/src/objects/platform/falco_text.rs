//! The text side of a Sysdig block's own macros and lists, as Falco's rule
//! loader treats them (`platforms/sysdig/expansion.py`): Falco's
//! `resolve_list` (textual: a list name between delimiters becomes its
//! items; `opentide_core::falco`'s, shared with the language server), and the
//! bare names in check positions of a condition, the macros it uses. No crate
//! does either: they are Falco's loader rules and the oracle's token scan over
//! them, which `sysdig_definition_order` and `sysdig_list_in_value` are
//! defined by. The condition's grammar is
//! `opentide-falco`'s (the `falco_*` findings); this module needs no parser,
//! so the model builds wherever the crate does (wasm32 included).
//!
//! Text is handled in Unicode code points, as the oracle's Python strings
//! index it.

use opentide_core::falco::{BLANKS, MODIFIERS, OPERATORS};

/// Falco's `resolve_list` and `occurs`: `opentide_core::falco`'s, which the
/// language server's Sysdig findings use too.
pub use opentide_core::falco::{occurs, resolve_list};

fn blank(ch: char) -> bool {
    BLANKS.contains(&ch)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Space,
    Text,
    Open,
    Close,
    Comma,
    Symbol,
    Word,
}

struct Token {
    kind: Kind,
    text: String,
}

/// Operators written as symbols, longest first.
const SYMBOLS: [&str; 7] = ["!=", "<=", ">=", "==", "=", "<", ">"];
/// One of Falco's operators written as a word (`in`, `contains`): the token
/// after one is a value.
fn word_operator(word: &str) -> bool {
    OPERATORS.contains(&word) && word.chars().all(char::is_alphabetic)
}
/// Field transformers, and `val`.
const TRANSFORMERS: [&str; 9] = [
    "tolower", "toupper", "b64", "basename", "len", "join", "concat", "getopt", "val",
];

/// A condition's tokens; together they hold every character of the text.
fn tokenize(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut tokens = Vec::new();
    let mut i = 0;
    let piece = |from: usize, to: usize| chars[from..to].iter().collect::<String>();
    while i < n {
        let ch = chars[i];
        let (kind, end) = if blank(ch) {
            let mut j = i;
            while j < n && blank(chars[j]) {
                j += 1;
            }
            (Kind::Space, j)
        } else if ch == '"' || ch == '\'' {
            let mut j = i + 1;
            while j < n && chars[j] != ch {
                j += if chars[j] == '\\' { 2 } else { 1 };
            }
            (Kind::Text, (j + 1).min(n))
        } else if ch == '(' {
            (Kind::Open, i + 1)
        } else if ch == ')' {
            (Kind::Close, i + 1)
        } else if ch == ',' {
            (Kind::Comma, i + 1)
        } else if let Some(symbol) = SYMBOLS
            .iter()
            .find(|symbol| piece(i, (i + symbol.chars().count()).min(n)) == **symbol)
        {
            (Kind::Symbol, i + symbol.chars().count())
        } else {
            let mut j = i;
            let mut depth = 0usize;
            // A field argument (`proc.aname[2]`, `proc.env["HOME"]`) stays in
            // its word.
            while j < n {
                let c = chars[j];
                if c == '[' {
                    depth += 1;
                } else if c == ']' && depth > 0 {
                    depth -= 1;
                } else if depth == 0 && (blank(c) || "(),\"'=<>!".contains(c)) {
                    break;
                }
                j += 1;
            }
            (Kind::Word, if j == i { i + 1 } else { j })
        };
        tokens.push(Token {
            kind,
            text: piece(i, end),
        });
        i = end;
    }
    tokens
}

/// The index of the `)` that closes the `(` at `start`, or the last token.
fn closing(tokens: &[Token], start: usize) -> usize {
    let mut depth = 0i64;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token.kind {
            Kind::Open => depth += 1,
            Kind::Close => {
                depth -= 1;
                if depth == 0 {
                    return index;
                }
            }
            _ => {}
        }
    }
    tokens.len().saturating_sub(1)
}

/// The `)` closing a call `word(` at `index`, when it starts one.
fn call_end(tokens: &[Token], index: usize) -> Option<usize> {
    (index + 1 < tokens.len() && tokens[index + 1].kind == Kind::Open)
        .then(|| closing(tokens, index + 1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Check,
    Operator,
    Value,
}

/// The bare identifiers in check positions of `text`: the macros it uses.
/// Values (after an operator: a word, a string, a value list, `val(...)` or
/// a transformer), field names, field arguments, transformer calls on the
/// left-hand side and quoted strings are not names.
pub fn check_position_names(text: &str) -> Vec<String> {
    let tokens = tokenize(text);
    let mut names = Vec::new();
    let mut expect = Expect::Check;
    let mut i = 0;
    while i < tokens.len() {
        let token = &tokens[i];
        if token.kind == Kind::Space {
            i += 1;
            continue;
        }
        if expect == Expect::Value {
            if token.kind == Kind::Word && MODIFIERS.contains(&token.text.as_str()) {
                i += 1;
                continue;
            }
            let end = match token.kind {
                Kind::Open => Some(closing(&tokens, i)),
                Kind::Word => call_end(&tokens, i),
                _ => None,
            };
            i = end.unwrap_or(i) + 1;
            expect = Expect::Check;
            continue;
        }
        if expect == Expect::Operator {
            if token.kind == Kind::Symbol
                || (token.kind == Kind::Word && word_operator(&token.text))
            {
                expect = if token.text == "exists" {
                    Expect::Check
                } else {
                    Expect::Value
                };
                i += 1;
                continue;
            }
            expect = Expect::Check;
        }
        if token.kind == Kind::Word {
            if matches!(token.text.as_str(), "and" | "or" | "not") {
                i += 1;
                continue;
            }
            if TRANSFORMERS.contains(&token.text.as_str())
                && let Some(end) = call_end(&tokens, i)
            {
                i = end + 1;
                expect = Expect::Operator;
                continue;
            }
            if token.text.contains('.') {
                expect = Expect::Operator;
                i += 1;
                continue;
            }
            names.push(token.text.clone());
        }
        i += 1;
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_positions_are_the_macros_a_condition_uses() {
        assert_eq!(
            check_position_names("spawned_process and not proc.name in (a, b) and m2"),
            ["spawned_process", "m2"]
        );
        assert_eq!(
            check_position_names("proc.name = m1 and tolower(proc.name) = x and m3"),
            ["m3"]
        );
        assert_eq!(check_position_names("fd.name exists and m4"), ["m4"]);
        assert_eq!(
            check_position_names("proc.name startswith oneof (a) or m5"),
            ["m5"]
        );
        assert_eq!(check_position_names("m2 and ("), ["m2"]);
        assert_eq!(
            check_position_names("proc.env[\"HOME\"] = \"m6\" and (m7)"),
            ["m7"]
        );
        // A backslash escapes the quote after it: `m9` is inside the string.
        assert_eq!(
            check_position_names("proc.name = \"a\\\" m9\" and m8"),
            ["m8"]
        );
    }
}
