//! A case's condition (RFC `rfc-datadog-cloud-siem.md` §5.8): comparisons of
//! query names with numbers, joined by `&&` and `||`.
//!
//! ```text
//! condition  = or_expr
//! or_expr    = and_expr ( "||" and_expr )*
//! and_expr   = comparison ( "&&" comparison )*
//! comparison = query_name ( ">" | ">=" | "<" | "<=" ) number
//! query_name = [a-z][a-z0-9_]*
//! number     = [0-9]+ ( "." [0-9]+ )?
//! ```
//!
//! The grammar has no parentheses and no unary operator, so the parser is a
//! flat scan: it never recurses, whatever the condition's length. Which of
//! `&&` and `||` binds tighter is undocumented (open question 3); the tree
//! this module gives is a list of comparisons and the operators between
//! them, and [`Condition::mixed`] says when the two are mixed, which the
//! model reports as a warning (`datadog_condition_mixed`).

use crate::configuration::repr::quote;

/// The comparisons, longest first.
pub const OPERATORS: [&str; 4] = [">=", ">", "<=", "<"];

/// Whether `text` is a query name: `[a-z][a-z0-9_]*`.
pub fn query_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

/// A number as written: `[0-9]+ ( "." [0-9]+ )?`.
fn number(text: &str) -> bool {
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (text, None),
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    digits(whole) && fraction.is_none_or(digits)
}

/// One comparison: `failed > 10`.
#[derive(Debug, Clone, PartialEq)]
pub struct Comparison {
    /// The query name.
    pub query: String,
    /// `>`, `>=`, `<` or `<=`.
    pub op: &'static str,
    /// The number, as written.
    pub number: String,
    /// The number's value.
    pub value: f64,
    /// The byte range of the comparison in the condition.
    pub start: usize,
    /// The byte after the comparison.
    pub end: usize,
}

/// A logical operator between two comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logic {
    /// `&&`.
    And,
    /// `||`.
    Or,
}

/// A parsed condition: its comparisons in order, and the operator after each
/// but the last.
#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    /// The comparisons.
    pub comparisons: Vec<Comparison>,
    /// `operators[i]` joins `comparisons[i]` and `comparisons[i + 1]`.
    pub operators: Vec<Logic>,
}

impl Condition {
    /// Whether the condition uses both `&&` and `||`, whose precedence
    /// Datadog does not document.
    pub fn mixed(&self) -> bool {
        self.operators.contains(&Logic::And) && self.operators.contains(&Logic::Or)
    }
}

/// Why a condition does not parse, and where: a byte range of the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionError {
    /// What is wrong.
    pub message: String,
    /// The first byte the error is about.
    pub start: usize,
    /// The byte after the last one.
    pub end: usize,
}

impl std::fmt::Display for ConditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConditionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Word,
    Number,
    Compare,
    Logic,
}

#[derive(Debug, Clone, Copy)]
struct Token<'a> {
    text: &'a str,
    kind: Kind,
    start: usize,
}

impl Token<'_> {
    const fn end(&self) -> usize {
        self.start + self.text.len()
    }
}

fn error(message: String, start: usize, end: usize) -> ConditionError {
    ConditionError {
        message,
        start,
        end,
    }
}

fn tokenize(text: &str) -> Result<Vec<Token<'_>>, ConditionError> {
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let Some(ch) = rest.chars().next() else {
            break;
        };
        if ch.is_whitespace() {
            at += ch.len_utf8();
            continue;
        }
        let (len, kind) = if rest.starts_with("&&") || rest.starts_with("||") {
            (2, Kind::Logic)
        } else if rest.starts_with(">=") || rest.starts_with("<=") {
            (2, Kind::Compare)
        } else if matches!(ch, '>' | '<') {
            (1, Kind::Compare)
        } else if ch.is_ascii_digit() {
            let len = rest
                .find(|c: char| !(c.is_ascii_digit() || c == '.'))
                .unwrap_or(rest.len());
            (len, Kind::Number)
        } else if ch.is_ascii_alphanumeric() || ch == '_' {
            let len = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (len, Kind::Word)
        } else {
            let shown: String = rest.chars().take(12).collect();
            let message = match ch {
                '(' | ')' => {
                    "Datadog does not document parentheses in a condition (open question 3)"
                        .to_owned()
                }
                '=' | '!' => format!(
                    "{} is not a comparison a condition takes: >, >=, < or <=",
                    quote(&shown.chars().take(2).collect::<String>())
                ),
                _ => format!("unexpected {}", quote(&shown)),
            };
            return Err(error(message, at, at + ch.len_utf8()));
        };
        tokens.push(Token {
            text: &rest[..len],
            kind,
            start: at,
        });
        at += len;
    }
    Ok(tokens)
}

/// Parses a condition (RFC §5.8). A blank condition, a number before the
/// query name (`3 < a`), a dangling operator and an unknown character are
/// errors that name where they are.
pub fn parse(text: &str) -> Result<Condition, ConditionError> {
    let tokens = tokenize(text)?;
    if tokens.is_empty() {
        return Err(error("the condition is empty".to_owned(), 0, text.len()));
    }
    let mut comparisons = Vec::new();
    let mut operators = Vec::new();
    let mut index = 0;
    loop {
        let Some(name) = tokens.get(index) else {
            let end = text.len();
            return Err(error(
                "the condition ends after an operator: a comparison follows it".to_owned(),
                end,
                end,
            ));
        };
        match name.kind {
            Kind::Word if query_name(name.text) => {}
            Kind::Word => {
                return Err(error(
                    format!("{} is not a query name: [a-z][a-z0-9_]*", quote(name.text)),
                    name.start,
                    name.end(),
                ));
            }
            Kind::Number => {
                return Err(error(
                    "the query name comes first: Datadog allows `a > 3`, not `3 < a`".to_owned(),
                    name.start,
                    name.end(),
                ));
            }
            Kind::Compare | Kind::Logic => {
                return Err(error(
                    format!("{} where a query name belongs", quote(name.text)),
                    name.start,
                    name.end(),
                ));
            }
        }
        let Some(op) = tokens
            .get(index + 1)
            .filter(|token| token.kind == Kind::Compare)
        else {
            let (start, end) = tokens
                .get(index + 1)
                .map_or((name.end(), name.end()), |token| (token.start, token.end()));
            return Err(error(
                format!(
                    "{} is compared with a number: >, >=, < or <=",
                    quote(name.text)
                ),
                start,
                end,
            ));
        };
        let Some(value) = tokens
            .get(index + 2)
            .filter(|token| token.kind == Kind::Number && number(token.text))
        else {
            let (start, end) = tokens
                .get(index + 2)
                .map_or((op.end(), op.end()), |token| (token.start, token.end()));
            return Err(error(
                format!(
                    "{} {} takes a number: digits, with an optional fraction (10, 0.995)",
                    name.text, op.text
                ),
                start,
                end,
            ));
        };
        let op_text = OPERATORS
            .iter()
            .find(|known| **known == op.text)
            .copied()
            .unwrap_or(">");
        comparisons.push(Comparison {
            query: name.text.to_owned(),
            op: op_text,
            number: value.text.to_owned(),
            value: value.text.parse().unwrap_or(f64::NAN),
            start: name.start,
            end: value.end(),
        });
        match tokens.get(index + 3) {
            None => break,
            Some(token) if token.kind == Kind::Logic => {
                operators.push(if token.text == "&&" {
                    Logic::And
                } else {
                    Logic::Or
                });
                index += 4;
            }
            Some(token) => {
                return Err(error(
                    format!(
                        "{} after a comparison: join comparisons with && or ||",
                        quote(token.text)
                    ),
                    token.start,
                    token.end(),
                ));
            }
        }
    }
    Ok(Condition {
        comparisons,
        operators,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_condition_is_comparisons_joined_by_operators() {
        let parsed = parse("failed > 10 && success > 0").unwrap();
        assert_eq!(parsed.comparisons.len(), 2);
        assert_eq!(parsed.comparisons[0].query, "failed");
        assert_eq!(parsed.comparisons[0].op, ">");
        assert_eq!(parsed.comparisons[1].number, "0");
        assert_eq!(parsed.operators, vec![Logic::And]);
        assert!(!parsed.mixed());
        let anomaly = parse("denied>=0.995").unwrap();
        assert!((anomaly.comparisons[0].value - 0.995).abs() < f64::EPSILON);
        assert_eq!(anomaly.comparisons[0].op, ">=");
        assert!(parse("a > 1 || b > 1 && c > 1").unwrap().mixed());
        assert!(!parse("first > 3 || second > 10").unwrap().mixed());
    }

    #[test]
    fn what_a_condition_refuses() {
        for (bad, says) in [
            ("", "empty"),
            ("   ", "empty"),
            ("3 < a", "comes first"),
            ("a > ", "takes a number"),
            ("a > b", "takes a number"),
            ("a > 1.", "takes a number"),
            ("a > 1 &&", "ends after an operator"),
            ("a", "compared with a number"),
            ("a == 1", "not a comparison"),
            ("!a", "not a comparison"),
            ("(a > 1)", "parentheses"),
            ("Failed > 1", "not a query name"),
            ("1a > 1", "comes first"),
            ("a > 1 b > 2", "join comparisons"),
            ("a > 1 AND b > 2", "join comparisons"),
            ("&& a > 1", "where a query name belongs"),
            ("a ~ 1", "unexpected"),
        ] {
            let found = parse(bad).expect_err(bad);
            assert!(found.message.contains(says), "{bad}: {}", found.message);
            assert!(found.start <= found.end && found.end <= bad.len(), "{bad}");
        }
    }

    #[test]
    fn a_long_condition_does_not_recurse() {
        let long = vec!["a > 1"; 20_000].join(" || ");
        assert_eq!(parse(&long).unwrap().comparisons.len(), 20_000);
    }

    #[test]
    fn query_names() {
        assert!(query_name("a"));
        assert!(query_name("my_query2"));
        assert!(!query_name("Failed-Logins"));
        assert!(!query_name("_a"));
        assert!(!query_name(""));
    }
}
