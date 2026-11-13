//! The aggregation condition grammar (graylog-1.0, "Condition grammar"):
//! `aggregation.condition` compiled into Graylog's series and condition tree
//! (`platforms/graylog/constraints.py` `parse_condition`).
//!
//! The parser is language-server 0.16.0's (`opentide-tide/src/graylog.rs`),
//! moved here so the model, deploy and the editor share one copy: it keeps
//! each token's byte range, so an error names where it is. What it accepts and
//! the messages it gives are 0.26.0's.
//!
//! ```text
//! or   := and ("OR" and)*
//! and  := not ("AND" not)*
//! not  := "NOT" not | primary
//! primary := "(" or ")" | call op number
//! call := function "(" [arg ("," arg)*] ")"
//! ```

use opentide_core::falco::is_python_space;

use crate::configuration::repr::quote;

/// Graylog's 12 aggregation functions, the same on every supported version,
/// with what each computes and the arguments it takes.
pub const FUNCTIONS: [(&str, &str, &str); 12] = [
    ("avg", "avg(field)", "The average of a numeric field."),
    (
        "card",
        "card(field)",
        "The cardinality of a field: how many distinct values it has.",
    ),
    (
        "count",
        "count() or count(field)",
        "The number of messages; with a field, of messages that have it.",
    ),
    ("latest", "latest(field)", "The field's most recent value."),
    ("max", "max(field)", "The largest value of a numeric field."),
    (
        "min",
        "min(field)",
        "The smallest value of a numeric field.",
    ),
    (
        "percentage",
        "percentage(field)",
        "The field's share of the total, as a percentage.",
    ),
    (
        "percentile",
        "percentile(field, p)",
        "The value below which `p` percent of the field's values fall, `0 < p ≤ 100`.",
    ),
    (
        "stddev",
        "stddev(field)",
        "The standard deviation of a numeric field.",
    ),
    ("sum", "sum(field)", "The sum of a numeric field."),
    (
        "sumofsquares",
        "sumofsquares(field)",
        "The sum of the squares of a numeric field.",
    ),
    (
        "variance",
        "variance(field)",
        "The variance of a numeric field.",
    ),
];

/// The comparisons, longest first.
pub const OPERATORS: [&str; 5] = [">=", ">", "<=", "<", "=="];

/// How deep parentheses and `NOT` may nest (graylog-1.1, "Condition
/// grammar"): the parser recurses once per level, so an unbounded condition
/// would overflow the stack.
pub const MAX_NESTING: usize = 32;

/// `[A-Za-z0-9_.@-]+`: a Graylog message field name (`Message.validKey`).
pub fn field_name(text: &str) -> bool {
    !text.is_empty() && text.chars().all(field_char)
}

fn field_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '@' | '-')
}

/// A comparison's or a percentile's number, as written (`3`, `-1`, `2.5`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number(pub String);

impl Number {
    /// `-?[0-9]+(\.[0-9]+)?`.
    fn parse(token: &str) -> Option<Self> {
        let digits = token.strip_prefix('-').unwrap_or(token);
        let (whole, fraction) = match digits.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (digits, None),
        };
        let all = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        (all(whole) && fraction.is_none_or(all)).then(|| Self(token.to_owned()))
    }

    /// The number as Graylog takes it: an integer when it has no fraction
    /// (Python's `int`), else a float.
    pub fn json(&self) -> serde_json::Value {
        if !self.0.contains('.')
            && let Ok(integer) = self.0.parse::<i64>()
        {
            return integer.into();
        }
        serde_json::Number::from_f64(self.value()).map_or(serde_json::Value::Null, Into::into)
    }

    /// The number as a float.
    pub fn value(&self) -> f64 {
        self.0.parse().unwrap_or(f64::NAN)
    }
}

/// A condition expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// `a OR b`.
    Or(Box<Expr>, Box<Expr>),
    /// `a AND b`.
    And(Box<Expr>, Box<Expr>),
    /// `NOT a`.
    Not(Box<Expr>),
    /// `call op number`.
    Compare {
        /// The comparison.
        op: &'static str,
        /// The series the call compiles to.
        series: String,
        /// The number compared with.
        value: Number,
    },
}

impl Expr {
    /// Graylog's condition tree (graylog-1.0, "Compilation").
    pub fn json(&self) -> serde_json::Value {
        use serde_json::json;
        match self {
            Self::Or(a, b) => json!({"expr": "||", "left": a.json(), "right": b.json()}),
            Self::And(a, b) => json!({"expr": "&&", "left": a.json(), "right": b.json()}),
            Self::Not(a) => json!({"expr": "!", "left": a.json()}),
            Self::Compare { op, series, value } => json!({
                "expr": op,
                "left": {"expr": "number-ref", "ref": series},
                "right": {"expr": "number", "value": value.json()},
            }),
        }
    }
}

/// One series: a distinct call, in order of first appearance.
#[derive(Debug, Clone, PartialEq)]
pub struct Series {
    /// `<function>-<field>[-<percentile>]`.
    pub id: String,
    /// The aggregation function.
    pub function: &'static str,
    /// The field, when the call names one.
    pub field: Option<String>,
    /// `percentile`'s percentile.
    pub percentile: Option<f64>,
}

impl Series {
    /// The series as Graylog takes it: `{id, type[, field][, percentile]}`.
    pub fn json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("id".into(), self.id.clone().into());
        map.insert("type".into(), self.function.into());
        if let Some(field) = &self.field {
            map.insert("field".into(), field.clone().into());
        }
        if let Some(percentile) = self.percentile.and_then(serde_json::Number::from_f64) {
            map.insert("percentile".into(), percentile.into());
        }
        map.into()
    }
}

/// A parsed condition: its tree and its series.
#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    /// The condition tree.
    pub expr: Expr,
    /// One series per distinct call, in order of first appearance.
    pub series: Vec<Series>,
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

#[derive(Debug, Clone, Copy)]
struct Token<'a> {
    text: &'a str,
    start: usize,
}

impl Token<'_> {
    fn end(&self) -> usize {
        self.start + self.text.len()
    }
}

/// The oracle's `_tokens`: comparisons, parentheses and commas, and words of
/// field-name characters, around whitespace.
fn tokenize(text: &str) -> Result<Vec<Token<'_>>, ConditionError> {
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let Some(ch) = rest.chars().next() else {
            break;
        };
        if is_python_space(ch) {
            at += ch.len_utf8();
            continue;
        }
        let len = if rest.starts_with(">=") || rest.starts_with("<=") || rest.starts_with("==") {
            2
        } else if matches!(ch, '>' | '<' | '(' | ')' | ',') {
            1
        } else if field_char(ch) {
            rest.find(|ch: char| !field_char(ch)).unwrap_or(rest.len())
        } else {
            let shown: String = text[at..]
                .trim_matches(is_python_space)
                .chars()
                .take(12)
                .collect();
            return Err(ConditionError {
                message: format!("unexpected {}", quote(&shown)),
                start: at,
                end: at + ch.len_utf8(),
            });
        };
        tokens.push(Token {
            text: &rest[..len],
            start: at,
        });
        at += len;
    }
    Ok(tokens)
}

struct Parser<'a> {
    text: &'a str,
    tokens: Vec<Token<'a>>,
    index: usize,
    series: Vec<Series>,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<Token<'a>> {
        self.tokens.get(self.index).copied()
    }

    fn peek_is(&self, text: &str) -> bool {
        self.peek().is_some_and(|token| token.text == text)
    }

    /// An error at `at`, or at the condition's last character when it ends.
    fn error(&self, message: String, at: Option<Token<'_>>) -> ConditionError {
        let (start, end) = match at {
            Some(token) => (token.start, token.end()),
            None => {
                let end = self.text.trim_end_matches(is_python_space).len();
                let start = self.text[..end]
                    .char_indices()
                    .next_back()
                    .map_or(0, |(at, _)| at);
                (start, end)
            }
        };
        ConditionError {
            message,
            start,
            end,
        }
    }

    /// The oracle's `take`: the next token, which must be `expected` when
    /// one is given.
    fn take(&mut self, expected: Option<&str>) -> Result<Token<'a>, ConditionError> {
        match self.peek() {
            Some(token) if expected.is_none_or(|expected| token.text == expected) => {
                self.index += 1;
                Ok(token)
            }
            found => Err(self.error(
                format!(
                    "expected {}, got {}",
                    expected.unwrap_or("more"),
                    found.map_or_else(|| "end of input".to_owned(), |token| quote(token.text))
                ),
                found,
            )),
        }
    }

    /// Enters one level of `(` or `NOT`, the token just taken.
    fn nest(&mut self) -> Result<(), ConditionError> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            let at = self.tokens.get(self.index - 1).copied();
            return Err(self.error(
                format!("the condition nests deeper than {MAX_NESTING} levels of '(' and 'NOT'"),
                at,
            ));
        }
        Ok(())
    }

    fn or(&mut self) -> Result<Expr, ConditionError> {
        let mut node = self.and()?;
        while self.peek_is("OR") {
            self.index += 1;
            node = Expr::Or(Box::new(node), Box::new(self.and()?));
        }
        Ok(node)
    }

    fn and(&mut self) -> Result<Expr, ConditionError> {
        let mut node = self.not()?;
        while self.peek_is("AND") {
            self.index += 1;
            node = Expr::And(Box::new(node), Box::new(self.not()?));
        }
        Ok(node)
    }

    fn not(&mut self) -> Result<Expr, ConditionError> {
        if self.peek_is("NOT") {
            self.index += 1;
            self.nest()?;
            let node = Expr::Not(Box::new(self.not()?));
            self.depth -= 1;
            return Ok(node);
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, ConditionError> {
        if self.peek_is("(") {
            self.index += 1;
            self.nest()?;
            let node = self.or()?;
            self.take(Some(")"))?;
            self.depth -= 1;
            return Ok(node);
        }
        let series = self.call()?;
        let token = self.take(None)?;
        let Some(op) = OPERATORS.iter().copied().find(|op| *op == token.text) else {
            return Err(self.error(
                format!("{} is not a comparison", quote(token.text)),
                Some(token),
            ));
        };
        let token = self.take(None)?;
        let value = self.number(token)?;
        Ok(Expr::Compare { op, series, value })
    }

    /// The oracle's `_number`.
    fn number(&self, token: Token<'_>) -> Result<Number, ConditionError> {
        Number::parse(token.text).ok_or_else(|| {
            self.error(
                format!("{} is not a number", quote(token.text)),
                Some(token),
            )
        })
    }

    /// A call: the series id it compiles to.
    fn call(&mut self) -> Result<String, ConditionError> {
        let head = self.take(None)?;
        let Some(&(function, _, _)) = FUNCTIONS.iter().find(|(name, _, _)| *name == head.text)
        else {
            return Err(self.error(
                format!("{} is not an aggregation function", quote(head.text)),
                Some(head),
            ));
        };
        self.take(Some("("))?;
        // field [ "," number ]: arguments are separated by exactly one comma.
        let mut args: Vec<Token<'a>> = Vec::new();
        if !self.peek_is(")") {
            args.push(self.take(None)?);
            while self.peek_is(",") {
                self.index += 1;
                args.push(self.take(None)?);
            }
        }
        let close = self.take(Some(")"))?;
        let call = Token {
            text: &self.text[head.start..close.end()],
            start: head.start,
        };
        let wrong = |message: &str| self.error(message.to_owned(), Some(call));
        let field = args.first().copied();
        if let Some(field) = field
            && !field_name(field.text)
        {
            return Err(self.error(
                format!("{} is not a field name", quote(field.text)),
                Some(field),
            ));
        }
        let mut percentile = None;
        if function == "count" && args.len() > 1 {
            return Err(wrong("count takes no field or one field"));
        }
        if function == "percentile" {
            let [_, p] = args.as_slice() else {
                return Err(wrong("percentile takes a field and a percentile"));
            };
            let value = self.number(*p)?;
            if !(value.value() > 0.0 && value.value() <= 100.0) {
                return Err(wrong("percentile is greater than 0 and at most 100"));
            }
            percentile = Some((p.text, value.value()));
        } else if function != "count" && args.len() != 1 {
            return Err(wrong(&format!("{function} takes one field")));
        }
        let field = field.map(|field| field.text.to_owned());
        let mut id = format!("{function}-{}", field.as_deref().unwrap_or(""));
        if let Some((written, _)) = percentile {
            id.push('-');
            id.push_str(written);
        }
        if !self.series.iter().any(|series| series.id == id) {
            self.series.push(Series {
                id: id.clone(),
                function,
                field: field.filter(|field| !field.is_empty()),
                percentile: percentile.map(|(_, value)| value),
            });
        }
        Ok(id)
    }
}

/// Parses an aggregation condition: its tree and its series, one per
/// distinct call in order of first appearance.
pub fn parse_condition(text: &str) -> Result<Condition, ConditionError> {
    let tokens = tokenize(text)?;
    let mut parser = Parser {
        text,
        tokens,
        index: 0,
        series: Vec::new(),
        depth: 0,
    };
    if parser.tokens.is_empty() {
        return Err(parser.error("the condition is empty".to_owned(), None));
    }
    let expr = parser.or()?;
    if let Some(token) = parser.peek() {
        return Err(parser.error(format!("unexpected {}", quote(token.text)), Some(token)));
    }
    Ok(Condition {
        expr,
        series: parser.series,
    })
}

/// Compiles an aggregation condition the way deploy sends it (graylog-1.0,
/// "Compilation"): the series, and the condition tree.
pub fn compile_condition(
    text: &str,
) -> Result<(serde_json::Value, Vec<serde_json::Value>), ConditionError> {
    let condition = parse_condition(text)?;
    Ok((
        condition.expr.json(),
        condition.series.iter().map(Series::json).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn error(text: &str) -> String {
        parse_condition(text).unwrap_err().message
    }

    #[test]
    fn compiles_the_fixtures_condition() {
        let (tree, series) =
            compile_condition("count() >= 3 OR card(parent_image_lc) >= 2").unwrap();
        assert_eq!(
            series,
            vec![
                json!({"id": "count-", "type": "count"}),
                json!({"id": "card-parent_image_lc", "type": "card", "field": "parent_image_lc"}),
            ]
        );
        assert_eq!(
            tree,
            json!({
                "expr": "||",
                "left": {"expr": ">=", "left": {"expr": "number-ref", "ref": "count-"},
                         "right": {"expr": "number", "value": 3}},
                "right": {"expr": ">=", "left": {"expr": "number-ref", "ref": "card-parent_image_lc"},
                          "right": {"expr": "number", "value": 2}},
            })
        );
    }

    #[test]
    fn and_binds_tighter_than_or_and_not_nests() {
        let (tree, series) =
            compile_condition("NOT (avg(x) > 1.5 AND max(x) < -2) OR percentile(y, 95) == 0")
                .unwrap();
        assert_eq!(tree["expr"], "||");
        assert_eq!(tree["left"]["expr"], "!");
        assert_eq!(tree["left"]["left"]["expr"], "&&");
        assert_eq!(tree["left"]["left"]["left"]["right"]["value"], json!(1.5));
        assert_eq!(tree["left"]["left"]["right"]["right"]["value"], json!(-2));
        assert_eq!(
            series[2],
            json!({"id": "percentile-y-95", "type": "percentile", "field": "y", "percentile": 95.0})
        );
    }

    #[test]
    fn a_repeated_call_is_one_series() {
        let condition = parse_condition("count() > 1 AND count() < 9").unwrap();
        assert_eq!(condition.series.len(), 1);
    }

    #[test]
    fn errors_name_what_the_oracle_names() {
        assert_eq!(error(""), "the condition is empty");
        assert_eq!(error("   "), "the condition is empty");
        assert_eq!(error("count() >= 3 $x"), "unexpected '$x'");
        assert_eq!(
            error("total() > 1"),
            "'total' is not an aggregation function"
        );
        assert_eq!(error("count > 1"), "expected (, got '>'");
        assert_eq!(error("count() > "), "expected more, got end of input");
        assert_eq!(error("count() ~ 1"), "unexpected '~ 1'");
        assert_eq!(error("count() AND 1"), "'AND' is not a comparison");
        assert_eq!(error("count() > x"), "'x' is not a number");
        assert_eq!(
            error("count(a, b) > 1"),
            "count takes no field or one field"
        );
        assert_eq!(
            error("percentile(a) > 1"),
            "percentile takes a field and a percentile"
        );
        assert_eq!(
            error("percentile(a, 101) > 1"),
            "percentile is greater than 0 and at most 100"
        );
        assert_eq!(error("percentile(a, x) > 1"), "'x' is not a number");
        assert_eq!(error("avg() > 1"), "avg takes one field");
        assert_eq!(error("avg(a, 1) > 1"), "avg takes one field");
        assert_eq!(error("avg(() > 1"), "'(' is not a field name");
        assert_eq!(error("count() > 1 count() > 2"), "unexpected 'count'");
        assert_eq!(error("(count() > 1"), "expected ), got end of input");
        assert_eq!(error("count() > 1 and count() > 2"), "unexpected 'and'");
    }

    #[test]
    fn nesting_is_bounded() {
        let deep = format!("{}count() > 1{}", "(".repeat(33), ")".repeat(33));
        assert_eq!(
            error(&deep),
            "the condition nests deeper than 32 levels of '(' and 'NOT'"
        );
        let fine = format!("{}count() > 1{}", "(".repeat(32), ")".repeat(32));
        assert!(parse_condition(&fine).is_ok());
        let nots = format!("{}count() > 1", "NOT ".repeat(33));
        assert!(error(&nots).contains("nests deeper"));
    }

    #[test]
    fn errors_carry_their_range() {
        let error = parse_condition("count() >= x").unwrap_err();
        assert_eq!((error.start, error.end), (11, 12));
        let error = parse_condition("count() >=  ").unwrap_err();
        assert_eq!((error.start, error.end), (9, 10));
        let error = parse_condition("avg(a, 1) > 1").unwrap_err();
        assert_eq!((error.start, error.end), (0, 9));
    }

    #[test]
    fn numbers_are_ints_without_a_fraction() {
        assert_eq!(Number("3".into()).json(), json!(3));
        assert_eq!(Number("-0".into()).json(), json!(0));
        assert_eq!(Number("2.50".into()).json(), json!(2.5));
        assert!(Number::parse("1.").is_none());
        assert!(Number::parse("-").is_none());
        assert!(Number::parse(".5").is_none());
    }
}
