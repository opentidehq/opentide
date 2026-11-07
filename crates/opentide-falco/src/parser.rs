//! A faithful port of libsinsp's filter parser
//! (falcosecurity/libs, `userspace/libsinsp/filter/parser.cpp`, Apache-2.0).
//!
//! Falco and the Sysdig agent parse every condition with that parser, so this
//! one follows it step for step instead of a grammar of its own: the same
//! cursor-based lexing (keywords matched as prefixes, word operators that need
//! a blank after them, `not(` without a blank, POSIX `[[:space:]]` in the
//! `not` and token regexes but only space, tab, `\b`, `\r`, `\n` as blanks),
//! the same recovery points (a list's first element, an operator modifier
//! that turns out to be a value), the same recursion limit, and the same error
//! messages. `crates/testdata/conformance/libsinsp/parser.json` holds libs' own
//! parser tests; the engine agrees with every verdict and message.
//!
//! The tree-sitter grammar (`grammars/tree-sitter-opentide-falco`) is for
//! highlighting and editor structure; verdicts come from here.

use std::fmt::Write as _;

/// Byte span `[start, end)` in the parsed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// libsinsp's filter AST (`filter/ast.h`), with spans.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Vec<Expr>, Span),
    Or(Vec<Expr>, Span),
    Not(Box<Expr>, Span),
    /// A bare name: a macro.
    Identifier(String, Span),
    /// A constant: a quoted string (unescaped), a bare string, a number, or a
    /// list name after a list operator.
    Value(String, Span),
    /// `(a, b, "c d")`, values unescaped, each with its span.
    List(Vec<(String, Span)>, Span),
    /// A transformer's `( ... )` argument (`join(",", (a.b, "x"))`).
    TransformerList(Vec<Expr>, Span),
    Field {
        name: String,
        arg: Option<String>,
        span: Span,
        name_span: Span,
    },
    Transformer {
        name: String,
        values: Vec<Expr>,
        arg: Option<String>,
        span: Span,
    },
    Unary {
        left: Box<Expr>,
        op: String,
        op_span: Span,
        span: Span,
    },
    Binary {
        left: Box<Expr>,
        op: String,
        op_span: Span,
        right: Box<Expr>,
        span: Span,
    },
}

impl Expr {
    pub fn span(&self) -> Span {
        match self {
            Expr::And(_, s)
            | Expr::Or(_, s)
            | Expr::Not(_, s)
            | Expr::Identifier(_, s)
            | Expr::Value(_, s)
            | Expr::List(_, s)
            | Expr::TransformerList(_, s) => *s,
            Expr::Field { span, .. }
            | Expr::Transformer { span, .. }
            | Expr::Unary { span, .. }
            | Expr::Binary { span, .. } => *span,
        }
    }

    /// libsinsp's `ast::as_string`.
    pub fn as_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Expr::And(children, _) | Expr::Or(children, _) => {
                let op = if matches!(self, Expr::And(..)) {
                    "and"
                } else {
                    "or"
                };
                out.push('(');
                for (i, c) in children.iter().enumerate() {
                    if i > 0 {
                        let _ = write!(out, " {op} ");
                    }
                    c.write(out);
                }
                out.push(')');
            }
            Expr::Not(child, _) => {
                out.push_str("not ");
                child.write(out);
            }
            Expr::Identifier(name, _) => out.push_str(name),
            Expr::Value(v, _) => out.push_str(&escape_str(v)),
            Expr::List(values, _) => {
                out.push('(');
                for (i, (v, _)) in values.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&escape_str(v));
                }
                out.push(')');
            }
            Expr::TransformerList(children, _) => {
                out.push('(');
                for (i, c) in children.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    c.write(out);
                }
                out.push(')');
            }
            Expr::Field { name, arg, .. } => {
                out.push_str(name);
                write_arg(out, arg);
            }
            Expr::Transformer {
                name, values, arg, ..
            } => {
                out.push_str(name);
                out.push('(');
                for (i, c) in values.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    c.write(out);
                }
                out.push(')');
                write_arg(out, arg);
            }
            Expr::Unary { left, op, .. } => {
                left.write(out);
                out.push(' ');
                out.push_str(op);
            }
            Expr::Binary {
                left, op, right, ..
            } => {
                left.write(out);
                let _ = write!(out, " {op} ");
                right.write(out);
            }
        }
    }
}

fn write_arg(out: &mut String, arg: &Option<String>) {
    match arg {
        None => {}
        Some(a) if a.is_empty() => out.push_str("[\"\"]"),
        Some(a) => {
            out.push('[');
            out.push_str(&escape_str(a));
            out.push(']');
        }
    }
}

/// libsinsp's `escape_str` (`filter/escaping.cpp`).
pub fn escape_str(s: &str) -> String {
    let mut res = String::new();
    let mut escape = false;
    for c in s.chars() {
        match c {
            '\u{8}' => res.push_str("\\b"),
            '\u{c}' => res.push_str("\\f"),
            '\n' => res.push_str("\\n"),
            '\r' => res.push_str("\\r"),
            '\t' => res.push_str("\\t"),
            ' ' | '=' | '\'' | '\0' => res.push(c),
            '\\' => res.push_str("\\\\"),
            '"' => res.push_str("\\\""),
            _ => {
                res.push(c);
                continue;
            }
        }
        escape = true;
    }
    if escape { format!("\"{res}\"") } else { res }
}

/// libsinsp's `unescape_str`: *quoted* still carries its delimiters.
pub fn unescape_str(quoted: &[u8]) -> Result<Vec<u8>, String> {
    let mut res = Vec::new();
    let len = quoted.len().saturating_sub(1);
    let mut escaped = false;
    let mut i = 1;
    while i < len {
        let c = quoted[i];
        if !escaped {
            if c == b'\\' {
                escaped = true;
            } else {
                res.push(c);
            }
            i += 1;
            continue;
        }
        match c {
            b'b' => res.push(8),
            b'f' => res.push(12),
            b'n' => res.push(b'\n'),
            b'r' => res.push(b'\r'),
            b't' => res.push(b'\t'),
            // libs maps `\ ` to a backslash: a fallthrough kept for old rules.
            b' ' | b'\\' => res.push(b'\\'),
            b'/' => res.push(b'/'),
            b'"' => {
                if quoted[0] != c {
                    return Err("invalid \\\" escape in '-quoted string".into());
                }
                res.push(b'"');
            }
            b'\'' => {
                if quoted[0] != c {
                    return Err("invalid \\' escape in \"-quoted string".into());
                }
                res.push(b'\'');
            }
            b'x' => {
                if i + 2 >= len {
                    return Err("truncated hex char escape sequence".into());
                }
                let hex = &quoted[i + 1..i + 3];
                let parsed = std::str::from_utf8(hex)
                    .ok()
                    .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match parsed {
                    Some(b) => res.push(b),
                    None => {
                        return Err(format!(
                            "invalid hex char escape sequence: {}",
                            String::from_utf8_lossy(hex)
                        ));
                    }
                }
                i += 2;
            }
            other => {
                return Err(format!(
                    "unsupported string escape sequence: \\{}",
                    other as char
                ));
            }
        }
        escaped = false;
        i += 1;
    }
    Ok(res)
}

/// A parse failure: libsinsp's message and the cursor where it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub offset: usize,
}

/// The operators the parser recognises (`parser::supported_operators`).
pub const OPERATORS: &[&str] = &[
    "exists",
    "<=",
    "<",
    ">=",
    ">",
    "==",
    "=",
    "!=",
    "glob",
    "iglob",
    "contains",
    "icontains",
    "bcontains",
    "startswith",
    "bstartswith",
    "endswith",
    "regex",
    "intersects",
    "in",
    "pmatch",
];
/// The list operators (`supported_operators(true)`).
pub const LIST_OPERATORS: &[&str] = &["intersects", "in", "pmatch"];
/// String operator modifiers.
pub const MODIFIERS: &[&str] = &["oneof", "anyof", "allof"];
/// Field transformers (`supported_field_transformers(false)`).
pub const TRANSFORMERS: &[&str] = &[
    "tolower", "toupper", "b64", "basename", "len", "join", "concat", "getopt",
];

const UNARY_OPS: &[&str] = &["exists"];
const NUM_OPS: &[&str] = &["<=", "<", ">=", ">"];
// A trailing space: the operator needs a blank after it.
const STR_OPS: &[&str] = &[
    "==",
    "=",
    "!=",
    "glob ",
    "iglob ",
    "contains ",
    "icontains ",
    "bcontains ",
    "startswith ",
    "bstartswith ",
    "endswith ",
    "regex ",
];
const STR_MODIFIER_OPS: &[&str] = &["oneof ", "anyof ", "allof "];
const LIST_OPS: &[&str] = &["intersects", "in", "pmatch"];
const TRANSFORMER_TOKENS: &[&str] = &[
    "tolower(",
    "toupper(",
    "b64(",
    "basename(",
    "len(",
    "join(",
    "concat(",
    "getopt(",
];
const VAL_TOKEN: &str = "val(";

/// What `supported_field_transformers(true)` lists, as libs quotes it in messages.
fn transformers_list() -> String {
    std::iter::once("val")
        .chain(TRANSFORMERS.iter().copied())
        .map(|t| format!("'{t}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn operators_list() -> String {
    // libs lists them as unary, numeric, string, list, each trimmed.
    UNARY_OPS
        .iter()
        .chain(NUM_OPS)
        .chain(STR_OPS)
        .chain(LIST_OPS)
        .map(|o| format!("'{}'", o.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// libsinsp's parser over *input*.
pub struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    last_token: Vec<u8>,
    depth: u32,
    max_depth: u32,
    partial: bool,
}

type PResult<T> = Result<T, String>;

fn is_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | 8 | b'\r' | b'\n')
}

/// POSIX `[[:space:]]`.
fn is_posix_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 11 | 12 | b'\r')
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a str) -> Self {
        Parser {
            input: input.as_bytes(),
            pos: 0,
            last_token: Vec::new(),
            depth: 0,
            max_depth: 100,
            partial: false,
        }
    }

    pub fn set_parse_partial(&mut self, partial: bool) {
        self.partial = partial;
    }

    /// The cursor: where the parse stopped.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// `parser::parse`.
    pub fn parse(&mut self) -> Result<Expr, ParseError> {
        if self.input.is_empty() {
            return Err(self.error("filter input string is empty".into()));
        }
        self.pos = 0;
        self.last_token.clear();
        self.depth = 0;
        let res = self.parse_or().map_err(|m| self.error(m))?;
        if !self.partial && self.pos != self.input.len() {
            let msg = format!(
                "unexpected token after '{}', expecting 'or', 'and'",
                self.last()
            );
            return Err(self.error(msg));
        }
        Ok(res)
    }

    /// `parser::parse_field_or_transformer`: a field or a transformer, parsed
    /// partially (output templates).
    pub fn parse_field_or_transformer(&mut self) -> Result<Expr, ParseError> {
        self.field_or_transformer().map_err(|m| self.error(m))
    }

    fn error(&self, message: String) -> ParseError {
        ParseError {
            message,
            offset: self.pos.min(self.input.len()),
        }
    }

    fn last(&self) -> String {
        String::from_utf8_lossy(&self.last_token).into_owned()
    }

    fn enter(&mut self) -> PResult<()> {
        self.depth += 1;
        if self.depth >= self.max_depth {
            return Err(format!("exceeded max depth limit of {}", self.max_depth));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    /// Runs *f* under a depth guard, as each libs function with a
    /// `depth_guard` does.
    fn guarded<T>(&mut self, f: impl FnOnce(&mut Self) -> PResult<T>) -> PResult<T> {
        self.enter().inspect_err(|_| self.leave())?;
        let res = f(self);
        self.leave();
        res
    }

    fn cur(&self) -> u8 {
        self.input.get(self.pos).copied().unwrap_or(0)
    }

    fn rest(&self) -> &'a [u8] {
        &self.input[self.pos.min(self.input.len())..]
    }

    fn span_from(&self, start: usize) -> Span {
        Span {
            start,
            end: self.pos,
        }
    }

    fn field_or_transformer(&mut self) -> PResult<Expr> {
        self.guarded(|p| {
            let start = p.pos;
            if p.lex_field_name() {
                let name = p.last();
                return p.parse_field_remainder(name, start);
            }
            if p.lex_field_transformer_type() {
                p.lex_blank();
                let name = p.transformer_name();
                return p.parse_field_or_transformer_remainder(name, start);
            }
            Err(format!("unexpected token after '{}", p.last()))
        })
    }

    fn transformer_name(&self) -> String {
        let mut t = self.last();
        t.pop(); // discard '('
        t
    }

    fn parse_or(&mut self) -> PResult<Expr> {
        self.guarded(|p| {
            let start = p.pos;
            p.lex_blank();
            let mut children = vec![p.parse_and()?];
            p.lex_blank();
            while p.lex_helper_str(b"or") {
                let child = if !p.lex_blank() {
                    if p.lex_helper_str(b"(") {
                        p.parse_embedded_remainder()?
                    } else {
                        return Err("expected blank or '(' after 'or'".into());
                    }
                } else {
                    p.parse_and()?
                };
                children.push(child);
                p.lex_blank();
            }
            Ok(if children.len() > 1 {
                Expr::Or(children, p.span_from(start))
            } else {
                children.pop().unwrap()
            })
        })
    }

    fn parse_and(&mut self) -> PResult<Expr> {
        self.guarded(|p| {
            let start = p.pos;
            p.lex_blank();
            let mut children = vec![p.parse_not()?];
            p.lex_blank();
            while p.lex_helper_str(b"and") {
                let child = if !p.lex_blank() {
                    if p.lex_helper_str(b"(") {
                        p.parse_embedded_remainder()?
                    } else {
                        return Err("expected blank or '(' after 'and'".into());
                    }
                } else {
                    p.parse_not()?
                };
                children.push(child);
                p.lex_blank();
            }
            Ok(if children.len() > 1 {
                Expr::And(children, p.span_from(start))
            } else {
                children.pop().unwrap()
            })
        })
    }

    fn parse_not(&mut self) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let start = p.pos;
            let mut is_not = false;
            while p.lex_not_blank() {
                is_not = !is_not;
            }
            let child = if p.lex_helper_str(b"not(") {
                is_not = !is_not;
                p.parse_embedded_remainder()?
            } else {
                p.parse_check()?
            };
            Ok(if is_not {
                Expr::Not(Box::new(child), p.span_from(start))
            } else {
                child
            })
        })
    }

    fn parse_embedded_remainder(&mut self) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let child = p.parse_or()?;
            p.lex_blank();
            if !p.lex_helper_str(b")") {
                return Err("expected a ')' token".into());
            }
            Ok(child)
        })
    }

    fn parse_check(&mut self) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let start = p.pos;
            if p.lex_helper_str(b"(") {
                return p.parse_embedded_remainder();
            }
            if p.lex_field_name() {
                let name = p.last();
                let left = p.parse_field_remainder(name, start)?;
                return p.parse_condition(left, start);
            }
            if p.lex_field_transformer_type() {
                p.lex_blank();
                let name = p.transformer_name();
                let left = p.parse_field_or_transformer_remainder(name, start)?;
                return p.parse_condition(left, start);
            }
            if p.lex_identifier() {
                return Ok(Expr::Identifier(p.last(), p.span_from(start)));
            }
            Err("expected a '(' token, a field check, or an identifier".into())
        })
    }

    fn parse_field_remainder(&mut self, name: String, start: usize) -> PResult<Expr> {
        self.guarded(|p| {
            let name_span = p.span_from(start);
            let arg = p.parse_optional_field_arg()?;
            Ok(Expr::Field {
                name,
                arg,
                span: p.span_from(start),
                name_span,
            })
        })
    }

    fn parse_optional_field_arg(&mut self) -> PResult<Option<String>> {
        if !self.lex_helper_str(b"[") {
            return Ok(None);
        }
        if !self.lex_quoted_str()? && !self.lex_field_arg_bare_str() {
            return Err("expected a valid field argument: a quoted string or a bare string".into());
        }
        let arg = self.last();
        if !self.lex_helper_str(b"]") {
            return Err("expected a ']' token".into());
        }
        Ok(Some(arg))
    }

    fn parse_field_or_transformer_remainder(
        &mut self,
        transformer: String,
        start: usize,
    ) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let mut children = Vec::new();
            loop {
                let arg_start = p.pos;
                children.push(p.parse_field_transformer_arg(arg_start)?);
                p.lex_blank();
                if !p.lex_helper_str(b",") {
                    break;
                }
            }
            p.lex_blank();
            if !p.lex_helper_str(b")") {
                return Err("expected a ')' token closing the transformer".into());
            }
            let arg = p.parse_optional_field_arg()?;
            Ok(Expr::Transformer {
                name: transformer,
                values: children,
                arg,
                span: p.span_from(start),
            })
        })
    }

    fn parse_field_transformer_arg(&mut self, start: usize) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let start = start.max(p.pos);
            if p.lex_hex_num() || p.lex_num() {
                return Ok(Expr::Value(p.last(), p.span_from(start)));
            }
            if p.lex_quoted_str()? {
                return Ok(Expr::Value(p.last(), p.span_from(start)));
            }
            if p.lex_helper_str(b"(") {
                return p.parse_transformer_list(start);
            }
            if p.lex_field_transformer_type() {
                let name = p.transformer_name();
                return p.parse_field_or_transformer_remainder(name, start);
            }
            if p.lex_field_name() {
                let name = p.last();
                return p.parse_field_remainder(name, start);
            }
            Err("expected field transformer argument: \
                 field, transformer, quoted string, number, or transformer list"
                .into())
        })
    }

    fn parse_transformer_list(&mut self, start: usize) -> PResult<Expr> {
        let mut children = Vec::new();
        self.lex_blank();
        if self.lex_helper_str(b")") {
            return Ok(Expr::TransformerList(children, self.span_from(start)));
        }
        children.push(self.parse_transformer_list_arg()?);
        self.lex_blank();
        while self.lex_helper_str(b",") {
            self.lex_blank();
            children.push(self.parse_transformer_list_arg()?);
            self.lex_blank();
        }
        if !self.lex_helper_str(b")") {
            return Err("expected ')'".into());
        }
        Ok(Expr::TransformerList(children, self.span_from(start)))
    }

    fn parse_transformer_list_arg(&mut self) -> PResult<Expr> {
        let start = self.pos;
        if self.lex_field_name() {
            let name = self.last();
            return self.parse_field_remainder(name, start);
        }
        if self.lex_field_transformer_type() {
            self.lex_blank();
            let name = self.transformer_name();
            return self.parse_field_or_transformer_remainder(name, start);
        }
        if self.lex_quoted_str()? {
            return Ok(Expr::Value(self.last(), self.span_from(start)));
        }
        if self.lex_hex_num() || self.lex_num() {
            return Ok(Expr::Value(self.last(), self.span_from(start)));
        }
        Err(
            "expected transformer list argument: field, transformer, quoted string, or number"
                .into(),
        )
    }

    fn parse_condition(&mut self, left: Expr, start: usize) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let op_start = p.pos;
            if p.lex_unary_op() {
                let op = p.last().trim().to_string();
                let op_span = p.span_from(op_start);
                return Ok(Expr::Unary {
                    left: Box::new(left),
                    op,
                    op_span,
                    span: p.span_from(start),
                });
            }
            p.lex_blank();
            let op_start = p.pos;
            let mut op;
            let mut op_span;
            let right;
            if p.lex_num_op() {
                op = p.last();
                op_span = p.span_from(op_start);
                right = p.parse_num_value_or_transformer()?;
            } else if p.lex_str_op() {
                op = p.last();
                op_span = p.span_from(op_start);
                // Word operators consumed their blank in the lexer; symbols need one
                // here before a modifier.
                let had_blank = op.as_bytes()[0].is_ascii_alphabetic() || p.lex_blank();
                let saved_pos = p.pos;
                let saved_token = p.last_token.clone();
                if had_blank
                    && p.lex_str_op_modifier()
                    && p.list_value_follows()
                    && !p.bool_keyword_follows()
                {
                    op = format!("{} {}", op.trim(), p.last());
                    op_span = Span {
                        start: op_span.start,
                        end: saved_pos + p.last_token.len(),
                    };
                    right = p.parse_list_value()?;
                } else {
                    p.pos = saved_pos;
                    p.last_token = saved_token;
                    right = p.parse_str_value_or_transformer(false)?;
                }
            } else if p.lex_list_op() {
                op = p.last();
                op_span = p.span_from(op_start);
                right = p.parse_list_value_or_transformer()?;
            } else {
                return Err(format!(
                    "expected a valid check operator: one of {}",
                    operators_list()
                ));
            }
            Ok(Expr::Binary {
                left: Box::new(left),
                op: op.trim().to_string(),
                op_span,
                right: Box::new(right),
                span: p.span_from(start),
            })
        })
    }

    fn parse_num_value_or_transformer(&mut self) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let start = p.pos;
            if let Some(res) = p.try_parse_transformer_or_val()? {
                return Ok(res);
            }
            if p.lex_hex_num() || p.lex_num() {
                return Ok(Expr::Value(p.last(), p.span_from(start)));
            }
            Err(format!(
                "expected a number value or a field with a valid transformer: {}",
                transformers_list()
            ))
        })
    }

    fn parse_str_value_or_transformer(&mut self, no_transformer: bool) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let start = p.pos;
            if !no_transformer && let Some(res) = p.try_parse_transformer_or_val()? {
                return Ok(res);
            }
            if p.lex_quoted_str()? || p.lex_bare_str() {
                return Ok(Expr::Value(p.last(), p.span_from(start)));
            }
            if no_transformer {
                return Err("expected a string value".into());
            }
            Err(format!(
                "expected a string value or a field with a valid transformer: {}",
                transformers_list()
            ))
        })
    }

    fn try_parse_list_expr(&mut self) -> PResult<Option<Expr>> {
        let start = self.pos;
        if !self.lex_helper_str(b"(") {
            return Ok(None);
        }
        let mut values = Vec::new();
        self.lex_blank();
        // libs catches a failure on the first element: the list is then empty.
        if let Ok(Expr::Value(v, s)) = self.parse_str_value_or_transformer(true) {
            values.push((v, s));
            self.lex_blank();
            while self.lex_helper_str(b",") {
                match self.parse_str_value_or_transformer(true)? {
                    Expr::Value(v, s) => values.push((v, s)),
                    _ => return Err("parser fatal error: null value expr in body of list".into()),
                }
                self.lex_blank();
            }
        }
        if !self.lex_helper_str(b")") {
            return Err("expected a ')' token".into());
        }
        Ok(Some(Expr::List(values, self.span_from(start))))
    }

    fn parse_list_value(&mut self) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let start = p.pos;
            if let Some(res) = p.try_parse_list_expr()? {
                return Ok(res);
            }
            if p.lex_identifier() {
                return Ok(Expr::Value(p.last(), p.span_from(start)));
            }
            Err("expected a list or an identifier".into())
        })
    }

    fn parse_list_value_or_transformer(&mut self) -> PResult<Expr> {
        self.guarded(|p| {
            p.lex_blank();
            let start = p.pos;
            if let Some(res) = p.try_parse_list_expr()? {
                return Ok(res);
            }
            if let Some(res) = p.try_parse_transformer_or_val()? {
                return Ok(res);
            }
            if p.lex_identifier() {
                return Ok(Expr::Value(p.last(), p.span_from(start)));
            }
            Err(format!(
                "expected a list, an identifier, or a field with a valid transformer: {}",
                transformers_list()
            ))
        })
    }

    fn try_parse_transformer_or_val(&mut self) -> PResult<Option<Expr>> {
        self.guarded(|p| {
            p.lex_blank();
            let start = p.pos;
            if p.lex_helper_str(VAL_TOKEN.as_bytes()) {
                p.lex_blank();
                let transformer = p.transformer_name();
                let field_start = p.pos;
                if !p.lex_field_name() {
                    return Err(format!(
                        "expected a field within '{transformer}' transformer"
                    ));
                }
                let name = p.last();
                let child = p.parse_field_remainder(name, field_start)?;
                p.lex_blank();
                if !p.lex_helper_str(b")") {
                    return Err("expected a ')' token closing the transformer".into());
                }
                let arg = p.parse_optional_field_arg()?;
                return Ok(Some(Expr::Transformer {
                    name: transformer,
                    values: vec![child],
                    arg,
                    span: p.span_from(start),
                }));
            }
            if p.lex_field_transformer_type() {
                p.lex_blank();
                let name = p.transformer_name();
                return p
                    .parse_field_or_transformer_remainder(name, start)
                    .map(Some);
            }
            Ok(None)
        })
    }

    // --- lexing ----------------------------------------------------------------

    fn lex_blank(&mut self) -> bool {
        let mut found = false;
        while self.pos < self.input.len() && is_blank(self.input[self.pos]) {
            found = true;
            self.pos += 1;
        }
        found
    }

    /// `(not[[:space:]]+)`.
    fn lex_not_blank(&mut self) -> bool {
        let rest = self.rest();
        if rest.starts_with(b"not") && rest.len() > 3 && is_posix_space(rest[3]) {
            let n = 3 + rest[3..].iter().take_while(|b| is_posix_space(**b)).count();
            self.take(n);
            return true;
        }
        false
    }

    fn take(&mut self, n: usize) {
        self.last_token = self.input[self.pos..self.pos + n].to_vec();
        self.pos += n;
    }

    /// `[a-zA-Z]+[a-zA-Z0-9_]*`.
    fn ident_len(bytes: &[u8]) -> usize {
        if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
            return 0;
        }
        bytes
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
            .count()
    }

    fn lex_identifier(&mut self) -> bool {
        let n = Self::ident_len(self.rest());
        if n == 0 {
            return false;
        }
        self.take(n);
        true
    }

    /// `[a-zA-Z]+[a-zA-Z0-9_]*(\.[a-zA-Z]+[a-zA-Z0-9_]*)+`.
    fn lex_field_name(&mut self) -> bool {
        let rest = self.rest();
        let mut n = Self::ident_len(rest);
        if n == 0 {
            return false;
        }
        let mut segments = 1;
        while rest.get(n) == Some(&b'.') {
            let seg = Self::ident_len(&rest[n + 1..]);
            if seg == 0 {
                break;
            }
            n += 1 + seg;
            segments += 1;
        }
        if segments < 2 {
            return false;
        }
        self.take(n);
        true
    }

    /// `[^][\"'[:space:]]+`.
    fn lex_field_arg_bare_str(&mut self) -> bool {
        let n = self
            .rest()
            .iter()
            .take_while(|b| !matches!(b, b']' | b'[' | b'"' | b'\'') && !is_posix_space(**b))
            .count();
        if n == 0 {
            return false;
        }
        self.take(n);
        true
    }

    /// `0[xX][0-9a-fA-F]+`.
    fn lex_hex_num(&mut self) -> bool {
        let rest = self.rest();
        if rest.len() > 2 && rest[0] == b'0' && matches!(rest[1], b'x' | b'X') {
            let n = rest[2..]
                .iter()
                .take_while(|b| b.is_ascii_hexdigit())
                .count();
            if n > 0 {
                self.take(2 + n);
                return true;
            }
        }
        false
    }

    /// `[+\-]?[0-9]+[\.]?[0-9]*([eE][+\-][0-9]+)?`.
    fn lex_num(&mut self) -> bool {
        let rest = self.rest();
        let mut n = usize::from(matches!(rest.first(), Some(b'+' | b'-')));
        let digits = rest[n..].iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return false;
        }
        n += digits;
        if rest.get(n) == Some(&b'.') {
            n += 1;
        }
        n += rest[n..].iter().take_while(|b| b.is_ascii_digit()).count();
        if matches!(rest.get(n), Some(b'e' | b'E')) && matches!(rest.get(n + 1), Some(b'+' | b'-'))
        {
            let exp = rest[n + 2..]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
            if exp > 0 {
                n += 2 + exp;
            }
        }
        self.take(n);
        true
    }

    /// libs' quoted string: `prev` starts as a backslash, so the opening quote
    /// never closes; a quote preceded by a backslash never does either.
    fn lex_quoted_str(&mut self) -> PResult<bool> {
        let delimiter = self.cur();
        if delimiter != b'\'' && delimiter != b'"' {
            return Ok(false);
        }
        let start = self.pos;
        let mut prev = b'\\';
        let mut i = self.pos;
        while i < self.input.len() {
            let c = self.input[i];
            if c == delimiter && prev != b'\\' {
                let token = &self.input[start..=i];
                // libs has moved the cursor past the string before it unescapes.
                self.pos = i + 1;
                let unescaped = unescape_str(token)?;
                self.last_token = unescaped;
                return Ok(true);
            }
            prev = c;
            i += 1;
        }
        Ok(false)
    }

    /// `[^()\"'[:space:]=,]+`.
    fn lex_bare_str(&mut self) -> bool {
        let n = self
            .rest()
            .iter()
            .take_while(|b| {
                !matches!(b, b'(' | b')' | b'"' | b'\'' | b'=' | b',') && !is_posix_space(**b)
            })
            .count();
        if n == 0 {
            return false;
        }
        self.take(n);
        true
    }

    fn lex_unary_op(&mut self) -> bool {
        self.lex_operator_list(UNARY_OPS)
    }

    fn lex_num_op(&mut self) -> bool {
        self.lex_operator_list(NUM_OPS)
    }

    fn lex_str_op(&mut self) -> bool {
        self.lex_operator_list(STR_OPS)
    }

    fn lex_str_op_modifier(&mut self) -> bool {
        self.lex_operator_list(STR_MODIFIER_OPS)
    }

    fn lex_list_op(&mut self) -> bool {
        self.lex_operator_list(LIST_OPS)
    }

    fn list_value_follows(&mut self) -> bool {
        if self.cur() == b'(' {
            return true;
        }
        Self::ident_len(self.rest()) > 0
    }

    fn bool_keyword_follows(&self) -> bool {
        let s = self.rest();
        ["and", "or", "not"].iter().any(|kw| {
            s.starts_with(kw.as_bytes())
                && (s.len() == kw.len() || !s[kw.len()].is_ascii_alphanumeric())
        })
    }

    fn lex_field_transformer_type(&mut self) -> bool {
        TRANSFORMER_TOKENS
            .iter()
            .any(|t| self.lex_helper_str(t.as_bytes()))
    }

    fn lex_helper_str(&mut self, s: &[u8]) -> bool {
        if self.rest().starts_with(s) {
            self.take(s.len());
            return true;
        }
        false
    }

    fn lex_operator_list(&mut self, list: &[&str]) -> bool {
        for op in list {
            let bytes = op.as_bytes();
            if bytes.last() != Some(&b' ') {
                if self.lex_helper_str(bytes) {
                    return true;
                }
                continue;
            }
            let saved_pos = self.pos;
            let saved_token = self.last_token.clone();
            if self.lex_helper_str(op.trim().as_bytes()) {
                if self.lex_blank() {
                    return true;
                }
                self.pos = saved_pos;
                self.last_token = saved_token;
            }
        }
        false
    }
}

/// Parse a condition as libsinsp does.
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    Parser::new(input).parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(input: &str) -> String {
        parse(input).unwrap().as_string()
    }

    #[test]
    fn precedence_and_ast_strings() {
        assert_eq!(s("a and b or c"), "((a and b) or c)");
        assert_eq!(s("not not a"), "a");
        assert_eq!(s("not(a)"), "not a");
        assert_eq!(s("proc.name in (a, \"b c\")"), "proc.name in (a, \"b c\")");
        assert_eq!(
            s(r#"getopt(proc.args, "nt:")[t] = value"#),
            "getopt(proc.args,nt:)[t] = value"
        );
        assert_eq!(s("fd.name = anyof (a, b)"), "fd.name = anyof (a, b)");
        assert_eq!(s("fd.name contains allof x"), "fd.name contains allof x");
    }

    #[test]
    fn libs_quirks() {
        // Word operators need a blank after them; `in` does not.
        assert!(parse("proc.name contains(x)").is_err());
        assert!(parse("proc.name in(a)").is_ok());
        // A list's first element that fails to lex leaves the list empty.
        assert!(parse("proc.name in (\"\\q\")").is_ok());
        // Numbers: an exponent needs a sign; hex needs a digit.
        assert!(parse("proc.pid > 1e+5").is_ok());
        assert!(parse("proc.pid > abc").is_err());
        // `not` at the end of input is a macro name.
        assert_eq!(s("not"), "not");
        let err = parse("proc.name = a b").unwrap_err();
        assert_eq!(
            err.message,
            "unexpected token after 'a', expecting 'or', 'and'"
        );
    }

    #[test]
    fn depth_limit() {
        let err = parse(&"(".repeat(100_000)).unwrap_err();
        assert_eq!(err.message, "exceeded max depth limit of 100");
        assert!(parse("((((((((((a))))))))))").is_ok());
    }
}
