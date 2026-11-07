//! The body of a `/regexp/` term, checked the way Elasticsearch builds it.
//!
//! `query_string` hands the text between the slashes to Lucene's `RegExp`
//! with every optional syntax flag on (`RegExp.ALL`, plus the complement
//! operator `~`), then determinizes the automaton with a work limit of
//! 10 000 (`max_determinized_states`). Lucene's regular expressions are their
//! own grammar, not PCRE: `\b`, `\n`, and `(?i)` mean something else or
//! nothing at all.
//!
//! The parser and the automaton constructions follow Lucene 10.5.2 and
//! 9.12.0 (`org.apache.lucene.util.automaton.RegExp` and `Operations`,
//! Apache-2.0, which derive from dk.brics.automaton), so the determinization
//! effort (the sum of NFA-state-set sizes over the subset construction) is
//! the one Lucene counts. Elasticsearch 9.x runs Lucene 10 and 8.19 runs
//! Lucene 9; they differ in how they build automata and in one corner of
//! character-class syntax. `crates/opentide-lucene/tests/regexp_oracle.rs`
//! compares this module with the Lucene jars.
//!
//! dk.brics.automaton notice, retained as its licence requires:
//!
//! Copyright (c) 2001-2009 Anders Moeller
//! All rights reserved.
//!
//! Redistribution and use in source and binary forms, with or without
//! modification, are permitted provided that the following conditions
//! are met:
//! 1. Redistributions of source code must retain the above copyright
//!    notice, this list of conditions and the following disclaimer.
//! 2. Redistributions in binary form must reproduce the above copyright
//!    notice, this list of conditions and the following disclaimer in the
//!    documentation and/or other materials provided with the distribution.
//! 3. The name of the author may not be used to endorse or promote products
//!    derived from this software without specific prior written permission.
//!
//! THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
//! IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
//! OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
//! IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
//! INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
//! NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//! DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//! THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//! (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
//! THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// State numbers index several parallel tables, as in Lucene.
#![allow(clippy::needless_range_loop)]

/// What Elasticsearch does with one regexp body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// `RegExp` rejects the text. `at` is a char index into the body.
    Invalid {
        at: usize,
        message: String,
    },
    /// Determinization needs more effort than the limit allows.
    TooComplex,
    /// Lucene 9 only: a finite automaton deeper than its 1000-level
    /// recursion limit (`input automaton is too large`).
    TooLarge,
}

/// The Lucene line an Elasticsearch stack builds regexps with. Syntax is the
/// same; the automaton constructions, and so the determinization effort,
/// differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stack {
    /// Elasticsearch 8.19: Lucene 9.12 minimizes after most steps.
    Es8,
    /// Elasticsearch 9.x: Lucene 10 builds one NFA and determinizes it once.
    Es9,
}

/// Lucene's default `max_determinized_states`, which `query_string` uses.
pub const DETERMINIZE_WORK_LIMIT: u64 = 10_000;

/// Constructions larger than this are not built; the check then gives no
/// verdict on complexity rather than guessing.
const MAX_STATES: usize = 200_000;

const MAX_CODE_POINT: u32 = 0x10FFFF;

/// Work (states and transitions built, state sets visited) one check may
/// spend before it gives up on a complexity verdict. Real rules stay far
/// below it; it bounds pathological input such as `(~a){2805,}`.
const WORK_BUDGET: u64 = 8_000_000;

thread_local! {
    static WORK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn spend(n: u64) {
    WORK.with(|w| w.set(w.get().saturating_add(n)));
}

fn over_budget() -> bool {
    WORK.with(|w| w.get() > WORK_BUDGET)
}

pub fn check(body: &str, stack: Stack) -> Verdict {
    let chars: Vec<char> = body.chars().collect();
    let parsed = match Parser::new(&chars, stack).parse() {
        Ok(re) => re,
        Err(e) => {
            return Verdict::Invalid {
                at: e.at,
                message: e.message,
            };
        }
    };
    if let Some(name) = parsed.first_automaton_name() {
        return Verdict::Invalid {
            at: 0,
            message: format!("`<{name}>` names an automaton, and Elasticsearch defines none"),
        };
    }
    let complex = match stack {
        Stack::Es8 => too_complex(&parsed, stack),
        Stack::Es9 => {
            // Recent 9.x releases collapse runs of quantifiers (`+?` becomes
            // `*`) before parsing; earlier ones do not. Report complexity
            // only when both readings agree.
            let collapsed = collapse_quantifiers(body);
            let mut complex = too_complex(&parsed, stack);
            if complex == Some(Verdict::TooComplex) && collapsed != body {
                let chars: Vec<char> = collapsed.chars().collect();
                complex = match Parser::new(&chars, stack).parse() {
                    Ok(re) => too_complex(&re, stack),
                    Err(_) => None,
                };
            }
            complex
        }
    };
    complex.unwrap_or(Verdict::Ok)
}

/// One thing Elasticsearch would object to in a regexp body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// `Error` when both 8.19 (Lucene 9.12) and 9.x (Lucene 10) reject it,
    /// `Warning` when one does or when it depends on an index setting.
    pub severity: opentide_core::Severity,
    /// Character index into the body, when the problem has one position.
    pub at: Option<usize>,
    pub message: String,
    /// A syntax error (as opposed to complexity or length).
    pub syntax: bool,
}

/// What Elasticsearch makes of a Lucene `RegExp` body compiled with
/// `ALL | DEPRECATED_COMPLEMENT`: the `query_string` `/…/` term, EQL `regex`,
/// and ES|QL `RLIKE` all compile it this way.
pub fn elasticsearch_problems(body: &str) -> Vec<Problem> {
    use opentide_core::Severity;
    let es9 = check(body, Stack::Es9);
    let es8 = check(body, Stack::Es8);
    // Lucene 9 and 10 read `[\x-y]` differently; everything else parses alike.
    let invalid = match (&es8, &es9) {
        (Verdict::Invalid { at, message }, Verdict::Invalid { .. }) => {
            Some((Severity::Error, *at, message.clone()))
        }
        (Verdict::Invalid { at, message }, _) => Some((
            Severity::Warning,
            *at,
            format!("{message} (Elasticsearch 8.19 rejects it, 9.x accepts it)"),
        )),
        (_, Verdict::Invalid { at, message }) => Some((
            Severity::Warning,
            *at,
            format!("{message} (Elasticsearch 9.x rejects it, 8.19 accepts it)"),
        )),
        _ => None,
    };
    if let Some((severity, at, message)) = invalid {
        return vec![Problem {
            severity,
            at: Some(at),
            message: format!("invalid Lucene regular expression: {message}"),
            syntax: true,
        }];
    }
    let mut out = Vec::new();
    let rejected9 = es9 == Verdict::TooComplex;
    let rejected8 = matches!(es8, Verdict::TooComplex | Verdict::TooLarge);
    let cause = if es8 == Verdict::TooLarge && !rejected9 {
        "its matches can be longer than Lucene 9's 1000-state recursion limit"
    } else {
        "determinizing it needs more work than `max_determinized_states` (10000) allows; narrow bounded repeats such as `.{1,128}`"
    };
    match (rejected8, rejected9) {
        (true, true) => out.push(Problem {
            severity: Severity::Error,
            at: None,
            message: format!("Elasticsearch cannot compile this regular expression: {cause}"),
            syntax: false,
        }),
        (true, false) | (false, true) => out.push(Problem {
            severity: Severity::Warning,
            at: None,
            message: format!(
                "Elasticsearch {} cannot compile this regular expression ({cause}); {} accepts it",
                if rejected9 { "9.x" } else { "8.19" },
                if rejected9 { "8.19" } else { "9.x" },
            ),
            syntax: false,
        }),
        (false, false) => {}
    }
    // Elasticsearch's default `index.max_regex_length`.
    if body.encode_utf16().count() > 1000 {
        out.push(Problem {
            severity: Severity::Warning,
            at: None,
            message: "this regular expression is longer than Elasticsearch's default `index.max_regex_length` (1000), so the query fails unless the index raises it".into(),
            syntax: false,
        });
    }
    out
}

/// The compile verdict, or `None` when the construction is too large (or
/// uses `<n-m>`) to evaluate here.
fn too_complex(re: &Re, stack: Stack) -> Option<Verdict> {
    WORK.with(|w| w.set(0));
    let built = match stack {
        Stack::Es9 => re.to_automaton(),
        Stack::Es8 => re.to_automaton_9(),
    };
    let a = match built {
        Ok(a) => a,
        Err(Build::TooComplex) => return Some(Verdict::TooComplex),
        Err(Build::Unknown) => return None,
    };
    if stack == Stack::Es9 {
        return match determinize(&a, DETERMINIZE_WORK_LIMIT) {
            Ok(_) => Some(Verdict::Ok),
            Err(Determinize::TooComplex) => Some(Verdict::TooComplex),
            Err(Determinize::OverBudget) => None,
        };
    }
    // Lucene 9's CompiledAutomaton: empty and total automata are done; the
    // rest is determinized, a single string is done, and the rest goes
    // through a recursive finiteness check limited to 1000 levels.
    if a.len() == 0 || is_empty_language(&a) || is_total(&a) {
        return Some(Verdict::Ok);
    }
    let det = match determinize(&a, DETERMINIZE_WORK_LIMIT) {
        Ok(det) => det,
        Err(Determinize::TooComplex) => return Some(Verdict::TooComplex),
        Err(Determinize::OverBudget) => return None,
    };
    if is_singleton(&det) {
        return Some(Verdict::Ok);
    }
    Some(if finite_check_overflows(&det) {
        Verdict::TooLarge
    } else {
        Verdict::Ok
    })
}

/// Lucene's `getSingleton`: the automaton accepts exactly one string.
fn is_singleton(a: &Automaton) -> bool {
    let mut visited = vec![false; a.len()];
    let mut s = 0;
    loop {
        visited[s] = true;
        if !a.accept[s] {
            if let [(min, max, d)] = a.trans[s][..] {
                if min == max && !visited[d] {
                    s = d;
                    continue;
                }
            }
        } else if a.trans[s].is_empty() {
            return true;
        }
        return false;
    }
}

/// Lucene 9's recursive `isFinite` walks transitions depth first, in label
/// order, and throws past 1000 levels unless it finds a cycle first.
fn finite_check_overflows(a: &Automaton) -> bool {
    const MAX_RECURSION_LEVEL: usize = 1000;
    let n = a.len();
    let mut path = vec![false; n];
    let mut visited = vec![false; n];
    // (state, next transition index); the level is the stack depth - 1.
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    path[0] = true;
    while let Some(&mut (state, ref mut next)) = stack.last_mut() {
        if let Some(&(_, _, d)) = a.trans[state].get(*next) {
            *next += 1;
            if path[d] {
                return false; // a cycle: infinite, no overflow
            }
            if !visited[d] {
                if stack.len() > MAX_RECURSION_LEVEL {
                    return true;
                }
                path[d] = true;
                stack.push((d, 0));
            }
        } else {
            path[state] = false;
            visited[state] = true;
            stack.pop();
        }
    }
    false
}

/// Runs of `+`, `*`, and `?` outside classes and quoted strings become one
/// quantifier: the same one when they repeat, otherwise `*`.
pub fn collapse_quantifiers(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    let (mut in_class, mut in_quote, mut prev_quantifier) = (false, false, false);
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().is_some() {
            out.push(c);
            out.push(chars.next().unwrap_or_default());
            prev_quantifier = false;
        } else if in_quote {
            out.push(c);
            in_quote = c != '"';
            prev_quantifier = false;
        } else if in_class {
            out.push(c);
            in_class = c != ']';
            prev_quantifier = false;
        } else if matches!(c, '+' | '*' | '?') {
            if prev_quantifier {
                let last = out.pop().unwrap_or(c);
                out.push(if last == c { c } else { '*' });
            } else {
                out.push(c);
                prev_quantifier = true;
            }
        } else {
            in_quote = c == '"';
            in_class = c == '[';
            out.push(c);
            prev_quantifier = false;
        }
    }
    out
}

/// The parsed expression, as Lucene's `RegExp` tree.
#[derive(Debug, Clone)]
enum Re {
    Union(Box<Re>, Box<Re>),
    Concat(Box<Re>, Box<Re>),
    Intersection(Box<Re>, Box<Re>),
    Optional(Box<Re>),
    Repeat(Box<Re>),
    RepeatMin(Box<Re>, u32),
    RepeatMinMax(Box<Re>, u32, u32),
    /// The negated part of `[^...]`.
    Complement(Box<Re>),
    /// `~x`.
    DeprecatedComplement(Box<Re>),
    Char(u32),
    CharRange(u32, u32),
    CharClass(Vec<(u32, u32)>),
    AnyChar,
    Empty,
    Str(Vec<u32>),
    AnyString,
    Automaton(String),
    Interval,
}

impl Re {
    fn first_automaton_name(&self) -> Option<&str> {
        match self {
            Re::Automaton(name) => Some(name),
            Re::Union(a, b) | Re::Concat(a, b) | Re::Intersection(a, b) => a
                .first_automaton_name()
                .or_else(|| b.first_automaton_name()),
            Re::Optional(a)
            | Re::Repeat(a)
            | Re::RepeatMin(a, _)
            | Re::RepeatMinMax(a, _, _)
            | Re::Complement(a)
            | Re::DeprecatedComplement(a) => a.first_automaton_name(),
            _ => None,
        }
    }

    fn is_char_or_string(&self) -> bool {
        matches!(self, Re::Char(_) | Re::Str(_))
    }

    fn string_parts(&self) -> Vec<u32> {
        match self {
            Re::Char(c) => vec![*c],
            Re::Str(s) => s.clone(),
            _ => Vec::new(),
        }
    }
}

/// Lucene merges adjacent characters and strings into one string node.
fn make_concatenation(e1: Re, e2: Re) -> Re {
    if e1.is_char_or_string() && e2.is_char_or_string() {
        let mut s = e1.string_parts();
        s.extend(e2.string_parts());
        return Re::Str(s);
    }
    if let Re::Concat(a, b) = &e1 {
        if b.is_char_or_string() && e2.is_char_or_string() {
            let mut s = b.string_parts();
            s.extend(e2.string_parts());
            return Re::Concat(a.clone(), Box::new(Re::Str(s)));
        }
    }
    if let Re::Concat(a, b) = &e2 {
        if e1.is_char_or_string() && a.is_char_or_string() {
            let mut s = e1.string_parts();
            s.extend(a.string_parts());
            return Re::Concat(Box::new(Re::Str(s)), b.clone());
        }
    }
    Re::Concat(Box::new(e1), Box::new(e2))
}

struct ParseError {
    at: usize,
    message: String,
}

type Parsed = Result<Re, ParseError>;

struct Parser<'a> {
    s: &'a [char],
    pos: usize,
    /// Lucene 9 reads `[\x-y]` as a range; Lucene 10 reads the escaped
    /// character on its own.
    lucene9: bool,
}

impl<'a> Parser<'a> {
    fn new(s: &'a [char], stack: Stack) -> Self {
        Self {
            s,
            pos: 0,
            lucene9: stack == Stack::Es8,
        }
    }

    fn err<T>(&self, message: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            at: self.pos.min(self.s.len()),
            message: message.into(),
        })
    }

    fn more(&self) -> bool {
        self.pos < self.s.len()
    }

    fn peek(&self, set: &str) -> bool {
        self.more() && set.contains(self.s[self.pos])
    }

    fn peek_backslash_or_letter(&self) -> bool {
        self.more() && (self.s[self.pos] == '\\' || self.s[self.pos].is_ascii_alphabetic())
    }

    fn eat(&mut self, c: char) -> bool {
        if self.more() && self.s[self.pos] == c {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Result<u32, ParseError> {
        if !self.more() {
            return self.err("the expression ends too early");
        }
        let c = self.s[self.pos];
        self.pos += 1;
        Ok(c as u32)
    }

    fn parse(mut self) -> Parsed {
        if self.s.is_empty() {
            return Ok(Re::Str(Vec::new()));
        }
        let e = self.union()?;
        if self.more() {
            return self.err(format!("unexpected `{}`", self.s[self.pos]));
        }
        Ok(e)
    }

    fn union(&mut self) -> Parsed {
        let mut e = self.intersection()?;
        while self.eat('|') {
            let r = self.intersection()?;
            e = Re::Union(Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn intersection(&mut self) -> Parsed {
        let mut e = self.concatenation()?;
        while self.eat('&') {
            let r = self.concatenation()?;
            e = Re::Intersection(Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn concatenation(&mut self) -> Parsed {
        let mut e = self.repeat()?;
        while self.more() && !self.peek(")|&") {
            let r = self.repeat()?;
            e = make_concatenation(e, r);
        }
        Ok(e)
    }

    fn repeat(&mut self) -> Parsed {
        let mut e = self.complement()?;
        while self.peek("?*+{") {
            if self.eat('?') {
                e = Re::Optional(Box::new(e));
            } else if self.eat('*') {
                e = Re::Repeat(Box::new(e));
            } else if self.eat('+') {
                e = Re::RepeatMin(Box::new(e), 1);
            } else if self.eat('{') {
                let n = self.integer()?.map_or_else(
                    || self.err("`{` must be followed by a number (`{n}`, `{n,}`, or `{n,m}`)"),
                    Ok,
                )?;
                let m = if self.eat(',') {
                    self.integer()?
                } else {
                    Some(n)
                };
                if !self.eat('}') {
                    return self.err("expected `}` to close the repetition");
                }
                e = match m {
                    Some(m) if n > m => {
                        return self.err(format!("repetition `{{{n},{m}}}` is out of order"));
                    }
                    Some(m) => Re::RepeatMinMax(Box::new(e), n, m),
                    None => Re::RepeatMin(Box::new(e), n),
                };
            }
        }
        Ok(e)
    }

    /// Digits for `{n,m}`: `None` when there are none.
    fn integer(&mut self) -> Result<Option<u32>, ParseError> {
        let start = self.pos;
        while self.peek("0123456789") {
            self.pos += 1;
        }
        if start == self.pos {
            return Ok(None);
        }
        let digits: String = self.s[start..self.pos].iter().collect();
        match digits.parse::<i32>() {
            Ok(n) => Ok(Some(n as u32)),
            Err(_) => self.err(format!("repetition count `{digits}` is too large")),
        }
    }

    fn complement(&mut self) -> Parsed {
        if self.eat('~') {
            Ok(Re::DeprecatedComplement(Box::new(self.complement()?)))
        } else {
            self.char_class_exp()
        }
    }

    fn char_class_exp(&mut self) -> Parsed {
        if !self.eat('[') {
            return self.simple();
        }
        let negate = self.eat('^');
        let mut e = self.char_classes()?;
        if negate {
            e = Re::Intersection(Box::new(Re::AnyChar), Box::new(Re::Complement(Box::new(e))));
        }
        if !self.eat(']') {
            return self.err("expected `]` to close the character class");
        }
        Ok(e)
    }

    fn char_classes(&mut self) -> Parsed {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        loop {
            if self.lucene9 {
                self.char_class_9(&mut ranges)?;
            } else if self.eat('\\') {
                if self.peek_backslash_or_letter() {
                    self.predefined(&mut ranges)?;
                } else {
                    let c = self.next()?;
                    ranges.push((c, c));
                }
            } else {
                let c = self.char_exp()?;
                if self.eat('-') {
                    let to = self.char_exp()?;
                    ranges.push((c, to));
                } else {
                    ranges.push((c, c));
                }
            }
            if !(self.more() && !self.peek("]")) {
                break;
            }
        }
        for &(from, to) in &ranges {
            if from > to {
                return self.err(format!(
                    "character range `{}-{}` is out of order",
                    char::from_u32(from).unwrap_or('?'),
                    char::from_u32(to).unwrap_or('?')
                ));
            }
        }
        Ok(match ranges.as_slice() {
            [(a, b)] if a == b => Re::Char(*a),
            [(a, b)] => Re::CharRange(*a, *b),
            _ => Re::CharClass(ranges),
        })
    }

    /// Lucene 9's `parseCharClass`: a predefined class, an escaped
    /// backslash, or a character (escaped or not) that may start a range.
    fn char_class_9(&mut self, ranges: &mut Vec<(u32, u32)>) -> Result<(), ParseError> {
        if self.eat('\\') && self.peek_backslash_or_letter() {
            return self.predefined(ranges);
        }
        let c = self.char_exp()?;
        if self.eat('-') {
            let to = self.char_exp()?;
            if c > to {
                return self.err(format!(
                    "character range `{}-{}` is out of order",
                    char::from_u32(c).unwrap_or('?'),
                    char::from_u32(to).unwrap_or('?')
                ));
            }
            ranges.push((c, to));
        } else {
            ranges.push((c, c));
        }
        Ok(())
    }

    /// `\\`, `\d \D \s \S \w \W`; any other letter is an error.
    fn predefined(&mut self, ranges: &mut Vec<(u32, u32)>) -> Result<(), ParseError> {
        let c = self.s[self.pos];
        let (lo, hi) = (MIN_CODE_POINT, MAX_CODE_POINT);
        let set: &[(u32, u32)] = match c {
            '\\' => &[(b'\\' as u32, b'\\' as u32)],
            'd' => &[(b'0' as u32, b'9' as u32)],
            'D' => &[(lo, b'0' as u32 - 1), (b'9' as u32 + 1, hi)],
            's' => &[(9, 10), (13, 13), (32, 32)],
            'S' => &[(lo, 8), (11, 12), (14, 31), (33, hi)],
            'w' => &[(48, 57), (65, 90), (95, 95), (97, 122)],
            'W' => &[(lo, 47), (58, 64), (91, 94), (96, 96), (123, hi)],
            _ => {
                return self.err(format!(
                    "`\\{c}` is not a Lucene regexp escape; only `\\d \\D \\s \\S \\w \\W` and escaped punctuation are"
                ));
            }
        };
        ranges.extend_from_slice(set);
        self.pos += 1;
        Ok(())
    }

    fn simple(&mut self) -> Parsed {
        if self.eat('.') {
            return Ok(Re::AnyChar);
        }
        if self.eat('#') {
            return Ok(Re::Empty);
        }
        if self.eat('@') {
            return Ok(Re::AnyString);
        }
        if self.eat('"') {
            let start = self.pos;
            while self.more() && !self.peek("\"") {
                self.pos += 1;
            }
            if !self.eat('"') {
                self.pos = start - 1;
                return self
                    .err("`\"` starts a quoted literal that is never closed; escape it as `\\\"`");
            }
            return Ok(Re::Str(
                self.s[start..self.pos - 1]
                    .iter()
                    .map(|&c| c as u32)
                    .collect(),
            ));
        }
        if self.eat('(') {
            if self.eat(')') {
                return Ok(Re::Str(Vec::new()));
            }
            let open = self.pos - 1;
            let e = self.union()?;
            if !self.eat(')') {
                let message = if self.more() {
                    format!("expected `)` to close the group opened at position {open}")
                } else {
                    format!("the group opened at position {open} is never closed")
                };
                return self.err(message);
            }
            return Ok(e);
        }
        if self.eat('<') {
            let open = self.pos - 1;
            let start = self.pos;
            while self.more() && !self.peek(">") {
                self.pos += 1;
            }
            if !self.eat('>') {
                self.pos = open;
                return self.err(
                    "`<` starts a numeric interval `<n-m>` that is never closed; escape it as `\\<`",
                );
            }
            let body: String = self.s[start..self.pos - 1].iter().collect();
            return match body.find('-') {
                None => Ok(Re::Automaton(body)),
                Some(i) => {
                    let (lo, hi) = (&body[..i], &body[i + 1..]);
                    let int = |s: &str| {
                        let digits = s.strip_prefix('+').unwrap_or(s);
                        !digits.is_empty()
                            && digits.chars().all(|c| c.is_ascii_digit())
                            && digits.parse::<i32>().is_ok()
                    };
                    if !body.is_ascii() || (int(lo) && int(hi)) {
                        Ok(Re::Interval)
                    } else {
                        self.pos = open;
                        self.err(format!(
                            "`<{body}>` is not a numeric interval `<n-m>`; escape `<` as `\\<` for a literal"
                        ))
                    }
                }
            };
        }
        // `\` before a letter is a character class or an error; before
        // anything else it escapes that character.
        if self.eat('\\') {
            if self.peek_backslash_or_letter() {
                let mut ranges = Vec::new();
                self.predefined(&mut ranges)?;
                return Ok(Re::CharClass(ranges));
            }
            return Ok(Re::Char(self.next()?));
        }
        Ok(Re::Char(self.next()?))
    }

    fn char_exp(&mut self) -> Result<u32, ParseError> {
        self.eat('\\');
        self.next()
    }
}

const MIN_CODE_POINT: u32 = 0;

// ---------------------------------------------------------------------------
// Automata, built the way Lucene builds them (epsilon-free NFAs).

#[derive(Debug, Clone, Default)]
struct Automaton {
    accept: Vec<bool>,
    /// Per state: `(min, max, dest)`, normalized like Lucene's `finishState`.
    trans: Vec<Vec<(u32, u32, usize)>>,
}

enum Build {
    TooComplex,
    Unknown,
}

type Built = Result<Automaton, Build>;

impl Automaton {
    fn len(&self) -> usize {
        self.accept.len()
    }

    fn create_state(&mut self) -> usize {
        spend(1);
        self.accept.push(false);
        self.trans.push(Vec::new());
        self.accept.len() - 1
    }

    fn add(&mut self, from: usize, to: usize, min: u32, max: u32) {
        spend(1);
        self.trans[from].push((min, max, to));
    }

    /// Lucene's `copy`: append `other`'s states and transitions.
    fn copy_from(&mut self, other: &Automaton) {
        let offset = self.len();
        for s in 0..other.len() {
            self.create_state();
            self.accept[offset + s] = other.accept[s];
        }
        for s in 0..other.len() {
            for &(min, max, d) in &other.trans[s] {
                self.add(offset + s, offset + d, min, max);
            }
        }
    }

    /// Copy `dest`'s transitions (and acceptance) onto `source`.
    fn add_epsilon(&mut self, source: usize, dest: usize) {
        if dest >= self.len() {
            return;
        }
        let ts = self.trans[dest].clone();
        for (min, max, d) in ts {
            self.add(source, d, min, max);
        }
        if self.accept[dest] {
            self.accept[source] = true;
        }
    }

    /// Merge touching ranges to the same state, then sort by label.
    fn finish(mut self) -> Automaton {
        spend(self.trans.iter().map(|t| t.len() as u64).sum());
        for ts in &mut self.trans {
            ts.sort_by_key(|&(min, max, d)| (d, min, max));
            let mut merged: Vec<(u32, u32, usize)> = Vec::with_capacity(ts.len());
            for &(min, max, d) in ts.iter() {
                if let Some(last) = merged.last_mut() {
                    if last.2 == d && min <= last.1.saturating_add(1) {
                        last.1 = last.1.max(max);
                        continue;
                    }
                }
                merged.push((min, max, d));
            }
            merged.sort_by_key(|&(min, max, d)| (min, max, d));
            *ts = merged;
        }
        self
    }

    fn is_deterministic(&self) -> bool {
        self.trans
            .iter()
            .all(|ts| ts.windows(2).all(|w| w[1].0 > w[0].1))
    }

    fn guard(self) -> Built {
        if self.len() > MAX_STATES || over_budget() {
            Err(Build::Unknown)
        } else {
            Ok(self)
        }
    }
}

fn make_empty() -> Automaton {
    Automaton::default()
}

fn make_empty_string() -> Automaton {
    let mut a = Automaton::default();
    let s = a.create_state();
    a.accept[s] = true;
    a
}

fn make_class(ranges: &[(u32, u32)]) -> Automaton {
    if ranges.is_empty() {
        return make_empty();
    }
    let mut a = Automaton::default();
    let s1 = a.create_state();
    let s2 = a.create_state();
    a.accept[s2] = true;
    for &(min, max) in ranges {
        a.add(s1, s2, min, max);
    }
    a.finish()
}

fn make_string(s: &[u32]) -> Automaton {
    let mut a = Automaton::default();
    let mut last = a.create_state();
    for &c in s {
        let next = a.create_state();
        a.add(last, next, c, c);
        last = next;
    }
    a.accept[last] = true;
    a.finish()
}

fn make_any_string() -> Automaton {
    let mut a = make_empty_string();
    a.add(0, 0, MIN_CODE_POINT, MAX_CODE_POINT);
    a.finish()
}

fn reachable_from_initial(a: &Automaton) -> Vec<bool> {
    let mut live = vec![false; a.len()];
    if a.len() == 0 {
        return live;
    }
    let mut work = vec![0usize];
    live[0] = true;
    while let Some(s) = work.pop() {
        for &(_, _, d) in &a.trans[s] {
            if !live[d] {
                live[d] = true;
                work.push(d);
            }
        }
    }
    live
}

fn reaching_accept(a: &Automaton) -> Vec<bool> {
    let mut rev: Vec<Vec<usize>> = vec![Vec::new(); a.len()];
    for (s, ts) in a.trans.iter().enumerate() {
        for &(_, _, d) in ts {
            rev[d].push(s);
        }
    }
    let mut live = a.accept.clone();
    let mut work: Vec<usize> = (0..a.len()).filter(|&s| a.accept[s]).collect();
    while let Some(s) = work.pop() {
        for &p in &rev[s] {
            if !live[p] {
                live[p] = true;
                work.push(p);
            }
        }
    }
    live
}

fn remove_dead_states(a: Automaton) -> Automaton {
    let from = reachable_from_initial(&a);
    let to = reaching_accept(&a);
    let live: Vec<bool> = from.iter().zip(&to).map(|(x, y)| *x && *y).collect();
    if live.iter().all(|l| *l) {
        return a;
    }
    let mut map = vec![usize::MAX; a.len()];
    let mut out = Automaton::default();
    for s in 0..a.len() {
        if live[s] {
            map[s] = out.create_state();
            out.accept[map[s]] = a.accept[s];
        }
    }
    for s in 0..a.len() {
        if live[s] {
            for &(min, max, d) in &a.trans[s] {
                if live[d] {
                    out.add(map[s], map[d], min, max);
                }
            }
        }
    }
    out.finish()
}

fn merge_accept_states_with_no_transition(a: Automaton) -> Automaton {
    let combined: Vec<usize> = (0..a.len())
        .filter(|&s| a.accept[s] && a.trans[s].is_empty())
        .collect();
    if combined.len() <= 1 {
        return a;
    }
    let remap = |s: usize| match combined.binary_search(&s) {
        Ok(_) => combined[0],
        Err(idx) if idx <= 1 => s,
        Err(idx) => s - (idx - 1),
    };
    let mut out = Automaton::default();
    for s in 0..a.len() {
        let r = remap(s);
        while out.len() <= r {
            out.create_state();
        }
        if a.accept[s] {
            out.accept[r] = true;
        }
    }
    for s in 0..a.len() {
        for &(min, max, d) in &a.trans[s] {
            out.add(remap(s), remap(d), min, max);
        }
    }
    out.finish()
}

fn concatenate(list: &[Automaton]) -> Built {
    if list.iter().any(|a| a.len() == 0) {
        return Ok(make_empty());
    }
    let total: usize = list.iter().map(Automaton::len).sum();
    if total > MAX_STATES {
        return Err(Build::Unknown);
    }
    let mut result = Automaton::default();
    for _ in 0..total {
        result.create_state();
    }
    let mut offset = 0;
    for (i, a) in list.iter().enumerate() {
        if over_budget() {
            return Err(Build::Unknown);
        }
        let n = a.len();
        for s in 0..n {
            for &(min, max, d) in &a.trans[s] {
                result.add(offset + s, offset + d, min, max);
            }
            if a.accept[s] {
                let mut follow = list.get(i + 1);
                let mut follow_offset = offset;
                let mut upto = i + 1;
                loop {
                    match follow {
                        Some(f) => {
                            for &(min, max, d) in &f.trans[0] {
                                result.add(offset + s, follow_offset + n + d, min, max);
                            }
                            if f.accept[0] {
                                follow_offset += f.len();
                                follow = list.get(upto + 1);
                                upto += 1;
                            } else {
                                break;
                            }
                        }
                        None => {
                            result.accept[offset + s] = true;
                            break;
                        }
                    }
                }
            }
        }
        offset += n;
    }
    if result.len() == 0 {
        result.create_state();
    }
    Ok(remove_dead_states(result.finish()))
}

fn union(list: &[Automaton]) -> Built {
    let mut result = Automaton::default();
    result.create_state();
    for a in list {
        result.copy_from(a);
    }
    let mut offset = 1;
    for a in list {
        if a.len() == 0 {
            continue;
        }
        result.add_epsilon(0, offset);
        offset += a.len();
    }
    let result = result.guard()?.finish();
    Ok(merge_accept_states_with_no_transition(remove_dead_states(
        result,
    )))
}

fn optional(a: Automaton) -> Automaton {
    if a.len() > 0 && a.accept[0] {
        return a;
    }
    let to_initial = a.trans.iter().flatten().any(|&(_, _, d)| d == 0);
    if !to_initial {
        let mut result = a;
        if result.len() == 0 {
            result.create_state();
        }
        result.accept[0] = true;
        return result;
    }
    let mut result = Automaton::default();
    result.create_state();
    result.accept[0] = true;
    result.copy_from(&a);
    result.add_epsilon(0, 1);
    result.finish()
}

fn repeat_star(a: Automaton) -> Automaton {
    if a.len() == 0 {
        return a;
    }
    if a.accept[0] && a.accept.iter().filter(|x| **x).count() == 1 {
        return a;
    }
    let mut b = Automaton::default();
    b.create_state();
    b.accept[0] = true;
    let mut map = vec![0usize; a.len()];
    for s in 0..a.len() {
        if !a.accept[s] {
            map[s] = b.create_state();
        } else if a.trans[s].is_empty() {
            map[s] = 0;
        } else {
            map[s] = b.create_state();
            b.accept[map[s]] = true;
        }
    }
    for s in 0..a.len() {
        for &(min, max, d) in &a.trans[s] {
            b.add(map[s], map[d], min, max);
        }
    }
    for &(min, max, d) in &a.trans[0] {
        b.add(0, map[d], min, max);
    }
    for s in 0..a.len() {
        if a.accept[s] && map[s] != 0 {
            for &(min, max, d) in &a.trans[0] {
                b.add(map[s], map[d], min, max);
            }
        }
    }
    remove_dead_states(b.finish())
}

fn repeat_min(a: Automaton, count: u32) -> Built {
    if count == 0 {
        return Ok(repeat_star(a));
    }
    if (count as usize).saturating_mul(a.len().max(1)) > MAX_STATES {
        return Err(Build::Unknown);
    }
    let mut list = vec![a.clone(); count as usize];
    list.push(repeat_star(a));
    concatenate(&list)
}

fn repeat_min_max(a: Automaton, min: u32, max: u32) -> Built {
    if min > max {
        return Ok(make_empty());
    }
    if (max as usize).saturating_mul(a.len().max(1)) > MAX_STATES {
        return Err(Build::Unknown);
    }
    let b = match min {
        0 => make_empty_string(),
        1 => a.clone(),
        _ => concatenate(&vec![a.clone(); min as usize])?,
    };
    let mut prev_accept: Vec<usize> = (0..b.len()).filter(|&s| b.accept[s]).collect();
    let mut builder = Automaton::default();
    builder.copy_from(&b);
    for _ in min..max {
        let n = builder.len();
        builder.copy_from(&a);
        for &s in &prev_accept {
            builder.add_epsilon(s, n);
        }
        prev_accept = (0..a.len())
            .filter(|&s| a.accept[s])
            .map(|s| s + n)
            .collect();
    }
    Ok(remove_dead_states(builder.finish()))
}

fn totalize(a: &Automaton) -> Automaton {
    let mut result = Automaton::default();
    for s in 0..a.len() {
        result.create_state();
        result.accept[s] = a.accept[s];
    }
    let dead = result.create_state();
    result.add(dead, dead, MIN_CODE_POINT, MAX_CODE_POINT);
    for s in 0..a.len() {
        let mut maxi = MIN_CODE_POINT;
        for &(min, max, d) in &a.trans[s] {
            result.add(s, d, min, max);
            if min > maxi {
                result.add(s, dead, maxi, min - 1);
            }
            if max + 1 > maxi {
                maxi = max + 1;
            }
        }
        if maxi <= MAX_CODE_POINT {
            result.add(s, dead, maxi, MAX_CODE_POINT);
        }
    }
    result.finish()
}

fn complement(a: &Automaton, limit: u64) -> Built {
    let det = determinize(a, limit).map_err(|e| match e {
        Determinize::TooComplex => Build::TooComplex,
        Determinize::OverBudget => Build::Unknown,
    })?;
    let mut t = totalize(&det);
    for acc in &mut t.accept {
        *acc = !*acc;
    }
    Ok(remove_dead_states(t))
}

fn intersection(a1: &Automaton, a2: &Automaton) -> Built {
    if a1.len() == 0 {
        return Ok(a1.clone());
    }
    if a2.len() == 0 {
        return Ok(a2.clone());
    }
    let mut c = Automaton::default();
    c.create_state();
    let mut ids: std::collections::HashMap<(usize, usize), usize> =
        std::collections::HashMap::new();
    ids.insert((0, 0), 0);
    let mut work = std::collections::VecDeque::from([(0usize, 0usize, 0usize)]);
    while let Some((s1, s2, s)) = work.pop_front() {
        c.accept[s] = a1.accept[s1] && a2.accept[s2];
        let (t1, t2) = (&a1.trans[s1], &a2.trans[s2]);
        let mut b2 = 0;
        for &(min1, max1, d1) in t1 {
            while b2 < t2.len() && t2[b2].1 < min1 {
                b2 += 1;
            }
            let mut n2 = b2;
            while n2 < t2.len() && max1 >= t2[n2].0 {
                let (min2, max2, d2) = t2[n2];
                if max2 >= min1 {
                    let r = match ids.get(&(d1, d2)) {
                        Some(&r) => r,
                        None => {
                            let r = c.create_state();
                            if r > MAX_STATES {
                                return Err(Build::Unknown);
                            }
                            ids.insert((d1, d2), r);
                            work.push_back((d1, d2, r));
                            r
                        }
                    };
                    c.add(s, r, min1.max(min2), max1.min(max2));
                }
                n2 += 1;
            }
        }
    }
    Ok(remove_dead_states(c.finish()))
}

enum Determinize {
    TooComplex,
    OverBudget,
}

/// Lucene's subset construction. The effort is the size of every state set
/// it visits; it fails when that reaches ten times `limit`.
fn determinize(a: &Automaton, limit: u64) -> Result<Automaton, Determinize> {
    if a.is_deterministic() || a.len() <= 1 {
        return Ok(a.clone());
    }
    let effort_limit = limit * 10;
    let mut effort = 0u64;
    let mut out = Automaton::default();
    let mut ids: std::collections::HashMap<Vec<usize>, usize> = std::collections::HashMap::new();
    let mut work: std::collections::VecDeque<(Vec<usize>, usize)> =
        std::collections::VecDeque::new();
    out.create_state();
    out.accept[0] = a.accept[0];
    ids.insert(vec![0], 0);
    work.push_back((vec![0], 0));
    while let Some((set, r)) = work.pop_front() {
        effort += set.len() as u64;
        if effort >= effort_limit {
            return Err(Determinize::TooComplex);
        }
        spend(set.len() as u64);
        if over_budget() {
            return Err(Determinize::OverBudget);
        }
        // Interval end points: +1 opens a destination, -1 closes it.
        let mut points: Vec<(u64, usize, i32)> = Vec::new();
        for &s in &set {
            for &(min, max, d) in &a.trans[s] {
                points.push((min as u64, d, 1));
                points.push((max as u64 + 1, d, -1));
            }
        }
        if points.is_empty() {
            continue;
        }
        spend(points.len() as u64);
        if over_budget() {
            return Err(Determinize::OverBudget);
        }
        points.sort_unstable_by_key(|p| p.0);
        let mut counts: std::collections::BTreeMap<usize, u32> = std::collections::BTreeMap::new();
        let mut last = 0u64;
        let mut i = 0;
        while i < points.len() {
            let point = points[i].0;
            if !counts.is_empty() {
                let target: Vec<usize> = counts.keys().copied().collect();
                let q = match ids.get(&target) {
                    Some(&q) => q,
                    None => {
                        let q = out.create_state();
                        out.accept[q] = target.iter().any(|&s| a.accept[s]);
                        ids.insert(target.clone(), q);
                        work.push_back((target, q));
                        q
                    }
                };
                out.add(r, q, last as u32, (point - 1) as u32);
            }
            while i < points.len() && points[i].0 == point {
                let (_, d, delta) = points[i];
                let entry = counts.entry(d).or_insert(0);
                if delta > 0 {
                    *entry += 1;
                } else {
                    *entry -= 1;
                    if *entry == 0 {
                        counts.remove(&d);
                    }
                }
                i += 1;
            }
            last = point;
        }
    }
    Ok(out.finish())
}

// Lucene 9.12 (Elasticsearch 8.19) variants. They skip some dead-state
// pruning and minimize after most steps, which changes the effort the final
// determinization counts.

fn concatenate_9(list: &[Automaton]) -> Built {
    let total: usize = list.iter().map(Automaton::len).sum();
    if total > MAX_STATES {
        return Err(Build::Unknown);
    }
    let mut result = Automaton::default();
    for a in list {
        if a.len() == 0 {
            return Ok(result.finish());
        }
        for _ in 0..a.len() {
            result.create_state();
        }
    }
    let mut offset = 0;
    for (i, a) in list.iter().enumerate() {
        if over_budget() {
            return Err(Build::Unknown);
        }
        let n = a.len();
        for s in 0..n {
            for &(min, max, d) in &a.trans[s] {
                result.add(offset + s, offset + d, min, max);
            }
            if a.accept[s] {
                let mut follow = list.get(i + 1);
                let mut follow_offset = offset;
                let mut upto = i + 1;
                loop {
                    match follow {
                        Some(f) => {
                            for &(min, max, d) in &f.trans[0] {
                                result.add(offset + s, follow_offset + n + d, min, max);
                            }
                            if f.accept[0] {
                                follow_offset += f.len();
                                follow = list.get(upto + 1);
                                upto += 1;
                            } else {
                                break;
                            }
                        }
                        None => {
                            result.accept[offset + s] = true;
                            break;
                        }
                    }
                }
            }
        }
        offset += n;
    }
    if result.len() == 0 {
        result.create_state();
    }
    Ok(result.finish())
}

fn union_9(list: &[Automaton]) -> Built {
    let mut result = Automaton::default();
    result.create_state();
    for a in list {
        result.copy_from(a);
    }
    let mut offset = 1;
    for a in list {
        if a.len() == 0 {
            continue;
        }
        result.add_epsilon(0, offset);
        offset += a.len();
    }
    Ok(remove_dead_states(result.guard()?.finish()))
}

fn optional_9(a: Automaton) -> Automaton {
    let mut result = Automaton::default();
    result.create_state();
    result.accept[0] = true;
    if a.len() > 0 {
        result.copy_from(&a);
        result.add_epsilon(0, 1);
    }
    result.finish()
}

fn repeat_star_9(a: Automaton) -> Automaton {
    if a.len() == 0 {
        return a;
    }
    let mut b = Automaton::default();
    b.create_state();
    b.accept[0] = true;
    b.copy_from(&a);
    for &(min, max, d) in &a.trans[0] {
        b.add(0, d + 1, min, max);
    }
    for s in 0..a.len() {
        if a.accept[s] {
            for &(min, max, d) in &a.trans[0] {
                b.add(s + 1, d + 1, min, max);
            }
        }
    }
    b.finish()
}

fn repeat_min_9(a: Automaton, count: u32) -> Built {
    if count == 0 {
        return Ok(repeat_star_9(a));
    }
    if (count as usize).saturating_mul(a.len().max(1)) > MAX_STATES {
        return Err(Build::Unknown);
    }
    let mut list = vec![a.clone(); count as usize];
    list.push(repeat_star_9(a));
    concatenate_9(&list)
}

fn repeat_min_max_9(a: Automaton, min: u32, max: u32) -> Built {
    if min > max {
        return Ok(make_empty());
    }
    if (max as usize).saturating_mul(a.len().max(1)) > MAX_STATES {
        return Err(Build::Unknown);
    }
    let b = match min {
        0 => make_empty_string(),
        1 => a.clone(),
        _ => concatenate_9(&vec![a.clone(); min as usize])?,
    };
    let mut prev_accept: Vec<usize> = (0..b.len()).filter(|&s| b.accept[s]).collect();
    let mut builder = Automaton::default();
    builder.copy_from(&b);
    for _ in min..max {
        let n = builder.len();
        builder.copy_from(&a);
        for &s in &prev_accept {
            builder.add_epsilon(s, n);
        }
        prev_accept = (0..a.len())
            .filter(|&s| a.accept[s])
            .map(|s| s + n)
            .collect();
    }
    Ok(builder.finish())
}

fn is_empty_language(a: &Automaton) -> bool {
    let from = reachable_from_initial(a);
    !(0..a.len()).any(|s| from[s] && a.accept[s])
}

fn is_total(a: &Automaton) -> bool {
    a.len() > 0 && a.accept[0] && a.trans[0] == [(MIN_CODE_POINT, MAX_CODE_POINT, 0)]
}

/// Lucene 9's `minimize`: determinize (counting effort), then the minimal
/// DFA without its dead state. The minimal DFA is unique up to renumbering,
/// so Moore's refinement gives the automaton Hopcroft's algorithm gives.
fn minimize_9(a: Automaton) -> Built {
    if a.len() == 0 || (!a.accept[0] && a.trans[0].is_empty()) {
        return Ok(make_empty());
    }
    let det = determinize(&a, DETERMINIZE_WORK_LIMIT).map_err(|e| match e {
        Determinize::TooComplex => Build::TooComplex,
        Determinize::OverBudget => Build::Unknown,
    })?;
    if is_total(&det) {
        return Ok(det);
    }
    let t = totalize(&det);
    let n = t.len();
    // Alphabet intervals: every transition start point.
    let mut points: Vec<u32> = t.trans.iter().flatten().map(|&(min, _, _)| min).collect();
    points.sort_unstable();
    points.dedup();
    let step = |s: usize, c: u32| -> usize {
        let ts = &t.trans[s];
        let i = ts.partition_point(|&(min, _, _)| min <= c);
        ts[i - 1].2
    };
    let table: Vec<Vec<usize>> = (0..n)
        .map(|s| points.iter().map(|&c| step(s, c)).collect())
        .collect();
    let mut block: Vec<usize> = t.accept.iter().map(|&acc| usize::from(acc)).collect();
    loop {
        spend((n * (points.len() + 1)) as u64);
        if over_budget() {
            return Err(Build::Unknown);
        }
        let mut ids: std::collections::HashMap<(usize, Vec<usize>), usize> =
            std::collections::HashMap::new();
        let mut next = vec![0usize; n];
        for s in 0..n {
            let sig = (
                block[s],
                table[s].iter().map(|&d| block[d]).collect::<Vec<_>>(),
            );
            let len = ids.len();
            next[s] = *ids.entry(sig).or_insert(len);
        }
        let stable = ids.len() == block.iter().collect::<std::collections::HashSet<_>>().len();
        block = next;
        if stable {
            break;
        }
    }
    // Number blocks so the initial state's block is 0.
    let mut order: Vec<usize> = vec![usize::MAX; n];
    let mut out = Automaton::default();
    let mut assign = |b: usize, out: &mut Automaton| {
        if order[b] == usize::MAX {
            order[b] = out.create_state();
        }
        order[b]
    };
    assign(block[0], &mut out);
    for s in 0..n {
        let from = assign(block[s], &mut out);
        out.accept[from] = t.accept[s];
    }
    let mut done = vec![false; out.len()];
    for s in 0..n {
        let from = order[block[s]];
        if done[from] {
            continue;
        }
        done[from] = true;
        for &(min, max, d) in &t.trans[s] {
            let to = order[block[d]];
            out.add(from, to, min, max);
        }
    }
    Ok(remove_dead_states(out.finish()))
}

impl Re {
    fn to_automaton(&self) -> Built {
        let a = match self {
            Re::Union(..) => {
                let mut leaves = Vec::new();
                self.leaves(&mut leaves, true);
                let parts = leaves
                    .into_iter()
                    .map(Re::to_automaton)
                    .collect::<Result<Vec<_>, _>>()?;
                union(&parts)?
            }
            Re::Concat(..) => {
                let mut leaves = Vec::new();
                self.leaves(&mut leaves, false);
                let parts = leaves
                    .into_iter()
                    .map(Re::to_automaton)
                    .collect::<Result<Vec<_>, _>>()?;
                concatenate(&parts)?
            }
            Re::Intersection(a, b) => intersection(&a.to_automaton()?, &b.to_automaton()?)?,
            Re::Optional(a) => optional(a.to_automaton()?),
            Re::Repeat(a) => repeat_star(a.to_automaton()?),
            Re::RepeatMin(a, n) => repeat_min(a.to_automaton()?, *n)?,
            Re::RepeatMinMax(a, n, m) => repeat_min_max(a.to_automaton()?, *n, *m)?,
            Re::Complement(a) => complement(&a.to_automaton()?, u64::MAX / 10)?,
            Re::DeprecatedComplement(a) => complement(&a.to_automaton()?, DETERMINIZE_WORK_LIMIT)?,
            Re::Char(c) => make_class(&[(*c, *c)]),
            Re::CharRange(a, b) => make_class(&[(*a, *b)]),
            Re::CharClass(ranges) => make_class(ranges),
            Re::AnyChar => make_class(&[(MIN_CODE_POINT, MAX_CODE_POINT)]),
            Re::Empty => make_empty(),
            Re::Str(s) => make_string(s),
            Re::AnyString => make_any_string(),
            Re::Automaton(_) | Re::Interval => return Err(Build::Unknown),
        };
        a.guard()
    }

    fn to_automaton_9(&self) -> Built {
        let a = match self {
            Re::Union(..) => {
                let mut leaves = Vec::new();
                self.leaves(&mut leaves, true);
                let parts = leaves
                    .into_iter()
                    .map(Re::to_automaton_9)
                    .collect::<Result<Vec<_>, _>>()?;
                minimize_9(union_9(&parts)?)?
            }
            Re::Concat(..) => {
                let mut leaves = Vec::new();
                self.leaves(&mut leaves, false);
                let parts = leaves
                    .into_iter()
                    .map(Re::to_automaton_9)
                    .collect::<Result<Vec<_>, _>>()?;
                minimize_9(concatenate_9(&parts)?)?
            }
            Re::Intersection(a, b) => {
                minimize_9(intersection(&a.to_automaton_9()?, &b.to_automaton_9()?)?)?
            }
            Re::Optional(a) => minimize_9(optional_9(a.to_automaton_9()?))?,
            Re::Repeat(a) => minimize_9(repeat_star_9(a.to_automaton_9()?))?,
            Re::RepeatMin(a, n) => {
                let a = a.to_automaton_9()?;
                if (a.len() as u64).saturating_sub(1) * u64::from(*n) > DETERMINIZE_WORK_LIMIT {
                    return Err(Build::TooComplex);
                }
                minimize_9(repeat_min_9(a, *n)?)?
            }
            Re::RepeatMinMax(a, n, m) => {
                let a = a.to_automaton_9()?;
                if (a.len() as u64).saturating_sub(1) * u64::from(*m) > DETERMINIZE_WORK_LIMIT {
                    return Err(Build::TooComplex);
                }
                repeat_min_max_9(a, *n, *m)?
            }
            Re::Complement(a) | Re::DeprecatedComplement(a) => {
                minimize_9(complement(&a.to_automaton_9()?, DETERMINIZE_WORK_LIMIT)?)?
            }
            Re::Char(_)
            | Re::CharRange(..)
            | Re::CharClass(_)
            | Re::AnyChar
            | Re::Empty
            | Re::Str(_)
            | Re::AnyString
            | Re::Automaton(_)
            | Re::Interval => return self.to_automaton(),
        };
        a.guard()
    }

    fn leaves<'r>(&'r self, out: &mut Vec<&'r Re>, union: bool) {
        match (self, union) {
            (Re::Union(a, b), true) | (Re::Concat(a, b), false) => {
                a.leaves(out, union);
                b.leaves(out, union);
            }
            _ => out.push(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid(re: &str) -> bool {
        matches!(check(re, Stack::Es9), Verdict::Invalid { .. })
    }

    #[test]
    fn lucene_syntax_is_its_own() {
        for ok in [
            "",
            "abc",
            "a.c",
            "(a|b)+",
            "[a-z]{2,5}",
            "[^0-9]*",
            "\\d+\\s\\w",
            "a{3}",
            "a{3,}",
            "(?i)foo",
            "(?:a|b)",
            "^start$",
            "<1-100>",
            "@&~(abc)",
            "#",
            "\"quoted*\"",
            "a&&b",
            "[]a]",
            "\\.\\/\\-",
            "()",
            "a|*",
        ] {
            assert_eq!(check(ok, Stack::Es9), Verdict::Ok, "{ok}");
        }
        for bad in [
            "\\b",
            "\\n",
            "(a|)",
            "a|",
            "(ab",
            "a)b",
            "[ab",
            "[z-a]",
            "a{2,1}",
            "a{,3}",
            "a{3",
            "x\"y",
            "\\s-\\s*<",
            "<abc>",
            "<a-b>",
            "a~",
            "a&",
            "\\",
            "[a-]",
        ] {
            assert!(invalid(bad), "{bad}");
        }
    }

    #[test]
    fn lucene_9_and_10_read_escaped_ranges_differently() {
        assert!(matches!(
            check("[\\.-z-]x", Stack::Es9),
            Verdict::Invalid { .. }
        ));
        assert_eq!(check("[\\.-z-]x", Stack::Es8), Verdict::Ok);
        assert_eq!(check("[\\~-!]x", Stack::Es9), Verdict::Ok);
        assert!(matches!(
            check("[\\~-!]x", Stack::Es8),
            Verdict::Invalid { .. }
        ));
        // Lucene 9's recursive finiteness check stops at 1000 levels.
        assert_eq!(check(".{1,1500}", Stack::Es8), Verdict::TooLarge);
        assert_eq!(check(".{1,1500}", Stack::Es9), Verdict::Ok);
        assert_eq!(check("(abc){3000}", Stack::Es8), Verdict::Ok);
    }

    #[test]
    fn collapse_matches_elasticsearch() {
        assert_eq!(collapse_quantifiers("a+?b**c?+"), "a*b*c*");
        assert_eq!(collapse_quantifiers("[+*]\"**\"a\\++"), "[+*]\"**\"a\\++");
    }

    #[test]
    fn determinization_effort() {
        let copy =
            "(Copy-Item|cpi) .{2,128} -Destination .{1,32}\\\\Windows\\\\(System32|SysWOW64)";
        for stack in [Stack::Es8, Stack::Es9] {
            assert_eq!(check(copy, stack), Verdict::TooComplex);
            assert_eq!(check(".{2,128}x", stack), Verdict::Ok);
            assert_eq!(check("[a-z]+@[a-z]+\\.com", stack), Verdict::Ok);
        }
        // Lucene 9 refuses a repeat whose expansion would exceed the limit
        // up front; Lucene 10 builds the (deterministic) chain.
        assert_eq!(check("(abc){1,5000}", Stack::Es8), Verdict::TooComplex);
        assert_eq!(check("(abc){1,5000}", Stack::Es9), Verdict::Ok);
    }
}
