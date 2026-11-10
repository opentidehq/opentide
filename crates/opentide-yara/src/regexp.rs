//! YARA regular expressions as libyara 4.5 reads them (`re_lexer.l`,
//! `re_grammar.y`). Errors are what libyara refuses (`yara_regexp`); notes
//! are what libyara accepts and YARA-X refuses (`yara_x_incompatible`): an
//! unknown escape such as `\R`, and a `{` that does not start a repetition.
//! The same pass collects the literal bytes every match must contain, for
//! the atom quality behind `yara_slow_pattern`.

/// libyara's `RE_MAX_RANGE` (`INT16_MAX`).
const RE_MAX_RANGE: u32 = 32767;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Byte offsets into the pattern text (between the slashes).
    pub start: usize,
    pub end: usize,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Check {
    pub errors: Vec<Finding>,
    pub yara_x: Vec<Finding>,
    /// The literal bytes matches contain, for atom quality.
    pub atoms: Atoms,
}

/// Where libyara can take atoms from: a run of literal bytes, a sequence
/// (any one of its parts will do), or an alternative (every branch needs
/// its own atom, so the weakest branch decides).
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Atoms {
    #[default]
    None,
    Run(Vec<u8>),
    Seq(Vec<Atoms>),
    Alt(Vec<Atoms>),
}

impl Atoms {
    /// The best atom quality, given a scorer for one run; `None` when some
    /// required branch has no literal at all.
    pub fn best(&self, score: &dyn Fn(&[u8]) -> Option<i32>) -> Option<i32> {
        match self {
            Atoms::None => None,
            Atoms::Run(bytes) => score(bytes),
            Atoms::Seq(parts) => parts.iter().filter_map(|p| p.best(score)).max(),
            Atoms::Alt(branches) => branches
                .iter()
                .map(|b| b.best(score))
                .collect::<Option<Vec<_>>>()
                .and_then(|qs| qs.into_iter().min()),
        }
    }
}

/// An item of a concatenation: a literal byte or something else.
#[derive(Clone, PartialEq)]
enum Item {
    Byte(u8),
    /// A group, with the atoms its matches contain.
    Group(Atoms),
    Other,
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
    check: Check,
}

/// Check the source of a regexp (the text between the slashes).
pub fn check(src: &str) -> Check {
    let mut p = Parser {
        src: src.as_bytes(),
        pos: 0,
        check: Check::default(),
    };
    if src.is_empty() {
        p.error(0, 0, "empty regular expression");
        return p.check;
    }
    if let Some(i) = src.bytes().position(|b| !b.is_ascii()) {
        p.error(i, i + 1, "non-ascii character");
        return p.check;
    }
    let atoms = p.alternation(0);
    if p.pos < p.src.len() && p.check.errors.is_empty() {
        p.error(p.pos, p.pos + 1, "unbalanced )");
    }
    p.check.atoms = atoms;
    p.check
}

impl<'a> Parser<'a> {
    fn error(&mut self, start: usize, end: usize, message: &str) {
        self.check.errors.push(Finding {
            start,
            end,
            message: message.to_string(),
        });
    }

    fn yara_x(&mut self, start: usize, end: usize, message: &str) {
        self.check.yara_x.push(Finding {
            start,
            end,
            message: message.to_string(),
        });
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    /// `a|b|c`.
    fn alternation(&mut self, depth: usize) -> Atoms {
        let mut branches = vec![self.concatenation(depth)];
        while self.peek() == Some(b'|') && self.check.errors.is_empty() {
            self.pos += 1;
            branches.push(self.concatenation(depth));
        }
        if branches.len() == 1 {
            branches.pop().unwrap_or_default()
        } else {
            Atoms::Alt(branches)
        }
    }

    fn concatenation(&mut self, depth: usize) -> Atoms {
        let mut runs = Vec::new();
        let mut current = Vec::new();
        while let Some(c) = self.peek() {
            if !self.check.errors.is_empty() || c == b'|' || (c == b')' && depth > 0) {
                break;
            }
            if c == b')' {
                self.error(self.pos, self.pos + 1, "unbalanced )");
                break;
            }
            let start = self.pos;
            let item = self.atom(depth);
            if !self.check.errors.is_empty() {
                break;
            }
            let optional = self.quantifier(start);
            match item {
                Item::Byte(b) if !optional => current.push(b),
                other => {
                    if !current.is_empty() {
                        runs.push(Atoms::Run(std::mem::take(&mut current)));
                    }
                    if let Item::Group(inner) = other
                        && !optional
                    {
                        runs.push(inner);
                    }
                }
            }
        }
        if !current.is_empty() {
            runs.push(Atoms::Run(current));
        }
        match runs.len() {
            0 => Atoms::None,
            1 => runs.pop().unwrap_or_default(),
            _ => Atoms::Seq(runs),
        }
    }

    fn atom(&mut self, depth: usize) -> Item {
        let start = self.pos;
        let Some(c) = self.peek() else {
            return Item::Other;
        };
        self.pos += 1;
        match c {
            b'(' => {
                if self.peek() == Some(b'?') {
                    self.error(
                        start,
                        start + 2,
                        "`(?` groups are YARA-X syntax; libyara 4.5 has no group flags",
                    );
                    return Item::Other;
                }
                let inner = self.alternation(depth + 1);
                if self.check.errors.is_empty() {
                    if self.peek() == Some(b')') {
                        self.pos += 1;
                    } else {
                        self.error(start, start + 1, "missing )");
                    }
                }
                Item::Group(inner)
            }
            b'[' => {
                self.class(start);
                Item::Other
            }
            b'.' | b'^' | b'$' => Item::Other,
            b'*' | b'+' | b'?' => {
                self.error(start, start + 1, "nothing to repeat");
                Item::Other
            }
            b'{' => {
                if self.repeat_bounds().is_some() {
                    self.error(start, self.pos, "nothing to repeat");
                } else {
                    self.yara_x(
                        start,
                        start + 1,
                        "YARA-X requires `{` to be escaped outside a repetition (`\\{`)",
                    );
                }
                Item::Byte(b'{')
            }
            b'\\' => self.escape(start, false),
            other => Item::Byte(other),
        }
    }

    /// After `\`. In a class, `\b` is a backspace in neither engine's
    /// sense; libyara refuses it there like any other non-literal.
    fn escape(&mut self, start: usize, in_class: bool) -> Item {
        let Some(c) = self.peek() else {
            self.error(start, start + 1, "illegal escape sequence");
            return Item::Other;
        };
        self.pos += 1;
        match c {
            b'w' | b'W' | b's' | b'S' | b'd' | b'D' => Item::Other,
            b'b' | b'B' if !in_class => Item::Other,
            b'0'..=b'9' if !in_class => {
                self.error(start, self.pos, "backreferences are not allowed");
                Item::Other
            }
            b'x' => {
                let hex = self.src.get(self.pos..self.pos + 2);
                match hex
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(v) => {
                        self.pos += 2;
                        Item::Byte(v)
                    }
                    None => {
                        self.error(start, self.pos, "illegal escape sequence");
                        Item::Other
                    }
                }
            }
            b'n' => Item::Byte(b'\n'),
            b't' => Item::Byte(b'\t'),
            b'r' => Item::Byte(b'\r'),
            b'f' => Item::Byte(0x0c),
            b'a' => Item::Byte(0x07),
            c if c.is_ascii_alphanumeric() => {
                // libyara warns "unknown escape sequence" and reads the
                // character; YARA-X refuses it.
                self.yara_x(
                    start,
                    self.pos,
                    &format!(
                        "unknown escape sequence `\\{}`: YARA-X refuses it",
                        c as char
                    ),
                );
                Item::Byte(c)
            }
            c => Item::Byte(c),
        }
    }

    fn class(&mut self, start: usize) {
        if self.peek() == Some(b'^') {
            self.pos += 1;
        }
        // A `]` first is a literal.
        if self.peek() == Some(b']') {
            self.pos += 1;
        }
        loop {
            let Some(c) = self.peek() else {
                self.error(start, self.pos, "missing terminating ] for character class");
                return;
            };
            if c == b']' {
                self.pos += 1;
                return;
            }
            let item_start = self.pos;
            let low = self.class_char();
            if !self.check.errors.is_empty() {
                return;
            }
            if self.peek() == Some(b'-') && self.src.get(self.pos + 1).is_some_and(|&n| n != b']') {
                self.pos += 1;
                let high = self.class_char();
                if let (Some(lo), Some(hi)) = (low, high)
                    && hi < lo
                {
                    self.error(item_start, self.pos, "bad character range");
                    return;
                }
            }
        }
    }

    /// One class member: its byte, or `None` for a class escape (`\w`).
    fn class_char(&mut self) -> Option<u8> {
        let start = self.pos;
        let c = self.peek()?;
        self.pos += 1;
        if c != b'\\' {
            return Some(c);
        }
        match self.escape(start, true) {
            Item::Byte(b) => Some(b),
            _ => None,
        }
    }

    /// `{n}`, `{n,}`, `{,m}`, `{n,m}` at `self.pos` (just after `{`).
    /// Advances past `}` and returns the bounds when it is one.
    fn repeat_bounds(&mut self) -> Option<(u32, Option<u32>)> {
        let rest = &self.src[self.pos..];
        let close = rest.iter().position(|&b| b == b'}')?;
        let body = std::str::from_utf8(&rest[..close]).ok()?;
        let (lo, hi) = match body.split_once(',') {
            None => {
                let n = parse_bound(body)?;
                (n, Some(n))
            }
            Some((a, b)) => {
                let lo = if a.is_empty() { 0 } else { parse_bound(a)? };
                let hi = if b.is_empty() {
                    None
                } else {
                    Some(parse_bound(b)?)
                };
                if a.is_empty() && b.is_empty() {
                    return None;
                }
                (lo, hi)
            }
        };
        self.pos += close + 1;
        Some((lo, hi))
    }

    /// A quantifier after an atom. Returns whether it makes the atom
    /// optional (`?`, `*`, `{0,..}`).
    fn quantifier(&mut self, atom_start: usize) -> bool {
        let start = self.pos;
        let optional = match self.peek() {
            Some(b'*') | Some(b'?') => {
                self.pos += 1;
                true
            }
            Some(b'+') => {
                self.pos += 1;
                false
            }
            Some(b'{') => {
                self.pos += 1;
                match self.repeat_bounds() {
                    Some((lo, hi)) => {
                        if lo > RE_MAX_RANGE || hi.is_some_and(|h| h > RE_MAX_RANGE) {
                            self.error(start, self.pos, "repeat interval too large");
                        } else if hi.is_some_and(|h| h < lo) {
                            self.error(start, self.pos, "bad repeat interval");
                        }
                        lo == 0
                    }
                    None => {
                        // A literal `{` after the atom: the next atom.
                        self.pos = start;
                        return false;
                    }
                }
            }
            _ => return false,
        };
        let _ = atom_start;
        // A lazy quantifier.
        if self.peek() == Some(b'?') {
            self.pos += 1;
        }
        if matches!(self.peek(), Some(b'*') | Some(b'+')) {
            self.error(self.pos, self.pos + 1, "nothing to repeat");
        }
        optional
    }
}

fn parse_bound(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Saturate: "repeat interval too large" either way.
    Some(
        s.parse::<u64>()
            .map_or(u32::MAX, |v| v.min(u32::MAX as u64) as u32),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(src: &str) -> Vec<String> {
        check(src).errors.into_iter().map(|f| f.message).collect()
    }

    fn yara_x(src: &str) -> Vec<String> {
        check(src).yara_x.into_iter().map(|f| f.message).collect()
    }

    #[test]
    fn valid_expressions() {
        for re in [
            "abc",
            "a(b|c)+d",
            "[a-z0-9_]{2,8}",
            "\\x41\\.\\/",
            "^foo$",
            "a{,3}",
            "a{2,}?",
            "[]a]",
            "[^\\]]",
            "\\w+\\s\\d\\b",
            "(a|)",
        ] {
            assert!(errors(re).is_empty(), "{re}: {:?}", errors(re));
            assert!(yara_x(re).is_empty(), "{re}: {:?}", yara_x(re));
        }
    }

    #[test]
    fn libyara_errors() {
        assert_eq!(errors("a(b"), ["missing )"]);
        assert_eq!(errors("ab)"), ["unbalanced )"]);
        assert_eq!(errors("[a-"), ["missing terminating ] for character class"]);
        assert_eq!(errors("[z-a]"), ["bad character range"]);
        assert_eq!(errors("a{3,1}"), ["bad repeat interval"]);
        assert_eq!(errors("a{40000}"), ["repeat interval too large"]);
        assert_eq!(errors("*a"), ["nothing to repeat"]);
        assert_eq!(errors("(a)\\1"), ["backreferences are not allowed"]);
        assert_eq!(errors("\\xZZ"), ["illegal escape sequence"]);
        assert_eq!(errors("é"), ["non-ascii character"]);
        assert!(errors("(?i)abc")[0].contains("YARA-X"));
    }

    #[test]
    fn yara_x_refusals() {
        assert_eq!(yara_x("\\Release").len(), 1);
        assert_eq!(yara_x("abc{").len(), 1);
        assert!(errors("abc{").is_empty());
    }

    #[test]
    fn atoms_follow_libyara() {
        let len = |b: &[u8]| Some(b.len() as i32);
        assert_eq!(check("abc?d").atoms.best(&len), Some(2));
        assert_eq!(check("a.bcd").atoms.best(&len), Some(3));
        // The weakest branch decides.
        assert_eq!(check("abcd|ef").atoms.best(&len), Some(2));
        assert_eq!(check("(abcd|e.)x").atoms.best(&len), Some(1));
        assert_eq!(check("(\\xC6\\x45.{2}){25}").atoms.best(&len), Some(2));
        assert_eq!(check("(ab)?c").atoms.best(&len), Some(1));
        assert_eq!(check(".*").atoms.best(&len), None);
    }
}
