//! The KQL parser on `opentide-parse` (#1230): recursive descent, with the
//! expressions by precedence climbing. `kql.ungram` is the shape of the
//! tree it builds.
//!
//! A word is a keyword only where the grammar takes one (the lexer reads
//! every word as the kind its text names): where a name is wanted, any
//! word is one, and the parser relabels it `IDENT` ([`P::bump_name`]).

mod expr;
mod statement;
mod tabular;
#[cfg(test)]
mod tests;

use crate::lexer::lex_kql_indexing;
use crate::syntax::SyntaxKind as K;
use opentide_parse::{CompletedMarker, Grammar, Input, Marker, Parse, Parser, TokenSet, build};

/// The deepest nesting of expressions and sub-pipelines the parser takes
/// (tree-sitter took 35 on a 1 MB stack). Past it: one error and the rest
/// of the input in one error node.
const MAX_DEPTH: u32 = 256;

pub(crate) const GRAMMAR: Grammar = Grammar {
    eof: K::EOF.raw(),
    error: K::ERROR.raw(),
    trivia: TokenSet::new(&[K::WHITESPACE.raw(), K::COMMENT.raw()]),
    max_depth: MAX_DEPTH,
};

/// Parses `source` into a lossless tree and its syntax errors.
///
/// A keyword is a name where the grammar wants one, and the lexer cannot tell
/// whether `['x']` after it is a quoted name (`project ['x']`) or an index
/// (`where step ['x']`, `step` a column). It reads a quoted name; where the
/// parser then finds one right after an expression, the text is lexed again
/// with an index there and parsed again (rare: a keyword used as a column and
/// indexed), as the old grammar read it. A hyphen keyword where an
/// expression starts is lexed again the same way: the lexer takes
/// `project-away` after a `(` for an operator, which it is in
/// `fork (project-away x)` and is not in `count(project-away)`.
pub(crate) fn parse(source: &str) -> Parse {
    PARSES.with(|n| n.set(n.get() + 1));
    let mut index_at = Vec::new();
    for _ in 0..4 {
        let input = Input::new(source, lex_kql_indexing(source, &index_at), GRAMMAR);
        let mut p = P::new(Parser::new(&input));
        statement::source_file(&mut p);
        let found = std::mem::take(&mut p.1.index_at);
        let parse = build(&input, p.0.finish());
        if found.is_empty() || parse.errors.is_empty() {
            return parse;
        }
        index_at.extend(found);
        // Sorted, so that the lexer finds a place by binary search: a query
        // with many of them is not re-lexed in quadratic time.
        index_at.sort_unstable();
        index_at.dedup();
    }
    let input = Input::new(source, lex_kql_indexing(source, &index_at), GRAMMAR);
    let mut p = P::new(Parser::new(&input));
    statement::source_file(&mut p);
    build(&input, p.0.finish())
}

thread_local! {
    /// The parses this thread ran: what the parse-once memo's test counts.
    static PARSES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// The last text parsed through [`parse_once`], and its parse.
    static LAST: std::cell::RefCell<Option<(String, Parse)>> = const { std::cell::RefCell::new(None) };
}

/// [`parse`], memoised for the last text: an analysis, its hover, its
/// completions and its column pass on one text parse it once (an editor asks
/// for them in a row on the same document). The green tree is shared, not
/// copied.
pub(crate) fn parse_once(source: &str) -> Parse {
    if let Some(hit) = LAST.with(|last| {
        last.borrow()
            .as_ref()
            .filter(|(text, _)| text == source)
            .map(|(_, parse)| parse.clone())
    }) {
        return hit;
    }
    let parse = parse(source);
    LAST.with(|last| *last.borrow_mut() = Some((source.to_owned(), parse.clone())));
    parse
}

/// How many times this thread has parsed a text (not counting memo hits).
pub(crate) fn parse_count() -> u64 {
    PARSES.with(std::cell::Cell::get)
}

/// The toolkit's parser, spoken in this language's kinds.
pub(crate) struct P<'i>(Parser<'i>, Flood);

/// What keeps a run of unexpected tokens to one error: the tokens consumed
/// so far, and how many had been when the last error was recorded.
#[derive(Default)]
pub(crate) struct Flood {
    consumed: u64,
    last_error: Option<u64>,
    /// Where a quoted name stands right after an expression, or a hyphen
    /// keyword starts one ([`parse`]): the places the lexer reads again.
    pub(crate) index_at: Vec<rowan::TextSize>,
}

impl<'i> P<'i> {
    fn new(parser: Parser<'i>) -> Self {
        Self(parser, Flood::default())
    }

    /// Records `message`, unless it continues a run of errors ([`P::flooding`]):
    /// `- - - a`, `,,,,` and `++++` are one error, not one per token (the
    /// first says where the query went wrong, the rest only repeat it).
    fn report(&mut self, message: &str) {
        if !self.flooding() {
            self.0.error(message);
        }
    }

    /// Whether an error here continues the run of the last one (it came at
    /// most two tokens later); either way, the run now ends here.
    fn flooding(&mut self) -> bool {
        let flooding = self
            .1
            .last_error
            .is_some_and(|at| self.1.consumed <= at + 2);
        self.1.last_error = Some(self.1.consumed);
        flooding
    }

    pub(crate) fn nth(&self, n: usize) -> K {
        K::from_raw(self.0.nth(n))
    }

    pub(crate) fn current(&self) -> K {
        self.nth(0)
    }

    pub(crate) fn at(&mut self, kind: K) -> bool {
        self.0.at(kind.raw())
    }

    pub(crate) fn current_range(&self) -> Option<rowan::TextRange> {
        self.0.current_range()
    }

    /// Whether the significant tokens `a` and `b` ahead touch: no blank or
    /// comment between them.
    pub(crate) fn tokens_touch(&self, a: usize, b: usize) -> bool {
        matches!(
            (self.0.nth_range(a), self.0.nth_range(b)),
            (Some(a), Some(b)) if a.end() == b.start()
        )
    }

    /// Notes a quoted name right after an expression: the old grammar read
    /// it as an index ([`parse`]).
    pub(crate) fn quoted_name_after_value(&mut self) {
        if self.current() == K::QUOTED_IDENT
            && let Some(range) = self.current_range()
        {
            self.1.index_at.push(range.start());
        }
    }

    /// Notes a hyphen keyword where an expression starts (`count(project-away)`,
    /// after a `(` the lexer took for a sub-pipeline's): the old grammar read
    /// names and a minus there ([`parse`]).
    pub(crate) fn hyphen_keyword_in_expression(&mut self) {
        // `granny-asc` and `granny-desc` the lexer never splits.
        if self.current().is_word()
            && !matches!(self.current(), K::GRANNY_ASC_KW | K::GRANNY_DESC_KW)
            && self.0.current_text().contains('-')
            && let Some(range) = self.current_range()
        {
            self.1.index_at.push(range.start());
        }
    }

    pub(crate) fn at_eof(&self) -> bool {
        self.0.at_eof()
    }

    pub(crate) fn eat(&mut self, kind: K) -> bool {
        let found = self.0.eat(kind.raw());
        self.1.consumed += u64::from(found);
        found
    }

    pub(crate) fn bump(&mut self) {
        self.1.consumed += 1;
        self.0.bump();
    }

    pub(crate) fn bump_as(&mut self, kind: K) {
        self.1.consumed += 1;
        self.0.bump_as(kind.raw());
    }

    /// Consumes `kind`, or records "expected ..." without consuming.
    pub(crate) fn expect(&mut self, kind: K) -> bool {
        let found = self.eat(kind);
        if !found {
            self.report(&format!("expected {}", kind.describe()));
        }
        found
    }

    pub(crate) fn error(&mut self, message: &str) {
        self.report(message);
    }

    /// Records `message` (unless [`P::report`] would not) and wraps the tokens
    /// up to one in `stop` in an error node.
    pub(crate) fn err_until(&mut self, message: &str, stop: TokenSet) {
        if self.flooding() {
            let m = self.0.start();
            while !self.0.at_eof() && !stop.contains(self.0.current()) {
                self.0.bump();
            }
            m.complete(&mut self.0, K::ERROR.raw());
        } else {
            self.0.err_until(message, stop);
        }
    }

    pub(crate) fn start(&mut self) -> Marker {
        self.0.start()
    }

    /// Lets go of a node `start` opened: what it took stays in the node
    /// around it.
    pub(crate) fn abandon(&mut self, marker: Marker) {
        marker.abandon(&mut self.0);
    }

    pub(crate) fn enter(&mut self) -> bool {
        self.0.enter()
    }

    pub(crate) fn exit(&mut self) {
        self.0.exit();
    }

    pub(crate) fn done(&mut self, marker: Marker, kind: K) -> CompletedMarker {
        marker.complete(&mut self.0, kind.raw())
    }

    pub(crate) fn precede(&mut self, done: CompletedMarker) -> Marker {
        done.precede(&mut self.0)
    }

    /// The text of the token `n` ahead.
    pub(crate) fn nth_text(&self, n: usize) -> &str {
        self.0.nth_text(n)
    }

    /// Whether the token `n` ahead is a word that can be a name: an
    /// identifier, or a keyword spelled like one (`has` is a column when no
    /// operator can come, `!has` never is).
    pub(crate) fn name_at(&self, n: usize) -> bool {
        let kind = self.nth(n);
        kind == K::IDENT
            || (kind.is_word()
                && self
                    .0
                    .nth_text(n)
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    }

    /// Consumes a name (a word, or a quoted name) as an identifier, or
    /// records "expected a name".
    pub(crate) fn expect_name(&mut self) -> bool {
        if self.name_at(0) {
            self.bump_as(K::IDENT);
            true
        } else {
            self.report("expected a name");
            false
        }
    }

    /// The index, past `n`, of the token after the group that opens at `n`
    /// (`(`, `[` or `{`): `n + 1` for any other token; the end of the input
    /// for a group that never closes.
    pub(crate) fn after_group(&self, n: usize) -> usize {
        let mut depth = 0usize;
        let mut at = n;
        loop {
            match self.nth(at) {
                K::EOF => return at,
                K::L_PAREN | K::L_BRACKET | K::L_BRACE => depth += 1,
                K::R_PAREN | K::R_BRACKET | K::R_BRACE => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return at + 1;
                    }
                }
                _ if depth == 0 => return at + 1,
                _ => {}
            }
            at += 1;
        }
    }

    /// Whether the group that opens at `n` (a `(`) is `( tabular_expression )`
    /// rather than `( expression )`. Both read `(b)`, `(f(1))` and `((b))`,
    /// and the grammar this one replaces took them as tabular: a pipe in the
    /// group, a source operator, or exactly one lone name, call or such group.
    ///
    /// A group that holds only another group (`((b))`) is read through, level
    /// by level, from one scan of the outer group: a deep nest of `(` costs
    /// one pass and no recursion (one pass per level burnt the parser's fuel
    /// on 3,000 levels, and recursed once per level).
    ///
    /// A group that never closes reaches the end of the input, so the pipes
    /// of the pipeline around it fall inside it: `in (4688, 4689` then
    /// `| project Account` on the next line. Before its first pipe, such a
    /// group that reads as a list of values ([`P::value_list`]) is a list
    /// that misses its `)`; any other is still a sub-query (`(T | where`,
    /// `(database("d").T | …`, `(['My Table'] | …`, `((S | …) | …`).
    pub(crate) fn paren_is_tabular(&self, n: usize) -> bool {
        if self.nth(n) != K::L_PAREN {
            return false;
        }
        let mut run = 1;
        while self.nth(n + run) == K::L_PAREN {
            run += 1;
        }
        // For the `(` at `n + k` (k < run): the index after its group, and
        // whether a `|` stands at its top level.
        let mut ends: Vec<Option<usize>> = vec![None; run];
        // The first `|` and the first `,` at each group's top level.
        let mut pipes: Vec<Option<usize>> = vec![None; run];
        let mut commas: Vec<Option<usize>> = vec![None; run];
        let mut open: Vec<usize> = Vec::new();
        let mut at = n;
        let end = loop {
            match self.nth(at) {
                K::EOF => break at,
                K::L_PAREN | K::L_BRACKET | K::L_BRACE => open.push(at),
                K::R_PAREN | K::R_BRACKET | K::R_BRACE => {
                    if let Some(opened) = open.pop()
                        && let Some(slot) = ends.get_mut(opened - n)
                    {
                        *slot = Some(at + 1);
                    }
                    if open.is_empty() {
                        break at + 1;
                    }
                }
                K::PIPE => {
                    if let Some(slot) = open.last().and_then(|&o| pipes.get_mut(o - n)) {
                        slot.get_or_insert(at);
                    }
                }
                K::COMMA => {
                    if let Some(slot) = open.last().and_then(|&o| commas.get_mut(o - n)) {
                        slot.get_or_insert(at);
                    }
                }
                _ => {}
            }
            at += 1;
        };
        // A group that never closes ends at the end of the input.
        let end_of = |k: usize| ends[k].unwrap_or(end);
        let mut k = 0;
        loop {
            if let Some(pipe) = pipes[k] {
                return ends[k].is_some()
                    || !self.value_list(n + k + 1, commas[k].filter(|&comma| comma < pipe));
            }
            let close = end_of(k).saturating_sub(1);
            if k + 1 < run {
                // `((`: tabular when the inner group is all of the outer one
                // and is tabular itself.
                if end_of(k + 1) != close {
                    return false;
                }
                k += 1;
                continue;
            }
            return self.tabular_item(n + k + 1, close);
        }
    }

    /// Whether the group content that starts at `from` reads as a list of
    /// values: it starts with a literal (`4688`, `"x"`, `true`, `-1`), or
    /// it has a top-level `,` (`comma`) and starts with no source operator
    /// (`union A, B` and `print a, b` are tabular).
    fn value_list(&self, from: usize, comma: Option<usize>) -> bool {
        match self.nth(from) {
            K::STRING
            | K::NUMBER
            | K::TIMESPAN
            | K::TYPED_LITERAL
            | K::BOOLEAN
            | K::NULL_KW
            | K::MINUS
            | K::DYNAMIC_KW => true,
            K::PRINT_KW
            | K::UNION_KW
            | K::DATATABLE_KW
            | K::EXTERNALDATA_KW
            | K::EXTERNAL_DATA_KW
            | K::SEARCH_KW
            | K::FIND_KW
            | K::RANGE_KW
            | K::MATERIALIZE_KW
            | K::L_PAREN => false,
            _ => comma.is_some(),
        }
    }

    /// Whether the tokens `from..close` are one tabular source: a name, a
    /// call or a source operator (a group is [`P::paren_is_tabular`]'s).
    fn tabular_item(&self, from: usize, close: usize) -> bool {
        match self.nth(from) {
            K::PRINT_KW
            | K::UNION_KW
            | K::DATATABLE_KW
            | K::EXTERNALDATA_KW
            | K::EXTERNAL_DATA_KW
            | K::SEARCH_KW
            | K::FIND_KW => true,
            K::MATERIALIZE_KW => self.nth(from + 1) == K::L_PAREN,
            K::RANGE_KW if self.name_at(from + 1) && self.nth(from + 2) == K::FROM_KW => true,
            K::DYNAMIC_KW | K::TOSCALAR_KW if self.nth(from + 1) == K::L_PAREN => false,
            K::BOOLEAN | K::NULL_KW => false,
            _ if self.name_at(from) => {
                from + 1 == close
                    || (self.nth(from + 1) == K::L_PAREN && self.after_group(from + 1) == close)
            }
            _ => false,
        }
    }
}
