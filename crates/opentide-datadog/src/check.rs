//! The checks of RFC §6.7 and the highlight of §6.8, in one walk over the tree (ADR 0014 §5a):
//! [`walk`] visits each element once, in preorder, runs the checks of a node when it enters it
//! and those of a token when it meets it, and hands each token's capture to the highlight.
//!
//! Every check reads the element it is at, its direct children or its ancestors' kinds (kept
//! on one stack), never the whole tree again, so the walk is linear in the tree.

use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_core::{ByteSpan, Severity, codes};
use opentide_highlight::Capture;
use opentide_parse::{Ancestors, walk_once};
use rowan::{NodeOrToken, TextRange};

/// Where a query runs (RFC §6.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Profile {
    /// A detection rule's `queries[].query`: `*:term` and `#name` are warnings.
    Rule,
    /// A `.datadog` file, a hunt search, `opentide query`: everything the syntax allows.
    #[default]
    Search,
}

/// One finding of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Its `datadog_*` code.
    pub code: &'static str,
    /// Its severity (RFC §6.7).
    pub severity: Severity,
    /// What it says.
    pub message: String,
    /// Where it is, in bytes.
    pub span: ByteSpan,
}

/// The note every finding that depends on the precedence carries (RFC §6.5, §14).
const PRECEDENCE_NOTE: &str =
    "AND binds tighter than OR, as VRL reads it; unverified on Cloud SIEM (RFC open question 2)";

/// Walks `root` once: the findings of the checks for `profile`, and each token's highlight
/// capture handed to `highlight` in document order.
pub(crate) fn walk(
    root: &SyntaxNode,
    source: &str,
    profile: Profile,
    mut highlight: impl FnMut(ByteSpan, Capture),
) -> Vec<Finding> {
    let mut w = Walker {
        source,
        profile,
        findings: Vec::new(),
        term: TermFlags::default(),
        curly_open: false,
        tags_clause: None,
    };
    let mut ancestors: Ancestors<K> = Ancestors::default();
    walk_once(root, |element, depth| {
        count_visit();
        let above = ancestors.at(depth);
        match element {
            NodeOrToken::Node(node) => {
                w.node(&node, above.last().copied());
                ancestors.push(node.kind());
            }
            NodeOrToken::Token(token) => {
                let parent = above.last().copied().unwrap_or(K::QUERY);
                w.token(&token, parent);
                if let Some(capture) = capture(&token, parent) {
                    let range = token.text_range();
                    if !range.is_empty() {
                        highlight(span(range), capture);
                    }
                }
            }
        }
    });
    w.findings
}

/// The checks that fire once per term, whatever the number of pieces that set them off.
#[derive(Debug, Default, Clone, Copy)]
struct TermFlags {
    special: bool,
    regex: bool,
    colon: bool,
}

struct Walker<'s> {
    source: &'s str,
    profile: Profile,
    findings: Vec<Finding>,
    term: TermFlags,
    /// Whether a left curly quote is open: its closing quote is the same mistake, reported once.
    curly_open: bool,
    /// The range of the last field clause on `tags`, whose values are `key:value` pairs by
    /// definition: a colon inside it needs no escape. Field clauses do not nest.
    tags_clause: Option<TextRange>,
}

impl Walker<'_> {
    fn push(&mut self, code: &'static str, severity: Severity, message: String, span: ByteSpan) {
        self.findings.push(Finding {
            code,
            severity,
            message,
            span,
        });
    }

    fn text(&self, range: TextRange) -> &str {
        self.source
            .get(usize::from(range.start())..usize::from(range.end()))
            .unwrap_or("")
    }

    /// The checks of a node, as the walk enters it. `parent` is the kind of the node above.
    fn node(&mut self, node: &SyntaxNode, parent: Option<K>) {
        match node.kind() {
            K::FIELD_CLAUSE => {
                let tags = node
                    .first_child()
                    .is_some_and(|f| f.kind() == K::TAG_KEY && self.text(trimmed(&f)) == "tags");
                if tags {
                    self.tags_clause = Some(node.text_range());
                }
            }
            K::OR_EXPR | K::VALUE_OR_EXPR => self.mixed_boolean(node),
            K::AND_EXPR | K::VALUE_AND_EXPR => self.lowercase_operators(node),
            K::TERM => {
                self.term = TermFlags::default();
                if parent == Some(K::FIELD_CLAUSE)
                    && node.first_token().is_some_and(|t| t.kind() == K::MINUS)
                {
                    self.term.special = true;
                    self.push(
                        codes::DATADOG_UNESCAPED_SPECIAL,
                        Severity::Error,
                        "a value cannot start with an unescaped `-`, which Datadog reads as an \
                         exclusion: escape it (`\\-`), or put the `-` before the field"
                            .into(),
                        span(trimmed(node)),
                    );
                }
            }
            K::TAG_KEY => self.tag_key(node, parent),
            K::QUOTED_FIELD => self.push(
                codes::DATADOG_PIPELINES_ONLY,
                Severity::Warning,
                "a quoted field name is Observability Pipelines syntax; in log search write the \
                 field bare, escaping what needs it (`service\\.status:disabled`)"
                    .into(),
                span(trimmed(node)),
            ),
            K::ALL_ATTRIBUTES if self.profile == Profile::Rule => self.push(
                codes::DATADOG_FULL_TEXT_IN_RULE,
                Severity::Warning,
                "`*:term` searches every attribute; Datadog documents it for monitor, dashboard \
                 and notebook queries, not for detection rules: name the attribute"
                    .into(),
                span(trimmed(node)),
            ),
            K::CALCULATED_FIELD if self.profile == Profile::Rule => self.push(
                codes::DATADOG_CALCULATED_FIELD_IN_RULE,
                Severity::Warning,
                "a calculated field (`#name`) exists in the Log Explorer only: a real-time \
                 detection rule has none"
                    .into(),
                span(trimmed(node)),
            ),
            K::CIDR_CALL => self.cidr_call(node),
            K::CIDR_BLOCK => {
                let range = trimmed(node);
                let text = self.text(range);
                if !is_cidr_block(text) {
                    let text = shorten(text);
                    self.push(
                        codes::DATADOG_CIDR,
                        Severity::Error,
                        format!(
                            "`{text}` is not an IPv4 or IPv6 CIDR block (`10.0.0.0/8`, `fc00::/7`)"
                        ),
                        span(range),
                    );
                }
            }
            K::RANGE => self.range(node),
            _ => {}
        }
    }

    /// The checks of a token. `parent` is the kind of the node that holds it.
    fn token(&mut self, token: &SyntaxToken, parent: K) {
        match token.kind() {
            K::BANG | K::LT | K::LT_EQ | K::GT | K::GT_EQ if parent == K::TERM => {
                if !std::mem::replace(&mut self.term.special, true) {
                    self.push(
                        codes::DATADOG_UNESCAPED_SPECIAL,
                        Severity::Error,
                        format!(
                            "an unescaped `{}` in a term: escape it with `\\`, or quote the value",
                            token.text()
                        ),
                        span(token.text_range()),
                    );
                }
            }
            K::TILDE | K::CARET if parent == K::TERM => {
                if !std::mem::replace(&mut self.term.regex, true) {
                    self.push(
                        codes::DATADOG_REGEX,
                        Severity::Error,
                        format!(
                            "`{}` in a term: the search syntax has no regular expression, fuzzy \
                             or boost operator; escape it with `\\` to search for it",
                            token.text()
                        ),
                        span(token.text_range()),
                    );
                }
            }
            K::COLON
                if parent == K::TERM
                    && !self
                        .tags_clause
                        .is_some_and(|clause| clause.contains_range(token.text_range())) =>
            {
                if !std::mem::replace(&mut self.term.colon, true) {
                    self.push(
                        codes::DATADOG_UNESCAPED_COLON,
                        Severity::Warning,
                        "an unescaped `:` in a value: Datadog's docs say to escape it (`\\:`)"
                            .into(),
                        span(token.text_range()),
                    );
                }
            }
            K::AMP_AMP | K::PIPE_PIPE => {
                let word = if token.kind() == K::AMP_AMP {
                    "AND"
                } else {
                    "OR"
                };
                self.push(
                    codes::DATADOG_SYMBOL_OPERATOR,
                    Severity::Warning,
                    format!(
                        "`{}` between clauses: Datadog's docs list it among the characters to \
                         escape, not the operators; write `{word}`",
                        token.text()
                    ),
                    span(token.text_range()),
                );
            }
            K::MINUS
                if matches!(parent, K::NOT_EXPR | K::VALUE_NOT_EXPR)
                    && token
                        .next_token()
                        .is_some_and(|next| next.kind() == K::WHITESPACE) =>
            {
                self.push(
                    codes::DATADOG_DETACHED_OPERATOR,
                    Severity::Warning,
                    "a space after the exclusion `-`: write it against what it excludes (`-@a:b`)"
                        .into(),
                    span(token.text_range()),
                );
            }
            K::PHRASE_TOKEN if parent != K::QUOTED_FIELD => {
                if wildcard_in_phrase(token.text()) {
                    self.push(
                        codes::DATADOG_WILDCARD_IN_PHRASE,
                        Severity::Warning,
                        "a `*` or `?` inside quotes is punctuation, not a wildcard: \
                         `\"*test*\"` searches for the word `test`; take the wildcard out of the \
                         quotes, escaping spaces (`*my\\ test*`)"
                            .into(),
                        span(token.text_range()),
                    );
                }
            }
            K::WORD => self.curly_quotes(token),
            _ => {}
        }
    }

    /// Curly quotes: a pair `“…”` is one mistake, reported on its opening quote; a closing
    /// quote with none open is reported on its own.
    fn curly_quotes(&mut self, token: &SyntaxToken) {
        let mut report = false;
        for c in token.text().chars() {
            match c {
                '\u{201c}' => {
                    report = true;
                    self.curly_open = true;
                }
                '\u{201d}' if self.curly_open => self.curly_open = false,
                '\u{201d}' => report = true,
                _ => {}
            }
        }
        if report {
            self.push(
                codes::DATADOG_CURLY_QUOTE,
                Severity::Warning,
                "a curly quote is not a quote: Datadog searches the words around it as \
                 separate terms; use straight double quotes (`\"…\"`)"
                    .into(),
                span(token.text_range()),
            );
        }
    }

    /// An OR beside an AND, written or implied, with no parentheses between them.
    fn mixed_boolean(&mut self, node: &SyntaxNode) {
        let and = if node.kind() == K::OR_EXPR {
            K::AND_EXPR
        } else {
            K::VALUE_AND_EXPR
        };
        let Some(first) = node.children().find(|c| c.kind() == and) else {
            return;
        };
        // `shorten` reads a bounded prefix: nested ORs do not re-read their whole text.
        let group = shorten(self.text(trimmed(&first)));
        self.push(
            codes::DATADOG_MIXED_BOOLEAN,
            Severity::Warning,
            format!(
                "OR beside AND without parentheses: `{group}` is read as one AND group \
                 ({PRECEDENCE_NOTE}); add parentheses to say which you mean"
            ),
            span(trimmed(node)),
        );
    }

    /// `and`, `or`, `not` in a lower-case spelling where an operator was meant: between two
    /// clauses that are not free text, or anywhere in a value group.
    fn lowercase_operators(&mut self, node: &SyntaxNode) {
        let value = node.kind() == K::VALUE_AND_EXPR;
        let children: Vec<SyntaxNode> = node.children().collect();
        for (i, child) in children.iter().enumerate() {
            let Some(word) = lowercase_operator(child) else {
                continue;
            };
            let between_fields = i > 0
                && i + 1 < children.len()
                && !is_free_text(&children[i - 1])
                && !is_free_text(&children[i + 1]);
            if value || between_fields {
                let upper = word.to_ascii_uppercase();
                self.push(
                    codes::DATADOG_LOWERCASE_OPERATOR,
                    Severity::Warning,
                    format!(
                        "`{word}` is searched as a word, not as an operator: operators are upper \
                         case (`{upper}`)"
                    ),
                    span(trimmed(child)),
                );
            }
        }
    }

    /// A bare key: a dotted one is searched as a tag; `_exists_` and `_missing_` are the
    /// pipelines'. The first argument of `CIDR` must be an `@attribute`.
    fn tag_key(&mut self, node: &SyntaxNode, parent: Option<K>) {
        let range = trimmed(node);
        // The key is read in place; a message's copy is made only when there is a finding.
        let source = self.source;
        let key = source
            .get(usize::from(range.start())..usize::from(range.end()))
            .unwrap_or("");
        if parent == Some(K::CIDR_CALL) {
            let text = shorten(key);
            self.push(
                codes::DATADOG_CIDR,
                Severity::Error,
                format!("`CIDR` takes an attribute first: `@{text}`"),
                span(range),
            );
            return;
        }
        if matches!(key, "_exists_" | "_missing_") {
            let text = key;
            let hint = if text == "_exists_" {
                "`@attribute:*`"
            } else {
                "`-@attribute:*`"
            };
            self.push(
                codes::DATADOG_PIPELINES_ONLY,
                Severity::Warning,
                format!("`{text}:` is Observability Pipelines syntax; in log search write {hint}"),
                span(range),
            );
            return;
        }
        if has_unescaped_dot(key) {
            let text = shorten(key);
            self.push(
                codes::DATADOG_UNKNOWN_ATTRIBUTE,
                Severity::Hint,
                format!(
                    "`{text}` is searched as a tag, not as an attribute: did you mean `@{text}`?"
                ),
                span(range),
            );
        }
    }

    /// `CIDR(…)` with no block.
    fn cidr_call(&mut self, node: &SyntaxNode) {
        let has_field = node
            .children()
            .any(|c| matches!(c.kind(), K::ATTRIBUTE | K::TAG_KEY));
        if has_field && !node.children().any(|c| c.kind() == K::CIDR_BLOCK) {
            self.push(
                codes::DATADOG_CIDR,
                Severity::Error,
                "`CIDR` takes at least one block after the attribute: `CIDR(@ip, 10.0.0.0/8)`"
                    .into(),
                span(trimmed(node)),
            );
        }
    }

    /// A lower-case `to`, and an inclusive bound with an exclusive one.
    fn range(&mut self, node: &SyntaxNode) {
        let mut open = None;
        let mut close = None;
        for element in node.children_with_tokens() {
            let NodeOrToken::Token(token) = element else {
                continue;
            };
            match token.kind() {
                K::L_BRACK | K::L_BRACE => open = Some(token.kind()),
                K::R_BRACK | K::R_BRACE => close = Some(token.kind()),
                K::TO_KW if token.text() != "TO" => {
                    self.push(
                        codes::DATADOG_RANGE,
                        Severity::Error,
                        format!(
                            "`{}` in a range: `TO` is an operator in upper case only",
                            token.text()
                        ),
                        span(token.text_range()),
                    );
                }
                _ => {}
            }
        }
        let mixed = matches!(
            (open, close),
            (Some(K::L_BRACK), Some(K::R_BRACE)) | (Some(K::L_BRACE), Some(K::R_BRACK))
        );
        if mixed {
            self.push(
                codes::DATADOG_RANGE,
                Severity::Warning,
                "the range mixes an inclusive and an exclusive bound (`[ … }`), which Datadog does \
                 not document: use `[ ]` or `{ }` on both ends"
                    .into(),
                span(trimmed(node)),
            );
        }
    }
}

/// The word of a one-word term that spells an operator in a case Datadog does not read as one.
fn lowercase_operator(node: &SyntaxNode) -> Option<String> {
    if node.kind() != K::TERM {
        return None;
    }
    let token = node.first_token()?;
    if token.kind() != K::WORD || node.last_token().as_ref() != Some(&token) {
        return None;
    }
    let text = token.text();
    let is_operator = ["and", "or", "not"]
        .iter()
        .any(|op| text.eq_ignore_ascii_case(op));
    (is_operator && text != text.to_ascii_uppercase()).then(|| text.to_owned())
}

/// A clause of free text (a term or a phrase without a field).
fn is_free_text(node: &SyntaxNode) -> bool {
    matches!(node.kind(), K::TERM | K::PHRASE)
}

/// Whether a key holds a `.` that no backslash escapes.
fn has_unescaped_dot(text: &str) -> bool {
    let mut escaped = false;
    for c in text.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '.' {
            return true;
        }
    }
    false
}

/// Whether a phrase holds a `*` or `?` next to a letter or a digit: `"*test*"`, not `"*"` or
/// `"SELECT *"`.
fn wildcard_in_phrase(phrase: &str) -> bool {
    let chars: Vec<char> = phrase.chars().collect();
    chars.iter().enumerate().any(|(i, &c)| {
        matches!(c, '*' | '?')
            && (i > 0 && chars[i - 1].is_alphanumeric()
                || chars.get(i + 1).is_some_and(|n| n.is_alphanumeric()))
    })
}

/// Whether `text` is an IPv4 or IPv6 address, with an optional prefix length in range.
pub(crate) fn is_cidr_block(text: &str) -> bool {
    let (address, prefix) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text, None),
    };
    let max = if address.parse::<std::net::Ipv4Addr>().is_ok() {
        32
    } else if address.parse::<std::net::Ipv6Addr>().is_ok() {
        128
    } else {
        return false;
    };
    prefix.is_none_or(|p| {
        !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| n <= max)
    })
}

/// `text`, cut to about 40 characters for a message.
fn shorten(text: &str) -> String {
    // Read a bounded prefix only: a message never costs more than its own length.
    let prefix = text
        .get(..text.floor_char_boundary(text.len().min(160)))
        .unwrap_or("");
    let one_line: String = prefix.split_whitespace().collect::<Vec<_>>().join(" ");
    match one_line.char_indices().nth(40) {
        Some((at, _)) => format!("{}…", &one_line[..at]),
        None => one_line,
    }
}

/// The range of `node` without the whitespace at its ends.
pub(crate) fn trimmed(node: &SyntaxNode) -> TextRange {
    let range = node.text_range();
    let mut first = node.first_token();
    while let Some(t) = &first {
        if t.kind() != K::WHITESPACE || !range.contains_range(t.text_range()) {
            break;
        }
        first = t.next_token();
    }
    let mut last = node.last_token();
    while let Some(t) = &last {
        if t.kind() != K::WHITESPACE || !range.contains_range(t.text_range()) {
            break;
        }
        last = t.prev_token();
    }
    match (first, last) {
        (Some(f), Some(l))
            if range.contains_range(f.text_range())
                && range.contains_range(l.text_range())
                && f.text_range().start() <= l.text_range().end() =>
        {
            TextRange::new(f.text_range().start(), l.text_range().end())
        }
        _ => TextRange::empty(range.start()),
    }
}

/// A rowan range as a byte span.
pub(crate) fn span(range: TextRange) -> ByteSpan {
    ByteSpan::new(usize::from(range.start()), usize::from(range.end()))
}

/// The capture of a token held by a node of kind `parent` (RFC §6.8).
fn capture(token: &SyntaxToken, parent: K) -> Option<Capture> {
    if parent == K::ERROR {
        return Some(Capture::ERROR);
    }
    Some(match token.kind() {
        K::WHITESPACE => return None,
        K::AND_KW | K::OR_KW | K::NOT_KW | K::TO_KW | K::AMP_AMP | K::PIPE_PIPE => Capture::KEYWORD,
        K::CIDR_KW => Capture::FUNCTION_BUILTIN,
        K::ESCAPE => Capture::CONSTANT,
        K::WORD | K::NUMBER | K::COLON if parent == K::CIDR_BLOCK => Capture::CONSTANT,
        K::WORD | K::NUMBER | K::STAR | K::QUESTION | K::MINUS | K::PLUS | K::EQ | K::COMMA
            if matches!(parent, K::ATTRIBUTE | K::TAG_KEY) =>
        {
            Capture::PROPERTY
        }
        K::WORD | K::NUMBER | K::STAR | K::QUESTION | K::MINUS | K::PLUS | K::EQ | K::COMMA
            if parent == K::CALCULATED_FIELD =>
        {
            Capture::VARIABLE
        }
        K::PHRASE_TOKEN if parent == K::QUOTED_FIELD => Capture::PROPERTY,
        K::PHRASE_TOKEN | K::UNCLOSED_PHRASE => Capture::STRING,
        K::NUMBER => Capture::NUMBER,
        // A term's text is a value, as Lucene colours its terms; its wildcards stay operators.
        K::WORD if matches!(parent, K::TERM | K::RANGE_BOUND) => Capture::STRING,
        K::COLON | K::COMMA | K::EQ | K::PLUS | K::MINUS if parent == K::TERM => Capture::STRING,
        K::COLON if matches!(parent, K::FIELD_CLAUSE | K::MATCH_ALL) => Capture::OPERATOR,
        K::STAR | K::QUESTION => Capture::OPERATOR,
        K::MINUS | K::PLUS if matches!(parent, K::NOT_EXPR | K::VALUE_NOT_EXPR) => {
            Capture::OPERATOR
        }
        K::GT | K::GT_EQ | K::LT | K::LT_EQ if parent == K::COMPARISON => Capture::OPERATOR,
        K::L_PAREN | K::R_PAREN | K::L_BRACK | K::R_BRACK | K::L_BRACE | K::R_BRACE => {
            Capture::BRACKET
        }
        K::COMMA if parent == K::CIDR_CALL => Capture::DELIMITER,
        K::ERROR_TOKEN => Capture::ERROR,
        _ => return None,
    })
}

#[cfg(test)]
thread_local! {
    /// The elements the walk visited on this thread: [`visits`].
    static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts one element visit, in tests (ADR 0014 §7).
#[inline]
fn count_visit() {
    #[cfg(test)]
    VISITS.set(VISITS.get() + 1);
}

/// How many elements the walk visited on this thread.
#[cfg(test)]
pub(crate) fn visits() -> usize {
    VISITS.get()
}
