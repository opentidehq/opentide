//! Lexical helpers the SPL checks share: pipeline segments, subsearches,
//! comments, quoted strings and macros. They work on byte offsets into the
//! authored text and never rewrite it.

use super::Catalog;

pub(crate) fn split_segments(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut seg_start = start;
    let mut brackets = 0i32;
    let mut segs = Vec::new();
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        match bytes[i] {
            // Parentheses are not counted: Splunk splits on `|` inside them.
            b'|' if brackets == 0 => {
                segs.push((seg_start, i));
                seg_start = i + 1;
            }
            b'[' => brackets += 1,
            b']' if brackets > 0 => brackets -= 1,
            _ => {}
        }
        i += 1;
    }
    if seg_start < end {
        segs.push((seg_start, end));
    }
    segs
}

pub(crate) fn command_word(
    source: &str,
    start: usize,
    end: usize,
) -> (String, Option<(usize, usize)>) {
    let bytes = source.as_bytes();
    let mut i = start;
    while i < end && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= end {
        return (String::new(), None);
    }
    let c = bytes[i];
    if !(c.is_ascii_alphabetic() || c == b'_') {
        return (String::new(), None);
    }
    let word_start = i;
    i += 1;
    while i < end && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    (source[word_start..i].to_string(), Some((word_start, i)))
}

pub(crate) fn skip_hidden(source: &str, i: usize, end: usize) -> Option<usize> {
    if let Some(next) = skip_comment(source, i, end) {
        return Some(next);
    }
    let bytes = source.as_bytes();
    if i >= end {
        return None;
    }
    if bytes[i] == b'"' || bytes[i] == b'\'' {
        return Some(end_quoted(bytes, i, end));
    }
    if bytes[i] == b'`' {
        return Some(end_of_macro(bytes, i, end));
    }
    None
}

pub(crate) fn skip_comment(source: &str, i: usize, end: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if i + 3 <= end && &bytes[i..i + 3] == b"```" {
        let mut j = i + 3;
        while j + 3 <= end && &bytes[j..j + 3] != b"```" {
            j += 1;
        }
        return Some((j + 3).min(end));
    }
    None
}

pub(crate) fn skip_ws_and_comments(source: &str, mut i: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    loop {
        while i < end && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if let Some(next) = skip_comment(source, i, end) {
            i = next;
            continue;
        }
        break;
    }
    i
}

pub(crate) fn read_word(source: &str, i: usize, end: usize) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    if i >= end || !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
        return None;
    }
    let mut j = i + 1;
    while j < end && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
        j += 1;
    }
    Some((i, j))
}

pub(crate) fn end_quoted(bytes: &[u8], start: usize, end: usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < end {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return (i + 1).min(end);
        }
        i += 1;
    }
    end
}

pub(crate) fn end_of_macro(bytes: &[u8], start: usize, end: usize) -> usize {
    let mut i = start + 1;
    while i < end && bytes[i] != b'`' {
        i += 1;
    }
    (i + 1).min(end)
}

/// The end of the `[ ... ]` subsearch that opens at `start` (past its `]`).
pub(crate) fn end_of_brackets(source: &str, start: usize, end: usize) -> usize {
    if let Some(close) = closing_bracket(source, start) {
        return if close < end { close + 1 } else { end };
    }
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut i = start;
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    end
}

pub(crate) fn skip_ws(bytes: &[u8], mut i: usize, end: usize) -> usize {
    while i < end && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// The stage that reads the index: the first stage when the pipeline does
/// not start with `|` (Splunk runs it as `search`), or a leading
/// `| search ...`. A leading `| tstats`, `| inputlookup` and the like read no
/// raw events, and every later stage filters results already in the pipeline.
pub(crate) fn base_search(
    source: &str,
    segments: &[(usize, usize)],
    catalog: &Catalog,
) -> Option<(usize, usize)> {
    let blank = |&(s, e): &(usize, usize)| skip_ws_and_comments(source, s, e) >= e;
    let first = *segments.first()?;
    if !blank(&first) {
        let (word, span) = command_word(source, first.0, first.1);
        let is_command = span.is_some_and(|(_, word_end)| {
            catalog.command(&word).is_some() && !is_field(source, word_end, first.1)
        });
        return (!is_command || word.eq_ignore_ascii_case("search")).then_some(first);
    }
    // A leading `|`: only an explicit `search` reads the index.
    let second = *segments.get(1)?;
    let (word, _) = command_word(source, second.0, second.1);
    word.eq_ignore_ascii_case("search").then_some(second)
}

/// Whether the word ending at `at` is a field (`stats=1`), not a command.
pub(crate) fn is_field(source: &str, at: usize, end: usize) -> bool {
    let i = skip_ws_and_comments(source, at, end);
    matches!(source.as_bytes().get(i), Some(b'=' | b'!' | b'<' | b'>'))
}

/// Subsearches nested deeper than the parser accepts (its `MAX_DEPTH` over
/// what one subsearch costs: 256 levels) are not walked: the parser has
/// reported the query, and every level a walk descends rescans the text
/// inside it.
pub(crate) const MAX_SUBSEARCH_DEPTH: usize =
    (crate::syntax::MAX_DEPTH / crate::syntax::SUBSEARCH_WEIGHT_LEVELS) as usize;

/// When a stage's subsearches are walked: before its own checks or after.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Order {
    SubsearchesFirst,
    StageFirst,
}

/// What a walk skips as text that cannot open or close a subsearch or end a
/// stage (comments, quoted strings, macros): `skip_hidden`'s shape.
pub(crate) type Hidden = fn(&str, usize, usize) -> Option<usize>;

/// Every `[` of `start..end` and the `]` that closes it, found in one pass;
/// a `[` never closed is absent.
fn bracket_pairs(
    source: &str,
    (start, end): (usize, usize),
    hidden: Hidden,
) -> std::collections::HashMap<usize, usize> {
    let bytes = source.as_bytes();
    let (mut open, mut pairs) = (Vec::new(), std::collections::HashMap::new());
    let mut i = start;
    while i < end {
        if let Some(next) = hidden(source, i, end) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'[' => open.push(i),
            b']' => {
                if let Some(at) = open.pop() {
                    pairs.insert(at, i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    pairs
}

/// The stages of `start..end` and, with `inner`, the subsearches of it, at
/// its top level: a subsearch is jumped over by its pair, never rescanned
/// (each level of a walk read all the text nested inside it). After a `[`
/// never closed nothing splits, and it opens no subsearch, as before.
fn top_level(
    source: &str,
    (start, end): (usize, usize),
    hidden: Hidden,
    pairs: &std::collections::HashMap<usize, usize>,
    inner: bool,
) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let (mut out, mut stage_start, mut i) = (Vec::new(), start, start);
    while i < end {
        if let Some(next) = hidden(source, i, end) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'|' if !inner => {
                out.push((stage_start, i));
                stage_start = i + 1;
            }
            b'[' => match pairs.get(&i) {
                Some(&close) if close < end => {
                    if inner {
                        out.push((i + 1, close));
                    }
                    i = close + 1;
                    continue;
                }
                _ => break,
            },
            _ => {}
        }
        i += 1;
    }
    if !inner && stage_start < end {
        out.push((stage_start, end));
    }
    out
}

/// The source and bracket pairs of the walk running on this thread.
type Pairs = (
    usize,
    usize,
    std::rc::Rc<std::collections::HashMap<usize, usize>>,
);

thread_local! {
    static PAIRS: std::cell::RefCell<Option<Pairs>> = const { std::cell::RefCell::new(None) };
}

/// Installs a walk's pairs for its stages, and puts back the ones before it.
struct Installed(Option<Pairs>);

impl Installed {
    fn new(source: &str, pairs: std::rc::Rc<std::collections::HashMap<usize, usize>>) -> Self {
        let mine = (source.as_ptr() as usize, source.len(), pairs);
        Installed(PAIRS.with(|p| p.replace(Some(mine))))
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        let before = self.0.take();
        PAIRS.with(|p| *p.borrow_mut() = before);
    }
}

/// The `]` that closes the `[` at `open`, from the walk running on this
/// thread over `source`; `None` outside a walk or for a `[` never closed, and
/// the caller scans. A stage checked within a walk then reads a subsearch's
/// text once, not once per level above it.
pub(crate) fn closing_bracket(source: &str, open: usize) -> Option<usize> {
    PAIRS.with(|p| match &*p.borrow() {
        Some((at, len, pairs)) if *at == source.as_ptr() as usize && *len == source.len() => {
            pairs.get(&open).copied()
        }
        _ => None,
    })
}

/// One pipeline [`walk_pipelines`] is walking.
struct Frame<S> {
    stages: Vec<(usize, usize)>,
    state: S,
    /// The stage being walked, and its subsearches not walked yet.
    next: usize,
    inner: Option<std::vec::IntoIter<(usize, usize)>>,
}

impl<S> Frame<S> {
    fn open(stages: Vec<(usize, usize)>, enter: &mut impl FnMut(&[(usize, usize)]) -> S) -> Self {
        let opened = enter(&stages);
        Frame {
            stages,
            state: opened,
            next: 0,
            inner: None,
        }
    }
}

/// Walks the pipeline `start..end` and every subsearch in it, depth first and
/// in order, as a recursion over the subsearches would, but on a stack of its
/// own: a recursion per `[` overflowed a 1 MB stack on a query nested 1,000
/// deep. `enter` opens a pipeline (its stages given) and returns its state;
/// `stage` checks one stage (its index in the pipeline) with that state.
pub(crate) fn walk_pipelines<S>(
    source: &str,
    (start, end): (usize, usize),
    hidden: Hidden,
    order: Order,
    mut enter: impl FnMut(&[(usize, usize)]) -> S,
    mut stage: impl FnMut(&mut S, usize, (usize, usize)),
) {
    let pairs = std::rc::Rc::new(bracket_pairs(source, (start, end), hidden));
    // The stages' own scans jump over a subsearch by it too ([`closing_bracket`]).
    let _installed = Installed::new(source, std::rc::Rc::clone(&pairs));
    let stages = |range| top_level(source, range, hidden, &pairs, false);
    let mut frames = vec![Frame::open(stages((start, end)), &mut enter)];
    while let Some(top) = frames.len().checked_sub(1) {
        let depth = frames.len();
        let frame = &mut frames[top];
        let Some(&range) = frame.stages.get(frame.next) else {
            frames.pop();
            continue;
        };
        let at = frame.next;
        let inner = frame.inner.get_or_insert_with(|| {
            if order == Order::StageFirst {
                stage(&mut frame.state, at, range);
            }
            if depth > MAX_SUBSEARCH_DEPTH {
                Vec::new().into_iter()
            } else {
                top_level(source, range, hidden, &pairs, true).into_iter()
            }
        });
        if let Some(sub) = inner.next() {
            let child = Frame::open(stages(sub), &mut enter);
            frames.push(child);
            continue;
        }
        frame.inner = None;
        if order == Order::SubsearchesFirst {
            stage(&mut frame.state, at, range);
        }
        frame.next += 1;
    }
}
