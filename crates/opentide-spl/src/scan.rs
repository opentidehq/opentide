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
    (
        cut(source, word_start, i).to_string(),
        Some((word_start, i)),
    )
}

/// `source[start..end]`, a span the byte scanners of this crate cut: they
/// stop at ASCII bytes or at the end, so its ends are char boundaries. A span
/// that is not fails a debug assertion and reads as empty.
pub(crate) fn cut(source: &str, start: usize, end: usize) -> &str {
    let text = source.get(start..end);
    debug_assert!(text.is_some(), "{start}..{end} in {} bytes", source.len());
    text.unwrap_or_default()
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
    count_nested_scan();
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
/// stage (comments, quoted strings, macros): `skip_hidden`'s shape. Hidden
/// text starts with a quote or a backtick (a comment's three of them): a
/// `Hidden` gives `None` at any other byte, so a scan calls it only at those
/// ([`next_stop`]).
pub(crate) type Hidden = fn(&str, usize, usize) -> Option<usize>;

/// Bytes a scan stops at: those [`Hidden`] text starts with, and `extra`.
const fn stops(extra: &[u8]) -> [bool; 256] {
    let mut table = [false; 256];
    table[b'"' as usize] = true;
    table[b'\'' as usize] = true;
    table[b'`' as usize] = true;
    let mut k = 0;
    while k < extra.len() {
        table[extra[k] as usize] = true;
        k += 1;
    }
    table
}

/// Where [`bracket_pairs`] stops: hidden text and brackets.
const PAIR_STOPS: [bool; 256] = stops(b"[]");
/// Where [`top_level`] stops: hidden text, a stage's `|` and a `[`.
const STAGE_STOPS: [bool; 256] = stops(b"|[");

/// The first byte of `i..end` in `stops`, or `end`: the bytes between are
/// neither hidden text nor anything the scan reads (ADR 0014 §4: the walk
/// called its [`Hidden`] at every byte).
fn next_stop(bytes: &[u8], i: usize, end: usize, stops: &[bool; 256]) -> usize {
    bytes[i..end]
        .iter()
        .position(|&b| stops[usize::from(b)])
        .map_or(end, |at| i + at)
}

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
        i = next_stop(bytes, i, end, &PAIR_STOPS);
        if i >= end {
            break;
        }
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
    #[cfg(test)]
    TOP_LEVELS.set(TOP_LEVELS.get() + 1);
    let bytes = source.as_bytes();
    let (mut out, mut stage_start, mut i) = (Vec::new(), start, start);
    while i < end {
        i = next_stop(bytes, i, end, &STAGE_STOPS);
        if i >= end {
            break;
        }
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

#[cfg(debug_assertions)]
thread_local! {
    static NESTED_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Notes a scan into a subsearch's text by a check that could not jump over
/// it (outside a walk, or a `[` never closed). Debug builds only.
#[inline]
pub(crate) fn count_nested_scan() {
    #[cfg(debug_assertions)]
    NESTED_SCANS.set(NESTED_SCANS.get() + 1);
}

/// How many scans into a subsearch's text this thread made byte by byte
/// ([`count_nested_scan`]); within an analysis of closed subsearches, none.
/// Debug builds only, for `tests/subsearch_depth.rs`. Not API.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn nested_scans() -> usize {
    NESTED_SCANS.get()
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
    enter: impl FnMut(&[(usize, usize)]) -> S,
    stage: impl FnMut(&mut S, usize, (usize, usize)),
) {
    // The plan an analysis installed for this text and range, else one of
    // this walk's own (ADR 0014 §5: the analysis's walks that read the text
    // alike, perf, CIM, declared datasets and the search operators, each
    // scanned it again).
    let installed = PLAN.with(|p| {
        p.borrow()
            .as_ref()
            .filter(|plan| plan.serves(source, (start, end), hidden))
            .map(std::rc::Rc::clone)
    });
    let plan =
        installed.unwrap_or_else(|| std::rc::Rc::new(Plan::new(source, (start, end), hidden)));
    plan.walk(source, order, enter, stage);
}

/// The pipelines of a text, its stages and their subsearches, scanned once:
/// what [`walk_pipelines`] walks, in either [`Order`].
pub(crate) struct Plan {
    at: usize,
    len: usize,
    range: (usize, usize),
    hidden: usize,
    pairs: std::rc::Rc<std::collections::HashMap<usize, usize>>,
    /// Each pipeline: its stages, and for each stage the pipelines of its
    /// subsearches (indices into `frames`). The first is the outer one.
    frames: Vec<Pipeline>,
}

/// A pipeline of a [`Plan`]: its stages, and for each stage the pipelines of
/// its subsearches.
type Pipeline = (Vec<(usize, usize)>, Vec<Vec<usize>>);

impl Plan {
    /// Scans `start..end` of `source` as [`walk_pipelines`] does, every
    /// subsearch to [`MAX_SUBSEARCH_DEPTH`].
    fn new(source: &str, (start, end): (usize, usize), hidden: Hidden) -> Self {
        let pairs = std::rc::Rc::new(bracket_pairs(source, (start, end), hidden));
        let mut frames = vec![(
            top_level(source, (start, end), hidden, &pairs, false),
            Vec::new(),
        )];
        // Each pipeline and its depth, the outer one at 1.
        let mut todo = vec![(0usize, 1usize)];
        while let Some((at, depth)) = todo.pop() {
            let mut subs = Vec::with_capacity(frames[at].0.len());
            for index in 0..frames[at].0.len() {
                let range = frames[at].0[index];
                let inner = if depth > MAX_SUBSEARCH_DEPTH {
                    Vec::new()
                } else {
                    top_level(source, range, hidden, &pairs, true)
                };
                let mut ids = Vec::with_capacity(inner.len());
                for sub in inner {
                    ids.push(frames.len());
                    todo.push((frames.len(), depth + 1));
                    frames.push((top_level(source, sub, hidden, &pairs, false), Vec::new()));
                }
                subs.push(ids);
            }
            frames[at].1 = subs;
        }
        Self {
            at: source.as_ptr() as usize,
            len: source.len(),
            range: (start, end),
            // A function's address names it here: one rule is in use, and a
            // copy of it at another address would only miss the plan and scan
            // again, to the same result (the plan tests hold that).
            hidden: hidden as usize,
            pairs,
            frames,
        }
    }

    /// Whether this plan is of `range` of this very `source` (its address
    /// and length, while the analysis that installed it borrows it).
    fn serves(&self, source: &str, range: (usize, usize), hidden: Hidden) -> bool {
        self.at == source.as_ptr() as usize
            && self.len == source.len()
            && self.range == range
            && self.hidden == hidden as usize
    }

    /// The walk: `enter` opens a pipeline, `stage` checks a stage, depth
    /// first and in order, the subsearches before or after their stage.
    fn walk<S>(
        &self,
        source: &str,
        order: Order,
        mut enter: impl FnMut(&[(usize, usize)]) -> S,
        mut stage: impl FnMut(&mut S, usize, (usize, usize)),
    ) {
        // The stages' own scans jump over a subsearch by it too ([`closing_bracket`]).
        let _installed = Installed::new(source, std::rc::Rc::clone(&self.pairs));
        // Each open pipeline: its plan, its state, the stage being walked and
        // how many of that stage's subsearches are open already.
        let mut frames: Vec<(usize, S, usize, Option<usize>)> =
            vec![(0, enter(&self.frames[0].0), 0, None)];
        while let Some(top) = frames.len().checked_sub(1) {
            let (id, walked, next, inner) = &mut frames[top];
            let (stages, subs) = &self.frames[*id];
            let Some(&range) = stages.get(*next) else {
                frames.pop();
                continue;
            };
            let at = *next;
            let opened = inner.get_or_insert_with(|| {
                if order == Order::StageFirst {
                    stage(walked, at, range);
                }
                0
            });
            if let Some(&child) = subs[at].get(*opened) {
                *opened += 1;
                let entered = enter(&self.frames[child].0);
                frames.push((child, entered, 0, None));
                continue;
            }
            *inner = None;
            if order == Order::SubsearchesFirst {
                stage(walked, at, range);
            }
            *next += 1;
        }
    }
}

thread_local! {
    static PLAN: std::cell::RefCell<Option<std::rc::Rc<Plan>>> =
        const { std::cell::RefCell::new(None) };
}

/// A plan installed for the walks of one analysis of `source`, and the one
/// before it put back on drop.
#[must_use = "the plan is installed while the scope lives"]
pub(crate) struct PlanScope<'a>(Option<std::rc::Rc<Plan>>, std::marker::PhantomData<&'a str>);

/// Scans the whole of `source` once for the analysis's walks, which read it
/// alike (perf, CIM, declared datasets and the search operators). The scope
/// borrows `source`, so the plan, keyed by its address, cannot outlive it.
pub(crate) fn plan_scope(source: &str) -> PlanScope<'_> {
    let plan = std::rc::Rc::new(Plan::new(source, (0, source.len()), skip_hidden));
    PlanScope(
        PLAN.with(|p| p.replace(Some(plan))),
        std::marker::PhantomData,
    )
}

impl Drop for PlanScope<'_> {
    fn drop(&mut self) {
        let before = self.0.take();
        PLAN.with(|p| *p.borrow_mut() = before);
    }
}

#[cfg(test)]
thread_local! {
    /// The pipeline scans on this thread: [`top_levels`].
    static TOP_LEVELS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many times this thread split a pipeline's text into stages or
/// subsearches (ADR 0014 §7).
#[cfg(test)]
pub(crate) fn top_levels() -> usize {
    TOP_LEVELS.get()
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    // [`bracket_pairs`] and [`top_level`] as they were: `hidden` asked at
    // every byte. The scanning walk below reads them, as it did.
    /// Every `[` of `start..end` and the `]` that closes it, found in one pass;
    /// a `[` never closed is absent.
    fn bracket_pairs_bytewise(
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
    fn top_level_bytewise(
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

    /// [`walk_pipelines`] as it was before plans: every pipeline scanned as
    /// the walk reaches it.
    fn walk_scanning<S>(
        source: &str,
        (start, end): (usize, usize),
        hidden: Hidden,
        order: Order,
        mut enter: impl FnMut(&[(usize, usize)]) -> S,
        mut stage: impl FnMut(&mut S, usize, (usize, usize)),
    ) {
        struct Frame<S> {
            stages: Vec<(usize, usize)>,
            state: S,
            next: usize,
            inner: Option<std::vec::IntoIter<(usize, usize)>>,
        }
        let pairs = std::rc::Rc::new(bracket_pairs_bytewise(source, (start, end), hidden));
        let _installed = Installed::new(source, std::rc::Rc::clone(&pairs));
        let stages = |range| top_level_bytewise(source, range, hidden, &pairs, false);
        let mut open = |stages: Vec<(usize, usize)>| {
            let entered = enter(&stages);
            Frame {
                stages,
                state: entered,
                next: 0,
                inner: None,
            }
        };
        let mut frames = vec![open(stages((start, end)))];
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
                    top_level_bytewise(source, range, hidden, &pairs, true).into_iter()
                }
            });
            if let Some(sub) = inner.next() {
                let child = open(stages(sub));
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

    /// Searches like the corpus's, written here: an engine crate reads no file
    /// (`check-io-free.sh`).
    const SAMPLES: &[&str] = &[
        "index=main sourcetype=access_combined status>=500 | stats count by host | where count > 10 | sort - count",
        "index=web [search index=threat | fields src_ip | rename src_ip as clientip] | table _time clientip uri",
        "search index=a \"quoted | pipe\" `macro(arg)` | eval x=if(a==\"[\", 1, 2) | append [| makeresults | eval y=1 [inner]]",
        "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest | `drop_dm_object_name(Processes)`",
        "index=main | join type=left host [search index=other | stats latest(_time) as t by host] | lookup assets ip as src",
        "index=x ``` a comment | with pipes [ ] ``` | stats count",
        "index=x [search index=y [search index=z [search index=w | head 1] | head 2] | head 3]",
        "index=main | eval a=\"unclosed [ | stats count",
        "index=main [search index=b | ",
        "",
    ];

    fn texts() -> Vec<String> {
        let mut out: Vec<String> = SAMPLES.iter().map(|s| (*s).to_owned()).collect();
        let cut: Vec<String> = SAMPLES
            .iter()
            .flat_map(|t| {
                t.char_indices()
                    .step_by(2)
                    .map(|(i, _)| t.get(..i).unwrap().to_owned())
            })
            .collect();
        out.extend(cut);
        let depth = MAX_SUBSEARCH_DEPTH + 3;
        out.push(format!(
            "index=a {}index=b{}",
            "[search ".repeat(depth),
            "]".repeat(depth)
        ));
        out
    }

    type Event = (char, usize, (usize, usize), Vec<(usize, usize)>);

    fn record(
        source: &str,
        order: Order,
        walk: impl Fn(
            &str,
            Order,
            &mut dyn FnMut(&[(usize, usize)]) -> usize,
            &mut dyn FnMut(&mut usize, usize, (usize, usize)),
        ),
    ) -> Vec<Event> {
        let events = std::cell::RefCell::new(Vec::new());
        let opened = std::cell::Cell::new(0);
        walk(
            source,
            order,
            &mut |stages| {
                opened.set(opened.get() + 1);
                events
                    .borrow_mut()
                    .push(('e', opened.get(), (0, 0), stages.to_vec()));
                opened.get()
            },
            &mut |pipeline, index, range| {
                let bracket = closing_bracket(source, range.0);
                events.borrow_mut().push((
                    's',
                    *pipeline,
                    range,
                    vec![(index, bracket.unwrap_or(0))],
                ));
            },
        );
        events.into_inner()
    }

    /// A plan walks the pipelines, in each order, exactly as the scanning walk
    /// did: the same pipelines opened, the same stages checked, in the same
    /// order, with the same subsearch brackets installed (ADR 0014 §5).
    #[test]
    fn a_plan_walks_as_the_scanning_walk() {
        let rules: [Hidden; 2] = [skip_hidden, crate::search_operators::skip_hidden_own];
        for source in texts() {
            for hidden in rules {
                for order in [Order::StageFirst, Order::SubsearchesFirst] {
                    let scanned = record(&source, order, |s, o, e, st| {
                        walk_scanning(s, (0, s.len()), hidden, o, e, st);
                    });
                    let planned = record(&source, order, |s, o, e, st| {
                        Plan::new(s, (0, s.len()), hidden).walk(s, o, e, st);
                    });
                    assert_eq!(planned, scanned, "{source:?}");
                    // Installed for the analysis's rule: another rule's walk
                    // misses it and scans its own, to the same result.
                    let _scope = plan_scope(&source);
                    let installed = record(&source, order, |s, o, e, st| {
                        walk_pipelines(s, (0, s.len()), hidden, o, e, st);
                    });
                    assert_eq!(installed, scanned, "{source:?}");
                }
            }
        }
    }

    /// An analysis scans its pipelines once, for every walk that reads them
    /// (perf, CIM, declared datasets and the search operators share one
    /// rule): the search operators' copy of the rule scanned them a second
    /// time (ADR 0014 §7).
    #[test]
    fn an_analysis_scans_its_pipelines_once() {
        let source = SAMPLES[1];
        let before = top_levels();
        let _ = Plan::new(source, (0, source.len()), skip_hidden);
        let once = top_levels() - before;
        let before = top_levels();
        crate::analyze(source);
        assert_eq!(top_levels() - before, once);
    }

    /// The rule finds hidden text only where [`next_stop`] stops: at a quote
    /// or a backtick, `None` at every other byte, which a scan jumps over
    /// (the [`Hidden`] contract).
    #[test]
    fn hidden_text_starts_only_at_a_stop() {
        let text: String = (0u8..=127)
            .map(char::from)
            .chain(['é', '\u{1F600}'])
            .collect();
        for source in texts().iter().chain([&text]) {
            for (i, byte) in source.bytes().enumerate() {
                if !matches!(byte, b'"' | b'\'' | b'`') {
                    assert_eq!(skip_hidden(source, i, source.len()), None, "{source:?} {i}");
                }
            }
        }
    }

    /// The search operators' rule is the scan's: the same end of hidden text
    /// at every byte of the samples, their prefixes and generated texts.
    #[test]
    fn the_search_operators_rule_is_the_scans() {
        let mut probes = texts();
        let mut seed: u32 = 11;
        for _ in 0..400 {
            let mut t = String::new();
            for _ in 0..(seed >> 16) % 24 {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                t.push(b"\"'`\\a |["[((seed >> 16) % 8) as usize] as char);
            }
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            probes.push(t);
        }
        for source in &probes {
            for end in 0..=source.len() {
                for i in 0..=end {
                    assert_eq!(
                        skip_hidden(source, i, end),
                        crate::search_operators::skip_hidden_own(source, i, end),
                        "{source:?} {i} {end}"
                    );
                }
            }
        }
    }

    thread_local! {
        static ASKED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    fn counting(source: &str, i: usize, end: usize) -> Option<usize> {
        ASKED.set(ASKED.get() + 1);
        skip_hidden(source, i, end)
    }

    /// A scan asks its rule only at the bytes hidden text or a stage's
    /// structure starts with, where it asked at every byte (ADR 0014 §4, §7):
    /// and finds the same stages and pairs.
    #[test]
    fn a_scan_asks_its_rule_only_where_hidden_text_can_start() {
        for source in texts() {
            let range = (0, source.len());
            let pairs = bracket_pairs(&source, range, skip_hidden);
            assert_eq!(
                pairs,
                bracket_pairs_bytewise(&source, range, skip_hidden),
                "{source:?}"
            );
            for inner in [false, true] {
                assert_eq!(
                    top_level(&source, range, skip_hidden, &pairs, inner),
                    top_level_bytewise(&source, range, skip_hidden, &pairs, inner),
                    "{source:?}"
                );
            }
            let stops = source
                .bytes()
                .filter(|&b| PAIR_STOPS[usize::from(b)] || STAGE_STOPS[usize::from(b)])
                .count();
            ASKED.set(0);
            let _ = Plan::new(&source, range, counting);
            let asked = ASKED.get();
            assert!(
                asked <= 3 * stops.max(1),
                "{source:?}: {asked} asks, {stops} stops"
            );
            if source.len() > 40 {
                ASKED.set(0);
                let _ = bracket_pairs_bytewise(&source, range, counting);
                assert!(ASKED.get() > asked, "{source:?}");
            }
        }
    }
}
