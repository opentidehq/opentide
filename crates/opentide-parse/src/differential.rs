//! The differential harness: the gate every language port passes before its
//! old engine is deleted (epic #1219).
//!
//! The harness knows no language and no engine. The caller supplies two
//! [`Engine`]s (the old and the new one) that turn an input into named
//! [`Surfaces`] (diagnostics, highlight tokens, fields, folding, ...) and,
//! for offset-indexed surfaces (hover, completions), into surfaces at one
//! byte offset; a `verdict` (is this input valid, judged from the
//! observation); a lexer that finds token ranges; and token samples for
//! random sentences. From the input files it derives every prefix, token
//! mutations and random sentences, deterministically from a seed, and
//! compares the engines on all of them.
//!
//! Every difference is counted (the run never stops at the first), with up
//! to [`Config::max_examples`] examples per (surface, [`Class`]).
//! [`assert_gates`] turns the report into the pass/fail rule:
//!
//! - valid input ([`Class::Valid`]): zero differences on every surface;
//! - broken input: identical verdicts ([`Class::Verdict`]); message and range
//!   changes ([`Class::Broken`]) are counted and listed, never failed.
//!
//! Offset surfaces are observed at every char boundary of an input up to
//! [`Config::max_offsets`] boundaries; a longer input is sampled at an even
//! stride (always including `0` and the end), so the cost per input is
//! bounded and the sample is the same on every run.
//!
//! Only dev-dependencies enable the `differential` feature: production code
//! never links the old and the new engine together.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Range;

/// Named observations of one input: `(surface name, rendered value)`.
pub type Surfaces = Vec<(String, String)>;

/// One engine under comparison.
pub trait Engine {
    /// The whole-input surfaces of `input`.
    fn observe(&self, input: &str) -> Surfaces;

    /// The surfaces at byte `offset` of `input` (a char boundary): hover,
    /// completions. Empty by default.
    fn observe_at(&self, _input: &str, _offset: usize) -> Surfaces {
        Vec::new()
    }
}

/// An input file: a name for the report and its text.
#[derive(Clone, Debug)]
pub struct Source {
    /// Shown in examples.
    pub name: String,
    /// The text.
    pub text: String,
}

/// What a difference means for the gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// The old engine judged the input valid: any difference fails.
    Valid,
    /// Broken input, same verdict: counted and listed, never failed.
    Broken,
    /// Broken input whose verdict changed: fails.
    Verdict,
}

impl Class {
    /// The name used in the JSON report.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Broken => "broken",
            Self::Verdict => "verdict",
        }
    }
}

/// How a run generates inputs and what it reports.
pub struct Config<'a> {
    /// Valid or not, judged on the observation of either engine.
    pub verdict: &'a dyn Fn(&Surfaces) -> bool,
    /// Token byte ranges of a text, from the caller's lexer.
    pub tokens: &'a dyn Fn(&str) -> Vec<Range<usize>>,
    /// Token texts for inserted tokens and random sentences.
    pub samples: &'a [&'a str],
    /// Seeds every random choice.
    pub seed: u64,
    /// Random mutations per input file.
    pub mutations_per_input: usize,
    /// Random sentences in total.
    pub sentences: usize,
    /// Longest random sentence, in samples.
    pub max_sentence_len: usize,
    /// Prefixes per file (sampled at a stride when a file has more boundaries).
    pub max_prefixes: usize,
    /// Offsets observed per input (sampled at a stride above this).
    pub max_offsets: usize,
    /// Examples kept per (surface, class); the count is never capped.
    pub max_examples: usize,
}

impl<'a> Config<'a> {
    /// A configuration with defaults: seed 1, 20 mutations per file, 500
    /// sentences of up to 12 samples, 200 prefixes, 256 offsets, 5 examples.
    #[must_use]
    pub fn new(
        verdict: &'a dyn Fn(&Surfaces) -> bool,
        tokens: &'a dyn Fn(&str) -> Vec<Range<usize>>,
        samples: &'a [&'a str],
    ) -> Self {
        Self {
            verdict,
            tokens,
            samples,
            seed: 1,
            mutations_per_input: 20,
            sentences: 500,
            max_sentence_len: 12,
            max_prefixes: 200,
            max_offsets: 256,
            max_examples: 5,
        }
    }
}

/// One listed difference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Example {
    /// Where the input came from: `file`, `file#prefix`, `file#mutation`, `sentence`.
    pub origin: String,
    /// The input, cut to 300 characters.
    pub input: String,
    /// The byte offset, for an offset surface.
    pub offset: Option<usize>,
    /// What the old engine observed (cut to 300 characters).
    pub old: String,
    /// What the new engine observed (cut to 300 characters).
    pub new: String,
}

/// The tally of one (surface, class).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    /// Every difference, past the example cap too.
    pub count: usize,
    /// The first [`Config::max_examples`] differences.
    pub examples: Vec<Example>,
}

/// The result of [`run`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The seed the run used.
    pub seed: u64,
    /// Distinct inputs compared.
    pub inputs: usize,
    /// Of those, valid for the old engine.
    pub valid: usize,
    /// Differences per (surface, class).
    pub entries: BTreeMap<(String, Class), Entry>,
}

impl Report {
    fn record(&mut self, key: (&str, Class), cap: usize, example: impl FnOnce() -> Example) {
        let entry = self.entries.entry((key.0.to_owned(), key.1)).or_default();
        entry.count += 1;
        if entry.examples.len() < cap {
            entry.examples.push(example());
        }
    }

    /// The differences of `class`, summed over every surface.
    #[must_use]
    pub fn total(&self, class: Class) -> usize {
        self.entries
            .iter()
            .filter(|((_, c), _)| *c == class)
            .map(|(_, e)| e.count)
            .sum()
    }

    /// The report as JSON: totals per surface and class, with examples.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let differences: Vec<Value> = self
            .entries
            .iter()
            .map(|((surface, class), entry)| {
                let examples: Vec<Value> = entry
                    .examples
                    .iter()
                    .map(|e| {
                        json!({
                            "origin": e.origin, "input": e.input, "offset": e.offset,
                            "old": e.old, "new": e.new,
                        })
                    })
                    .collect();
                json!({
                    "surface": surface, "class": class.name(),
                    "count": entry.count, "examples": examples,
                })
            })
            .collect();
        json!({
            "seed": self.seed,
            "inputs": { "total": self.inputs, "valid": self.valid, "broken": self.inputs - self.valid },
            "differences": differences,
        })
    }

    /// [`Report::to_json`] pretty-printed, for the caller to write where it
    /// wants (the crate does no file I/O).
    #[must_use]
    pub fn to_json_string(&self) -> String {
        let mut text = serde_json::to_string_pretty(&self.to_json()).unwrap_or_default();
        text.push('\n');
        text
    }
}

/// Fail (panic, for a test) with a readable summary unless the gates hold:
/// no difference on valid input, no verdict change on broken input.
///
/// # Panics
/// When a gate fails; the message lists every failing (surface, class) with
/// its count and examples, and the counts of the broken-input changes.
pub fn assert_gates(report: &Report) {
    let mut failures = String::new();
    for ((surface, class), entry) in &report.entries {
        if *class == Class::Broken {
            continue;
        }
        failures.push_str(&format!(
            "\n  {} difference(s) on `{surface}` ({} input)",
            entry.count,
            class.name()
        ));
        for e in &entry.examples {
            failures.push_str(&format!(
                "\n    [{}{}] input {:?}\n      old: {:?}\n      new: {:?}",
                e.origin,
                e.offset.map_or_else(String::new, |o| format!(" @{o}")),
                e.input,
                e.old,
                e.new
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "differential gates failed over {} inputs ({} valid), seed {}:{failures}\n  broken-input changes (not failures): {}",
        report.inputs,
        report.valid,
        report.seed,
        report.total(Class::Broken),
    );
}

/// Compare `old` and `new` over `files` and everything derived from them.
#[must_use]
pub fn run(old: &dyn Engine, new: &dyn Engine, files: &[Source], config: &Config<'_>) -> Report {
    let mut report = Report {
        seed: config.seed,
        ..Report::default()
    };
    let mut seen = HashSet::new();
    for (origin, text) in generate(files, config) {
        if !seen.insert(text.clone()) {
            continue;
        }
        compare(old, new, &origin, &text, config, &mut report);
    }
    report
}

fn compare(
    old: &dyn Engine,
    new: &dyn Engine,
    origin: &str,
    text: &str,
    config: &Config<'_>,
    report: &mut Report,
) {
    let (o, n) = (old.observe(text), new.observe(text));
    let valid = (config.verdict)(&o);
    report.inputs += 1;
    report.valid += usize::from(valid);
    let class = if valid { Class::Valid } else { Class::Broken };
    let cap = config.max_examples;
    if valid != (config.verdict)(&n) {
        let class = if valid { Class::Valid } else { Class::Verdict };
        report.record(("verdict", class), cap, || {
            example(
                origin,
                text,
                None,
                &valid.to_string(),
                &(!valid).to_string(),
            )
        });
    }
    diff_surfaces(report, class, cap, (origin, text, None), &o, &n);
    for offset in sample_offsets(text, config.max_offsets) {
        let (o, n) = (old.observe_at(text, offset), new.observe_at(text, offset));
        diff_surfaces(report, class, cap, (origin, text, Some(offset)), &o, &n);
    }
}

fn diff_surfaces(
    report: &mut Report,
    class: Class,
    cap: usize,
    at: (&str, &str, Option<usize>),
    old: &Surfaces,
    new: &Surfaces,
) {
    let find = |s: &'_ Surfaces, name: &str| {
        s.iter()
            .find(|(n, _)| n == name)
            .map_or("<absent>", |(_, v)| v.as_str())
            .to_owned()
    };
    let names: BTreeSet<&str> = old.iter().chain(new).map(|(n, _)| n.as_str()).collect();
    for name in names {
        let (ov, nv) = (find(old, name), find(new, name));
        if ov != nv {
            report.record((name, class), cap, || example(at.0, at.1, at.2, &ov, &nv));
        }
    }
}

fn example(origin: &str, input: &str, offset: Option<usize>, old: &str, new: &str) -> Example {
    Example {
        origin: origin.to_owned(),
        input: cut(input),
        offset,
        old: cut(old),
        new: cut(new),
    }
}

fn cut(text: &str) -> String {
    text.chars().take(300).collect()
}

/// Char-boundary offsets of `text` (`0` and the end included), at an even
/// stride when there are more than `cap`.
fn sample_offsets(text: &str, cap: usize) -> Vec<usize> {
    let all: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain([text.len()])
        .collect();
    if all.len() <= cap.max(2) {
        return all;
    }
    let step = all.len().div_ceil(cap.max(2) - 1);
    let mut picked: Vec<usize> = all.iter().copied().step_by(step).collect();
    if picked.last() != Some(&text.len()) {
        picked.push(text.len());
    }
    picked
}

/// A seeded xorshift, so a failure reproduces.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
    }
}

/// Files, their prefixes, mutations and random sentences, as `(origin, text)`.
fn generate(files: &[Source], config: &Config<'_>) -> Vec<(String, String)> {
    let mut rng = Rng(config.seed.max(1) | 1);
    let mut out = Vec::new();
    for file in files {
        out.push((file.name.clone(), file.text.clone()));
        for end in sample_offsets(&file.text, config.max_prefixes) {
            out.push((format!("{}#prefix", file.name), file.text[..end].to_owned()));
        }
        let tokens = clean_ranges(&file.text, (config.tokens)(&file.text));
        for _ in 0..config.mutations_per_input {
            if let Some(m) = mutate(&file.text, &tokens, config.samples, &mut rng) {
                out.push((format!("{}#mutation", file.name), m));
            }
        }
    }
    if !config.samples.is_empty() {
        for _ in 0..config.sentences {
            let len = 1 + rng.below(config.max_sentence_len.max(1));
            let words: Vec<&str> = (0..len)
                .map(|_| config.samples[rng.below(config.samples.len())])
                .collect();
            out.push(("sentence".to_owned(), words.join(" ")));
        }
    }
    out
}

/// Keep ranges inside `text`, on char boundaries, sorted and disjoint.
fn clean_ranges(text: &str, mut ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    ranges.retain(|r| {
        r.start < r.end
            && r.end <= text.len()
            && text.is_char_boundary(r.start)
            && text.is_char_boundary(r.end)
    });
    ranges.sort_by_key(|r| (r.start, r.end));
    let mut end = 0;
    ranges.retain(|r| {
        let keep = r.start >= end;
        end = end.max(r.end);
        keep
    });
    ranges
}

/// One mutation: delete, duplicate or swap a token, insert a sample,
/// duplicate a line, unbalance a bracket, strip a quote. `None` when the
/// chosen mutation does not apply to this text.
fn mutate(text: &str, tokens: &[Range<usize>], samples: &[&str], rng: &mut Rng) -> Option<String> {
    let token = |i: usize| &text[tokens[i].clone()];
    let splice = |range: Range<usize>, with: &str| {
        format!("{}{with}{}", &text[..range.start], &text[range.end..])
    };
    let char_at = |set: &str| {
        let hits: Vec<(usize, char)> = text
            .char_indices()
            .filter(|(_, c)| set.contains(*c))
            .collect();
        (!hits.is_empty()).then_some(hits)
    };
    match rng.below(7) {
        0 if !tokens.is_empty() => Some(splice(tokens[rng.below(tokens.len())].clone(), "")),
        1 if !tokens.is_empty() => {
            let i = rng.below(tokens.len());
            Some(splice(
                tokens[i].end..tokens[i].end,
                &format!(" {}", token(i)),
            ))
        }
        2 if tokens.len() > 1 => {
            let i = rng.below(tokens.len() - 1);
            let between = &text[tokens[i].end..tokens[i + 1].start];
            let swapped = format!("{}{between}{}", token(i + 1), token(i));
            Some(splice(tokens[i].start..tokens[i + 1].end, &swapped))
        }
        3 if !samples.is_empty() => {
            let at = tokens
                .get(rng.below(tokens.len().max(1)))
                .map_or(0, |r| r.start);
            Some(splice(
                at..at,
                &format!("{} ", samples[rng.below(samples.len())]),
            ))
        }
        4 => {
            let lines: Vec<&str> = text.split_inclusive('\n').collect();
            let i = rng.below(lines.len());
            let line = lines.get(i)?;
            let sep = if line.ends_with('\n') { "" } else { "\n" };
            let start: usize = lines[..i].iter().map(|l| l.len()).sum();
            Some(splice(start..start, &format!("{line}{sep}")))
        }
        5 | 6 => {
            let hits = char_at(if rng.below(2) == 0 { "()[]{}" } else { "\"'`" })?;
            let (at, c) = hits[rng.below(hits.len())];
            Some(splice(at..at + c.len_utf8(), ""))
        }
        _ => None,
    }
}
