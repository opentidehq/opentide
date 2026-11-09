//! A bit-exact port of Python's `difflib.SequenceMatcher` and
//! `difflib.get_close_matches` (CPython 3.13 `Lib/difflib.py`), over strings.
//!
//! The frozen Python CLI suggests "did you mean" values with
//! `difflib.get_close_matches`; the Rust core must suggest the same values in
//! the same order, so this module follows the Python algorithm step by step:
//! the `b2j` index with the "popular element" junk heuristic (`autojunk`, for a
//! second sequence of 200 or more elements), `find_longest_match`,
//! `get_matching_blocks`, `ratio` = 2 * M / T, `quick_ratio`,
//! `real_quick_ratio`, and `get_close_matches`' ordering (the `n` largest
//! `(score, string)` pairs, as `heapq.nlargest` returns them).
//!
//! Python strings are sequences of code points, so the elements here are
//! `char`s (Unicode scalar values), never bytes, and strings compare by code
//! point, which is what `str`'s `Ord` (UTF-8 byte order) gives.
//!
//! `crates/opentide-core/tests/difflib_cases.rs` checks every case of
//! `tests/data/difflib_cases.json`, which `scripts/build/gen_difflib_cases.py`
//! records from Python's own `difflib`.

use std::collections::{HashMap, HashSet};

/// One matching block: `a[a..a + size] == b[b..b + size]` (Python's `Match`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Match {
    /// Start in the first sequence.
    pub a: usize,
    /// Start in the second sequence.
    pub b: usize,
    /// Length of the block.
    pub size: usize,
}

/// Python's `difflib.SequenceMatcher` over the characters of two strings.
///
/// As in Python, the index is built on the second sequence `b`, so to compare
/// one string against many, keep it as `b` and change `a` with
/// [`SequenceMatcher::set_seq1`].
pub struct SequenceMatcher<'j> {
    a: Vec<char>,
    b: Vec<char>,
    isjunk: Option<&'j dyn Fn(char) -> bool>,
    autojunk: bool,
    /// For each element of `b` that is neither junk nor popular, the indices
    /// where it occurs, ascending.
    b2j: HashMap<char, Vec<usize>>,
    /// The elements of `b` `isjunk` holds junk.
    bjunk: HashSet<char>,
    /// The elements of `b` the autojunk heuristic dropped.
    bpopular: HashSet<char>,
    /// Count of each element of `b`, built on the first `quick_ratio`.
    fullbcount: Option<HashMap<char, usize>>,
    matching_blocks: Option<Vec<Match>>,
}

impl std::fmt::Debug for SequenceMatcher<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SequenceMatcher")
            .field("a", &self.a)
            .field("b", &self.b)
            .field("isjunk", &self.isjunk.is_some())
            .field("autojunk", &self.autojunk)
            .finish_non_exhaustive()
    }
}

impl SequenceMatcher<'static> {
    /// `SequenceMatcher(None, a, b)`: no junk function, autojunk on.
    #[must_use]
    pub fn new(a: &str, b: &str) -> Self {
        Self::with_options(a, b, None, true)
    }
}

impl<'j> SequenceMatcher<'j> {
    /// `SequenceMatcher(isjunk, a, b, autojunk)`.
    #[must_use]
    pub fn with_options(
        a: &str,
        b: &str,
        isjunk: Option<&'j dyn Fn(char) -> bool>,
        autojunk: bool,
    ) -> Self {
        let mut matcher = Self {
            a: Vec::new(),
            b: Vec::new(),
            isjunk,
            autojunk,
            b2j: HashMap::new(),
            bjunk: HashSet::new(),
            bpopular: HashSet::new(),
            fullbcount: None,
            matching_blocks: None,
        };
        matcher.set_seq1(a);
        matcher.set_seq2(b);
        matcher
    }

    /// `set_seqs(a, b)`.
    pub fn set_seqs(&mut self, a: &str, b: &str) {
        self.set_seq1(a);
        self.set_seq2(b);
    }

    /// `set_seq1(a)`: change the first sequence, keeping `b`'s index.
    pub fn set_seq1(&mut self, a: &str) {
        self.a = a.chars().collect();
        self.matching_blocks = None;
    }

    /// `set_seq2(b)`: change the second sequence and rebuild its index.
    pub fn set_seq2(&mut self, b: &str) {
        self.b = b.chars().collect();
        self.matching_blocks = None;
        self.fullbcount = None;
        self.chain_b();
    }

    /// Python's `__chain_b`: index `b`, then drop junk and, with autojunk on
    /// and `len(b) >= 200`, every element occurring more than
    /// `len(b) // 100 + 1` times.
    fn chain_b(&mut self) {
        let mut b2j: HashMap<char, Vec<usize>> = HashMap::new();
        for (i, &elt) in self.b.iter().enumerate() {
            b2j.entry(elt).or_default().push(i);
        }

        let mut junk = HashSet::new();
        if let Some(isjunk) = self.isjunk {
            junk.extend(b2j.keys().copied().filter(|&elt| isjunk(elt)));
            for elt in &junk {
                b2j.remove(elt);
            }
        }

        let mut popular = HashSet::new();
        let n = self.b.len();
        if self.autojunk && n >= 200 {
            let ntest = n / 100 + 1;
            popular.extend(
                b2j.iter()
                    .filter(|(_, idxs)| idxs.len() > ntest)
                    .map(|(&elt, _)| elt),
            );
            for elt in &popular {
                b2j.remove(elt);
            }
        }

        self.b2j = b2j;
        self.bjunk = junk;
        self.bpopular = popular;
    }

    /// The first sequence, as characters.
    #[must_use]
    pub fn a(&self) -> &[char] {
        &self.a
    }

    /// The second sequence, as characters.
    #[must_use]
    pub fn b(&self) -> &[char] {
        &self.b
    }

    /// The elements of `b` the autojunk heuristic treats as junk.
    #[must_use]
    pub fn bpopular(&self) -> &HashSet<char> {
        &self.bpopular
    }

    /// The elements of `b` the junk function marks as junk.
    #[must_use]
    pub fn bjunk(&self) -> &HashSet<char> {
        &self.bjunk
    }

    /// `find_longest_match(alo, ahi, blo, bhi)`: the longest matching block in
    /// `a[alo..ahi]` and `b[blo..bhi]`, earliest in `a`, then earliest in `b`,
    /// extended over junk on both sides as Python does. `(alo, blo, 0)` when
    /// nothing matches.
    #[must_use]
    #[expect(
        clippy::similar_names,
        reason = "Python's names (besti, bestj), so the port reads line by line against Lib/difflib.py"
    )]
    pub fn find_longest_match(&self, alo: usize, ahi: usize, blo: usize, bhi: usize) -> Match {
        let (a, b) = (&self.a, &self.b);
        let isbjunk = |c: char| self.bjunk.contains(&c);
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        // j2len[j] = length of the longest match ending with a[i-1] and b[j].
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for (i, elt) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut newj2len: HashMap<usize, usize> = HashMap::new();
            if let Some(indices) = self.b2j.get(elt) {
                for &j in indices {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let prev = j
                        .checked_sub(1)
                        .and_then(|jm1| j2len.get(&jm1).copied())
                        .unwrap_or(0);
                    let k = prev + 1;
                    newj2len.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = newj2len;
        }

        // Extend the best block over equal non-junk elements, then over equal
        // junk elements, on both sides (the popular elements count as
        // non-junk here, exactly as in Python).
        while besti > alo && bestj > blo && !isbjunk(b[bestj - 1]) && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && !isbjunk(b[bestj + bestsize])
            && a[besti + bestsize] == b[bestj + bestsize]
        {
            bestsize += 1;
        }
        while besti > alo && bestj > blo && isbjunk(b[bestj - 1]) && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && isbjunk(b[bestj + bestsize])
            && a[besti + bestsize] == b[bestj + bestsize]
        {
            bestsize += 1;
        }
        Match {
            a: besti,
            b: bestj,
            size: bestsize,
        }
    }

    /// `get_matching_blocks()`: the matching blocks, ascending, adjacent
    /// blocks merged, ending with the dummy `(len(a), len(b), 0)`.
    pub fn get_matching_blocks(&mut self) -> &[Match] {
        let (la, lb) = (self.a.len(), self.b.len());
        if self.matching_blocks.is_none() {
            let mut queue = vec![(0, la, 0, lb)];
            let mut blocks: Vec<Match> = Vec::new();
            while let Some((alo, ahi, blo, bhi)) = queue.pop() {
                let x = self.find_longest_match(alo, ahi, blo, bhi);
                let (i, j, k) = (x.a, x.b, x.size);
                if k > 0 {
                    blocks.push(x);
                    if alo < i && blo < j {
                        queue.push((alo, i, blo, j));
                    }
                    if i + k < ahi && j + k < bhi {
                        queue.push((i + k, ahi, j + k, bhi));
                    }
                }
            }
            blocks.sort_unstable();

            let (mut i1, mut j1, mut k1) = (0, 0, 0);
            let mut non_adjacent = Vec::with_capacity(blocks.len() + 1);
            for m in blocks {
                if i1 + k1 == m.a && j1 + k1 == m.b {
                    k1 += m.size;
                } else {
                    if k1 > 0 {
                        non_adjacent.push(Match {
                            a: i1,
                            b: j1,
                            size: k1,
                        });
                    }
                    (i1, j1, k1) = (m.a, m.b, m.size);
                }
            }
            if k1 > 0 {
                non_adjacent.push(Match {
                    a: i1,
                    b: j1,
                    size: k1,
                });
            }
            non_adjacent.push(Match {
                a: la,
                b: lb,
                size: 0,
            });
            self.matching_blocks = Some(non_adjacent);
        }
        self.matching_blocks.as_deref().unwrap_or_default()
    }

    /// `ratio()`: `2.0 * M / T`, M the matched elements, T the elements of
    /// both sequences; `1.0` when both are empty.
    pub fn ratio(&mut self) -> f64 {
        let matches = self.get_matching_blocks().iter().map(|m| m.size).sum();
        calculate_ratio(matches, self.a.len() + self.b.len())
    }

    /// `quick_ratio()`: an upper bound on [`ratio`](Self::ratio), counting
    /// common elements regardless of order.
    pub fn quick_ratio(&mut self) -> f64 {
        let b = &self.b;
        let fullbcount = self.fullbcount.get_or_insert_with(|| {
            let mut counts = HashMap::new();
            for &elt in b {
                *counts.entry(elt).or_insert(0usize) += 1;
            }
            counts
        });
        // avail[x] = number of x left in b after the a-elements seen so far
        // took theirs; Python's counter may go negative, so this one is i64.
        let mut avail: HashMap<char, i64> = HashMap::new();
        let mut matches = 0usize;
        for &elt in &self.a {
            let numb = match avail.get(&elt) {
                Some(&left) => left,
                None => fullbcount
                    .get(&elt)
                    .map_or(0, |&count| i64::try_from(count).unwrap_or(i64::MAX)),
            };
            avail.insert(elt, numb - 1);
            if numb > 0 {
                matches += 1;
            }
        }
        calculate_ratio(matches, self.a.len() + self.b.len())
    }

    /// `real_quick_ratio()`: an upper bound on [`quick_ratio`](Self::quick_ratio)
    /// from the lengths alone.
    #[must_use]
    pub fn real_quick_ratio(&self) -> f64 {
        let (la, lb) = (self.a.len(), self.b.len());
        calculate_ratio(la.min(lb), la + lb)
    }
}

/// Python's `_calculate_ratio`: `2.0 * matches / length`, or `1.0` for
/// `length == 0`. The operations, and so the rounding, are Python's.
#[expect(
    clippy::cast_precision_loss,
    reason = "Python converts the int counts to float the same way; counts of a string's chars are far below 2^53"
)]
fn calculate_ratio(matches: usize, length: usize) -> f64 {
    if length == 0 {
        return 1.0;
    }
    2.0 * matches as f64 / length as f64
}

/// Python's `difflib.get_close_matches(word, possibilities, n, cutoff)`: the
/// at most `n` possibilities whose `ratio()` against `word` is at least
/// `cutoff`, best first, ties broken by the larger string first (as
/// `heapq.nlargest` orders `(score, x)` pairs).
///
/// Python raises `ValueError` for `n == 0` or a cutoff outside `[0.0, 1.0]`;
/// this returns no matches for them instead.
#[must_use]
pub fn get_close_matches<'a>(
    word: &str,
    possibilities: impl IntoIterator<Item = &'a str>,
    n: usize,
    cutoff: f64,
) -> Vec<String> {
    if n == 0 || !(0.0..=1.0).contains(&cutoff) {
        return Vec::new();
    }
    let mut result: Vec<(f64, &str)> = Vec::new();
    let mut s = SequenceMatcher::with_options("", word, None, true);
    for x in possibilities {
        s.set_seq1(x);
        if s.real_quick_ratio() >= cutoff && s.quick_ratio() >= cutoff {
            let score = s.ratio();
            if score >= cutoff {
                result.push((score, x));
            }
        }
    }
    // heapq.nlargest(n, result) == sorted(result, reverse=True)[:n]; scores
    // are finite and non-negative, so total_cmp orders them as Python does.
    result.sort_by(|p, q| q.0.total_cmp(&p.0).then_with(|| q.1.cmp(p.1)));
    result.truncate(n);
    result.into_iter().map(|(_, x)| x.to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_docstring_examples() {
        let mut s = SequenceMatcher::new("abcd", "bcde");
        assert!((s.ratio() - 0.75).abs() < f64::EPSILON);
        assert!((s.quick_ratio() - 0.75).abs() < f64::EPSILON);
        assert!((s.real_quick_ratio() - 1.0).abs() < f64::EPSILON);

        let s = SequenceMatcher::new(" abcd", "abcd abcd");
        assert_eq!(
            s.find_longest_match(0, 5, 0, 9),
            Match {
                a: 0,
                b: 4,
                size: 5
            }
        );
        let blank = |c: char| c == ' ';
        let s = SequenceMatcher::with_options(" abcd", "abcd abcd", Some(&blank), true);
        assert_eq!(
            s.find_longest_match(0, 5, 0, 9),
            Match {
                a: 1,
                b: 0,
                size: 4
            }
        );
        let s = SequenceMatcher::new("ab", "c");
        assert_eq!(
            s.find_longest_match(0, 2, 0, 1),
            Match {
                a: 0,
                b: 0,
                size: 0
            }
        );

        let mut s = SequenceMatcher::new("abxcd", "abcd");
        assert_eq!(
            s.get_matching_blocks(),
            &[
                Match {
                    a: 0,
                    b: 0,
                    size: 2
                },
                Match {
                    a: 3,
                    b: 2,
                    size: 2
                },
                Match {
                    a: 5,
                    b: 4,
                    size: 0
                },
            ]
        );

        assert_eq!(
            get_close_matches("appel", ["ape", "apple", "peach", "puppy"], 3, 0.6),
            ["apple", "ape"]
        );
    }

    #[test]
    fn both_empty_is_ratio_one() {
        let mut s = SequenceMatcher::new("", "");
        assert!((s.ratio() - 1.0).abs() < f64::EPSILON);
        assert!((s.quick_ratio() - 1.0).abs() < f64::EPSILON);
        assert!((s.real_quick_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn autojunk_drops_popular_elements_of_long_b_only() {
        let long = "a".repeat(199) + "b";
        let s = SequenceMatcher::new("", &long);
        assert!(s.bpopular().contains(&'a'));
        let short = "a".repeat(198) + "b";
        let s = SequenceMatcher::new("", &short);
        assert!(s.bpopular().is_empty());
        let s = SequenceMatcher::with_options("", &long, None, false);
        assert!(s.bpopular().is_empty());
    }

    #[test]
    fn chars_not_bytes() {
        // Two-byte chars: a byte-wise port would count 4 elements per side.
        let mut s = SequenceMatcher::new("éé", "éa");
        assert!((s.ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn invalid_arguments_return_nothing() {
        assert!(get_close_matches("a", ["a"], 0, 0.6).is_empty());
        assert!(get_close_matches("a", ["a"], 1, 1.5).is_empty());
        assert!(get_close_matches("a", ["a"], 1, -0.1).is_empty());
        assert!(get_close_matches("a", ["a"], 1, f64::NAN).is_empty());
    }

    #[test]
    fn ties_put_the_larger_string_first() {
        assert_eq!(
            get_close_matches("ab", ["ac", "ad", "ab", "ab"], 3, 0.0),
            ["ab", "ab", "ad"]
        );
    }
}
