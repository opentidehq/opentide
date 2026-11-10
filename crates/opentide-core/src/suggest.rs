//! "Did you mean" suggestions: the allowed value a mistyped one most likely
//! means.
//!
//! One rule for every caller (vocabulary values, configuration choices, CLI
//! commands and options), so the editor, `validate` and the CLI never suggest
//! different things for the same typo:
//!
//! 1. **The same word wins outright.** A candidate equal to the value once
//!    case, whitespace, `-` and `_` are ignored (`AMBER` → `amber`,
//!    `localised_incident` → `Localised incident`) is the answer
//!    (`docs/internal/cli-experience.md`, "Forgiving input").
//! 2. **Otherwise the fewest edits.** The optimal string alignment distance
//!    ([`strsim::osa_distance`]: insertions, deletions, substitutions and
//!    transpositions of adjacent characters, each one edit) between the
//!    lower-cased spellings, counted in characters. A candidate qualifies when
//!    it is at most [`max_edits`] away (a third of the length, at least one
//!    edit: the bound rustc uses for its own suggestions), measured twice: over
//!    the whole value, and over the words that hold the part that differs
//!    once the prefix and suffix both spellings share are set aside. A typo
//!    is a few edits in one word, adjacent or not (`SecurityEve` →
//!    `SecurityEvent`, two letters cut); a different word is many, and
//!    sharing ` incident` with it does not make `Big incident` a typo of
//!    `Minor incident` (`big`/`minor`: four edits in a five-letter word).
//!    A caller with its own bound ([`closest_within`], [`ranked`]) caps both.
//! 3. **Ties** go to the candidate whose start matches best
//!    ([`strsim::jaro_winkler`]), then to the one that sorts first, so the
//!    result never depends on the order the candidates came in.
//!
//! [`best`] applies rules 1 and 3, with the fewest edits between them, and no
//! bound: for a check whose own threshold decides whether a near miss is
//! reported at all.
//!
//! This is deliberately not Python's `difflib.get_close_matches`: a ratio of
//! matching blocks suggests unrelated words that share letters (`Big
//! incident` → `Substantial incident`), and an edit distance does not.

use std::cmp::Ordering;

/// The most edits a candidate may be from a value of `len` characters and
/// still be suggested: a third of the length, at least one.
pub fn max_edits(len: usize) -> usize {
    len.max(3) / 3
}

/// `value` without case, whitespace, `-` or `_`: two spellings that fold to
/// the same string are the same word.
pub fn fold(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

/// The candidate `value` most likely means, if any is close enough
/// ([`max_edits`]).
pub fn closest<'a>(value: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    suggestions(value, candidates, 1).into_iter().next()
}

/// The candidate `value` most likely means, within `edits` edits.
pub fn closest_within<'a>(
    value: &str,
    candidates: impl IntoIterator<Item = &'a str>,
    edits: usize,
) -> Option<&'a str> {
    ranked(value, candidates, edits, 1).into_iter().next()
}

/// Up to `limit` candidates `value` may mean, best first ([`max_edits`]).
pub fn suggestions<'a>(
    value: &str,
    candidates: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Vec<&'a str> {
    ranked(value, candidates, max_edits(value.chars().count()), limit)
}

/// Up to `limit` candidates within `edits` edits of `value`, best first.
/// A candidate equal to `value` once folded ([`fold`]) qualifies whatever
/// `edits` is, and ranks before every other.
pub fn ranked<'a>(
    value: &str,
    candidates: impl IntoIterator<Item = &'a str>,
    edits: usize,
    limit: usize,
) -> Vec<&'a str> {
    let candidates: Vec<&'a str> = candidates.into_iter().collect();
    Candidates::new(candidates.iter().copied())
        .ranked(value, edits, limit)
        .into_iter()
        .map(|index| candidates[index])
        .collect()
}

/// The candidate the shared order (rules 1 and 3, with the fewest edits
/// between) puts first, with no bound on the edits: for a check whose own
/// threshold decides whether a near miss is reported at all, and which only
/// needs this rule to choose among the candidates it accepted.
///
/// Whether a diagnostic is reported, and at what severity, is a contract
/// (plan §3, invariant 3), so a check that reports only near misses (an ECS
/// field, a CIM data model, a KQL column of a documented table) keeps its own
/// threshold; what it suggests comes from here, as everywhere else. `Some`
/// whenever `candidates` is not empty, even when the value itself is among
/// them.
pub fn best<'a>(value: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let lower = value.to_lowercase();
    let folded = fold(value);
    candidates
        .into_iter()
        .map(|candidate| {
            let other = candidate.to_lowercase();
            let (a, b) = middles(&lower, &other);
            Scored {
                candidate,
                index: 0,
                same_word: fold(candidate) == folded,
                distance: strsim::osa_distance(a, b),
                prefix: strsim::jaro_winkler(&lower, &other),
            }
        })
        .min_by(Scored::order)
        .map(|s| s.candidate)
}

/// Candidates prepared once (lower-cased, folded, measured) for many
/// lookups: a field's allowed values, checked for every value of a
/// workspace. Results are indices into the candidates as given.
#[derive(Debug, Clone, Default)]
pub struct Candidates {
    items: Vec<Prepared>,
}

#[derive(Debug, Clone)]
struct Prepared {
    index: usize,
    text: String,
    lower: String,
    folded: String,
    length: usize,
}

impl Candidates {
    /// Prepares `candidates`; a repeated one keeps its first index.
    pub fn new<'a>(candidates: impl IntoIterator<Item = &'a str>) -> Self {
        let mut seen = std::collections::HashSet::new();
        let items = candidates
            .into_iter()
            .enumerate()
            .filter(|(_, text)| seen.insert(*text))
            .map(|(index, text)| {
                let lower = text.to_lowercase();
                Prepared {
                    index,
                    text: text.to_owned(),
                    length: lower.chars().count(),
                    folded: fold(text),
                    lower,
                }
            })
            .collect();
        Self { items }
    }

    /// The index of the candidate `value` most likely means ([`max_edits`]).
    pub fn closest(&self, value: &str) -> Option<usize> {
        self.ranked(value, max_edits(value.chars().count()), 1)
            .into_iter()
            .next()
    }

    /// The indices of up to `limit` candidates within `edits` edits of
    /// `value`, best first ([`ranked`]).
    pub fn ranked(&self, value: &str, edits: usize, limit: usize) -> Vec<usize> {
        let folded = fold(value);
        let lower = value.to_lowercase();
        let length = lower.chars().count();
        let mut scored: Vec<Scored<'_>> = Vec::new();
        for item in &self.items {
            if item.text == value {
                continue;
            }
            let same_word = item.folded == folded;
            // The distance is at least the difference in length: skip the rest.
            if !same_word && item.length.abs_diff(length) > edits {
                continue;
            }
            // A common prefix and suffix cost no edit: measure what lies
            // between, against a third of the words it falls in.
            let (a, b) = middles(&lower, &item.lower);
            let (wa, wb) = words(&lower, &item.lower);
            let differing = wa.chars().count().max(wb.chars().count());
            let bound = edits.min(max_edits(differing));
            if !same_word && a.chars().count().abs_diff(b.chars().count()) > bound {
                continue;
            }
            let distance = strsim::osa_distance(a, b);
            if !same_word && distance > bound {
                continue;
            }
            scored.push(Scored {
                candidate: &item.text,
                index: item.index,
                same_word,
                distance,
                prefix: strsim::jaro_winkler(&lower, &item.lower),
            });
        }
        scored.sort_by(Scored::order);
        scored.into_iter().take(limit).map(|s| s.index).collect()
    }
}

/// What is left of `a` and `b` once the prefix and the suffix they share are
/// set aside: the part an edit has to change.
fn middles<'s>(a: &'s str, b: &'s str) -> (&'s str, &'s str) {
    let (prefix, suffix) = shared(a, b);
    (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix])
}

/// The lengths, in bytes, of the prefix and the suffix `a` and `b` share; the
/// suffix is taken from what the prefix leaves, so the two never overlap.
fn shared(a: &str, b: &str) -> (usize, usize) {
    let prefix: usize = a
        .chars()
        .zip(b.chars())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x.len_utf8())
        .sum();
    let suffix: usize = a[prefix..]
        .chars()
        .rev()
        .zip(b[prefix..].chars().rev())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x.len_utf8())
        .sum();
    (prefix, suffix)
}

/// The whole words of `a` and `b` that hold their differing part
/// ([`middles`]): the middles widened, through the shared prefix and suffix,
/// to the nearest whitespace on each side. A typo is bound by the length of
/// the word it is in, so `SecurityEve` (two letters cut from a thirteen-letter
/// name) is a typo of `SecurityEvent`, while `Big incident` is not one of
/// `Minor incident`: its differing word, `big`/`minor`, is too short for four
/// edits.
fn words<'s>(a: &'s str, b: &'s str) -> (&'s str, &'s str) {
    let (prefix, suffix) = shared(a, b);
    // The prefix and the suffix are the same text in both spellings.
    let start = a[..prefix]
        .char_indices()
        .rev()
        .find(|(_, c)| c.is_whitespace())
        .map_or(0, |(i, c)| i + c.len_utf8());
    let tail = &a[a.len() - suffix..];
    let end = suffix
        - tail
            .char_indices()
            .find(|(_, c)| c.is_whitespace())
            .map_or(suffix, |(i, _)| i);
    (&a[start..a.len() - end], &b[start..b.len() - end])
}

struct Scored<'a> {
    candidate: &'a str,
    index: usize,
    same_word: bool,
    distance: usize,
    prefix: f64,
}

impl Scored<'_> {
    fn order(a: &Self, b: &Self) -> Ordering {
        b.same_word
            .cmp(&a.same_word)
            .then(a.distance.cmp(&b.distance))
            .then(b.prefix.total_cmp(&a.prefix))
            .then(a.candidate.cmp(b.candidate))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLP: [&str; 4] = ["clear", "green", "amber", "red"];

    #[test]
    fn the_same_word_wins_outright() {
        assert_eq!(closest("AMBER", TLP), Some("amber"));
        assert_eq!(
            closest(
                "localised_incident",
                ["Localised incident", "Local incident"]
            ),
            Some("Localised incident")
        );
        assert_eq!(closest("high", ["High", "Higher"]), Some("High"));
        assert_eq!(closest("dry-run", ["dry_run", "dry"]), Some("dry_run"));
    }

    /// The same word ranks first even when another candidate is fewer edits
    /// away: `a_b_c` is `abc` (two edits) before it is `a_b_x` (one).
    #[test]
    fn the_same_word_ranks_before_a_closer_spelling() {
        assert_eq!(closest("a_b_c", ["a_b_x", "abc"]), Some("abc"));
        assert_eq!(suggestions("a_b_c", ["abc", "a_b_x"], 2), ["abc", "a_b_x"]);
    }

    #[test]
    fn one_edit_finds_the_value() {
        assert_eq!(closest("clearr", TLP), Some("clear"));
        assert_eq!(closest("ambr", TLP), Some("amber"));
        assert_eq!(closest("rde", TLP), Some("red"));
        assert_eq!(closest("gren", TLP), Some("green"));
    }

    #[test]
    fn a_different_word_finds_nothing() {
        assert_eq!(closest("whitish", TLP), None);
        assert_eq!(
            closest("Big incident", ["Substantial incident", "Minor incident"]),
            None
        );
        assert_eq!(closest("", TLP), None);
        assert_eq!(
            closest("Host::Gizmo", ["Host::File", "Host::Process"]),
            None
        );
    }

    #[test]
    fn typos_in_long_phrases_are_found() {
        let severities = [
            "Localised incident",
            "Moderate incident",
            "Substantial incident",
        ];
        assert_eq!(
            closest("Localised incidnet", severities),
            Some("Localised incident")
        );
        assert_eq!(
            closest("Localsed incidnet", severities),
            Some("Localised incident")
        );
        assert_eq!(
            closest("Moderat incident", severities),
            Some("Moderate incident")
        );
        assert_eq!(middles("big incident", "minor incident"), ("big", "minor"));
        assert_eq!(middles("clearr", "clear"), ("r", ""));
        assert_eq!(middles("aa", "aaa"), ("", "a"));
        assert_eq!(middles("zürich", "zürch"), ("i", ""));
    }

    /// Two edits side by side, or two characters cut or added at one place,
    /// are bound by the word they are in, not by the two characters that
    /// differ: a long name keeps its suggestion.
    #[test]
    fn adjacent_edits_and_truncations_are_found() {
        assert_eq!(
            closest("SecurityEve", ["SecurityEvent", "Event"]),
            Some("SecurityEvent")
        );
        assert_eq!(closest("summari", ["summarize"]), Some("summarize"));
        assert_eq!(
            closest("DeviceProcessEven", ["DeviceProcessEvents"]),
            Some("DeviceProcessEvents")
        );
        assert_eq!(closest("plXYet", ["planet"]), Some("planet"));
        let uuid = "00000000-0000-0000-0000-000000000001";
        for typo in [
            "00000000-0000-0000-0000-0000000000ab",
            "00000000-0000-0000-0000-0000000001",
            "00000000-0000-0000-0000-00000000000100",
        ] {
            assert_eq!(closest_within(typo, [uuid], 2), Some(uuid), "{typo}");
        }
        // The caller's bound still caps it.
        assert_eq!(
            closest_within("00000000-0000-0000-0000-000000000abc", [uuid], 2),
            None
        );
        // Only the words that differ count: a short differing word in a
        // phrase is still bound by its own length.
        assert_eq!(words("big incident", "minor incident"), ("big", "minor"));
        assert_eq!(
            words("severe planet incident", "severe glands incident"),
            ("planet", "glands")
        );
        assert_eq!(
            words("securityeve", "securityevent"),
            ("securityeve", "securityevent")
        );
        assert_eq!(words("a bc d", "a bxc d"), ("bc", "bxc"));
        assert_eq!(words("one two", "one two"), ("two", "two"));
    }

    #[test]
    fn the_bound_is_a_third_of_the_length() {
        assert_eq!(max_edits(0), 1);
        assert_eq!(max_edits(3), 1);
        assert_eq!(max_edits(5), 1);
        assert_eq!(max_edits(6), 2);
        assert_eq!(max_edits(9), 3);
        assert_eq!(
            closest_within("T1059.01", ["T1059.001", "T1059"], 1),
            Some("T1059.001")
        );
        assert_eq!(closest_within("T1234.567", ["T1059.001"], 1), None);
    }

    /// The bound is inclusive and exact: a six-letter word takes two edits,
    /// never three, over the whole value and over the part that differs.
    #[test]
    fn the_bound_is_exact() {
        assert_eq!(max_edits("planet".len()), 2);
        // p→g, t→s: two edits, no shared prefix or suffix.
        assert_eq!(closest("planet", ["glanes"]), Some("glanes"));
        // p→g, e→d, t→s: three.
        assert_eq!(closest("planet", ["glands"]), None);
        // In a phrase, the differing middle (`planet`, six letters) is bound
        // to two edits, though the whole phrase would allow seven.
        assert_eq!(
            closest("Severe planet incident", ["Severe glanes incident"]),
            Some("Severe glanes incident")
        );
        assert_eq!(
            closest("Severe planet incident", ["Severe glands incident"]),
            None
        );
    }

    #[test]
    fn ties_do_not_depend_on_the_order_of_the_candidates() {
        let forward = suggestions("bat", ["cat", "bad", "hat"], 3);
        let backward = suggestions("bat", ["hat", "bad", "cat"], 3);
        assert_eq!(forward, backward);
        // `bad` keeps the first two characters; the rest sort by name.
        assert_eq!(forward, ["bad", "cat", "hat"]);
    }

    #[test]
    fn the_value_itself_and_duplicates_are_not_suggested() {
        assert_eq!(suggestions("red", ["red", "rad", "rad"], 5), ["rad"]);
    }

    #[test]
    fn best_orders_without_a_bound() {
        // The same word first, then the fewest edits, then the best start.
        assert_eq!(
            best("Process_Name", ["process_title", "process_name"]),
            Some("process_name")
        );
        assert_eq!(best("stast", ["stash", "stats"]), Some("stats"));
        assert_eq!(best("bat", ["hat", "cat", "bad"]), Some("bad"));
        assert_eq!(best("bat", ["hat", "cat"]), Some("cat"));
        // The same word beats a closer spelling: `a_b_c` is `abc` (two
        // edits) before it is `a_b_x` (one).
        assert_eq!(best("a_b_c", ["a_b_x", "abc"]), Some("abc"));
        // No bound: a far candidate is still the best of one.
        assert_eq!(best("planet", ["glands"]), Some("glands"));
        // The value itself is not skipped: the caller's check chose it.
        assert_eq!(best("red", ["red"]), Some("red"));
        assert_eq!(best("red", []), None);
        // The order of the candidates does not matter.
        assert_eq!(
            best("tabel", ["label", "table"]),
            best("tabel", ["table", "label"])
        );
    }

    #[test]
    fn prepared_candidates_give_indices() {
        let candidates = Candidates::new(["clear", "amber", "clear", "red"]);
        assert_eq!(candidates.closest("ambr"), Some(1));
        assert_eq!(candidates.closest("CLEAR"), Some(0));
        assert_eq!(candidates.closest("rde"), Some(3));
        assert_eq!(candidates.closest("violet"), None);
        assert_eq!(Candidates::default().closest("red"), None);
    }

    #[test]
    fn counts_characters_not_bytes() {
        assert_eq!(closest("Zürch", ["Zürich", "Zug"]), Some("Zürich"));
        // Five characters (one edit) in ten bytes (three): the candidate,
        // two edits away, is out of reach.
        assert_eq!("äöüßé".len(), 10);
        assert_eq!(closest("äöüßé", ["xöüßéy"]), None);
        assert_eq!(closest("äöüßé", ["xöüßé"]), Some("xöüßé"));
        // The same through the prepared candidates vocabularies suggest from.
        assert_eq!(Candidates::new(["xöüßéy"]).closest("äöüßé"), None);
        assert_eq!(Candidates::new(["xöüßé"]).closest("äöüßé"), Some(0));
        assert_eq!(fold("Straße-Nord"), "straßenord");
    }
}
