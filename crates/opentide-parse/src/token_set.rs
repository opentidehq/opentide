//! [`TokenSet`]: a set of token kinds, as a fixed bitset.

use rowan::SyntaxKind;
use std::fmt;

/// 64-bit words in a [`TokenSet`].
const WORDS: usize = 8;

/// A set of token kinds: what the parser looked for at a failure, and the
/// recovery sets a grammar stops at. It holds kinds below
/// [`TokenSet::CAPACITY`]; a language numbers its token kinds first, so its
/// node kinds may go past it.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TokenSet([u64; WORDS]);

impl TokenSet {
    /// The number of kinds a set can hold: kinds `0..CAPACITY`.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "8 words of 64 bits is 512, which a u16 holds"
    )]
    pub const CAPACITY: u16 = (WORDS * 64) as u16;

    /// No kind.
    pub const EMPTY: Self = Self([0; WORDS]);

    /// The set of `kinds`.
    ///
    /// # Panics
    ///
    /// When a kind is [`TokenSet::CAPACITY`] or more: a set never drops a kind
    /// silently. In a `const` item that is a compile error; at run time it
    /// fails the first test that reaches the kind.
    pub const fn new(kinds: &[SyntaxKind]) -> Self {
        let mut set = Self::EMPTY;
        let mut i = 0;
        while i < kinds.len() {
            set = set.with(kinds[i]);
            i += 1;
        }
        set
    }

    /// This set and `kind`.
    ///
    /// # Panics
    ///
    /// As [`TokenSet::new`], when `kind` does not fit.
    #[must_use]
    pub const fn with(self, kind: SyntaxKind) -> Self {
        assert!(
            kind.0 < Self::CAPACITY,
            "a token kind does not fit a TokenSet: number token kinds below TokenSet::CAPACITY"
        );
        let mut words = self.0;
        words[(kind.0 / 64) as usize] |= 1 << (kind.0 % 64);
        Self(words)
    }

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        let mut words = self.0;
        let mut i = 0;
        while i < WORDS {
            words[i] |= other.0[i];
            i += 1;
        }
        Self(words)
    }

    /// Whether `kind` is in the set; never for a kind the set cannot hold.
    pub const fn contains(self, kind: SyntaxKind) -> bool {
        kind.0 < Self::CAPACITY && self.0[(kind.0 / 64) as usize] & (1 << (kind.0 % 64)) != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        let mut i = 0;
        while i < WORDS {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// The number of kinds in the set.
    pub fn len(self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// The kinds in the set, smallest first.
    pub fn iter(self) -> impl Iterator<Item = SyntaxKind> {
        self.0.into_iter().zip(0u16..).flat_map(|(word, n)| {
            let mut rest = word;
            std::iter::from_fn(move || {
                if rest == 0 {
                    return None;
                }
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "trailing_zeros of a non-zero u64 is below 64"
                )]
                let bit = rest.trailing_zeros() as u16;
                rest &= rest - 1;
                Some(SyntaxKind(n * 64 + bit))
            })
        })
    }
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter().map(|k| k.0)).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_word_boundary_is_held() {
        let edges = [0, 1, 63, 64, 65, 127, 128, 255, 256, 511].map(SyntaxKind);
        let set = TokenSet::new(&edges);
        assert_eq!(set.iter().collect::<Vec<_>>(), edges);
        assert_eq!(set.len(), edges.len());
        for kind in edges {
            assert!(set.contains(kind), "{kind:?}");
        }
        for kind in [2, 62, 66, 129, 254, 257, 510].map(SyntaxKind) {
            assert!(!set.contains(kind), "{kind:?}");
        }
    }

    #[test]
    fn a_kind_past_the_capacity_is_never_contained() {
        assert_eq!(TokenSet::CAPACITY, 512);
        let full = (0..TokenSet::CAPACITY).fold(TokenSet::EMPTY, |s, k| s.with(SyntaxKind(k)));
        assert_eq!(full.len(), 512);
        assert!(!full.contains(SyntaxKind(512)));
        assert!(!full.contains(SyntaxKind(u16::MAX)));
    }

    #[test]
    #[should_panic(expected = "does not fit a TokenSet")]
    fn a_kind_past_the_capacity_is_refused_not_dropped() {
        let _ = TokenSet::new(&[SyntaxKind(1), SyntaxKind(512)]);
    }

    #[test]
    fn union_and_emptiness() {
        let a = TokenSet::new(&[SyntaxKind(3), SyntaxKind(300)]);
        let b = TokenSet::new(&[SyntaxKind(3), SyntaxKind(70)]);
        assert_eq!(
            a.union(b).iter().collect::<Vec<_>>(),
            [3, 70, 300].map(SyntaxKind)
        );
        assert!(TokenSet::EMPTY.is_empty());
        assert!(!a.is_empty());
        assert_eq!(format!("{a:?}"), "{3, 300}");
    }
}
