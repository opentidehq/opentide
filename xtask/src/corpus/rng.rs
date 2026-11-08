//! The generator's random numbers: SplitMix64, written out here so that a
//! seed gives the same workspace on every platform, toolchain and dependency
//! update (no crate's algorithm can change under the recorded hash).

use std::fmt::Write as _;

/// A SplitMix64 generator (Steele, Lea and Flood, 2014).
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// A generator for `seed`.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// An independent generator for one stream of the workspace (threats,
    /// rules, ...), so that adding a field to one family leaves the others'
    /// draws unchanged.
    pub fn fork(&self, stream: &str) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in stream.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        let mut forked = Self::new(self.state ^ hash);
        forked.next_u64();
        forked
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in `0..n`; 0 when `n` is 0.
    pub fn below(&mut self, n: usize) -> usize {
        let Ok(bound) = u64::try_from(n) else {
            return 0;
        };
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % bound).unwrap_or(0)
    }

    /// A number in `low..=high`.
    pub fn range(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high.saturating_sub(low) + 1)
    }

    /// True with probability `percent` / 100.
    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    /// One element of `items`.
    pub fn pick<'a, T: ?Sized>(&mut self, items: &[&'a T]) -> &'a T {
        items[self.below(items.len())]
    }

    /// `count` distinct elements of `items`, in the order of `items`.
    pub fn sample<'a, T: ?Sized>(&mut self, items: &[&'a T], count: usize) -> Vec<&'a T> {
        let count = count.min(items.len());
        let mut chosen = vec![false; items.len()];
        let mut left = count;
        while left > 0 {
            let index = self.below(items.len());
            if !chosen[index] {
                chosen[index] = true;
                left -= 1;
            }
        }
        items
            .iter()
            .zip(chosen)
            .filter_map(|(item, keep)| keep.then_some(*item))
            .collect()
    }

    /// A random UUID version 4 in its canonical lowercase form.
    pub fn uuid(&mut self) -> String {
        let high = self.next_u64();
        let low = self.next_u64();
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&high.to_be_bytes());
        bytes[8..].copy_from_slice(&low.to_be_bytes());
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex = bytes
            .iter()
            .fold(String::with_capacity(32), |mut hex, byte| {
                let _ = write!(hex, "{byte:02x}");
                hex
            });
        format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Rng;

    #[test]
    fn splitmix64_reference_values() {
        // The first outputs of SplitMix64 for seed 1234567 (the reference
        // implementation's test vector).
        let mut rng = Rng::new(1_234_567);
        assert_eq!(rng.next_u64(), 6_457_827_717_110_365_317);
        assert_eq!(rng.next_u64(), 3_203_168_211_198_807_973);
        assert_eq!(rng.next_u64(), 9_817_491_932_198_370_423);
    }

    #[test]
    fn uuid_is_version_4() {
        let mut rng = Rng::new(7);
        for _ in 0..100 {
            let uuid = rng.uuid();
            assert_eq!(uuid.len(), 36);
            assert_eq!(&uuid[14..15], "4");
            assert!(matches!(&uuid[19..20], "8" | "9" | "a" | "b"), "{uuid}");
        }
    }

    #[test]
    fn sample_is_distinct_and_ordered() {
        let items = ["a", "b", "c", "d", "e"];
        let refs: Vec<&str> = items.to_vec();
        let mut rng = Rng::new(3);
        let picked = rng.sample(&refs, 3);
        assert_eq!(picked.len(), 3);
        let mut sorted = picked.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, picked);
    }
}
