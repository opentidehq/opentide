//! libyara's atom quality (`libyara/atoms.c`, `yr_atoms_heuristic_quality`),
//! behind its warning "string may slow down scanning" (`yara_slow_pattern`).
//!
//! libyara scans for short atoms (at most 4 bytes) taken from each string and
//! warns when the best atom it can extract scores below the threshold
//! (`YR_ATOM_QUALITY_WARNING_THRESHOLD`: 38 points above the floor). This
//! module scores every window of up to 4 bytes of the runs a string is sure
//! to contain and keeps the best. libyara's atom extraction from regexps and
//! hex alternatives is richer; here an alternative or a jump ends a run, so
//! the score never overestimates a string libyara would warn about less.

/// A byte and its mask: 0xFF fixed, 0x0F or 0xF0 a nibble, 0x00 `??`.
pub type MaskedByte = (u8, u8);

pub const YR_MAX_ATOM_LENGTH: usize = 4;

/// The warning threshold, on the zero-based scale of [`quality`].
pub const WARNING_THRESHOLD: i32 = 38;

/// `yr_atoms_heuristic_quality` without its constant offset.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "an atom is at most a few bytes long"
)]
pub fn quality(atom: &[MaskedByte]) -> i32 {
    let mut q = 0;
    let mut seen = [false; 256];
    let mut unique = 0;
    for &(byte, mask) in atom {
        match mask {
            0x00 => q -= 10,
            0x0F | 0xF0 => q += 4,
            _ => {
                q += match byte {
                    0x00 | 0x20 | 0xCC | 0xFF => 12,
                    b if b.is_ascii_alphabetic() => 18,
                    _ => 20,
                };
                if !seen[byte as usize] {
                    seen[byte as usize] = true;
                    unique += 1;
                }
            }
        }
    }
    let common = [0x00u8, 0x20, 0x90, 0xCC, 0xFF];
    if unique == 1 && common.iter().any(|&b| seen[b as usize]) {
        q -= 10 * atom.len() as i32;
    } else {
        q += 2 * unique;
    }
    q
}

/// The best atom quality in any run; `None` when there is no byte at all.
pub fn best_quality(runs: &[Vec<MaskedByte>]) -> Option<i32> {
    runs.iter()
        .filter(|r| !r.is_empty())
        .flat_map(|run| {
            // libyara trims an atom's masked ends, so shorter atoms count too.
            (1..=run.len().min(YR_MAX_ATOM_LENGTH))
                .flat_map(|len| run.windows(len).map(quality).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .max()
}

/// Whether libyara would warn that the string may slow down scanning.
pub fn is_slow(runs: &[Vec<MaskedByte>]) -> bool {
    best_quality(runs).is_none_or(|q| q < WARNING_THRESHOLD)
}

/// A text string's bytes as one run, interleaved with zeros for `wide`.
/// libyara scores atoms before widening them, so the checks pass `false`.
pub fn text_run(bytes: &[u8], wide: bool) -> Vec<MaskedByte> {
    let mut run = Vec::with_capacity(bytes.len() * if wide { 2 } else { 1 });
    for &b in bytes {
        run.push((b, 0xFF));
        if wide {
            run.push((0, 0xFF));
        }
    }
    run
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(bytes: &[u8]) -> Vec<MaskedByte> {
        bytes.iter().map(|&b| (b, 0xFF)).collect()
    }

    /// The examples in libyara's own comment.
    #[test]
    fn libyara_examples() {
        assert_eq!(quality(&fixed(&[1, 2, 3, 4])), 88);
        assert_eq!(quality(&[(1, 0xFF), (0, 0x00), (3, 0xFF), (4, 0xFF)]), 56);
        assert_eq!(quality(&fixed(&[1, 2])), 44);
        assert_eq!(quality(&fixed(b"ab")), 40);
        assert_eq!(quality(&fixed(b"aa")), 38);
        assert_eq!(quality(&fixed(&[0, 1])), 36);
        assert_eq!(quality(&fixed(&[1])), 22);
    }

    #[test]
    fn slow_strings() {
        assert!(is_slow(&[fixed(b"a")]));
        assert!(is_slow(&[fixed(&[0, 0, 0, 0])]));
        assert!(is_slow(&[]));
        assert!(!is_slow(&[fixed(b"aa")]));
        assert!(!is_slow(&[fixed(b"MZ")]));
    }
}
