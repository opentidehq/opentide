//! What differs between two runs of the same command for reasons that are not
//! the implementation's: the workspace each ran in, and the wall time. The
//! normaliser rewrites both runs the same way before they are compared, in
//! place and without re-serialising anything, so the byte comparison still
//! sees the layout each implementation printed.
//!
//! `cargo xtask golden` (UC-0.5) normalises its recordings the same way;
//! the two are to share one implementation (`crates/opentide-compare/AGENTS.md`).

use crate::{FileState, Run, replace};

/// The JSON key whose integer value is wall time.
pub const DURATION_KEY: &[u8] = b"\"duration_ms\"";

/// Rewrites runs: literal replacements (an absolute path to `<WS>`), then
/// the value of every `"duration_ms"` key to `0`.
#[derive(Debug, Clone, Default)]
pub struct Normaliser {
    replacements: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Normaliser {
    /// A normaliser that only zeroes `duration_ms`.
    pub fn new() -> Normaliser {
        Normaliser::default()
    }

    /// Also replaces every occurrence of `from` with `to`. Longer texts are
    /// replaced first, so a path is replaced before its parent folder.
    pub fn replace(mut self, from: impl Into<Vec<u8>>, to: impl Into<Vec<u8>>) -> Normaliser {
        let from = from.into();
        if !from.is_empty() {
            self.replacements.push((from, to.into()));
            self.replacements
                .sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
        }
        self
    }

    /// `bytes`, normalised.
    pub fn bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        for (from, to) in &self.replacements {
            out = replace(&out, from, to);
        }
        zero_durations(&out)
    }

    /// Normalises `run`'s streams and the contents of the files it wrote.
    pub fn run(&self, run: &mut Run) {
        run.stdout = self.bytes(&run.stdout);
        run.stderr = self.bytes(&run.stderr);
        for state in run.files.values_mut() {
            if let FileState::Written { bytes, .. } = state {
                *bytes = self.bytes(bytes);
            }
        }
    }
}

/// `bytes` with the digits after each `"duration_ms":` (spaces allowed
/// around the colon) replaced by `0`.
fn zero_durations(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at..].starts_with(DURATION_KEY) {
            let mut end = at + DURATION_KEY.len();
            while end < bytes.len() && matches!(bytes[end], b' ' | b'\t' | b'\n' | b'\r') {
                end += 1;
            }
            if bytes.get(end) == Some(&b':') {
                end += 1;
                while end < bytes.len() && matches!(bytes[end], b' ' | b'\t' | b'\n' | b'\r') {
                    end += 1;
                }
                let digits = bytes[end..]
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .count();
                if digits > 0 {
                    out.extend_from_slice(&bytes[at..end]);
                    out.push(b'0');
                    at = end + digits;
                    continue;
                }
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_zeroed_in_both_layouts() {
        let normaliser = Normaliser::new();
        assert_eq!(
            normaliser.bytes(br#"{"duration_ms":1234,"x":"duration_ms"}"#),
            br#"{"duration_ms":0,"x":"duration_ms"}"#
        );
        assert_eq!(
            normaliser.bytes(b"{\n  \"duration_ms\": 87\n}\n"),
            b"{\n  \"duration_ms\": 0\n}\n"
        );
        assert_eq!(
            normaliser.bytes(br#"{"duration_ms":"x"}"#),
            br#"{"duration_ms":"x"}"#
        );
    }

    #[test]
    fn longer_paths_are_replaced_first() {
        let normaliser = Normaliser::new()
            .replace("/tmp/a", "<TMP>")
            .replace("/tmp/a/ws", "<WS>");
        assert_eq!(
            normaliser.bytes(b"/tmp/a/ws/x and /tmp/a/y"),
            b"<WS>/x and <TMP>/y"
        );
    }

    #[test]
    fn files_are_normalised_too() {
        let mut run = Run::default();
        run.files.insert(
            "out.json".into(),
            FileState::Written {
                mode: 0o644,
                bytes: b"/w/x".to_vec(),
            },
        );
        Normaliser::new().replace("/w", "<WS>").run(&mut run);
        assert_eq!(
            run.files["out.json"],
            FileState::Written {
                mode: 0o644,
                bytes: b"<WS>/x".to_vec()
            }
        );
    }
}
