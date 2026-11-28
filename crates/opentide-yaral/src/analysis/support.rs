//! The yara-l-1.0 facts the checks share: section order and profiles,
//! Google's limits, durations, near-miss suggestions and RE2 patterns. None of
//! it reads a tree.

use crate::Profile;

/// Section order of yara-l-1.0 "Sections"; `select` and `unselect` share 12.
pub(crate) fn section_rank(name: &str) -> u8 {
    match name {
        "meta" => 1,
        "setup" => 2,
        "events" => 3,
        "match" => 4,
        "outcome" => 5,
        "condition" => 6,
        "options" => 7,
        "export" => 8,
        "dedup" => 9,
        "order" => 10,
        "limit" => 11,
        _ => 12,
    }
}

pub(crate) fn in_profile(name: &str, profile: Profile) -> bool {
    match profile {
        Profile::Rule => matches!(
            name,
            "meta" | "setup" | "events" | "match" | "outcome" | "condition" | "options" | "export"
        ),
        // `meta` is optional in a search and ignored (getting-started).
        Profile::Search => !matches!(name, "setup" | "options"),
    }
}

/// The most `in` statements of each kind (total, regex, cidr).
pub(crate) fn reference_limits(profile: Profile) -> (usize, usize, usize) {
    match profile {
        Profile::Rule => (10, 5, 5),
        Profile::Search => (7, 4, 2),
    }
}

pub(crate) const MAX_OUTCOMES: usize = 20;

/// A search's grouped fields: aliases for groups of UDM fields
/// (search-syntax-reference, "Search grouped fields").
pub(crate) const GROUPED_FIELDS: &[&str] = &[
    "domain",
    "email",
    "file_path",
    "hash",
    "hostname",
    "ip",
    "namespace",
    "process_id",
    "user",
];
pub(crate) const DAY: u64 = 24 * 60;

/// A duration's minutes, and its unit.
pub(crate) fn duration(text: &str) -> Option<(u64, &str)> {
    // ASCII digits: as many bytes as characters.
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (amount, unit) = text.split_at_checked(digits)?;
    let amount: u64 = amount.parse().ok()?;
    let per = match unit {
        "s" => return Some((amount / 60, unit)),
        "m" => 1,
        "h" => 60,
        "d" => DAY,
        "w" => 7 * DAY,
        "mo" => 30 * DAY,
        _ => return Some((0, unit)),
    };
    Some((amount.saturating_mul(per), unit))
}

pub(crate) fn format_minutes(minutes: u64) -> String {
    if minutes.is_multiple_of(DAY) && minutes >= 7 * DAY {
        format!("{}d", minutes / DAY)
    } else if minutes.is_multiple_of(60) {
        format!("{}h", minutes / 60)
    } else {
        format!("{minutes}m")
    }
}

/// The closest of `candidates` to `name`, within two edits, by the shared
/// rule ([`opentide_core::suggest`]).
pub(crate) fn closest<'a>(
    name: &str,
    candidates: impl Iterator<Item = &'a str>,
) -> Option<&'a str> {
    opentide_core::suggest::closest_within(name, candidates, 2)
}

/// An RE2 pattern as Rust's `regex-syntax` reads it: a `{` that does not
/// start a repetition is a literal in RE2 and must be escaped here. `i` steps
/// a whole character, or ASCII bytes, at a time: it stays on a char boundary.
fn as_rust_pattern(pattern: &str) -> String {
    use crate::cut;
    let bytes = pattern.as_bytes();
    let mut out = String::with_capacity(pattern.len() + 4);
    let mut i = 0;
    let mut class = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            // RE2 octal escapes: `\0`, or two or three octal digits (`\12`).
            // A single non-zero digit is a backreference, which RE2 refuses.
            let octal = bytes[i + 1..]
                .iter()
                .take(3)
                .take_while(|b| (b'0'..=b'7').contains(b))
                .count();
            if octal > 0 && (next == b'0' || octal > 1) {
                let digits = cut(pattern, i + 1, i + 1 + octal);
                let value = u32::from_str_radix(digits, 8).unwrap_or(0);
                out.push_str(&format!("\\x{{{value:x}}}"));
                i += 1 + octal;
                continue;
            }
            // RE2 `\Q…\E` quotes a literal run (to `\E` or the end).
            if next == b'Q' {
                let rest = cut(pattern, i + 2, pattern.len());
                let (quoted, consumed) = match rest.split_once("\\E") {
                    Some((quoted, _)) => (quoted, quoted.len() + 2),
                    None => (rest, rest.len()),
                };
                out.push_str(&regex_syntax::escape(quoted));
                i += 2 + consumed;
                continue;
            }
            // RE2 `\C` is any byte; only the pattern's validity is checked here.
            if next == b'C' {
                out.push('.');
                i += 2;
                continue;
            }
            // `\/` is a literal slash in a YARA-L regex literal.
            if next == b'/' {
                out.push('/');
            } else {
                out.push_str(cut(pattern, i, i + 2 + utf8_extra(bytes[i + 1])));
                i += utf8_extra(bytes[i + 1]);
            }
            i += 2;
            continue;
        }
        if c == b'[' {
            class = true;
        } else if c == b']' {
            class = false;
        } else if c == b'{' && !class {
            let rest = cut(pattern, i + 1, pattern.len());
            let repetition = rest.split_once('}').is_some_and(|(inside, _)| {
                let (lo, hi) = inside.split_once(',').unwrap_or((inside, "0"));
                !lo.is_empty()
                    && lo.bytes().all(|b| b.is_ascii_digit())
                    && hi.bytes().all(|b| b.is_ascii_digit())
            });
            if !repetition {
                out.push_str("\\{");
                i += 1;
                continue;
            }
        }
        let len = 1 + utf8_extra(c);
        out.push_str(cut(pattern, i, i + len));
        i += len;
    }
    out
}

fn utf8_extra(first: u8) -> usize {
    match first {
        0xF0..=0xFF => 3,
        0xE0..=0xEF => 2,
        0xC0..=0xDF => 1,
        _ => 0,
    }
}

/// Why RE2 refuses `pattern`, if it does.
pub(crate) fn regex_problem(pattern: &str) -> Option<String> {
    let rust = as_rust_pattern(pattern);
    regex_syntax::ParserBuilder::new()
        .build()
        .parse(&rust)
        .err()
        .map(|e| {
            let text = e.to_string();
            text.lines()
                .rev()
                .find(|l| l.starts_with("error:"))
                .map_or(text.clone(), |l| {
                    l.trim_start_matches("error:").trim().to_string()
                })
        })
}

/// A pattern that starts with `.*` and has no anchor.
pub(crate) fn leading_wildcard(pattern: &str) -> bool {
    let mut p = pattern;
    // Inline flags first: `(?i).*x`.
    while let Some(rest) = p.strip_prefix("(?") {
        match rest.split_once(')') {
            Some((flags, after)) if flags.chars().all(|c| c.is_ascii_alphabetic() || c == '-') => {
                p = after;
            }
            _ => break,
        }
    }
    p.starts_with(".*")
}

impl Profile {
    pub(crate) fn noun(self) -> &'static str {
        match self {
            Profile::Rule => "rule",
            Profile::Search => "search",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_misses_within_two_edits_are_suggested() {
        let names = ["principal", "target", "src", "network"];
        // One and two edits, a swapped pair one edit.
        assert_eq!(closest("princpal", names.into_iter()), Some("principal"));
        assert_eq!(closest("targte", names.into_iter()), Some("target"));
        assert_eq!(closest("netwrk", names.into_iter()), Some("network"));
        // Ties go to the best-matching start, then the first in order.
        assert_eq!(closest("ab", ["ac", "ad"].into_iter()), Some("ac"));
        assert_eq!(closest("ab", ["ad", "ac"].into_iter()), Some("ac"));
        // Too far: nothing.
        assert_eq!(closest("hostname", names.into_iter()), None);
    }

    #[test]
    fn helpers_read_multi_byte_text() {
        assert_eq!(duration("5é😀"), Some((0, "é😀")));
        assert_eq!(duration("é"), None);
        assert_eq!(duration("2h"), Some((120, "h")));
        assert_eq!(as_rust_pattern("é{😀}"), r"é\{😀}");
        assert_eq!(as_rust_pattern("é{2,3}😀"), "é{2,3}😀");
        assert_eq!(as_rust_pattern(r"\é\😀\/"), r"\é\😀/");
        assert_eq!(as_rust_pattern(r"\Qé😀\Eé"), "é😀é");
        assert_eq!(as_rust_pattern(r"\Qé😀"), "é😀");
        assert_eq!(as_rust_pattern(r"\012é"), r"\x{a}é");
        for pattern in ["é😀", r"(?é).*", r"\é\", r"\Q😀\", "{é", "é{😀,é}"] {
            for (i, _) in pattern.char_indices() {
                let _ = regex_problem(pattern.get(i..).unwrap());
                let _ = leading_wildcard(pattern.get(i..).unwrap());
            }
        }
        assert!(leading_wildcard("(?i).*é"));
        assert!(!leading_wildcard("(?é).*"));
    }

    #[test]
    fn re2_patterns() {
        assert!(regex_problem(r"\\(winword|excel)\.exe$").is_none());
        assert!(regex_problem(r"a{").is_none());
        assert!(regex_problem(r"\{[0-9]+}").is_none());
        assert!(regex_problem(r"a/b\/c").is_none());
        assert!(regex_problem(r"(a").is_some());
        assert!(regex_problem(r"(?=a)").is_some());
        assert!(regex_problem(r"\1").is_some());
        assert!(regex_problem(r"\0").is_none());
        assert!(regex_problem(r"\012x").is_none());
        // RE2 quoting and the any-byte escape (regex-syntax has neither).
        assert!(regex_problem(r"\Q.exe\E$").is_none());
        assert!(regex_problem(r"\Qa(b").is_none());
        assert!(regex_problem(r"a\Cb").is_none());
    }

    #[test]
    fn leading_wildcards() {
        assert!(leading_wildcard(".*evil"));
        assert!(leading_wildcard("(?i).*evil"));
        assert!(!leading_wildcard("^.*evil"));
        assert!(!leading_wildcard("evil.*"));
    }

    #[test]
    fn durations() {
        assert_eq!(duration("30m"), Some((30, "m")));
        assert_eq!(duration("2d"), Some((2 * DAY, "d")));
        assert_eq!(duration("10x"), Some((0, "x")));
        assert_eq!(format_minutes(14 * DAY), "14d");
        assert_eq!(format_minutes(72 * 60), "72h");
    }
}
