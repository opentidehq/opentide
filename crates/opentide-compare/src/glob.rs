//! The case globs of the ledger: `*` matches any run of characters, `/`
//! included, and `?` exactly one; everything else matches itself.

/// Whether `text` matches `pattern`.
pub fn matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    // The last `*` seen, and the text position it was tried at.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == '?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn stars_and_question_marks() {
        assert!(matches("*", ""));
        assert!(matches("*", "json/tide_corpus/validate"));
        assert!(matches("json/*", "json/tide_corpus/validate"));
        assert!(matches("*/validate", "json/tide_corpus/validate"));
        assert!(matches("json/?ide*", "json/tide_corpus"));
        assert!(matches("a*b*c", "aXbYbZc"));
        assert!(!matches("json/*", "plain/tide_corpus"));
        assert!(!matches("validate", "validate-1"));
        assert!(!matches("a?", "a"));
        assert!(matches("exact", "exact"));
    }
}
