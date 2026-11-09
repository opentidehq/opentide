//! A small YAML tree and its block-style emitter: the generator writes every
//! object through it, so the output is byte-for-byte determined by the tree.
//!
//! Scalars are plain when YAML 1.1 (PyYAML, the oracle's loader) reads them
//! back as the same string, double-quoted otherwise; [`Yaml::Raw`] writes a
//! scalar verbatim (integers, booleans, dates, or a deliberately bad value).

/// A YAML node.
#[derive(Debug, Clone, PartialEq)]
pub enum Yaml {
    /// A mapping, in insertion order.
    Map(Vec<(String, Yaml)>),
    /// A sequence.
    Seq(Vec<Yaml>),
    /// A string: plain when it reads back as itself, quoted otherwise;
    /// a literal block (`|`) when it spans lines.
    Str(String),
    /// A scalar written verbatim: `3`, `true`, `2026-01-01`.
    Raw(String),
}

impl Yaml {
    /// A string node.
    pub fn s(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    /// A verbatim scalar.
    pub fn raw(value: impl ToString) -> Self {
        Self::Raw(value.to_string())
    }

    /// A sequence of strings.
    pub fn strs<S: AsRef<str>>(values: &[S]) -> Self {
        Self::Seq(values.iter().map(|v| Self::s(v.as_ref())).collect())
    }

    /// A mapping from `(key, value)` pairs.
    pub fn map<K: Into<String>>(pairs: Vec<(K, Yaml)>) -> Self {
        Self::Map(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// The value under `key` of a mapping.
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Self::Map(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The node at a dotted path (`configurations.sentinel.query`,
    /// `objective.signals.0.uuid`).
    pub fn at(&self, path: &str) -> Option<&Yaml> {
        let mut node = self;
        for segment in path.split('.') {
            node = match node {
                Self::Map(pairs) => pairs.iter().find(|(k, _)| k == segment).map(|(_, v)| v)?,
                Self::Seq(items) => items.get(segment.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(node)
    }

    /// The node at a dotted path, mutably; with `create`, missing mapping
    /// keys are added as empty mappings on the way.
    pub fn at_mut(&mut self, path: &str, create: bool) -> Option<&mut Yaml> {
        let mut node = self;
        for segment in path.split('.') {
            node = match node {
                Self::Map(pairs) => {
                    let position = pairs.iter().position(|(k, _)| k == segment);
                    let index = match position {
                        Some(index) => index,
                        None if create => {
                            pairs.push((segment.to_string(), Self::Map(Vec::new())));
                            pairs.len() - 1
                        }
                        None => return None,
                    };
                    &mut pairs[index].1
                }
                Self::Seq(items) => items.get_mut(segment.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(node)
    }

    /// Sets the node at `path`, creating missing mapping keys; whether the
    /// path could be reached.
    pub fn set(&mut self, path: &str, value: Yaml) -> bool {
        match self.at_mut(path, true) {
            Some(node) => {
                *node = value;
                true
            }
            None => false,
        }
    }

    /// Removes the node at `path`; whether it existed.
    pub fn remove(&mut self, path: &str) -> bool {
        let (parent, last) = match path.rsplit_once('.') {
            Some((parent, last)) => match self.at_mut(parent, false) {
                Some(node) => (node, last),
                None => return false,
            },
            None => (self, path),
        };
        match parent {
            Self::Map(pairs) => {
                let before = pairs.len();
                pairs.retain(|(k, _)| k != last);
                pairs.len() != before
            }
            Self::Seq(items) => match last.parse::<usize>() {
                Ok(index) if index < items.len() => {
                    items.remove(index);
                    true
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// The string of a [`Yaml::Str`] or [`Yaml::Raw`] node.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) | Self::Raw(value) => Some(value),
            _ => None,
        }
    }

    /// The document as YAML text, ending in a newline.
    pub fn render(&self) -> String {
        let mut out = String::new();
        match self {
            Self::Map(pairs) => write_map(&mut out, pairs, 0, true),
            Self::Seq(items) => write_seq(&mut out, items, 0),
            scalar => {
                out.push_str(&scalar_inline(scalar, 0));
                out.push('\n');
            }
        }
        out
    }
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// Top-level keys whose block is preceded by a blank line, as the
/// templates lay objects out.
const SPACED_KEYS: &[&str] = &[
    "metadata",
    "description",
    "threat",
    "objective",
    "response",
    "configurations",
    "references",
];

fn write_map(out: &mut String, pairs: &[(String, Yaml)], level: usize, top: bool) {
    for (index, (key, value)) in pairs.iter().enumerate() {
        if top && index > 0 && SPACED_KEYS.contains(&key.as_str()) {
            out.push('\n');
        }
        indent(out, level);
        out.push_str(&key_text(key));
        out.push(':');
        write_value(out, value, level);
    }
}

fn write_seq(out: &mut String, items: &[Yaml], level: usize) {
    for item in items {
        indent(out, level);
        out.push('-');
        match item {
            Yaml::Map(pairs) if !pairs.is_empty() => {
                // The first key goes on the dash's line, the rest under it.
                out.push(' ');
                let (first_key, first_value) = &pairs[0];
                out.push_str(&key_text(first_key));
                out.push(':');
                write_value(out, first_value, level + 1);
                write_map(out, &pairs[1..], level + 1, false);
            }
            _ => write_value(out, item, level),
        }
    }
}

/// Writes what follows `key:` or `-`: a scalar on the same line, or a
/// nested block on the next lines.
fn write_value(out: &mut String, value: &Yaml, level: usize) {
    match value {
        Yaml::Map(pairs) if pairs.is_empty() => out.push_str(" {}\n"),
        Yaml::Seq(items) if items.is_empty() => out.push_str(" []\n"),
        Yaml::Map(pairs) => {
            out.push('\n');
            write_map(out, pairs, level + 1, false);
        }
        Yaml::Seq(items) => {
            out.push('\n');
            write_seq(out, items, level + 1);
        }
        Yaml::Str(text) if text.contains('\n') && block_safe(text) => {
            let body = text.strip_suffix('\n').unwrap_or(text);
            let chomp = if text.ends_with('\n') { "|" } else { "|-" };
            out.push(' ');
            out.push_str(chomp);
            out.push('\n');
            for line in body.split('\n') {
                if !line.is_empty() {
                    indent(out, level + 1);
                    out.push_str(line);
                }
                out.push('\n');
            }
        }
        scalar => {
            out.push(' ');
            out.push_str(&scalar_inline(scalar, level));
            out.push('\n');
        }
    }
}

fn scalar_inline(value: &Yaml, _level: usize) -> String {
    match value {
        Yaml::Raw(text) => text.clone(),
        Yaml::Str(text) => {
            if is_plain_safe(text) {
                text.clone()
            } else {
                quote(text)
            }
        }
        Yaml::Map(_) => "{}".to_string(),
        Yaml::Seq(_) => "[]".to_string(),
    }
}

/// A key is written plain when it reads back as itself, or when it is all
/// digits: an integer key on purpose (`references.public`, whose model
/// keys are integers).
fn key_text(key: &str) -> String {
    let digits = !key.is_empty() && key.chars().all(|c| c.is_ascii_digit());
    if digits || is_plain_safe(key) {
        key.to_string()
    } else {
        quote(key)
    }
}

/// Double-quoted, with the escapes YAML defines.
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            // Controls, YAML's other line breaks (NEL, LS, PS), the BOM and
            // the non-characters PyYAML's reader refuses.
            c if c.is_control()
                || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{feff}')
                || (u32::from(c) & 0xfffe) == 0xfffe
                || ('\u{fdd0}'..='\u{fdef}').contains(&c) =>
            {
                let code = u32::from(c);
                if code > 0xffff {
                    out.push_str(&format!("\\U{code:08x}"));
                } else {
                    out.push_str(&format!("\\u{code:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Whether `text` written plain reads back, under YAML 1.1, as the same
/// string. Conservative: a `false` only costs quotes.
pub fn is_plain_safe(text: &str) -> bool {
    let Some(first) = text.chars().next() else {
        return false;
    };
    if text.trim() != text
        || text.contains('\n')
        || text
            .chars()
            .any(|c| c.is_control() || c as u32 >= 0x80 && !c.is_alphanumeric())
    {
        return false;
    }
    if "-?:,[]{}#&*!|><'\"%@`~".contains(first) {
        return false;
    }
    if text.contains(": ") || text.contains(" #") || text.ends_with(':') {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "y" | "n" | "yes" | "no" | "on" | "off" | "true" | "false" | "null" | "~" | "="
    ) {
        return false;
    }
    // Anything that starts like a number, date or sexagesimal is quoted,
    // except a canonical UUID, which no YAML 1.1 scalar type matches.
    if (first.is_ascii_digit() || first == '+' || first == '.') && !is_uuid(text) {
        return false;
    }
    true
}

/// Whether a multi-line string can be a literal block (`|` or `|-`) that
/// reads back as itself: no leading space on the first line (it would need
/// an indentation indicator), no carriage return or other line break, at
/// most one final newline (`|` clips the rest), and only characters a
/// plain line can hold.
fn block_safe(text: &str) -> bool {
    let first = text.split('\n').next().unwrap_or("");
    !first.is_empty()
        && !first.starts_with(' ')
        && !text.ends_with("\n\n")
        && !text.chars().any(|c| {
            (c.is_control() && c != '\n')
                || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{feff}')
                || (u32::from(c) & 0xfffe) == 0xfffe
        })
}

/// Whether `text` is a UUID in its canonical 8-4-4-4-12 hexadecimal form.
pub fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::Yaml;

    #[test]
    fn renders_a_document() {
        let doc = Yaml::map(vec![
            ("name", Yaml::s("Rule one")),
            (
                "metadata",
                Yaml::map(vec![
                    ("uuid", Yaml::s("0bd2e4f2-5d3a-4a52-9c39-0f3f3c4f7d10")),
                    ("version", Yaml::raw(1)),
                    ("created", Yaml::raw("2026-01-01")),
                ]),
            ),
            ("description", Yaml::s("Line one.\nLine two.\n")),
            ("techniques", Yaml::strs(&["T1059", "T1003"])),
            (
                "items",
                Yaml::Seq(vec![Yaml::map(vec![
                    ("name", Yaml::s("a: b")),
                    ("count", Yaml::raw(2)),
                ])]),
            ),
            ("empty", Yaml::Seq(vec![])),
            ("flag", Yaml::s("true")),
        ]);
        let expected = "\
name: Rule one

metadata:
  uuid: 0bd2e4f2-5d3a-4a52-9c39-0f3f3c4f7d10
  version: 1
  created: 2026-01-01

description: |
  Line one.
  Line two.
techniques:
  - T1059
  - T1003
items:
  - name: \"a: b\"
    count: 2
empty: []
flag: \"true\"
";
        assert_eq!(doc.render(), expected);
    }

    #[test]
    fn paths_set_and_remove() {
        let mut doc = Yaml::map(vec![(
            "a",
            Yaml::map(vec![("list", Yaml::strs(&["x", "y"]))]),
        )]);
        assert_eq!(doc.at("a.list.1"), Some(&Yaml::s("y")));
        assert!(doc.set("a.b.c", Yaml::raw(3)));
        assert_eq!(doc.at("a.b.c"), Some(&Yaml::raw(3)));
        assert!(doc.remove("a.list.0"));
        assert_eq!(doc.at("a.list.0"), Some(&Yaml::s("y")));
        assert!(doc.remove("a.b"));
        assert!(!doc.remove("a.b"));
        assert!(!doc.set("a.list.5", Yaml::raw(1)));
    }

    #[test]
    fn awkward_strings_are_quoted() {
        let render = |s: &str| Yaml::map(vec![("k", Yaml::s(s))]).render();
        assert_eq!(render("  indented\nnext"), "k: \"  indented\\nnext\"\n");
        assert_eq!(render("ends\n\n"), "k: \"ends\\n\\n\"\n");
        assert_eq!(render("\n"), "k: \"\\n\"\n");
        assert_eq!(render("a\r\nb"), "k: \"a\\u000d\\nb\"\n");
        assert_eq!(render("a\u{2028}b"), "k: \"a\\u2028b\"\n");
        assert_eq!(render("\u{fffe}"), "k: \"\\ufffe\"\n");
        assert_eq!(render("<<"), "k: \"<<\"\n");
        assert_eq!(render("one\ntwo\n"), "k: |\n  one\n  two\n");
        let keys = Yaml::map(vec![
            ("1", Yaml::raw(1)),
            ("true", Yaml::raw(2)),
            ("a b", Yaml::raw(3)),
        ]);
        assert_eq!(keys.render(), "1: 1\n\"true\": 2\na b: 3\n");
    }

    #[test]
    fn quoting_rules() {
        for safe in ["Rule", "att&ck::G0006", "OS::Windows::Desktop", "a-b c"] {
            assert!(super::is_plain_safe(safe), "{safe}");
        }
        for unsafe_ in [
            "",
            "yes",
            "No",
            "1h",
            "2026-01-01",
            "- x",
            "a: b",
            "x #y",
            "*x",
            " x",
        ] {
            assert!(!super::is_plain_safe(unsafe_), "{unsafe_}");
        }
    }
}
