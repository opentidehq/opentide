//! CommonMark-ish highlighting for Tide YAML text fields.
//!
//! Used inside block scalars such as `description`, `procedure.analysis`,
//! `recommendation`. Captures must be a subset of HighlightSpec.

use opentide_core::ByteSpan;

/// Highlight one YAML line (no trailing newline) as markdown.
/// `line_start` is the byte offset of `line` in the host document.
pub fn highlight_markdown_line(line_start: usize, line: &str) -> Vec<(ByteSpan, &'static str)> {
    let mut spans = Vec::new();
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return spans;
    }
    let mut i = 0usize;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    if i >= bytes.len() {
        return spans;
    }

    let mut prose_capture = "string";
    let rest = &line[i..];
    if let Some(end) = match_heading_marker(line, i) {
        push(&mut spans, line_start, i, end, "markdown.heading");
        i = end;
        prose_capture = "markdown.heading";
    } else if let Some(end) = match_list_marker(line, i) {
        push(&mut spans, line_start, i, end, "markdown.list");
        i = end;
    } else if rest == ">" || rest.starts_with("> ") {
        let end = if rest.starts_with("> ") { i + 2 } else { i + 1 };
        push(&mut spans, line_start, i, end, "markdown.quote");
        i = end;
        prose_capture = "markdown.quote";
    }

    highlight_inline(&mut spans, line_start, line, i, prose_capture);
    spans
}

fn push(
    spans: &mut Vec<(ByteSpan, &'static str)>,
    base: usize,
    start: usize,
    end: usize,
    cap: &'static str,
) {
    if start < end {
        spans.push((ByteSpan::new(base + start, base + end), cap));
    }
}

fn match_heading_marker(line: &str, i: usize) -> Option<usize> {
    let rest = &line[i..];
    let hashes = rest.chars().take_while(|c| *c == '#').count();
    if !(1..=6).contains(&hashes) {
        return None;
    }
    let after = i + hashes;
    if after == line.len() {
        return Some(after);
    }
    if line.as_bytes().get(after) == Some(&b' ') {
        return Some(after + 1);
    }
    None
}

fn match_list_marker(line: &str, i: usize) -> Option<usize> {
    let rest = &line[i..];
    let b = rest.as_bytes();
    if matches!(b.first(), Some(b'-' | b'*' | b'+')) && b.get(1) == Some(&b' ') {
        return Some(i + 2);
    }
    let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits > 0 {
        let n = i + digits;
        if line.get(n..n + 2) == Some(". ") {
            return Some(n + 2);
        }
    }
    None
}

fn highlight_inline(
    spans: &mut Vec<(ByteSpan, &'static str)>,
    base: usize,
    line: &str,
    mut i: usize,
    prose: &'static str,
) {
    let bytes = line.as_bytes();
    let mut prose_from = i;
    while i < bytes.len() {
        if let Some((end, cap)) = match_inline(line, i) {
            if prose_from < i {
                push(spans, base, prose_from, i, prose);
            }
            push(spans, base, i, end, cap);
            i = end;
            prose_from = i;
            continue;
        }
        i += line[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
    }
    if prose_from < bytes.len() {
        push(spans, base, prose_from, bytes.len(), prose);
    }
}

fn match_inline(line: &str, i: usize) -> Option<(usize, &'static str)> {
    let rest = &line[i..];
    let bytes = rest.as_bytes();
    if let Some(inner) = rest.strip_prefix('`') {
        if let Some(rel) = inner.find('`') {
            return Some((i + 1 + rel + 1, "markdown.code"));
        }
    }
    if let Some(inner) = rest.strip_prefix("**") {
        if let Some(rel) = inner.find("**") {
            return Some((i + 2 + rel + 2, "markdown.strong"));
        }
    }
    if let Some(inner) = rest.strip_prefix("__") {
        if let Some(rel) = inner.find("__") {
            return Some((i + 2 + rel + 2, "markdown.strong"));
        }
    }
    if bytes.first() == Some(&b'*') && bytes.get(1) != Some(&b'*') {
        if let Some(inner) = rest.strip_prefix('*') {
            if let Some(rel) = inner.find('*') {
                return Some((i + 1 + rel + 1, "markdown.emphasis"));
            }
        }
    }
    if rest.starts_with("[") {
        if let Some(close) = rest.find(']') {
            let after = &rest[close + 1..];
            if after.starts_with('(') {
                if let Some(end_paren) = after.find(')') {
                    return Some((i + close + 1 + end_paren + 1, "markdown.link"));
                }
            }
        }
    }
    if rest.starts_with("http://") || rest.starts_with("https://") {
        let end_rel = rest
            .find(|c: char| c.is_ascii_whitespace() || matches!(c, ')' | ']' | '>' | '"' | '\''))
            .unwrap_or(rest.len());
        let mut end_rel = end_rel;
        while end_rel > 0 && matches!(rest.as_bytes()[end_rel - 1], b'.' | b',' | b';' | b':') {
            end_rel -= 1;
        }
        if end_rel > 7 {
            return Some((i + end_rel, "markdown.link"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(line: &str) -> Vec<(&'static str, String)> {
        highlight_markdown_line(0, line)
            .into_iter()
            .map(|(sp, c)| (c, line[sp.start..sp.end].to_string()))
            .collect()
    }

    #[test]
    fn heading_and_inline_code() {
        let got = caps("  #### MDR Technical Details");
        assert!(
            got.iter()
                .any(|(c, t)| *c == "markdown.heading" && t.contains("####")),
            "{got:?}"
        );
        let got = caps("  Aggregates `DeviceFileEvents` to flag");
        assert!(
            got.iter()
                .any(|(c, t)| *c == "markdown.code" && t == "`DeviceFileEvents`"),
            "{got:?}"
        );
    }

    #[test]
    fn list_and_numbered() {
        let got = caps("  - Threshold: `PathThreshold = 15` distinct");
        assert!(got.iter().any(|(c, _)| *c == "markdown.list"), "{got:?}");
        assert!(
            got.iter()
                .any(|(c, t)| *c == "markdown.code" && t.contains("PathThreshold")),
            "{got:?}"
        );
        let got = caps("      1. Review the sample paths");
        assert!(
            got.iter()
                .any(|(c, t)| *c == "markdown.list" && t.contains("1.")),
            "{got:?}"
        );
    }

    #[test]
    fn links_and_emphasis() {
        let got = caps("See [docs](https://example.com) and **bold** and *em*");
        assert!(got.iter().any(|(c, _)| *c == "markdown.link"), "{got:?}");
        assert!(got.iter().any(|(c, _)| *c == "markdown.strong"), "{got:?}");
        assert!(
            got.iter().any(|(c, _)| *c == "markdown.emphasis"),
            "{got:?}"
        );
    }
}
