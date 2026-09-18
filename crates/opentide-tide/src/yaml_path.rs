//! Indent-based YAML cursor path for Tide objects (no serde at the caret).

use opentide_core::ByteSpan;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlCursor {
    /// Mapping path from the document root to the current key (inclusive when
    /// the caret is on a key or its value).
    pub path: Vec<String>,
    /// Immediate parent mapping key; empty string means document root.
    pub parent: String,
    pub current_key: Option<String>,
    pub on_key: bool,
    pub value: Option<String>,
    pub siblings: Vec<String>,
    pub in_list: bool,
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '&' | '-')
}

fn line_indent(line: &str) -> usize {
    line.bytes().take_while(|b| *b == b' ').count()
}

fn strip_comment(body: &str) -> &str {
    if let Some(idx) = body.find('#') {
        let before = &body[..idx];
        if !before.contains('"') && !before.contains('\'') {
            return before.trim_end();
        }
    }
    body.trim_end()
}

fn line_contains(offset: usize, line_start: usize, line_end: usize, raw: &str) -> bool {
    if raw.ends_with('\n') {
        offset >= line_start && offset < line_end
    } else {
        offset >= line_start && offset <= line_end
    }
}

/// Locate the YAML mapping path covering `offset`.
pub fn yaml_cursor(source: &str, offset: usize) -> YamlCursor {
    let offset = offset.min(source.len());
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut siblings_by_parent: Vec<(String, String)> = Vec::new();
    let mut block_indent: Option<usize> = None;
    let mut found: Option<YamlCursor> = None;
    let mut last: YamlCursor = YamlCursor {
        path: Vec::new(),
        parent: String::new(),
        current_key: None,
        on_key: false,
        value: None,
        siblings: Vec::new(),
        in_list: false,
    };

    let mut byte = 0usize;
    for raw in source.split_inclusive('\n') {
        let line_start = byte;
        let line_end = byte + raw.len();
        byte = line_end;
        let on_line = line_contains(offset, line_start, line_end, raw);
        let body = raw.trim_end_matches(['\n', '\r']);
        let indent = line_indent(body);
        let trimmed = strip_comment(body.trim());

        if let Some(bi) = block_indent {
            if trimmed.is_empty() || indent > bi {
                if on_line && found.is_none() {
                    found = Some(last.clone());
                }
                continue;
            }
            block_indent = None;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            if on_line && found.is_none() {
                while stack.last().is_some_and(|(i, _)| *i >= indent) {
                    stack.pop();
                }
                last = cursor_from_stack(&stack, None, false, None, false);
                found = Some(last.clone());
            }
            continue;
        }

        while stack.last().is_some_and(|(i, _)| *i >= indent) {
            stack.pop();
        }

        let parent = stack.last().map(|(_, k)| k.clone()).unwrap_or_default();
        let in_list = trimmed.starts_with("- ");
        let content = if let Some(rest) = trimmed.strip_prefix("- ") {
            rest
        } else {
            trimmed
        };
        let content_offset = body.find(content).unwrap_or(indent);

        if let Some((key, value, key_rel, _value_rel)) = parse_key_value(content) {
            let key_start = line_start + content_offset + key_rel;
            let key_end = key_start + key.len();
            siblings_by_parent.push((parent.clone(), key.clone()));
            let is_block = matches!(value.as_str(), "|" | "|-" | "|+" | ">" | ">-" | ">+");
            if is_block {
                block_indent = Some(indent);
            }
            if on_line && found.is_none() {
                let on_key = offset < key_end;
                last = cursor_from_stack(
                    &stack,
                    Some(key.clone()),
                    on_key,
                    if on_key { None } else { Some(value.clone()) },
                    in_list,
                );
                found = Some(last.clone());
            }
            if value.is_empty() || is_block {
                stack.push((indent, key));
            }
        } else if in_list {
            if on_line && found.is_none() {
                last = cursor_from_stack(&stack, None, false, Some(content.to_string()), true);
                found = Some(last.clone());
            }
        } else if content.chars().all(is_key_char) && on_line && found.is_none() {
            last = cursor_from_stack(&stack, Some(content.to_string()), true, None, in_list);
            found = Some(last.clone());
        }
    }

    finish(found.unwrap_or(last), &siblings_by_parent)
}

fn parse_key_value(content: &str) -> Option<(String, String, usize, usize)> {
    let colon = content.find(':')?;
    let key = &content[..colon];
    if key.is_empty() || !key.chars().all(is_key_char) {
        return None;
    }
    let after = content[colon + 1..].trim_start();
    let value_rel = colon + 1 + (content[colon + 1..].len() - after.len());
    Some((key.to_string(), after.to_string(), 0, value_rel))
}

fn cursor_from_stack(
    stack: &[(usize, String)],
    current_key: Option<String>,
    on_key: bool,
    value: Option<String>,
    in_list: bool,
) -> YamlCursor {
    let parent = stack.last().map(|(_, k)| k.clone()).unwrap_or_default();
    let mut path: Vec<String> = stack.iter().map(|(_, k)| k.clone()).collect();
    if let Some(k) = &current_key {
        path.push(k.clone());
    }
    YamlCursor {
        path,
        parent,
        current_key,
        on_key,
        value,
        siblings: Vec::new(),
        in_list,
    }
}

fn finish(mut cursor: YamlCursor, siblings_by_parent: &[(String, String)]) -> YamlCursor {
    let mut seen = std::collections::BTreeSet::new();
    cursor.siblings = siblings_by_parent
        .iter()
        .filter(|(p, _)| *p == cursor.parent)
        .map(|(_, k)| k.clone())
        .filter(|k| seen.insert(k.clone()))
        .collect();
    cursor
}

/// Byte span of the first occurrence of `uuid` in `source`.
pub fn uuid_span(source: &str, uuid: &str) -> Option<ByteSpan> {
    let idx = source.find(uuid)?;
    Some(ByteSpan::new(idx, idx + uuid.len()))
}

/// Schema id from `metadata.schema` (`rule::1.0` → `rule`).
pub fn object_schema_kind(source: &str) -> String {
    for raw in source.lines() {
        let t = raw.trim();
        if let Some(rest) = t.strip_prefix("schema:") {
            let v = rest.trim();
            return v.split("::").next().unwrap_or(v).to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
  tlp: clear
description: |
  hello
configurations:
  sentinel:
    query: |
      SecurityEvent
"#;

    #[test]
    fn path_on_metadata_key() {
        let off = RULE.find("uuid:").unwrap();
        let c = yaml_cursor(RULE, off);
        assert_eq!(c.parent, "metadata");
        assert_eq!(c.current_key.as_deref(), Some("uuid"));
        assert!(c.on_key);
        assert!(c.siblings.contains(&"schema".into()), "{:?}", c.siblings);
    }

    #[test]
    fn path_on_tlp_value() {
        let off = RULE.find("clear").unwrap();
        let c = yaml_cursor(RULE, off);
        assert_eq!(c.current_key.as_deref(), Some("tlp"));
        assert!(!c.on_key);
        assert_eq!(c.value.as_deref(), Some("clear"));
    }

    #[test]
    fn path_inside_metadata_block() {
        let off = RULE.find("  tlp:").unwrap();
        let c = yaml_cursor(RULE, off);
        assert_eq!(c.parent, "metadata");
    }

    #[test]
    fn path_on_root_description() {
        let off = RULE.find("description:").unwrap();
        let c = yaml_cursor(RULE, off);
        assert_eq!(c.parent, "");
        assert_eq!(c.current_key.as_deref(), Some("description"));
        assert!(c.on_key);
    }
}
