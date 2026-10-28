//! Indent-based YAML cursor path for Tide objects (no serde at the caret).

use opentide_core::ByteSpan;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlCursor {
    /// Mapping path from the document root to the current key (inclusive when
    /// the caret is on a key or its value).
    pub path: Vec<String>,
    /// Immediate parent mapping key; empty string means document root.
    pub parent: String,
    /// Full parent path (`configurations.sentinel`), empty at the document root.
    /// Sibling keys are grouped by this path, not by the immediate key name.
    pub parent_path: String,
    pub current_key: Option<String>,
    pub on_key: bool,
    pub value: Option<String>,
    pub siblings: Vec<String>,
    pub in_list: bool,
    /// Sequence element under `parent_path`. Mapping keys use 0.
    /// A new `-` item increments this so siblings do not leak across elements.
    pub item_scope: u32,
}

impl YamlCursor {
    /// Path of the mapping whose keys should be completed.
    pub fn container_path(&self) -> String {
        if self.current_key.is_some() {
            let mut parts = self.path.clone();
            parts.pop();
            parts.join(".")
        } else {
            self.path.join(".")
        }
    }

    /// Path of the field under the caret (key or its value).
    pub fn field_path(&self) -> String {
        self.path.join(".")
    }
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
    let mut stack: Vec<Frame> = Vec::new();
    let mut siblings_by_parent: Vec<(String, u32, String)> = Vec::new();
    let mut item_gen: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut block_indent: Option<usize> = None;
    let mut found: Option<YamlCursor> = None;
    let mut last: YamlCursor = YamlCursor {
        path: Vec::new(),
        parent: String::new(),
        parent_path: String::new(),
        current_key: None,
        on_key: false,
        value: None,
        siblings: Vec::new(),
        in_list: false,
        item_scope: 0,
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
                pop_closed(&mut stack, indent, false);
                let parent_path = frame_path(&stack);
                let scope = item_gen.get(&parent_path).copied().unwrap_or(0);
                last = cursor_from_stack(&stack, None, false, None, false, scope);
                found = Some(last.clone());
            }
            continue;
        }

        let list_body = sequence_content(body);
        let in_list = list_body.is_some();
        // A sequence item may sit at the same column as the key that opened it
        // (`searches:\n- purpose:`). That key stays. Keys opened by the previous
        // `-` item, including block scalars, close.
        pop_closed(&mut stack, indent, in_list);

        let parent_path = frame_path(&stack);
        let mut scope = item_gen.get(&parent_path).copied().unwrap_or(0);
        if in_list {
            scope += 1;
            item_gen.insert(parent_path.clone(), scope);
        }
        let content = list_body.unwrap_or(trimmed);
        let content_offset = if content.is_empty() {
            indent + 1
        } else {
            body.find(content).unwrap_or(indent)
        };

        if let Some((key, value, key_rel, _value_rel)) = parse_key_value(content) {
            let key_start = line_start + content_offset + key_rel;
            let key_end = key_start + key.len();
            siblings_by_parent.push((parent_path, scope, key.clone()));
            let is_block = matches!(value.as_str(), "|" | "|-" | "|+" | ">" | ">-" | ">+");
            if is_block {
                block_indent = Some(indent);
            }
            let on_key = on_line && offset < key_end;
            last = cursor_from_stack(
                &stack,
                Some(key.clone()),
                on_key,
                if on_key { None } else { Some(value.clone()) },
                in_list,
                scope,
            );
            if on_line && found.is_none() {
                found = Some(last.clone());
            }
            if value.is_empty() || is_block {
                stack.push(Frame {
                    indent,
                    key,
                    from_item: in_list,
                });
            }
        } else if in_list {
            if on_line && found.is_none() {
                last =
                    cursor_from_stack(&stack, None, false, Some(content.to_string()), true, scope);
                found = Some(last.clone());
            }
        } else if content.chars().all(is_key_char) && on_line && found.is_none() {
            last = cursor_from_stack(
                &stack,
                Some(content.to_string()),
                true,
                None,
                in_list,
                scope,
            );
            found = Some(last.clone());
        }
    }

    finish(found.unwrap_or(last), &siblings_by_parent)
}

struct Frame {
    indent: usize,
    key: String,
    from_item: bool,
}

fn frame_path(stack: &[Frame]) -> String {
    stack
        .iter()
        .map(|frame| frame.key.as_str())
        .collect::<Vec<_>>()
        .join(".")
}

/// Content after a block-sequence marker, if this line is one.
/// `  - ` and `  -` are items. `-purpose` is not.
fn sequence_content(body: &str) -> Option<&str> {
    let indent = line_indent(body);
    let rest = body.get(indent..)?;
    let rest = rest.strip_prefix('-')?;
    if rest.is_empty() || rest.chars().all(|c| c == ' ' || c == '\t') {
        return Some("");
    }
    if rest.starts_with(' ') || rest.starts_with('\t') {
        return Some(rest.trim_start());
    }
    None
}

fn pop_closed(stack: &mut Vec<Frame>, indent: usize, in_list: bool) {
    while stack.last().is_some_and(|frame| {
        if in_list {
            frame.indent > indent || (frame.indent == indent && frame.from_item)
        } else {
            frame.indent >= indent
        }
    }) {
        stack.pop();
    }
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
    stack: &[Frame],
    current_key: Option<String>,
    on_key: bool,
    value: Option<String>,
    in_list: bool,
    item_scope: u32,
) -> YamlCursor {
    let parent = stack
        .last()
        .map(|frame| frame.key.clone())
        .unwrap_or_default();
    let parent_path = frame_path(stack);
    let mut path: Vec<String> = stack.iter().map(|frame| frame.key.clone()).collect();
    if let Some(k) = &current_key {
        path.push(k.clone());
    }
    YamlCursor {
        path,
        parent,
        parent_path,
        current_key,
        on_key,
        value,
        siblings: Vec::new(),
        in_list,
        item_scope,
    }
}

fn finish(mut cursor: YamlCursor, siblings_by_parent: &[(String, u32, String)]) -> YamlCursor {
    let mut seen = std::collections::BTreeSet::new();
    cursor.siblings = siblings_by_parent
        .iter()
        .filter(|(parent, scope, _)| *parent == cursor.parent_path && *scope == cursor.item_scope)
        .map(|(_, _, key)| key.clone())
        .filter(|key| seen.insert(key.clone()))
        .collect();
    cursor
}

/// Byte span of the first occurrence of `uuid` in `source`.
pub fn uuid_span(source: &str, uuid: &str) -> Option<ByteSpan> {
    let idx = source.find(uuid)?;
    Some(ByteSpan::new(idx, idx + uuid.len()))
}

/// Schema id from `metadata.schema` (`rule::1.0` → `rule`).
/// The object's schema id (`rule::1.1`) from its first `schema:` line, or an
/// empty string. Catalog lookups resolve it to its revision's fields.
pub fn document_schema_id(source: &str) -> String {
    for raw in source.lines() {
        let t = raw.trim();
        if let Some(rest) = t.strip_prefix("schema:") {
            let v = rest.split_whitespace().next().unwrap_or("");
            let v = v.trim_matches(|c| c == '"' || c == '\'');
            if v.contains("::") {
                return v.to_string();
            }
        }
    }
    String::new()
}

/// The span of the key at mapping `path` (`["metadata", "reviewed"]`), in
/// block-style YAML. Comment lines and block scalars are skipped, so a
/// commented-out template key (`#reviewed:`) is never taken for the real one.
/// List items do not count in the path: the first item holding the key wins.
pub fn key_span(source: &str, path: &[&str]) -> Option<ByteSpan> {
    if path.is_empty() {
        return None;
    }
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut block: Option<usize> = None;
    let mut offset = 0;
    for raw in source.split_inclusive('\n') {
        let start = offset;
        offset += raw.len();
        let line = raw.trim_end_matches(['\n', '\r']);
        let indent = line_indent(line);
        let body = &line[indent..];
        if body.is_empty() {
            continue;
        }
        if let Some(owner) = block {
            if indent > owner {
                continue;
            }
            block = None;
        }
        if body.starts_with('#') {
            continue;
        }
        // `- key: value` puts the key after the dash.
        let mut column = indent;
        let mut content = body;
        while let Some(rest) = content.strip_prefix('-') {
            if !(rest.is_empty() || rest.starts_with(' ')) {
                break;
            }
            let trimmed = rest.trim_start();
            column += content.len() - trimmed.len();
            content = trimmed;
        }
        let Some(colon) = content.find(':') else {
            continue;
        };
        let key = &content[..colon];
        let after = &content[colon + 1..];
        if key.is_empty()
            || !key.chars().all(is_key_char)
            || !(after.is_empty() || after.starts_with(' '))
        {
            continue;
        }
        while stack.last().is_some_and(|(depth, _)| *depth >= column) {
            stack.pop();
        }
        if stack.len() + 1 == path.len()
            && stack.iter().zip(path).all(|((_, name), want)| name == want)
            && key == path[path.len() - 1]
        {
            return Some(ByteSpan::new(start + column, start + column + key.len()));
        }
        let value = strip_comment(after).trim();
        if value.starts_with('|') || value.starts_with('>') {
            block = Some(column);
        }
        stack.push((column, key.to_string()));
    }
    None
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
        assert_eq!(c.parent_path, "metadata");
        assert_eq!(c.field_path(), "metadata.uuid");
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

    #[test]
    fn path_inside_description_block_keeps_current_key() {
        let off = RULE.find("  hello").unwrap();
        let c = yaml_cursor(RULE, off);
        assert_eq!(c.current_key.as_deref(), Some("description"));
        assert!(!c.on_key);
    }

    #[test]
    fn list_item_keeps_same_indent_sequence_key() {
        let src = "threat:\n  impact:\n  - Nuisance\n";
        let off = src.find("Nuisance").unwrap();
        let c = yaml_cursor(src, off);
        assert!(c.in_list);
        assert_eq!(c.field_path(), "threat.impact");
        assert_eq!(c.parent_path, "threat.impact");
    }

    #[test]
    fn empty_sequence_marker_is_not_a_key() {
        let src = "threat:\n  impact:\n  - \n";
        let off = src.find("- ").unwrap() + 2;
        let c = yaml_cursor(src, off);
        assert!(c.in_list, "{c:?}");
        assert_eq!(c.field_path(), "threat.impact");
        assert!(c.current_key.is_none(), "{c:?}");
    }

    #[test]
    fn next_sequence_item_does_not_inherit_previous_keys() {
        let src = "response:\n  procedure:\n    searches:\n    - purpose: first\n      system: defender_for_endpoint\n    - \n";
        let off = src.rfind("- ").unwrap() + 2;
        let c = yaml_cursor(src, off);
        assert_eq!(c.field_path(), "response.procedure.searches");
        assert!(c.current_key.is_none(), "{c:?}");
        assert!(
            !c.siblings
                .iter()
                .any(|key| key == "purpose" || key == "system"),
            "{:?}",
            c.siblings
        );
    }

    #[test]
    fn block_scalar_on_dash_does_not_swallow_next_item() {
        let src = "response:\n  procedure:\n    searches:\n    - query: |-\n        DeviceNetworkEvents\n    - purpose: next\n";
        let off = src.find("purpose:").unwrap();
        let c = yaml_cursor(src, off);
        assert_eq!(c.field_path(), "response.procedure.searches.purpose");
    }

    #[test]
    fn key_span_finds_the_real_key_by_path() {
        let source = "a:\n  #b: commented\n  c: |\n    b: inside a block\n  b: real\nlist:\n  - x: 1\n    b: item\n";
        let at = |path: &[&str]| key_span(source, path).map(|span| &source[span.start..span.end]);
        let span = key_span(source, &["a", "b"]).expect("a.b");
        assert_eq!(&source[span.start..span.end], "b");
        assert_eq!(source[..span.start].matches('\n').count(), 4);
        assert_eq!(at(&["list", "b"]), Some("b"));
        assert_eq!(at(&["list", "x"]), Some("x"));
        assert_eq!(at(&["b"]), None);
        assert_eq!(at(&[]), None);
    }

    #[test]
    fn the_document_schema_id_is_the_whole_id() {
        assert_eq!(document_schema_id(RULE), "rule::1.0");
        assert_eq!(
            document_schema_id("metadata:\n  schema: \"rule::1.1\"  # note\n"),
            "rule::1.1"
        );
        assert_eq!(document_schema_id("name: x\n"), "");
    }
}
