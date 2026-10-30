//! Edits to `visibility.toml` that declare a dataset a query reads (#114):
//! the quick fix for `kql_table_not_declared`, `spl_dataset_not_declared` and
//! `elastic_dataset_not_declared`. The host reads and writes the file; this
//! module only computes the text edit.

use opentide_core::datasets::DatasetKind;
use opentide_core::{Position, Range};

/// Workspace-relative path of the visibility configuration.
pub const VISIBILITY_CONFIGURATION: &str = ".opentide/configurations/visibility.toml";

/// One text edit to `visibility.toml`, and what it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetEdit {
    /// A code action title (`Declare 'X' in log source "Y" (visibility.toml)`).
    pub title: String,
    /// Where to put `new_text`; an empty range inserts.
    pub range: Range,
    pub new_text: String,
}

/// The edit that declares `name` (a table, index, sourcetype, macro, index
/// pattern or data view) for `platform` in `visibility.toml`, whose text is
/// `toml` (`None` when the file does not exist yet).
///
/// The name is added to the `kind` list of the first `[[logsources]]` entry
/// whose `system` is `platform`, creating the list if the entry has none.
/// When no entry fits, a new `[[logsources]]` entry is appended.
pub fn declare_dataset(
    toml: Option<&str>,
    platform: &str,
    kind: DatasetKind,
    name: &str,
) -> DatasetEdit {
    let text = toml.unwrap_or("");
    let key = kind.key();
    let quoted = quote(name);
    let lines: Vec<&str> = text.split('\n').collect();
    for block in logsource_blocks(&lines) {
        if block.system.as_deref() != Some(platform) {
            continue;
        }
        let title = format!(
            "Declare '{name}' in log source \"{}\" (visibility.toml)",
            block.name.as_deref().unwrap_or(platform)
        );
        // An existing list: add to it.
        if let Some(at) = (block.start..block.end).find(|&i| key_of(lines[i]) == Some(key)) {
            let line = lines[at];
            let value = &line[line.find('=').map(|i| i + 1).unwrap_or(line.len())..];
            if let Some(close) = closing_bracket(value) {
                // `tables = ["A", "B"]` on one line.
                let close = line.len() - value.len() + close;
                let inner = line[..close].trim_end();
                let empty = inner.ends_with('[');
                let insert = if empty {
                    quoted.clone()
                } else {
                    format!(", {quoted}")
                };
                let column = utf16_len(inner);
                return DatasetEdit {
                    title,
                    range: point(at, column),
                    new_text: insert,
                };
            }
            // A list over several lines: before the line that closes it.
            if let Some(end) = (at + 1..block.end.max(at + 1).min(lines.len()))
                .find(|&i| lines[i].trim_start().starts_with(']'))
            {
                let indent: String = lines[end - 1]
                    .chars()
                    .take_while(|c| c.is_whitespace())
                    .collect();
                let indent = if end - 1 == at {
                    "  ".to_string()
                } else {
                    indent
                };
                return DatasetEdit {
                    title,
                    range: point(end, 0),
                    new_text: format!("{indent}{quoted},\n"),
                };
            }
        }
        // No list yet: after the entry's last key.
        let last = (block.start..block.end)
            .rev()
            .find(|&i| {
                let t = lines[i].trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .unwrap_or(block.start);
        return DatasetEdit {
            title,
            range: point(last + 1, 0),
            new_text: format!("{key} = [{quoted}]\n"),
        };
    }
    // No entry for the platform: a new one at the end.
    let last = lines.len() - 1;
    let tail = utf16_len(lines[last]);
    let lead = if text.is_empty() || text.ends_with("\n\n") {
        ""
    } else if text.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    DatasetEdit {
        title: format!("Add a [[logsources]] entry declaring '{name}' to visibility.toml"),
        range: point(last, tail),
        new_text: format!(
            "{lead}[[logsources]]\nname = {}\ndescription = {}\nsystem = {}\n{key} = [{quoted}]\n",
            quote(&format!("{name} ({platform})")),
            quote(&format!(
                "Declared from the editor; describe what {name} records."
            )),
            quote(platform),
        ),
    }
}

struct Block {
    start: usize,
    end: usize,
    system: Option<String>,
    name: Option<String>,
}

/// The `[[logsources]]` entries: header line + 1 up to the next table header.
fn logsource_blocks(lines: &[&str]) -> Vec<Block> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "[[logsources]]" {
            let start = i + 1;
            let mut end = start;
            while end < lines.len() && !lines[end].trim_start().starts_with('[') {
                end += 1;
            }
            // A multi-line array value starts with `[` on a continuation
            // line only after `key = [`; those lines start with `"` or `]`.
            let mut block = Block {
                start,
                end,
                system: None,
                name: None,
            };
            for line in &lines[start..end] {
                match key_of(line) {
                    Some("system") => block.system = string_value(line),
                    Some("name") => block.name = string_value(line),
                    _ => {}
                }
            }
            out.push(block);
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// The bare key of a `key = value` line.
fn key_of(line: &str) -> Option<&str> {
    let (key, _) = line.split_once('=')?;
    let key = key.trim();
    (!key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    .then_some(key)
}

fn string_value(line: &str) -> Option<String> {
    let (_, value) = line.split_once('=')?;
    let value = value.trim();
    let quote = value.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &value[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// The byte offset of the `]` that closes a one-line array value, outside
/// strings and before a comment.
fn closing_bracket(value: &str) -> Option<usize> {
    let mut in_string: Option<char> = None;
    let mut depth = 0i32;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        if let Some(q) = in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' && q == '"' {
                escaped = true;
            } else if c == q {
                in_string = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => in_string = Some(c),
            '#' => return None,
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn utf16_len(text: &str) -> u32 {
    text.chars().map(|c| c.len_utf16() as u32).sum()
}

fn point(line: usize, character: u32) -> Range {
    let p = Position::new(line as u32, character);
    Range { start: p, end: p }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(text: &str, edit: &DatasetEdit) -> String {
        let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
        let line = edit.range.start.line as usize;
        let col = edit.range.start.character as usize;
        let current = lines[line].clone();
        let byte = current
            .char_indices()
            .nth(col)
            .map(|(i, _)| i)
            .unwrap_or(current.len());
        let joined = format!("{}{}{}", &current[..byte], edit.new_text, &current[byte..]);
        lines[line] = joined;
        lines.join("\n")
    }

    const VISIBILITY: &str = r#"[[logsources]]
name = "Windows"
description = "Security events."
system = "splunk"
indexes = ["wineventlog"]

[[logsources]]
name = "VNet flow logs"
description = "Traffic analytics."
system = "sentinel"
tenants = ["Production"]
tables = ["NTANetAnalytics"]

[[logsources]]
name = "Hunting"
description = "Advanced hunting."
system = "defender_for_endpoint"
tables = [
    "DeviceProcessEvents",
]

[[logsources]]
name = "Elastic"
description = "Endpoint."
system = "elastic"
"#;

    #[test]
    fn adds_to_the_list_of_the_matching_log_source() {
        let edit = declare_dataset(
            Some(VISIBILITY),
            "sentinel",
            DatasetKind::Tables,
            "NTAIpDetails",
        );
        assert_eq!(
            edit.title,
            "Declare 'NTAIpDetails' in log source \"VNet flow logs\" (visibility.toml)"
        );
        assert!(
            apply(VISIBILITY, &edit).contains(r#"tables = ["NTANetAnalytics", "NTAIpDetails"]"#)
        );

        let edit = declare_dataset(
            Some(VISIBILITY),
            "defender_for_endpoint",
            DatasetKind::Tables,
            "DeviceInfo",
        );
        assert!(
            apply(VISIBILITY, &edit)
                .contains("    \"DeviceProcessEvents\",\n    \"DeviceInfo\",\n]")
        );

        // An entry without the list gets one.
        let edit = declare_dataset(Some(VISIBILITY), "elastic", DatasetKind::Indices, "logs-*");
        assert!(
            apply(VISIBILITY, &edit).ends_with("system = \"elastic\"\nindices = [\"logs-*\"]\n")
        );
        let edit = declare_dataset(Some(VISIBILITY), "splunk", DatasetKind::Macros, "sysmon");
        let applied = apply(VISIBILITY, &edit);
        assert!(
            applied.contains("indexes = [\"wineventlog\"]\nmacros = [\"sysmon\"]\n"),
            "{applied}"
        );
    }

    #[test]
    fn appends_an_entry_when_none_fits() {
        let text = "[[logsources]]\nname = \"x\"\ndescription = \"y\"\nsystem = \"splunk\"\n";
        let edit = declare_dataset(Some(text), "sentinel", DatasetKind::Tables, "Custom_CL");
        assert_eq!(
            edit.title,
            "Add a [[logsources]] entry declaring 'Custom_CL' to visibility.toml"
        );
        let applied = apply(text, &edit);
        assert!(applied.ends_with(
            "system = \"splunk\"\n\n[[logsources]]\nname = \"Custom_CL (sentinel)\"\ndescription = \"Declared from the editor; describe what Custom_CL records.\"\nsystem = \"sentinel\"\ntables = [\"Custom_CL\"]\n"
        ), "{applied}");
        let edit = declare_dataset(None, "sentinel", DatasetKind::Tables, "Custom_CL");
        assert!(edit.new_text.starts_with("[[logsources]]\n"));
        assert_eq!(edit.range, point(0, 0));
    }

    #[test]
    fn empty_lists_comments_and_quotes() {
        let text =
            "[[logsources]]\nname = \"s\"\nsystem = \"sentinel\" # prod\ntables = [] # none yet\n";
        let edit = declare_dataset(Some(text), "sentinel", DatasetKind::Tables, "A\"B");
        assert!(apply(text, &edit).contains("tables = [\"A\\\"B\"] # none yet"));
        let text = "[[logsources]]\nsystem = 'sentinel'\ntables = [\"a]b\"]\n";
        let edit = declare_dataset(Some(text), "sentinel", DatasetKind::Tables, "C");
        assert!(apply(text, &edit).contains("tables = [\"a]b\", \"C\"]"));
    }
}
