//! Edits to `visibility.toml` that declare a dataset a query reads (#114):
//! the quick fix for `kql_table_not_declared`, `kql_unknown_table` (where it
//! names the declaration), `spl_dataset_not_declared` and
//! `elastic_dataset_not_declared`. The host reads and writes the file; this
//! module only computes the text edit.

use opentide_core::{Position, Range};

/// Workspace-relative path of the visibility configuration.
pub const VISIBILITY_CONFIGURATION: &str = ".opentide/configurations/visibility.toml";

/// One text edit to `visibility.toml`, and what it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetEdit {
    /// A code action title (`Add a [[logsources]] entry declaring 'X' to visibility.toml`).
    pub title: String,
    /// Where to put `new_text`; an empty range inserts.
    pub range: Range,
    pub new_text: String,
}

/// The edit that declares `name` (a table, sourcetype or index pattern) for
/// `platform` in `visibility.toml`, whose text is `toml` (`None` when the
/// file does not exist yet).
///
/// A log source's `name` is its dataset (`visibility::1.0`), so the edit
/// appends a new `[[logsources]]` entry with that `name`, an empty
/// `description` to fill in, and the `system`; it never edits an existing
/// entry.
pub fn declare_dataset(toml: Option<&str>, platform: &str, name: &str) -> DatasetEdit {
    let text = toml.unwrap_or("");
    // Editors do not count a byte-order mark as a character of the first line.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines: Vec<&str> = text.split('\n').collect();
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
            "{lead}[[logsources]]\nname = {}\ndescription = \"\"\nsystem = {}\n",
            quote(name),
            quote(platform),
        ),
    }
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
name = "WinEventLog:Security"
description = "Security events."
system = "splunk"

[[logsources]]
name = "NTANetAnalytics"
description = "Traffic analytics."
system = "sentinel"
tenants = ["Production"]

[logsources.columns]
FlowType_s = { type = "string" }
"#;

    #[test]
    fn appends_a_new_log_source_and_never_edits_one() {
        let edit = declare_dataset(Some(VISIBILITY), "sentinel", "NTAIpDetails");
        assert_eq!(
            edit.title,
            "Add a [[logsources]] entry declaring 'NTAIpDetails' to visibility.toml"
        );
        let applied = apply(VISIBILITY, &edit);
        assert!(applied.starts_with(VISIBILITY), "{applied}");
        assert_eq!(
            &applied[VISIBILITY.len()..],
            "\n[[logsources]]\nname = \"NTAIpDetails\"\ndescription = \"\"\nsystem = \"sentinel\"\n"
        );
        // The result still parses, with both tables declared, and the new
        // entry does not join the previous one's columns.
        let d = opentide_core::datasets::DeclaredDatasets::from_visibility(&applied).unwrap();
        assert_eq!(d.names("sentinel"), ["NTANetAnalytics", "NTAIpDetails"]);
        assert!(d.sources("sentinel").nth(1).unwrap().columns.is_empty());

        for (platform, name) in [
            ("splunk", "syslog"),
            ("elastic", "logs-*"),
            ("defender_for_endpoint", "DeviceInfo"),
        ] {
            let edit = declare_dataset(Some(VISIBILITY), platform, name);
            let applied = apply(VISIBILITY, &edit);
            assert!(
                applied.ends_with(&format!(
                    "\n\n[[logsources]]\nname = \"{name}\"\ndescription = \"\"\nsystem = \"{platform}\"\n"
                )),
                "{applied}"
            );
        }
    }

    #[test]
    fn a_missing_file_a_byte_order_mark_and_quotes() {
        let edit = declare_dataset(None, "sentinel", "Custom_CL");
        assert_eq!(
            edit.new_text,
            "[[logsources]]\nname = \"Custom_CL\"\ndescription = \"\"\nsystem = \"sentinel\"\n"
        );
        assert_eq!(edit.range, point(0, 0));

        let text = "\u{feff}[[logsources]]\nname = \"main\"\nsystem = \"splunk\"";
        let edit = declare_dataset(Some(text), "sentinel", "A\"B");
        assert_eq!(edit.range, point(2, 17));
        assert!(
            edit.new_text
                .starts_with("\n\n[[logsources]]\nname = \"A\\\"B\"\n")
        );
    }
}
