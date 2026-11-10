//! VS Code snippets from the object and platform templates
//! (`vscode_snippets.py`): each template's lines, with a tabstop on every
//! empty value and on every `...`; commented optional lines stay comments.

use std::sync::OnceLock;

use regex::Regex;

use super::json::{Json, Object};

/// The languages a snippet completes in: plain YAML, and `opentide-yaml`,
/// the language the opentide VS Code extension gives object files.
pub const SNIPPET_SCOPE: &str = "yaml,opentide-yaml";

struct Patterns {
    empty_scalar: Regex,
    ellipsis: Regex,
}

#[expect(
    clippy::expect_used,
    reason = "literal patterns: generate::snippets::tests compiles them"
)]
fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        empty_scalar: Regex::new(r"^(\s*)([^:#\n][^:\n]*):\s*$").expect("a literal pattern"),
        ellipsis: Regex::new(r"^(\s*)(\.\.\.)\s*$").expect("a literal pattern"),
    })
}

/// The prefix of a core object's snippet.
pub fn core_prefix(family: &str) -> String {
    match family {
        "threat" => "tide-threat".to_owned(),
        "objective" => "tide-objective".to_owned(),
        "rule" => "tide-rule".to_owned(),
        other => format!("tide-{other}"),
    }
}

fn indent_width(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// The indentation of the next line that is not blank, commented lines
/// included.
fn next_content_indent(lines: &[&str], index: usize) -> Option<usize> {
    lines[index + 1..]
        .iter()
        .find(|line| !line.trim().is_empty())
        .map(|line| indent_width(line))
}

/// Empty values as tabstops; a key whose next line is indented deeper is a
/// parent, not a value to fill in.
fn with_tabstops(lines: &[&str]) -> Vec<String> {
    let p = patterns();
    let mut body = Vec::with_capacity(lines.len());
    let mut index = 1;
    for (number, line) in lines.iter().enumerate() {
        if line.trim_start_matches(' ').starts_with('#') {
            body.push((*line).to_owned());
            continue;
        }
        if let Some(found) = p.empty_scalar.captures(line) {
            let indent = &found[1];
            let key = &found[2];
            if next_content_indent(lines, number).is_some_and(|child| child > indent_width(line)) {
                body.push((*line).to_owned());
                continue;
            }
            body.push(format!("{indent}{key}: ${{{index}:{}}}", key.trim()));
            index += 1;
            continue;
        }
        if let Some(found) = p.ellipsis.captures(line) {
            body.push(format!("{}${{{index}:{}}}", &found[1], &found[2]));
            index += 1;
            continue;
        }
        body.push((*line).to_owned());
    }
    body
}

/// One snippet from a template's text (`vs_code_snippet_generator`):
/// `blanks` empty lines first, then the template's lines with tabstops.
pub fn snippet(template: &str, prefix: &str, blanks: usize, description: Option<&str>) -> Json {
    let lines: Vec<&str> = template.lines().collect();
    let mut body: Vec<Json> = vec![Json::from(""); blanks];
    body.extend(with_tabstops(&lines).into_iter().map(Json::from));
    let mut entry = Object::new();
    entry.insert("prefix".to_owned(), Json::from(prefix));
    entry.insert("scope".to_owned(), Json::from(SNIPPET_SCOPE));
    entry.insert(
        "description".to_owned(),
        Json::from(description.unwrap_or(prefix)),
    );
    entry.insert("body".to_owned(), Json::Array(body));
    Json::Object(entry)
}

/// A core object's snippet: `<full name> Template`.
pub fn core_snippet(family: &str, full_name: &str, template: &str) -> (String, Json) {
    let description = format!(
        "{full_name}: a new object from the generated template, with a tabstop on every field to fill."
    );
    (
        format!("{full_name} Template").trim().to_owned(),
        snippet(template, &core_prefix(family), 0, Some(&description)),
    )
}

/// A platform block's snippet: `Platform configuration : <name> Template`.
pub fn platform_snippet(platform: &str, name: &str, template: &str) -> (String, Json) {
    let description = format!(
        "{name}: the platform block for a detection rule's configurations, from the generated template."
    );
    (
        format!("Platform configuration : {name} Template")
            .trim()
            .to_owned(),
        snippet(template, &format!("tide-{platform}"), 1, Some(&description)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: &Json) -> Vec<String> {
        json.get("body")
            .and_then(Json::as_array)
            .unwrap()
            .iter()
            .map(|line| line.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn empty_values_and_ellipses_become_numbered_tabstops() {
        let template =
            "name: \nmetadata:\n  uuid: \n  #tlp: \ndescription: |\n  ...\n#tags:\n  #- \n";
        let entry = snippet(template, "tide-x", 0, None);
        assert_eq!(
            body(&entry),
            vec![
                "name: ${1:name}",
                "metadata:",
                "  uuid: ${2:uuid}",
                "  #tlp: ",
                "description: |",
                "  ${3:...}",
                "#tags:",
                "  #- ",
            ]
        );
        assert_eq!(entry.get("description"), Some(&Json::from("tide-x")));
        assert_eq!(entry.get("scope"), Some(&Json::from(SNIPPET_SCOPE)));
    }

    #[test]
    fn a_parent_before_commented_children_is_not_a_tabstop() {
        let entry = snippet("configurations:\n  #sentinel:\n", "p", 1, None);
        assert_eq!(body(&entry), vec!["", "configurations:", "  #sentinel:"]);
    }

    #[test]
    fn titles_and_prefixes() {
        let (title, entry) = core_snippet("rule", "Detection Rules", "name: \n");
        assert_eq!(title, "Detection Rules Template");
        assert_eq!(entry.get("prefix"), Some(&Json::from("tide-rule")));
        let (title, entry) = platform_snippet("sentinel", "Microsoft Sentinel", "  a: \n");
        assert_eq!(
            title,
            "Platform configuration : Microsoft Sentinel Template"
        );
        assert_eq!(entry.get("prefix"), Some(&Json::from("tide-sentinel")));
        assert_eq!(core_prefix("signal"), "tide-signal");
    }
}
