//! YARA editor features for `.yar` and `.yara` files. language-server also
//! served them in a Tide object's YARA (`yara.signature`, HarfangLab's
//! decomposed fragments); that injection is written on serde_yaml, which this
//! workspace does not use (#850), and comes back with its port onto
//! `opentide_core::node`.

use opentide_core::{ByteSpan, LanguageId};
use opentide_tide::DocumentSymbol;
use opentide_yara::editor;

/// Rules and strings of a `.yar` file, for the document outline.
pub(crate) fn symbols(text: &str) -> Vec<DocumentSymbol> {
    let lines = opentide_core::LineIndex::new(text);
    editor::symbols(text)
        .into_iter()
        .map(|s| DocumentSymbol {
            name: s.name,
            kind: match s.kind {
                editor::SymbolKind::Rule => "rule".into(),
                editor::SymbolKind::String => "string".into(),
            },
            range: lines.range(ByteSpan::new(s.selection.0, s.selection.1)),
            detail: s.detail,
        })
        .collect()
}

/// The definition of the YARA string or rule at `offset`.
pub fn definition(language: LanguageId, text: &str, offset: usize) -> Option<ByteSpan> {
    (language == LanguageId::Yara)
        .then(|| editor::definition(text, offset))
        .flatten()
        .map(|(s, e)| ByteSpan::new(s, e))
}

/// Where the YARA string or rule at `offset` is written.
pub fn references(
    language: LanguageId,
    text: &str,
    offset: usize,
    with_definition: bool,
) -> Vec<ByteSpan> {
    if language != LanguageId::Yara {
        return Vec::new();
    }
    editor::references(text, offset, with_definition)
        .into_iter()
        .map(|(s, e)| ByteSpan::new(s, e))
        .collect()
}

/// The edits that rename the YARA string at `offset`. `Err` says why there
/// is nothing to rename, or why it is refused.
pub fn rename(
    language: LanguageId,
    text: &str,
    offset: usize,
    new_name: &str,
) -> Result<Vec<(ByteSpan, String)>, String> {
    if language != LanguageId::Yara {
        return Err("nothing to rename here".into());
    }
    Ok(editor::rename(text, offset, new_name)?
        .into_iter()
        .map(|((s, e), t)| (ByteSpan::new(s, e), t))
        .collect())
}

/// A `.yar` file formatted with `yara-x-fmt`; `None` for any other
/// document, or one that does not parse.
pub fn format(language: LanguageId, text: &str) -> Option<String> {
    (language == LanguageId::Yara)
        .then(|| opentide_yara::format(text))
        .flatten()
}

/// Fold spans of a `.yar` file (rules, sections, multi-line hex strings and
/// comments); `None` for other documents, whose host folds by indentation.
pub fn folding(language: LanguageId, text: &str) -> Option<Vec<ByteSpan>> {
    (language == LanguageId::Yara).then(|| {
        editor::folding(text)
            .into_iter()
            .map(|(s, e)| ByteSpan::new(s, e))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_follows_a_string_in_a_yar_file() {
        let text = "rule a {\n  strings:\n    $cmd = \"cmd.exe\" ascii\n  condition:\n    $cmd and #cmd > 1\n}\n";
        let at = text.find("#cmd").unwrap() + 1;
        let edits = rename(LanguageId::Yara, text, at, "shell").unwrap();
        let mut out = text.to_string();
        for (span, t) in edits.iter().rev() {
            out.replace_range(span.start..span.end, t);
        }
        assert!(out.contains("$shell = \"cmd.exe\""), "{out}");
        assert!(out.contains("$shell and #shell > 1"), "{out}");
        let def = definition(LanguageId::Yara, text, text.rfind("$cmd").unwrap() + 1).unwrap();
        assert_eq!(def.start, text.find("$cmd").unwrap());
        assert_eq!(references(LanguageId::Yara, text, at, true).len(), 3);
        assert!(rename(LanguageId::TideYaml, text, at, "shell").is_err());
    }

    #[test]
    fn raw_files_format_and_fold() {
        assert_eq!(
            format(LanguageId::Yara, "rule a{condition:true}").as_deref(),
            Some("rule a {\n  condition:\n    true\n}\n")
        );
        assert_eq!(format(LanguageId::Kql, "x"), None);
        assert!(
            folding(LanguageId::Yara, "rule a {\n  condition:\n    true\n}\n")
                .is_some_and(|f| !f.is_empty())
        );
    }
}
