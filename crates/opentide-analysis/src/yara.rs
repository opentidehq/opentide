//! YARA editor features in document coordinates: a `.yar` file as it is,
//! and a YARA injection of a Tide object (`yara.signature`, HarfangLab's
//! decomposed fragments) through its map back to the YAML. A rename in a
//! decomposed block edits `strings` and `condition` together.

use opentide_core::{ByteSpan, LanguageId};
use opentide_tide::{DocumentSymbol, InjectedQuery, injection_at_offset, remap_span};
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

/// The YARA text at `offset`: the document itself, or the injection the
/// offset is in, with that offset inside it.
enum At {
    Raw,
    Injected {
        inj: InjectedQuery,
        inner: usize,
        bom: usize,
    },
}

fn at(language: LanguageId, text: &str, offset: usize) -> Option<At> {
    match language {
        LanguageId::Yara => Some(At::Raw),
        LanguageId::TideYaml => {
            let (stripped, offset) = opentide_core::strip_bom_at(text, offset);
            let bom = text.len() - stripped.len();
            let (inj, inner) = injection_at_offset(stripped, offset)?;
            (inj.language == LanguageId::Yara).then_some(At::Injected { inj, inner, bom })
        }
        _ => None,
    }
}

/// An inner span in document coordinates; `None` in generated text.
fn host(inj: &InjectedQuery, bom: usize, span: (usize, usize)) -> Option<ByteSpan> {
    if inj.is_synthetic(span.0) {
        return None;
    }
    let s = remap_span(inj, ByteSpan::new(span.0, span.1));
    Some(ByteSpan::new(s.start + bom, s.end + bom))
}

/// The definition of the YARA string or rule at `offset`.
pub fn definition(language: LanguageId, text: &str, offset: usize) -> Option<ByteSpan> {
    match at(language, text, offset)? {
        At::Raw => editor::definition(text, offset).map(|(s, e)| ByteSpan::new(s, e)),
        At::Injected { inj, inner, bom } => host(&inj, bom, editor::definition(&inj.inner, inner)?),
    }
}

/// Where the YARA string or rule at `offset` is written.
pub fn references(
    language: LanguageId,
    text: &str,
    offset: usize,
    with_definition: bool,
) -> Vec<ByteSpan> {
    match at(language, text, offset) {
        Some(At::Raw) => editor::references(text, offset, with_definition)
            .into_iter()
            .map(|(s, e)| ByteSpan::new(s, e))
            .collect(),
        Some(At::Injected { inj, inner, bom }) => {
            editor::references(&inj.inner, inner, with_definition)
                .into_iter()
                .filter_map(|span| host(&inj, bom, span))
                .collect()
        }
        None => Vec::new(),
    }
}

/// The edits that rename the YARA string at `offset`. `Err` says why there
/// is nothing to rename, or why it is refused.
pub fn rename(
    language: LanguageId,
    text: &str,
    offset: usize,
    new_name: &str,
) -> Result<Vec<(ByteSpan, String)>, String> {
    match at(language, text, offset) {
        Some(At::Raw) => Ok(editor::rename(text, offset, new_name)?
            .into_iter()
            .map(|((s, e), t)| (ByteSpan::new(s, e), t))
            .collect()),
        Some(At::Injected { inj, inner, bom }) => editor::rename(&inj.inner, inner, new_name)?
            .into_iter()
            .map(|(span, t)| {
                host(&inj, bom, span)
                    .map(|s| (s, t))
                    .ok_or_else(|| "the string is in text deploy generates".to_string())
            })
            .collect(),
        None => Err("nothing to rename here".into()),
    }
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

    const RULE: &str = "name: Cmd String\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  harfanglab:\n    yara:\n      meta:\n        context:\n          - file\n        os: Windows\n      strings: |\n        $cmd = \"cmd.exe\" ascii\n      condition: |\n        $cmd and #cmd > 1\n";

    #[test]
    fn rename_spans_both_decomposed_fragments() {
        let at = RULE.find("#cmd").unwrap() + 1;
        let edits = rename(LanguageId::TideYaml, RULE, at, "shell").unwrap();
        let mut out = RULE.to_string();
        for (span, t) in edits.iter().rev() {
            out.replace_range(span.start..span.end, t);
        }
        assert!(out.contains("$shell = \"cmd.exe\""), "{out}");
        assert!(out.contains("$shell and #shell > 1"), "{out}");
    }

    #[test]
    fn definition_and_references_in_a_decomposed_block() {
        let at = RULE.rfind("$cmd").unwrap() + 1;
        let def = definition(LanguageId::TideYaml, RULE, at).unwrap();
        assert_eq!(&RULE[def.start..def.end], "$cmd");
        assert_eq!(def.start, RULE.find("$cmd").unwrap());
        assert_eq!(references(LanguageId::TideYaml, RULE, at, true).len(), 3);
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
