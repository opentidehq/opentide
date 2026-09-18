//! I/O-free analysis orchestrator. Filesystem lives behind [`WorkspaceHost`].

use opentide_core::{CompletionItem, Diagnostic, LanguageId, Position, SignatureHelp};
use opentide_highlight::{
    encode_lsp_semantic_tokens, HighlightResult, HighlightSpec, HighlightToken, SemanticTokens,
};
use opentide_kql::Profile;
use opentide_tide::{IndexedObject, TideAnalyzeResult};

/// Host-supplied workspace snapshot. The analysis crate never calls `std::fs`.
pub trait WorkspaceHost {
    fn document(&self, uri: &str) -> Option<String>;
    fn documents(&self) -> Vec<(String, String)>;
}

#[derive(Debug, Clone, Default)]
pub struct MemoryWorkspace {
    pub files: Vec<(String, String)>,
}

impl WorkspaceHost for MemoryWorkspace {
    fn document(&self, uri: &str) -> Option<String> {
        self.files
            .iter()
            .find(|(p, _)| p == uri)
            .map(|(_, s)| s.clone())
    }

    fn documents(&self) -> Vec<(String, String)> {
        self.files.clone()
    }
}

#[derive(Debug, Clone)]
pub struct AnalyzeRequest {
    pub uri: String,
    pub language: LanguageId,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct AnalyzeResponse {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
    pub symbols: Vec<opentide_tide::DocumentSymbol>,
}

pub fn index_workspace(host: &dyn WorkspaceHost) -> Vec<IndexedObject> {
    host.documents()
        .iter()
        .filter_map(|(path, src)| opentide_tide::index_object(path, src))
        .collect()
}

pub fn analyze(host: &dyn WorkspaceHost, request: AnalyzeRequest) -> AnalyzeResponse {
    let workspace = index_workspace(host);
    match request.language {
        LanguageId::Kql => {
            let r = opentide_kql::analyze(&request.text, Profile::Sentinel);
            AnalyzeResponse {
                diagnostics: r.diagnostics,
                tokens: r.tokens,
                symbols: Vec::new(),
            }
        }
        LanguageId::Spl => {
            let r = opentide_spl::analyze(&request.text);
            AnalyzeResponse {
                diagnostics: r.diagnostics,
                tokens: r.tokens,
                symbols: Vec::new(),
            }
        }
        LanguageId::TideYaml => {
            let r: TideAnalyzeResult = opentide_tide::analyze(opentide_tide::AnalyzeInput {
                path: &request.uri,
                source: &request.text,
                workspace: &workspace,
            });
            AnalyzeResponse {
                diagnostics: r.diagnostics,
                tokens: r.tokens,
                symbols: r.symbols,
            }
        }
    }
}

pub fn highlight(language: LanguageId, text: &str) -> HighlightResult {
    let host = MemoryWorkspace {
        files: vec![("memory".into(), text.to_string())],
    };
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: "memory".into(),
            language,
            text: text.to_string(),
        },
    );
    let spec = HighlightSpec::load().expect("spec");
    HighlightResult {
        language_id: language.as_str().to_string(),
        tokens: response.tokens,
        legend: spec.legend,
    }
}

pub fn semantic_tokens(language: LanguageId, text: &str) -> SemanticTokens {
    let result = highlight(language, text);
    SemanticTokens {
        data: encode_lsp_semantic_tokens(&result.tokens),
        legend: result.legend,
    }
}

fn offset_at_position(text: &str, position: Position) -> usize {
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in text.char_indices() {
        if line == position.line && col >= position.character {
            return idx;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    text.len()
}

fn position_at_offset(text: &str, offset: usize) -> Position {
    opentide_core::span_to_range(text, opentide_core::ByteSpan::new(offset, offset.max(1))).start
}

fn defender_profile(field_path: &[String]) -> Profile {
    if field_path.iter().any(|p| p == "defender_for_endpoint") {
        Profile::Defender
    } else {
        Profile::Sentinel
    }
}

pub fn hover(
    host: &dyn WorkspaceHost,
    language: LanguageId,
    text: &str,
    position: Position,
) -> Option<String> {
    match language {
        LanguageId::Kql => opentide_kql::hover(text, position, Profile::Sentinel),
        LanguageId::Spl => opentide_spl::hover(text, position),
        LanguageId::TideYaml => {
            let offset = offset_at_position(text, position);
            if let Some((inj, inner)) = opentide_tide::injection_at_offset(text, offset) {
                let inner_pos = position_at_offset(&inj.inner, inner);
                return match inj.language {
                    LanguageId::Kql => opentide_kql::hover(
                        &inj.inner,
                        inner_pos,
                        defender_profile(&inj.field_path),
                    ),
                    LanguageId::Spl => opentide_spl::hover(&inj.inner, inner_pos),
                    LanguageId::TideYaml => None,
                };
            }
            let workspace = index_workspace(host);
            let window = text
                .get(offset.saturating_sub(40)..(offset + 40).min(text.len()))
                .unwrap_or("");
            let re = regex::Regex::new(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            )
            .ok()?;
            if let Some(uuid) = re.find(window).map(|m| m.as_str()) {
                if let Some(o) = opentide_tide::definition(&workspace, uuid) {
                    return Some(format!(
                        "**{}** ({})\n\n`{}`",
                        o.name, o.object_type, o.uuid
                    ));
                }
            }
            for vocab in opentide_tide::bundled_vocabs().values() {
                for key in &vocab.keys {
                    for (idx, _) in text.match_indices(&key.name) {
                        let end = idx + key.name.len();
                        if offset >= idx && offset < end {
                            return vocab.hover(&key.name);
                        }
                    }
                }
            }
            None
        }
    }
}

pub fn completions(
    host: &dyn WorkspaceHost,
    language: LanguageId,
    text: &str,
    offset: usize,
) -> Vec<CompletionItem> {
    match language {
        LanguageId::Kql => opentide_kql::completions(text, offset, Profile::Sentinel),
        LanguageId::Spl => opentide_spl::completions(text, offset),
        LanguageId::TideYaml => {
            if let Some((inj, inner)) = opentide_tide::injection_at_offset(text, offset) {
                return match inj.language {
                    LanguageId::Kql => opentide_kql::completions(
                        &inj.inner,
                        inner,
                        defender_profile(&inj.field_path),
                    ),
                    LanguageId::Spl => opentide_spl::completions(&inj.inner, inner),
                    LanguageId::TideYaml => Vec::new(),
                };
            }
            let workspace = index_workspace(host);
            let mut items = Vec::new();
            for (name, uuid) in opentide_tide::completions_for(&workspace, "objective") {
                items.push(CompletionItem::new(name, "reference").with_detail(uuid));
            }
            for (name, uuid) in opentide_tide::completions_for(&workspace, "threat") {
                items.push(CompletionItem::new(name, "reference").with_detail(uuid));
            }
            for (field, vocab) in opentide_tide::bundled_vocabs() {
                for key in vocab.keys {
                    items.push(
                        CompletionItem::new(key.name, "enum")
                            .with_detail(format!("{field} vocabulary")),
                    );
                }
            }
            items
        }
    }
}

pub fn compiled_kql(text: &str, tenant: &str) -> String {
    opentide_kql::compile_kql_query(text, &[], tenant)
}

pub fn compiled_spl(text: &str) -> String {
    // Authored text is the compiled form; implicit `| search` is not rewritten.
    text.to_string()
}

pub fn signature_help(
    _host: &dyn WorkspaceHost,
    language: LanguageId,
    text: &str,
    position: Position,
) -> Option<SignatureHelp> {
    let offset = offset_at_position(text, position);
    match language {
        LanguageId::Kql => opentide_kql::signature_help(text, offset, Profile::Sentinel),
        LanguageId::Spl => opentide_spl::signature_help(text, offset),
        LanguageId::TideYaml => {
            let (inj, inner) = opentide_tide::injection_at_offset(text, offset)?;
            match inj.language {
                LanguageId::Kql => opentide_kql::signature_help(
                    &inj.inner,
                    inner,
                    defender_profile(&inj.field_path),
                ),
                LanguageId::Spl => opentide_spl::signature_help(&inj.inner, inner),
                LanguageId::TideYaml => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_workspace_indexes_objects() {
        let host = MemoryWorkspace {
            files: vec![(
                "objects/rules/a.yaml".into(),
                "name: A\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n".into(),
            )],
        };
        let idx = index_workspace(&host);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx[0].object_type, "rule");
    }

    #[test]
    fn highlight_kql_returns_legend() {
        let h = highlight(LanguageId::Kql, "SecurityEvent | take 1");
        assert!(!h.legend.is_empty());
        assert!(!h.tokens.is_empty());
    }

    #[test]
    fn hover_and_completions_for_kql() {
        let host = MemoryWorkspace { files: vec![] };
        let items = completions(&host, LanguageId::Kql, "SecurityEvent | ", 16);
        assert!(items.iter().any(|i| i.label == "where"));
        let h = hover(
            &host,
            LanguageId::Kql,
            "SecurityEvent | where EventID == 1",
            Position::new(0, 16),
        );
        assert!(h.unwrap().contains("where"));
    }

    #[test]
    fn hover_and_completions_inside_tide_injected_kql() {
        let src = r#"name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
configurations:
  sentinel:
    query: |
      SecurityEvent
      | where EventID == 4688
"#;
        let host = MemoryWorkspace {
            files: vec![("objects/rules/rule.yaml".into(), src.to_string())],
        };
        let where_off = src.find("where").expect("where");
        let line = src[..where_off].bytes().filter(|b| *b == b'\n').count() as u32;
        let col = src[..where_off]
            .rsplit_once('\n')
            .map(|(_, rest)| rest.len())
            .unwrap_or(where_off) as u32;
        let h = hover(&host, LanguageId::TideYaml, src, Position::new(line, col));
        assert!(
            h.as_deref().unwrap_or("").contains("where"),
            "hover at injected where, got {h:?}"
        );
        let pipe = src.find("| where").expect("pipe") + 2;
        let items = completions(&host, LanguageId::TideYaml, src, pipe);
        assert!(
            items.iter().any(|i| i.label == "where"),
            "{:?}",
            items.iter().map(|i| &i.label).collect::<Vec<_>>()
        );
    }
}
