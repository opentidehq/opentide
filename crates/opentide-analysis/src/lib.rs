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
            opentide_tide::hover_tide(text, offset, &workspace)
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
            opentide_tide::completions_tide(text, offset, &workspace)
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

    #[test]
    fn tide_field_hover_and_path_scoped_completions() {
        let src = r#"name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
  tlp: clear
description: |
  hello
detection_model: 00000000-0000-4000-8002-000000000001
"#;
        let host = MemoryWorkspace {
            files: vec![
                ("objects/rules/rule.yaml".into(), src.to_string()),
                (
                    "objects/objectives/o.yaml".into(),
                    "name: Parent\nmetadata:\n  uuid: 00000000-0000-4000-8002-000000000001\n  schema: objective::1.0\n".into(),
                ),
            ],
        };
        let desc = src.find("description:").unwrap();
        let line = src[..desc].bytes().filter(|b| *b == b'\n').count() as u32;
        let h = hover(&host, LanguageId::TideYaml, src, Position::new(line, 0));
        assert!(
            h.as_deref().unwrap_or("").contains("Description"),
            "key hover, got {h:?}"
        );
        let tlp_val = src.find("clear").unwrap();
        let tlp_line = src[..tlp_val].bytes().filter(|b| *b == b'\n').count() as u32;
        let col = src[..tlp_val]
            .rsplit_once('\n')
            .map(|(_, rest)| rest.len())
            .unwrap_or(tlp_val) as u32;
        let tlp = hover(
            &host,
            LanguageId::TideYaml,
            src,
            Position::new(tlp_line, col),
        );
        assert!(
            tlp.as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains("clear"),
            "{tlp:?}"
        );
        let meta_off = src.find("  tlp:").unwrap();
        let items = completions(&host, LanguageId::TideYaml, src, meta_off);
        assert!(
            items.iter().any(|i| i.label == "author"),
            "{:?}",
            items.iter().map(|i| &i.label).collect::<Vec<_>>()
        );
        assert!(items.iter().any(|i| i.documentation.is_some()));
        assert!(!items.iter().any(|i| i.label == "High"));
        let dm = src.find("detection_model:").unwrap() + "detection_model: ".len();
        let refs = completions(&host, LanguageId::TideYaml, src, dm);
        assert!(
            refs.iter()
                .any(|i| i.label == "00000000-0000-4000-8002-000000000001"),
            "{:?}",
            refs.iter().map(|i| &i.label).collect::<Vec<_>>()
        );
    }
}
