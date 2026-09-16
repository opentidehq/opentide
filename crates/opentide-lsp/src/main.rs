//! OpenTide language server — stdio JSON-RPC and CLI (`analyze` / `highlight`).
//!
//! The CLI never speaks JSON-RPC. `--stdio` is the editor protocol.

mod jsonrpc;
mod server;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, highlight};
use opentide_core::LanguageId;
use opentide_highlight::{
    HighlightSpec, generate_helix, generate_monaco, generate_tm_language, tokens_to_html,
};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "opentide-lsp", version, about = "OpenTide language server")]
struct Cli {
    /// Speak LSP over stdin/stdout.
    #[arg(long)]
    stdio: bool,

    /// Optional TCP listen address (e.g. 127.0.0.1:2087).
    #[arg(long)]
    listen: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Analyze a file and print JSON diagnostics (not JSON-RPC).
    Analyze {
        file: PathBuf,
        #[arg(long)]
        language: Option<String>,
    },
    /// Highlight a file and print JSON tokens.
    Highlight {
        file: PathBuf,
        #[arg(long)]
        language: Option<String>,
        #[arg(long)]
        html: bool,
    },
    /// Rewrite generated editor maps from HighlightSpec (`--check` for CI).
    GenerateHighlights {
        #[arg(long)]
        check: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.stdio {
        return server::run_stdio();
    }
    if let Some(addr) = cli.listen {
        return server::run_listen(&addr);
    }
    match cli.command {
        Some(Command::Analyze { file, language }) => cmd_analyze(&file, language.as_deref()),
        Some(Command::Highlight {
            file,
            language,
            html,
        }) => cmd_highlight(&file, language.as_deref(), html),
        Some(Command::GenerateHighlights { check }) => cmd_generate_highlights(check),
        None => {
            eprintln!("opentide-lsp: pass --stdio, --listen, or a subcommand (analyze/highlight)");
            std::process::exit(2);
        }
    }
}

fn detect_language(path: &Path, override_lang: Option<&str>) -> Result<LanguageId> {
    if let Some(l) = override_lang {
        return LanguageId::parse(l).context("unknown language id");
    }
    match path.extension().and_then(|s| s.to_str()) {
        Some("kql") => Ok(LanguageId::Kql),
        Some("spl") => Ok(LanguageId::Spl),
        Some("yaml" | "yml") => Ok(LanguageId::TideYaml),
        other => anyhow::bail!("cannot detect language from extension {other:?}; pass --language"),
    }
}

fn cmd_analyze(file: &Path, language: Option<&str>) -> Result<()> {
    let text = std::fs::read_to_string(file)?;
    let language = detect_language(file, language)?;
    let mut files = vec![(file.display().to_string(), text.clone())];
    if let Some(root) = find_objects_root(file) {
        collect_yaml(&root, &mut files)?;
    }
    let host = MemoryWorkspace { files };
    let response = opentide_analysis::analyze(
        &host,
        AnalyzeRequest {
            uri: file.display().to_string(),
            language,
            text,
        },
    );
    println!("{}", serde_json::to_string_pretty(&response.diagnostics)?);
    Ok(())
}

fn cmd_highlight(file: &Path, language: Option<&str>, html: bool) -> Result<()> {
    let text = std::fs::read_to_string(file)?;
    let language = detect_language(file, language)?;
    let result = highlight(language, &text);
    if html {
        print!("{}", tokens_to_html(&text, &result.tokens));
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn cmd_generate_highlights(check: bool) -> Result<()> {
    let spec = HighlightSpec::load().map_err(|e| anyhow::anyhow!("{e}"))?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../highlights/generated");
    std::fs::create_dir_all(&root)?;
    let files = [
        (
            root.join("kql.tmLanguage.json"),
            serde_json::to_string_pretty(&generate_tm_language(LanguageId::Kql, &spec))?,
        ),
        (
            root.join("spl.tmLanguage.json"),
            serde_json::to_string_pretty(&generate_tm_language(LanguageId::Spl, &spec))?,
        ),
        (
            root.join("tide.tmLanguage.json"),
            serde_json::to_string_pretty(&generate_tm_language(LanguageId::TideYaml, &spec))?,
        ),
        (
            root.join("monaco.json"),
            serde_json::to_string_pretty(&generate_monaco(&spec))?,
        ),
        (root.join("helix.toml"), generate_helix(&spec)),
        (
            root.join("legend.json"),
            serde_json::to_string_pretty(&spec.legend)?,
        ),
    ];
    if check {
        for (path, expected) in &files {
            let actual = std::fs::read_to_string(path).unwrap_or_default();
            if actual.trim() != expected.trim() {
                anyhow::bail!("{} is stale", path.display());
            }
        }
        eprintln!("highlight artifacts up to date");
        return Ok(());
    }
    for (path, contents) in &files {
        std::fs::write(path, contents)?;
        eprintln!("wrote {}", path.display());
    }
    Ok(())
}

fn find_objects_root(file: &Path) -> Option<PathBuf> {
    for ancestor in file.ancestors() {
        let objects = ancestor.join("objects");
        if objects.is_dir() {
            return Some(objects);
        }
        if ancestor.join(".opentide").is_dir() {
            return Some(ancestor.join("objects"));
        }
    }
    file.parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
}

fn collect_yaml(root: &Path, files: &mut Vec<(String, String)>) -> Result<()> {
    if !root.is_dir() {
        return Ok(());
    }
    for entry in walk(root)? {
        if matches!(
            entry.extension().and_then(|s| s.to_str()),
            Some("yaml" | "yml")
        ) {
            let text = std::fs::read_to_string(&entry)?;
            files.push((entry.display().to_string(), text));
        }
    }
    Ok(())
}

fn walk(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    fn rec(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let p = e.path();
            if p.is_dir() {
                rec(&p, out)?;
            } else {
                out.push(p);
            }
        }
        Ok(())
    }
    rec(dir, &mut out)?;
    Ok(out)
}
