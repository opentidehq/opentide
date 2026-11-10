//! opentide language server — stdio JSON-RPC and CLI (`analyze` / `highlight`).
//!
//! The CLI never speaks JSON-RPC. `--stdio` is the editor protocol.

use opentide_lsp::server;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, highlight};
use opentide_core::LanguageId;
use opentide_highlight::{
    HighlightSpec, generate_helix, generate_monaco, generate_tm_language, tokens_to_html,
};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "opentide-lsp",
    about = "opentide language server",
    disable_version_flag = true
)]
struct Cli {
    /// Print the version (`--json`: what `initialize` reports in
    /// `capabilities.experimental.opentide`, without starting a session).
    #[arg(long, short = 'V')]
    version: bool,

    /// With `--version`: print it as JSON.
    #[arg(long, requires = "version")]
    json: bool,

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
        /// The detection platform a query file is for, as a `configurations`
        /// key: `carbon_black_cloud` checks Lucene in the Carbon Black
        /// dialect, `defender_for_endpoint` KQL against the Defender schema.
        #[arg(long)]
        platform: Option<String>,
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
    if cli.version {
        if cli.json {
            println!("{}", opentide_lsp::host_info());
        } else {
            println!("opentide-lsp {}", opentide_lsp::VERSION);
        }
        return Ok(());
    }
    if cli.stdio {
        // LSP: exit 0 after `shutdown` then `exit`, 1 when the client exits
        // or closes the stream without shutting the server down.
        if !server::run_stdio_status()? {
            std::process::exit(1);
        }
        return Ok(());
    }
    if let Some(addr) = cli.listen {
        return server::run_listen(&addr);
    }
    match cli.command {
        Some(Command::Analyze {
            file,
            language,
            platform,
        }) => cmd_analyze(&file, language.as_deref(), platform.as_deref()),
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
    let ext = path.extension().and_then(|s| s.to_str());
    if matches!(ext, Some("yaml" | "yml")) {
        return Ok(LanguageId::TideYaml);
    }
    ext.and_then(LanguageId::from_extension)
        .with_context(|| format!("cannot detect language from extension {ext:?}; pass --language"))
}

fn cmd_analyze(file: &Path, language: Option<&str>, platform: Option<&str>) -> Result<()> {
    // A bare file name is in the current directory: the filename checks
    // skip a path with no directory, as they do an unsaved buffer.
    let here;
    let file = if file.parent().is_none_or(|p| p.as_os_str().is_empty()) {
        here = Path::new(".").join(file);
        here.as_path()
    } else {
        file
    };
    let text = read_document(file)?;
    let language = detect_language(file, language)?;
    if let Some(platform) = platform.filter(|_| language != LanguageId::TideYaml) {
        let diagnostics = opentide_analysis::analyze_query(&opentide_analysis::QueryRequest {
            language,
            platform: Some(platform.to_string()),
            stack: None,
            text,
        });
        println!("{}", serde_json::to_string_pretty(&diagnostics)?);
        return Ok(());
    }
    let mut files = vec![(file.display().to_string(), text.clone())];
    // Only Tide YAML resolves references across the workspace; a raw query
    // file is analysed on its own.
    let root = (language == LanguageId::TideYaml)
        .then(|| find_objects_root(file))
        .flatten();
    if let Some(root) = root {
        collect_yaml(&root, &mut files);
        if let Some(workspace) = root.parent() {
            server::install_workspace_catalog(workspace);
            let config = workspace.join(opentide_analysis::ELASTIC_CONFIGURATION);
            if let Ok(text) = std::fs::read_to_string(&config) {
                files.push((config.display().to_string(), text));
            }
            // The filename and metadata checks follow the workspace's
            // lint.toml, as the server and `opentide lint` do (#214).
            let lint = workspace.join(opentide_analysis::LINT_CONFIGURATION);
            if let Ok(text) = std::fs::read_to_string(&lint)
                && let Err(err) = opentide_analysis::install_lint(Some(&text))
            {
                eprintln!(
                    "opentide-lsp: {}: {err}; opentide lint's defaults apply",
                    lint.display()
                );
            }
        }
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
    let text = read_document(file)?;
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
            root.join("esql.tmLanguage.json"),
            serde_json::to_string_pretty(&generate_tm_language(LanguageId::Esql, &spec))?,
        ),
        (
            root.join("eql.tmLanguage.json"),
            serde_json::to_string_pretty(&generate_tm_language(LanguageId::Eql, &spec))?,
        ),
        (
            root.join("kuery.tmLanguage.json"),
            serde_json::to_string_pretty(&generate_tm_language(LanguageId::Kuery, &spec))?,
        ),
        (
            root.join("lucene.tmLanguage.json"),
            serde_json::to_string_pretty(&generate_tm_language(LanguageId::Lucene, &spec))?,
        ),
        (
            root.join("falco.tmLanguage.json"),
            serde_json::to_string_pretty(&generate_tm_language(LanguageId::Falco, &spec))?,
        ),
        (
            root.join("cql.tmLanguage.json"),
            serde_json::to_string_pretty(&generate_tm_language(LanguageId::Cql, &spec))?,
        ),
        (
            root.join("monaco.json"),
            serde_json::to_string_pretty(&generate_monaco(&spec))?,
        ),
        (root.join("helix.toml"), generate_helix(&spec)),
        (
            root.join("package-contributions.json"),
            serde_json::to_string_pretty(&opentide_highlight::generate_package_contributions())?,
        ),
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
    if let Some(root) = server::workspace_root(file) {
        return Some(root.join("objects"));
    }
    file.parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
}

/// A document's text without its byte-order mark, which an editor neither
/// shows nor counts as a column ([`opentide_core::strip_bom`]).
fn read_document(path: &Path) -> std::io::Result<String> {
    let text = std::fs::read_to_string(path)?;
    Ok(opentide_core::strip_bom(&text).to_string())
}

/// The workspace YAML under `root`. A file that cannot be read as UTF-8 is
/// left out rather than failing the file being analysed.
fn collect_yaml(root: &Path, files: &mut Vec<(String, String)>) {
    files.extend(opentide_lsp::server::yaml_files(root));
}
