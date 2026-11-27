//! Shared I/O-free types for the opentide language server.
//!
//! Names use `opentide`, never `otide`.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

#![expect(
    missing_docs,
    reason = "imported from language-server with public items undocumented: crates/AGENTS.md, Lints"
)]
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// The version a build of opentide reports, in SemVer (`1.0.0`, `1.0.0-rc.1`):
/// `OPENTIDE_BUILD_VERSION` when the build sets it, otherwise the crate's own.
///
/// A release candidate's crates on crates.io carry its version, but the
/// binaries and the wheel are built from the branch, whose workspace keeps the
/// release's `X.Y.Z`; the release train sets `OPENTIDE_BUILD_VERSION` for them (the
/// binaries' environment, the wheel's `.cargo/config.toml`), so that every
/// channel names the candidate. The analysis engine, the language
/// server and their `--version` report this value.
pub const VERSION: &str = reported_version(
    option_env!("OPENTIDE_BUILD_VERSION"),
    env!("CARGO_PKG_VERSION"),
);

/// `from_build` when the build set a version, else `package`; an empty value
/// counts as not set.
const fn reported_version(from_build: Option<&'static str>, package: &'static str) -> &'static str {
    match from_build {
        Some(version) if !version.is_empty() => version,
        _ => package,
    }
}

/// Language identifier advertised to editors and WASM hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LanguageId {
    #[serde(rename = "kql", alias = "opentide-kql")]
    Kql,
    #[serde(rename = "spl", alias = "opentide-spl")]
    Spl,
    #[serde(rename = "opentide-yaml", alias = "yaml", alias = "tide")]
    TideYaml,
    /// Elasticsearch ES|QL (Elastic Security `esql` rules).
    #[serde(rename = "esql", alias = "opentide-esql")]
    Esql,
    /// Elasticsearch Event Query Language (Elastic Security `eql` rules).
    #[serde(rename = "eql", alias = "opentide-eql")]
    Eql,
    /// Kibana Query Language. Kibana's API calls it `kuery`; `KQL` stays Kusto.
    #[serde(rename = "kuery", alias = "opentide-kuery")]
    Kuery,
    /// Lucene query string syntax (Elastic `language: lucene`).
    #[serde(rename = "lucene", alias = "opentide-lucene")]
    Lucene,
    /// A configuration TOML file under `.opentide/configurations/`. The host
    /// checks it (opentide's models); the engine places the findings. Not an
    /// alias of `toml`: only those files are this language.
    #[serde(rename = "opentide-config")]
    Config,
    /// Falco rule conditions (Sysdig Secure `configurations.sysdig`).
    #[serde(rename = "falco", alias = "opentide-falco")]
    Falco,
    /// CrowdStrike Query Language: Falcon LogScale and Next-Gen SIEM
    /// (`configurations.crowdstrike`). Not Cassandra's CQL.
    #[serde(rename = "cql", alias = "opentide-cql")]
    Cql,
    /// YARA signatures as YARA-X 1.x compiles them (yara-1.0; HarfangLab
    /// and Bitdefender `yara` blocks).
    #[serde(rename = "yara", alias = "opentide-yara")]
    Yara,
    /// The Exabeam Query Language of the New-Scale SIEM (exabeam-1.0;
    /// `configurations.exabeam`, `system: exabeam` hunts). Exabeam's guides
    /// call it "EQL"; opentide never does, because `eql` is Elastic's.
    #[serde(rename = "exabeam", alias = "opentide-exabeam")]
    Exabeam,
    /// YARA-L 2.0, the detection and search language of Google Security
    /// Operations (yara-l-1.0; `configurations.google_secops`, `.yaral` and
    /// `.yl2` files). Not YARA: no code is shared.
    #[serde(rename = "yaral", alias = "opentide-yaral", alias = "yara-l")]
    Yaral,
    /// The Datadog log search syntax (Datadog Cloud SIEM detection-rule
    /// queries, `.datadog` files): Datadog's API calls it `event_query`.
    #[serde(rename = "datadog", alias = "opentide-datadog")]
    Datadog,
}

impl LanguageId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kql => "kql",
            Self::Spl => "spl",
            Self::TideYaml => "opentide-yaml",
            Self::Esql => "esql",
            Self::Eql => "eql",
            Self::Kuery => "kuery",
            Self::Lucene => "lucene",
            Self::Config => "opentide-config",
            Self::Falco => "falco",
            Self::Cql => "cql",
            Self::Yara => "yara",
            Self::Exabeam => "exabeam",
            Self::Yaral => "yaral",
            Self::Datadog => "datadog",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "kql" | "opentide-kql" | "KQL" | "kusto" => Some(Self::Kql),
            "spl" | "opentide-spl" | "SPL" => Some(Self::Spl),
            "opentide-yaml" | "yaml" | "tide" | "tide-yaml" => Some(Self::TideYaml),
            "esql" | "opentide-esql" | "ES|QL" | "es|ql" | "ESQL" => Some(Self::Esql),
            "eql" | "opentide-eql" | "EQL" => Some(Self::Eql),
            "kuery" | "opentide-kuery" | "kibana-kql" => Some(Self::Kuery),
            "lucene" | "opentide-lucene" | "Lucene" => Some(Self::Lucene),
            "opentide-config" => Some(Self::Config),
            "falco" | "opentide-falco" | "Falco" => Some(Self::Falco),
            "cql" | "opentide-cql" | "CQL" | "logscale" | "crowdstrike" => Some(Self::Cql),
            "yara" | "opentide-yara" | "YARA" => Some(Self::Yara),
            "exabeam" | "opentide-exabeam" | "Exabeam" => Some(Self::Exabeam),
            "yaral" | "opentide-yaral" | "yara-l" | "YARA-L" => Some(Self::Yaral),
            "datadog" | "opentide-datadog" | "Datadog" => Some(Self::Datadog),
            _ => None,
        }
    }

    /// Language of a raw query file, from its extension. Anything else is
    /// Tide YAML or unknown, which the caller decides.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension {
            "kql" => Some(Self::Kql),
            "spl" => Some(Self::Spl),
            "esql" => Some(Self::Esql),
            "eql" => Some(Self::Eql),
            "kuery" => Some(Self::Kuery),
            "lucene" => Some(Self::Lucene),
            "falco" => Some(Self::Falco),
            "cql" => Some(Self::Cql),
            "yar" | "yara" => Some(Self::Yara),
            "exabeam" => Some(Self::Exabeam),
            "yaral" | "yl2" => Some(Self::Yaral),
            "datadog" => Some(Self::Datadog),
            _ => None,
        }
    }

    /// Query languages with a tree-sitter grammar and an engine.
    pub const QUERY_LANGUAGES: [Self; 12] = [
        Self::Kql,
        Self::Spl,
        Self::Esql,
        Self::Eql,
        Self::Kuery,
        Self::Lucene,
        Self::Falco,
        Self::Cql,
        Self::Yara,
        Self::Exabeam,
        Self::Yaral,
        Self::Datadog,
    ];
}

impl fmt::Display for LanguageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Zero-based UTF-16-friendly line/character position (LSP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

impl Position {
    pub fn new(line: u32, character: u32) -> Self {
        Self { line, character }
    }
}

/// Half-open range in a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub fn new(start: Position, end: Position) -> Self {
        Self { start, end }
    }

    pub fn point(line: u32, character: u32) -> Self {
        let p = Position::new(line, character);
        Self { start: p, end: p }
    }

    pub fn contains(&self, position: Position) -> bool {
        (position.line > self.start.line
            || (position.line == self.start.line && position.character >= self.start.character))
            && (position.line < self.end.line
                || (position.line == self.end.line && position.character <= self.end.character))
    }
}

/// Byte span in the original source (UTF-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

/// The text of a document without its leading UTF-8 byte-order mark
/// (U+FEFF, `EF BB BF`), if it has one. Some Windows editors save files with
/// one; an editor neither shows it nor counts it as a column, so a document's
/// offsets and positions are those of the text after it.
pub fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// [`strip_bom`], with `offset` (a byte offset into `text`) moved onto the
/// text it returns. An offset inside the mark is the start of the text.
/// Where the run of characters `keep` accepts that ends `text` starts: the
/// byte after the last character it rejects, or 0. Always a char boundary,
/// whatever the rejected character's width (#182: `rfind(...) + 1` landed
/// inside `é`).
pub fn word_start(text: &str, keep: impl Fn(char) -> bool) -> usize {
    text.char_indices()
        .rev()
        .find(|(_, c)| !keep(*c))
        .map_or(0, |(i, c)| i + c.len_utf8())
}

pub fn strip_bom_at(text: &str, offset: usize) -> (&str, usize) {
    let stripped = strip_bom(text);
    let shift = text.len() - stripped.len();
    (stripped, offset.saturating_sub(shift))
}

/// Convert a UTF-8 byte offset to an LSP position. An offset inside a
/// multi-byte character counts from that character's start: a span that ends
/// mid-character gives a slightly short range, never a panic.
pub fn offset_to_position(source: &str, offset: usize) -> Position {
    if let Some(position) = scoped::position(source, offset) {
        return position;
    }
    let offset = source.floor_char_boundary(offset);
    let mut line = 0u32;
    let mut last_line_start = 0usize;
    for (idx, ch) in source.char_indices() {
        if idx >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            last_line_start = idx + 1;
        }
    }
    let slice = &source[last_line_start..offset];
    Position {
        line,
        character: utf16_len(slice),
    }
}

/// Convert an LSP position (UTF-16 columns) to a UTF-8 byte offset, the
/// inverse of [`offset_to_position`]. A column past the end of its line
/// clamps to the line end; a line past the end of the text gives its length.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a char is one or two UTF-16 units"
)]
pub fn position_to_offset(source: &str, position: Position) -> usize {
    scoped::SCANS.with(|scans| scans.set(scans.get() + 1));
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in source.char_indices() {
        if line == position.line && (col >= position.character || ch == '\n') {
            return idx;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += ch.len_utf16() as u32;
        }
    }
    source.len()
}

/// The LSP range of `span` in `source`. Each call scans `source` from its
/// start, unless [`with_line_index`] has installed the line table of this very
/// `source`: an engine that reports many findings runs its analysis inside
/// [`with_line_index`], so that converting them all stays linear.
pub fn span_to_range(source: &str, span: ByteSpan) -> Range {
    Range {
        start: offset_to_position(source, span.start),
        end: offset_to_position(source, span.end),
    }
}

/// Line starts of a text, for many offset-to-position conversions: each is a
/// binary search instead of [`offset_to_position`]'s scan from the start, so
/// converting every token of a large query stays linear.
pub struct LineIndex<'a> {
    source: &'a str,
    table: LineTable,
}

/// The line starts and UTF-16 corrections of a text, owned: what
/// [`LineIndex`] and [`with_line_index`] search.
struct LineTable {
    starts: Vec<usize>,
    /// Lines that are pure ASCII, where a column is a byte distance.
    ascii: Vec<bool>,
    /// Each non-ASCII character's byte offset and the running sum, up to and
    /// including it, of its UTF-8 length minus its UTF-16 length: a column
    /// is the byte distance less that sum over the characters before it, so
    /// a long non-ASCII line needs no scan.
    wide: Vec<(usize, usize)>,
}

impl LineTable {
    fn new(source: &str) -> Self {
        scoped::TABLES.with(|tables| tables.set(tables.get() + 1));
        let mut starts = vec![0];
        starts.extend(source.match_indices('\n').map(|(i, _)| i + 1));
        let ascii = (0..starts.len())
            .map(|line| {
                let end = starts.get(line + 1).copied().unwrap_or(source.len());
                source[starts[line]..end].is_ascii()
            })
            .collect();
        let mut excess = 0;
        let wide = source
            .char_indices()
            .filter(|(_, c)| !c.is_ascii())
            .map(|(i, c)| {
                excess += c.len_utf8() - c.len_utf16();
                (i, excess)
            })
            .collect();
        Self {
            starts,
            ascii,
            wide,
        }
    }

    /// The excess (UTF-8 minus UTF-16 length) of the characters before byte
    /// `offset`, a char boundary.
    fn excess_before(&self, offset: usize) -> usize {
        match self.wide.partition_point(|&(at, _)| at < offset) {
            0 => 0,
            n => self.wide[n - 1].1,
        }
    }

    /// The position of `offset` in `source`, the text the table was built
    /// from: the same result as [`offset_to_position`].
    #[expect(
        clippy::cast_possible_truncation,
        reason = "LSP positions are u32 (lines, UTF-16 units); a document past 4 GiB is out of scope (#843)"
    )]
    fn position(&self, source: &str, offset: usize) -> Position {
        let offset = source.floor_char_boundary(offset);
        let line = self.starts.partition_point(|&start| start <= offset) - 1;
        let start = self.starts[line];
        let character = if self.ascii[line] {
            (offset - start) as u32
        } else {
            (offset - start - (self.excess_before(offset) - self.excess_before(start))) as u32
        };
        Position {
            line: line as u32,
            character,
        }
    }
}

impl<'a> LineIndex<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            source,
            table: LineTable::new(source),
        }
    }

    /// Same result as [`offset_to_position`].
    pub fn position(&self, offset: usize) -> Position {
        self.table.position(self.source, offset)
    }

    /// Same result as [`position_to_offset`]: the byte offset of an LSP
    /// position (UTF-16 columns), a column past its line's end clamping to
    /// that end, a line past the text's end giving its length.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a char is one or two UTF-16 units"
    )]
    pub fn offset(&self, position: Position) -> usize {
        let line = position.line as usize;
        let Some(&start) = self.table.starts.get(line) else {
            return self.source.len();
        };
        // The line's end: its `\n`, or the end of the text.
        let end = self
            .table
            .starts
            .get(line + 1)
            .map_or(self.source.len(), |next| next - 1);
        if self.table.ascii[line] {
            return (start + position.character as usize).min(end);
        }
        let mut col = 0u32;
        for (i, ch) in self.source[start..end].char_indices() {
            if col >= position.character {
                return start + i;
            }
            col += ch.len_utf16() as u32;
        }
        end
    }

    /// Same result as [`span_to_range`].
    pub fn range(&self, span: ByteSpan) -> Range {
        Range {
            start: self.position(span.start),
            end: self.position(span.end),
        }
    }
}

/// Runs `run` with the line table of `source` installed, so that
/// [`span_to_range`] and [`offset_to_position`] on this very `source` (the same
/// bytes: the same address and length) search the table instead of scanning
/// from the start. An engine wraps the analysis of a query in it, so that a
/// query with many findings converts them in linear time. The table built
/// before is put back afterwards, even on a panic; when `source`'s is already
/// installed, nothing is built.
pub fn with_line_index<T>(source: &str, run: impl FnOnce() -> T) -> T {
    scoped::with(source, run)
}

/// Whether [`with_line_index`] has installed the line table of this very
/// `source`: then [`span_to_range`] searches it, and a caller that would build
/// a [`LineIndex`] of its own for `source` need not (ADR 0014 §1).
#[must_use]
pub fn line_index_installed(source: &str) -> bool {
    scoped::installed(source)
}

/// How many times [`span_to_range`] and [`offset_to_position`] scanned a text
/// from its start on this thread (no [`with_line_index`] table was installed
/// for it), and [`position_to_offset`], which always does ([`LineIndex::offset`]
/// is its table's). Tests read it to prove an analysis converts its findings through
/// one table (a work count, not a wall clock).
#[doc(hidden)]
pub fn scans_from_the_start() -> usize {
    scoped::SCANS.with(std::cell::Cell::get)
}

/// How many line tables ([`LineIndex::new`], [`with_line_index`]) this thread
/// has built. Tests read it to prove an analysis builds one table for a text
/// and hands it to every pass (ADR 0014 §1, a work count).
#[doc(hidden)]
pub fn line_tables_built() -> usize {
    scoped::TABLES.with(std::cell::Cell::get)
}

mod scoped {
    use super::{LineTable, Position};
    use std::cell::{Cell, RefCell};

    /// The installed table and the text it is for, by address and length.
    /// While [`with`] runs, that text is borrowed, so no other text can have
    /// its address: a `&str` with the same address and length is the same
    /// bytes.
    struct Installed {
        key: (usize, usize),
        table: LineTable,
    }

    thread_local! {
        static INSTALLED: RefCell<Option<Installed>> = const { RefCell::new(None) };
        pub(super) static SCANS: Cell<usize> = const { Cell::new(0) };
        pub(super) static TABLES: Cell<usize> = const { Cell::new(0) };
    }

    fn key(source: &str) -> (usize, usize) {
        (source.as_ptr() as usize, source.len())
    }

    pub(super) fn with<T>(source: &str, run: impl FnOnce() -> T) -> T {
        struct Restore(Option<Installed>);
        impl Drop for Restore {
            fn drop(&mut self) {
                let previous = self.0.take();
                INSTALLED.with(|installed| *installed.borrow_mut() = previous);
            }
        }
        let current = INSTALLED.with(|installed| {
            installed
                .borrow()
                .as_ref()
                .is_some_and(|table| table.key == key(source))
        });
        if current {
            return run();
        }
        let table = Installed {
            key: key(source),
            table: LineTable::new(source),
        };
        let previous = INSTALLED.with(|installed| installed.replace(Some(table)));
        let _restore = Restore(previous);
        run()
    }

    /// Whether the installed table is `source`'s.
    pub(super) fn installed(source: &str) -> bool {
        INSTALLED.with(|installed| {
            installed
                .borrow()
                .as_ref()
                .is_some_and(|table| table.key == key(source))
        })
    }

    /// The position of `offset` from the installed table, if it is
    /// `source`'s; otherwise `None`, counted as a scan from the start.
    pub(super) fn position(source: &str, offset: usize) -> Option<Position> {
        let found = INSTALLED.with(|installed| {
            installed
                .borrow()
                .as_ref()
                .filter(|table| table.key == key(source))
                .map(|table| table.table.position(source, offset))
        });
        if found.is_none() {
            SCANS.with(|scans| scans.set(scans.get() + 1));
        }
        found
    }
}

/// The length of `text` in UTF-16 code units, the unit of an LSP column.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a char is one or two UTF-16 units"
)]
pub fn utf16_len(text: &str) -> u32 {
    text.chars().map(|c| c.len_utf16() as u32).sum()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Information,
    Hint,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Information => "information",
            Self::Hint => "hint",
        }
    }

    /// A severity named the way hosts name it (`error`, `warning`,
    /// `information` or `info`, `hint`), case-insensitively.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warning" | "warn" => Some(Self::Warning),
            "information" | "info" => Some(Self::Information),
            "hint" => Some(Self::Hint),
            _ => None,
        }
    }
}

/// Machine-stable diagnostic. CLI Pydantic issues map onto `{code, field_path, severity}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    pub range: Range,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_path: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionItem {
    pub label: String,
    pub detail: Option<String>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
    /// What an editor shows beside the label, in the list (LSP
    /// `labelDetails.description`): a vocabulary value's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_detail: Option<String>,
    /// The text an editor filters the item by, when it is more than the
    /// label: a vocabulary value with its name and aliases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_text: Option<String>,
}

impl CompletionItem {
    pub fn new(label: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: None,
            kind: kind.into(),
            documentation: None,
            label_detail: None,
            filter_text: None,
        }
    }

    /// The item with `label_detail` shown beside its label.
    pub fn with_label_detail(mut self, label_detail: impl Into<String>) -> Self {
        self.label_detail = Some(label_detail.into());
        self
    }

    /// The item with `filter_text` to filter it by.
    pub fn with_filter_text(mut self, filter_text: impl Into<String>) -> Self {
        self.filter_text = Some(filter_text.into());
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_docs(mut self, documentation: impl Into<String>) -> Self {
        self.documentation = Some(documentation.into());
        self
    }
}

/// LSP `textDocument/signatureHelp` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHelp {
    pub signatures: Vec<SignatureInformation>,
    pub active_signature: u32,
    pub active_parameter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureInformation {
    pub label: String,
    pub documentation: Option<String>,
    pub parameters: Vec<ParameterInformation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterInformation {
    pub label: String,
    pub documentation: Option<String>,
}

impl Diagnostic {
    pub fn error(code: impl Into<String>, message: impl Into<String>, range: Range) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Error,
            message: message.into(),
            range,
            field_path: None,
            suggestion: None,
            object_uuid: None,
            object_type: None,
        }
    }

    pub fn warning(code: impl Into<String>, message: impl Into<String>, range: Range) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Warning,
            message: message.into(),
            range,
            field_path: None,
            suggestion: None,
            object_uuid: None,
            object_type: None,
        }
    }

    /// A finding that is worth knowing and never wrong: an optional field
    /// left out, say. Hosts show it without counting it as a problem.
    pub fn information(code: impl Into<String>, message: impl Into<String>, range: Range) -> Self {
        Self {
            severity: Severity::Information,
            ..Self::warning(code, message, range)
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_field_path(mut self, path: Vec<String>) -> Self {
        self.field_path = Some(path);
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}

pub mod catalog;
pub mod datasets;
pub mod duration;
pub mod falco;
pub mod ids;
pub mod json;
pub mod node;
pub mod suggest;
pub mod yara;

/// Well-known diagnostic codes. Extra query diagnostics are allowed.
pub mod codes {
    /// Declares every code once: its constant (with its doc comment), its
    /// entry in [`ALL`] and its sentence in [`describe`] (#1960).
    macro_rules! codes {
        ($($(#[$meta:meta])* $name:ident = $code:literal => $text:literal;)*) => {
            $($(#[$meta])* pub const $name: &str = $code;)*

            /// Every code above, in declaration order.
            pub const ALL: &[&str] = &[$($name),*];

            /// One sentence on what a code means, for hosts that explain a
            /// diagnostic (`opentide explain <code>`). `None` for a code this
            /// engine does not emit.
            pub fn describe(code: &str) -> Option<&'static str> {
                match code {
                    $($code => Some($text),)*
                    _ => None,
                }
            }
        };
    }

    codes! {
        SCHEMA_VALIDATION = "schema_validation"
            => "A Tide object does not match its schema: a required field is missing, or a value has the wrong shape.";
        VOCAB_UNKNOWN = "vocab_unknown" => "A value is not in the vocabulary its field draws from.";
        INVALID_UUID = "invalid_uuid" => "An object id is not a version 4 UUID.";
        DUPLICATE_ID = "duplicate_id" => "Two object files carry the same UUID.";
        INVALID_REF = "invalid_ref" => "A reference names an object the workspace does not have.";
        CHAINING_RELATION_UNKNOWN = "chaining_relation_unknown"
            => "A threat chaining relation is not in the chaining_relations vocabulary.";
        DEPRECATED_FIELD = "deprecated_field" => "The field is deprecated in its schema revision.";
        KQL_CONTROL_COMMAND_UNSUPPORTED = "kql_control_command_unsupported"
            => "A KQL control command (.show, .create, ...) is not a detection query; rules cannot run it.";
        KQL_UNKNOWN_OPERATOR = "kql_unknown_operator"
            => "The KQL tabular operator is not one Kusto knows.";
        KQL_UNKNOWN_FUNCTION = "kql_unknown_function"
            => "The KQL function is not in the Kusto function catalog.";
        KQL_DEPRECATED_FUNCTION = "kql_deprecated_function"
            => "The KQL function is a deprecated alias; Microsoft Learn names its replacement.";
        KQL_DEPRECATED_OPERATOR = "kql_deprecated_operator"
            => "The KQL scalar operator is a legacy spelling (containscs); use the current name (contains_cs).";
        KQL_UNKNOWN_TABLE = "kql_unknown_table"
            => "The table is neither one the engine knows for the platform nor one the workspace declares in visibility.toml: a warning under Sentinel, whose workspaces hold tables no catalog lists; an error under Defender's advanced hunting schema. Declaring it in visibility.toml makes it known.";
        KQL_TABLE_MISSPELT = "kql_table_misspelt"
            => "A KQL table is not one the engine knows or the workspace declares, but is a near miss of one that is (one edit for a name of up to seven characters, two for a longer one, and not a custom `_CL` table): most likely a typo.";
        KQL_RENDER_NOT_VALID = "kql_render_not_valid"
            => "render draws a chart; it has no effect in a detection rule.";
        KQL_PARSE_ERROR = "kql_parse_error" => "The KQL query does not parse.";
        KQL_WHERE_NOT_FIRST = "kql_where_not_first"
            => "A filter comes after a more expensive operator; filtering first scans fewer rows.";
        KQL_UNSCOPED_SEARCH = "kql_unscoped_search"
            => "search without a table scans every table in the workspace.";
        KQL_UNSCOPED_UNION = "kql_unscoped_union"
            => "union * or an unscoped union reads every table.";
        KQL_WILDCARD_TABLE = "kql_wildcard_table"
            => "A wildcard table name reads every matching table.";
        KQL_JOIN_SUMMARIZE_BEFORE_PROJECT = "kql_join_summarize_before_project"
            => "A `join` runs while the pipeline it sits in still carries every column, and a later `project` would have narrowed it.";
        /// A `//` comment in a query that YAML folds into one line, so the
        /// comment swallows the lines after it.
        QUERY_FOLDED_COMMENT = "query_folded_comment"
            => "A `//` comment in a query that YAML folds into one line comments out the lines after it.";
        SPL_UNKNOWN_COMMAND = "spl_unknown_command"
            => "The SPL command is not in the Splunk Search Reference or a catalogued app such as MLTK: a warning, since an app on the search head can add commands, or an error when the name is one edit from a known command.";
        SPL_PARSE_ERROR = "spl_parse_error" => "The SPL search does not parse.";
        SPL_WILDCARD = "spl_wildcard"
            => "A leading or mid-token wildcard in a base search that nothing else narrows (no index, sourcetype, source, host, TERM() or macro) cannot use the index and scans every event.";
        SPL_LEADING_NOT = "spl_leading_not"
            => "A base search that starts with NOT scans every event before excluding any.";
        SPL_SUBSEARCH_TRUNCATION = "spl_subsearch_truncation"
            => "A subsearch is silently truncated at its result or time limit.";
        /// `==`, `<>`, `=>`, `=<`, `!~` or `=~` in a search clause.
        SPL_SEARCH_OPERATOR = "spl_search_operator"
            => "A search clause compares with an operator search does not have (`==`, `<>`, `=>`, `=<`, `!~`): Splunk accepts it but the comparison never matches, or `=~`, which compares with a value that starts with `~`.";
        /// A command Splunk parses with no arguments, where it does nothing,
        /// returns no results or fails at run time.
        SPL_EMPTY_COMMAND = "spl_empty_command"
            => "A command with no arguments: Splunk runs it, but it does nothing, returns no results, or fails at run time.";
        /// A trailing `|` with no command, which Splunk ignores.
        SPL_EMPTY_STAGE = "spl_empty_stage" => "A trailing | with no command; Splunk ignores it.";
        /// The query starts with a command name but no `|`, so Splunk searches
        /// for the word.
        SPL_COMMAND_WITHOUT_PIPE = "spl_command_without_pipe"
            => "The query starts with a command name but no |, so Splunk searches for the word instead of running the command.";
        ESQL_PARSE_ERROR = "esql_parse_error" => "The ES|QL query does not parse.";
        ESQL_UNKNOWN_COMMAND = "esql_unknown_command"
            => "The ES|QL command is not one Elasticsearch knows.";
        ESQL_UNKNOWN_FUNCTION = "esql_unknown_function"
            => "The ES|QL function is not in the Elasticsearch function catalog.";
        ESQL_UNAVAILABLE = "esql_unavailable"
            => "The command, function or form is missing or in preview on a targeted stack version.";
        ESQL_METADATA_ID = "esql_metadata_id"
            => "A non-aggregating ES|QL rule query has no METADATA _id, so alerts cannot be deduplicated.";
        EQL_PARSE_ERROR = "eql_parse_error" => "The EQL query does not parse.";
        EQL_UNKNOWN_FUNCTION = "eql_unknown_function"
            => "The EQL function is not in the Elasticsearch function catalog.";
        EQL_UNSUPPORTED = "eql_unsupported"
            => "Elasticsearch EQL does not support this construct (pipes, relationships, ...).";
        EQL_MAXSPAN_UNIT = "eql_maxspan_unit"
            => "A sequence maxspan uses a unit Elasticsearch does not accept.";
        EQL_MAXSPAN_WINDOW = "eql_maxspan_window"
            => "A sequence maxspan is longer than the rule's interval plus lookback, so the rule cannot see whole sequences.";
        EQL_MAXSPAN_LOOKBACK = "eql_maxspan_lookback"
            => "A sequence maxspan is longer than the rule's lookback.";
        EQL_FUNCTION_ARITY = "eql_function_arity"
            => "An EQL function is called with the wrong number of arguments.";
        EQL_CASE_SENSITIVE = "eql_case_sensitive"
            => "The comparison is case-sensitive; the case-insensitive form may be meant.";
        EQL_LITERAL_WILDCARD = "eql_literal_wildcard"
            => "A wildcard character is compared literally; use : or like for a pattern.";
        EQL_NESTED_COMMENT = "eql_nested_comment"
            => "Elasticsearch nests /* */ comments; the comment ends later than it looks.";
        EQL_EXPRESSION_DEPTH = "eql_expression_depth"
            => "The expression nests deeper than Elasticsearch accepts.";
        EQL_ARGUMENT_TYPE = "eql_argument_type"
            => "A literal has a type the EQL verifier rejects in this position.";
        EQL_FIELD_COMPARISON = "eql_field_comparison"
            => "Both sides of a comparison read fields, which EQL does not support.";
        EQL_RUNS_IGNORED = "eql_runs_ignored"
            => "A decimal runs count is truncated by Elasticsearch.";
        EQL_UNTIL_TERM = "eql_until_term"
            => "runs or a missing-event term ![ ] is not allowed on until.";
        EQL_REGEX = "eql_regex" => "The regular expression trips a Lucene RegExp pitfall.";
        EQL_MAXSPAN_MISSING = "eql_maxspan_missing"
            => "A sequence has no maxspan, so partial sequences are held until they expire.";
        KUERY_PARSE_ERROR = "kuery_parse_error" => "The Kibana KQL (kuery) query does not parse.";
        KUERY_LUCENE_SYNTAX = "kuery_lucene_syntax"
            => "Lucene syntax inside a Kibana KQL (kuery) query.";
        KUERY_ESCAPE = "kuery_escape" => "A character needs escaping in Kibana KQL (kuery).";
        KUERY_QUOTED_WILDCARD = "kuery_quoted_wildcard"
            => "A wildcard inside quotes is a literal * in Kibana KQL (kuery).";
        LUCENE_PARSE_ERROR = "lucene_parse_error" => "The Lucene query does not parse.";
        LUCENE_LOWERCASE_OPERATOR = "lucene_lowercase_operator"
            => "Lucene operators are upper case; lowercase and/or/not are search terms.";
        LUCENE_MIXED_OPERATORS = "lucene_mixed_operators"
            => "AND and OR mixed without parentheses do not bind as they read.";
        LUCENE_ESCAPE = "lucene_escape" => "A character needs escaping in Lucene.";
        LUCENE_KUERY_SYNTAX = "lucene_kuery_syntax"
            => "Kibana KQL (kuery) syntax inside a Lucene query.";
        LUCENE_REGEXP = "lucene_regexp"
            => "The /regexp/ body is rejected by, or too costly for, Lucene's RegExp.";
        LUCENE_FUZZY = "lucene_fuzzy"
            => "Elasticsearch accepts only 0, 1, 2 or AUTO as a fuzziness.";
        LUCENE_RANGE_OPERATOR = "lucene_range_operator"
            => "f:> 10 searches f for the text >; the value must follow the operator.";
        LUCENE_UNESCAPED_SLASH = "lucene_unescaped_slash"
            => "An unescaped / starts a regular expression.";
        LUCENE_BARE_TERM = "lucene_bare_term" => "A term with no field searches every field.";
        LUCENE_LOOKS_LIKE_KUERY = "lucene_looks_like_kuery"
            => "The query reads like Kibana KQL (kuery); language: kuery may be meant.";
        LUCENE_ELASTICSEARCH_ONLY = "lucene_elasticsearch_only"
            => "The syntax works in Elasticsearch but not in Carbon Black Cloud.";
        // The Graylog dialect of Lucene (graylog-1.0, "Query diagnostics").
        GRAYLOG_LEADING_WILDCARD = "graylog_leading_wildcard"
            => "A Graylog query term starts with `*` or `?`: Graylog refuses leading wildcards unless the server allows them; a regex with a leading `.*` is the portable form.";
        GRAYLOG_REGEX_UNSUPPORTED = "graylog_regex_unsupported"
            => "A Graylog regex uses an inline flag, a `(?…)` group, `\\b`, `\\B`, a lookaround, or a backreference, which Lucene's regex engine does not have: Graylog matches nothing or rejects the query.";
        GRAYLOG_REGEX_OPERATOR = "graylog_regex_operator"
            => "A Graylog regex holds an unescaped `#`, `&`, `@`, `~`, `<`, or `>`, which Lucene reads as a regex operator, not the character.";
        GRAYLOG_REGEX_QUOTE = "graylog_regex_quote"
            => "A Graylog regex holds an unescaped `\"`, which Lucene reads as a quoted literal, not the character: escape it as `\\\"`.";
        GRAYLOG_OPEN_RANGE = "graylog_open_range"
            => "A Graylog range has `*` as a bound (`[1 TO *]`, `{* TO 5}`). Graylog's query validator refuses it, so deploy cannot save the definition: write `field:>=1` or `field:<5`.";
        GRAYLOG_DOUBLE_BACKSLASH = "graylog_double_backslash"
            => "A Graylog query holds four backslashes in a row: `\\\\` is already one literal backslash, so `\\\\\\\\` matches two.";
        GRAYLOG_ANALYZED_FIELD = "graylog_analyzed_field"
            => "A regex, wildcard, or range applies to Graylog's analysed `message` or `full_message` field, so it matches single lower-cased tokens, never the whole value.";
        KUERY_QUESTION_MARK = "kuery_question_mark"
            => "? is a literal in Kibana KQL (kuery), not a single-character wildcard.";
        KUERY_FREE_TEXT = "kuery_free_text" => "A value with no field searches every field.";
        KUERY_LOOKS_LIKE_LUCENE = "kuery_looks_like_lucene"
            => "The query reads like Lucene; language: lucene may be meant.";
        KUERY_RANGE_TYPE = "kuery_range_type" => "A range compares a value of the wrong type.";
        // elastic-1.0 Advisories on the block itself (specifications#57).
        LOOKBACK_ZERO = "lookback_zero"
            => "The Elastic rule's lookback is zero, so events that arrive late are missed.";
        LOOKBACK_LONG = "lookback_long"
            => "The Elastic rule's lookback exceeds an hour; it is added to the interval, not the whole window.";
        THRESHOLD_LOOKBACK = "threshold_lookback"
            => "A threshold rule's lookback exceeds its interval, so windows overlap and alerts repeat.";
        RISK_BAND = "risk_band" => "The risk score is outside the band of the rule's severity.";
        TECHNIQUE_NOT_ENTERPRISE = "technique_not_enterprise"
            => "The ATT&CK technique is not in the Enterprise matrix that Elastic maps.";
        DEFENDER_OUTPUT_COLUMNS = "defender_output_columns"
            => "A Defender custom detection must return the columns Defender requires.";
        /// `::type` names no Elasticsearch release can cast to.
        ESQL_UNKNOWN_TYPE = "esql_unknown_type"
            => "The ::type cast names a type no Elasticsearch release can cast to.";
        ESQL_GROUP_BY_COLUMN = "esql_group_by_column"
            => "A suppression group_by field is not a column the ES|QL query returns.";
        EQL_NOT_BOOLEAN = "eql_not_boolean" => "A string or number literal is used as a condition.";
        ESQL_PATTERN = "esql_pattern"
            => "A LIKE or RLIKE pattern escapes or matches differently than it reads.";
        ESQL_EXPRESSION_DEPTH = "esql_expression_depth"
            => "The expression nests deeper than Elasticsearch accepts.";
        // Dataset knowledge (#110): known schemas, then visibility.toml, then warn.
        KQL_TABLE_NOT_DECLARED = "kql_table_not_declared"
            => "The engine knows the table, but the workspace, which declares its tables for the platform in visibility.toml, does not declare it.";
        KQL_UNKNOWN_COLUMN = "kql_unknown_column"
            => "The column is not in the documented schema of the table or ASIM parser it comes from, or in the columns visibility.toml declares for the table.";
        KQL_TYPE_MISMATCH = "kql_type_mismatch"
            => "The operator cannot apply to the column's documented or declared type.";
        SPL_UNKNOWN_DATAMODEL = "spl_unknown_datamodel"
            => "The CIM data model or dataset is not one Splunk CIM defines.";
        SPL_UNKNOWN_DATAMODEL_FIELD = "spl_unknown_datamodel_field"
            => "The field is not in the CIM data model the search reads.";
        SPL_DATASET_NOT_DECLARED = "spl_dataset_not_declared"
            => "The sourcetype is not one the workspace's Splunk log sources name in visibility.toml.";
        ECS_TYPE_MISMATCH = "ecs_type_mismatch"
            => "The operation cannot apply to the field's type, from ECS or from the columns visibility.toml declares for the index.";
        ECS_UNKNOWN_FIELD = "ecs_unknown_field"
            => "The field is not in the Elastic Common Schema, on indices that use it, nor declared for the index in visibility.toml; ECS allows custom fields.";
        ELASTIC_DATASET_NOT_DECLARED = "elastic_dataset_not_declared"
            => "The index pattern is not one the workspace's elastic log sources name, or cover, in visibility.toml.";
        /// A Carbon Black Cloud query field one edit or two from a catalog field
        /// (#162).
        CBC_UNKNOWN_FIELD = "cbc_unknown_field"
            => "A field in a Carbon Black Cloud query is a near miss of a process search field.";
        /// The host's configuration checker failed on a configuration file.
        CONFIG_CHECK_FAILED = "config_check_failed"
            => "opentide could not check this configuration file; the message says why. Its other findings are missing.";
        // Falco conditions (sysdig-1.0, "Falco language").
        FALCO_PARSE_ERROR = "falco_parse_error" => "The Falco condition does not parse.";
        FALCO_UNKNOWN_FIELD = "falco_unknown_field"
            => "The field is not one Falco or its plugins define for the rule's event source; a plugin the engine does not know may add it.";
        FALCO_UNKNOWN_MACRO = "falco_unknown_macro"
            => "The name is not a macro of the block or of the Falco default rules; the tenant may define it, as Sysdig does for its managed macros.";
        FALCO_UNKNOWN_LIST = "falco_unknown_list"
            => "The name after a list operator, without parentheses, is not a list of the block or of the Falco default rules, so it is compared as a single value.";
        FALCO_MISPLACED_LIST = "falco_misplaced_list"
            => "A list is used where its expansion breaks the condition: as a macro, or as a single value; a list belongs inside a value list, `in (name)`.";
        FALCO_FIELD_ARGUMENT = "falco_field_argument"
            => "A known Falco field is used with an argument it refuses, or without one it requires (libsinsp's field rules: `proc.aname[N]` takes an index, `evt.arg.NAME` an event argument).";
        FALCO_OPERATOR_TYPE = "falco_operator_type"
            => "The operator does not apply to the field's type (libsinsp `flt_is_comparable`); Falco refuses to load the rule.";
        FALCO_VALUE_TYPE = "falco_value_type"
            => "The value cannot be parsed as the field's type (a number, `true` or `false`, an IP address or network, a hex string for `bcontains`); Falco refuses to load the rule.";
        FALCO_TRANSFORMER = "falco_transformer"
            => "A field transformer cannot apply here: the field's type, a field that refuses transformers, or the arguments of `join`, `concat`, or `getopt`.";
        FALCO_RHS_FIELD = "falco_rhs_field"
            => "A field cannot be compared with another field here (`val(...)` or a transformer on the right): not with `pmatch` or `regex`, not on networks, not on fields that refuse it, and only between fields of the same type.";
        FALCO_INVALID_REGEX = "falco_invalid_regex" => "The `regex` pattern does not compile.";
        FALCO_REGEX_SIMPLE = "falco_regex_simple"
            => "A `regex` check a plain operator (`=`, `contains`, `startswith`, `endswith`) could make, which libsinsp warns about: regex is the slowest check.";
        FALCO_FIELD_AS_VALUE = "falco_field_as_value"
            => "A constant value that is a field name: compare with `val(field)` to read the field.";
        FALCO_TRANSFORMER_AS_VALUE = "falco_transformer_as_value"
            => "A constant value that looks like a transformer call, compared as text.";
        FALCO_DEPRECATED_FIELD = "falco_deprecated_field"
            => "A field Falco deprecates (`evt.dir`, `evt.latency`): it no longer carries the value it used to.";
        FALCO_UNSAFE_NA_CHECK = "falco_unsafe_na_check"
            => "A `ka.` or `jevt.` field compared with `<NA>`, which Falco warns about: the field may hold that text.";
        FALCO_NO_EVTTYPE = "falco_no_evttype"
            => "The rule cannot be narrowed to a few event types (`evt.type`), so it runs on every event; Falco and Sysdig warn about the performance penalty.";
        FALCO_OUTPUT_SYNTAX = "falco_output_syntax"
            => "The output template does not format: a `%` at the end, a length with no field, or a token that is no field or transformer.";
        FALCO_NEWER_SYNTAX = "falco_newer_syntax"
            => "Syntax that only recent libsinsp releases parse (operator modifiers, `join`, `concat`, `getopt`, transformer arguments); an older Falco or Sysdig agent refuses the rule.";
        FALCO_EXCEPTION = "falco_exception"
            => "A rule exception Falco refuses: comparison operators, field and value counts, or a value the field's type cannot hold.";
        FALCO_UNKNOWN_EVENT = "falco_unknown_event"
            => "The event type is not in the driver's event table nor a syscall name; libsinsp refuses it.";
        FALCO_UNKNOWN_SOURCE = "falco_unknown_source"
            => "The event source is not one Falco or its published plugins define, so its fields are not checked.";
        FALCO_APPEND_CONDITION = "falco_append_condition"
            => "A tuning's condition is appended to the tuned rule's condition and must start with `and` or `or`; a new rule's condition must not.";
        FALCO_UNKNOWN_RULE = "falco_unknown_rule"
            => "A tuning (`append_to_rule`) names a rule the Falco default rules do not define: Falco refuses the append, and on Sysdig the tenant must have that rule.";
        // Sysdig block constraint codes (sysdig-1.0, Constraints), as opentide names them.
        SYSDIG_RULE_SHAPE = "sysdig_rule_shape"
            => "A Sysdig block is a new rule with a non-blank `condition`, or a tuning (`append_to_rule`) that appends a condition, exceptions, or both.";
        SYSDIG_TUNING_KEYS = "sysdig_tuning_keys"
            => "A tuning (`append_to_rule`) inherits `output`, `priority`, `policies`, `source`, and `name` from the rule it tunes, so it must not set them.";
        SYSDIG_PRIORITY = "sysdig_priority"
            => "`priority` is not one of Falco's eight priorities (or `INFO`), compared case-insensitively.";
        SYSDIG_SOURCE = "sysdig_source"
            => "`source` is not an event source name (`[a-z][a-z0-9_]*`).";
        SYSDIG_EXCEPTION_SHAPE = "sysdig_exception_shape"
            => "An exception's fields, comps, and values do not have a shape Falco's rule loader accepts (`validate_exception_info`).";
        SYSDIG_DEFINITION_NAME = "sysdig_definition_name"
            => "A block macro or list name is not `[A-Za-z_][A-Za-z0-9_]*`, or is a Falco operator or keyword.";
        SYSDIG_DEFINITION_DUPLICATE = "sysdig_definition_duplicate"
            => "A name is defined more than once across the block's macros and lists.";
        SYSDIG_DEFINITION_ORDER = "sysdig_definition_order"
            => "A block macro uses itself or a macro defined after it: Falco gives a macro no view of itself or later macros, and refuses it as an undefined macro.";
        SYSDIG_LIST_IN_VALUE = "sysdig_list_in_value"
            => "A block list name appears in an exception value where Falco's expansion would not produce a value list.";
        SYSDIG_LIST_SELF_REFERENCE = "sysdig_list_self_reference"
            => "A block list names itself: Falco keeps the name as a literal item, which on Sysdig resolves against a tenant list of that name, not this one.";
        // Bitdefender GravityZone block codes (bitdefender-1.0, Constraints and
        // Advisories), as opentide names them.
        BITDEFENDER_RULE_KIND = "bitdefender_rule_kind"
            => "A Bitdefender block sets exactly one of `detection` (a Basic rule) and `yara` (a YARA rule).";
        BITDEFENDER_TARGET = "bitdefender_target"
            => "`detection.target` is not a GravityZone detection target; the exclusion-only targets `flow` and `bitbucket repository` are refused.";
        BITDEFENDER_CRITERION_SHAPE = "bitdefender_criterion_shape"
            => "A criterion has a `field` and exactly one of `is`, `contains`, and `any`; `any` is a non-empty list, `is` and `contains` one value.";
        BITDEFENDER_CRITERION_FIELD = "bitdefender_criterion_field"
            => "The criterion's field is not a field of the rule's target in the GravityZone criteria catalogue (a warning for a target bitdefender-1.0 does not list).";
        BITDEFENDER_CRITERION_RELATION = "bitdefender_criterion_relation"
            => "The field does not take this relation: enumerated fields take `is` or `any` (some only `is`), and hashes take no `contains`.";
        BITDEFENDER_CRITERION_VALUE = "bitdefender_criterion_value"
            => "The value is not one of the field's enumerated values, or a port is not an integer from 0 to 65535.";
        BITDEFENDER_CRITERIA_COMBINATION = "bitdefender_criteria_combination"
            => "The criteria break a GravityZone pairing rule: EDR-only and XDR-only criteria mixed, a field without the field it needs, two incompatible fields, or `alert` beside an operation criterion.";
        BITDEFENDER_ACTION_SCOPE = "bitdefender_action_scope"
            => "An automatic action is unknown, has a value it does not take, or is not allowed for the rule's kind or target.";
        BITDEFENDER_TARGETS_SHAPE = "bitdefender_targets_shape"
            => "`targets` sets one of `endpoint_tags` and `companies`, as a non-empty list with no blank alias.";
        BITDEFENDER_SEVERITY = "bitdefender_severity"
            => "`severity` is not `Low`, `Medium`, or `High`.";
        BITDEFENDER_REGISTRY_FULL_HIVE = "bitdefender_registry_full_hive"
            => "A `Registry.Key` value starts with a full hive name: GravityZone accepts it, and the rule never triggers. Write `HKLM`, `HKCU`, `HKU`, `HKCR`, `HKCC`, or `HKLU`.";
        BITDEFENDER_CONTAINS_NO_WILDCARD = "bitdefender_contains_no_wildcard"
            => "A `contains` value has neither `*` nor `?`, so GravityZone matches it as written; the author most likely meant `*value*`.";
        BITDEFENDER_SEVERITY_COLLAPSED = "bitdefender_severity_collapsed"
            => "`response.alert_severity` is `Critical` or `Informational` and the block sets no `severity`: GravityZone has three levels, so it is sent as `High` or `Low`.";
        // Graylog block codes (graylog-1.0, Constraints and Advisories), as
        // opentide names them.
        GRAYLOG_QUERY_BLANK = "graylog_query_blank"
            => "A Graylog block's `query` is missing or blank.";
        GRAYLOG_LIST_SHAPE = "graylog_list_shape"
            => "A Graylog list field is not one string or a list of distinct non-blank strings.";
        GRAYLOG_SCHEDULE = "graylog_schedule"
            => "A Graylog `schedule` sets both `every` and `cron`, a duration that is not greater than zero, a cron that is not a 6- or 7-field Quartz expression, an unknown time zone, or `cron` without `window`.";
        GRAYLOG_EVENT_LIMIT = "graylog_event_limit"
            => "A Graylog `event_limit` is not an integer from 1 to 1,000, or is set on an aggregation.";
        GRAYLOG_AGGREGATION = "graylog_aggregation"
            => "A Graylog `aggregation.condition` is missing, does not parse under the condition grammar, or calls a function with the wrong arguments.";
        GRAYLOG_EVENT_FIELD = "graylog_event_field"
            => "A Graylog event field name is not `[A-Za-z0-9_.@-]+`, or its value is not a field name, a `${…}` template, `{template}`, or `{lookup}`.";
        GRAYLOG_EVENT_KEY = "graylog_event_key"
            => "A Graylog `event_key` item is not an `event_fields` name.";
        GRAYLOG_PRIORITY = "graylog_priority"
            => "A Graylog `priority` is not `Informational`, `Low`, `Medium`, `High`, or `Critical`.";
        GRAYLOG_FIELD_NAME = "graylog_field_name"
            => "A Graylog `aggregation.group_by` item is not a field name (`[A-Za-z0-9_.@-]+`).";
        GRAYLOG_OVERLAPPING_WINDOW = "graylog_overlapping_window"
            => "A Graylog filter searches a `window` longer than it runs `every`, so each message alerts once per overlapping run.";
        GRAYLOG_ALL_STREAMS = "graylog_all_streams"
            => "A Graylog definition names no stream, so it searches every stream the token's user can read.";

        // CrowdStrike Query Language (Falcon LogScale, Next-Gen SIEM).
        CQL_PARSE_ERROR = "cql_parse_error"
            => "The CrowdStrike Query Language (CQL) query does not parse.";
        CQL_UNKNOWN_FUNCTION = "cql_unknown_function"
            => "No CQL function has this name; function names are matched without regard to case.";
        CQL_REMOVED_FUNCTION = "cql_removed_function"
            => "The CQL function was removed from LogScale and Next-Gen SIEM no longer runs it.";
        CQL_DEPRECATED_FUNCTION = "cql_deprecated_function"
            => "CrowdStrike's reference marks the CQL function deprecated.";
        CQL_UNKNOWN_PARAMETER = "cql_unknown_parameter"
            => "The CQL function has no parameter with this name.";
        CQL_DUPLICATE_PARAMETER = "cql_duplicate_parameter"
            => "A CQL function parameter is given more than once.";
        CQL_UNNAMED_ARGUMENT = "cql_unnamed_argument"
            => "A CQL function gets an argument without a name that it cannot take: a second one, or one when every parameter needs its name.";
        CQL_MISSING_PARAMETER = "cql_missing_parameter"
            => "A CQL function call leaves out a required parameter.";
        CQL_PARAMETER_VALUE = "cql_parameter_value"
            => "A literal CQL argument is not one of the parameter's allowed values, or is outside its bounds.";
        CQL_REGEX_FLAG = "cql_regex_flag"
            => "A CQL regex literal has a flag other than d, g, i, m or F.";
        CQL_STRING_ESCAPE = "cql_string_escape"
            => "A CQL string has an escape LogScale does not translate; it keeps the backslash and the character.";
        CQL_FREE_TEXT_AFTER_AGGREGATE = "cql_free_text_after_aggregate"
            => "A CQL free-text filter comes after the first aggregate function, which LogScale refuses since 1.190.";
        CQL_ASSIGNMENT_AS = "cql_assignment_as"
            => "A CQL assignment names the output field and the function's as= parameter names it again.";
        CQL_LINK_OUTSIDE_CORRELATE = "cql_link_outside_correlate"
            => "The CQL link operator <=> appears outside the queries of correlate(), the only place it links fields.";
        CQL_UNKNOWN_EVENT = "cql_unknown_event"
            => "The #event_simpleName value is not a Falcon sensor event the engine knows.";
        CQL_EVENT_FUNCTION_AFTER_AGGREGATE = "cql_event_function_after_aggregate"
            => "A CQL eventSize(), eventInternals() or eventFieldCount() call comes after the first aggregate function, which LogScale refuses since 1.190.";
        CQL_CORRELATE_PLACEMENT = "cql_correlate_placement"
            => "CQL correlate() stands where its reference forbids: after an aggregate or a source function, inside another function's arguments, or with an aggregate in its queries.";
        CQL_MATCH_GUARD = "cql_match_guard"
            => "A CQL match guard is an aggregate function; a guard must be a filter.";
        CQL_REGEX_GROUP_UNDER_OR = "cql_regex_group_under_or"
            => "A CQL regex with named groups is an operand of or, where LogScale extracts none of its fields.";
        CQL_CORRELATE_AGGREGATE = "cql_correlate_aggregate"
            => "A Next-Gen SIEM correlation rule combines correlate() with another aggregate function, which CrowdStrike does not allow.";

        // YARA (yara-1.0, #165). Errors are what YARA-X 1.x refuses (#1225),
        // and yara_x_only_syntax what a profile refuses; the warnings are
        // yara_slow_pattern through yara_meta_missing. yara_x_incompatible is
        // retired (opentide-cli's `explain::RETIRED`).
        YARA_PARSE_ERROR = "yara_parse_error"
            => "The YARA signature does not parse as YARA-X 1.x reads it.";
        YARA_INCLUDE = "yara_include"
            => "A YARA signature uses an include directive, which no platform resolves: each API takes one text with no file system behind it.";
        YARA_SIGNATURE_ALIAS = "yara_signature_alias"
            => "A YARA signature is a YAML alias instead of text written out in its own block.";
        YARA_EMPTY_SIGNATURE = "yara_empty_signature"
            => "The YARA signature has no rule, or only private or global rules.";
        YARA_DUPLICATE_RULE = "yara_duplicate_rule"
            => "Two YARA rules in one signature have the same name.";
        YARA_DUPLICATE_STRING = "yara_duplicate_string"
            => "Two strings of one YARA rule have the same identifier.";
        YARA_DUPLICATE_TAG = "yara_duplicate_tag" => "A YARA rule repeats a tag.";
        YARA_UNDEFINED_STRING = "yara_undefined_string"
            => "A YARA condition names a string ($id, #id, @id, !id or $prefix*) that the rule does not define.";
        YARA_UNREFERENCED_STRING = "yara_unreferenced_string"
            => "A YARA string is never used in the condition, which YARA-X refuses unless the condition uses them.";
        YARA_UNDEFINED_IDENTIFIER = "yara_undefined_identifier"
            => "A YARA identifier is neither a rule defined earlier in the signature nor an imported module, or is used as YARA-X refuses: a module field called as a function, a module function named without a call, or `entrypoint`.";
        YARA_RULE_IDENTIFIER_CONFLICT = "yara_rule_identifier_conflict"
            => "A YARA rule is named like a keyword, a built-in or an imported module.";
        YARA_UNKNOWN_MODULE = "yara_unknown_module"
            => "A YARA import names a module opentide does not know: it knows YARA-X's default modules except vt, and refuses magic, which YARA-X does not build by default.";
        YARA_MODULE_NOT_IMPORTED = "yara_module_not_imported"
            => "A YARA module field or function is used without importing its module.";
        YARA_UNKNOWN_MODULE_MEMBER = "yara_unknown_module_member"
            => "The YARA module has no such field or function, or the function takes other arguments.";
        YARA_TYPE = "yara_type"
            => "A YARA operator or function is applied to a value of the wrong type.";
        YARA_REGEXP = "yara_regexp" => "A YARA regular expression is invalid.";
        YARA_HEX_STRING = "yara_hex_string"
            => "A YARA hex string is invalid: an odd number of nibbles, a bad jump, or unbalanced alternatives.";
        YARA_STRING_MODIFIER = "yara_string_modifier"
            => "YARA-X refuses this combination of YARA string modifiers, or an xor or base64 argument is out of range.";
        YARA_NUMBER_OUT_OF_RANGE = "yara_number_out_of_range"
            => "A YARA integer, size suffix, jump bound or string index is outside the range YARA-X accepts.";
        YARA_X_ONLY_SYNTAX = "yara_x_only_syntax"
            => "This YARA uses syntax only YARA-X has, and the platform profile has yara_x_syntax refused: the platform may not accept it.";
        YARA_SLOW_PATTERN = "yara_slow_pattern"
            => "libyara warns that this YARA string or loop may slow scanning down.";
        YARA_ENTRYPOINT_DEPRECATED = "yara_entrypoint_deprecated"
            => "entrypoint is deprecated in libyara and refused by YARA-X (yara_undefined_identifier); use pe.entry_point or elf.entry_point.";
        YARA_SUSPICIOUS_EXPRESSION = "yara_suspicious_expression"
            => "A YARA condition is invariant, unsatisfiable or not boolean, or compares an integer with a boolean.";
        YARA_MODULE_UNCONFIRMED = "yara_module_unconfirmed"
            => "The YARA module is known but not confirmed on the platform's agents.";
        YARA_META_MISSING = "yara_meta_missing"
            => "A non-private YARA rule lacks a meta key the platform profile recommends.";
        // The YARA profiles of harfanglab-1.0 (1.2) and bitdefender-1.0.
        HARFANGLAB_RULE_KIND = "harfanglab_rule_kind"
            => "A HarfangLab block sets both sigma and yara; a block is one kind.";
        HARFANGLAB_YARA_FORM = "harfanglab_yara_form"
            => "A HarfangLab yara object sets signature together with decomposed keys (meta, strings, condition or imports).";
        HARFANGLAB_YARA_SECTION_HEADER = "harfanglab_yara_section_header"
            => "A decomposed HarfangLab YARA fragment contains a strings:, condition: or rule header, which deploy writes itself.";
        HARFANGLAB_YARA_IMPORT = "harfanglab_yara_import"
            => "A decomposed HarfangLab YARA imports entry is not a module the YARA language knows.";
        HARFANGLAB_YARA_RULE_NAME = "harfanglab_yara_rule_name"
            => "The YARA rule name deploy derives from the rule name is a YARA keyword or keeps a character other than an ASCII letter, digit or underscore.";
        HARFANGLAB_YARA_CONTEXT = "harfanglab_yara_context"
            => "A HarfangLab YARA rule's meta context is not a comma-joined list, without blanks, of file, memory, file.pe, file.elf and file.macho.";
        BITDEFENDER_YARA_ASCII = "bitdefender_yara_ascii"
            => "A Bitdefender YARA signature holds a character that is not ASCII.";
        BITDEFENDER_YARA_SIZE = "bitdefender_yara_size"
            => "A Bitdefender YARA signature is longer than 30,000 characters.";

        // The Exabeam Query Language (specifications exabeam-1.0, language).
        EXABEAM_PARSE_ERROR = "exabeam_parse_error"
            => "The Exabeam query does not parse: an unterminated string, an unbalanced bracket, a missing operand, an empty sequence query, or a comparison with a non-number.";
        EXABEAM_IMPLICIT_OPERATOR = "exabeam_implicit_operator"
            => "An Exabeam NOT stands between two terms with no AND or OR before it, which Exabeam calls invalid; write AND NOT or OR NOT.";
        EXABEAM_NOT_EQUAL = "exabeam_not_equal"
            => "Exabeam filters have no != operator; write NOT field:value.";
        EXABEAM_BARE_WILDCARD = "exabeam_bare_wildcard"
            => "A * alone is not an Exabeam query term.";
        EXABEAM_LEADING_SLASH = "exabeam_leading_slash" => "An Exabeam query cannot start with /.";
        EXABEAM_FREE_TEXT_SPECIAL = "exabeam_free_text_special"
            => "Unquoted Exabeam free text holds a character other than letters, digits, _, * and ?; put it in double quotes.";
        EXABEAM_UNKNOWN_FUNCTION = "exabeam_unknown_function"
            => "The call is not an Exabeam function: RGX, RGXi, WLD and WLDi in a filter, an aggregation or RGX_EXTRACT in SELECT.";
        EXABEAM_FUNCTION_ARITY = "exabeam_function_arity"
            => "An Exabeam function gets the wrong arguments: a filter function takes one string, an aggregation one field (* for COUNT only), RGX_EXTRACT an optional field and a pattern.";
        EXABEAM_REGEX = "exabeam_regex"
            => "The Exabeam regular expression is not valid RE2: a syntax error, a back-reference, look-around, an atomic group or a possessive quantifier.";
        EXABEAM_RANGE = "exabeam_range"
            => "The Exabeam range or CIDR block is invalid: a bound that is not a number, IPv4 address, datetime or *, mixed kinds, low above high, two open bounds, mismatched brackets, or a bad network.";
        EXABEAM_IPV6_RANGE = "exabeam_ipv6_range"
            => "An Exabeam range or CIDR block holds an IPv6 address; Exabeam ranges are IPv4 only.";
        EXABEAM_TIME_EXACT = "exabeam_time_exact"
            => "An Exabeam time field (time, approxLogTime, ingest_time, raw_log_time) is matched with an exact value; Search matches time with a range only.";
        EXABEAM_CONTEXT_TABLE_OR = "exabeam_context_table_or"
            => "An Exabeam context table lookup is under OR; lookups combine with AND or AND NOT only.";
        EXABEAM_CONTEXT_TABLE_LIMIT = "exabeam_context_table_limit"
            => "An Exabeam query has more than two context table lookups.";
        EXABEAM_ADVANCED_IN_RULE = "exabeam_advanced_in_rule"
            => "A correlation rule sequence query uses Exabeam's advanced operators (SELECT, WHERE, pipes and the rest), which are Search only.";
        EXABEAM_KEYWORD_CASE = "exabeam_keyword_case"
            => "An Exabeam clause keyword, aggregation or RGX_EXTRACT is in mixed case; write it all upper or all lower case.";
        EXABEAM_CLAUSE_ORDER = "exabeam_clause_order"
            => "Exabeam clauses are out of order, or one appears twice in a statement: SELECT, FROM, WHERE, AS, GROUP-BY, ORDER-BY, LIMIT.";
        EXABEAM_PIPE_LIMIT = "exabeam_pipe_limit" => "An Exabeam query has more than five pipes.";
        EXABEAM_RGX_EXTRACT_LIMIT = "exabeam_rgx_extract_limit"
            => "An Exabeam query has more than three RGX_EXTRACT calls.";
        EXABEAM_RESERVED_ALIAS = "exabeam_reserved_alias"
            => "An Exabeam AS name is one of the Search guide's reserved words.";
        EXABEAM_GROUP_BY_SELECT_STAR = "exabeam_group_by_select_star"
            => "An Exabeam GROUP-BY is combined with SELECT *.";
        EXABEAM_GROUP_BY_COLUMN = "exabeam_group_by_column"
            => "An Exabeam selected column is neither in GROUP-BY nor aggregated.";
        EXABEAM_FOREACH_CLAUSE = "exabeam_foreach_clause"
            => "An Exabeam FOREACH sub-query has GROUP-BY or ORDER-BY.";
        EXABEAM_FOREACH_REFERENCE = "exabeam_foreach_reference"
            => "An Exabeam @field reference is outside a FOREACH sub-query.";
        EXABEAM_FOREACH_POSITION = "exabeam_foreach_position"
            => "An Exabeam FOREACH is the first statement; it runs on the result of a preceding query.";
        EXABEAM_MIXED_BOOLEAN = "exabeam_mixed_boolean"
            => "Exabeam AND and OR are mixed at one level without parentheses; Exabeam does not document their precedence.";
        EXABEAM_IMPLICIT_AND = "exabeam_implicit_and"
            => "Two Exabeam terms, not both free text, stand side by side and are read as AND; write AND.";
        EXABEAM_SINGLE_GROUP = "exabeam_single_group"
            => "Parentheses hold a single Exabeam expression, which the Search guide calls an error; drop them.";
        EXABEAM_PIPE_MISUSE = "exabeam_pipe_misuse"
            => "An Exabeam statement after a pipe follows no SELECT or uses none of its columns; write one query with AND or WHERE.";
        EXABEAM_WILDCARD_IN_PHRASE = "exabeam_wildcard_in_phrase"
            => "A quoted Exabeam value with a space holds * or ?, which Exabeam does not expand inside a phrase.";
        EXABEAM_UNQUOTED_VALUE = "exabeam_unquoted_value"
            => "An Exabeam field value is a bare word that is not a number, boolean, null, IP address or @field; Exabeam documents string values in double quotes.";
        EXABEAM_LEGACY_REGEX = "exabeam_legacy_regex"
            => "An Exabeam value between slashes may be read as a regular expression; write RGX(\"...\") for a pattern, or drop the slashes for a path.";
        EXABEAM_UNKNOWN_FIELD = "exabeam_unknown_field"
            => "The field is not in Exabeam's Common Information Model, a platform field, a c_ or m_ field, or an AS name defined earlier in the query; a tenant's parsers may still define it.";
        EXABEAM_STRING_FIELD_NUMBER = "exabeam_string_field_number"
            => "An unquoted number is matched against a field the Exabeam Common Information Model types as a string; Exabeam requires the number in double quotes.";
        EXABEAM_UNKNOWN_VALUE = "exabeam_unknown_value"
            => "An Exabeam activity_type, subject or outcome value is not one the Common Information Model lists; a tenant's parsers may still emit it.";
        // Exabeam block constraint codes and advisories (platform exabeam-1.0).
        EXABEAM_SEQUENCES = "exabeam_sequences"
            => "An Exabeam block's sequences is not a non-empty list of sequences, each with a non-blank query.";
        EXABEAM_CORRELATION = "exabeam_correlation"
            => "An Exabeam block has two or more sequences without correlation, one sequence with it, or a correlation that is not within and group_by.";
        EXABEAM_THRESHOLD_FUNCTION = "exabeam_threshold_function"
            => "An Exabeam threshold function is not count, unique_count, value, max, min, sum or average, or its field is blank or missing.";
        EXABEAM_THRESHOLD_OPERATOR = "exabeam_threshold_operator"
            => "An Exabeam threshold operator is not allowed with its function: more_than or less_than, in or not_in for value.";
        EXABEAM_THRESHOLD_VALUE = "exabeam_threshold_value"
            => "An Exabeam threshold value does not have the shape its operator takes, or count and unique_count compare with a non-integer.";
        EXABEAM_GROUP_BY = "exabeam_group_by"
            => "An Exabeam group_by is not a list of one to three distinct non-blank fields (correlation.group_by may be empty).";
        EXABEAM_DURATION = "exabeam_duration"
            => "An Exabeam duration is not a whole number and a unit its field allows, or delay is outside 7 to 180 minutes.";
        EXABEAM_SEVERITY = "exabeam_severity"
            => "An Exabeam severity is not none, low, medium, high or critical.";
        EXABEAM_OUTCOME = "exabeam_outcome" => "An Exabeam outcome is not alert, case or none.";
        EXABEAM_EMAIL = "exabeam_email"
            => "An Exabeam email does not have a non-empty list of distinct addresses, or its subject is blank.";
        EXABEAM_SCHEDULE = "exabeam_schedule"
            => "An Exabeam schedule recurrence has an unknown every, a from or to that is not HH:MMZ, or day keys its every does not take.";
        EXABEAM_NAME_LENGTH = "exabeam_name_length"
            => "The Exabeam rule name is longer than 128 characters.";
        EXABEAM_CONTEXT_TABLE_TRIGGER = "exabeam_context_table_trigger"
            => "An Exabeam sequence whose query looks up a context table has a threshold; Exabeam requires trigger on first match.";
        EXABEAM_NAME_DUPLICATE = "exabeam_name_duplicate"
            => "Two enabled Exabeam blocks of the workspace resolve to the same rule name, compared without regard to case.";
        EXABEAM_OUTCOME_SILENT = "exabeam_outcome_silent"
            => "An Exabeam rule's outcome is none and it sends no email, so it only writes a rule-trigger event.";
        EXABEAM_CORRELATION_WINDOW = "exabeam_correlation_window"
            => "An Exabeam correlation window is shorter than the longest sequence threshold window.";
        // YARA-L 2.0 (yara-l-1.0). Errors are what Google's compiler refuses;
        // the warnings are yaral_string_escape and yaral_deprecated_field
        // through yaral_reference_list_deprecated.
        YARAL_PARSE_ERROR = "yaral_parse_error"
            => "The YARA-L text does not parse, or a text holds a second rule.";
        YARAL_SECTION_HEADER = "yaral_section_header"
            => "A `google_secops` section text holds a section label, a `rule` header, or braces around a rule: deploy writes those, so each key holds its section's body only.";
        YARAL_SECTION_EMPTY = "yaral_section_empty"
            => "A YARA-L section key has no text. A plain YAML scalar that starts with `#` is a YAML comment, so it loads as null: write the text as a block scalar (`|`).";
        YARAL_SECTION_ALIAS = "yaral_section_alias"
            => "A YARA-L section key is a YAML alias: write the section out in the block, so the block shows what it deploys.";
        YARAL_SECTION_MISSING = "yaral_section_missing"
            => "A required YARA-L section is absent: `meta` in a rule file, `events` and `condition` in every rule.";
        YARAL_SECTION_ORDER = "yaral_section_order"
            => "A YARA-L section is repeated or out of order (meta, setup, events, match, outcome, condition, options, export).";
        YARAL_SECTION_UNAVAILABLE = "yaral_section_unavailable"
            => "The section is not part of this profile: `dedup`, `order`, `limit`, `select` and `unselect` are search sections; `meta`, `setup` and `options` are rule sections.";
        YARAL_META_DUPLICATE = "yaral_meta_duplicate"
            => "A meta key appears twice, or a meta value is not a double-quoted string.";
        YARAL_RESERVED_IDENTIFIER = "yaral_reserved_identifier"
            => "A YARA-L keyword is used as a rule name, meta key or variable, or a variable is named `$window_start` or `$window_end`.";
        YARAL_UNDEFINED_VARIABLE = "yaral_undefined_variable"
            => "A variable in `match`, `outcome` or `condition` is not defined by `events` or `outcome`, or an event variable of `events` is absent from `condition`.";
        YARAL_MULTI_EVENT_MATCH = "yaral_multi_event_match"
            => "A rule with two or more event variables has no `match` section.";
        YARAL_MATCH_SHAPE = "yaral_match_shape"
            => "The `match` block is not a YaraLMatch: `group_by` and `window`, and `pivot` and `direction` exactly when `type` is `sliding`.";
        YARAL_MATCH_VARIABLE = "yaral_match_variable"
            => "A `match` name is not a placeholder bound in `events`.";
        YARAL_MATCH_WINDOW = "yaral_match_window"
            => "The match window is outside its bounds (hop and sliding 1m to 14d in a rule, 1m to 48h in a search; tumbling 1m to 72h) or has a unit other than m, h or d.";
        YARAL_CONDITION_SHAPE = "yaral_condition_shape"
            => "The condition is not one Google compiles: `not` or a comma on event terms, `or` across too many event variables or in an unbounded condition, or non-existence without a window and a bounded event.";
        YARAL_NOCASE_ON_ENUM = "yaral_nocase_on_enum"
            => "`nocase` is applied to a comparison with an enumerated UDM field.";
        YARAL_OUTCOME_LIMIT = "yaral_outcome_limit"
            => "A rule or search assigns more than 20 outcome variables.";
        YARAL_OUTCOME_AGGREGATION = "yaral_outcome_aggregation"
            => "With `match`, an outcome reads an event field, or a placeholder that is not a `match` variable, outside an aggregation; or it aggregates an outcome variable.";
        YARAL_UNKNOWN_FUNCTION = "yaral_unknown_function"
            => "The function is not in Google's YARA-L function list, or it takes a different number of arguments.";
        YARAL_FUNCTION_UNAVAILABLE = "yaral_function_unavailable"
            => "The function exists, but not in this profile (rules or search).";
        YARAL_UNKNOWN_UDM_FIELD = "yaral_unknown_udm_field"
            => "The field path is not in the Unified Data Model.";
        YARAL_ENUM_VALUE = "yaral_enum_value"
            => "The value is not one of the enumerated UDM field's values.";
        YARAL_TYPE = "yaral_type"
            => "An operator or function is applied to a value of the wrong type: a count compared with a string, `any` or `all` on a map key, `nocase` on a number.";
        YARAL_REGEX = "yaral_regex" => "The regular expression is not valid RE2.";
        YARAL_STRING_ESCAPE = "yaral_string_escape"
            => "A double-quoted string holds an escape Google does not document (only backslash, double quote, n, r and t); the tenant decides whether it compiles.";
        YARAL_REFERENCE_LIST_LIMIT = "yaral_reference_list_limit"
            => "More `in` statements than the profile allows (rules: 10, 5 with regex, 5 with cidr; search: 7, 4, 2).";
        YARAL_OPTION = "yaral_option" => "An unknown option, or an option value of the wrong kind.";
        YARAL_EXPORT_VALUE = "yaral_export_value"
            => "An `export` `write_row` value is not an outcome variable: Google exports outcome variables only.";
        YARAL_WINDOW_BOUND = "yaral_window_bound"
            => "`window_start` or `window_end` is used in `events`, or in a rule or search with no `match` window.";
        YARAL_DEPRECATED_FIELD = "yaral_deprecated_field" => "The UDM field is deprecated.";
        YARAL_UNFILTERED_EVENT = "yaral_unfiltered_event"
            => "An event variable has no equality on `metadata.event_type`, `metadata.log_type` or `metadata.product_name`, so the rule scans every event.";
        YARAL_LEADING_WILDCARD_REGEX = "yaral_leading_wildcard_regex"
            => "The regular expression starts with `.*` without an anchor: RE2 matches anywhere already, and the prefix only costs time.";
        YARAL_REFERENCE_LIST_DEPRECATED = "yaral_reference_list_deprecated"
            => "Reference lists are deprecated from May 2027 and migrate to data tables by July 2027: use a data table (`%table.column`).";
        // The constraints and advisories of google-secops-1.0.
        GOOGLE_SECOPS_RULE_NAME = "google_secops_rule_name"
            => "The Google SecOps rule `name` is not a YARA-L identifier, or is a keyword.";
        GOOGLE_SECOPS_SEVERITY = "google_secops_severity"
            => "`severity` or `priority` is not `Info`, `Low`, `Medium`, `High`, or `Critical`.";
        GOOGLE_SECOPS_RUN_FREQUENCY = "google_secops_run_frequency"
            => "`run_frequency` is not `LIVE`, `LIVE_CUSTOMIZABLE`, `HOURLY_CUSTOMIZABLE`, or `DAILY`; Google's legacy `HOURLY` is refused.";
        GOOGLE_SECOPS_SCHEDULE = "google_secops_schedule"
            => "`schedule` is set without a customizable `run_frequency`, or its `late_arriving_data_adjustment` is not a positive duration.";
        GOOGLE_SECOPS_META_KEY = "google_secops_meta_key"
            => "A block `meta` key is not an identifier, is a keyword or a key deploy derives, or its value is not a string.";
        GOOGLE_SECOPS_RISK_SCORE_MISSING = "google_secops_risk_score_missing"
            => "`outcome` assigns no `$risk_score`, so every detection gets the instance's default score.";
        GOOGLE_SECOPS_RULE_ID_LITERAL = "google_secops_rule_id_literal"
            => "The rule compares `detection.detection.rule_id` with a literal `ru_` id, which differs per tenant: match `detection.detection.rule_name` instead.";
        GOOGLE_SECOPS_LIVE_FREQUENCY_UNAVAILABLE = "google_secops_live_frequency_unavailable"
            => "`run_frequency` is `LIVE` on a multi-event rule: Google stores `LIVE_CUSTOMIZABLE`, so the block differs from the tenant on every deploy.";
        // The constraints and advisory of microsoft-defender-1.0.
        MICROSOFT_DEFENDER_SCHEMA = "microsoft_defender_schema"
            => "`schema`, when set, is not `platform::microsoft_defender::1.0`.";
        MICROSOFT_DEFENDER_FREQUENCY = "microsoft_defender_frequency"
            => "`schedule.frequency` is not `NRT`, `<n>H` or `<n>D`.";
        MICROSOFT_DEFENDER_LOOKBACK = "microsoft_defender_lookback"
            => "`schedule.lookback` is not `<n>H` or `<n>D`, is set with `frequency: NRT`, or is shorter than `frequency`.";
        MICROSOFT_DEFENDER_SEVERITY = "microsoft_defender_severity"
            => "`alert.severity` is not `Informational`, `Low`, `Medium`, `High`, or `Critical`.";
        MICROSOFT_DEFENDER_GROUPING = "microsoft_defender_grouping"
            => "`alert.grouping` is not `alert_per_event` or `single_alert`.";
        MICROSOFT_DEFENDER_CUSTOM_DETAILS = "microsoft_defender_custom_details"
            => "`alert.custom_details` is not a mapping of non-blank names to strings.";
        MICROSOFT_DEFENDER_ENTITY_KIND = "microsoft_defender_entity_kind"
            => "A key of `entities` is not one of the seventeen entity kinds.";
        MICROSOFT_DEFENDER_ENTITY_MAPPING = "microsoft_defender_entity_mapping"
            => "An entity kind does not hold a list, or a mapping is empty or names a field its kind does not have.";
        MICROSOFT_DEFENDER_ENTITY_IDENTIFIER = "microsoft_defender_entity_identifier"
            => "An entity mapping lacks an identifier Graph requires of its kind (a registry value without its `key`).";
        MICROSOFT_DEFENDER_ACTION_KIND = "microsoft_defender_action_kind"
            => "A key of `actions` is not one of the sixteen automated actions.";
        MICROSOFT_DEFENDER_ACTION_TARGET = "microsoft_defender_action_target"
            => "An action does not hold a non-empty list, a target is empty or names a field its action does not take, or `device_groups` is not a non-empty list of names.";
        MICROSOFT_DEFENDER_ISOLATION_TYPE = "microsoft_defender_isolation_type"
            => "`isolation_type` is not `full` or `selective`.";
        MICROSOFT_DEFENDER_COLUMN = "microsoft_defender_column"
            => "A column name (an entity field, an action column, a custom detail's value) is blank or not a string.";
        // A block against its query's inferred output (#1885).
        MICROSOFT_DEFENDER_COLUMN_NOT_IN_OUTPUT = "microsoft_defender_column_not_in_output"
            => "A column the block names (an entity field, an action column, a custom detail's value, an alert `{{placeholder}}`) is not a column of the query's output.";
        MICROSOFT_DEFENDER_REQUIRED_COLUMNS = "microsoft_defender_required_columns"
            => "The query's output lacks a column a custom detection needs for the tables it reads (`Timestamp`, and `DeviceId` and `ReportId` for a device table).";
        MICROSOFT_DEFENDER_COLUMN_TYPE = "microsoft_defender_column_type"
            => "An entity field or action column is mapped from an output column whose type is `dynamic`, `datetime`, `bool` or `timespan`.";
        MICROSOFT_DEFENDER_UNPROJECTED_OUTPUT = "microsoft_defender_unprojected_output"
            => "The query returns columns no entity, action, custom detail or alert placeholder uses, from which Defender derives entity mappings of its own.";
        MICROSOFT_DEFENDER_SCOPE = "microsoft_defender_scope"
            => "`scope` is not `{device_groups: [...]}` with a non-empty list of non-blank names.";
        MICROSOFT_DEFENDER_INCIDENT = "microsoft_defender_incident"
            => "`incident` is not a mapping whose `exclude_from_correlation` is `true` or `false`.";
        MICROSOFT_DEFENDER_NO_ENTITIES = "microsoft_defender_no_entities"
            => "The block maps no entity, so the alert names no device, user, or mailbox to triage or act on.";
        MICROSOFT_DEFENDER_IMPACTED_ASSET_IDENTIFIER = "microsoft_defender_impacted_asset_identifier"
            => "A device or user mapping sets no strong identifier of its impacted asset.";
        // The limits of Microsoft's custom detection docs (#1890).
        MICROSOFT_DEFENDER_CUSTOM_DETAILS_LIMIT = "microsoft_defender_custom_details_limit"
            => "`alert.custom_details` has more than the 20 details Defender documents per rule, or names longer than the 4 KB beyond which Defender drops every detail from the alert.";
        MICROSOFT_DEFENDER_PLACEHOLDER_LIMIT = "microsoft_defender_placeholder_limit"
            => "`alert.title` or `alert.description` references more than the three `{{Column}}` columns Defender documents per field.";
        MICROSOFT_DEFENDER_NRT_QUERY = "microsoft_defender_nrt_query"
            => "A `frequency: NRT` rule's query is one Defender documents it cannot run continuously: it reads more than one table or a table outside the NRT list, joins, unions, uses externaldata, has a comment, or reads `EmailEvents`' `LatestDeliveryLocation` or `LatestDeliveryAction`.";

        // The Datadog search syntax (rfc-datadog-cloud-siem, §6.7). Errors are
        // datadog_parse_error through datadog_range (a range's mixed bounds are a
        // warning); datadog_unknown_attribute is a hint; the rest are warnings.
        DATADOG_PARSE_ERROR = "datadog_parse_error"
            => "The Datadog search does not parse: an unbalanced bracket, a dangling operator, an empty group, a field with no value, two modifiers in a row, or an unclosed phrase.";
        DATADOG_UNESCAPED_SPECIAL = "datadog_unescaped_special"
            => "A Datadog search term holds an unescaped `!`, `<` or `>`, or a value starts with an unescaped `-`, which Datadog reads as an exclusion: escape it with `\\`.";
        DATADOG_REGEX = "datadog_regex"
            => "A Datadog search term holds `~` or `^`: the search syntax has no regular expression, fuzzy or boost operator.";
        DATADOG_CIDR = "datadog_cidr"
            => "A Datadog `CIDR()` call does not name an `@attribute` first, has no block, or has an argument that is not an IPv4 or IPv6 CIDR block.";
        DATADOG_RANGE = "datadog_range"
            => "A Datadog range is malformed (a missing bound, a lower-case `to`), or mixes an inclusive and an exclusive bound.";
        DATADOG_MIXED_BOOLEAN = "datadog_mixed_boolean"
            => "A Datadog search puts OR beside an AND, written or implied, without parentheses: AND binds tighter, as VRL reads it (unverified on Cloud SIEM).";
        DATADOG_LOWERCASE_OPERATOR = "datadog_lowercase_operator"
            => "A lower-case `and`, `or` or `not` stands between field clauses or in a value group, where Datadog reads it as a search term, not an operator.";
        DATADOG_CURLY_QUOTE = "datadog_curly_quote"
            => "A Datadog search holds a curly quote, which is not a quote: the words around it are searched as separate terms.";
        DATADOG_WILDCARD_IN_PHRASE = "datadog_wildcard_in_phrase"
            => "A `*` or `?` touches a word inside a quoted phrase, where it is punctuation, not a wildcard.";
        DATADOG_UNESCAPED_COLON = "datadog_unescaped_colon"
            => "A Datadog search value holds an unescaped `:`, which Datadog's docs say to escape.";
        DATADOG_SYMBOL_OPERATOR = "datadog_symbol_operator"
            => "`&&` or `||` stands between Datadog search clauses: Datadog's docs list them as characters to escape; write AND or OR.";
        DATADOG_DETACHED_OPERATOR = "datadog_detached_operator"
            => "A Datadog exclusion `-` is followed by a space.";
        DATADOG_FULL_TEXT_IN_RULE = "datadog_full_text_in_rule"
            => "A detection rule's query searches every attribute with `*:term`, which Datadog documents for monitors, dashboards and notebooks, not for detection rules.";
        DATADOG_CALCULATED_FIELD_IN_RULE = "datadog_calculated_field_in_rule"
            => "A detection rule's query names a calculated field (`#name`): real-time detection rules have none.";
        DATADOG_PIPELINES_ONLY = "datadog_pipelines_only"
            => "A Datadog search uses Observability Pipelines syntax (`_exists_:`, `_missing_:`, a quoted field name), which log search does not read the same way.";
        DATADOG_UNKNOWN_ATTRIBUTE = "datadog_unknown_attribute"
            => "A Datadog search field is a dotted bare key, searched as a tag, where an `@attribute` was probably meant.";
        // Datadog block constraint codes and the advisory (rfc-datadog-cloud-siem, §5.9).
        DATADOG_METHOD_UNSUPPORTED = "datadog_method_unsupported"
            => "A Datadog detection method is not threshold, new_value, anomaly or impossible_travel.";
        DATADOG_DURATION = "datadog_duration"
            => "A Datadog duration is not one of the values its key accepts (a window, a bucket, a learning period, forget_after).";
        DATADOG_WINDOW_ORDER = "datadog_window_order"
            => "A Datadog detection window is longer than the signal's keep_alive or max_duration.";
        DATADOG_QUERY_NAME = "datadog_query_name"
            => "A Datadog query name is not [a-z][a-z0-9_]*, is a duplicate, or is set on a new_value query.";
        DATADOG_MEASURE = "datadog_measure"
            => "A Datadog query sets more than one measure, or new_value does not match the detection method.";
        DATADOG_DETECTION_OPTION = "datadog_detection_option"
            => "A Datadog detection key the method does not take, or a new_value rule without forget_after.";
        DATADOG_SIGNAL_GROUP_BY = "datadog_signal_group_by"
            => "A Datadog signal.group_by field is in no query's group_by.";
        DATADOG_CONDITION = "datadog_condition"
            => "A Datadog case condition does not parse, names an unknown query, or does not suit the detection method.";
        DATADOG_SEVERITY = "datadog_severity"
            => "A Datadog case severity is not info, low, medium, high or critical.";
        DATADOG_TAG = "datadog_tag"
            => "A Datadog tag would be refused or rewritten: upper case, a character outside a-z 0-9 _ - : . /, or longer than 200 characters.";
        DATADOG_CONDITION_MIXED = "datadog_condition_mixed"
            => "A Datadog case condition mixes && and ||, whose precedence Datadog does not document.";
    }
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("{0}")]
    Message(String),
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_build_that_sets_the_version_reports_it_and_any_other_the_crates() {
        // The candidate's binaries and wheel are built from a workspace at
        // `1.0.0` with `OPENTIDE_BUILD_VERSION=1.0.0-rc.1`: they report the candidate.
        assert_eq!(reported_version(Some("1.0.0-rc.1"), "1.0.0"), "1.0.0-rc.1");
        assert_eq!(reported_version(None, "1.0.0"), "1.0.0");
        assert_eq!(reported_version(Some(""), "1.0.0"), "1.0.0");
    }

    #[test]
    fn the_reported_version_is_the_builds_or_the_crates() {
        assert_eq!(
            VERSION,
            option_env!("OPENTIDE_BUILD_VERSION")
                .filter(|version| !version.is_empty())
                .unwrap_or(env!("CARGO_PKG_VERSION"))
        );
    }

    use super::word_start;

    /// #182: the character before the word may be wider than a byte.
    #[test]
    fn word_start_is_a_char_boundary_after_a_wide_character() {
        let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
        assert_eq!(word_start("a b", word), 2);
        assert_eq!(word_start("abc", word), 0);
        let text = "wehrE\u{59a}ndsWith";
        assert_eq!(&text[word_start(text, word)..], "ndsWith");
        let text = "x 日本name";
        assert_eq!(&text[word_start(text, word)..], "name");
        assert_eq!(word_start("😀", word), "😀".len());
    }
    use super::*;

    /// #180: a span that ends inside a multi-byte character gave a panic.
    #[test]
    fn an_offset_inside_a_character_counts_from_its_start() {
        let src = "a\\é日😀";
        for offset in 0..=src.len() + 2 {
            let position = offset_to_position(src, offset);
            assert_eq!(LineIndex::new(src).position(offset), position, "{offset}");
        }
        // Byte 3 is inside `é` (bytes 2..4): its column is `é`'s start, 2.
        assert_eq!(offset_to_position(src, 3), Position::new(0, 2));
        let _ = span_to_range(src, ByteSpan::new(1, 4));
    }

    #[test]
    fn line_index_matches_offset_to_position() {
        let text = "ab\n\u{1F600}c\r\n\nd é";
        let index = LineIndex::new(text);
        for (offset, _) in text
            .char_indices()
            .chain([(text.len(), ' '), (text.len() + 5, ' ')])
        {
            assert_eq!(
                index.position(offset),
                offset_to_position(text, offset),
                "{offset}"
            );
        }
    }

    /// A long non-ASCII line converts each offset by binary search, not by a
    /// scan from the line's start (8,000 kuery diagnostics on one line of
    /// non-ASCII text took 9 s).
    #[test]
    fn a_long_non_ascii_line_converts_in_linear_time() {
        let text = "\u{e9}:\"\u{fc} ".repeat(50_000);
        let index = LineIndex::new(&text);
        let started = std::time::Instant::now();
        let mut last = Position::new(0, 0);
        for offset in (0..text.len()).step_by(7) {
            last = index.position(offset);
        }
        assert!(last.character > 0);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            index.position(text.len()),
            offset_to_position(&text, text.len())
        );
    }

    /// `LineIndex` gives exactly what the scanning functions give, at every
    /// offset and every position: multi-byte UTF-8 (2, 3 and 4 bytes, the
    /// last two UTF-16 units), CRLF, tabs, empty lines, a text with and
    /// without a final newline, and positions past a line's or the text's end.
    #[test]
    fn line_index_agrees_with_the_scans_everywhere() {
        for text in [
            "",
            "\n",
            "ascii only\nsecond line\n",
            "ab\n\u{1F600}c\r\n\nd \u{e9}",
            "\tkey:\t\u{65e5}\u{672c}\u{8a9e}\r\n\t- \u{e9}t\u{e9} \u{1F600}\u{1F600} x\r\n\r\nend",
            "no final newline \u{e9}",
            "\u{1F600}",
        ] {
            let index = LineIndex::new(text);
            for offset in 0..=text.len() + 2 {
                assert_eq!(
                    index.position(offset),
                    offset_to_position(text, offset),
                    "{text:?} @ {offset}"
                );
            }
            let lines = u32::try_from(text.split('\n').count()).unwrap();
            for line in 0..=lines + 1 {
                for character in 0..=40 {
                    let p = Position::new(line, character);
                    assert_eq!(
                        index.offset(p),
                        position_to_offset(text, p),
                        "{text:?} @ {line}:{character}"
                    );
                }
            }
            for start in 0..=text.len() {
                let span = ByteSpan::new(start, (start + 3).min(text.len()));
                assert_eq!(
                    index.range(span),
                    span_to_range(text, span),
                    "{text:?} {span:?}"
                );
            }
        }
    }

    #[test]
    fn no_otide_in_crate_name() {
        assert!(
            !env!("CARGO_PKG_NAME").contains("otide")
                || env!("CARGO_PKG_NAME").starts_with("opentide")
        );
        assert!(env!("CARGO_PKG_NAME").starts_with("opentide"));
    }

    #[test]
    fn every_code_is_listed_once_and_described() {
        // `codes!` writes each code's constant, `ALL` entry and sentence
        // from one line, so none can be missing: this holds the table's
        // contents.
        let mut seen = std::collections::BTreeSet::new();
        for code in codes::ALL {
            assert!(seen.insert(*code), "{code} listed twice");
            assert!(
                !code.is_empty()
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{code}: lower-case snake_case"
            );
            let text = codes::describe(code).unwrap_or_else(|| panic!("{code} has no description"));
            assert!(
                text.ends_with('.'),
                "{code}: one sentence ending in a period"
            );
        }
        assert_eq!(codes::describe("not_a_code"), None);
    }

    #[test]
    fn language_id_roundtrip() {
        for id in LanguageId::QUERY_LANGUAGES
            .into_iter()
            .chain([LanguageId::TideYaml])
        {
            assert_eq!(LanguageId::parse(id.as_str()), Some(id));
        }
        assert_eq!(LanguageId::parse("kusto"), Some(LanguageId::Kql));
        // `KQL` is Kusto. Kibana's language is `kuery`.
        assert_eq!(LanguageId::parse("KQL"), Some(LanguageId::Kql));
        assert_eq!(LanguageId::parse("kibana-kql"), Some(LanguageId::Kuery));
        assert_eq!(LanguageId::parse("sql"), None);
        assert_eq!(LanguageId::parse("esql"), Some(LanguageId::Esql));
        assert_eq!(LanguageId::from_extension("sql"), None);
        assert_eq!(LanguageId::from_extension("eql"), Some(LanguageId::Eql));
        assert_eq!(LanguageId::from_extension("falco"), Some(LanguageId::Falco));
        assert_eq!(LanguageId::parse("falco"), Some(LanguageId::Falco));
        assert_eq!(LanguageId::parse("cql"), Some(LanguageId::Cql));
        assert_eq!(LanguageId::parse("yara"), Some(LanguageId::Yara));
        assert_eq!(
            LanguageId::parse(LanguageId::Yara.as_str()),
            Some(LanguageId::Yara)
        );
        assert_eq!(LanguageId::from_extension("yar"), Some(LanguageId::Yara));
        assert_eq!(LanguageId::from_extension("yara"), Some(LanguageId::Yara));
        assert_eq!(LanguageId::parse("logscale"), Some(LanguageId::Cql));
        assert_eq!(LanguageId::from_extension("cql"), Some(LanguageId::Cql));
        // Exabeam's guides call it EQL; opentide's id is `exabeam`.
        assert_eq!(LanguageId::parse("exabeam"), Some(LanguageId::Exabeam));
        assert_eq!(
            LanguageId::from_extension("exabeam"),
            Some(LanguageId::Exabeam)
        );
        assert_eq!(LanguageId::parse("EQL"), Some(LanguageId::Eql));
    }

    #[test]
    fn a_byte_order_mark_is_not_text() {
        let src = "\u{feff}a: é😀";
        assert_eq!(strip_bom(src), "a: é😀");
        assert_eq!(strip_bom("a: 1"), "a: 1");
        // Only one leading mark is a byte-order mark.
        assert_eq!(strip_bom("\u{feff}\u{feff}a"), "\u{feff}a");
        assert_eq!(strip_bom("a\u{feff}"), "a\u{feff}");
        assert_eq!(strip_bom_at(src, 4), ("a: é😀", 1));
        assert_eq!(strip_bom_at(src, 1), ("a: é😀", 0));
        assert_eq!(strip_bom_at("a: 1", 2), ("a: 1", 2));
        let stripped = strip_bom(src);
        assert_eq!(
            offset_to_position(stripped, stripped.len()),
            Position::new(0, 6)
        );
    }

    #[test]
    fn offset_to_position_handles_newlines() {
        let src = "abc\néé";
        let pos = offset_to_position(src, src.len());
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 2);
    }

    /// Diagnostic ranges leave the process as UTF-16 code units. `é` is one
    /// unit (two UTF-8 bytes); an emoji outside the BMP is two units.
    #[test]
    fn offset_to_position_counts_utf16_for_accent_and_emoji() {
        let src = "aé😀";
        assert_eq!(offset_to_position(src, 0), Position::new(0, 0));
        assert_eq!(offset_to_position(src, 1), Position::new(0, 1));
        assert_eq!(offset_to_position(src, 1 + "é".len()), Position::new(0, 2));
        assert_eq!(offset_to_position(src, src.len()), Position::new(0, 4));

        let emoji_start = 1 + "é".len();
        let range = span_to_range(src, ByteSpan::new(emoji_start, src.len()));
        assert_eq!(range.start, Position::new(0, 2));
        assert_eq!(range.end, Position::new(0, 4));
        assert_eq!(range.end.character - range.start.character, 2);
    }

    #[test]
    fn offset_to_position_emoji_on_the_next_line() {
        let src = "a\n😀b";
        let after_emoji = "a\n😀".len();
        assert_eq!(offset_to_position(src, after_emoji), Position::new(1, 2));
        assert_eq!(offset_to_position(src, src.len()), Position::new(1, 3));
    }

    #[test]
    fn range_contains_inclusive_end() {
        let range = Range::new(Position::new(0, 1), Position::new(0, 4));
        assert!(range.contains(Position::new(0, 1)));
        assert!(range.contains(Position::new(0, 4)));
        assert!(!range.contains(Position::new(0, 0)));
    }

    /// Inside [`with_line_index`], `span_to_range` and `offset_to_position`
    /// on the installed text give what the scans give, everywhere, without
    /// scanning; on another text (even with the same content) they scan.
    #[test]
    fn the_installed_table_gives_what_the_scans_give() {
        for text in [
            "",
            "ascii only\nsecond line\n",
            "ab\n\u{1F600}c\r\n\nd \u{e9}",
            "\tkey:\t\u{65e5}\u{672c}\r\n\t- \u{e9}t\u{e9} \u{1F600} x\r\n\r\nend",
        ] {
            let scanned: Vec<Range> = (0..=text.len() + 2)
                .map(|start| span_to_range(text, ByteSpan::new(start, start + 2)))
                .collect();
            let before = scans_from_the_start();
            let installed: Vec<Range> = with_line_index(text, || {
                (0..=text.len() + 2)
                    .map(|start| span_to_range(text, ByteSpan::new(start, start + 2)))
                    .collect()
            });
            assert_eq!(installed, scanned, "{text:?}");
            assert_eq!(
                scans_from_the_start(),
                before,
                "{text:?}: scanned inside the scope"
            );

            // An empty text's address may be shared (a dangling pointer):
            // the same key then means the same, empty, content.
            if text.is_empty() {
                continue;
            }
            let copy = text.to_string();
            let before = scans_from_the_start();
            let other = with_line_index(text, || offset_to_position(&copy, copy.len()));
            assert_eq!(other, offset_to_position(text, text.len()));
            assert_eq!(
                scans_from_the_start(),
                before + 2,
                "another text is scanned"
            );
        }
    }

    /// A slice of the installed text is another text: its offsets count from
    /// its own start.
    #[test]
    fn a_slice_of_the_installed_text_is_scanned() {
        let text = "one\ntwo\nthree";
        let tail = &text[4..];
        let inside = with_line_index(text, || offset_to_position(tail, 4));
        assert_eq!(inside, Position::new(1, 0));
    }

    /// Scopes nest: the inner text's table is installed for the inner run,
    /// the outer's is back after it, also when the inner run panics, and
    /// nothing is installed after the outer scope.
    #[test]
    fn scopes_nest_and_restore_even_on_a_panic() {
        let outer = "a\nb";
        let inner = "x\ny\nz";
        with_line_index(outer, || {
            let before = scans_from_the_start();
            with_line_index(inner, || {
                assert_eq!(offset_to_position(inner, 4), Position::new(2, 0));
                // The same text again: nothing rebuilt, still installed.
                with_line_index(inner, || {
                    assert_eq!(offset_to_position(inner, 2), Position::new(1, 0));
                });
            });
            assert_eq!(offset_to_position(outer, 2), Position::new(1, 0));
            assert_eq!(scans_from_the_start(), before, "the tables were installed");
            let panicked = std::panic::catch_unwind(|| {
                with_line_index(inner, || panic!("inside"));
            });
            assert!(panicked.is_err());
            let before = scans_from_the_start();
            assert_eq!(offset_to_position(outer, 2), Position::new(1, 0));
            assert_eq!(scans_from_the_start(), before, "the outer table is back");
        });
        let before = scans_from_the_start();
        assert_eq!(offset_to_position(outer, 2), Position::new(1, 0));
        assert_eq!(scans_from_the_start(), before + 1, "nothing is installed");
    }
}
