---
name: add-language
description: Add a query language to opentide's engine (S1QL, Sigma) - the step-by-step checklist from LanguageId through a pure-Rust parser on opentide-parse (logos lexer, hand-written grammar, rowan, .ungram), ADR 0013 catalogs, HighlightSpec and its KEYWORDS table, ADR 0014's analysis rules and §5a's single walk, the depth contract, YAML injection, the proofs (corpus gate, vendor differential, work counts, throughput row and instruction budgets, fuzz target, snapshots) and the registry, docs and companion updates, with a definition of done. SQL stays unsupported. Use when creating a new engine crate or parser.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Add a language

This is the checklist. Every rule it names is written down once, in the file it links; read that
file at the step, not this summary of it. A language is done when every box of
[Definition of done](#definition-of-done) is ticked in its pull request.

Models to copy: `opentide-falco` is the smallest complete language (a grammar, catalogs from a
generator, block context from Tide); `opentide-esql` and `opentide-eql` the most complete;
`opentide-lucene` the single walk (ADR 0014 §5a); `opentide-exabeam` a language whose
specification ships a reference checker (port it as the verdict parser, record its verdicts with
`scripts/engine/sync_exabeam_conformance.py`, and give it a recovering tree in `src/cst.rs` for
highlighting). Detection-authoring skills live in `opentidehq/skills`; they are not an engine.

SQL stays unsupported until a real dialect and grammar are chosen. A stub parser or a fake
highlighter is not a language, and a platform whose language is unspecified gets no offline check
(`supported: false`, or a usage error naming `--live`), never a fake pass.

## The rules a language meets

| Rule | Where it is written |
|------|---------------------|
| Pure Rust: a logos lexer (or one by hand where the language lexes by context), a hand-written recursive-descent or Pratt grammar on `opentide-parse`, a lossless rowan tree, a `.ungram` and `cargo xtask codegen`. No C, no `cc` or `*-sys` crate, no `unsafe`, no generated parser | [ADR 0012](../../../docs/internal/adr/0012-pure-rust-parsing.md), [`parser`](../parser/SKILL.md), [`crates/opentide-parse/AGENTS.md`](../../../crates/opentide-parse/AGENTS.md) |
| The depth contract: `Grammar::max_depth` (one `TooDeep`, the rest in one error node), `MAX_TREE_DEPTH` and `TreeTooDeep`, the nesting floor (`NESTING_CEILING`), every token class safe at 1 000 000 characters on a 1 MB stack; linear on broken input; recovery that never makes broken input noisier | ADR 0012 decision 4, [`parser`](../parser/SKILL.md) "Rules" |
| Catalogs: generated TOML in ADR 0013's form, built and indexed once in a `OnceLock`, read item by item through `opentide_core::catalog` (`array_items`, `preamble`, `compiled_in`), never `toml::from_str` on a whole file | [ADR 0013](../../../docs/internal/adr/0013-language-catalogs.md), [`catalogs`](../catalogs/SKILL.md) |
| Analysis: nothing shared copied per call; indexes and prepared suggestions built once per catalog; memos keyed by what they read and bounded; a cheap bound before an expensive measure; walk once, from where the answer is; measured with callgrind; held by work counts | [ADR 0014](../../../docs/internal/adr/0014-analysis-performance.md) §1 to §7 |
| One walk for the checks and the highlight: one preorder walk over every element, held by a count of element visits equal to the tree's element count | ADR 0014 §5a (Lucene's `tree::walk_once`) |
| Highlighting: HighlightSpec captures from the tree; a capture is appended, never renamed; the TextMate, Monaco and Helix grammars come from the `KEYWORDS` table | [`parser`](../parser/SKILL.md) "Highlighting", [`crates/opentide-highlight/AGENTS.md`](../../../crates/opentide-highlight/AGENTS.md) |
| I/O and concurrency: no `std::fs` in an engine's `src/` (`scripts/engine/check-io-free.sh` lists the crates; add the new one); no `async` or tokio in the engine; CPU work on rayon, network I/O only on the one process runtime (#1558) | [`crates/AGENTS.md`](../../../crates/AGENTS.md) "Hard rules", [`rust-engine`](../rust-engine/SKILL.md) |
| Errors, panics and lints: no panic on user input, `thiserror` in the engine, `#[expect(..., reason)]` on the narrowest item, `missing_docs` for every new crate, the crate placed in `xtask/layers.toml` | [`rust-engine`](../rust-engine/SKILL.md), [`crates/AGENTS.md`](../../../crates/AGENTS.md) "Lints", [`rust`](../rust/SKILL.md) |

## Checklist

Work in this order; each step names what it proves. `<id>` is the public language id (`kql`,
`yaral`), `<Id>` its `LanguageId` variant.

### 1. The id

- [ ] `LanguageId::<Id>` in `crates/opentide-core` (`as_str`, `parse`, `Display`, serde rename,
  `from_extension` for each file suffix). The wire name is the public id, not a crate path.
- [ ] Its diagnostic codes in `opentide_core::codes`, prefixed `<id>_`; an unknown construct gets
  a stable code, not a free-form message.
- [ ] `scripts/engine/check-names.sh` passes (`opentide`, never `otide`; no `opentide-sql`).

### 2. The parser (`crates/opentide-<id>`)

- [ ] The crate, in the root `Cargo.toml` members and in [`xtask/layers.toml`](../../../xtask/layers.toml)
  (a query language is a `foundation` crate below `opentide-schema`), with an `AGENTS.md`, its
  crate docs (`missing_docs` holds), and its name in `scripts/engine/check-io-free.sh`.
- [ ] `SyntaxKind`, the lexer, the grammar, `src/<id>.ungram` and `src/generated/ast.rs` from
  `cargo xtask codegen`, as [`parser`](../parser/SKILL.md) lays them out. A plain `parses(text)`
  entry point that builds the tree and nothing else (the bench's parse mode reads it).
- [ ] The hidden `debug_kinds` and `debug_node_kinds` hooks the corpus gate reads (`opentide-kuery`
  has the shortest pair).
- [ ] Its floors in `crates/opentide-analysis/tests/deep_queries.rs` (`*_NEST_FLOOR`,
  `*_CHAIN_FLOOR`), the 1 000 000-character test of every token class on a 1 MB stack, and a
  `tests/long_runs.rs` that compares growth (n against 4n), never an absolute time.
- [ ] Every corpus tree that parses without an error conforms to the `.ungram`
  (`opentide_parse::conformance`, as in `opentide-eql`'s `tests/ast_conformance.rs`).

### 3. Catalogs

- [ ] `data/catalogs/<id>/`, written by a `scripts/engine/sync_<id>_catalog.py` in ADR 0013's form
  (facts from upstream, summaries written here; `sync_falco_catalog.py` is the pattern).
- [ ] `src/catalog.rs`: `Catalog::cached()` builds and indexes it once in a `OnceLock`, with no
  rayon, lock or other catalog inside the build, and a test that the files read item by item equal
  `toml::from_str` of the whole files (`opentide-falco`'s `catalog.rs`).

### 4. Analysis and highlighting

- [ ] The analysis (diagnostics, hover, completion, signature help) in the crate, to ADR 0014:
  shared data borrowed (`HighlightSpec::shared()`, `Arc` for what stages pass along), indexes and
  suggestion candidates prepared in the catalog's build, memos keyed by what they read (the
  catalog's identity among it) and bounded, cheap bounds before edit distances.
- [ ] The checks and the highlight in one walk (§5a), unless the highlight reads another text;
  say why in the crate's `AGENTS.md` if so.
- [ ] HighlightSpec captures (the crate's `highlight`); new captures appended to
  `highlights/spec.toml`'s `legend`.
- [ ] `crates/opentide-highlight/src/keywords/<id>.rs` (`KEYWORDS`, wired in `keywords()`), a lexer
  test that holds the table to the tokens the lexer cuts, the language's comment pattern and
  TextMate scope in `crates/opentide-highlight/src/lib.rs`, and the `tmLanguage` file
  `generate-highlights` writes (`crates/opentide-lsp/src/main.rs`).
  `cargo run -p opentide-lsp -- generate-highlights --check` passes.

### 5. Wiring

- [ ] `opentide-analysis` dispatches `LanguageId::<Id>` (`src/lib.rs`: analyze, hover,
  completions, signature help). No second copy of them in `opentide-tide`.
- [ ] If a platform embeds the language: `crates/opentide-tide` (`language_for_field_path` in
  `src/lib.rs`, the platform's language in `src/injection.rs`), the injection table in
  [`docs/engine/ARCHITECTURE.md`](../../../docs/engine/ARCHITECTURE.md), tokens remapped onto YAML
  coordinates after the block-scalar indent is stripped, and
  `tests/raw_query_composability.rs`: the same finding on a raw file and in the Tide block.
- [ ] The platforms registry, [`crates/opentide-schema/src/platforms.rs`](../../../crates/opentide-schema/src/platforms.rs)
  (`offline_languages`), and what reads it: `validate`'s `queries` check, `validate query`
  (`crates/opentide-cli/src/tree.rs`'s query-file suffixes, `mcp/queries.rs`), `opentide explain`
  (a page for each code, `crates/opentide-cli/src/explain.rs`).
- [ ] Hosts: the language server picks the language from the URI suffix
  (`crates/opentide-lsp/src/server.rs`, an e2e frame in `tests/e2e_stdio.rs`); the editors' file
  associations (`editors/`, `packages/lsp-client/src/index.ts`; `lsp-host` and `wasm-hosts`).
  The WASM build needs nothing per language: do not add a wasm-bindgen export.

### 6. Proof

- [ ] **Corpus gate.** Fixtures under `crates/testdata/corpus/<id>/`, each tagged on its first line
  (`// prod:<rule> valid`), a row in [`docs/engine/LANGUAGE.md`](../../../docs/engine/LANGUAGE.md),
  and the language in `crates/opentide-analysis/tests/corpus_gate.rs` (`kind_names`, its
  structural list): every node kind tagged or structural with a reason.
- [ ] **Baseline.** The new files' diagnostics and tokens in `tests/parser_baseline.rs`'s
  snapshots, read before they are committed.
- [ ] **Public rules.** `crates/testdata/conformance/external/<id>/`: unmodified public rules, a
  `<name>.broken.<ext>` twin with one injected fault each, the source and licence in `SOURCES.md`;
  `tests/external_corpus.rs` asserts the fault on the longest prefix that parses and a diagnostic on
  every broken file. Never delete a public rule because it does not parse yet.
- [ ] **Against the vendor.** Where the vendor publishes a parser or checker: a `<id>` mode in
  `scripts/engine/oracles/oracle.py`, `[[<id>]]` entries in `crates/testdata/oracles/exceptions.toml`,
  a job in `.github/workflows/oracle.yml`, and the reference's packages in
  `scripts/engine/license-scan.sh` (the reference never ships). Where none exists,
  `scripts/engine/oracles/README.md` says why. A port of a reference checker records its verdicts
  as a conformance corpus instead (Exabeam, Falco).
- [ ] **Work counts.** Each ADR 0014 optimisation held by a test that counts work and fails on the
  naive path (put the old path back and watch it fail), and §5a's element-visit count.
- [ ] **Throughput.** A row in the `LANGUAGES` table of
  `crates/opentide-analysis/benches/throughput.rs`, a row in
  [`docs/engine/THROUGHPUT.md`](../../../docs/engine/THROUGHPUT.md), and the language's
  instruction and allocation budgets in `tests/bench/instructions.toml`:
  `cargo xtask throughput --record --language <id>` (#1581). Its corpus figures are in the range of
  the other languages', and a callgrind of the warm loop shows no setup repeated per call.
- [ ] **Fuzzing.** `fuzz/fuzz_targets/<id>.rs` (`exercise` in `fuzz/src/lib.rs`), its `[[bin]]` in
  `fuzz/Cargo.toml`, the target in `.github/workflows/engine-fuzz.yml`'s matrix, its seeds row in
  `fuzz/README.md`; crashes it finds go in `crates/opentide-analysis/tests/fuzz_regressions.rs`.
- [ ] **The command line.** `crates/opentide-cli/tests/validate_query.rs` checks a query file of the
  language offline; where `validate` or `validate query` prints differently for it, a case in
  `tests/golden/cases.toml` and its reviewed snapshots ([`golden`](../golden/SKILL.md)).

### 7. Docs and companions

- [ ] `docs/engine/<LANGUAGE>.md` (what is checked, and against which source; `FALCO.md` and
  `YARAL.md` are the models), the language in `crates/AGENTS.md` "Product" and in this skill's
  models if it is a new pattern.
- [ ] A platform's offline engine changed: the table in the root `AGENTS.md` "Platforms",
  `docs/cli/validate.md` and `docs/usage/concepts/platforms.md`.
- [ ] `CHANGELOG.md` `## [Unreleased]` ([`release-notes`](../release-notes/SKILL.md)) and
  `crates/CHANGELOG.md` ([`engine-release-notes`](../engine-release-notes/SKILL.md)).
- [ ] A companion pull request on [opentidehq/skills](https://github.com/opentidehq/skills) (the
  platform skill, `coverage.json`), linked from this one.

## Definition of done

- Every box above is ticked, or the pull request says why one does not apply.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo xtask check-layers`, `cargo xtask codegen --check`,
  `bash scripts/engine/check-io-free.sh`, `bash scripts/engine/check-names.sh` and
  `generate-highlights --check` pass.
- `cargo nextest run --workspace --profile ci` and `cargo test --workspace --doc` pass
  ([`rust`](../rust/SKILL.md)); `cargo xtask throughput --check` passes with the new budgets.
- `scripts/ci-local.sh --full` passes (the root `AGENTS.md`, "Definition of done").
- The parser had an independent adversarial review before merging ([`parser`](../parser/SKILL.md),
  "Tests"): the reviews found the 1 MB-stack and quadratic-on-broken-input bugs the corpus did not.

## Dispatch

`Session::language_for` selects the engine from a reported language id, then from the URI suffix
(`LanguageId::from_extension`). A reported id the parser does not know is ignored and the suffix is
used. Raw query files are first-class documents with an empty Tide workspace;
`tests/raw_query_composability.rs` holds a raw file and the same text in a Tide block to the same
finding.

## Out of scope

- Rewriting the server onto `tower-lsp` or an async runtime.
- Shipping a vendor's library (Kusto.Language, a Splunk SDK, `yara-x`) in the binary: references
  stay in CI.
- Validating a platform whose language is unspecified.
