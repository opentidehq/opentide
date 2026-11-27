---
name: add-language
description: Add a query language to opentide's engine (S1QL, Sigma) - the step-by-step checklist from deciding the language through LanguageId, a pure-Rust parser on opentide-parse (logos lexer, hand-written grammar, rowan, .ungram), ADR 0013 catalogs, HighlightSpec and its KEYWORDS table, ADR 0014's analysis rules and §5a's single walk, the depth contract, YAML and hunt injection, every place a language is wired (registry, CLI, MCP, hosts, editors, CI), the proofs (corpus gate, vendor differential, work counts, throughput budgets, fuzz target, snapshots) and the docs and companion updates, with a definition of done. SQL stays unsupported. Use when creating a new engine crate or parser.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Add a language

This is the checklist. Every rule it names is written down once, in the file it links; read that
file at the step, not this summary of it. A language is done when every box of
[Definition of done](#definition-of-done) is ticked in its pull request, or the pull request says
why a box does not apply.

**Models to copy.**

- `opentide-esql` and `opentide-eql`: the most complete languages, with a `.ungram`, an AST
  conformance test, catalogs, hover, completion and signature help.
- `opentide-falco`: the smallest complete crate (`build.rs`, catalogs from a generator, block
  context from Tide). Its verdict parser is a port of libsinsp's, and its tree only highlights, so
  it has no `.ungram`: do not copy that part.
- `opentide-lucene`: the single walk for the checks and the highlight (ADR 0014 §5a,
  `src/tree.rs`).
- `opentide-exabeam`: a language whose specification ships a reference checker. Port the checker
  as the verdict parser, record its verdicts as a conformance corpus
  (`scripts/engine/sync_exabeam_conformance.py`), and give it a recovering tree on
  `opentide-parse` for highlighting (`src/cst.rs`).

Detection-authoring skills live in `opentidehq/skills`; they are not an engine.

SQL stays unsupported until a real dialect and grammar are chosen. A stub parser or a fake
highlighter is not a language, and a platform whose language is unspecified gets no offline check
(`supported: false`, or a usage error naming `--live`), never a fake pass.

## The rules a language meets

| Rule | Where it is written |
|------|---------------------|
| Pure Rust: a logos lexer (or one by hand where the language lexes by context), a hand-written recursive-descent or Pratt grammar on `opentide-parse`, a lossless rowan tree. No C, no `cc` or `*-sys` crate, no `unsafe`, no generated parser. A new language has a `.ungram` and `cargo xtask codegen`, unless its tree only highlights (Falco's and Exabeam's, beside their verdict parsers); kuery and Lucene, whose trees have a few kinds, predate the rule | [ADR 0012](../../../docs/internal/adr/0012-pure-rust-parsing.md), [`parser`](../parser/SKILL.md), [`crates/opentide-parse/AGENTS.md`](../../../crates/opentide-parse/AGENTS.md) |
| The depth contract: `Grammar::max_depth` (one `TooDeep`, the rest in one error node), `MAX_TREE_DEPTH` and `TreeTooDeep`; a new language's nesting floor is `NESTING_CEILING` (1 000 levels); every token class safe at 1 000 000 characters on a 1 MB stack; linear on broken input; recovery that never makes broken input noisier | ADR 0012 decision 4, [`parser`](../parser/SKILL.md) "Rules" |
| Catalogs: generated TOML in ADR 0013's form, built and indexed once in a `OnceLock`, read item by item through `opentide_core::catalog` (`array_items`, `preamble`, `compiled_in`), never `toml::from_str` on a whole file; included with `concat!(env!("OPENTIDE_ASSETS"), ...)`, which the crate's `build.rs` sets | [ADR 0013](../../../docs/internal/adr/0013-language-catalogs.md), [`catalogs`](../catalogs/SKILL.md) |
| Analysis: nothing shared copied per call (`HighlightSpec::shared()`, not `load()`); indexes and prepared suggestions built once per catalog; memos keyed by what they read and bounded; a cheap bound before an expensive measure; walk once, from where the answer is; measured with callgrind; held by work counts | [ADR 0014](../../../docs/internal/adr/0014-analysis-performance.md) §1 to §7 |
| One walk for the checks and the highlight: one preorder walk over every element, held by a count of element visits equal to the tree's element count. There is no shared walk in `opentide-parse` yet: write the crate's own on Lucene's `tree::walk_once` | ADR 0014 §5a (#1588) |
| Highlighting: HighlightSpec captures from the tree; a capture is appended, never renamed (a minor bump of `highlights/spec.toml`'s `[meta].version`); the TextMate grammar's keywords come from the `KEYWORDS` table, the Monaco and Helix themes from the spec's captures | [`parser`](../parser/SKILL.md) "Highlighting", [`crates/opentide-highlight/AGENTS.md`](../../../crates/opentide-highlight/AGENTS.md) |
| I/O and concurrency: no `std::fs` in an engine's `src/`; no `async` or tokio in the engine; CPU work on rayon, network I/O only on the one process runtime (#1558) | [`crates/AGENTS.md`](../../../crates/AGENTS.md) "Hard rules", [`rust-engine`](../rust-engine/SKILL.md) |
| Errors, panics and lints: no panic on user input, `thiserror` in the engine, `#[expect(..., reason)]` on the narrowest item, `missing_docs` for every new crate | [`rust-engine`](../rust-engine/SKILL.md), [`crates/AGENTS.md`](../../../crates/AGENTS.md) "Lints", [`rust`](../rust/SKILL.md) |
| The facade's semver: `LanguageId` is `#[non_exhaustive]` and `QUERY_LANGUAGES` a slice (ADR 0015 §6), so a new variant is additive: a minor release and an **Added** entry, not a **Breaking** one | [`crates/opentide/AGENTS.md`](../../../crates/opentide/AGENTS.md) |

## Checklist

`<id>` is the public language id (`kql`, `yaral`), `<Id>` its `LanguageId` variant.
`cargo test -p xtask --test language_wiring` lists, with its file, every table a query language
is missing from: its crate, codes, `ENGINE_REFERENCES`, the registry (its offline languages and
suffixes, and MCP's manifest lists), the output schema, `PARSER_CRATES`, `check-io-free.sh`, the
corpus directory, the `KEYWORDS` file, the throughput row and budgets, the fuzz target, matrix and
script, the WASM smoke sample, the npm client, the editors and the Python stub; MCP's
`default_language` has its own test. Run it after step 1 and again at the end. It does not see
the depth floors, the corpus gate's arms and lists, the external and oracle tests, the Tide and
highlight injection tables, `analyze_query`, the docs and changelogs, or the companions: read
those boxes with care. Steps 1 to 5
add arms to `match`es across the workspace. Outside `opentide-core` those `match`es have a
wildcard arm (`LanguageId` is non-exhaustive), so the compiler does not point at them: the
wiring test and `default_language` do, and the language works only at the end of step 5. Work
them on one branch and check each crate as you go (`cargo check -p <crate>`). Step 6's proofs run once it builds.

### 0. Decide what the language is

- [ ] **The language and its grammar.** Read the platform's model in `opentide-schema`
  (`src/objects/platform/<platform>.rs`), its deploy body in `opentide-compile`, its live check in
  `opentide-connectors` and its row in the registry
  ([`platforms.rs`](../../../crates/opentide-schema/src/platforms.rs): `runner_languages`,
  `offline_languages`). Where they name different languages (SentinelOne's rules are S1QL 2.0,
  while its `opentide query` runner is PowerQuery), settle which one the engine checks, for rule
  blocks and for hunts, in an issue before writing code.
- [ ] **The sources.** The grammar's reference, the field and function reference the catalogs
  come from, and public rules for the conformance corpus, each with its licence. Where one is not
  public, say so in the issue: the catalogs then hold only what the engine can state, and the
  public-rule step uses the vendor's published examples, or says none exist.
- [ ] **The names.** The id (lower case, the vendor's own short name, never `sql`), the
  `LanguageId` variant, the crate `opentide-<id>`, the code prefix `<id>_`, the file suffixes.

### 1. The id

- [ ] `LanguageId::<Id>` in `crates/opentide-core/src/lib.rs`: `as_str`, `parse`, `Display`, the
  serde rename, `from_extension` for each file suffix, and `QUERY_LANGUAGES`.
- [ ] Its diagnostic codes in `opentide_core::codes`, prefixed `<id>_`, each in `codes::ALL` and
  `codes::describe`; an unknown construct gets a stable code, not a free-form message.
- [ ] `scripts/engine/check-names.sh` passes (`opentide`, never `otide`; no `opentide-sql`).

### 2. The crate and the parser (`crates/opentide-<id>`)

- [ ] The crate: a member and a `[workspace.dependencies]` entry (`version = "=<workspace
  version>"`) in the root `Cargo.toml`; `readme = "../COMPONENT.md"`; Falco's `build.rs`
  (`OPENTIDE_ASSETS`); an `AGENTS.md`; crate docs (`missing_docs` holds).
- [ ] Its place: `xtask/layers.toml` (a query language is `foundation` tier 2, beside
  `opentide-cql`, unless it reads another language's grammar, as Lucene reads kuery's) and the
  `WORKSPACE` graph and crate count of `xtask/src/layers.rs`'s test; `cargo xtask check-layers`.
- [ ] Its name in `scripts/engine/check-io-free.sh` and in `scripts/ci/changes.py`'s
  `PARSER_CRATES` (without it, its pull requests never run the WASM job, where 1 MB-stack failures
  show).
- [ ] `SyntaxKind`, the lexer, the grammar, and (rules table) `src/<id>.ungram` with
  `src/generated/ast.rs` from `cargo xtask codegen`, as [`parser`](../parser/SKILL.md) lays them
  out. A plain `parses(text)` that builds the tree and nothing else (the bench's parse mode).
- [ ] The hidden hooks the corpus gate reads: `debug_kinds`, `debug_node_kinds` and
  `debug_error_kinds` (`opentide-kuery` has the shortest set).

### 3. Catalogs

- [ ] `data/catalogs/<id>/`, written by a `scripts/engine/sync_<id>_catalog.py` in ADR 0013's form
  (facts from upstream, summaries written here; `sync_falco_catalog.py` is the pattern), with the
  upstream's `NOTICE` or `LICENSE` beside it and listed in `pyproject.toml`'s `license-files`.
- [ ] `src/catalog.rs`: `Catalog::cached()` builds and indexes it once in a `OnceLock`, with no
  rayon, lock or other catalog inside the build. Two tests: the files read item by item equal
  `toml::from_str` of the whole files, and `cached()` loads the expected counts
  (`opentide-falco`'s `catalog.rs`).

### 4. Analysis and highlighting

- [ ] The analysis (diagnostics, hover, completion, signature help) in the crate, to ADR 0014:
  shared data borrowed, indexes and suggestion candidates prepared in the catalog's build, memos
  keyed by what they read (the catalog's identity among it) and bounded, cheap bounds before edit
  distances.
- [ ] The checks and the highlight in one walk (§5a), unless the highlight reads another text; say
  why in the crate's `AGENTS.md` if so.
- [ ] HighlightSpec captures (the crate's `highlight`); new captures appended to
  `highlights/spec.toml`'s `legend`, with a minor bump of its `[meta].version`.
- [ ] `crates/opentide-highlight/src/keywords/<id>.rs` (`KEYWORDS`), wired in `keywords.rs`
  (`mod`, `keywords()`, the test's language list); the comment pattern and TextMate scope in
  `crates/opentide-highlight/src/lib.rs`; the `tmLanguage` file `generate-highlights` writes
  (`crates/opentide-lsp/src/main.rs`); a test in the crate (`tests/keywords.rs`, as Exabeam's)
  that holds the table to the tokens the lexer cuts.

### 5. Wiring

- [ ] **Analysis.** `crates/opentide-analysis`: the dependency, and `LanguageId::<Id>` in
  `src/lib.rs`'s `analyze`, `analyze_query` (the CLI's, with a platform profile), `hover`,
  `completions` and `signature_help`. `opentide-tide` holds no hover, completion or signature help
  of its own: it only runs the engine on injected text and remaps the result.
- [ ] **`ENGINE_REFERENCES`** in `crates/opentide-analysis/src/queries.rs`: the code prefix and its
  reference. It decides that `opentide lint` reports the language's findings, and the reference
  each `opentide explain` page and code frame cites; no test fails without it.
- [ ] **Tide.** If a platform embeds the language: `crates/opentide-tide` (its dependency;
  `platform_field_language` in `src/lib.rs` for the block's query fields; `analyze_injections` in
  `src/lib.rs`, which runs the language on each injected query with its block or hunt context, the
  one place Tide calls an engine; `hunt_query_language` in `src/injection.rs` for a hunt's
  `system`; the docs table there), `crates/opentide-highlight`'s `EMBEDDED_QUERIES` (the TextMate
  grammar's injections), the injection table in
  [`docs/engine/ARCHITECTURE.md`](../../../docs/engine/ARCHITECTURE.md), and tokens remapped onto
  YAML coordinates after the block-scalar indent is stripped.
- [ ] **The registry**, [`platforms.rs`](../../../crates/opentide-schema/src/platforms.rs):
  `offline_languages` and `query_file_suffixes` (what `validate query` accepts), and its tests.
  `validate`'s `queries` check, `validate query` and MCP's `validate_query` read it.
- [ ] **The command line and MCP.** In `crates/opentide-cli`: `src/tree.rs`'s `SUFFIX_ORDER`
  (help order); `src/mcp/queries.rs`'s `default_language` (it falls back to `kql`) and its tests;
  `data/mcp/manifest.json`'s offline list; `data/output-schemas.json`'s `language` enum
  ([`mcp-server`](../mcp-server/SKILL.md), [`golden`](../golden/SKILL.md)).
- [ ] **Hosts and editors.** The language server's `Session::language_for`
  (`crates/opentide-lsp/src/session.rs`) needs no change, since it reads `LanguageId::parse` and
  `from_extension`, but its test in `src/server.rs` and an e2e frame in `tests/e2e_stdio.rs` take
  the language; `editors/helix/languages.toml`, `editors/nvim/opentide.lua`,
  `editors/zed/opentide.json`; `packages/lsp-client/src/index.ts` and its test
  ([`lsp-host`](../lsp-host/SKILL.md), [`wasm-hosts`](../wasm-hosts/SKILL.md)). The WASM build
  needs no export per language, but `scripts/engine/wasm-smoke.mjs` takes a sample.
- [ ] **Generated docs.** `opentide-compile`'s `src/generate/docs/platforms.rs` names the code
  fence of the platform's queries.

### 6. Proof

- [ ] **Corpus gate.** Fixtures under `crates/testdata/corpus/<id>/`, each tagged on its first
  line in the language's comment syntax (`// prod:<rule> valid`; a language without comments puts
  it on a `#` first line the gate strips, as Kibana KQL and Lucene do; `<rule>` is the snake_case
  of the `SyntaxKind`), a section in
  [`docs/engine/LANGUAGE.md`](../../../docs/engine/LANGUAGE.md), and the language in
  `crates/opentide-analysis/tests/corpus_gate.rs`: a `kind_names` arm, its tags, tokens and
  unlocated lists, and its own gate test with the structural kinds and their reasons. Every
  `__invalid` fixture must be rejected.
- [ ] **Shape.** Every corpus tree that parses without an error conforms to the `.ungram`
  (`tests/ast_conformance.rs` in the crate, as `opentide-eql`'s).
- [ ] **Depth and length.** In `crates/opentide-analysis/tests/deep_queries.rs`: the floors
  (`*_NEST_FLOOR = NESTING_CEILING`, `*_CHAIN_FLOOR`) and the language in the long-chain and
  precedence-chain tests. In the crate: `tests/parser_depth.rs`, the 1 000 000-character test of
  every token class on a 1 MB stack, and `tests/long_runs.rs`, which compares growth (n against
  4n), never an absolute time.
- [ ] **Baselines.** In `crates/opentide-analysis/tests/`: `parser_baseline.rs` (each file's
  diagnostics and tokens), `plain_parses.rs` (a row), `goldens.rs`, and
  `raw_query_composability.rs` (the same finding on a raw file and in the Tide block). Read every
  new snapshot before committing it.
- [ ] **Public rules.** `crates/testdata/conformance/external/<id>/`: unmodified public rules, a
  `<name>.broken.<ext>` twin with one injected fault each, the source and licence in `SOURCES.md`.
  A test of the language's own, `crates/opentide-analysis/tests/external_<id>.rs` (as
  `external_falco.rs`; `external_corpus.rs` is KQL's and SPL's), asserts the fault on the longest
  prefix that parses and a diagnostic on every broken file. Never delete a public rule because it
  does not parse yet.
- [ ] **Against the vendor.** Where the vendor publishes a parser or checker: a mode of
  `scripts/engine/oracles/oracle.py`, or a directory of its own under `scripts/engine/oracles/`
  (as `falco/` and `yara/`), `[[<id>]]` entries in `crates/testdata/oracles/exceptions.toml`, a job
  in `.github/workflows/oracle.yml`, and the reference's packages in
  `scripts/engine/license-scan.sh` (the reference never ships). Where only a tenant API checks
  queries, a tenant mode (Carbon Black's) is the differential. Where none exists,
  `scripts/engine/oracles/README.md` says why. A port of a reference checker also records its
  verdicts as a conformance corpus (Exabeam, Falco).
- [ ] **Work counts.** Each ADR 0014 optimisation held by a test that counts work and fails on the
  naive path (put the old path back and watch it fail), and §5a's element-visit count.
- [ ] **Throughput.** A row in the `LANGUAGES` table of
  `crates/opentide-analysis/benches/throughput.rs`, a row in
  [`docs/engine/THROUGHPUT.md`](../../../docs/engine/THROUGHPUT.md), and the language's
  instruction and allocation budgets in `tests/bench/instructions.toml`:
  `cargo xtask throughput --record --language <id>` (#1581). Its corpus figures are in the range of
  the other languages', and a callgrind of the warm loop shows no setup repeated per call.
- [ ] **Fuzzing.** `fuzz/fuzz_targets/<id>.rs` (`exercise` in `fuzz/src/lib.rs`), its `[[bin]]` in
  `fuzz/Cargo.toml`, the target in `.github/workflows/engine-fuzz.yml`'s matrix and in
  `scripts/engine/fuzz.sh`, its seeds row in `fuzz/README.md`; crashes it finds go in
  `crates/opentide-analysis/tests/fuzz_regressions.rs`.
- [ ] **The command line.** `crates/opentide-cli/tests/validate_query.rs` checks a query file of
  the language offline. A platform that gains an offline check changes `validate`'s and
  `validate query`'s output: the cases in `tests/golden/cases.toml` and their reviewed snapshots,
  the generated workspaces' queries (`xtask/src/corpus/`) and their snapshots
  ([`golden`](../golden/SKILL.md)). A new supported platform or MCP surface is a decision the
  issue of step 0 records, not only a snapshot update.

### 7. Docs, release and companions

- [ ] `docs/engine/<LANGUAGE>.md` (what is checked, and against which source; `FALCO.md` and
  `YARAL.md` are the models) and its page in `docs/engine/meta.json`.
- [ ] The lists that name every language: `src/opentide/_native/__init__.pyi`'s `Language`
  literal, `docs/engine/EDITORS.md`, `docs/cli/lsp.md`, `crates/opentide-analysis/benches/analyze.rs`,
  `crates/AGENTS.md` "Product" and its layer table,
  [`docs/engine/LANGUAGE-HARNESS.md`](../../../docs/engine/LANGUAGE-HARNESS.md)'s suffixes,
  `rust-engine`'s `LanguageId` list, `lsp-host`'s ids and suffixes, the `parser` skill's
  description, the oracles README.
- [ ] A platform's offline engine changed: the table in the root `AGENTS.md` "Platforms",
  `docs/cli/validate.md` and `docs/usage/concepts/platforms.md`. `docs/cli/diagnostics.md` comes
  from `cargo xtask codegen`.
- [ ] `CHANGELOG.md` `## [Unreleased]` ([`release-notes`](../release-notes/SKILL.md)) and
  `crates/CHANGELOG.md`, with the **Breaking** entry for the new `LanguageId` variant
  ([`engine-release-notes`](../engine-release-notes/SKILL.md)).
- [ ] The new crate's name in [`docs/internal/publishing.md`](../../../docs/internal/publishing.md):
  its first publish to crates.io needs the maintainers' token.
- [ ] A companion pull request on [opentidehq/skills](https://github.com/opentidehq/skills) (the
  platform skill, `coverage.json`), and one on opentidehq/vscode-extension (the language's id,
  suffixes and grammar), each linked from this one.

## Definition of done

- Every box above is ticked, or the pull request says why one does not apply.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo xtask check-layers`, `cargo xtask codegen --check`,
  `bash scripts/engine/check-io-free.sh`, `bash scripts/engine/check-names.sh`,
  `bash scripts/engine/validate-skills.sh` and
  `cargo run -p opentide-lsp -- generate-highlights --check` pass.
- `cargo nextest run --workspace --profile ci` and `cargo test --workspace --doc` pass
  ([`rust`](../rust/SKILL.md)); `cargo xtask throughput --check` passes with the new budgets;
  CI's `facade` job passes (`LanguageId` is non-exhaustive, so the new variant is no breaking
  change), and `crates/CHANGELOG.md` has its **Added** entry; the minor bump comes with the release.
- `scripts/ci-local.sh --full` passes (the root `AGENTS.md`, "Definition of done").
- The parser had an independent adversarial review before merging ([`parser`](../parser/SKILL.md),
  "Tests"): the reviews found the 1 MB-stack and quadratic-on-broken-input bugs the corpus did not.

## Dispatch

`Session::language_for` selects the engine from a reported language id, then from the URI suffix
(`LanguageId::from_extension`). A reported id the parser does not know is ignored and the suffix is
used. Raw query files are first-class documents with an empty Tide workspace;
`crates/opentide-analysis/tests/raw_query_composability.rs` holds a raw file and the same text in a
Tide block to the same finding.

## Out of scope

- Rewriting the server onto `tower-lsp` or an async runtime.
- Shipping a vendor's library (Kusto.Language, a Splunk SDK, `yara-x`) in the binary: references
  stay in CI.
- Validating a platform whose language is unspecified.
