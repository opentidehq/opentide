---
title: "0012: Pure-Rust parsing replaces tree-sitter"
description: "Full decommission of tree-sitter (#1219): logos + rowan + hand-written parsers on opentide-parse for the query languages, ungrammar typed ASTs, YARA-X's CST for YARA, a depth contract, and the differential harness as the gate."
---

# 0012: Pure-Rust parsing (logos + rowan + hand-written parsers) replaces tree-sitter

| | |
|---|---|
| Status | Accepted: full decommission (maintainer, 2026-11-14) |
| Date | 2026-11-14, amended 2026-11-16 |
| Decision | Epic [#1219](https://github.com/opentidehq/opentide/issues/1219) |
| Issues | [#1219](https://github.com/opentidehq/opentide/issues/1219), [#1221](https://github.com/opentidehq/opentide/issues/1221), [#1225](https://github.com/opentidehq/opentide/issues/1225), [#1266](https://github.com/opentidehq/opentide/pull/1266), [#1267](https://github.com/opentidehq/opentide/pull/1267), [#1279](https://github.com/opentidehq/opentide/pull/1279) |

Supersedes the language-server#89 decision to keep tree-sitter. Epic #1219 supersedes this ADR's
first draft: its "Phase A", "gate G1" and "hybrid fallback" are gone. Every language moves, all in
parallel, and tree-sitter is deleted at the end. Keeping tree-sitter for any language is not an
option. The kuery pilot is the branch `exp/pure-rust-parser-kuery`, commit `c691c409`.

## Context

The engine parses 11 query languages with tree-sitter grammars (`grammars/`, 6.14 MB of generated
`parser.c`, C scanners for CQL and ES|QL) through `crates/opentide-syntax`, the crate that holds one
of the workspace's two `unsafe` permissions. The first review (language-server#89, v0.7.1, 6
grammars) kept tree-sitter on cost: parsing was cheap, the binary saving small, a rewrite estimated
at 66–107 days. Since then the grammar count has gone to 11, and one of the review's listed triggers
has happened: new languages fit tree-sitter badly. YARA's reference parser is logos + rowan, and
Falco and Exabeam already have hand-written verdict parsers, so tree-sitter only highlights them. The
maintainer also asks for the decision to be made on philosophy and toolchain grounds: opentide is a
pure-Rust project.

What tree-sitter costs us today (checked on `integration/unified-core` at `be6159f9`):

| Cost | Where |
|---|---|
| A C toolchain on every build; `cc` in `opentide-syntax/build.rs` (2.5 s dev, 4.3 s release + 3–4.5 s runtime) | `crates/opentide-syntax/build.rs` |
| Node and `tree-sitter-cli@0.25.10` to regenerate grammars; the `grammars` CI job | `ci.yml` `grammars` |
| wasi-sdk downloaded, `libc.a` linked into the browser build, 7 `#[no_mangle]` syscall shims | `scripts/engine/build-wasm.sh`, `crates/opentide-wasm/src/libc_syscalls.rs` |
| `unsafe` FFI (12 sites) | `crates/opentide-syntax/src/lib.rs:16–84` |
| Error messages rebuilt from `ERROR`/`MISSING` nodes, ~350 LOC across 8 crates, never able to say what was expected | `parse_error_message` in cql, eql, esql, kuery, lucene; spl `parse_errors.rs`; yaral `parse_error` |
| One hang already found in error trees (zero-width `prev_sibling` cycle) | language-server#89 |
| We pin 0.25.10; upstream is 0.27.2 | root `Cargo.toml:119` |

What tree-sitter does **not** give us: incremental parsing is unused (`did_change` re-analyses the
whole text; every parse passes `None` as the old tree), and no editor loads the grammars. Helix,
Neovim and Zed configs in `editors/` use only the LSP; colour comes from semantic tokens and
generated TextMate grammars.

## Decision

### 1. Stack

| Piece | Choice | Evidence |
|---|---|---|
| Lexer | **logos 0.16.1** | Already in `Cargo.lock` via yara-x-parser; already builds for wasm32-unknown-unknown and wasip1; cargo-deny accepts it. `ignore(case)` covers ES|QL, SPL, Exabeam, YARA-L keywords. No lookaround: position-dependent keywords are resolved in the parser (the pilot does this for `or`/`and`/`not`) or with `morph` (yara-x uses three lexers). |
| Tree | **rowan 0.17.0** (not cstree) | Already in the lock; the same tree type yara-x-parser hands us; used by rust-analyzer, taplo, slint, apollo-parser. `SyntaxNode` is `!Send`, which we do not need: rayon workers each parse their own text and the LSP caches `Arc<AnalyzeResponse>`, never a tree. cstree (0.14) adds interning and Send we don't use. Watch rowan 0.18 (alpha.2, already used by rust-analyzer). |
| Incremental | **No salsa now** | No incremental reuse exists anywhere. salsa 0.28.5 needs MSRV 1.88 (fine) but pulls rayon and inventory into WASM. The cheaper win is a one-parse-per-(text, language) memo: KQL parses the same text three times today (`analyze`, `lower`, `query_captures`). Revisit only if the LSP adopts incremental analysis. |
| Parser | **Hand-written recursive descent + Pratt over a shared event/marker toolkit** (rust-analyzer / yara-x pattern), not chumsky | chumsky (0.14.1; there is no 1.0) has no lossless/rowan story and heavy generic compile times. The hand-written style gives direct control of recovery points and messages, which our oracles compare text by text; two hand-written parsers already ship (falco `parser.rs`, exabeam `check.rs`). |
| Errors | Expected-token sets accumulated by `at()`/`eat()`; one message per failure: "near `)`; expected `or`, `and`, or end of input" | Pilot: our tree-sitter code says only "near `)`". tree-sitter 0.25 *can* produce lookahead sets (`Language::lookahead_iterator`, `Node::parse_state`), so this is a quality gain of the rewrite, not something only a rewrite can deliver. |
| Trivia | Lossless: whitespace and comments are tokens in the green tree, skipped by lookahead | Pilot `Input`; byte spans stay exact for YAML injection remapping. |
| Depth | `Grammar::max_depth`: past it, one diagnostic and the rest of the input in one error node; n-ary `and`/`or` nodes so a 20k-term chain is flat | Pilot: 100k nested `(` → one diagnostic on a 1 MB stack; vendor limits (ES|QL 400/301, EQL 250, Falco 100) stay as analysis checks. |

**Why not tree-sitter.** Pure-Rust *parsing*: the browser build (wasm32-unknown-unknown) becomes
C-free, losing wasi-sdk's `libc.a` and the 7 syscall shims; `opentide-syntax`'s FFI `unsafe` goes;
the `grammars` job's Node + tree-sitter-cli goes. Error messages that say what was expected, with
recovery we control; no error-tree traps; context-sensitive lexing that our query languages need
everywhere (Kibana keywords, SPL commands, YARA hex strings) written as code rather than fought in a
GLR grammar; one pattern for all 13 engines instead of two (falco and exabeam are already
hand-written).

**Scope of "pure Rust", stated honestly.** Native builds and the WASI CLI (wasm32-wasip1) still
compile C after this ADR: `ring 0.17.14` (via `jsonwebtoken` → `opentide-connectors`, `rustls` →
`reqwest`, `rcgen` → `opentide-cassette`) builds with `cc`, and `build-wasm.sh` keeps wasi-sdk's
clang for wasip1. A C-free build of everything is a separate decision about crypto/TLS
(`jsonwebtoken`'s `rust_crypto` backend is cheap; a pure-Rust rustls provider is not mature) and is
not claimed here. Node stays for bindings/node, packages/ and docs.

**What is lost.** A declarative grammar file a reader can scan; tree-sitter's generic error
recovery (ours must be written per rule); a query language (`.scm`) for highlights; the option of
contributing grammars to nvim-treesitter / Helix / Zed / GitHub Linguist (unused today: no editor
config loads them); incremental reparsing (unused). Exact error messages and ranges on **broken**
input change (pilot: 4,967 of 6,591 broken inputs differ in some surface, verdicts identical).

### 2. Shared toolkit: `crates/opentide-parse`

One crate, foundation layer beside `opentide-syntax`, language-agnostic, no `unsafe`. Pilot: 445
LOC + 113 test LOC.

- `TokenSet` (a 512-kind bitset; a kind past the capacity panics, never vanishes); `Grammar { eof, error, trivia, max_depth }`.
- `lex::<T: Logos>` token source (on a lexer error, takes one char and resumes).
- `Parser`: `nth/current/at/at_set/eat/expect/bump/bump_as/error/err_and_bump/err_until/start/enter/exit/finish`, fuel against stuck loops, expected-set accumulation.
- `Marker`, `CompletedMarker::precede` (left-assoc / Pratt), `Event` (Start with forward_parent, Token, Finish, Error, Tombstone).
- `build()` → rowan `GreenNode` + `SyntaxError { message, expected, gap }`.
- `debug_tree()` for insta tree snapshots; a differential harness helper (old vs new analyze).

The case for sharing: the toolkit is 445 lines written once. Without it each of 11 languages repeats
the event buffer, marker, trivia, expected-set and depth logic (~300–400 lines each in yara-x's
`parser/mod.rs` + `token_stream.rs`), i.e. ~3.5–4.5k duplicated lines. With it, kuery's language
part was 185 lines of grammar functions + 189 of kinds/lexer.

### 3. Pilot results (kuery, `c691c409`)

| Measure | tree-sitter | pure Rust |
|---|---|---|
| Hand-written LOC (kuery crate, code only) | 760 + 119 grammar.js + 28 `.scm` | 1,173 (parser 185, kinds/lexer 189, analysis 665, ECS 134) + 445 toolkit |
| Generated / vendored deleted (kuery share) | 94 KB (`parser.c` 42.5 KB, `grammar.json`, `node-types.json`) | 0 |
| Parse, median, 301 valid queries | 1.50 µs | 0.77 µs |
| Analyze, median, 301 valid queries | 10.8 µs | 6.2 µs |
| Analyze, 2,000-term OR chain | 10.9 ms | 2.0 ms |
| Release `opentide-lsp` | 28,335,400 B | +62.7 KB (kuery's `parser.c` still linked via Lucene) |
| Clean build of the crate alone | 23.2 s | 32.3 s (logos-codegen; the workspace already pays it via yara-x) |
| WASM size | not measured (target not installed) | — |

Gates, all green: nextest `ci` on kuery, parse, highlight, analysis, lsp, syntax, lucene (409
passed); `opensearch_dashboards_cases`; `deep_queries`; LSP `e2e_stdio` + protocol; analysis
goldens and snapshots; `elastic_corpus`; corpus gate; `generate-highlights --check`; clippy, fmt,
layers. 200k random strings: no panic, no hang. Not run: cargo-fuzz (no nightly), `kibana_oracle`
(no Kibana verdict file locally).

**Differential, 12,475 inputs** (corpus, OpenSearch cases and twins, test literals, Elastic fixtures,
every prefix, mutations, random sentences): 5,884 valid inputs, **zero** differences in
diagnostics, tokens, ECS, fields, hover at every offset and completions (24 duplicate warnings the
old walk emitted twice now appear once). 6,591 broken inputs: **identical verdicts**; messages or
ranges differ on 3,503 first errors, mostly more precise:

| Query | tree-sitter | pure Rust |
|---|---|---|
| `a:1)` | near `)` | near `)`; expected `or`, `and`, or end of input |
| `:x` | near `:` | near `:`; expected a value, `not`, or `(` |
| `C:\Windows` | near `\` | near `\`; expected a value, `(`, or `{` |
| `a and (b:` | near `and` (2..9) | a value is missing after `(b:` |
| `message:"failed login` | quoted string never closed (0..21) | same (8..21) |
| `a:1 b:2` | no implicit `and` (0..6) | same (5..6) |
| `a:{}` | the query ends too early | near `}`; expected a value, `not`, or `(` |

The hard parts were not the grammar: context keywords, a non-backtracking lexer, deep-tree drops,
and matching tree-sitter's hover quirks. About half the effort went to exact parity on valid input.

**Against #89's exit criteria:** corpus gate and (local) oracle parity ✅; `deep_queries` on 1 MB ✅;
messages at least as specific ✅ (more specific); **net lines removed ❌ for hand-written code** (+413
in kuery, +445 toolkit once), ✅ counting generated code. The ADR accepts this: generated C is the
cost being removed.

### 4. Highlighting without `highlights.scm`

- Each engine maps its rowan tree to HighlightSpec captures in Rust: `fn capture(token, parent) ->
  Option<Capture>`; the pilot replaces 28 `.scm` lines with 30 Rust lines. Output stays
  `Vec<HighlightToken>`, so `tokens_from_spans`, `encode_lsp_semantic_tokens` and the LSP's
  semantic tokens are untouched.
- The capture names in `highlights/spec.toml` stay the frozen contract; a capture used by an engine
  must exist in the spec (a unit test per language).
- TextMate/Monaco/Helix maps: `generate_tm_language` today regex-scrapes `"kw" @capture` pairs from
  the `.scm`. Each language instead has a keyword table (`KEYWORDS: &[(&str, Capture)]`) in
  `opentide-highlight` (`keywords.rs`, #1291), which the generators read: the language crates sit
  a tier above it and depend on it, so the table cannot live in them. Each language crate's tests
  check the table against its logos lexer. The generated files must stay byte-identical:
  `generate-highlights --check` and the `textmate` job prove it.
- yara keeps yara-x-parser's CST for highlight, folding and paren pairs (see decision 7.3).

### 5. Migration plan

**The toolkit's three fixes landed with it** ([#1266](https://github.com/opentidehq/opentide/pull/1266)):
`TokenSet` holds 512 kinds and panics past that; fuel exhaustion is the `Stalled` diagnostic and a
debug panic; every language's `max_depth` accepts what its tree-sitter engine accepted, up to the
1,000-level nesting ceiling (decision 7.4).

**No phases, no gate.** The first draft piloted ES|QL behind a decision gate (G1) and kept a hybrid
(tree-sitter for the six expression and pipe grammars) as the fallback. Epic #1219 replaces that
with one prerequisite stage (stage 0, #1221), then every language in parallel (stage 1, one session
each, each owning only its crate and its `grammars/` directory), then one deletion stage (stage 2).
A language that runs past about 3,000 hand-written parser lines, or keeps a parity gap after a day,
reports at a checkpoint and the orchestrator decides how to finish it. The hybrid is not a fallback.

**Stage 0, gates first (before any language, #1221).** (a) A parser-swap baseline: for every
corpus, conformance and `.broken.` file of every language, an insta snapshot of diagnostics (code,
range, message) and tokens, recorded on tree-sitter. (b) `deep_queries` for kql, spl, cql, yaral,
yara, exabeam. (c) Highlight goldens for yara and yaral. (d) The `wasi` and browser WASM builds on
PRs touching any language crate (`scripts/ci/changes.py`). (e) The corpus gate's `prod:<rule>`
re-expressed through a per-language kind-name table. (f) `opentide-parse` (landed, #1266). (g) This
ADR. (h) The `KEYWORDS` interface for the highlight generators. (i) Typed AST codegen from
`.ungram` files.

**Per language, one series of ≤500 hand-written lines per PR:** (1) kinds + lexer + keyword table + `.ungram`;
(2..n) grammar functions with tree snapshots, plus the test-only differential (old analyze kept as
`tests/legacy`) over every corpus file, prefixes and mutations; (last) analysis on rowan, highlight
mapping, tree-sitter dependency removed from the crate, the language's grammar dir deleted,
baseline snapshots updated only for broken input, each change a reviewed snapshot diff (the
Rust-owned snapshot suite, #1139; byte parity with the Python oracle is not required, #1121). Exit: zero differences on valid input; identical
verdicts on broken input; messages at least as specific; fuzz smoke and the local oracle run by hand.

Order and estimate of the first draft (sequential, scaled from the pilot: kuery 2.5 agent-hours to a
parity branch, ~1 day to land through review). Under #1219 the languages run in parallel, about 2
days end to end, and the yara row is replaced by decision 7.3:

| # | Language | Why here | grammar.js / nav calls | PRs | Days |
|---|---|---|---|---|---|
| 1 | kuery | pilot exists | 119 / 26 | 3 | 1 |
| 2 | lucene | small; kuery and lucene cross-parse each other, so both leave `opentide-syntax` together | 137 / 78 | 3 | 2 |
| 3 | falco | highlight + `fields()` only; verdicts already hand-written | 194 / 3 | 2 | 1 |
| 4 | exabeam | highlight only; verdicts in `check.rs` | 233 / 3 | 2 | 1 |
| 5 | eql | small expression grammar, has an oracle | 273 / 131 | 3–4 | 2–3 |
| 6 | yara | reuse yara-x-parser CST; pre-lexer for libyara-only forms | 468 / 9 | 3 | 2–3 |
| 7 | cql | C scanner to replace with a lexer mode | 554 / 74 | 4–5 | 3–4 |
| 8 | yaral | no oracle; all keywords case-insensitive | 497 / 165 | 5–6 | 4–6 |
| 9 | esql | C scanner, contextual keywords, depth checks | 633 / 175 | 6–7 | 5–7 |
| 10 | spl | 140 lines of error reconstruction; per-command syntax | 1019 / 58 | 7–9 | 6–9 |
| 11 | kql | biggest grammar, three parses per analysis | 860 / 208 | 7–9 | 7–10 |
| F | final | delete `grammars/`, `opentide-syntax` (or its tree-sitter half), `cc`, the `grammars` CI job, wasi-sdk + `libc_syscalls.rs`, the tree-sitter skill; rewrite LANGUAGE-HARNESS step 2, add-language skill, ARCHITECTURE, AGENTS.md; `forbid(unsafe_code)` widened | — | 3 | 2–3 |

Total ≈ 48–60 PRs, **~39–54 working days** if done one after the other. The previous 66–107-day
estimate was for human-written parsers; the pilot suggests agent implementation is 5–10× faster on
grammar work but review-bound. Run in parallel, #1219 plans about 2 days end to end. Treat the
large-language numbers as ±50 % until lucene and eql land.

### 6. CI proof

Existing gates that prove outside behaviour unchanged (all on PR via `ci.yml` `build`, which runs
the changed crates and reverse dependencies with `INSTA_UPDATE=no`): corpus gate
(`opentide-syntax/tests/corpus_gate.rs`); external conformance and `.broken.` twins (analysis
`external_corpus`, `elastic_corpus`, `external_cql/falco/exabeam/elastic`, `tide_corpus`,
`yara/conformance.rs`, `yaral/external_corpus.rs`, lucene `lucene_queryparser_cases.rs`,
`graylog_verdicts.rs`, falco `libsinsp_parser.rs`); analysis `snapshots.rs` and `goldens.rs`;
`deep_queries.rs`; LSP `e2e_stdio`, `protocol`, `message_session`; the Rust-owned snapshot suite (#1139; `command_goldens.rs`
and `APPROVED_DIFFS.toml` left CI in #1121); fuzz regressions; `textmate`; `wasi` (when its paths change). By hand per
language: `oracle.yml` references via `scripts/engine/ci-oracle.sh` (Kusto, Splunk, @elastic/esql,
EQL, kuery peggy, Lucene, Falco, libyara/YARA-X; none for CQL, Exabeam, YARA-L), fuzz smoke.

Missing at the time of the first draft, added in stage 0: full-corpus diagnostics + token snapshots (snapshots cover only eql,
kql, spl; highlight goldens one sample per language, none for yara/yaral); deep queries for 6
languages; a language-neutral corpus gate; WASM on language PRs; folding/selection-range snapshots
for yara. Per language, the test-only differential (old vs new diagnostics, tokens, fields, hover,
completions over every corpus file, its prefixes and mutations) gates the switch and is deleted
with the old code.

### 7. Decisions since the first draft

1. **ungrammar for typed AST accessors.** `ungrammar` 1.16.1 (zero dependencies; rust-analyzer's grammar DSL, kept in its tree) is a build-time input of `xtask` only, never a dependency of a product crate. A `.ungram` per language is the readable spec of its tree shape. `cargo xtask codegen` turns it into typed wrappers over rowan, committed and checked by `codegen --check`. A conformance helper in `opentide-parse` checks that every corpus tree matches its `.ungram`. It applies to KQL, SPL, ES|QL, EQL, CQL and YARA-L, and optionally to kuery and Lucene. It is not used for Falco, Exabeam and YARA. It is not a parser generator: the parsers stay hand-written, so the recovery-control decision stands.
2. **`text-size` spans.** Every span in a new engine is rowan's `TextRange`/`TextSize`; UTF-16 is converted only at the LSP edge, by `opentide-core`.
3. **YARA targets YARA-X.** YARA keeps `yara-x-parser`'s CST and `yara-x-fmt`, for highlighting, folding, paren pairs and its semantic pass. The libyara-dialect emulation is removed entirely: the pre-lexer that blanked libyara-only forms, `Dialect::Libyara` and `yara_x_incompatible`. YARA-X's module reflection is the only source of the module catalogue. YARA-X-only syntax is gated by one portability check per platform profile (`yara_x_syntax: allowed | refused`, both starting at `refused`), not by a second grammar. libyara is not emulated; the YARA-X wheel is the by-hand oracle. The spec change is opentidehq/specifications#93 and the scope is in [#1225](https://github.com/opentidehq/opentide/issues/1225). This supersedes the first draft's "pre-lexer for libyara-only forms".
4. **A depth contract: `MAX_TREE_DEPTH` and `TreeTooDeep` (#1266).** Depth is bounded in two places, so no input recurses without bound or overflows a 1 MB stack. First, `Grammar::max_depth` bounds recursion in a language's own grammar functions: past it, `Parser::enter` returns `false`, one `TooDeep` diagnostic is reported, and the rest of the input goes into one error node. Second, `MAX_TREE_DEPTH` (4,096 nodes) bounds the tree `build` produces, including a `precede` loop (`a + b + c …`) that never calls `enter`: nodes past the limit are not opened, their tokens go to the node at the limit, and one `TreeTooDeep` diagnostic is reported. Chains stay flat: `a or b or c` is one n-ary node, because rowan drops a green tree recursively. The toolkit itself (`build`, `debug_tree`) is iterative. Each language's floors are recorded in `crates/opentide-analysis/tests/deep_queries.rs` (#1279): the longest flat chain and the deepest nesting its tree-sitter engine analysed on a 1 MB stack. A language's `max_depth` is at or above its nesting floor, and its chains stay at or above its chain floor. The vendor depth limits (ES|QL 400/301, EQL 250, Falco 100) stay as analysis checks on top.

   **The nesting ceiling.** For nesting, the floor is `min(tree-sitter edge, 1,000)` (`NESTING_CEILING`; the decision is recorded on #1219). Tree-sitter accepted 10,000 levels or more (the probe cap) for SPL, CQL, ES|QL, EQL, kuery, Lucene and YARA-L, only because its parse and the old walks are iterative. A recursive descent on this toolkit and the rowan tree it builds cannot hold that on the 1 MB stack of the browser WebAssembly module: a minimal two-function grammar overflows near 6,000 levels in a debug build, and rowan drops about 10,000 levels. 1,000 is above every vendor limit known, so the only queries the ceiling refuses are ones no vendor accepts; past its `max_depth` a parser reports one `TooDeep` diagnostic. The floors below the ceiling (KQL 35, Falco 18, Exabeam 199, YARA 495) are kept as measured. Raising a language later is local to its grammar (an explicit stack for its nesting rule and a teardown of its deep trees).
5. **The differential harness is the gate (#1267).** A language switches only when a test-only differential, old engine against new, over every corpus file, its prefixes and its mutations, shows zero differences on valid input (diagnostics, tokens, fields, hover at every offset, completions) and identical verdicts on broken input, with messages at least as specific. A changed message on broken input is a reviewed snapshot diff in the Rust-owned suite (#1139). The harness and the old engine are deleted with the language's tree-sitter code.
6. **"Pure Rust" means parsing and the browser WASM build.** wasm32-unknown-unknown loses wasi-sdk's `libc.a` and the 7 syscall shims; `opentide-syntax`'s FFI `unsafe` goes; the `grammars` job's Node and tree-sitter-cli go. Native builds and the WASI CLI keep compiling C through `ring` (jsonwebtoken, rustls, rcgen), which this ADR does not touch. Removing it is a separate crypto/TLS decision.
7. **Small additions.** A `Marker` must be completed or abandoned, checked by a `debug_assert!` in `Drop` and no extra dependency. Per-file baseline and differential snapshots use insta `glob!`. Parser fuzz targets generate from token kinds, not only random bytes. Not added: salsa, cstree, chumsky, pest, lalrpop, nom, winnow, lady-deirdre, annotate-snippets, miette, codespan, expect-test, `line-index`, interning, rowan 0.18 (alpha; revisit when stable).

## Counter-arguments (independent adversarial review, arguing to keep tree-sitter)

| # | Argument | Weight | Response |
|---|---|---|---|
| 1 | "Pure Rust / no C / no wasi-sdk" is false for native and WASI: `ring` compiles C | **Decisive against the original wording** | Accepted; claim scoped to parsing and the browser build (above). Full C-freedom is a separate crypto decision. |
| 2 | kuery is the least representative grammar (19 rules, 32 tokens vs KQL 85/172, SPL 82/225, ES\|QL 90/105); by the pilot's ratio KQL needs 1.7–2.7k and SPL 1.6–3.2k hand-written parser lines; 9.6–14.2k for all but yara, replacing ~4.5k lines of grammar.js | **Strong** | Accepted as a cost. The G1 pilot gate is dropped (#1219): a checkpoint at about 3k hand-written lines per language reports to the orchestrator instead. |
| 3 | `TokenSet` u128 can't hold KQL/SPL kinds | Bug | Fixed in #1266. |
| 4 | tree-sitter already exposes lookahead sets; expected messages don't need a rewrite | **Strong** | Accepted as fact. The rewrite is still justified by recovery control, toolchain and one engine pattern, not by messages alone. |
| 5 | Maintainability: grammar.js is a readable spec; hand-written parsers drift silently; net hand-written lines grow (#89 criterion fails) | Mitigable | Each parser keeps the vendor grammar as doc comments per function; tree snapshots + oracles detect drift; the #89 line criterion is consciously replaced by "generated code removed". |
| 6 | 75 % of broken inputs change on some surface; users type in broken states | Mitigable | Baseline snapshots of broken input in stage 0, changes are reviewed snapshot diffs (#1139), not ledger entries; the bar is messages at least as specific. |
| 7 | Gains not shown: binary +62.7 KB, crate build slower, WASM/fuzz/Kibana oracle not run; speed moves no unified-core §11 metric | Partly accepted | Speed is not a reason for this ADR. WASM, fuzz and the oracles are measured per language at its exit and in stage 2. |
| 8 | Fuel exhaustion and a new depth limit hide failures | Bug | Fixed in #1266. |
| 9 | Opportunity cost; 39–54 (to ~80) days | Weaker than stated | The review's premise was stale: UC-1 → UC-6 are done; the remaining work is the 1.0 RC. The maintainer decided on 2026-11-14 to start once the agent-usage budget allows. |
| 10 | Hybrid: hand-write only falco, exabeam, yara | Rejected | Superseded by #1219: full decommission. Keeping tree-sitter is not an option. |

Reviewer's conditions for approval were a wide `TokenSet` (done), the C claim corrected (done) and
the work ranked against UC-1/UC-2 (maintainer: decided in #1219). A large-language pilot, a
`LookaheadIterator` comparison and the hybrid are dropped with gate G1.
