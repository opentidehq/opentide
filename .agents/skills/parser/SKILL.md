---
name: parser
description: Write and change opentide's pure-Rust query parsers (KQL, SPL, ES|QL, EQL, Kibana KQL, Lucene, Falco, CQL, Exabeam, YARA-L, Datadog) on crates/opentide-parse - a logos lexer, a hand-written recursive-descent or Pratt grammar into a lossless rowan tree, the .ungram and its typed AST (cargo xtask codegen), the KEYWORDS table the TextMate generator reads, the depth and stack limits, recovery, the corpus gate and the parser tests. YARA reads yara-x-parser's CST. Use when editing a language crate's lexer, parser, syntax kinds, .ungram, highlight captures or keyword table, crates/opentide-parse, or crates/opentide-highlight/src/keywords/.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Pure-Rust parsers

Every query language parses in Rust (ADR 0012, `docs/internal/adr/0012-pure-rust-parsing.md`,
epic #1219): a lexer ([logos](https://docs.rs/logos), or by hand where the language lexes by
context) and a hand-written grammar over the toolkit
`crates/opentide-parse` (`crates/opentide-parse/AGENTS.md`, on rust-analyzer's pattern), into a
lossless [rowan](https://docs.rs/rowan) tree. YARA is the exception: it reads
`yara-x-parser`'s CST and AST (YARA-X is the language, #1225). There is no C, no tree-sitter
and no generated parser in the repository; tree-sitter left in #1231 (the grammars it used are in
git history, last at `5608d3c7`, `grammars/tree-sitter-opentide-<id>/grammar.js`, where a
comment still names them).

Read `crates/opentide-parse/AGENTS.md` before changing a parser: the toolkit's invariants
(lossless, finite on every input, iterative, markers) are the rules every grammar keeps.

## A language's files

| Part | Where |
|------|-------|
| `SyntaxKind` (token kinds first, below `TokenSet::CAPACITY`, 512, then node kinds), `Lang` (the `rowan::Language`), `SyntaxNode`/`SyntaxToken` | `src/syntax.rs`; SPL `src/syntax/kind.rs` |
| The lexer: whitespace and comments are trivia kinds, never `skip`ped | `src/lexer.rs` (KQL, ES\|QL, EQL, CQL, YARA-L, Datadog); SPL `src/syntax/lexer.rs`; kuery, Lucene, Falco and Exabeam in `src/syntax.rs`. CQL and ES\|QL lex by context (modes), Lucene by hand without logos; Exabeam's lexer is context-free and its parser glues the pieces |
| The grammar: one function per production, `Marker`s, `enter`/`exit` around every recursive rule | `src/parser.rs` or `src/parser/`; SPL `src/syntax/parser.rs`; Falco and Exabeam `src/cst.rs` |
| `src/<lang>.ungram`, and `src/generated/ast.rs` that `cargo xtask codegen` writes from it (`codegen --check` in CI) | KQL, SPL, ES\|QL, EQL, CQL, YARA-L, Datadog; kuery, Lucene, Falco and Exabeam have none (small trees, or highlighting only) |
| `KEYWORDS`: the keywords and punctuation the TextMate grammar lists, each with its HighlightSpec capture | `crates/opentide-highlight/src/keywords/<lang>.rs`, every query language |

Falco and Exabeam keep a hand-written verdict parser (the ports of libsinsp's parser and of the
specification's reference checker): their CST (`src/cst.rs`) is for highlighting and fields, and
recovers rather than reports.

## Rules

- **Lossless.** The tree's text is the source, on every input. A corpus test asserts it per file.
- **Depth.** Every recursive rule calls `enter` (and stops when it returns `false`); chains are
  flat n-ary nodes (`a or b or c` is one node). `max_depth` is at or above the language's floor
  in `crates/opentide-analysis/tests/deep_queries.rs` (`*_NEST_FLOOR`: `NESTING_CEILING`, 1 000
  levels, for most; KQL 254; the lower floors the old engine had for Falco 18, Exabeam 199 and
  YARA 495). Past it, one
  `TooDeep` diagnostic, never a stack overflow.
- **1 MB stack.** The browser module runs on a 1 MB stack. A logos regex with a repeated group
  recurses once per repetition: every token class is tested at 1 000 000 characters on a 1 MB
  stack (each crate's lexer tests, ES|QL's `a_million_character_token_does_not_overflow_the_stack`).
- **Linear.** No quadratic walk over broken input (recovery that rescans, an error walk per
  token): `deep_queries.rs` parses 20 000-term chains of every language (`*_CHAIN_FLOOR`), and
  the `tests/long_runs.rs` of CQL, Datadog, EQL, Exabeam, Falco, kuery, Lucene and YARA-L time long
  inputs.
- **Recovery.** Kibana and the vendors read nothing past the first error: advice (hints,
  warnings) on a fragment recovery rebuilt is noise. Broken input must not get noisier.
- **No panic on user input.** `unwrap`/`expect` are for tests (workspace lints). A grammar loop
  that does not consume runs out of fuel (`Stalled`), and debug builds panic on it, so tests
  catch it.
- **Keywords.** A keyword the parser reads out of a word (`bump_as`) is a kind of its own, so the
  tree and the highlighter tell it apart. The TextMate grammar lists only the `KEYWORDS` table;
  a lexer test holds the table to the tokens the lexer cuts.

## Typed AST (`.ungram`)

Navigate the tree through the generated accessors (`WhereOp::predicate()`), not by walking
children by kind. `crates/opentide-parse/AGENTS.md` ("The typed AST") has the generator's rules:
label a node type that repeats in one rule, label tokens you need apart. Each of the six
languages with a `.ungram` checks every corpus tree that parses without an error against it
(`opentide_parse::conformance::check` or `assert_conforms` with the generated `RULES`: the
`tests/ast_conformance.rs` of CQL, ES|QL and EQL, SPL's `tests/conformance.rs`, the corpus tests
of KQL and YARA-L), so a parser
change that breaks the documented shape fails.

## Corpus gate

Every production is covered by a fixture under `crates/testdata/corpus/<id>/`, tagged on its
first line (`// prod:take_operator valid`). `crates/opentide-analysis/tests/corpus_gate.rs`
reads each language through its crate's hidden `debug_kinds` / `debug_node_kinds` (KQL,
CQL and ES|QL through their own names): every node kind is tagged or listed as structural, each
`<rule>__valid` fixture parses and contains its rule, and each required rule has a valid and an
invalid fixture. A new language tags its fixtures with its own `SyntaxKind` names. The older
languages' tags are the rule names their fixtures were first written for; a kind spelt
otherwise is translated in the gate's table (`EQL_TAGS`, `YARAL_TAGS`, `YARA_TAGS`), and a token
counts only as a production the language lists in its `*_TOKENS`. A new node kind gets a fixture
or a structural entry with the reason.

`crates/opentide-analysis/tests/parser_baseline.rs` snapshots every testdata file's diagnostics
and tokens: a parser change that moves them is a reviewed snapshot diff
(`INSTA_UPDATE=always cargo test -p opentide-analysis --test parser_baseline`, then read it),
never an unread `cargo insta accept`.

## Highlighting

The analysis colours tokens from the tree (each crate's `highlight`), with HighlightSpec
captures (`highlights/spec.toml`; a new capture is an append-only change and a minor bump of its
`[meta].version`). The TextMate grammar's keywords are generated from the `KEYWORDS` tables, and
the Monaco and Helix themes from the spec's captures:

```bash
cargo run -p opentide-lsp -- generate-highlights          # write highlights/generated/
cargo run -p opentide-lsp -- generate-highlights --check  # CI: the committed files are current
```

## Tests

```bash
cargo nextest run --profile fast -p opentide-<lang>
cargo test -p opentide-analysis --test corpus_gate --test parser_baseline --test deep_queries
cargo xtask codegen --check
cargo test -p opentide-highlight
```

A parser PR gets an independent adversarial review before it merges (#1219's protocol): the
reviews found the 1 MB-stack and quadratic-on-broken-input bugs the corpus did not.
