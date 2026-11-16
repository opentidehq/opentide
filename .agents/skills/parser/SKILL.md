---
name: parser
description: Write and change opentide's pure-Rust query parsers (KQL, SPL, ES|QL, EQL, Kibana KQL, Lucene, Falco, CQL, Exabeam, YARA-L) on crates/opentide-parse - a logos lexer, a hand-written recursive-descent or Pratt grammar into a lossless rowan tree, the .ungram and its typed AST (cargo xtask codegen), the KEYWORDS table the TextMate generator reads, the depth and stack limits, recovery, the corpus gate and the parser tests. YARA reads yara-x-parser's CST. Use when editing a language crate's lexer, parser, syntax kinds, .ungram, highlight captures or keyword table, crates/opentide-parse, or crates/opentide-highlight/src/keywords/.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Pure-Rust parsers

Every query language parses in Rust (ADR 0012, `docs/internal/adr/0012-pure-rust-parsing.md`,
epic #1219): a [logos](https://docs.rs/logos) lexer and a hand-written grammar over the toolkit
`crates/opentide-parse` (`crates/opentide-parse/AGENTS.md`, on rust-analyzer's pattern), into a
lossless [rowan](https://docs.rs/rowan) tree. YARA is the exception: it reads
`yara-x-parser`'s CST and AST (YARA-X is the language, #1225). There is no C, no tree-sitter
and no generated parser in the repository; tree-sitter left in #1231 (the grammars it used are in
git history, last at `5608d3c7`, `grammars/tree-sitter-opentide-<id>/grammar.js`, where a
comment still names them).

Read `crates/opentide-parse/AGENTS.md` before changing a parser: the toolkit's invariants
(lossless, finite on every input, iterative, markers) are the rules every grammar keeps.

## A language's files

| File | What |
|------|------|
| `src/syntax.rs` (or `src/syntax/kind.rs`) | `SyntaxKind`: token kinds first (below `TokenSet::CAPACITY`, 512), then node kinds; `Lang`, the `rowan::Language`; `SyntaxNode`/`SyntaxToken` |
| `src/lexer.rs` | the logos token type (whitespace and comments are trivia kinds, never `skip`); hand-driven modes where the language lexes by context (CQL, ES|QL, Exabeam) |
| `src/parser.rs` or `src/parser/` | the grammar: one function per production, `Marker`s, `enter`/`exit` around every recursive rule |
| `src/<lang>.ungram` | the readable spec of the tree; `cargo xtask codegen` writes `src/generated/ast.rs` from it (`codegen --check` in CI) |
| `crates/opentide-highlight/src/keywords/<lang>.rs` | `KEYWORDS`: the keywords and punctuation the TextMate grammar lists, each with its HighlightSpec capture |

Falco and Exabeam keep a hand-written verdict parser (the ports of libsinsp's parser and of the
specification's reference checker): their CST (`src/cst.rs`) is for highlighting and fields, and
recovers rather than reports.

## Rules

- **Lossless.** The tree's text is the source, on every input. A corpus test asserts it per file.
- **Depth.** Every recursive rule calls `enter` (and stops when it returns `false`); chains are
  flat n-ary nodes (`a or b or c` is one node). `max_depth` is at or above the language's floor
  in `crates/opentide-analysis/tests/deep_queries.rs` (`NESTING_CEILING`, 1 000 levels, or the
  lower floor the old engine had: KQL 35, Falco 18, Exabeam 199, YARA 495). Past it, one
  `TooDeep` diagnostic, never a stack overflow.
- **1 MB stack.** The browser module runs on a 1 MB stack. A logos regex with a repeated group
  recurses once per repetition: every token class is tested at 1 000 000 characters on a 1 MB
  stack (each crate's lexer tests, ES|QL's `a_million_character_token_does_not_overflow_the_stack`).
- **Linear.** No quadratic walk over broken input (recovery that rescans, an error walk per
  token): the crate's `long_runs` tests time 20 000-term chains.
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
label a node type that repeats in one rule, label tokens you need apart. A corpus test runs
`opentide_parse::conformance::assert_conforms(&root, RULES, GRAMMAR)` on every tree that parses
without an error, so a parser change that breaks the documented shape fails.

## Corpus gate

Every production is covered by a fixture under `crates/testdata/corpus/<id>/`, tagged on its
first line (`// prod:take_operator valid`). `crates/opentide-analysis/tests/corpus_gate.rs`
reads each language through its crate's hidden `debug_kinds` / `debug_node_kinds` (KQL,
CQL and ES|QL through their own names): every node kind is tagged or listed as structural, each
`<rule>__valid` fixture parses and contains its rule, and each required rule has a valid and an
invalid fixture. Tags are the tree-sitter rule names the fixtures were written for; a kind spelt
otherwise is translated in the gate's table (`EQL_TAGS`, `YARAL_TAGS`, `YARA_TAGS`), and a token
counts only as a production the language lists in its `*_TOKENS`. A new node kind gets a fixture
or a structural entry with the reason.

`crates/opentide-analysis/tests/parser_baseline.rs` snapshots every testdata file's diagnostics
and tokens: a parser change that moves them is a reviewed snapshot diff
(`INSTA_UPDATE=always cargo test -p opentide-analysis --test parser_baseline`, then read it),
never an unread `cargo insta accept`.

## Highlighting

The analysis colours tokens from the tree (each crate's `highlight`), with HighlightSpec
captures (`highlights/spec.toml`; a new capture is an append-only change). The TextMate, Monaco
and Helix grammars are generated from the `KEYWORDS` tables:

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
