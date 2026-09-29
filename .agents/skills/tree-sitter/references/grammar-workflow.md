# Grammar workflow

## CLI

```bash
tree-sitter --version   # must print: tree-sitter 0.25.10
```

If it is missing or a different version:

```bash
node_prefix="$(dirname "$(dirname "$(command -v npm)")")"
npm install -g --prefix "$node_prefix" tree-sitter-cli@0.25.10
```

Do not `npm install tree-sitter-cli` at the repo root. There is no root `package.json`. The grammar `package.json` files are metadata for the grammar (`tree-sitter` file-types), not an npm workspace.

## Generate

From the repository root. The subshell is what puts `tree-sitter` next to `grammar.js`; the check script resolves the repo from its own path and must be invoked as `scripts/check-grammars.sh`.

```bash
(cd grammars/tree-sitter-opentide-kql && tree-sitter generate)   # or -spl
bash scripts/check-grammars.sh
```

0.25 reads `grammar.js` and writes `src/parser.c`, `src/grammar.json`, `src/node-types.json`, and `src/tree_sitter/parser.h`. Commit every file git shows as changed. Do not format `parser.c` with rustfmt or clang-format; the diff against a fresh generate must be empty.

`scripts/check-grammars.sh` generates in a temp copy and diffs only `parser.c`. If `grammar.json` drifted but `parser.c` did not, still commit `grammar.json`: `corpus_gate.rs` reads it.

## Rule design

Tree-sitter is GLR. Conflicts are allowed when they are real (a token that starts two operators) and named in a comment. Do not paper over a conflict with `prec` that makes a valid query fail to parse. Check with:

```bash
# grammar directory, so the CLI finds grammar.js; the corpus lives two levels up
tree-sitter parse ../../testdata/corpus/kql/take_operator__valid.kql
```

Run that from `grammars/tree-sitter-opentide-kql` (use `...-spl` and `../../testdata/corpus/spl/...` for SPL). A successful parse prints an S-expression. `ERROR` or `MISSING` nodes are failures even if the process exits 0. The Rust tests use `has_error`.

Keywords that are also identifiers (`and`, `or`, `by`) belong in the expression rules as literals, not as a reserved-word list that rejects them as column names. Look at the existing `grammar.js` before adding a word to a reserved set.

Strings: KQL uses single and double quotes with doubled-quote escapes. Do not import a JSON string rule.

Comments are extras so they do not appear between every token the engine matches. The comment rule itself is still a named node (`comment`) and has a corpus tag.

## Corpus fixture

File name: `<rule>__valid.kql` or `<rule>__invalid.kql` (SPL uses `.spl`). First line:

```
// prod:<rule_name> valid
```

The tag is the grammar rule name, which is also `node.kind()`. `corpus_gate.rs` splits the file on whitespace and strips a trailing comma, so `prod:where_operator` and `prod:where_operator,` both count. One fixture may carry more than one tag when one query covers several productions. The required lists in `corpus_gate.rs` are the contract; a tag that nothing requires still helps, but a required rule without a tag fails the test.

Invalid fixtures are for productions that must parse as an error node (`has_error() == true`) when the test says so. A semantically unknown operator (`frobnicate`) should still **parse** if the grammar has `unknown_operator`. The diagnostic comes from the engine, not from an `ERROR` node. Do not encode catalog membership in the grammar.

## Renames

Renaming a rule is an engine change: `.scm` patterns, `node.kind()` matches, corpus tags, and `docs/LANGUAGE.md`. Do it in one commit. Do not leave the old kind as an alias node unless the old name is still a real production.
