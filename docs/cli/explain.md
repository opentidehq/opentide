---
title: opentide explain
description: What a diagnostic code means, an example, and how to fix it.
---

# opentide explain

`opentide explain` prints the page for one diagnostic code: what it means, an example, and how to fix it. Every finding `opentide validate`, `opentide lint`, `opentide doctor` and the language server report carries a `code`, and so does every failed command (`failure.code`, see [JSON output](./json-output.md#failure-codes)). With no code it lists them all.

```bash
opentide explain vocab_unknown
opentide explain
opentide --json explain vocab_unknown
```

| Argument | Meaning |
|----------|---------|
| `[code]` | A diagnostic code, such as `vocab_unknown`, in any case. Omit it to list every code. |

The pages are bundled with opentide, its own under `src/opentide/data/diagnostics/` and those of the analysis engine's query codes, so `explain` reads no workspace and needs no network. The [Diagnostic codes](./diagnostics.md) reference is generated from the same pages, and each finding's help links to its section there: a SARIF report's rule help, and the language server's `codeDescription.href` (`https://opentide.org/docs/cli/diagnostics/#<code>`). The MCP server offers the same pages as its [`explain`](../mcp/tools.md) tool. [Shell completion](./global-options.md#shell-completion) completes the codes.

## One code

At a terminal the page is rendered as Markdown. Piped, in CI or under an agent it is the Markdown itself:

```text output-of="opentide explain vocab_unknown"
# vocab_unknown

A value is not in the vocabulary its field uses.

Severity: error. Reported by `opentide validate` (schema check).

## Example
```

With `--json`, the document carries the code, its one-line meaning and the whole page:

```json output-of="opentide --json explain vocab_unknown"
{
  "code": "vocab_unknown",
  "meaning": "A value is not in the vocabulary its field uses.",
  "markdown": "...",
  "ok": true,
  "status": "completed",
  "message": "A value is not in the vocabulary its field uses.",
  "command": "explain",
  "exit_code": 0
}
```

## Every code

Without a code, `explain` prints one line per code with its meaning, sorted by code, and ends with the count:

```bash
opentide explain
```

```text output-of="opentide explain"
analysis_engine                           The analysis engine loads: the Rust module compiled into opentide (`opentide._native`) behind the `queries` checks of `opentide validate` and `opentide lint`, `opentide validate query` and `opentide lsp`.
api_key_literal                           A `sharing.toml` block holds its API key as a literal.
```

With `--json` the codes are `codes`, a list of `{code, meaning}` in the same order (elided below), and `summary.codes` counts them:

```bash
opentide --json explain
```

```json output-of="opentide --json explain"
{
  "codes": "...",
  "ok": true,
  "status": "completed",
  "command": "explain",
  "exit_code": 0
}
```

## An unknown code

A code opentide does not know is a usage error: `explain` exits `2` with `failure.code` `usage_invalid_choice`, `failure.argument` `code`, and the closest code in `failure.suggestion` when one is close:

```bash
opentide explain vocab_unknwn
```

```text output-of="opentide explain vocab_unknwn" exit=2
error: No diagnostic code 'vocab_unknwn'. Run 'opentide explain' to list them.
  help: did you mean 'vocab_unknown'?
```

## Exit codes

| Code | When |
|------|------|
| `0` | The page, or the list, was printed |
| `2` | The code is not a diagnostic code |

## Source

`crates/opentide-cli/src/commands/explain.rs`, `crates/opentide-cli/src/explain.rs`, and the pages in `src/opentide/data/diagnostics/`, from which `cargo xtask codegen` renders [Diagnostic codes](./diagnostics.md).
