# usage_needs_input

The command would ask a question, but nobody can answer it.

Exit 2, as `failure.code`. Raised under `--json`, without a terminal, or when a coding agent runs the command.

## Example

```text
opentide --json setup
```

## How to fix

Pass the flags the message names, which answer the prompt, or run the command in a terminal.
