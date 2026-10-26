# usage_watch_needs_tty

`validate --watch` ran where nobody can watch it.

Exit 2, as `failure.code`. Raised under `--json`, when a coding agent runs the command, or with `OPENTIDE_OUTPUT=agent`: the watch redraws a terminal until Ctrl-C.

## Example

```text
opentide --json validate --watch
```

## How to fix

Run `opentide validate --watch` in a terminal, or run `opentide validate` once (with `--json` for a document).
