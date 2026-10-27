# usage_tui_needs_tty

`opentide tui` ran where it cannot draw: it needs a person at a terminal.

Exit 2, as `failure.code`. Raised under `--json`, in a pipe, in CI, under a coding agent, and at a terminal whose settings select `plain` output (`NO_COLOR`, `--no-color`, `TERM=dumb`); the error names the setting.

## Example

```text
opentide --json tui
```

## How to fix

Run `opentide tui` in an interactive terminal. When a `plain` setting such as `NO_COLOR` refused it, set `OPENTIDE_OUTPUT=human` to open it anyway. For a script, run the commands the UI runs (`opentide validate`, `opentide generate`, `opentide deploy --dry-run`) directly, with `--json`.
