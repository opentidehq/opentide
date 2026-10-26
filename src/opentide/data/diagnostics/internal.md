# internal

opentide stopped on an exception it did not handle: a bug in opentide, not in your input.

Exit 1, as `failure.code`. Under `--json` the document also carries `failure.crash_log`, the path of a redacted crash log. On stderr, `error[internal]: <Type>: <message>` is followed by that path and a link that opens a pre-filled GitHub issue. Under `opentide mcp start` nothing is written to stdout.

## Example

```text
error[internal]: RuntimeError: index exploded
  note: crash log, with credentials and tenant names redacted: ~/.local/state/opentide/crash-20261023T110335102704Z-648.log
  help: this is a bug in opentide; report it: https://github.com/opentidehq/opentide/issues/new?…
  help: add --debug to see the traceback
```

## How to fix

Open the issue from the link, and attach the crash log after reading it: opentide removes the secrets and tenant names it recognises, but not a value it cannot tell is one. Add `--debug` (or `OPENTIDE_DEBUG=1`) to print the traceback on stderr too. See [Troubleshooting](../usage/troubleshooting.md#opentide-stops-with-errorinternal).
