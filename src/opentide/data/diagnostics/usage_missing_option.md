# usage_missing_option

A required option or argument is missing.

Exit 2, as `failure.code`. `failure.argument` names it (`--platform`, `--strategy`, `--technique`).

## Example

```text
opentide info coverage
```

## How to fix

Add the option the message names. `opentide <command> --help` shows what it takes.
