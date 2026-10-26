# command_failed

The command failed for a reason no more specific code covers.

Exit 1, as `failure.code`. `message` and `error` say what went wrong.

## Example

```text
opentide deploy --strategy PREVIEW --all --platform sentinel
```

## How to fix

Read `message`. Run the command again with `--debug` to see the log lines that led to it.
