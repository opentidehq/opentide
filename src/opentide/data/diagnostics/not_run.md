# not_run

The command was skipped, and says why in its message.

Exit non-zero, as `failure.code`. Nothing was changed.

## Example

The document of a skipped run, trimmed to the keys that say so:

```json illustrative
{"status": "skipped", "exit_code": 2, "failure": {"code": "not_run", "message": "…"}}
```

## How to fix

Read `message`: it names what the command needed to run.
