# doctor_checks_failed

At least one `opentide doctor` check failed.

Exit 1, as `failure.code`. Warnings and skipped checks never change the exit code. Under `--json`, `checks` lists every check with its `code`, `status`, `message` and `fix`.

## Example

```text
opentide --json doctor
```

## How to fix

Run the fix printed under each `✗` line (or read each failed check's `fix` in JSON), then run `opentide doctor` again. `opentide explain <check code>` describes each check.
