---
title: Exit codes
description: What each opentide exit code means, and how to gate CI on them.
---

# Exit codes

Every `opentide` command sets a process exit code so pipelines can gate on results without parsing output. Combine these with `--json` for structured detail.

OpenTide uses the same result semantics in human and JSON modes: presentation follows `ok` / `status`, while the process exit code is CI policy.

## Codes

| Code | Meaning | Emitted when |
|-----:|---------|--------------|
| `0` | Success | The command completed or intentionally skipped without an operational failure. Success JSON includes `"ok": true`. |
| `1` | Error | Validation/deployment errors, network/runtime failure, or `--strict` with warnings. |
| `2` | Usage error | Invalid arguments, missing required flags, or an explicitly unsupported command. |

There is no soft-failure exit code. Warnings are listed under `warnings` in JSON (and printed in human mode) and only fail the process when `--strict` is set.

## How warnings vs errors work

`validate` and `deploy` record outcomes during the run:

| Signal | Set when | Affects |
|--------|----------|---------|
| `VALIDATION_ERROR_RAISED` | Any validation error | Exit `1`, `status: failed` |
| `VALIDATION_WARNING_RAISED` | Any validation warning | Exit `1` with `--strict`; otherwise exit `0` with warnings |
| `DEPLOYMENT_ERROR_RAISED` | Any deployment error | Exit `1`, `status: failed` |
| `DEPLOYMENT_WARNING_RAISED` | Any deployment warning | Exit `0` with warnings |

With `--json`, failures still write one complete object to stdout before exiting:

```json
{
  "ok": false,
  "status": "failed",
  "message": "Validation failed"
}
```

Diagnostics use stderr. Automation should parse stdout and evaluate both `ok`/`status` and the process exit code.

## Gating CI

```bash
opentide validate --strict   # warnings and errors both fail the job
opentide validate            # errors fail; warnings are reported but exit 0
```

For finer control:

```bash
if opentide validate --json > result.json; then
  echo "validation passed"
else
  code=$?
  echo "validation failed with exit code $code"
  [ -s result.json ] && cat result.json
  exit $code
fi
```

## Related

- [`validate`](./validate.md) — `--strict` and object/query checks.
- [`deploy`](./deploy.md) — deployment errors and warnings.
- [CI/CD](../usage/workflows/ci-cd.md) — pipelines that gate on these codes.
