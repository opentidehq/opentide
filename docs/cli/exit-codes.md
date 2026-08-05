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
| `1` | Error | Validation errors, deployment errors, network/runtime failure, or `--strict` with warnings outside GitLab. |
| `2` | Usage error | Invalid arguments, missing required flags, or an explicitly unsupported command. |
| `19` | GitLab soft-fail (warnings) | Legacy warning policy when GitLab CI is detected. Treat as process policy, not a presentation signal — `status: failed` is the only hard failure. |

<Callout type="info">
Exit `19` is legacy GitLab soft-fail behaviour retained for existing pipelines. Prefer gating on exit `0`/`1` and the JSON `ok`/`status` fields. A follow-up removes exit `19` entirely.
</Callout>

## How warnings vs errors work

`validate` and `deploy` record outcomes during the run:

| Signal | Set when | Affects |
|--------|----------|---------|
| `VALIDATION_ERROR_RAISED` | Any validation error | Exit `1`, `status: failed` |
| `VALIDATION_WARNING_RAISED` | Any validation warning | Exit `19` on GitLab; exit `1` with `--strict` elsewhere |
| `DEPLOYMENT_ERROR_RAISED` | Any deployment error | Exit `1`, `status: failed` |
| `DEPLOYMENT_WARNING_RAISED` | Any deployment warning | Exit `19` on GitLab |

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

Because failures set a non-zero code, a plain step fails the job automatically:

```bash
opentide validate          # non-zero on any error → job fails
```

For finer control, branch on the code:

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

- [`validate`](./validate.md) — the main source of `1` / `19`.
- [`deploy`](./deploy.md) — deployment errors and warnings.
- [CI/CD](../usage/workflows/ci-cd.md) — pipelines that gate on these codes.
