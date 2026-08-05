---
title: Exit codes
description: What each opentide exit code means, and how to gate CI on them.
---

# Exit codes

Every `opentide` command sets a process exit code so pipelines can gate on results without parsing output. Combine these with `--json` for structured detail.

## Codes

| Code | Meaning | Emitted when |
|-----:|---------|--------------|
| `0` | Success | The command completed with no errors. With `--json`, the payload includes `"ok": true`. |
| `1` | Error | Validation errors, deployment errors, or a command-level failure. With `--json`, `"ok": false`. |
| `2` | Usage error | Invalid arguments or options (Typer/Click). The command did not run. |
| `19` | GitLab soft-fail (warnings) | Warnings were raised **and** the run is detected as GitLab CI, so the job fails softly rather than passing silently. |

<Callout type="info">
`19` is intentional GitLab behaviour: warnings (e.g. deprecated fields) fail the job on GitLab so they are visible, while on other CI systems warnings do not by themselves fail the build. Use `--strict` to turn warnings into hard errors (`1`) everywhere.
</Callout>

## How warnings vs errors work

`validate` and `deploy` record outcomes in environment signals during the run:

| Signal | Set when | Affects |
|--------|----------|---------|
| `VALIDATION_ERROR_RAISED` | Any validation error | Exit `1` |
| `VALIDATION_WARNING_RAISED` | Any validation warning | Exit `19` on GitLab |
| `DEPLOYMENT_ERROR_RAISED` | Any deployment error | Exit `1` |
| `DEPLOYMENT_WARNING_RAISED` | Any deployment warning | Exit `19` on GitLab |

`--strict` promotes warnings to errors, so a warning becomes exit `1` on every platform.

## Gating CI

Because failures set a non-zero code, a plain step fails the job automatically:

```bash
opentide validate --strict          # non-zero on any error → job fails
```

For finer control, branch on the code:

```bash
if opentide validate --json > result.json; then
  echo "validation passed"
else
  code=$?
  echo "validation failed with exit code $code"
  cat result.json        # inspect the "issues" array
  exit $code
fi
```

## Related

- [`validate`](./validate.md) — the main source of `1` / `19`.
- [`deploy`](./deploy.md) — deployment errors and warnings.
- [CI/CD](../usage/workflows/ci-cd.md) — pipelines that gate on these codes.
