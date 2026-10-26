---
title: Exit codes
description: What each opentide exit code means, and how to gate CI on them.
---

# Exit codes

Every `opentide` command sets a process exit code so pipelines can gate on results without parsing output. Combine these with `--json` for structured detail.

opentide uses the same result semantics in human and JSON modes: presentation follows `ok` / `status`, while the process exit code is CI policy.

## Codes

| Code | Meaning | Emitted when |
|-----:|---------|--------------|
| `0` | Success | The command completed or intentionally skipped without an operational failure. Success JSON includes `"ok": true`. |
| `1` | Error | Validation/deployment errors, a [`generate` phase](./generate.md#when-a-phase-fails) that raised or logged an error, network/runtime failure, an unexpected error (`failure.code` `internal`, see [JSON output](./json-output.md#an-unexpected-error)), or `--strict` with a warning other than `platform_not_enabled`. |
| `2` | Usage error | An unknown command or option, a value outside the accepted ones (an `info` section, a `generate` phase, `--type`, `--platform`, `share --target`), a missing required flag, a prompt nobody can answer (`setup` without a terminal, under `--json` or under a coding agent), or an explicitly unsupported command. Also the `validate query --live`, `migrate vocab-scope` and `share` cases below. |
| `3` | Partial success | `share` only: see [Share](#share). |
| `130` | Interrupted | Ctrl-C. One `error: interrupted` line on stderr, no traceback. |

With `--json`, `failure.code` tells the cases of one exit code apart: `usage_unknown_command`, `usage_invalid_choice`, `no_tenant_reached`, `share_unreachable` and so on. `failure` is `null` exactly when the exit code is `0`. The codes are listed in [JSON output](./json-output.md#failure-codes).

Usage errors the command itself detects (an unknown `info` section, `info coverage` without `--technique`, an unknown `generate` phase, `generate docs --changed` with a scope, an invalid `--type`, an unknown `share --target`, a `setup` prompt with no terminal, `validate query` without `--live`, a `rules unreviewed --older-than` that is not a window) exited `1` before this release. They exit `2` now, like the usage errors Click detects.

There is no soft-failure exit code. Warnings are listed under `warnings` in JSON (and printed in human mode) and only fail the process when `--strict` is set. Even then, [`platform_not_enabled`](./validate.md#platforms-this-workspace-has-not-enabled) is reported without failing.

`validate query --live` also exits `2` (`failure.code` `no_tenant_reached`) when it reports `skipped` because the plan's rules reached no configured tenant, so no query was sent. That is a check that did not run, not a pass. See [Which tenants are checked](./validate.md#which-tenants-are-checked).

`migrate vocab-scope` exits `2` (`needs_human_decision`) when values are defined under several stages and need a person to choose; `--force` makes that a success.

## How warnings vs errors work

`validate` and `deploy` record outcomes during the run:

| Signal | Set when | Affects |
|--------|----------|---------|
| `VALIDATION_ERROR_RAISED` | Any validation error | Exit `1`, `status: failed` |
| `VALIDATION_WARNING_RAISED` | Any validation warning except [`platform_not_enabled`](./validate.md#platforms-this-workspace-has-not-enabled) | Exit `1` with `--strict`; otherwise exit `0` with warnings |
| `DEPLOYMENT_ERROR_RAISED` | Any deployment error | Exit `1`, `status: failed` |
| `DEPLOYMENT_WARNING_RAISED` | Any deployment warning | Exit `0` with warnings |

With `--json`, failures still write one complete object to stdout before exiting. In the [tutorial](../usage/tutorial.md) repository with the dangling `detection_model` from [step 7](../usage/tutorial.md#7-break-it-on-purpose), `opentide --json validate` exits `1` and prints the whole report, trimmed here to its outcome:

```json output-of="opentide --json validate" exit=1 state=dangling-reference
{
  "report": { "ok": false, "issues": ["..."] },
  "ok": false,
  "status": "failed",
  "message": "Validation failed",
  "exit_code": 1,
  "failure": { "code": "command_failed", "message": "Validation failed" }
}
```

Diagnostics use stderr. Automation should parse stdout and evaluate both `ok`/`status` and the process exit code; `exit_code` in the document is the same number.

## Gating CI

```bash
opentide validate --strict   # errors and warnings fail the job, except platform_not_enabled
opentide validate            # errors fail; warnings are reported but exit 0
```

For finer control:

```bash
if opentide --json validate > result.json; then
  echo "validation passed"
else
  code=$?
  echo "validation failed with exit code $code"
  [ -s result.json ] && cat result.json
  exit $code
fi
```

## Share

[`opentide share`](./share.md) keeps `0` and `1`, and adds two codes. `2` on share means every object failure was authentication or connectivity (`share_unreachable`). `3` means the run both succeeded and failed (`share_partial`). Skipped objects are not failures. The global `2` usage error still applies to unknown flags, unknown `--type` values and a `--target` that names no configured block.

| Code | Meaning |
|-----:|---------|
| `0` | Nothing failed. An all-skip run exits `0`. `share push --changed` also exits `0` for an empty diff or when no block is enabled |
| `1` | Preflight (configuration, a disabled `--target`, confirmation, `--changed` outside CI or on a pull request; `failure.code` is the `preflight` value) or a non-auth object failure with no success |
| `2` | Every failure is authentication or connectivity, and nothing succeeded |
| `3` | At least one success and at least one failure |

## Related

- [`validate`](./validate.md) — `--strict` and object/query checks.
- [`deploy`](./deploy.md) — deployment errors and warnings.
- [`share`](./share.md) — MISP push, preview, status, and retract.
- [JSON output](./json-output.md) — the document every command prints, and `failure.code`.
- [CI/CD](../usage/workflows/ci-cd.md) — pipelines that gate on these codes.
