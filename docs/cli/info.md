---
title: opentide info
description: Repository statistics, platform capabilities, object listings, and ATT&CK coverage lookup.
---

# opentide info

Show repository and platform information.

```bash
opentide info
opentide --json info --platform sentinel
opentide --json info rules
opentide --json info --technique T1059 coverage
```

## Arguments and options

| Input | Purpose |
|-------|---------|
| `[section]` | Optional section: `rules`, `threats`, `objectives`, or `coverage` (requires `--technique`) |
| `--platform` | Filter platform table to one platform |
| `--technique` | ATT&CK technique ID — use with positional `coverage` |
| `--json` | Structured output (**global flag** — place before `info`) |

### Coverage lookup

Both `--technique` and the `coverage` positional are required. Option order does not matter:

```bash
opentide --json info coverage --technique T1059
opentide --json info --technique T1059 coverage
```

`opentide info --technique T1059` alone does **not** include coverage data.

A parent technique also matches its sub-techniques (`T1059` finds rules tagged `T1059.001`); a sub-technique does not match its parent. Matching is case-insensitive.

## Default output

Interactive mode prints a Rich table:

- Package version
- Rule, threat, objective counts
- Per-platform `enabled`, deploy, and validate capabilities

## JSON payload shape

`info` emits the same envelope as every other command, so the payload carries the `ok` / `status` / `message` keys alongside its own fields. In the [tutorial](../usage/tutorial.md) repository, with the platform list filtered to Sentinel:

```json output-of="opentide --json info --platform sentinel"
{
  "version": "...",
  "repo": "...",
  "counts": { "rules": 1, "threats": 1, "objectives": 1 },
  "platforms": [
    { "name": "sentinel", "enabled": true, "can_deploy": true, "can_validate": true }
  ],
  "ok": true,
  "status": "completed",
  "message": "Completed successfully"
}
```

Log lines are written to stderr, so `opentide --json info 2>/dev/null` is a single JSON document.

With coverage, the payload adds a `coverage` object:

```json output-of="opentide --json info --technique T1059 coverage"
{
  "coverage": { "technique": "T1059", "rules": ["..."], "count": 1 }
}
```

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/info.py`
