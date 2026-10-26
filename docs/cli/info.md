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
| `--strict` | Exit non-zero when any object file failed to load |
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

Without `--json`, `info` prints a Rich table:

- Package version
- Rule, threat, objective counts
- How many object files failed to load
- One row per platform: `enabled=True` or `enabled=False`, then its capabilities — `[deploy, validate]`, or `[deploy]` for CrowdStrike and HarfangLab

With a section, the table for that section replaces the summary:

| Section | Human output |
|---------|--------------|
| `rules` | UUID, name, and the platforms each rule configures |
| `threats`, `objectives` | UUID and name |
| `coverage` | `Coverage for T1059: 1 rule`, then the matching rules as in `rules` |

An empty section prints `No rules found` (or threats, objectives).

Every view ends with one line counting the catalogue: `✓ 1 rule · 1 threat · 1 objective · 0 load errors`. When object files failed to load, `status` is `issues`, the line starts with `!`, and the next step is `opentide validate`, which shows the file, line and column of each. With `--strict` the run fails instead: `✗ … · 1 load error` on stderr, exit `1`, and `failure.code` `issues_found`. `summary` carries the four counts (`rules`, `threats`, `objectives`, `load_errors`).

## JSON payload shape

`info` emits the same envelope as every other command, so the payload carries the `ok` / `status` / `message` keys alongside its own fields. In the [tutorial](../usage/tutorial.md) repository, with the platform list filtered to Sentinel:

```json output-of="opentide --json info --platform sentinel"
{
  "version": "...",
  "repo": "...",
  "counts": { "rules": 1, "threats": 1, "objectives": 1 },
  "parse_error_count": 0,
  "platforms": [
    { "name": "sentinel", "enabled": true, "can_deploy": true, "can_validate": true }
  ],
  "ok": true,
  "status": "completed",
  "message": "Completed successfully",
  "schema_version": 1,
  "command": "info",
  "duration_ms": "...",
  "exit_code": 0,
  "summary": {},
  "next_actions": [],
  "failure": null
}
```

The keys from `schema_version` on are the envelope every command adds; see [JSON output](./json-output.md). Log lines are written to stderr, so `opentide --json info 2>/dev/null` is a single JSON document.

With coverage, the payload adds a `coverage` object:

```json output-of="opentide --json info --technique T1059 coverage"
{
  "coverage": { "technique": "T1059", "rules": ["..."], "count": 1 }
}
```

## Source

`src/opentide/cli/commands/info.py`, `src/opentide/cli/services/info.py`
