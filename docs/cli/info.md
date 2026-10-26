---
title: opentide info
description: Repository statistics, platform capabilities, object listings, ATT&CK coverage lookup, and vocabulary contract revisions.
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
| `[section]` | Optional section: `rules`, `threats`, `objectives`, `coverage` (requires `--technique`), or `vocab` |
| `[name]` | With `vocab` only: the vocabulary to inspect (see [Vocabulary contract revisions](#vocabulary-contract-revisions)) |
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
| `vocab` | The vocabularies table, or with a name, that vocabulary's summary, revisions and pins |

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

## Vocabulary contract revisions

A vocabulary file carries no top-level `version`. Each `[[keys]]` entry carries its own lifecycle (`version`, the revision that introduced it, and `removed`, the revision that retired it), and each object schema pins a field to one revision in `src/opentide/data/pins/`. The `vocab` section reads those back, so you can tell which revision a field validates against and how many keys it admits:

```bash
opentide info vocab
opentide info vocab surface
opentide --json info vocab surface
```

| Input | Reports |
|-------|---------|
| `info vocab` | One row per vocabulary: entries, keys carrying `removed`, the latest revision its lifecycle defines, and whether it is staged |
| `info vocab <name>` | The vocabulary's title, key field, entry count, removed-key count, stage ids, then two tables: **Revisions** and **Pins** |

The name is the vocabulary's `field`, which is also its file name without `.vocab.toml` (`surface`, `signal.entities`, `att&ck`). An unknown name is a [usage error](./exit-codes.md): it exits `2`, lists the available names and suggests the closest one. A name typed after any other section (`info rules surface`) also exits `2`. A key whose `version` or `removed` is not `M` or `M.m` (`1`, `1.2`) exits `1`, naming the vocabulary and the key. The vocabularies listed are the ones under the data root (bundled with the engine unless `--data` / `OPENTIDE_DATA_ROOT` points elsewhere); the object vocabularies (`rule`, `threat`, `objective`) built from your repository have no key lifecycle and are not listed.

**Revisions** lists each revision the key lifecycle defines, oldest first: the keys it introduces, the keys it removes, and how many keys a pin to it admits (introduced at or before it, and not removed at or before it).

**Pins** lists each object schema field pinned to this vocabulary:

| Column | Meaning |
|--------|---------|
| Schema | The object schema the pin belongs to (`threat::1.0`) |
| Field | The pinned field path (`threat.surface`) |
| Revision | The pinned revision; `(undefined)` when no key's `version` or `removed` names it |
| Admitted | How many keys validate in that field |
| Scoped | `yes` when the field is authored `<stage>::<key>` (for example `OS::Windows`), `no` when the bare key is authored |

A staged vocabulary whose field is not scoped takes the bare key name; only a scoped field needs the stage prefix. A schema revision that has no model of its own (`objective::1.1`) reads `Scoped` from the latest model of its family.

```json output-of="opentide --json info vocab surface"
{
  "vocabulary": {
    "name": "surface",
    "title": "Threat Surface",
    "entries": "...",
    "removed": "...",
    "latest_revision": "...",
    "staged": true,
    "key": "name",
    "stages": ["OS", "Application", "Authentication", "Cloud", "Infrastructure", "Security", "IoT", "Protocol"],
    "pins": [
      {
        "schema": "threat::1.0",
        "field": "threat.surface",
        "revision": "1.0",
        "defined": true,
        "admitted": "...",
        "scoped": true
      }
    ]
  }
}
```

`revisions` is a list of `{ "revision", "introduced", "removed", "admitted" }` objects. A pin's `scoped` is `null` when no model declares its field.

## Source

`src/opentide/cli/commands/info.py`, `src/opentide/cli/services/info.py`
