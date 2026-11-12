---
title: opentide info
description: Repository statistics, platform capabilities, object listings, the catalogue with its relationships, ATT&CK coverage lookup, and vocabulary contract revisions.
---

# opentide info

Show repository and platform information.

```bash
opentide info
opentide --json info --platform sentinel
opentide --json info rules
opentide --json info --technique T1059 coverage
opentide --json info catalog
```

## Arguments and options

| Input | Purpose |
|-------|---------|
| `[section]` | Optional section: `rules`, `threats`, `objectives`, `coverage` (requires `--technique`), `vocab`, or `catalog` (see [The catalogue](#the-catalogue)) |
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

A rule covers a technique when it lists it in its own `techniques`, or when it inherits it: from the objective its `detection_model` names (directly, or through one of that objective's signals), or, when that objective lists none, from the threats the objective covers. This is the same walk `info catalog` reports as `techniques.own` and `techniques.inherited`, and the MCP [`coverage`](../mcp/tools.md#coverage) tool and the TUI's [Coverage tab](./tui.md) read it too, so all four agree. `rules` and `count` hold both kinds; `own` and `inherited` keep them apart, since a rule that lists the technique itself is the stronger claim.

A parent technique also matches its sub-techniques (`T1059` finds rules tagged `T1059.001`); a sub-technique does not match its parent. Matching is case-insensitive. `matched_techniques` lists the catalogue's IDs that answered.

## Default output

Without `--json`, `info` prints a Rich table:

- Package version
- Rule, threat, objective counts
- How many object files failed to load
- One row per platform: `enabled=True` or `enabled=False`, then its capabilities — `[deploy, validate]`, or `[deploy]` for CrowdStrike, HarfangLab, Sysdig and Bitdefender

With a section, the table for that section replaces the summary:

| Section | Human output |
|---------|--------------|
| `rules` | UUID, name, and the platforms each rule configures |
| `threats`, `objectives` | UUID and name |
| `coverage` | `Coverage for T1059: 3 rules (1 own, 2 inherited)`, then the matching rules as in `rules` |
| `vocab` | The vocabularies table, or with a name, that vocabulary's summary, revisions and pins |
| `catalog` | Objects by family, signals, edges by kind (and how many name no object), the ATT&CK techniques the catalogue reaches, and load errors |

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
    { "name": "sentinel", "enabled": true, "can_deploy": true, "can_validate": true, "tenants": [] }
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

### Tenants

Each `platforms[]` entry lists the platform's `[[tenants]]` from `.opentide/configurations/platforms/<id>.toml`, so a client can show them and their credentials without reading TOML:

| Key | Content |
|-----|---------|
| `name`, `description` | From the tenant's table |
| `strategies` | The run strategies the tenant accepts (`PREVIEW`, `RELEASE`); both when the file omits `strategies` |
| `manual` | `true` when only rules whose block names the tenant reach it |
| `variables` | `{name, set}` for each `$VAR` (or `${VAR}`) the tenant's `[tenants.setup]` references, in order: whether the process environment sets it to a non-empty value. A reference is a top-level setup value that is `$NAME` or `${NAME}` as a whole, the values opentide resolves; a value that only starts with `$` is a literal |

A variable's value is never printed, in either output. A tenant's setup values that are not variable references are not printed either. `opentide doctor`'s `credentials` check reports the same variables as a pass or a warning.

```json illustrative
{
  "name": "sentinel",
  "tenants": [
    { "name": "prod", "description": "Production workspace", "strategies": ["RELEASE"], "manual": false,
      "variables": [ { "name": "AZURE_CLIENT_ID", "set": true }, { "name": "AZURE_CLIENT_SECRET", "set": false } ] }
  ]
}
```

The keys from `schema_version` on are the envelope every command adds; see [JSON output](./json-output.md). Log lines are written to stderr, so `opentide --json info 2>/dev/null` is a single JSON document.

With coverage, the payload adds a `coverage` object:

```json output-of="opentide --json info --technique T1059 coverage"
{
  "coverage": {
    "technique": "T1059",
    "rules": ["..."],
    "count": 1,
    "own": ["..."],
    "inherited": [],
    "matched_techniques": ["T1059"]
  }
}
```

## The catalogue

`info catalog` prints every object, how the objects relate, and the ATT&CK Enterprise matrix in one document. It is what an editor needs for a catalogue tree, a coverage graph, an ATT&CK matrix and search, without reading YAML itself:

```bash
opentide info catalog
opentide --json info catalog
```

The document holds the `info` keys, plus `objects`, `edges`, `signals` and `attack`. `summary` adds `objects` (rows, load errors included), `signals` and `edges` to the four counts. In the [tutorial](../usage/tutorial.md) repository:

```json output-of="opentide --json info catalog"
{
  "summary": { "rules": 1, "threats": 1, "objectives": 1, "load_errors": 0, "objects": 3 }
}
```

**`objects`**: one row per threat, objective and rule, threats first, each family sorted by path.

| Key | Content |
|-----|---------|
| `uuid`, `type`, `schema`, `name` | Identity: `metadata.uuid`, `threat`/`objective`/`rule`, `metadata.schema`, `name` |
| `path`, `file_path`, `line` | The file relative to the workspace (forward slashes), the same file absolute, and the 1-based line of the `name:` key (1 when there is none) |
| `tlp`, `author`, `created`, `modified`, `reviewed` | From `metadata`; `null` when unset |
| `platforms` | A rule's platform blocks: `{id, enabled, status, strategy}`, the strategy being the one `deployment.toml` maps the status to |
| `deployment` | A rule's tenant bindings in `.opentide/states/deployment/`: `{platform, tenant, deployed, rule_id}`. | `deployment` | A rule's tenant bindings in `.opentide/states/deployment/`: `{platform, tenant, deployed, rule_id}`. Only Defender, SentinelOne, CrowdStrike, Sysdig, Bitdefender, Graylog and Exabeam keep one |
| `techniques` | `own`: the ATT&CK ids the object lists. `inherited`: those its objective or threats give it that it does not list. An objective that lists no techniques inherits those of each threat it covers that exists; a rule, its objective's (through a signal's objective) |
| `tactics` | The tactic shortnames of all those techniques, in matrix order |
| `actors` | The actors of the threat, of the threats an objective covers, or of the threats of a rule's objective, as written (`att&ck::G0006`) |
| `load_error` | `null`, or `{code, message, line}` for a file that did not load |

A file that did not load still has a row, so an editor can show it: its `load_error` says why (`yaml_parse` with the line of the problem, `missing_uuid`, or `duplicate_id` for a file whose UUID a later file also uses: the index keeps that file's object, and the message names the UUID and that file), and `uuid`, `name` and `schema` are read from the text where they can be (`uuid` is `null` otherwise). A `duplicate_id` row's `uuid` is `null`, so no two rows share a `uuid`. Another load-error row's `uuid` read from its text can still be a loaded object's (a copy of a file whose YAML is broken), so key load-error rows by `path`. It also counts in `summary.load_errors`, and sets `status` to `issues` as in every view.

**`edges`**: one per reference, `{from, to, kind, field_path, relation, missing}`. `field_path` is the dotted path of the field holding the reference; a signal's starts at its entry in the objective (`objective.signals.1.parent`).

| `kind` | From → to | Read from |
|--------|-----------|-----------|
| `covers` | objective → threat | `objective.threats` |
| `implements` | rule → objective or signal | `detection_model` |
| `parent` | signal → parent signal | `objective.signals[].parent` |
| `chains` | threat → threat, with `relation` as written (`sequence::preceeds`) | `threat.chaining` |
| `technique` | threat, objective or rule → ATT&CK id | `threat.mitre_attack`, `objective.mitre_attack`, `techniques` |
| `logsource` | signal → log source name from `visibility.toml` | `objective.signals[].data.logsources` |

`missing` is `true` when `to` should name an object or signal and none carries that UUID: a dangling reference, which `opentide validate` reports as `invalid_ref`.

**`signals`**: signals live inside objectives, so they are not `objects` rows. Each is `{uuid, name, objective, parent}`, and is an endpoint of `implements`, `parent` and `logsource` edges.

**`attack`**: the Enterprise matrix of the bundled `att&ck` vocabulary, as the object schemas pin it (keys retired after the pinned revision included), so a client can draw the gaps:

- `tactics`: in matrix order, each `{id, shortname, name, techniques}` (`TA0006`, `credential-access`, `Credential Access`), `techniques` listing its techniques, not their sub-techniques.
- `techniques`: by id, each `{name, parent, subtechniques}`. A sub-technique's name drops its parent's (`T1003.001` is `LSASS Memory`, under `T1003`).

The shape of one object, edge and tactic (values from a larger repository, not captured output):

```json illustrative
{
  "objects": [
    {
      "uuid": "…", "type": "rule", "schema": "rule::1.0", "name": "LSASS access",
      "path": "objects/rules/lsass-access.yaml", "file_path": "/repo/objects/rules/lsass-access.yaml",
      "line": 1, "tlp": "amber", "author": "…", "created": "2026-10-23", "modified": "2026-10-23",
      "reviewed": null,
      "platforms": [{ "id": "sentinel", "enabled": true, "status": "DESIGN", "strategy": "INERT" }],
      "deployment": [],
      "techniques": { "own": ["T1003.001"], "inherited": ["T1003"] },
      "tactics": ["credential-access"],
      "actors": ["att&ck::G0016"],
      "load_error": null
    }
  ],
  "edges": [
    { "from": "<rule uuid>", "to": "<objective uuid>", "kind": "implements",
      "field_path": "detection_model", "relation": null, "missing": false }
  ],
  "signals": [{ "uuid": "…", "name": "…", "objective": "<objective uuid>", "parent": null }],
  "attack": {
    "tactics": [{ "id": "TA0006", "shortname": "credential-access", "name": "Credential Access",
                  "techniques": ["T1003", "…"] }],
    "techniques": { "T1003.001": { "name": "LSASS Memory", "parent": "T1003", "subtechniques": [] } }
  }
}
```

The document is built from one registry load, in time linear in the catalogue: a 500-rule workspace answers in about 1.3 s, most of it the load every `info` view pays.

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

`src/opentide/cli/commands/info.py`, `src/opentide/cli/services/info.py`, `src/opentide/cli/services/catalog.py`
