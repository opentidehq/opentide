# CLI Reference

Run `opentide --help` for the full command surface.

| Command | Purpose |
|---------|---------|
| `init` | Scaffold a detection repository |
| `generate` | Build indexes, schemas, templates |
| `validate` | Object and query validation (default: full registry; narrow with `--file`, `--uuid`, `--type`) |
| `deploy` | Platform deployment |
| `document` | Object wiki generation (`docs/Rules`, `docs/Objectives`, `docs/Threats`) |
| `mutate` | Content mutations |
| `export` | Navigator/table exports |
| `extract` | Framework ingestion |
| `info` | Repository statistics |
| `migrate` | Legacy import migration |

Query validation supports **5 platforms** only (not CrowdStrike or HarfangLab).

## `opentide validate`

Validates detection objects (schema, UUID format, ID uniqueness, cross-object references, and vocabulary fields) against live Pydantic models and an in-memory preflight graph.

| Flag | Effect |
|------|--------|
| *(none)* | Validate the **entire** object registry (CI / PR default) |
| `--file PATH` | Narrow to one or more YAML files |
| `--uuid UUID` | Narrow to objects by UUID (repeatable) |
| `--type {threat,objective,rule}` | Narrow to an object type |
| `--check` | Run a single check (`schema`, `id-uniqueness`, `uuid-format`, `cve`) |
| `--strict` | Fail on warnings |

JSON Schema files from `opentide generate schemas` remain for editor hints; runtime validation uses Pydantic and does not require schema regeneration when adding interrelated objects in a branch.

### Parallel validation (full-registry runs)

Large repos validate objects concurrently when the scoped object count meets a threshold (default **32**). Tune with environment variables:

| Variable | Default | Effect |
|----------|---------|--------|
| `OPENTIDE_VALIDATE_PARALLEL_THRESHOLD` | `32` | Minimum objects (or ID-scan YAML files) before using a thread pool |
| `OPENTIDE_VALIDATE_WORKERS` | `auto` | Max worker threads (`auto` ≈ `cpu_count + 4`, capped at 32) |

Per-object work (Pydantic, vocabulary fields, UUID format, cross-object refs) and ID-uniqueness filesystem scans run in parallel independently. Narrow scope (`--file`, `--uuid`, `--type`) usually stays sequential because the object count is small. **ID uniqueness always scans the full registry** (duplicate IDs are a global invariant); narrow scope only filters which duplicate findings are reported when neither file is in scope. `ValidationReport.stats` includes `parallel`, `workers`, `object_workers`, `id_workers`, and `wall_ms`.
