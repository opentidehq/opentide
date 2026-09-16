# KQL control / management commands (unsupported in detections)

Control (management) commands are **not** Kusto Query Language query operators. They begin with `.` and mutate or inspect cluster/database metadata and data.

Citations:

- [Management commands overview](https://learn.microsoft.com/kusto/management/)
- [KQL overview](https://learn.microsoft.com/kusto/query/) — queries vs management commands

In OpenTide they are parsed only so the engine can emit **`kql_control_command_unsupported`**. They must never be treated as valid Sentinel analytics or Defender custom-detection bodies.

Also summarized under [`operators.md`](operators.md) (“Unsupported: control / management commands”).

---

## Families (unsupported in detections)

| Family | Examples | Purpose | Detections |
| --- | --- | --- | --- |
| Metadata show | `.show tables`, `.show table T`, `.show databases`, `.show functions` | List entities | **No** |
| Schema show | `.show table T schema`, `.show database schema` | Describe schema | **No** |
| Table DDL | `.create table`, `.create-merge table`, `.alter table`, `.drop table` | Create/alter/drop tables | **No** |
| Function DDL | `.create function`, `.alter function`, `.drop function` | Stored functions | **No** |
| Ingest / set | `.ingest`, `.set`, `.append`, `.set-or-append`, `.set-or-replace` | Load or replace data | **No** |
| Data mutation | `.clear table`, `.drop extents` | Delete data / extents | **No** |
| Scripts | `.execute database script` | Batch management | **No** |

Additional ADX management verbs (`.alter-merge`, `.create-or-alter`, workload groups, policies, continuous export, …) are likewise **No** for detections. Prefer portal UX or ARM/Bicep for workspace administration.

---

## Query-side alternatives

| Need | Use instead |
| --- | --- |
| Column list | `T \| getschema` (hunting) or portal schema browser |
| Scalar constants / IOC tables | `datatable` / `print` / `let` |
| Cross-workspace read | `workspace("…")` (Sentinel limits apply; Defender custom detections: **No**) |

---

## Engine status

| Surface | Status |
| --- | --- |
| Grammar | `control_command`: `.` + identifiers |
| Catalog | **None** (optional future list for nicer messages) |
| Diagnostics | Any `control_command` → error `kql_control_command_unsupported` |
| Completions | Should **not** suggest `.show` / `.create` in detection editors |

---

## Count

**7** families listed (representative commands inside each). Full ADX management surface is larger and out of scope for detection authoring.
