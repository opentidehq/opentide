# CIM field coverage (detections)

Checklist of Splunk Common Information Model (CIM) data models and the field names OpenTide cares about for ES / ESCU-style `splunk.query` blocks.

Citations:

- [CIM fields](https://docs.splunk.com/Documentation/CIM/latest/User/CIMfields)
- [CIM data models](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- Narrative field notes: [common-fields.md](common-fields.md)

After `| tstats … from datamodel=Model.Dataset`, fields are prefixed (`Processes.process_name`) until a macro such as `` `drop_dm_object_name(Processes)` `` strips the dataset prefix.

## Completeness status

| CIM data model | Detection relevance | Inventory status in `docs/spl` |
| --- | --- | --- |
| Authentication | Critical | Covered in [common-fields.md](common-fields.md) |
| Change | High | Covered (object / action / result) |
| Endpoint | Critical | Covered (process / registry / service / file) |
| Network Traffic | Critical | Covered (src/dest/ports/bytes/action) |
| Network Resolution (DNS) | High | Covered (query/answer/reply) |
| Web | High | Covered (url/http_*) |
| Intrusion Detection | High | Covered (signature/ids_type/severity) |
| Malware | High | Covered (file_*/signature) |
| Email | Medium | Covered (recipient/message_id/filter_*) |
| Alerts | Medium | Covered (severity/mitre_technique_id/vendor_*) |
| Certificates | Low–medium | Partial (`src`/`dest`/`transport` only) |
| Data Access | Medium | Partial (`object_*` / `user_*`) |
| Data Loss Prevention | Medium | Partial (category/severity/dvc) |
| Databases | Low | Partial (`query` overlap with DNS — disambiguate by sourcetype) |
| Inventory | Low | Partial (IP/MAC inventory fields) |
| Performance / Updates / Ticket Management / Java Virtual Machines / Application State | Rare in ES correlation searches | **Not inventoried** (deferred) |

There is **no** field catalog in `catalogs/spl/` yet — field knowledge is docs-only. Completions do not suggest CIM names.

## Critical field set (always recognize)

### Default Splunk

`index` `sourcetype` `source` `host` `_time` `_raw` `_indextime` `splunk_server` `linecount` `punct` `eventtype` `tag` `date_hour` `date_mday` `date_month` `date_year` `date_wday` `date_zone`

### Identity / asset

`user` `src_user` `user_id` `user_name` `user_role` `user_type` `user_group` `src_nt_domain` `dest_nt_domain` `src_bunit` `dest_bunit` `user_bunit` `src_category` `dest_category` `user_category` `src_priority` `dest_priority` `user_priority`

### Network

`src` `dest` `dvc` `src_ip` `dest_ip` `src_port` `dest_port` `src_mac` `dest_mac` `src_translated_ip` `dest_translated_ip` `transport` `protocol` `bytes` `bytes_in` `bytes_out` `packets` `packets_in` `packets_out` `rule` `action` `vendor_product` `app` `duration` `ttl`

### Endpoint / process

`process` `process_name` `process_exec` `process_path` `process_id` `process_guid` `process_hash` `process_current_directory` `process_integrity_level` `parent_process` `parent_process_name` `parent_process_path` `parent_process_id` `parent_process_guid` `parent_process_exec` `original_file_name` `os`

### Raw Windows / Sysmon (not CIM, but detection-critical)

`CommandLine` `Process_Command_Line` `EventCode` `EventID` `Logon_Type` `TargetUserName` `SubjectUserName` `Image` `ParentImage` `TargetFilename` `ImageLoaded` `Hashes` `QueryName`

### File / malware / web / DNS / registry

See tables in [common-fields.md](common-fields.md). Highlights: `file_name` `file_path` `file_hash` `url` `http_method` `http_user_agent` `query` `answer` `registry_path` `registry_value_name` `service_name` `signature` `signature_id` `severity`

### ES notable / risk conventions

`firstTime` `lastTime` `count` `risk_score` `risk_object` `risk_object_type` `search_name` `normalized_risk_object`

## `tstats` prefix map

| `datamodel=…` | Prefix before drop macro |
| --- | --- |
| `Endpoint.Processes` | `Processes.*` |
| `Endpoint.Filesystem` | `Filesystem.*` |
| `Endpoint.Registry` | `Registry.*` |
| `Authentication.Authentication` | `Authentication.*` |
| `Network_Traffic.All_Traffic` | `All_Traffic.*` |
| `Web.Web` | `Web.*` |
| `Intrusion_Detection.IDS_Attacks` | `IDS_Attacks.*` |
| `Malware.Malware_Attacks` | `Malware_Attacks.*` |
| `Change.All_Changes` | `All_Changes.*` |
| `Network_Resolution.DNS` | `DNS.*` |

## Gaps to close later (docs or field catalog)

1. Certificates model fields (`ssl_*`, `subject`, `issuer`, …) if TLS detections become first-class.
2. Data Access full object inventory.
3. Inventory / Performance models — only if product scope expands beyond ES correlation searches.
4. A real `catalogs/spl/fields.toml` (or similar) for completion/hover — **not** present today.

## Related

- [common-fields.md](common-fields.md) — detailed notes / alias cheat-sheet
- [macros.md](macros.md) — `` `drop_dm_object_name` `` / CIM index macros
- [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md) — no field completions yet
