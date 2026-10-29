# CIM data models and fields (detections)

The Splunk Common Information Model (CIM) data models, their datasets and field names, as the engine knows them for ES / ESCU-style `splunk.query` blocks.

Citations:

- [CIM fields](https://docs.splunk.com/Documentation/CIM/latest/User/CIMfields)
- [CIM data models](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- Narrative field notes: [common-fields.md](common-fields.md)

After `| tstats … from datamodel=Model.Dataset`, fields are prefixed (`Processes.process_name`) until a macro such as `` `drop_dm_object_name(Processes)` `` strips the dataset prefix.

## The catalog

`catalogs/spl/datamodels.toml` lists every CIM data model (Alerts, Authentication, Certificates, Change, Compute_Inventory, DLP, Data_Access, Databases, Email, Endpoint, Event_Signatures, Interprocess_Messaging, Intrusion_Detection, JVM, Malware, Network_Resolution, Network_Sessions, Network_Traffic, Performance, Ticket_Management, Updates, Vulnerabilities, Web), every dataset with its lineage, and every field each dataset defines. `scripts/sync_cim_datamodels.py` generates it from `splunk/pytest-splunk-addon` (`pytest_splunk_addon/data_models`, Apache-2.0), the files Splunk uses to test add-ons for CIM compliance, and adds:

- `_time`, `host`, `source`, `sourcetype` (the CIM base event) on every dataset;
- `tag` and the Enterprise Security asset and identity fields (`dest_bunit`, `dest_category`, `dest_priority`, the same for `src`, `user`, `src_user`, `dvc`, and `dest_requires_av`, `dest_should_timesync`, `dest_should_update`, `dest_is_expected`) on every root dataset;
- fields CIM 4.x defines that CIM 5 dropped (`Authentication.src_nt_domain`, `DNS.src_port`, ...), since searches written for a CIM 4.x install still read them;
- the deprecated CIM models (Application_State, Change_Analysis) and the data models Enterprise Security adds (Risk, Threat_Intelligence, Identity_Management, Assets_And_Identities, ...) by name only: their fields are never checked.

Completion offers a dataset's fields with their prefix (`Processes.process_name`, `All_Email.Filtering.filter_action`) and, after `Prefix.field=`, the values CIM expects for the field (`Authentication.action=` → `success`, `failure`, ...). Hover shows the data model.

## Checks

| Code | Severity | When |
| --- | --- | --- |
| `spl_unknown_datamodel` | error | `datamodel=`, `| datamodel M D`, `| from datamodel:M.D` or `| pivot M D` names a data model or dataset the catalog lacks that is a near miss of a CIM one (`Endpont.Processes`, `Endpoint.Process`). The suggestion is the corrected name. |
| `spl_unknown_datamodel_field` | error | `Prefix.field` names a field the dataset's root lacks that is a near miss of one it has (`Processes.proces_name` → `Processes.process_name`). |

Precision over recall: sites add fields and datasets to their CIM models, and apps add data models, so a name the catalog lacks is **not** an error by itself. A near miss is one edit away for a name of up to five characters and two for a longer one (a swapped pair of letters counts as one); names shorter than four characters are never misses. Field names are case-sensitive; data model and dataset names are not.

Where the check applies:

- A data model reference brings its root dataset's prefix into scope (`datamodel=Network_Traffic` brings `All_Traffic`; `datamodel=Endpoint` brings all five Endpoint roots). A child dataset (`Authentication.Failed_Authentication`) brings its root and its own name.
- A field a child dataset defines is named by its lineage (`All_Changes.Account_Management.src_user`, `All_Email.Filtering.filter_action`).
- The prefix stops applying after `` `drop_dm_object_name(Processes)` `` (quoted or not) or `| rename Processes.* as *`. `process_name` without a prefix is never checked.
- Not checked: names in strings, macros and comments, values (`x=Processes.y`), `nodename=` dataset paths, the target of `as`, an `eval` assignment target, wildcards (`Processes.*`), and a prefix of a data model the search does not read. A subsearch has its own data model.
- Expected values are not checked: CIM lists them as recommendations, and real add-ons emit others (`DNS.reply_code=NXDOMAIN`).

`splunk/security_content`'s detections are the false-positive corpus: at commit `70e15c6`, its 2,207 detections (about 21,000 `Prefix.field` references in the 1,100 that read a data model) and 404 removed detections and baselines give no `spl_unknown_datamodel` or `spl_unknown_datamodel_field` error. Dropping one letter from one CIM field in each of the 1,084 data model searches is caught in 1,081; the three it misses are rename targets (`as Processes.original_file_name`).

## Indexes, sourcetypes and macros

`spl_dataset_not_declared` (warning) checks the names a search reads against the `indexes`, `sourcetypes` and `macros` a workspace declares on its `system = "splunk"` log sources in `visibility.toml` (opentide writes them to `.opentide/lsp/catalogs/generated/datasets.json`):

- `index=`, `index::`, `index IN (...)` and the same for `sourcetype`, in the base search (before the first pipe, or a `search` command that starts the query; each subsearch has its own) and in a `tstats` `where` clause. Negated terms (`NOT index=x`, `index!=x`) are not checked.
- Macro calls in the base search, before the first pipe: `` `wineventlog_security` ``, `` `cim_Endpoint_indexes` ``. A macro with arguments matches a declared `name` or `name(N)`. Macros after a pipe are utilities (`drop_dm_object_name`, `security_content_ctime`, `security_content_summariesonly`) or filters and are never checked; neither is `comment` or a `*_filter` macro.
- `source=` is not checked: `visibility.toml` declares no kind for it.
- Declared names may hold `*`; Splunk names match without regard to case.

A kind is checked only in a workspace that declares at least one name of that kind for Splunk, so a workspace that declares nothing sees no warning. Fields of raw sourcetypes are never checked. A search with no index and no macro at all is the slow-query checks' concern (#56), not this one.

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
| `Email.All_Email` | `All_Email.*` |

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

## Related

- [common-fields.md](common-fields.md) — detailed notes / alias cheat-sheet
- [macros.md](macros.md) — `` `drop_dm_object_name` `` / CIM index macros
- [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md)
