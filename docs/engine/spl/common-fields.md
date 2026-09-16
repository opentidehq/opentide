# Common fields (CIM / ES detections)

Fields that appear in Splunk Enterprise Security detections, CIM-normalized data, and OpenTide `splunk.query` blocks. Default Splunk fields are always present; CIM fields exist when a TA / datamodel maps them.

Data-model coverage checklist: [cim-fields.md](cim-fields.md). There is **no** field catalog in `catalogs/spl/` yet (docs only).

Citations:

- [CIM fields per associated data model](https://docs.splunk.com/Documentation/CIM/latest/User/CIMfields)
- [Use default fields](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Usedefaultfields)
- [Windows CIM field mapping](https://docs.splunk.com/Documentation/WindowsAddOn/latest/User/CIMModelandFieldMappingChanges)
- [Intrusion Detection datamodel](https://docs.splunk.com/Documentation/CIM/latest/User/IntrusionDetection)

After `| tstats … from datamodel=Endpoint.Processes`, fields are prefixed (`Processes.process_name`) until `` `drop_dm_object_name(Processes)` ``.

## Default Splunk fields

| Field | Kind | Notes |
| --- | --- | --- |
| `index` | search modifier | Index name. Always constrain detections (`index=wineventlog` or a CIM index macro). |
| `sourcetype` | search modifier | e.g. `WinEventLog:Security`, `XmlWinEventLog:Security`, `sysmon:process` |
| `source` | search modifier | Originating path / input |
| `host` | search modifier | Originating host (not always CIM `dest`) |
| `_time` | internal | Event timestamp (UTC epoch internally). `min(_time)` / `max(_time)` as `firstTime`/`lastTime` is an ES convention. |
| `_raw` | internal | Raw event text. Dropped after transforming commands. Keyword searches without `field=` scan `_raw`. |
| `_indextime` | internal | Index time |
| `splunk_server` | search modifier | Search peer |
| `linecount` | extracted | Lines in the event |
| `punct` | extracted | Punctuation pattern |
| `eventtype` | knowledge | Event type matches |
| `tag` | knowledge | Tags (`tag=authentication`) |
| `date_hour`, `date_mday`, `date_month`, `date_year`, `date_wday`, `date_zone` | date | Broken-out time; **do not** use for range filters — use `earliest`/`latest` / `_time` |
| `timestamp` | extracted | Original timestamp string |

Citation: [Use default fields](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Usedefaultfields).

## Identity / assets (CIM)

| Field | Models | Detection use |
| --- | --- | --- |
| `user` | Auth, Endpoint, Change, Web, … | Account involved. Normalize with `lower(user)` / `coalesce(user, src_user, User)`. |
| `src_user` | Auth, Change, Email, DLP | Initiating user (e.g. runas / email sender) |
| `user_id`, `user_name`, `user_role`, `user_type`, `user_group` | Auth, Endpoint, Data Access | Directory identifiers |
| `src_nt_domain`, `dest_nt_domain` | Auth, Change, Malware | Windows domain |
| `src_bunit`, `dest_bunit`, `user_bunit` | most models | ES asset/identity category (business unit) |
| `src_category`, `dest_category`, `user_category` | most models | Asset category |
| `src_priority`, `dest_priority`, `user_priority` | most models | Asset priority |

## Network (CIM)

| Field | Models | Detection use |
| --- | --- | --- |
| `src` | Alerts, Auth, Endpoint, IDS, Web, … | Source host (may be name, IP, or alias of `src_ip`) |
| `dest` | almost all | Destination / victim host. ES notables key off `dest`. |
| `dvc` | Change, DLP, IDS, Network Traffic | Observing device (sensor, firewall) |
| `src_ip`, `dest_ip` | Inventory, Network Sessions, Network Traffic | IP-specific; alias into `src`/`dest` when needed |
| `src_port`, `dest_port` | Certificates, Endpoint, IDS, DNS, Network Traffic, Web | Ports |
| `src_mac`, `dest_mac` | Network Sessions, Network Traffic | MAC |
| `src_translated_ip`, `dest_translated_ip` | Network Traffic | NAT |
| `transport` | Certificates, Endpoint, IDS, DNS, Network Traffic | `tcp` / `udp` / `icmp` |
| `protocol` | Change, Email, Network Traffic | App protocol |
| `bytes`, `bytes_in`, `bytes_out` | Network Traffic, Web | Volume |
| `packets`, `packets_in`, `packets_out` | Network Traffic | Packet counts |
| `rule` | Network Traffic | Firewall / IDS rule name |
| `action` | Auth, Change, Endpoint, IDS, Malware, Network Traffic, Web | `allowed`, `blocked`, `failure`, `success` |
| `vendor_product` | most security models | Product name (`Sysmon`, `CrowdStrike`, …) |
| `app` | Alerts, Auth, Network Traffic, Web | Application |
| `duration` | Auth, DNS, Network Traffic, Web | Session / request duration |
| `ttl` | DNS, Network Traffic | Time-to-live |

## Endpoint / process (CIM Endpoint + Windows TA)

| Field | Notes |
| --- | --- |
| `process` | Full command line **or** process path depending on TA. CIM Endpoint recommended. |
| `process_name` | Image name (`cmd.exe`). Sysmon EventCode 1, Windows 4688. |
| `process_exec` | Executable file name |
| `process_path` | Full path to image |
| `process_id` | PID |
| `process_guid` | Sysmon / CIM GUID |
| `process_hash` | Image hash |
| `process_current_directory` | CWD |
| `process_integrity_level` | Windows integrity |
| `parent_process` | Parent command line / path |
| `parent_process_name` | Parent image name |
| `parent_process_path` | Parent path |
| `parent_process_id` | PPID |
| `parent_process_guid` | Parent GUID |
| `parent_process_exec` | Parent exec name |
| `CommandLine` | **Raw Windows/Sysmon field** (not CIM). Map to `process` / `process_command_line`. |
| `Process_Command_Line` | Windows TA XML 4688 |
| `process_command_line_arguments` | Windows TA split of argv |
| `original_file_name` | PE original filename (lolbin detections) |
| `os` | OS family |

Citation: [CIM fields](https://docs.splunk.com/Documentation/CIM/latest/User/CIMfields), [Windows CIM mapping (4688)](https://docs.splunk.com/Documentation/WindowsAddOn/latest/User/CIMModelandFieldMappingChanges).

## Windows event identifiers

| Field | Notes |
| --- | --- |
| `EventCode` | Classic WinEventLog field (`4688`, `4624`, `1` for Sysmon). **Not** a CIM name. |
| `event_id` | CIM / XML Windows TA equivalent |
| `signature` | Human-readable event / signature name (CIM recommended) |
| `signature_id` | Numeric / vendor ID (often `EventCode` aliased) |
| `Error_Code` | Windows TA |
| `status` | Outcome (`success`, `failure`) — CIM Change/Web/Endpoint |
| `reason` | Auth failure reason |
| `Logon_Type` | Windows 4624/4625 (not CIM; commonly kept) |
| `TargetUserName`, `SubjectUserName`, `Caller_User_Name` | Raw Windows fields; alias to `user` / `src_user` |

## Files / malware

| Field | Models | Notes |
| --- | --- | --- |
| `file_name` | Email, Endpoint, IDS, Malware, Updates | |
| `file_path` | Endpoint, IDS, Malware | |
| `file_hash` | Email, Endpoint, IDS, Malware, Updates | MD5/SHA1/SHA256; pair with `eval md5()` / `sha256()` only for computed hashes |
| `file_size` | Email, Endpoint | |
| `file_create_time`, `file_modify_time`, `file_access_time` | Endpoint | |
| `file_acl` | Endpoint | |
| `original_file_name` | Endpoint | |

## Web / URL / DNS

| Field | Models | Notes |
| --- | --- | --- |
| `url` | Email, Malware, Vulnerabilities, Web | Full URL |
| `url_domain`, `url_length` | Web | |
| `uri_path`, `uri_query` | Web | |
| `http_method`, `http_user_agent`, `http_referrer`, `http_content_type` | Web | |
| `site` | Web | |
| `error_code` | Web | HTTP status (also raw `status`) |
| `query` | DNS, Databases | DNS question name |
| `query_type` | DNS | A, AAAA, TXT, … |
| `answer` | DNS | |
| `reply_code`, `reply_code_id` | DNS | |
| `record_type` | DNS | |
| `message_type` | DNS | query vs response |
| `transaction_id` | DNS | |

## Registry / service (CIM Endpoint)

| Field | Notes |
| --- | --- |
| `registry_hive` | `HKLM`, `HKCU`, … |
| `registry_path` | Full key path |
| `registry_key_name` | Key |
| `registry_value_name` | Value name |
| `registry_value_data` / `registry_value_text` | Data |
| `registry_value_type` | REG_SZ, … |
| `service`, `service_name`, `service_path`, `service_exec` | Windows services |
| `service_dll`, `service_dll_path`, `service_hash`, `service_dll_hash` | Service image / svchost DLL |
| `start_mode`, `state` | Service start / state |

## Authentication / change / alerts

| Field | Models | Notes |
| --- | --- | --- |
| `action` | Auth, Change, … | `success`, `failure`, `created`, `deleted`, `modified` |
| `authentication_method`, `authentication_service` | Auth | |
| `change_type` | Change | |
| `object`, `object_path`, `object_attrs`, `object_category`, `object_id` | Change, Data Access, DLP | |
| `command` | Change | Command executed (not always Endpoint `process`) |
| `result`, `result_id` | Change | |
| `severity`, `severity_id` | Alerts, IDS, DLP, Vulnerabilities | |
| `ids_type` | Intrusion Detection | |
| `category` | DLP, IDS, Malware, Web | |
| `mitre_technique_id` | Alerts | ATT&CK technique on notables |
| `vendor_account`, `vendor_region`, `vendor_product_id` | Alerts, Change, Cloud | Cloud account context |
| `src_user_id`, `src_user_role`, `src_user_type` | Auth | |

## Email

| Field | Notes |
| --- | --- |
| `recipient`, `recipient_domain`, `recipient_count` | |
| `orig_src`, `orig_dest`, `orig_recipient` | |
| `internal_message_id`, `message_id` | |
| `filter_action`, `filter_score` | |
| `process` | Sometimes the handling MTA process |

## ES notable / risk conventions (not CIM-required)

Detections often **create** these with `eval` before `| collect` / notable:

| Field | Convention |
| --- | --- |
| `firstTime`, `lastTime` | `min(_time)`, `max(_time)` |
| `count` | Volume |
| `risk_score`, `risk_object`, `risk_object_type` | Risk notables |
| `search_name` | Correlation search name |
| `orig_sid`, `orig_rid` | Drilldown to notable |
| `normalized_risk_object` | ES risk |

## Aliasing cheat-sheet (raw → CIM)

| Raw / TA | CIM / detection |
| --- | --- |
| `EventCode`, `EventID` | `event_id` / `signature_id` |
| `CommandLine`, `Process_Command_Line` | `process` |
| `Image`, `New_Process_Name` | `process_name` / `process_path` |
| `ParentImage`, `Parent_Process_Name` | `parent_process_name` |
| `User`, `TargetUserName`, `Account_Name` | `user` |
| `Computer`, `ComputerName`, `dvc_nt_host` | `dest` / `dvc` |
| `SourceIp`, `Source_Network_Address` | `src` / `src_ip` |
| `DestinationIp` | `dest` / `dest_ip` |
| `Hashes`, `MD5`, `SHA256` | `file_hash` / `process_hash` |
| `TargetFilename` | `file_path` / `file_name` |
| `QueryName` | `query` (DNS) |
| `ImageLoaded` | `file_path` / `process_path` (image load) |

## Datamodel prefixes (`tstats`)

| Datamodel.dataset | Typical prefixed fields |
| --- | --- |
| `Endpoint.Processes` | `Processes.process_name`, `Processes.process`, `Processes.parent_process_name`, `Processes.dest`, `Processes.user` |
| `Endpoint.Filesystem` | `Filesystem.file_name`, `Filesystem.file_path`, `Filesystem.file_hash` |
| `Endpoint.Registry` | `Registry.registry_path`, `Registry.registry_value_name` |
| `Authentication.Authentication` | `Authentication.user`, `Authentication.src`, `Authentication.action` |
| `Network_Traffic.All_Traffic` | `All_Traffic.src`, `All_Traffic.dest`, `All_Traffic.dest_port`, `All_Traffic.action` |
| `Web.Web` | `Web.url`, `Web.src`, `Web.dest`, `Web.http_method` |
| `Intrusion_Detection.IDS_Attacks` | `IDS_Attacks.signature`, `IDS_Attacks.src`, `IDS_Attacks.dest` |
| `Malware.Malware_Attacks` | `Malware_Attacks.file_name`, `Malware_Attacks.file_hash` |
| `Change.All_Changes` | `All_Changes.object`, `All_Changes.command`, `All_Changes.user` |
| `Network_Resolution.DNS` | `DNS.query`, `DNS.query_type`, `DNS.answer` |

Citation: [CIM fields](https://docs.splunk.com/Documentation/CIM/latest/User/CIMfields).
