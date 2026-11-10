<!--
Copied verbatim from opentidehq/specifications specs/platforms/bitdefender-1.0.md
(sections "`detection` (BitdefenderDetection)" and "Criteria catalogue"),
commit a6378a8787a19a47ee05cc2eb3987c75961d6237. CC BY 4.0, see SOURCES.md.
crates/opentide-tide/tests/bitdefender_spec.rs holds catalogs/bitdefender/criteria.toml
to these tables. When the spec changes, paste the new sections here.
-->

### `detection` (BitdefenderDetection)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target` | string | yes | — | A GravityZone detection target, as the API spells it: `process`, `file`, `connection`, `registry`, `user connection`, `email`, `application`, `key vault`, `role`, `policy`, `sharing link`, `url`, `ssh key`, `launch template`, `service principal`, `user group`, `automation account`, `automation account hook`, `certificate authority`, `api`, `bucket`, `jira project`, or `confluence page` |
| `criteria` | list[Criterion] | yes | — | At least one. All criteria must match (AND). |
| `alert` | string | optional | null | A GravityZone alert (detection) name. Sent as `filters: [{"field": "detection", "value": <alert>}]`. |

### Criteria catalogue

The fields per target, their kinds, their enum values, and the pairing rules are Bitdefender's [Detection and exclusion criteria for Basic rules](https://www.bitdefender.com/business/support/en/77209-1486297-detection-and-exclusion-criteria.html). The language server ships them as data in `catalogs/bitdefender/criteria.toml`, generated from that page. The EDR targets:

| Target | Fields |
|--------|--------|
| `process` | `Process.Name`, `Process.Path`, `Process.FullPathName`, `Process.CommandLine`, `Process.Parent.Name`, `Process.Parent.Path`, `Process.Parent.FullPathName`, `Process.Parent.CommandLine`, `Process.User`, `Process.MD5`, `Process.SHA2` |
| `file` | `File.Name`, `File.Path`, `File.FullPathName`, `File.Operation`, `File.CreatedBy.Name`, `File.CreatedBy.Path`, `File.CreatedBy.FullPathName`, `File.CreatedBy.CommandLine`, `File.CreatedBy.User`, `File.CertificateSigner`, `File.CertificateIssuer`, `File.CertificateSignedStatus`, and the XDR fields `File.MD5`, `File.SHA2`, `File.Url`, `File.SourceIP`, `File.DestinationIP` |
| `connection` | `Connection.SourceIP`, `Connection.DestinationIP`, `Connection.SourcePort`, `Connection.DestinationPort`, `Connection.Process.Name`, `Connection.Process.Path`, `Connection.Process.FullPathName`, `Connection.Process.CommandLine`, `Connection.Process.User`, `Connection.URL`, `Connection.Domain`, `Connection.Protocol`, `Connection.HTTPUser`, `Connection.HTTPDownloadedFile`, `Connection.HTTPUploadedFile`, `Connection.FTPUser`, `Connection.SSHUser`, `Connection.TelnetUser`, `Connection.SMBDomain`, `Connection.SMBSharePath`, `Connection.SMBUser`, `Connection.WMIExecQuery`, `Connection.FileRemotePath`, `Connection.FileRemoteOperation` |
| `registry` | `Registry.Key`, `Registry.Value`, `Registry.Data`, `Registry.DataType`, `Registry.Operation`, `Registry.CreatedBy.Name`, `Registry.CreatedBy.Path`, `Registry.CreatedBy.FullPathName`, `Registry.CreatedBy.CommandLine` |

| Enum field | Values |
|------------|--------|
| `File.Operation` | `rename`, `copy`, `create` (EDR only); `shared`, `downloaded`, `uploaded` (XDR only); `read`, `write`, `move` |
| `File.CertificateSignedStatus` | `is_signed`, `is_unsigned` |
| `Connection.Protocol` | `http/https`, `smb` |
| `Connection.FileRemoteOperation` | `create`, `rem_delete`, `read`, `write`, `move` |
| `Registry.Operation` | `key_created`, `key_deleted`, `key_renamed`, `value_created`, `value_deleted`, `value_written` |
| `Registry.DataType` | `string`, `expandablestring`, `dword`, `qword`, `binary`, `none`, `link`, `resource_list`, `full_resource_descriptor`, `resource_requirements_list` |
