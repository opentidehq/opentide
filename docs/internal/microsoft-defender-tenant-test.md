---
title: Microsoft Defender tenant test plan
description: Step-by-step checks a person with a Microsoft Defender XDR tenant runs to confirm or correct the ten positions microsoft-defender-1.0 takes where the Graph beta docs are silent.
---

# Microsoft Defender tenant test plan

`microsoft_defender` deploys custom detection rules through the Microsoft Graph **beta** custom
detection API, `https://graph.microsoft.com/beta/security/rules/detectionRules`
([microsoft-defender-1.0](https://github.com/opentidehq/specifications/blob/main/specs/platforms/microsoft-defender-1.0.md),
[RFC 0021](https://github.com/opentidehq/specifications/blob/main/rfcs/0021-defender-graph-beta-detection-rules.md)).
The Graph documentation leaves ten questions open. opentide 1.0 implements the position the
specification takes for each; this page is how someone with a tenant confirms each position, or
records what Graph does instead, before 1.0.0 GA.

Every check below is one `curl` call or one `opentide` command. Each ends with **Expected** (the
specification's position, what opentide does today) and **If not** (what to change, and where).
Record each result in the table at the end and attach it to the tracking issue.

## Before you start

You need:

- a Microsoft Defender XDR tenant with Defender for Endpoint onboarded (one test device is
  enough), and, for check 6, a tenant that also has Defender for Office 365, Identity or Cloud
  Apps if you can get one;
- an Entra ID app registration with the **application** permission
  `CustomDetection.ReadWrite.All` (granted admin consent), and `ThreatHunting.Read.All` for the
  advanced hunting checks;
- a client secret for it, and `curl` and `jq`;
- opentide 1.0 (a release candidate or a build of `integration/unified-core`).

Use a test tenant, or a test device group in your tenant: the checks create, change and delete
custom detection rules, and check 6 runs automated actions only if you add some (none of the
bodies below do).

Set the variables once:

```bash
export MDE_TENANT_ID=…  MDE_CLIENT_ID=…  MDE_CLIENT_SECRET=…
export BASE=https://graph.microsoft.com/beta/security/rules/detectionRules
export TOKEN=$(curl -s -X POST \
  "https://login.microsoftonline.com/$MDE_TENANT_ID/oauth2/v2.0/token" \
  -d client_id="$MDE_CLIENT_ID" -d client_secret="$MDE_CLIENT_SECRET" \
  -d scope=https://graph.microsoft.com/.default -d grant_type=client_credentials | jq -r .access_token)
g() { curl -s -w '\nHTTP %{http_code}\n' -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' "$@"; }
```

`g` prints Graph's answer and its status. Each check uses its own fresh uuid (`uuidgen | tr A-Z a-z`)
so the checks do not depend on each other. Delete every rule you create at the end (check 2c deletes
its own).

A minimal body, used by several checks (replace `$ID`):

```bash
body() { cat <<EOF
{
  "id": "$1",
  "displayName": "opentide tenant test $1",
  "description": "opentide 1.0 tenant test, safe to delete",
  "status": "disabled",
  "queryCondition": {"queryText": "DeviceProcessEvents | where FileName =~ \"opentide-test.exe\""},
  "schedule": {"frequency": "${2:-PT1H}"},
  "detectionAction": {
    "alertTemplate": {
      "title": "opentide tenant test",
      "description": "opentide tenant test",
      "severity": "low",
      "entityMappings": {"hosts": [{"deviceIdColumn": "DeviceId"}]}
    }
  }
}
EOF
}
```

The rules are created `disabled`, so none of them runs.

## 1. The NRT frequency

The specification sends near real time as `PT0S` (`frequency: NRT`).

1. `ID=$(uuidgen | tr A-Z a-z); g -X POST "$BASE" -d "$(body $ID PT0S)"`
2. `g "$BASE/$ID" | jq .schedule`

**Expected:** `201`, and the rule reads back with a near-real-time schedule (the portal shows
"Continuous (NRT)").

**If not:** repeat step 1 with `PT0M`, then `P0D`. Record which one Graph accepts. If one does,
change `Duration::iso8601` in `crates/opentide-schema/src/objects/platform/microsoft_defender.rs`
(the `NearRealTime` arm) and the spec's `schedule` table. If none does, Graph cannot create an NRT
rule through this API: report it, and the spec makes `NRT` a `microsoft_defender_frequency` error.

## 2. 404 and 409

The specification assumes `404` for an id the tenant does not have, on `PATCH` and on `DELETE`,
and `409` for a `POST` whose `id` exists.

a. Unknown id on `PATCH`:
   `g -X PATCH "$BASE/$(uuidgen | tr A-Z a-z)" -d '{"status":"disabled"}'`

b. Existing id on `POST`: `ID=$(uuidgen | tr A-Z a-z); g -X POST "$BASE" -d "$(body $ID)"`, then the
   same `POST` again.

c. `DELETE`: `g -X DELETE "$BASE/$ID"` (expect `204`), then the same `DELETE` again.

**Expected:** a: `404`. b: `201`, then `409`. c: `204`, then `404`.

**If not:** record the status and the `error.code` of each answer. opentide treats only `404` as
"absent" (`crates/opentide-connectors/src/microsoft_defender.rs`: `upsert`, `disable`, `delete`). If Graph answers `400`
or `403` for an unknown id, the deployer must `GET {base}/{uuid}` first and decide on its `404`; if
the second `POST` is not `409`, the concurrent-create path changes. Either is a spec change
(microsoft-defender-1.0, Deploy).

## 3. PATCH on nested objects

The update page says only that an omitted `incidentConfiguration` "leaves the existing setting
unchanged". opentide sends the whole body on every update and omits unset keys. If Graph merges,
removing a key from the YAML does not clear it in the tenant.

1. Create a rule with everything that can be removed later:

   ```bash
   ID=$(uuidgen | tr A-Z a-z)
   g -X POST "$BASE" -d "$(body $ID | jq '.schedule.lookback="PT4H"
     | .detectionAction.alertTemplate.customDetails={"Name":"DeviceName"}
     | .detectionAction.alertTemplate.eventGroupingKind="singleAlert"
     | .detectionAction.alertTemplate.entityMappings.files=[{"sha1Column":"SHA1"}]
     | .detectionAction.organizationalScope={"deviceGroups":["<a device group of yours>"]}
     | .detectionAction.incidentConfiguration={"isExcludedFromIncidentCorrelation":true}')"
   ```

2. `PATCH` the minimal body (no lookback, custom details, grouping, files mapping, scope or
   incident): `g -X PATCH "$BASE/$ID" -d "$(body $ID | jq 'del(.id)')"`
3. `g "$BASE/$ID" | jq '{schedule, t: .detectionAction.alertTemplate, s: .detectionAction.organizationalScope, i: .detectionAction.incidentConfiguration}'`

**Expected (the position opentide relies on):** after step 2 the rule has no lookback (or the
default), no custom details, `eventGroupingKind` `alertPerEvent` (or absent), only the `hosts`
mapping, no scope, and incident correlation unchanged (`true`, as documented).

**If not:** list each property that kept its step-1 value. For each, a 1.x minor sends an explicit
empty value when the key is unset (`[]`, `{}`, `alertPerEvent`, `false`): record which, so the change
is one table in `crates/opentide-compile/src/microsoft_defender.rs` (`body_with_warnings` and `alert_template`). The
`incidentConfiguration` result decides whether `incident` removed from the YAML must send
`{"isExcludedFromIncidentCorrelation": false}`.

## 4. Tactic values

opentide sends ATT&CK tactic names without spaces (`InitialAccess`, `DefenseEvasion`,
`CommandAndControl`), and technique ids as the `att&ck` vocabulary resolves them (ATT&CK v19).

1. Create a rule whose alert template has these tactics:

   ```json
   "tactics": [
     {"tactic": "DefenseEvasion", "techniques": [{"technique": "T1078", "subTechniques": ["T1078.004"]}]},
     {"tactic": "CommandAndControl", "techniques": [{"technique": "T1071"}]}
   ]
   ```

2. Read it back, and open it in the portal (Hunting > Custom detection rules).

**Expected:** `201`; the read-back holds both tactics as sent; the portal shows Defense Evasion
and Command and Control with their techniques.

**If not:** try `"Defense Evasion"` (display name) and `"TA0005"` (id) in turn and record which
Graph accepts and the portal shows. The mapping is `TACTICS` in
`crates/opentide-compile/src/microsoft_defender.rs`. Also try a v19-only technique id (one the
`att&ck` vocabulary marks as added in v19) and record whether Graph accepts it; if not, Defender
needs Sentinel's v18 fallback (`crates/opentide-compile/src/sentinel.rs`, `v18_replacement`).

## 5. Technique nesting

opentide sends the parent in `technique` and the sub-technique in `subTechniques`
(`{"technique": "T1059", "subTechniques": ["T1059.001"]}`); Graph's create example puts
`T1059.001` in `technique`.

1. Create a rule with `{"tactic": "Execution", "techniques": [{"technique": "T1059", "subTechniques": ["T1059.001"]}]}`.
2. Create another with `{"tactic": "Execution", "techniques": [{"technique": "T1059.001"}]}`.
3. Read both back and compare them in the portal.

**Expected:** both are accepted; the first shows T1059.001 under T1059.

**If not:** if only the second form is accepted, or the first loses the sub-technique, record it:
the tree is built in `tactics` in `crates/opentide-compile/src/microsoft_defender.rs`.

## 6. Which entity mappings Defender honours

All seventeen kinds are on one Graph type. The specification accepts every kind, requires a
mapping to name at least one column (an opentide rule), and only warns
(`microsoft_defender_no_entities`) when a block maps none.

1. In a tenant with Defender for Endpoint only, create one rule per kind with one mapping of one
   column (the complete example's columns:
   `tests/fixtures/microsoft_defender/microsoft-defender-complete.yaml`). Use a query that projects
   that column, for example `DeviceProcessEvents | project Timestamp, DeviceId, ReportId, AccountSid`.
2. Create a rule with no `entityMappings` at all.
3. Repeat step 1 in a tenant with the other Defender products, if you have one.

**Expected:** every kind is accepted at create (`201`) in both tenants; the rule with no mapping is
accepted too.

**If not:** list the kinds refused, with Graph's message, and whether a rule without a mapping is
refused. A refused kind on an Endpoint-only tenant becomes an advisory; a required mapping makes
`microsoft_defender_no_entities` an error. Both are spec changes (Constraints, Advisories). Note
which columns each kind needed to show an entity in the alert: the docs list none.

## 7. Frequencies and lookback bounds

opentide accepts any `NRT`, `<n>H` or `<n>D`, and checks only that `lookback` is at least
`frequency` and absent with NRT.

1. Create rules with frequency `PT1H`, `PT3H`, `PT12H`, `PT24H`, `P1D`, then `PT2H`, `PT6H`, `P2D`.
2. Create rules with `frequency: PT1H` and lookback `PT1H`, `P7D`, `P14D`, `P30D`, `P31D`.
3. Create a rule with `frequency: PT3H, lookback: PT1H` (shorter than the frequency).

**Expected:** step 1: the first five are accepted (Defender's documented 1, 3, 12 and 24 hours;
`P1D` is 24 hours); record the answer for the others. Step 2: record the largest lookback Graph
accepts. Step 3: refused (`400`), which opentide refuses before the call
(`microsoft_defender_lookback`).

**If not / to record:** the accepted frequencies and the largest lookback. If Graph accepts only
the documented frequencies, the spec can tighten `microsoft_defender_frequency`; the check is
`schedule` in `crates/opentide-schema/src/objects/platform/microsoft_defender/checks.rs`.

## 8. The client id

opentide uses the rule's lowercase canonical `metadata.uuid` as `id` and compares ids exactly.

1. Create a rule with an upper-case uuid as `id`, then `GET` it with the lower-case form.
2. Create a rule whose `id` is not a uuid (`opentide-test-1`).
3. `GET "$BASE?\$filter=id eq '$ID'"` for a rule you created, and list `$BASE` to see how ids are
   returned.

**Expected:** a lower-case uuid round-trips unchanged; record whether Graph folds case (step 1) and
whether it takes a non-uuid id (step 2).

**If not:** if Graph rewrites the id (case, braces, its own id instead of ours), deploy cannot
address the rule by uuid and the platform needs deployment state: report it at once, as it changes
the identity model (RFC 0021, Identity).

## 9. Custom detail limits

1. Create a rule with 20 custom details (`Detail1` … `Detail20`, each a projected column).
2. Create rules with a detail name holding a space, a dot, a non-ASCII letter, and a 100-character
   name.

**Expected:** record the largest count accepted, and which names are refused, with Graph's message.

**If not / to record:** limits found become `microsoft_defender_custom_details` constraints in the
spec and in `checks.rs` (`custom_details`).

## 10. Which identifiers each entity kind requires

Graph's entity mapping types list their columns, not which are required, and Graph checks a
rule's mappings when it creates or enables the rule, not while the rule is disabled. One rule is
known from production: a `registryValues` mapping with `valueNameColumn` and no `keyColumn` is
refused with `HTTP 400 · Entity mapping for type 'RegistryValue' does not include a required
identifier. Supported identifiers: RegKey | Name` (#1884). opentide enforces it
(`microsoft_defender_entity_identifier`, the table `ENTITY_IDENTIFIERS` in
`crates/opentide-schema/src/objects/platform/microsoft_defender.rs`); every other kind needs one
of its fields.

1. For each kind with more than one field (`hosts`, `accounts`, `files`, `processes`, `ips`,
   `dns`, `registryValues`, `mailMessages`, `mailClusters`, `cloudApplications`,
   `securityGroups`), create a **disabled** rule whose only mapping sets one column, once per
   column (`entityMappings: {"ips": [{"scopeColumn": "RemoteIPType"}]}`), with a query that
   projects it.
2. Enable each rule Graph created (`PATCH {"status": "enabled"}`), then disable it again.
3. For `registryValues`, also try `keyColumn` alone.

**Expected:** every single-column mapping is accepted at create and at enable, except
`registryValues` with `valueNameColumn` alone (refused, as above).

**If not:** record each refused combination with Graph's message (its "Supported identifiers"
list names the kind's identifiers). Each becomes a row of `ENTITY_IDENTIFIERS` with
`Evidence::Observed`, the message as its reference and the date, and a case in
`crates/opentide-schema/tests/microsoft_defender.rs`; and a spec change (microsoft-defender-1.0,
Constraints). Note which identifiers made the alert show an impacted device, user or mailbox: the
warning `microsoft_defender_impacted_asset_identifier` relies on Defender's documented strong
identifiers (`DeviceId`, `DeviceName`; `AccountObjectId`, `AccountSid`, `AccountUpn`).

## End to end with opentide

After the curl checks, run the platform the way users will:

1. `opentide setup --platform microsoft_defender`, then fill `.opentide/configurations/platforms/microsoft_defender.toml` with one tenant whose `setup` names the three variables above.
2. `opentide doctor --live`: the tenant is reachable.
3. `opentide new rule --platform microsoft_defender`, keep the template's `schedule.frequency: 1H`,
   uncomment one `hosts` mapping, write a query (`DeviceProcessEvents | where FileName =~ "opentide-test.exe" | project Timestamp, DeviceId, ReportId`), and set `status` to a status of your
   `deployment.toml` whose strategy is `PREVIEW`.
4. `opentide validate` and `opentide validate query --platform microsoft_defender --live <file>`.
5. `opentide deploy --dry-run --platform microsoft_defender --json`: the payload is
   `PATCH {base}/{uuid}` with the body.
6. `opentide deploy --platform microsoft_defender`: the rule is **created** (`404` then `POST`).
   Deploy again: it is **updated** (one `PATCH`).
7. Set a DISABLEMENT status and deploy: `status: disabled` in the portal. Deploy the same rule with
   another uuid that the tenant does not hold: `microsoft_defender_rule_absent`, nothing created.
8. Set a DELETION status and deploy: the rule is gone. Deploy again: "already gone".
9. Delete the rule file and run `opentide deploy --prune`: a rule deployed from it is deleted by uuid.

**Expected:** each step as written. Any difference is a bug to file against opentide, with the
`--json` output attached.

## Results

| # | Question | Result | Graph's answer, if different | Follow-up |
|---|----------|--------|-------------------------------|-----------|
| 1 | NRT encoding (`PT0S`) | | | |
| 2 | 404 on PATCH and DELETE, 409 on POST | | | |
| 3 | PATCH replaces nested objects | | | |
| 4 | Tactic values (`DefenseEvasion`), v19 ids | | | |
| 5 | Parent in `technique`, sub in `subTechniques` | | | |
| 6 | Every entity kind accepted; none required | | | |
| 7 | Frequencies, largest lookback | | | |
| 8 | The uuid as client id, compared exactly | | | |
| 9 | Custom detail count and names | | | |
| 10 | Required identifiers per entity kind | | | |
