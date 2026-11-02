---
title: Configuration
description: What lives in .opentide/configurations/ — enabling platforms, credentials, deployment statuses, promotion, and visibility.
---

# Configuration

opentide ships sensible defaults inside the package. Your repository customises them under `.opentide/configurations/`. This guide is the practical tour of that directory; the normative merge rules live in the [Configuration spec](/docs/specifications/specs/configuration/).

## How configuration is layered

opentide deep-merges configuration from several sources. Later layers win; nested tables merge, scalars replace.

```mermaid
flowchart LR
  bundled["1 · Package defaults<br/>(bundled in the wheel)"] --> platforms["2 · Bundled platform configs"]
  platforms --> client["3 · Your workspace<br/>.opentide/configurations/"]
  client --> parent["4 · Parent instance<br/>(nested workspaces)"]
```

You only ever edit **layer 3** — your workspace. You override just the keys you care about; everything else falls through to the package defaults.

```
.opentide/configurations/
├── paths.toml              # workspace directory layout
├── deployment.toml         # statuses + promotion
├── schema.toml             # template defaults
├── visibility.toml         # what is exposed/deployed
├── documentation.toml      # `opentide generate docs` settings
├── lint.toml               # `opentide lint` checks and required metadata
└── platforms/
    ├── sentinel.toml
    └── splunk.toml
```

<Callout type="warn">
Do not put vocabulary files here, and do not try to extend a vocabulary locally. Vocabularies are canonical in the [specifications](/docs/specifications/specs/vocabularies/format/) and are **not** locally extensible: a missing entry is added upstream, never injected from your repository. The CoreTIDE-era `[vocabulary]` block in `schema.toml` was removed in 0.13.0 — if you carried one, it was silently ignored by validation and is now simply dropped.

`threat.surface` is covered by that rule like every other vocabulary. Earlier releases harvested an extra surface value from a `visibility.toml` asset that named a technology, so an instance could effectively invent one; that no longer happens, and it was never a supported mechanism. A technology the catalogue does not yet name is [proposed upstream](https://github.com/opentidehq/specifications) — which is what makes a surface value mean the same thing in every opentide instance. Where a local system needs naming, the asset itself is the place for it.

Two fields are deliberately **not** vocabularies, because their values are per-organisation rather than shared: `response.responders` (your alert handling teams) and `configurations.<platform>.status` (your deployment statuses). Both are *configuration enums* — you declare the allowed values in `deployment.toml`, the generated schema offers them in your editor, and `validate` holds authored objects to them. Declaring none leaves the field unconstrained.
</Callout>

## Enabling a platform

A platform is loaded only when it is enabled in your workspace config. Create one file per platform under `platforms/`:

```toml
# .opentide/configurations/platforms/sentinel.toml
[platform]
enabled = true
```

Confirm what the engine actually loaded:

```bash
opentide info
opentide --json info --platform sentinel
```

See [Platforms](./concepts/platforms.md) for the capability matrix and the exact `--platform` identifiers.

## Credentials

Deploying rules or running live query checks needs platform credentials. Keep secrets out of the repo — reference environment variables from the platform TOML and inject them at runtime (locally via a `.env` you never commit, in CI via secrets).

```toml
# .opentide/configurations/platforms/sentinel.toml
[platform]
enabled = true

[[tenants]]
name = "Primary"
description = "Production Sentinel workspace"
strategies = ["RELEASE"]   # omit to accept PREVIEW and RELEASE

[tenants.setup]
resource_group = "rg-soc"
workspace_name = "soc-sentinel"
workspace_id = "$AZURE_WORKSPACE_ID"
azure_tenant_id = "$AZURE_TENANT_ID"
azure_subscription_id = "$AZURE_SUBSCRIPTION_ID"
azure_client_id = "$AZURE_CLIENT_ID"
azure_client_secret = "$AZURE_CLIENT_SECRET"
```

<Callout type="info">
Exact connection keys differ per platform. Use `opentide info --platform <name>` to see what a platform expects, and never commit real secrets — see [CI/CD](./workflows/ci-cd.md#secrets) for injecting them in pipelines.
</Callout>

If you sit behind an outbound proxy, pass it on the command, or set `OPENTIDE_PROXY`. Either wins over `HTTP_PROXY` and `HTTPS_PROXY`; omitting both leaves those variables as they are. Hosts listed in `NO_PROXY` are still reached directly, so an internal tenant can bypass the proxy that a cloud tenant needs ([global options](../cli/global-options.md#proxy)). The same retirement covers platform tenant config, not only `[cve].proxy`: a `proxy` key under `[tenants.setup]` or in `deployment.toml` `[proxy]` fails the command and names `opentide --proxy`.

```bash
opentide --proxy http://user:pass@proxy.internal:8080 validate --strict
```

### TLS verification

Each tenant's `ssl` decides whether opentide verifies that tenant's TLS certificate. It defaults to `true`. Set `ssl = false` for a tenant whose certificate your machine does not trust, such as an on-premises Splunk with a self-signed certificate; prefer trusting its CA (see [CI/CD → Behind a proxy or a private CA](./workflows/ci-cd.md#behind-a-proxy-or-a-private-ca)) and keeping `ssl = true`. The setting is per tenant and covers every request opentide makes to that tenant, sign-in included (the Entra ID token request for Sentinel and Defender, the OAuth token for CrowdStrike), so one run can reach a cloud tenant with verification and an internal one without.

```toml
[[tenants]]
name = "On-premises"
[tenants.setup]
ssl = false            # or "$SPLUNK_SSL", set to true or false
url = "$SPLUNK_URL"
port = "8089"
app = "search"
token = "$SPLUNK_TOKEN"
```

`ssl` takes `true` or `false`; from an environment variable, `true`/`false`, `yes`/`no`, `on`/`off` or `1`/`0` in any case. Any other value fails to load and names the tenant. An `ssl = "$VAR"` whose variable is unset fails before the first request, naming the tenant and the variable.

## Deployment statuses and strategies

Every rule's `status` must match a status defined in the merged `deployment.toml`. That is the only constraint — statuses are a configurable set, not a fixed lifecycle, and opentide does not enforce an order between them. Each status maps to a **strategy**, and the strategy alone decides what deploy does. opentide ships this default set; none of these names is special:

| Default status | Strategy | What it does |
|--------|----------|--------------|
| `DESIGN` | `INERT` | Functional design only — never deployed |
| `DEVELOPMENT` | `PREVIEW` | Under technical implementation |
| `IMPROVING` | `PREVIEW` | Qualified, being refined |
| `STAGING` | `PREVIEW` | Deployed to staging for operational testing |
| `ACCEPTANCE` | `PREVIEW` | Production-ready; analyst validating alert + playbook |
| `PRODUCTION` | `RELEASE` | Live production deployment |
| `DISABLED` | `DISABLEMENT` | Present but inactive |
| `REMOVED` | `DELETION` | Removed from platforms |

`INERT` never deploys. A `PREVIEW` run (`opentide deploy --strategy PREVIEW`, the pull or merge request job) deploys `PREVIEW` rules. A `RELEASE` run (`--strategy RELEASE`, the default-branch job) deploys `RELEASE` rules and disables or deletes `DISABLEMENT` and `DELETION` ones. Both deploy `UNIVERSAL` rules. Each rule goes to the tenants whose `strategies` accept the run's strategy. [Statuses, strategies and tenants](./concepts/statuses-and-strategies.md) explains this with worked examples.

You can add or rename statuses by overriding `deployment.toml`:

```toml
# .opentide/configurations/deployment.toml
[[statuses]]
name = "PILOT"
description = "Limited rollout to a pilot workspace"
strategy = "PREVIEW"
```

A `PREVIEW` run deploys a `PILOT` rule, exactly as it deploys a `DEVELOPMENT` one.

Full field contract: [Deployment spec](/docs/specifications/specs/deployment/).

### Which tenants a rule reaches

A tenant in a platform file lists the strategies it accepts, `PREVIEW`, `RELEASE`, or both (the default when `strategies` is omitted). `manual = true` keeps a tenant to the rules that name it under their block's `tenants`.

```toml
# .opentide/configurations/platforms/sentinel.toml
[[tenants]]
name = "Test"
strategies = ["PREVIEW"]

[[tenants]]
name = "Primary"
strategies = ["RELEASE"]
```

## Promotion

Promotion rewrites a rule's status directly to `promotion_target` — it is a single jump, not a step through intermediate statuses.

```toml
# .opentide/configurations/deployment.toml
[promotion]
enabled = true
promotion_target = "PRODUCTION"
```

`opentide setup --no-promotion` or `--promotion-target <STATUS>` writes this table, with or without `--ci`; see [setup](../cli/setup.md#default-callback-flags).

There is no separate promote command. Edit a rule's `status` in YAML for deliberate changes. When promotion is enabled, the default-branch `opentide deploy --strategy RELEASE` job applies the promotion target to each changed rule whose status maps to a strategy other than `RELEASE`, `DISABLEMENT`, or `DELETION`, then deploys it. See [`deploy`](../cli/deploy.md) and the [detection-as-code workflow](./workflows/detection-as-code.md#status-and-deployment-strategy).

## Deployment plans (removed)

opentide 0.17.0 removed deployment plans: `--plan`, `DEPLOYMENT_PLAN`, and the tenant `deployment` key fail with a message naming the replacement. A run now names the strategy it deploys with `--strategy`, and a tenant lists the strategies it accepts. The [migration table](./concepts/statuses-and-strategies.md#moving-from-deployment-plans-016-and-earlier) maps each old value.

## Unknown keys are errors

Each file is checked against its model when a command reads it, after your file is merged onto the package default. A misspelt key, a value of the wrong type, or a strategy outside the enum fails the command and names the file and key, for example `deployment.toml is invalid: promotion.enabeld: unknown key`. The value itself is never printed, so a credential in a tenant `setup` table stays out of logs. The JSON Schema of each file, for editor completion and hover, is generated from the same models; see [Configuration models](../sdk/configuration.md).

## Visibility and documentation

- `visibility.toml` declares the assets, log sources and external detectors of your environment; a rule's signals name its log sources. It is validated by a generated `visibility` schema.
- `documentation.toml` tunes `opentide generate docs` output (which folders, which sections). CVE links and optional API enrichment use [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu); see [`generate docs`](../cli/generate.md).

### The datasets a log source fills

A log source is **one dataset**, and its `name` is that dataset: the KQL table (or workspace function) for `sentinel` and `defender_for_endpoint`, the sourcetype for `splunk`, the index pattern or data stream for `elastic`. The query checks (`opentide validate`, `opentide validate query`, `opentide lint`, `opentide lsp start` and `opentide tui`) then know that name, so a custom table is not reported as unknown, and a log source can list the dataset's columns so the checks know them too.

| `system` | `name` declares | What it matches in a query |
|----------|-----------------|----------------------------|
| `sentinel`, `defender_for_endpoint` | a KQL table or workspace function | The names a KQL query reads: a pipeline's first source, a `union` leg, a `join` or `lookup` right side |
| `splunk` | a sourcetype | `sourcetype=` |
| `elastic` | an index pattern or data stream | A rule's `index`, a threat match's `index`, ES\|QL `FROM` |
| any other | nothing | — |

```toml
# .opentide/configurations/visibility.toml
[[logsources]]
name = "Contoso_Audit_CL"
description = "Administrative audit events from the Contoso connector."
system = "sentinel"
tenants = ["Production"]

[logsources.columns]
TimeGenerated = { type = "datetime" }
Actor_s = { type = "string", description = "UPN of the account that made the change" }

[[logsources]]
name = "*_CL"
description = "Every custom table."
system = "sentinel"

[[logsources]]
name = "WinEventLog:Security"          # splunk: the sourcetype
description = "Security event log of the domain controllers."
system = "splunk"

[[logsources]]
name = "logs-endpoint.events.*"        # elastic: the index pattern
description = "Elastic Defend endpoint data."
system = "elastic"

[logsources.columns]
"process.name" = { type = "keyword" }
```

- **Keys.** A log source takes `name`, `description` and `system` (required), and `tenants`, `assets`, `references` and `columns`. Any other key fails validation. `name` cannot be empty and is unique per `system`; the same name may appear under two systems (`DeviceEvents` under `sentinel` and `defender_for_endpoint`).
- **Signals** name a log source in `data.logsources` as `<name>`, `<system>::<name>` or `<system>::<tenant>::<name>`; a bare name two systems declare refers to both.
- **Patterns.** `*` matches any run of characters (`*_CL`, `logs-azure.*`). KQL and Elastic names match case-sensitively, Splunk names regardless of case. Splunk indexes and macros and Elastic data views are not declarable.
- **Opt-in per system.** A system with at least one log source is checked against its names; a system with none is checked as if nothing were declared. The bundled `visibility.toml` declares no log source.
- **Nothing is generated:** the analysis engine reads `.opentide/configurations/visibility.toml` itself. The language server (`opentide lsp start`, or `opentide-lsp` on its own) reads it again whenever it changes, in the editor before you save or on disk, and checks the open documents again; each CLI run reads it afresh. A quick fix on an undeclared name appends a new log source with that `name`, the system and an empty `description` for you to fill; it never edits another log source.

How a KQL source name is reported:

| The name is | Opted in | Report |
|---|---|---|
| declared | yes | nothing |
| known to the engine's catalog, not declared | yes | [`kql_table_not_declared`](../cli/diagnostics.md#kql_table_not_declared), warning |
| known to the engine's catalog | no | nothing |
| unknown to the catalog, not declared | either | [`kql_unknown_table`](../cli/diagnostics.md#kql_unknown_table): a warning under `sentinel`, an error under `defender_for_endpoint` |

Under opt-in a name is checked whatever its case; without, a name that starts with a lowercase letter is checked only when it ends in `_CL`, as it may be a workspace function. Under opt-in, a Splunk sourcetype that is not declared is [`spl_dataset_not_declared`](../cli/diagnostics.md#spl_dataset_not_declared), and an Elastic index pattern that is not declared is [`elastic_dataset_not_declared`](../cli/diagnostics.md#elastic_dataset_not_declared), both warnings; neither has an unknown-dataset error.

#### Columns

`columns` is a table keyed by column name, as the platform spells it (quote a name with a dot: `"process.name"`). Each value takes a `type` from the system's type set and an optional `description`; any other key fails validation, and so does `columns` on a system with no type set. Columns on a name with `*` apply to every dataset the name matches.

| `system` | Types |
|----------|-------|
| `sentinel`, `defender_for_endpoint` | KQL scalar types: `bool`, `datetime`, `decimal`, `dynamic`, `guid`, `int`, `long`, `real`, `string`, `timespan` |
| `splunk` | `string`, `number`, `boolean` |
| `elastic` | Elasticsearch field types: `binary`, `boolean`, `byte`, `constant_keyword`, `date`, `date_nanos`, `double`, `flattened`, `float`, `geo_point`, `half_float`, `integer`, `ip`, `keyword`, `long`, `match_only_text`, `nested`, `object`, `scaled_float`, `short`, `text`, `unsigned_long`, `version`, `wildcard` |

- KQL: a declared table with `columns` is checked like a documented table: a near miss of a declared column is `kql_unknown_column`, an operator the declared type does not support is `kql_type_mismatch`, and hover and completion show the declared columns. On a table the engine's catalog also knows, the declared columns extend the catalog's, and a declared column with a catalog column's name replaces its type and description. A table declared without `columns` is known by name only.
- Elastic: declared columns are fields the index pattern maps, so `ecs_unknown_field` is not reported for them and `ecs_type_mismatch` uses their declared type.
- Splunk: declared columns are offered in hover and completion where the engine has them, and are not checked.

#### Upgrading from 0.20.0

opentide 0.20.0 let one log source list datasets under `tables`, `indexes`, `sourcetypes`, `macros`, `indices`, `data_views` and `ecs`. `visibility::1.0` is corrected in place, and those keys now fail validation, each with a message that says what to do instead. Rewrite `visibility.toml` with one `[[logsources]]` per table, sourcetype or index pattern, named after it (copy the entry's `description`, `system`, `tenants`, `assets` and `references`), remove `indexes`, `macros`, `data_views` and `ecs`, and update the signals' `data.logsources` that named the old entry to the new names:

```toml
# 0.20.0
[[logsources]]
name = "Custom tables"
description = "Custom connector tables"
system = "sentinel"
tables = ["Contoso_Audit_CL", "Fabrikam_Proxy_CL"]

# 0.20.1
[[logsources]]
name = "Contoso_Audit_CL"
description = "Custom connector tables"
system = "sentinel"

[[logsources]]
name = "Fabrikam_Proxy_CL"
description = "Custom connector tables"
system = "sentinel"
```

## Lint

`lint.toml` tunes [`opentide lint`](../cli/lint.md#configuration): switch a check off, change the severity of its findings, choose which `metadata` keys every object must fill, or keep your own [file naming convention](../cli/lint.md#filename-convention). Generated templates leave those keys uncommented, so a new object and the lint check agree.

```toml
# .opentide/configurations/lint.toml
[metadata]
required = ["author"]   # replaces the default ["author", "organisation"]
severity = "warning"

[filenames]
enabled = false         # `opentide lint --check filenames` still runs it
style = "slug"          # the file stem is slugify(name) (default); "name" or "none"

[filenames.rules]       # rules only; also [filenames.threats] and [filenames.objectives]
style = "name"          # the file stem is the rule's name
pattern = '^\[(SEN|XDR)\]\[.+'   # the whole stem must match this regular expression
```

A `[filenames.<kind>]` table sets `style` and `pattern` for one kind of object; a key it leaves unset comes from `[filenames]`. See [A convention per object kind](../cli/lint.md#a-convention-per-object-kind).

## Paths

`paths.toml` overrides the default workspace layout (where `objects/`, `docs/`, and `.opentide/` live). Most repos never touch it; the defaults are described in the [Workspace spec](/docs/specifications/specs/workspace/).

## Related

- [Configuration spec](/docs/specifications/specs/configuration/) — normative merge order and file contract.
- [Repository setup](./repository-setup.md) — how `opentide setup` scaffolds this directory.
- [Troubleshooting](./troubleshooting.md) — "unknown status", "platform not loaded", and other config errors.
