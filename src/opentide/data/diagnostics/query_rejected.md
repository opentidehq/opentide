# query_rejected

`validate query --live` failed because a tenant refused a rule's query as invalid.

Exit 1. As `failure.code` when at least one query was rejected and the run did not fail only on timeouts. When a tenant also fails the run, the code is that tenant's. A tenant that refuses the check itself (`authentication_failed`) does not stop the run: its remaining queries are not sent, the next tenant is checked, and `rejected` lists every query any tenant refused as invalid. A tenant that cannot be reached (`tenant_unreachable`) or whose credential is unset (`credential_unset`) stops it, and `rejected` lists the queries refused before it. Each rejected check is an entry of `rejected` in `--json`, with the rule's `file` and the `line` of its query, the `platform`, the `tenant` and the platform's own `message`. In CI the same rejections are annotations on the rule file (`::error file=…,line=…::` on GitHub Actions) and rows of the job summary. A check that got no answer is not a rejection: see `query_check_timeout`.

The other rules are still checked, so one run lists every rejected query.

## Example

A Splunk rule whose search the tenant refused, trimmed to the keys that say so (illustrative: it needs a tenant):

```json illustrative
{"status": "failed", "exit_code": 1, "message": "Queries rejected on splunk · 1 checked on 1 tenant", "rejected": [{"rule": "…", "name": "…", "tenant": "prod", "platform": "splunk", "file": "rules/example.yaml", "line": 14, "message": "…", "errors": ["…"]}], "failure": {"code": "query_rejected", "message": "…"}}
```

## How to fix

Read `message` for what the platform refused, edit the query at `file` and `line`, and run the check again. `opentide validate query --file <rule>` checks the query's syntax without a tenant.
