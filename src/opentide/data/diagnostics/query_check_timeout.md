# query_check_timeout

`validate query --live` failed because a tenant did not answer a query's check within the check timeout.

Exit 1, as `failure.code` when every failed check timed out; as the `code` of each entry under `timed_out` otherwise. Only that rule's check fails: the other rules are still checked. A tenant is reported unreachable only after 3 queries in a row get no answer.

A read timeout, a gateway or proxy's HTTP 502, 503 or 504 page, or a SentinelOne PowerQuery still running at the deadline all count. The default timeout is 120 seconds.

## Example

A live check of 403 Splunk rules where one parse took longer than 120 seconds, trimmed to the keys that say so (illustrative: it needs a tenant):

```json illustrative
{"status": "failed", "exit_code": 1, "message": "Queries rejected on splunk · 403 checked on 1 tenant · 1 with no answer within 120s", "check_timeout": 120.0, "timed_out": [{"code": "query_check_timeout", "…": "…"}], "failure": {"code": "query_check_timeout", "message": "…"}}
```

## How to fix

Raise the timeout with `--check-timeout SECONDS` or `OPENTIDE_QUERY_CHECK_TIMEOUT`, or make the query cheaper. When a gateway answered (HTTP 504), its own timeout may be shorter than the check's: raise the gateway's timeout too.
