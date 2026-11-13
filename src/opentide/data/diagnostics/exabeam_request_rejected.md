# exabeam_request_rejected

Exabeam refused the rule with HTTP 400.

Severity: error. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). The answer's `errors[]` name what Exabeam refused (`code`, `message`, `fields`), and its `traceId` identifies the request for Exabeam support.

## Example

```text
exabeam_request_rejected: POST /correlation-rules/v2/rules: HTTP 400: INVALID_QUERY: query is invalid (fields: sequencesConfig.sequences[0].query) (traceId 5f1c…)
```

## How to fix

Fix the field the error names, run `opentide validate`, and deploy again. Send the `traceId` to Exabeam support if the rule looks right.
