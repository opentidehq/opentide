# bitdefender_request_failed

GravityZone refused a call for this rule with a JSON-RPC error.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). A response with an `error` member is a failure even with HTTP 200; the message carries its code and `error.data.details`. Other rules on the tenant carry on.

## Example

```text
bitdefender_request_failed: updateCustomRule: error -32602: Invalid params (Invalid value for parameter settings.criteriaList)
```

## How to fix

Read `error.data.details` in the message, fix the block it points at, and deploy again. `opentide validate` catches most refusals before any call.
