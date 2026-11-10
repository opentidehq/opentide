# bitdefender_tenant_unreachable

A call to the GravityZone tenant got no answer, so no further rule deploys to it.

Severity: error. Reported by `opentide deploy` on a `bitdefender` tenant (bitdefender-1.0). A timeout or a connection error on an update or a delete stops the tenant. A create with no answer is retried once instead; a retry with no answer, or one refused because the name is taken, is `bitdefender_create_unconfirmed` for that rule, and the tenant goes on.

## Example

```text
bitdefender_tenant_unreachable: HTTPSConnectionPool(host='cloudgz.gravityzone.bitdefender.com', port=443): Read timed out
```

## How to fix

Check the tenant `url` (it ends in `/api`), the network path to it, and the tenant's `ssl` setting, then deploy again.
