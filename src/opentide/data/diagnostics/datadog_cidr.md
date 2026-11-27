# datadog_cidr

A Datadog `CIDR()` call does not name an `@attribute` first, has no block, or has an argument that is not an IPv4 or IPv6 CIDR block.

Severity: error. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

`CIDR(@attribute, block, …)` matches an IP attribute inside any of the blocks. The first argument is an attribute (with `@`); each block is an IPv4 or IPv6 address with an optional prefix length (`10.0.0.0/8`, `fc00::/7`), within 32 or 128.

## Example

```text
CIDR(network.client.ip, 10.0.0.0/8)
CIDR(@network.client.ip, 10.0.0.300)
```

## How to fix

Name the attribute with `@` and write each block as an address and prefix: `CIDR(@network.client.ip, 10.0.0.0/8)`.
