# proxy

The proxy in `--proxy`, `OPENTIDE_PROXY` or `HTTPS_PROXY` accepts a connection.

Reported by `opentide doctor`. Fails when it does not (3-second timeout); skipped when no proxy is set or with `--offline`. The proxy is shown without its user and password.

## Example

```text
✗ Cannot connect to proxy http://proxy.example:3128 (ConnectionRefusedError) · proxy
  → check --proxy, OPENTIDE_PROXY or HTTPS_PROXY, and that the proxy is up
```

## How to fix

Check the host and port, and that the proxy is reachable from this machine. Hosts in `NO_PROXY` are reached directly.
