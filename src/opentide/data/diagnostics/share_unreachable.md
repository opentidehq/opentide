# share_unreachable

`share` could not authenticate to, or reach, any destination.

Exit 2, as `failure.code`.

## Example

```text
opentide share push
```

## How to fix

Check the API key, the URL and the network path (proxy, `NO_PROXY`) of the target in `sharing.toml`.
