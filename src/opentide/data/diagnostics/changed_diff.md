# changed_diff

`share push --changed` could not calculate which objects changed.

Exit 1, as `failure.code` and `preflight`. The message says why.

## Example

```text
opentide share push --changed
```

## How to fix

Fetch enough history for the diff (`fetch-depth: 0` in GitHub Actions), or select objects with `--uuid`, `--type` or `--file`.
