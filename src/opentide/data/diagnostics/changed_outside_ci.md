# changed_outside_ci

`share push --changed` runs only in CI, where the diff it shares is known.

Exit 1, as `failure.code` and `preflight`.

## Example

```text
opentide share push --changed
```

## How to fix

Run it in GitHub Actions, GitLab CI or Azure Pipelines, or select objects with `--uuid`, `--type` or `--file`.
