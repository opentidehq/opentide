# changed_on_pull_request

`share push --changed` does not run on a pull request.

Exit 1, as `failure.code` and `preflight`. Objects are shared once they are merged.

## Example

```text
opentide share push --changed
```

## How to fix

Run it on the default branch after the merge.
