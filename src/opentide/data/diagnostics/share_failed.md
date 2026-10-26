# share_failed

`share` reached the destination, and every object failed.

Exit 1, as `failure.code`. Each record in the document says why its object failed.

## Example

```text
opentide share push
```

## How to fix

Read the failed records, fix the objects or the target configuration, then share again.
