# share_partial

`share` shared some objects, and others failed.

Exit 3, as `failure.code`. Each record in the document says what happened to its object.

## Example

```text
opentide share push
```

## How to fix

Fix the failed records, then share again: objects already shared are updated, not duplicated.
