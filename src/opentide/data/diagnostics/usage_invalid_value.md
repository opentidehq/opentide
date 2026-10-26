# usage_invalid_value

An option has a value that cannot be used, although it is spelled correctly.

Exit 2, as `failure.code`. The message says why, for example a removed option such as `--plan`.

## Example

```text
opentide deploy --plan plan.json
```

## How to fix

Do what the message says: drop the option, or pass the replacement it names.
