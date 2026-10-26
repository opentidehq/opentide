# usage_invalid_choice

An option or argument has a value outside the ones it accepts.

Exit 2, as `failure.code`. Raised for `--platform`, `--type`, `--target`, `--strategy`, an `info` section, an `info vocab` name and a `generate` phase. `failure.suggestion` names the closest valid value.

## Example

```text
opentide validate --type rulez
```

## How to fix

Use one of the values the message lists.
