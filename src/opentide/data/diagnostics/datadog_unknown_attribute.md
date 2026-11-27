# datadog_unknown_attribute

A Datadog search field is a dotted bare key, searched as a tag, where an `@attribute` was probably meant.

Severity: hint. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

A bare key (`host`, `service`, `env:prod`) searches a reserved attribute or a tag; an attribute of the log is written with `@`. A dotted bare key such as `evt.name` searches a tag named `evt.name`, which is rarely what was meant.

## Example

```text
evt.name:ConsoleLogin
```

## How to fix

Add `@` to search the attribute: `@evt.name:ConsoleLogin`. If the tag is meant, escape the dot (`evt\.name:ConsoleLogin`) to say so.
