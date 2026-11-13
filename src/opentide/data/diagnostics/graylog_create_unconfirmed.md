# graylog_create_unconfirmed

A Graylog create got no answer, so the definition may exist without a binding.

Severity: error. Reported by `opentide deploy` on a `graylog` block (graylog-1.0). `POST /api/events/definitions` got no answer (a timeout, a reset), or answered no id. The create may have succeeded, but its id never reached opentide, so nothing was recorded. Titles are not unique, so deploy does not retry, which could create a second definition, and never lists definitions to find it.

## Example

```text
graylog_create_unconfirmed: the create got no answer, so it may have succeeded with an id opentide
does not know. Find the definition by the title 'mshta remote script' or the tag
'opentide.00000000-0000-4000-8003-000000000061' in Graylog
```

## How to fix

Find the definition by its title (on 7.2, by the `opentide.<uuid>` tag). Delete it and deploy again, or record its 24-hex id under `platforms.graylog.<tenant>` in the rule's `.opentide/states/deployment/<uuid>.json` and commit it.
