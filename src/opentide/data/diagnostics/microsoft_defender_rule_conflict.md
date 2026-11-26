# microsoft_defender_rule_conflict

Graph refused to create a Microsoft Defender rule because another rule most likely holds its display name or alert title.

Severity: error. Reported by `opentide deploy` on a `microsoft_defender` tenant (microsoft-defender-1.0). Deploy addresses each rule as `opentide-<uuid>`: its `PATCH` found no rule with that id, so it sent a `POST` to create one, and Graph answered `409` (`A detection rule with this name, title, or rule ID already exists.`). The `PATCH` deploy sends after a `409` found no rule with the id either, so the conflict is another rule with the same display name or alert title. Most often it is one an earlier opentide release created: 1.0.0 deployed under the bare uuid, without the `opentide-` prefix, and 0.x under ids of its own. It can also be a rule created by hand in the portal. Graph keeps the name and alert title of a disabled rule reserved, so disabling that rule is not enough, and the alert title defaults to the rule's name, so renaming the rule alone may not be either. The rule fails, with the code before its message in the row's `error`; the others are deployed.

## Example

```text
microsoft_defender_rule_conflict: Graph refused to create detection rule opentide-8f3c4a7e-1b2d-4c3e-9f0a-1234567890ab on tenant contoso: HTTP 409 (A detection rule with this name, title, or rule ID already exists.). No rule has this id, so another rule most likely holds its display name or alert title: one an earlier opentide release created (under the bare uuid in 1.0.0, or in 0.x), or one created by hand. Graph keeps them reserved for a disabled rule too: delete that rule in the Defender portal (or rename both its name and its alert title), then deploy again
```

## How to fix

In the Defender portal (Investigation & response > Hunting > Custom detection rules), find the rule with the same name or alert title: delete it (the simplest fix), or rename both its name and its alert title, then deploy again. A rule that an earlier opentide release created is replaced by the one this deploy creates. To keep the other rule, give the opentide rule another display name (`configurations.microsoft_defender.name`, else the rule's `name`) and alert title (`alert.title`).
