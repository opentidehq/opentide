// prod:rule_wildcard valid
private rule base1 { condition: true }

rule r {
  condition:
    any of (base*)
}
