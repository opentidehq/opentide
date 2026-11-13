// prod:rule_wildcard invalid
private rule base1 { condition: true }

rule r {
  condition:
    any of (*)
}
