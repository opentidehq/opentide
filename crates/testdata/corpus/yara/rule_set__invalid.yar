// prod:rule_set invalid
private rule base1 { condition: true }

rule r {
  condition:
    any of (base1,)
}
