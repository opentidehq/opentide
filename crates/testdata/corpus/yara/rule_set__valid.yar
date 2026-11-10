// prod:rule_set valid
private rule base1 { condition: true }

rule r {
  condition:
    any of (base1, base*)
}
