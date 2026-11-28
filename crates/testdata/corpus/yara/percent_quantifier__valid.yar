// prod:percent_quantifier valid
rule r {
  strings:
    $a = "abc"
  condition:
    50% of them
}
