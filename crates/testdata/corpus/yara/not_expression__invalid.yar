// prod:not_expression invalid
rule r {
  strings:
    $a = "abc"
  condition:
    $a not
}
