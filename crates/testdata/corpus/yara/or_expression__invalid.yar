// prod:or_expression invalid
rule r {
  strings:
    $a = "abc"
  condition:
    $a or
}
