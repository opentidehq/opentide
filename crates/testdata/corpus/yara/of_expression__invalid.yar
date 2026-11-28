// prod:of_expression invalid
rule r {
  strings:
    $a = "abc"
  condition:
    any of
}
