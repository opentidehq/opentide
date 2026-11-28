// prod:and_expression invalid
rule r {
  strings:
    $a = "abc"
  condition:
    $a and and true
}
