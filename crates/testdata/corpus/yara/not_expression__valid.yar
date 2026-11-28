// prod:not_expression valid
rule r {
  strings:
    $a = "abc"
  condition:
    not $a and not defined 1
}
