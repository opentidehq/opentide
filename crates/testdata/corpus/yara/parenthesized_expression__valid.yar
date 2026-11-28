// prod:parenthesized_expression valid
rule r {
  strings:
    $a = "abc"
  condition:
    ($a or true) and not ($a)
}
