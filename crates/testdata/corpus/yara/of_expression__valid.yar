// prod:of_expression valid
rule r {
  strings:
    $a = "a"
    $b1 = "b"
  condition:
    any of them and 2 of ($a, $b*) and none of them in (0..10) and any of ($a) at 0
}
