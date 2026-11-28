// prod:xor_modifier invalid
rule r {
  strings:
    $a = "abc" xor(1-)
  condition:
    $a
}
