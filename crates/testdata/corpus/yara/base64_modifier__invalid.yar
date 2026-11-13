// prod:base64_modifier invalid
rule r {
  strings:
    $a = "abc" base64()
  condition:
    $a
}
