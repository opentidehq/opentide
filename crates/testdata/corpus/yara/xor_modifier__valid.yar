// prod:xor_modifier valid
rule r {
  strings:
    $a = "abc" xor
    $b = "abc" xor(2)
    $c = "abc" xor(1-255)
  condition:
    all of them
}
