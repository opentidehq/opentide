// prod:base64_modifier valid
rule r {
  strings:
    $a = "abc" base64
    $b = "abcd" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
  condition:
    all of them
}
