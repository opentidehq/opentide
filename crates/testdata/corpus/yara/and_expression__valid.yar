// prod:and_expression valid
rule r {
  strings:
    $a = "abc"
  condition:
    $a and filesize > 0
}
