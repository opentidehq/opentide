// prod:or_expression valid
rule r {
  strings:
    $a = "abc"
  condition:
    $a or filesize > 0
}
