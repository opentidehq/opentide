// prod:strings_section valid
rule r {
  strings:
    $a = "abc"
  condition:
    $a
}
