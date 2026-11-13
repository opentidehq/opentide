// prod:indexed_string invalid
rule r {
  strings:
    $a = "abc"
  condition:
    @a[] < 10
}
