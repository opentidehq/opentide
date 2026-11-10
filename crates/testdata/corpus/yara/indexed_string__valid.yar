// prod:indexed_string valid
rule r {
  strings:
    $a = "abc"
  condition:
    @a[1] < 10 and !a[1] == 3
}
