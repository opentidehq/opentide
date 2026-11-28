// prod:range invalid
rule r {
  strings:
    $a = "abc"
  condition:
    $a in (0..filesize
}
