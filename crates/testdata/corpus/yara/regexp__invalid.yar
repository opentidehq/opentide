// prod:regexp invalid
rule r {
  strings:
    $r = /abc
  condition:
    $r
}
