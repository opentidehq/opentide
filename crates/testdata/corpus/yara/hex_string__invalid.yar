// prod:hex_string invalid
rule r {
  strings:
    $h = { }
  condition:
    $h
}
