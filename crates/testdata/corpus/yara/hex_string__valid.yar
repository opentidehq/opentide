// prod:hex_string valid
rule r {
  strings:
    $h = { 4D 5A 90 00 }
  condition:
    $h
}
