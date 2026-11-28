// prod:hex_alternative invalid
rule r {
  strings:
    $h = { 4D ( 5A | 5B 90 }
  condition:
    $h
}
