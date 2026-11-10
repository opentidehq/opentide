// prod:hex_alternative valid
rule r {
  strings:
    $h = { 4D ( 5A | 5B 00 | ?? ) 90 }
  condition:
    $h
}
