// prod:hex_jump invalid
rule r {
  strings:
    $h = { 4D [a] 5A }
  condition:
    $h
}
