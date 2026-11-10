// prod:hex_not invalid
rule r {
  strings:
    $h = { 4D ~ }
  condition:
    $h
}
