// prod:hex_not valid
rule r {
  strings:
    $h = { 4D ~5A ~?0 }
  condition:
    $h
}
