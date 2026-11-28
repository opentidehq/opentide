// prod:hex_jump valid
rule r {
  strings:
    $h = { 4D [4] 5A [2-8] 90 [-] 00 [3-] 01 }
  condition:
    all of them
}
