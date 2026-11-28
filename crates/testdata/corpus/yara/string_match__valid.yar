// prod:string_match valid
rule r {
  strings:
    $a = "abc"
  condition:
    $a at 0 or $a in (0..filesize)
}
