// prod:string_modifier valid
rule r {
  strings:
    $a = "abc" nocase wide ascii fullword private
  condition:
    $a
}
