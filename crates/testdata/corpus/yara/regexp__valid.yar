// prod:regexp valid
rule r {
  strings:
    $r = /ab[cd]+\/e{1,3}/is wide
  condition:
    $r
}
