// prod:parenthesized_primary invalid
rule r {
  condition:
    (filesize + ) > 10
}
