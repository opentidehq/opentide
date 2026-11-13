// prod:arithmetic_expression valid
rule r {
  condition:
    (filesize \ 2 + 1 * 3 - 4 % 5) & 0xFF | 1 ^ 2 << 1 >> 1 == 0o17
}
