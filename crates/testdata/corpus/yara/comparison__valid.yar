// prod:comparison valid
rule r {
  condition:
    filesize >= 10 and "a" icontains "A" and "ab" startswith "a" and "x" iequals "X" and "abc" matches /b/i and 1 != 2
}
