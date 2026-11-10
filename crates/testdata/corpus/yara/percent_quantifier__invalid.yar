// prod:percent_quantifier invalid
rule r {
  strings:
    $a = "abc"
  condition:
    % of them
}
