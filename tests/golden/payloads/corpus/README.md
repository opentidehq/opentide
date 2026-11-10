# The deploy compile's corpus

Rules that exercise every branch of opentide-compile's Sentinel, Elastic and Sysdig compilers, with the
objective and threat of tests/fixtures/tide_corpus that their techniques resolve through, and
tenants whose names select exclusions and whose `setup` adds index, tags and suppression
(Elastic) or tags (Sysdig).
`cargo xtask payloads diff --against python --corpus payloads --record` writes what the oracle
compiles from it to `tests/golden/payloads/oracle.json` (generated: never edit); `opentide-compile`'s
`tests/oracle.rs` compares with it, and `cargo xtask payloads diff --against python --corpus
payloads` with the oracle itself. Credentials are `$VARIABLE` references and hosts are on
example domains.
