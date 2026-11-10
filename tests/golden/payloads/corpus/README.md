# The deploy compile's corpus

Rules that exercise every branch of opentide-compile's compilers, for all nine platforms, with the
objective and threat of tests/fixtures/tide_corpus that their techniques resolve through, and
tenants whose names select exclusions and whose `setup` adds index, tags and suppression
(Elastic) or tags (Sysdig), or sets what a deployer reads (Splunk's Enterprise Security, actions,
schedule, skew and `[[modifiers]]`, SentinelOne's site or account, CrowdStrike's cloud,
HarfangLab's type, Carbon Black's watchlist). `.opentide/states/deployment/` records ids on some
tenants, so Defender, SentinelOne and CrowdStrike rules are created on one tenant and updated or
deleted on the other.
`cargo xtask payloads diff --against python --corpus payloads --record` writes what the oracle
compiles from it to `tests/golden/payloads/oracle.json` (generated: never edit); `opentide-compile`'s
`tests/oracle.rs` compares with it, and `cargo xtask payloads diff --against python --corpus
payloads` with the oracle itself. Credentials are `$VARIABLE` references and hosts are on
example domains.
