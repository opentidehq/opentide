# query_position_needs_platform

A query on its own is to be checked as a rule's query, but no platform says whose rule block it is.

Severity: error. Reported by the analysis engine on a query checked on its own at position `rule` with no platform: the Rust SDK's `opentide::analysis::analyze_query_at` answers this one error and checks nothing else. The command line and MCP refuse the same request before any check: `opentide validate query --position rule` without `--platform` exits `2` with `usage_missing_option` (`failure.argument` `--platform`), and MCP `validate_query` requires `platform`. Python's `opentide.analysis.check_query(..., position="rule")` without a `platform` raises `ValueError`.

A rule block is a platform's: Exabeam's sequence filter refuses Search's operators, and CrowdStrike's query is a Next-Gen SIEM correlation rule. Without the platform there is no block to check the query as, and checking it as a search instead would pass a query the rule would refuse ([#1993](https://github.com/opentidehq/opentide/issues/1993), ADR 0015 §4).

## Example

```rust
use opentide::analysis::{LanguageId, QueryPosition, QueryRequest, analyze_query_at};

let request = QueryRequest::new(LanguageId::Exabeam, r#"SELECT user WHERE vendor:"x""#);
let diagnostics = analyze_query_at(&request, QueryPosition::Rule); // [query_position_needs_platform]
```

## How to fix

Name the platform whose rule block the query is for (`.with_platform(Some("exabeam"))`, `--platform exabeam`), or check it as a search: `analyze_query`, or position `search`.
