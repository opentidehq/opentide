# KQL scalar and comparison operators

These operators appear in `where`, `extend`, `project`, `join` predicates, and other scalar expressions. They are **not** tabular pipeline operators (`| where` is tabular; `==` / `has` inside the predicate are scalar).

Primary citations:

- [String operators](https://learn.microsoft.com/kusto/query/datatypes-string-operators)
- [Numerical operators](https://learn.microsoft.com/kusto/query/numerical-operators)
- [Logical operators](https://learn.microsoft.com/kusto/query/logical-operators)
- [between](https://learn.microsoft.com/kusto/query/between-operator)
- [not-between](https://learn.microsoft.com/kusto/query/not-between-operator)
- [in](https://learn.microsoft.com/kusto/query/in-operator)
- [has](https://learn.microsoft.com/kusto/query/has-operator)
- [contains](https://learn.microsoft.com/kusto/query/contains-operator)
- [matches regex](https://learn.microsoft.com/kusto/query/matches-regex-operator)
- [Query best practices](https://learn.microsoft.com/kusto/query/best-practices)

Detection validity: all of the following are **Yes** for Sentinel scheduled analytics and Defender custom detections unless noted. Prefer case-sensitive / term-indexed forms for performance (`==`, `has`/`has_cs`, `in` over `contains` / `=~`).

## Equality and inequality

| Operator | Case-sensitive | Description | Example (`true`) | Citation |
| --- | --- | --- | --- | --- |
| `==` | yes (strings) | Equals; both non-null | `"aBc" == "aBc"`, `1 == 1` | [string](https://learn.microsoft.com/kusto/query/datatypes-string-operators), [logical](https://learn.microsoft.com/kusto/query/logical-operators) |
| `!=` | yes | Not equals | `"abc" != "ABC"` | same |
| `=~` | **no** | String equals ignore case | `"abc" =~ "ABC"` | [string operators](https://learn.microsoft.com/kusto/query/datatypes-string-operators) |
| `!~` | **no** | String not-equals ignore case | `"aBc" !~ "xyz"` | same |
| `<>` | yes | Alias of `!=` (numeric/string) | `1 <> 0` | numerical / legacy |

Null: `bool(null) == bool(null)` is `false`; `bool(null) != bool(null)` is `false`. [Logical operators](https://learn.microsoft.com/kusto/query/logical-operators)

## String search (substring vs term)

A **term** is a maximal alphanumeric sequence of **≥ 3** characters, indexed. `has*` matches terms; `contains` / `startswith` / `endswith` scan substrings (slower). `"KustoExplorerQueryRun" has "Explorer"` is **false**; `contains` is **true**.

| Operator | Meaning | CS? | Example (`true`) |
| --- | --- | --- | --- |
| `contains` | RHS is a subsequence of LHS | no | `"FabriKam" contains "BRik"` |
| `!contains` | RHS not a subsequence | no | `"Fabrikam" !contains "xyz"` |
| `contains_cs` | subsequence | yes | `"FabriKam" contains_cs "Kam"` |
| `!contains_cs` | not subsequence | yes | `"Fabrikam" !contains_cs "Kam"` |
| `startswith` | RHS is a prefix subsequence | no | `"Fabrikam" startswith "fab"` |
| `!startswith` | not prefix | no | `"Fabrikam" !startswith "kam"` |
| `startswith_cs` | prefix | yes | `"Fabrikam" startswith_cs "Fab"` |
| `!startswith_cs` | not prefix | yes | `"Fabrikam" !startswith_cs "fab"` |
| `endswith` | RHS is a suffix subsequence | no | `"Fabrikam" endswith "Kam"` |
| `!endswith` | not suffix | no | `"Fabrikam" !endswith "brik"` |
| `endswith_cs` | suffix | yes | `"Fabrikam" endswith_cs "kam"` |
| `!endswith_cs` | not suffix | yes | `"Fabrikam" !endswith_cs "brik"` |
| `has` | RHS is a **whole term** in LHS | no | `"North America" has "america"` |
| `!has` | not a whole term | no | `"North America" !has "amer"` |
| `has_cs` | whole term | yes | `"North America" has_cs "America"` |
| `!has_cs` | not whole term | yes | `"North America" !has_cs "amer"` |
| `hasprefix` | RHS is a term **prefix** | no | `"North America" hasprefix "ame"` |
| `!hasprefix` | not term prefix | no | `"North America" !hasprefix "mer"` |
| `hasprefix_cs` | term prefix | yes | `"North America" hasprefix_cs "Ame"` |
| `!hasprefix_cs` | not | yes | `"North America" !hasprefix_cs "CA"` |
| `hassuffix` | RHS is a term **suffix** | no | `"North America" hassuffix "ica"` |
| `!hassuffix` | not | no | `"North America" !hassuffix "americ"` |
| `hassuffix_cs` | term suffix | yes | `"North America" hassuffix_cs "ica"` |
| `!hassuffix_cs` | not | yes | `"North America" !hassuffix_cs "icA"` |
| `has_any` | any element is a term in LHS | no | `"North America" has_any ("south", "north")` |
| `has_all` | all elements are terms in LHS | no | `"North and South America" has_all ("south", "north")` |

Per-operator pages: [has](https://learn.microsoft.com/kusto/query/has-operator), [has_any](https://learn.microsoft.com/kusto/query/has-any-operator), [has_all](https://learn.microsoft.com/kusto/query/has-all-operator), [contains](https://learn.microsoft.com/kusto/query/contains-operator), [startswith](https://learn.microsoft.com/kusto/query/startswith-operator), [endswith](https://learn.microsoft.com/kusto/query/endswith-operator), [hasprefix](https://learn.microsoft.com/kusto/query/hasprefix-operator), [hassuffix](https://learn.microsoft.com/kusto/query/hassuffix-operator).

Search **all columns**: `where * has "cow"` (expensive). Prefer a named column in detections.

## Membership: `in` / `!in`

Citation: [in operator](https://learn.microsoft.com/kusto/query/in-operator)

| Operator | Case-sensitive | Description |
| --- | --- | --- |
| `in` | yes | Equals any list element |
| `!in` | yes | Equals none |
| `in~` | no | Case-insensitive `in` |
| `!in~` | no | Case-insensitive `!in` |

```kusto
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")
| where AccountType !in ("User", "Guest")
| where ProcessId in (SuspiciousPids)   // tabular / dynamic list
```

Huge `in` lists can exceed expanded query length (Sentinel 10k chars; data-lake expansion limits). Prefer watchlists, `datatable` + `join`/`lookup`, or `_GetWatchlist()`.

## Regex

| Operator | Description | CS | Example |
| --- | --- | --- | --- |
| `matches regex` | LHS contains a match for RE2/Kusto regex RHS | yes (pattern-defined) | `"Fabrikam" matches regex "b.*k"` |

Citation: [matches regex](https://learn.microsoft.com/kusto/query/matches-regex-operator)

NRT: encode regex as string literals (`"\\A"` for `\A`); NRT detections cannot use comment lines. [Custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)

Related functions (not operators): `extract()`, `extract_all()`, `replace_regex()`, `trim()`.

## IPv4 text-match operators

Index-accelerated search for IPv4 addresses **inside text**. Citation: [String operators — IPv4](https://learn.microsoft.com/kusto/query/datatypes-string-operators#operators-on-ipv4-addresses)

| Operator | Description | Example (`true`) |
| --- | --- | --- |
| `has_ipv4` | LHS contains IPv4 RHS | `has_ipv4("Source address is 10.1.2.3:1234", "10.1.2.3")` |
| `has_ipv4_prefix` | LHS contains IPv4 matching prefix | `has_ipv4_prefix("…10.1.2.3:1234", "10.1.2.")` |
| `has_any_ipv4` | LHS contains any of the IPv4s | `has_any_ipv4("…", dynamic(["10.1.2.3","127.0.0.1"]))` |
| `has_any_ipv4_prefix` | LHS contains any prefix | `has_any_ipv4_prefix("…", dynamic(["10.1.2.","127.0.0."]))` |

These also exist as **functions** with the same names ([IPv4 text match functions](https://learn.microsoft.com/kusto/query/scalar-functions#ipv4-text-match-functions)). For CIDR membership of a dedicated IP column, prefer `ipv4_is_in_range()` / `ipv4_is_in_any_range()`.

## Range: `between` / `!between`

Citation: [between](https://learn.microsoft.com/kusto/query/between-operator), [!between](https://learn.microsoft.com/kusto/query/not-between-operator)

Inclusive range on numeric, `datetime`, or `timespan`.

```kusto
| where EventID between (4624 .. 4625)
| where TimeGenerated between (ago(1d) .. now())
| where StartTime between (datetime(2007-07-27) .. 3d)  // datetime + timespan width
```

## Logical operators

Citation: [Logical operators](https://learn.microsoft.com/kusto/query/logical-operators), [not()](https://learn.microsoft.com/kusto/query/not-function)

| Operator | Syntax | Meaning |
| --- | --- | --- |
| `and` | `p and q` | Both true. **Higher precedence than `or`** |
| `or` | `p or q` | Either true |
| `not()` | `not(p)` | Boolean negation (function, not `!p` on bool — `!` is used in `!=`, `!in`, `!has`) |

Parenthesize mixed `and`/`or`. Put cheapest / most selective predicates first.

## Arithmetic and numeric comparison

Citation: [Numerical operators](https://learn.microsoft.com/kusto/query/numerical-operators)

| Operator | Description | Notes |
| --- | --- | --- |
| `+` `-` `*` `/` `%` | Add, subtract, multiply, divide, modulo | If either operand is `real`, result is `real`. Integer `/` **truncates** (`1/2 == 0`). Use `toreal(1)/2`. |
| `<` `>` `<=` `>=` | Ordering | Works on numbers, `datetime`, `timespan` |
| `==` `!=` | Equality | |
| `%` | Modulo | Always a small **non-negative** remainder: `0 ≤ n % d < abs(d)` |

Datetime arithmetic: `now() - 1h`, `ago(5m) + 5m`, `datetime(2024-01-01) + 7d`.

## Dynamic / JSON access (syntax, not a named operator)

Citation: [dynamic](https://learn.microsoft.com/kusto/query/scalar-data-types/dynamic)

```kusto
| extend City = tostring(LocationDetails.city)
| extend FirstIp = tostring(parse_json(Network)[0])
| where AdditionalFields has "MalwareName"
```

Use `parse_json()` / `todynamic()` when the column is `string`. `evaluate bag_unpack(BagCol)` expands property bags to columns ([bag_unpack](https://learn.microsoft.com/kusto/query/bag-unpack-plugin)); Sentinel analytics must use `column_ifexists` if projected unpacked fields might be absent. [Scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/scheduled-rules-overview)

## Performance cheat sheet for detections

| Prefer | Avoid |
| --- | --- |
| `==`, `has` / `has_cs`, `in` | `=~`, `contains`, `matches regex` when a term match suffices |
| Column `has "mimikatz"` | `* has "mimikatz"` |
| `TimeGenerated > ago(1d)` | `bin(TimeGenerated, 1d) == ago(1d)` as a filter |
| `ipv4_is_in_range(src, "10.0.0.0/8")` | `src startswith "10."` |
