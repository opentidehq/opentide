# KQL scalar functions

Scalar functions take scalar arguments and return a scalar. Index: [Scalar functions](https://learn.microsoft.com/kusto/query/scalar-functions)

Citation URLs follow `https://learn.microsoft.com/kusto/query/<name>-function` unless noted (hyphens in multi-word names).

Detection validity defaults to **Yes** in Sentinel scheduled analytics and Defender custom detections. Marked otherwise when Azure Monitor does not support the function or it is hunting-only / non-deterministic.

Aliases commonly appearing in hunting queries are listed in the **Aliases** column.

---

## Conversion

| Name | Aliases | Signature | Docs | Citation |
| --- | --- | --- | --- | --- |
| `tobool` | `toboolean` | `tobool(value)` | Convert to `bool` | [tobool](https://learn.microsoft.com/kusto/query/tobool-function) |
| `todatetime` | — | `todatetime(value)` | Convert to `datetime` (prefer literals) | [todatetime](https://learn.microsoft.com/kusto/query/todatetime-function) |
| `todecimal` | — | `todecimal(value)` | Convert to `decimal` | [todecimal](https://learn.microsoft.com/kusto/query/todecimal-function) |
| `todouble` | `toreal` | `todouble(value)` / `toreal(value)` | Convert to `real` | [toreal](https://learn.microsoft.com/kusto/query/toreal-function) |
| `toguid` | — | `toguid(value)` | Convert to `guid` | [toguid](https://learn.microsoft.com/kusto/query/toguid-function) |
| `toint` | — | `toint(value)` | Convert to `int` | [toint](https://learn.microsoft.com/kusto/query/toint-function) |
| `tolong` | — | `tolong(value)` | Convert to `long` | [tolong](https://learn.microsoft.com/kusto/query/tolong-function) |
| `tostring` | — | `tostring(value)` | Convert to `string` | [tostring](https://learn.microsoft.com/kusto/query/tostring-function) |
| `totimespan` | — | `totimespan(value)` | Convert to `timespan` | [totimespan](https://learn.microsoft.com/kusto/query/totimespan-function) |
| `todynamic` | `parse_json` (when input is JSON text) | `todynamic(value)` | Interpret as `dynamic` | [todynamic](https://learn.microsoft.com/kusto/query/todynamic-function) |

Failed conversions return `null`.

---

## DateTime / timespan

| Name | Signature | Docs | Citation |
| --- | --- | --- | --- |
| `ago` | `ago(timespan)` | `now() - timespan` (query-start clock) | [ago](https://learn.microsoft.com/kusto/query/ago-function) |
| `now` | `now([offset])` | Current UTC query-start time | [now](https://learn.microsoft.com/kusto/query/now-function) |
| `datetime_add` | `datetime_add(period, amount, datetime)` | Add periods (`year`,`month`,`day`,`hour`,…) | [datetime_add](https://learn.microsoft.com/kusto/query/datetime-add-function) |
| `datetime_diff` | `datetime_diff(period, datetime1, datetime2)` | Difference in period units | [datetime_diff](https://learn.microsoft.com/kusto/query/datetime-diff-function) |
| `datetime_part` | `datetime_part(part, datetime)` | Extract part as `int` | [datetime_part](https://learn.microsoft.com/kusto/query/datetime-part-function) |
| `datetime_local_to_utc` | `datetime_local_to_utc(dt, tz)` | Local → UTC | [datetime_local_to_utc](https://learn.microsoft.com/kusto/query/datetime-local-to-utc-function) |
| `datetime_utc_to_local` | `datetime_utc_to_local(dt, tz)` | UTC → local | [datetime_utc_to_local](https://learn.microsoft.com/kusto/query/datetime-utc-to-local-function) |
| `dayofmonth` | `dayofmonth(datetime)` | Day of month | [dayofmonth](https://learn.microsoft.com/kusto/query/dayofmonth-function) |
| `dayofweek` | `dayofweek(datetime)` | Timespan since preceding Sunday | [dayofweek](https://learn.microsoft.com/kusto/query/dayofweek-function) |
| `dayofyear` | `dayofyear(datetime)` | Day of year | [dayofyear](https://learn.microsoft.com/kusto/query/dayofyear-function) |
| `hourofday` | `hourofday(datetime)` | Hour 0–23 | [hourofday](https://learn.microsoft.com/kusto/query/hourofday-function) |
| `getyear` | `getyear(datetime)` | Year | [getyear](https://learn.microsoft.com/kusto/query/getyear-function) |
| `monthofyear` | `monthofyear(datetime)` | Month 1–12 | [monthofyear](https://learn.microsoft.com/kusto/query/monthofyear-function) |
| `weekofyear` | `weekofyear(datetime)` | ISO-style week number | [weekofyear](https://learn.microsoft.com/kusto/query/weekofyear-function) |
| `startofday` / `endofday` | `startofday(dt [, offset])` | Day boundaries | [startofday](https://learn.microsoft.com/kusto/query/startofday-function), [endofday](https://learn.microsoft.com/kusto/query/endofday-function) |
| `startofweek` / `endofweek` | same pattern | Week boundaries | [startofweek](https://learn.microsoft.com/kusto/query/startofweek-function), [endofweek](https://learn.microsoft.com/kusto/query/endofweek-function) |
| `startofmonth` / `endofmonth` | same pattern | Month boundaries | [startofmonth](https://learn.microsoft.com/kusto/query/startofmonth-function), [endofmonth](https://learn.microsoft.com/kusto/query/endofmonth-function) |
| `startofyear` / `endofyear` | same pattern | Year boundaries | [startofyear](https://learn.microsoft.com/kusto/query/startofyear-function), [endofyear](https://learn.microsoft.com/kusto/query/endofyear-function) |
| `make_datetime` | `make_datetime(year, month, day [, hour, minute, second])` | Construct datetime | [make_datetime](https://learn.microsoft.com/kusto/query/make-datetime-function) |
| `make_timespan` | `make_timespan([days][, hours][, minutes][, seconds])` | Construct timespan | [make_timespan](https://learn.microsoft.com/kusto/query/make-timespan-function) |
| `format_datetime` | `format_datetime(datetime, format)` | Format string | [format_datetime](https://learn.microsoft.com/kusto/query/format-datetime-function) |
| `format_timespan` | `format_timespan(timespan, format)` | Format string | [format_timespan](https://learn.microsoft.com/kusto/query/format-timespan-function) |
| `unixtime_seconds_todatetime` | `unixtime_seconds_todatetime(unix)` | Epoch seconds → UTC | [unixtime_seconds_todatetime](https://learn.microsoft.com/kusto/query/unixtime-seconds-todatetime-function) |
| `unixtime_milliseconds_todatetime` | `unixtime_milliseconds_todatetime(unix)` | Epoch ms | [unixtime_milliseconds_todatetime](https://learn.microsoft.com/kusto/query/unixtime-milliseconds-todatetime-function) |
| `unixtime_microseconds_todatetime` | `unixtime_microseconds_todatetime(unix)` | Epoch µs | [unixtime_microseconds_todatetime](https://learn.microsoft.com/kusto/query/unixtime-microseconds-todatetime-function) |
| `unixtime_nanoseconds_todatetime` | `unixtime_nanoseconds_todatetime(unix)` | Epoch ns | [unixtime_nanoseconds_todatetime](https://learn.microsoft.com/kusto/query/unixtime-nanoseconds-todatetime-function) |

---

## Rounding / binning

| Name | Aliases | Signature | Docs | Citation |
| --- | --- | --- | --- | --- |
| `bin` | `floor` | `bin(value, roundTo)` | Round **down** to multiple of bin size (time or numeric) | [bin](https://learn.microsoft.com/kusto/query/bin-function) |
| `bin_at` | — | `bin_at(value, binSize, origin)` | Bins aligned to an origin | [bin_at](https://learn.microsoft.com/kusto/query/bin-at-function) |
| `bin_auto` | — | `bin_auto(value)` | Query-time automatic bin (mostly UX) | [bin_auto](https://learn.microsoft.com/kusto/query/bin-auto-function) |
| `ceiling` | — | `ceiling(expr)` | Smallest integer ≥ expr | [ceiling](https://learn.microsoft.com/kusto/query/ceiling-function) |

`bin(TimeGenerated, 1h)` is the standard detection bucketing function.

---

## Conditional / null

| Name | Aliases | Signature | Docs | Citation |
| --- | --- | --- | --- | --- |
| `iff` | `iif` | `iff(predicate, then, else)` | Ternary | [iff](https://learn.microsoft.com/kusto/query/iff-function) |
| `case` | — | `case(p1, r1, p2, r2, …, else)` | Multi-branch | [case](https://learn.microsoft.com/kusto/query/case-function) |
| `coalesce` | — | `coalesce(expr, …)` | First non-null (non-empty for strings) | [coalesce](https://learn.microsoft.com/kusto/query/coalesce-function) |
| `max_of` | — | `max_of(expr, …)` | Max of scalars | [max_of](https://learn.microsoft.com/kusto/query/max-of-function) |
| `min_of` | — | `min_of(expr, …)` | Min of scalars | [min_of](https://learn.microsoft.com/kusto/query/min-of-function) |
| `not` | — | `not(bool)` | Logical not | [not](https://learn.microsoft.com/kusto/query/not-function) |
| `isnull` | — | `isnull(expr)` | True if null | [isnull](https://learn.microsoft.com/kusto/query/isnull-function) |
| `isnotnull` | — | `isnotnull(expr)` | | [isnotnull](https://learn.microsoft.com/kusto/query/isnotnull-function) |
| `isempty` | — | `isempty(expr)` | Empty string or null | [isempty](https://learn.microsoft.com/kusto/query/isempty-function) |
| `isnotempty` | `notempty` (rare) | `isnotempty(expr)` | | [isnotempty](https://learn.microsoft.com/kusto/query/isnotempty-function) |
| `column_ifexists` | — | `column_ifexists("Name", default)` | Column ref or default — **required** with `bag_unpack` in Sentinel analytics | [column_ifexists](https://learn.microsoft.com/kusto/query/column-ifexists-function) |

---

## String

| Name | Aliases | Signature | Docs | Citation |
| --- | --- | --- | --- | --- |
| `strcat` | — | `strcat(s1, s2, …)` | Concat 1–64 args | [strcat](https://learn.microsoft.com/kusto/query/strcat-function) |
| `strcat_delim` | — | `strcat_delim(delim, s1, …)` | Concat with delimiter | [strcat_delim](https://learn.microsoft.com/kusto/query/strcat-delim-function) |
| `strcat_array` | — | `strcat_array(array, delimiter)` | Join dynamic string array | [strcat_array](https://learn.microsoft.com/kusto/query/strcat-array-function) |
| `strlen` | — | `strlen(string)` | Character length | [strlen](https://learn.microsoft.com/kusto/query/strlen-function) |
| `substring` | — | `substring(source, start [, length])` | Slice (0-based) | [substring](https://learn.microsoft.com/kusto/query/substring-function) |
| `split` | — | `split(source, delimiter [, requestedIndex])` | Split to dynamic array | [split](https://learn.microsoft.com/kusto/query/split-function) |
| `extract` | — | `extract(regex, captureGroup, source)` | Regex capture | [extract](https://learn.microsoft.com/kusto/query/extract-function) |
| `extract_all` | `extractall` | `extract_all(regex, [captureGroups,] source)` | All matches | [extract_all](https://learn.microsoft.com/kusto/query/extract-all-function) |
| `extract_json` | `extractjson` | `extract_json(path, json [, type])` | JSONPath-like extract | [extract_json](https://learn.microsoft.com/kusto/query/extract-json-function) |
| `parse_json` | `parsejson` | `parse_json(json)` | JSON text → `dynamic` | [parse_json](https://learn.microsoft.com/kusto/query/parse-json-function) |
| `parse_csv` | — | `parse_csv(string)` | CSV line → array | [parse_csv](https://learn.microsoft.com/kusto/query/parse-csv-function) |
| `parse_command_line` | — | `parse_command_line(cmd, flavor)` | Windows/Linux argv array — **very common in MDE hunting** | [parse_command_line](https://learn.microsoft.com/kusto/query/parse-command-line-function) |
| `parse_url` | `parseurl` | `parse_url(url)` | URL parts as dynamic | [parse_url](https://learn.microsoft.com/kusto/query/parse-url-function) |
| `parse_urlquery` | `parseurlquery` | `parse_urlquery(query)` | Query-string bag | [parse_urlquery](https://learn.microsoft.com/kusto/query/parse-urlquery-function) |
| `parse_path` | — | `parse_path(path)` | File path parts | [parse_path](https://learn.microsoft.com/kusto/query/parse-path-function) |
| `parse_user_agent` | — | `parse_user_agent(ua, regex)` | Browser/OS from UA | [parse_user_agent](https://learn.microsoft.com/kusto/query/parse-user-agent-function) |
| `parse_version` | — | `parse_version(string)` | Version → comparable decimal | [parse_version](https://learn.microsoft.com/kusto/query/parse-version-function) |
| `parse_xml` | — | `parse_xml(xml)` | XML → dynamic | [parse_xml](https://learn.microsoft.com/kusto/query/parse-xml-function) |
| `replace_string` | `replace` (deprecated 3-arg) | `replace_string(source, lookup, rewrite)` | Literal replace all | [replace_string](https://learn.microsoft.com/kusto/query/replace-string-function) |
| `replace_strings` | — | `replace_strings(source, lookups, rewrites)` | Multi replace | [replace_strings](https://learn.microsoft.com/kusto/query/replace-strings-function) |
| `replace_regex` | — | `replace_regex(source, regex, rewrite)` | Regex replace | [replace_regex](https://learn.microsoft.com/kusto/query/replace-regex-function) |
| `countof` | — | `countof(source, search [, kind])` | Count substring/regex | [countof](https://learn.microsoft.com/kusto/query/countof-function) |
| `indexof` | `indexof_regex` (related) | `indexof(source, lookup [, start][, length][, occurrence])` | First index | [indexof](https://learn.microsoft.com/kusto/query/indexof-function) |
| `has_any_index` | — | `has_any_index(source, lookupArray)` | Index of first matching term | [has_any_index](https://learn.microsoft.com/kusto/query/has-any-index-function) |
| `tolower` / `toupper` | — | `tolower(s)` / `toupper(s)` | Case fold | [tolower](https://learn.microsoft.com/kusto/query/tolower-function), [toupper](https://learn.microsoft.com/kusto/query/toupper-function) |
| `trim` / `trim_start` / `trim_end` | — | `trim(regex, s)` | Trim regex matches | [trim](https://learn.microsoft.com/kusto/query/trim-function) |
| `strrep` | — | `strrep(s, n [, delimiter])` | Repeat | [strrep](https://learn.microsoft.com/kusto/query/strrep-function) |
| `strcmp` | — | `strcmp(s1, s2)` | strcmp-style int | [strcmp](https://learn.microsoft.com/kusto/query/strcmp-function) |
| `reverse` | — | `reverse(s)` | Reverse string | [reverse](https://learn.microsoft.com/kusto/query/reverse-function) |
| `translate` | — | `translate(searchList, replacementList, s)` | 1:1 char map | [translate](https://learn.microsoft.com/kusto/query/translate-function) |
| `tohex` | — | `tohex(value [, minLength])` | Hex string | [tohex](https://learn.microsoft.com/kusto/query/tohex-function) |
| `url_encode` / `url_decode` | — | `url_encode(url)` | Percent-encoding | [url_encode](https://learn.microsoft.com/kusto/query/url-encode-function), [url_decode](https://learn.microsoft.com/kusto/query/url-decode-function) |
| `url_encode_component` | — | `url_encode_component(s)` | Encode a component | [url_encode_component](https://learn.microsoft.com/kusto/query/url-encode-component-function) |
| `base64_encode_tostring` | `encode_base64` (related) | `base64_encode_tostring(s)` | UTF-8 → base64 | [base64_encode_tostring](https://learn.microsoft.com/kusto/query/base64-encode-tostring-function) |
| `base64_decode_tostring` | `decode_base64` | `base64_decode_tostring(b64)` | Base64 → UTF-8 | [base64_decode_tostring](https://learn.microsoft.com/kusto/query/base64-decode-tostring-function) |
| `base64_encode_fromguid` | — | `base64_encode_fromguid(guid)` | GUID → base64 | [base64_encode_fromguid](https://learn.microsoft.com/kusto/query/base64-encode-fromguid-function) |
| `base64_decode_toguid` | — | `base64_decode_toguid(b64)` | Base64 → GUID | [base64_decode_toguid](https://learn.microsoft.com/kusto/query/base64-decode-toguid-function) |
| `base64_decode_toarray` | — | `base64_decode_toarray(b64)` | Base64 → byte array | [base64_decode_toarray](https://learn.microsoft.com/kusto/query/base64-decode-toarray-function) |
| `punycode_from_string` / `punycode_to_string` | — | `punycode_from_string(domain)` | IDN encode/decode | [punycode_from_string](https://learn.microsoft.com/kusto/query/punycode-from-string-function) |

PowerShell `-enc` hunting almost always uses `base64_decode_tostring` + `replace` of UTF-16 nulls.

---

## Dynamic / array / bag

| Name | Aliases | Signature | Docs | Citation |
| --- | --- | --- | --- | --- |
| `array_length` | `arraylength` | `array_length(array)` | Length | [array_length](https://learn.microsoft.com/kusto/query/array-length-function) |
| `array_concat` | — | `array_concat(a1, a2, …)` | Concat arrays | [array_concat](https://learn.microsoft.com/kusto/query/array-concat-function) |
| `array_slice` | — | `array_slice(array, start, end)` | Slice | [array_slice](https://learn.microsoft.com/kusto/query/array-slice-function) |
| `array_split` | — | `array_split(array, indices)` | Split | [array_split](https://learn.microsoft.com/kusto/query/array-split-function) |
| `array_reverse` | — | `array_reverse(array)` | Reverse | [array_reverse](https://learn.microsoft.com/kusto/query/array-reverse-function) |
| `array_rotate_left` / `array_rotate_right` | — | `array_rotate_left(array, n)` | Rotate | [array_rotate_left](https://learn.microsoft.com/kusto/query/array-rotate-left-function) |
| `array_shift_left` / `array_shift_right` | — | `array_shift_left(array, n [, default])` | Shift | [array_shift_left](https://learn.microsoft.com/kusto/query/array-shift-left-function) |
| `array_index_of` | — | `array_index_of(array, value)` | Index | [array_index_of](https://learn.microsoft.com/kusto/query/array-index-of-function) |
| `array_iff` | `array_iif` | `array_iff(condArray, ifTrue, ifFalse)` | Element-wise iff | [array_iff](https://learn.microsoft.com/kusto/query/array-iff-function) |
| `array_sum` | — | `array_sum(array)` | Sum numeric array | [array_sum](https://learn.microsoft.com/kusto/query/array-sum-function) |
| `array_sort_asc` / `array_sort_desc` | — | `array_sort_asc(array [, …])` | Sort parallel arrays | [array_sort_asc](https://learn.microsoft.com/kusto/query/array-sort-asc-function) |
| `pack_array` | `pack` (when packing values to array) | `pack_array(v1, v2, …)` | Values → array | [pack_array](https://learn.microsoft.com/kusto/query/pack-array-function) |
| `pack_all` | — | `pack_all([ignoreEmpty])` | All columns → bag | [pack_all](https://learn.microsoft.com/kusto/query/pack-all-function) |
| `bag_pack` | `pack` (deprecated bag form), `pack_dictionary` | `bag_pack(k1, v1, k2, v2, …)` | Build property bag | [bag_pack](https://learn.microsoft.com/kusto/query/bag-pack-function) |
| `bag_pack_columns` | — | `bag_pack_columns(col1, col2, …)` | Columns → bag | [bag_pack_columns](https://learn.microsoft.com/kusto/query/bag-pack-columns-function) |
| `bag_keys` | — | `bag_keys(bag)` | Root keys | [bag_keys](https://learn.microsoft.com/kusto/query/bag-keys-function) |
| `bag_has_key` | — | `bag_has_key(bag, key)` | Key exists | [bag_has_key](https://learn.microsoft.com/kusto/query/bag-has-key-function) |
| `bag_merge` | — | `bag_merge(b1, b2, …)` | Merge bags | [bag_merge](https://learn.microsoft.com/kusto/query/bag-merge-function) |
| `bag_remove_keys` | — | `bag_remove_keys(bag, keys)` | Drop keys | [bag_remove_keys](https://learn.microsoft.com/kusto/query/bag-remove-keys-function) |
| `bag_set_key` | — | `bag_set_key(bag, key, value)` | Set key (nested path) | [bag_set_key](https://learn.microsoft.com/kusto/query/bag-set-key-function) |
| `repeat` | — | `repeat(value, count)` | Array of equals | [repeat](https://learn.microsoft.com/kusto/query/repeat-function) |
| `range` | — | `range(start, stop, step)` | **Scalar** array series (not the tabular operator) | [range](https://learn.microsoft.com/kusto/query/range-function) |
| `set_union` / `set_intersect` / `set_difference` | — | `set_union(a1, a2, …)` | Set ops on arrays | [set_union](https://learn.microsoft.com/kusto/query/set-union-function) |
| `set_has_element` | — | `set_has_element(array, value)` | Membership | [set_has_element](https://learn.microsoft.com/kusto/query/set-has-element-function) |
| `jaccard_index` | — | `jaccard_index(a, b)` | Jaccard similarity | [jaccard_index](https://learn.microsoft.com/kusto/query/jaccard-index-function) |
| `zip` | — | `zip(a1, a2, …)` | Zip arrays | [zip](https://learn.microsoft.com/kusto/query/zip-function) |
| `treepath` | — | `treepath(object)` | Leaf path expressions | [treepath](https://learn.microsoft.com/kusto/query/treepath-function) |

---

## Hashing

Used constantly in Defender file/process detections (`SHA1`, `SHA256` columns are already hashed; these hash **query values**).

| Name | Signature | Docs | Citation |
| --- | --- | --- | --- |
| `hash` | `hash(value [, mod])` | Non-crypto xxhash-like (can change between versions — do not persist) | [hash](https://learn.microsoft.com/kusto/query/hash-function) |
| `hash_xxhash64` | `hash_xxhash64(value [, mod])` | XXHASH64 | [hash_xxhash64](https://learn.microsoft.com/kusto/query/hash-xxhash64-function) |
| `hash_md5` | `hash_md5(value)` | MD5 | [hash_md5](https://learn.microsoft.com/kusto/query/hash-md5-function) |
| `hash_sha1` | `hash_sha1(value)` | SHA1 | [hash_sha1](https://learn.microsoft.com/kusto/query/hash-sha1-function) |
| `hash_sha256` | `hash_sha256(value)` | SHA-256 | [hash_sha256](https://learn.microsoft.com/kusto/query/hash-sha256-function) |
| `hash_combine` | `hash_combine(h1, h2, …)` | Combine hashes | [hash_combine](https://learn.microsoft.com/kusto/query/hash-combine-function) |
| `hash_many` | `hash_many(v1, v2, …)` | Hash multiple values | [hash_many](https://learn.microsoft.com/kusto/query/hash-many-function) |

Related: `hash_sha2_256` may appear as an alias in some docs versions of `hash_sha256`.

---

## IPv4 / IPv6

| Name | Signature | Docs | Citation |
| --- | --- | --- | --- |
| `ipv4_is_private` | `ipv4_is_private(ip)` | RFC1918 / loopback / link-local | [ipv4_is_private](https://learn.microsoft.com/kusto/query/ipv4-is-private-function) |
| `ipv4_is_in_range` | `ipv4_is_in_range(ip, range)` | CIDR or `start-end` | [ipv4_is_in_range](https://learn.microsoft.com/kusto/query/ipv4-is-in-range-function) |
| `ipv4_is_in_any_range` | `ipv4_is_in_any_range(ip, r1, …)` | Any range | [ipv4_is_in_any_range](https://learn.microsoft.com/kusto/query/ipv4-is-in-any-range-function) |
| `ipv4_is_match` | `ipv4_is_match(ip1, ip2 [, prefix])` | Match with optional prefix | [ipv4_is_match](https://learn.microsoft.com/kusto/query/ipv4-is-match-function) |
| `ipv4_compare` | `ipv4_compare(ip1, ip2 [, prefix])` | Compare | [ipv4_compare](https://learn.microsoft.com/kusto/query/ipv4-compare-function) |
| `ipv4_netmask_suffix` | `ipv4_netmask_suffix(ip)` | Suffix from CIDR string | [ipv4_netmask_suffix](https://learn.microsoft.com/kusto/query/ipv4-netmask-suffix-function) |
| `ipv4_range_to_cidr_list` | `ipv4_range_to_cidr_list(start, end)` | Range → CIDRs | [ipv4_range_to_cidr_list](https://learn.microsoft.com/kusto/query/ipv4-range-to-cidr-list-function) |
| `parse_ipv4` | `parse_ipv4(ip)` | IPv4 → `long` | [parse_ipv4](https://learn.microsoft.com/kusto/query/parse-ipv4-function) |
| `parse_ipv4_mask` | `parse_ipv4_mask(ip, prefix)` | Masked long | [parse_ipv4_mask](https://learn.microsoft.com/kusto/query/parse-ipv4-mask-function) |
| `format_ipv4` | `format_ipv4(value [, prefix])` | Format IPv4 | [format_ipv4](https://learn.microsoft.com/kusto/query/format-ipv4-function) |
| `format_ipv4_mask` | `format_ipv4_mask(value, prefix)` | CIDR string | [format_ipv4_mask](https://learn.microsoft.com/kusto/query/format-ipv4-mask-function) |
| `ipv6_is_match` | `ipv6_is_match(ip1, ip2 [, prefix])` | IPv6/IPv4 match | [ipv6_is_match](https://learn.microsoft.com/kusto/query/ipv6-is-match-function) |
| `ipv6_compare` | `ipv6_compare(ip1, ip2 [, prefix])` | Compare | [ipv6_compare](https://learn.microsoft.com/kusto/query/ipv6-compare-function) |
| `ipv6_is_in_range` / `ipv6_is_in_any_range` | same pattern as v4 | CIDR checks | [ipv6_is_in_range](https://learn.microsoft.com/kusto/query/ipv6-is-in-range-function) |
| `parse_ipv6` / `parse_ipv6_mask` | `parse_ipv6(ip)` | Canonical IPv6 string | [parse_ipv6](https://learn.microsoft.com/kusto/query/parse-ipv6-function) |
| `geo_info_from_ip_address` | `geo_info_from_ip_address(ip)` | Geo bag (country, city, coords) | [geo_info_from_ip_address](https://learn.microsoft.com/kusto/query/geo-info-from-ip-address-function) |
| `has_ipv4` / `has_ipv4_prefix` / `has_any_ipv4` / `has_any_ipv4_prefix` | See [operators-scalar](operators-scalar.md) | Search IPv4 in **text** | [has_ipv4](https://learn.microsoft.com/kusto/query/has-ipv4-function) |

---

## Binary / bitwise

| Name | Signature | Citation |
| --- | --- | --- |
| `binary_and` | `binary_and(a, b)` | [binary_and](https://learn.microsoft.com/kusto/query/binary-and-function) |
| `binary_or` | `binary_or(a, b)` | [binary_or](https://learn.microsoft.com/kusto/query/binary-or-function) |
| `binary_xor` | `binary_xor(a, b)` | [binary_xor](https://learn.microsoft.com/kusto/query/binary-xor-function) |
| `binary_not` | `binary_not(a)` | [binary_not](https://learn.microsoft.com/kusto/query/binary-not-function) |
| `binary_shift_left` | `binary_shift_left(value, n)` | [binary_shift_left](https://learn.microsoft.com/kusto/query/binary-shift-left-function) |
| `binary_shift_right` | `binary_shift_right(value, n)` | [binary_shift_right](https://learn.microsoft.com/kusto/query/binary-shift-right-function) |
| `bitset_count_ones` | `bitset_count_ones(value)` | [bitset_count_ones](https://learn.microsoft.com/kusto/query/bitset-count-ones-function) |

---

## Math

| Name | Signature | Citation |
| --- | --- | --- |
| `abs` | `abs(x)` | [abs](https://learn.microsoft.com/kusto/query/abs-function) |
| `sqrt` / `pow` / `exp` / `exp2` / `exp10` | `pow(base, exponent)` | [pow](https://learn.microsoft.com/kusto/query/pow-function) |
| `log` / `log2` / `log10` / `loggamma` / `gamma` | `log(x)` | [log](https://learn.microsoft.com/kusto/query/log-function) |
| `sin` `cos` `tan` `cot` `asin` `acos` `atan` `atan2` | radians | [sin](https://learn.microsoft.com/kusto/query/sin-function) |
| `degrees` / `radians` | angle convert | [degrees](https://learn.microsoft.com/kusto/query/degrees-function) |
| `pi` | `pi()` | [pi](https://learn.microsoft.com/kusto/query/pi-function) |
| `sign` | `sign(x)` | [sign](https://learn.microsoft.com/kusto/query/sign-function) |
| `round` | `round(x [, precision])` | [round](https://learn.microsoft.com/kusto/query/round-function) |
| `rand` | `rand([n])` | [rand](https://learn.microsoft.com/kusto/query/rand-function) — **non-deterministic**; avoid as detection key |
| `isfinite` / `isinf` / `isnan` | `isnan(x)` | [isnan](https://learn.microsoft.com/kusto/query/isnan-function) |
| `erf` / `erfc` | error function | [erf](https://learn.microsoft.com/kusto/query/erf-function) |
| `beta_cdf` / `beta_inv` / `beta_pdf` | beta distribution | [beta_cdf](https://learn.microsoft.com/kusto/query/beta-cdf-function) |
| `welch_test` | `welch_test(m1,v1,c1,m2,v2,c2)` | [welch_test](https://learn.microsoft.com/kusto/query/welch-test-function) |

---

## Window functions (require `serialize` / `sort` / `top`)

| Name | Signature | Citation |
| --- | --- | --- |
| `next` | `next(column [, offset][, default])` | [next](https://learn.microsoft.com/kusto/query/next-function) |
| `prev` | `prev(column [, offset][, default])` | [prev](https://learn.microsoft.com/kusto/query/prev-function) |
| `row_number` | `row_number([start][, restart])` | [row_number](https://learn.microsoft.com/kusto/query/row-number-function) |
| `row_cumsum` | `row_cumsum(column [, restart])` | [row_cumsum](https://learn.microsoft.com/kusto/query/row-cumsum-function) |
| `row_rank_dense` | `row_rank_dense(column [, restart])` | [row_rank_dense](https://learn.microsoft.com/kusto/query/row-rank-dense-function) |
| `row_rank_min` | `row_rank_min(column [, restart])` | [row_rank_min](https://learn.microsoft.com/kusto/query/row-rank-min-function) |
| `row_window_session` | sessionize by gap | [row_window_session](https://learn.microsoft.com/kusto/query/row-window-session-function) |

---

## Flow control / materialize / type

| Name | Signature | Docs | Citation | Detections |
| --- | --- | --- | --- | --- |
| `toscalar` | `toscalar(tabularExpr)` | Force a tabular result to one scalar (first column, first row) | [toscalar](https://learn.microsoft.com/kusto/query/toscalar-function) | **Yes** |
| `materialize` | `materialize(tabularExpr)` | Cache tabular subquery in the query | [materialize](https://learn.microsoft.com/kusto/query/materialize-function) | **Yes** |
| `gettype` | `gettype(expr)` | Runtime type name | [gettype](https://learn.microsoft.com/kusto/query/gettype-function) | **Yes** |

---

## Metadata / ingestion (Azure Monitor caveats)

| Name | Signature | Citation | Detections |
| --- | --- | --- | --- |
| `ingestion_time` | `ingestion_time()` | [ingestion_time](https://learn.microsoft.com/kusto/query/ingestion-time-function) | **Yes** — Defender custom detections evaluate this for lookback |
| `estimate_data_size` | `estimate_data_size(*)` or columns | [estimate_data_size](https://learn.microsoft.com/kusto/query/estimate-data-size-function) | Hunting |
| `current_cluster_endpoint` | `current_cluster_endpoint()` | [current_cluster_endpoint](https://learn.microsoft.com/kusto/query/current-cluster-endpoint-function) | **AM-no** / unused |
| `current_database` | `current_database()` | [current_database](https://learn.microsoft.com/kusto/query/current-database-function) | Rare |
| `current_principal` | `current_principal()` | [current_principal](https://learn.microsoft.com/kusto/query/current-principal-function) | **AM-no** |
| `current_principal_details` | `current_principal_details()` | [current_principal_details](https://learn.microsoft.com/kusto/query/current-principal-details-function) | **AM-no** |
| `current_principal_is_member_of` | `current_principal_is_member_of(group)` | [current_principal_is_member_of](https://learn.microsoft.com/kusto/query/current-principal-is-member-of-function) | **AM-no** |
| `cursor_after` / `cursor_before_or_at` / `cursor_current` | cursor APIs | [cursor_after](https://learn.microsoft.com/kusto/query/cursor-after-function) | **AM-no** |
| `extent_id` / `extent_tags` | shard metadata | [extent_id](https://learn.microsoft.com/kusto/query/extent-id-function) | **AM-no** |
| `cluster` / `database` | cross-cluster | [cluster](https://learn.microsoft.com/kusto/query/cluster-function) | **AM-no** |
| `table` | `table(name)` | [table](https://learn.microsoft.com/kusto/query/table-function) | Restricted (dynamic table names) |

---

## Scalar aggregation companions (sketches)

| Name | Signature | Citation |
| --- | --- | --- |
| `dcount_hll` | `dcount_hll(hll)` | [dcount_hll](https://learn.microsoft.com/kusto/query/dcount-hll-function) |
| `hll_merge` | `hll_merge(hll1, …)` scalar merge | [hll_merge](https://learn.microsoft.com/kusto/query/hll-merge-function) |
| `percentile_tdigest` | `percentile_tdigest(tdigest, p)` | [percentile_tdigest](https://learn.microsoft.com/kusto/query/percentile-tdigest-function) |
| `percentile_array_tdigest` | `percentile_array_tdigest(tdigest, pArray)` | [percentile-array-tdigest](https://learn.microsoft.com/kusto/query/percentile-array-tdigest-function) |
| `percentrank_tdigest` | `percentrank_tdigest(digest, value)` | [percentrank_tdigest](https://learn.microsoft.com/kusto/query/percentrank-tdigest-function) |
| `rank_tdigest` | `rank_tdigest(digest, value)` | [rank_tdigest](https://learn.microsoft.com/kusto/query/rank-tdigest-function) |
| `merge_tdigest` | `merge_tdigest(t1, t2, …)` | [merge_tdigest](https://learn.microsoft.com/kusto/query/merge-tdigest-function) |

---

## Series element-wise and processing

Used after `make-series`. Full list: [Scalar functions — series](https://learn.microsoft.com/kusto/query/scalar-functions)

**Element-wise:** `series_abs`, `series_acos`, `series_add`, `series_asin`, `series_atan`, `series_ceiling`, `series_cos`, `series_divide`, `series_equals`, `series_exp`, `series_floor`, `series_greater`, `series_greater_equals`, `series_less`, `series_less_equals`, `series_log`, `series_multiply`, `series_not_equals`, `series_pow`, `series_sign`, `series_sin`, `series_subtract`, `series_tan`.

**Processing:** `series_cosine_similarity`, `series_decompose`, `series_decompose_anomalies`, `series_decompose_forecast`, `series_dot_product`, `series_fill_backward`, `series_fill_const`, `series_fill_forward`, `series_fill_linear`, `series_fft`, `series_fir`, `series_fit_2lines`, `series_fit_2lines_dynamic`, `series_fit_line`, `series_fit_line_dynamic`, `series_fit_poly`, `series_ifft`, `series_iir`, `series_magnitude`, `series_outliers`, `series_pearson_correlation`, `series_periods_detect`, `series_periods_validate`, `series_product`, `series_seasonal`, `series_stats`, `series_stats_dynamic`, `series_sum`.

Detection validity: **Hunting** / advanced scheduled anomaly rules, not NRT.

Citations use `https://learn.microsoft.com/kusto/query/<name>-function` with underscores as hyphens (`series-decompose-anomalies-function`).

---

## Geospatial

Index: [Geospatial functions](https://learn.microsoft.com/kusto/query/scalar-functions#geospatial-functions)

Includes `geo_distance_2points`, `geo_point_in_circle`, `geo_point_in_polygon`, `geo_point_to_geohash` / `_s2cell` / `_h3cell`, line/polygon buffer/centroid/simplify/union, cell parent/children/rings, `geo_from_wkt`, intersection tests, `geo_info_from_ip_address` (also under IP). Rare in classic Sentinel analytics; used in location-based hunting.

Validity: **Yes** where the workspace supports them (Azure Monitor generally does for the core geo_* set).

---

## Units conversion

`convert_angle`, `convert_energy`, `convert_force`, `convert_length`, `convert_mass`, `convert_speed`, `convert_temperature`, `convert_volume` — [convert_length](https://learn.microsoft.com/kusto/query/convert-length-function). Uncommon in detections.

---

## Azure Monitor–only helpers (not in core scalar index)

| Name | Signature | Citation | Detections |
| --- | --- | --- | --- |
| `_GetWatchlist` | `_GetWatchlist('Name')` | [Watchlists](https://learn.microsoft.com/azure/sentinel/watchlists) | **Yes** (Sentinel) |
| `workspace` | `workspace('id-or-name')` | [Cross-workspace](https://learn.microsoft.com/azure/azure-monitor/logs/cross-workspace-query) | Restricted / Defender custom detection **No** |
| ASIM parsers | e.g. `_Im_NetworkSession`, `imAuthentication` | [ASIM](https://learn.microsoft.com/azure/sentinel/normalization) | **Yes** (recommended sources) |

---

## Count (this page)

| Bucket | Approx. documented names |
| --- | --- |
| Conversion + datetime + rounding + conditional | 55 |
| String + parse | 50 |
| Dynamic/array/bag | 35 |
| Hash + IP + binary + math | 55 |
| Window + metadata + sketches | 25 |
| Series element-wise + processing | 50 |
| Geo + unit convert | 55 |
| **Total scalar functions inventoried** | **~325** (official index ~280 + aliases + AM helpers) |
