# Evaluation functions

Functions used with `eval`, `where`, `fieldformat`, and eval-expressions inside `stats`/`tstats`/`chart`.

Citation: [Evaluation functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonEvalFunctions)

Category pages:

- [Comparison and Conditional](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions)
- [Conversion](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConversionFunctions)
- [Cryptographic](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CryptographicFunctions)
- [Date and Time](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/DateandTimeFunctions)
- [Informational](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/InformationalFunctions)
- [JSON](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions)
- [Mathematical](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions)
- [Multivalue eval](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions)
- [Statistical eval](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/StatisticalFunctions)
- [Text](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions)
- [Trigonometry and Hyperbolic](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions)
- [Bitwise](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/BitFunctions)

Notes:

- String literals use **double quotes**. Field names with punctuation use **single quotes**.
- Equality in eval is `==`, not `=`.
- Nested calls are allowed: `if(cidrmatch("10.0.0.0/8", src_ip), "internal", "external")`.
- `true()` is the usual default arm of `case(...)`.
- `ceil` is accepted as an alias of `ceiling` in SPL.

Functions marked **detection-common** appear constantly in ES / ESCU searches.

---

## Comparison and conditional

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `if` | `if(X,Y,Z)` | yes | If boolean X is true return Y else Z. | [if](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `case` | `case(X1,Y1,X2,Y2,...,true(),Ydefault)` | yes | First true condition’s value; else null unless `true()` arm. | [case](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `coalesce` | `coalesce(X,...)` | yes | First non-null argument. Normalize `user`/`src`/`CommandLine`. | [coalesce](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `cidrmatch` | `cidrmatch("cidr", ip)` | yes | True if IP is in CIDR. IPv4/IPv6. | [cidrmatch](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `match` | `match(SUBJECT, "REGEX")` | yes | True if regex matches. Use with `where`. | [match](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `like` | `like(TEXT, PATTERN)` | yes | SQL-like: `%` and `_`. | [like](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `searchmatch` | `searchmatch("search string")` | yes | True if the search string matches the event (`search` semantics). | [searchmatch](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `in` | `in(FIELD, v1, v2, ...)` | yes | True if field equals one value. **No wildcards** (unlike `search` `IN`). | [in](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `validate` | `validate(X,Y,...)` | | Opposite of `case`: first **false** X returns Y. | [validate](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `nullif` | `nullif(X,Y)` | | Null if X=Y else X. | [nullif](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `null` | `null()` | | Null constant. | [null](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `true` | `true()` | yes | Boolean true (default `case` arm). | [true](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `false` | `false()` | | Boolean false. | [false](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |
| `lookup` | `lookup(table, json_object, json_array)` | | Eval-time CSV lookup returning JSON. Rare vs the `lookup` **command**. | [lookup](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions) |

---

## Text

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `len` | `len(X)` | yes | Character count (not bytes). | [len](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |
| `lower` | `lower(X)` | yes | Lowercase. Normalize `user`, `process_name`, `dest`. | [lower](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |
| `upper` | `upper(X)` | yes | Uppercase. | [upper](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |
| `replace` | `replace(X,Y,Z)` | yes | Substitute regex Y with Z in X. | [replace](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |
| `substr` | `substr(X,Y,Z)` | yes | Substring of X from 1-based Y, length Z. | [substr](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |
| `trim` | `trim(X,Y)` | yes | Trim characters in Y (default whitespace) from both ends. | [trim](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |
| `ltrim` | `ltrim(X,Y)` | | Left trim. | [ltrim](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |
| `rtrim` | `rtrim(X,Y)` | | Right trim. | [rtrim](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |
| `urldecode` | `urldecode(X)` | yes | Decode `%xx` URL encoding. | [urldecode](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |
| `spath` | `spath(X,Y)` | yes | Extract from JSON/XML string X at path Y (eval form of the `spath` command). | [spath](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions) |

---

## Multivalue

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `split` | `split(X,"Y")` | yes | Split X on delimiter Y → mv. Command-line argv, hashes. | [split](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvcount` | `mvcount(MVFIELD)` | yes | Number of values. | [mvcount](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvindex` | `mvindex(MV,START,END)` | yes | Slice; negative index counts from end. `mvindex(split(process,"\\"),-1)` → image name. | [mvindex](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvjoin` | `mvjoin(MV,STR)` | yes | Join with delimiter. | [mvjoin](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvfilter` | `mvfilter(X)` | yes | Keep mv values where boolean X is true (`mvfilter(match(_,"(?i)pass"))`). | [mvfilter](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvappend` | `mvappend(X,...)` | | Concatenate mv/single values. | [mvappend](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvdedup` | `mvdedup(X)` | | Drop duplicate mv values. | [mvdedup](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvfind` | `mvfind(MV,"REGEX")` | | Index of first matching value. | [mvfind](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvmap` | `mvmap(X,Y)` | | Map expression Y over mv X. | [mvmap](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvrange` | `mvrange(X,Y,Z)` | | Numeric range X..Y step Z. | [mvrange](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvsort` | `mvsort(X)` | | Lexicographic sort. | [mvsort](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `mvzip` | `mvzip(X,Y,"Z")` | | Zip two mv fields with delimiter Z. | [mvzip](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |
| `commands` | `commands(X)` | | Mv list of SPL commands used in search string X. | [commands](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MultivalueEvalFunctions) |

---

## Conversion

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `tonumber` | `tonumber(NUMSTR,BASE)` | yes | String → number; BASE 2..36. Hex hashes / EventCode. | [tonumber](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConversionFunctions) |
| `tostring` | `tostring(X,Y)` | yes | To string. Y: `"hex"`, `"commas"`, `"duration"`, `"binary"`. | [tostring](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConversionFunctions) |
| `printf` | `printf("format", args...)` | | C-style format string. | [printf](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConversionFunctions) |
| `ipmask` | `ipmask(mask, ip)` | | Mask IPv4 via bitwise AND (`ipmask("255.255.0.0", src)`). | [ipmask](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConversionFunctions) |
| `toint` | `toint(value, base)` | | Convert to integer (later platform versions). | [toint](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConversionFunctions) |
| `todouble` | `todouble(value, base)` | | Convert to double. | [todouble](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConversionFunctions) |

---

## Date and time

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `strftime` | `strftime(X,Y)` | yes | UNIX time X → string with format Y (`%Y-%m-%d %H:%M:%S`). | [strftime](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/DateandTimeFunctions) |
| `strptime` | `strptime(X,Y)` | yes | Parse string X with format Y → UNIX time. | [strptime](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/DateandTimeFunctions) |
| `now` | `now()` | yes | Search start time (same for all events). | [now](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/DateandTimeFunctions) |
| `relative_time` | `relative_time(X,Y)` | yes | Apply relative specifier Y (`-1h@h`) to UNIX time X. | [relative_time](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/DateandTimeFunctions) |
| `time` | `time()` | | Wall time when **this event** was processed (varies per event). | [time](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/DateandTimeFunctions) |

Format tokens: [Date and time format variables](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Commontimeformatvariables).

---

## Informational / type tests

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `isnull` | `isnull(X)` | yes | True if null. | [isnull](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/InformationalFunctions) |
| `isnotnull` | `isnotnull(X)` | yes | True if not null. | [isnotnull](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/InformationalFunctions) |
| `isnum` | `isnum(X)` | yes | True if numeric. | [isnum](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/InformationalFunctions) |
| `isstr` | `isstr(X)` | yes | True if string. | [isstr](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/InformationalFunctions) |
| `typeof` | `typeof(X)` | yes | `"Number"`, `"String"`, `"Boolean"`, `"Invalid"`, … | [typeof](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/InformationalFunctions) |
| `isbool` | `isbool(X)` | | True if Boolean. | [isbool](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/InformationalFunctions) |
| `isint` | `isint(X)` | | True if integer. | [isint](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/InformationalFunctions) |

---

## Cryptographic

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `md5` | `md5(X)` | yes | MD5 hex digest. | [md5](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CryptographicFunctions) |
| `sha1` | `sha1(X)` | yes | SHA-1 hex digest. | [sha1](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CryptographicFunctions) |
| `sha256` | `sha256(X)` | yes | SHA-256 hex digest. | [sha256](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CryptographicFunctions) |
| `sha512` | `sha512(X)` | | SHA-512 hex digest. | [sha512](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CryptographicFunctions) |

These hash the **string value**, not a file on disk. Detections usually compare already-extracted `file_hash` / `process_hash` fields rather than computing hashes of `_raw`.

---

## JSON

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `json_extract` | `json_extract(json, path...)` | yes | Value at JSON path(s). CloudTrail / o365 / kube JSON. | [json_extract](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_object` | `json_object(k1,v1,...)` | yes | Build a JSON object. | [json_object](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_array` | `json_array(v,...)` | | Build a JSON array. | [json_array](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_keys` | `json_keys(json)` | | Keys as JSON array. | [json_keys](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_valid` | `json_valid(json)` | | True if valid JSON. | [json_valid](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_set` | `json_set(json, path, value, ...)` | | Insert/overwrite nodes. | [json_set](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_set_exact` | `json_set_exact(json, k, v, ...)` | | Set by literal keys. | [json_set_exact](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_append` | `json_append(json, path, value, ...)` | | Append to arrays. | [json_append](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_extend` | `json_extend(json, path, value, ...)` | | Flatten and append array values. | [json_extend](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_extract_exact` | `json_extract_exact(json, keys...)` | | Extract by literal strings. | [json_extract_exact](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `json_array_to_mv` | `json_array_to_mv(json_array)` | | JSON array → mv field. | [json_array_to_mv](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |
| `mv_to_json_array` | `mv_to_json_array(mv)` | | Mv field → JSON array. | [mv_to_json_array](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/JSONFunctions) |

---

## Mathematical

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `round` | `round(X,Y)` | yes | Round X to Y decimal places (default 0). | [round](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `abs` | `abs(X)` | yes | Absolute value. | [abs](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `ceil` / `ceiling` | `ceil(X)` / `ceiling(X)` | yes | Round up. | [ceiling](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `floor` | `floor(X)` | yes | Round down. | [floor](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `log` | `log(X,Y)` | yes | Log of X, base Y (default 10). | [log](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `ln` | `ln(X)` | | Natural log. | [ln](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `pow` | `pow(X,Y)` | yes | X^Y. | [pow](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `exp` | `exp(X)` | | e^X. | [exp](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `sqrt` | `sqrt(X)` | | Square root. | [sqrt](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `pi` | `pi()` | | π to 11 digits. | [pi](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `sigfig` | `sigfig(X)` | | Significant figures. | [sigfig](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `exact` | `exact(X)` | | Higher precision numeric eval. | [exact](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |
| `sum` | `sum(X,...)` | | Sum of numeric **eval args** (not the stats function). | [sum](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/MathematicalFunctions) |

---

## Statistical eval (event-local)

These are **not** the `stats` aggregations. They reduce arguments **on one event**.

| Name | Syntax | Detection-common | Docs | Citation |
| --- | --- | --- | --- | --- |
| `random` | `random()` | yes | Pseudo-random int in `[0, 2^31-1)`. Sampling / jitter. | [random](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/StatisticalFunctions) |
| `min` | `min(X,...)` | | Min of arguments on this event. | [min](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/StatisticalFunctions) |
| `max` | `max(X,...)` | | Max of arguments on this event. | [max](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/StatisticalFunctions) |
| `avg` | `avg(X,...)` | | Average of numeric arguments. | [avg](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/StatisticalFunctions) |

---

## Bitwise

Nonnegative integers in `0 .. 2^53-1`. Citation: [Bitwise functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/BitFunctions)

| Name | Syntax | Docs | Citation |
| --- | --- | --- | --- |
| `bit_and` | `bit_and(X,Y,...)` | Bitwise AND (flags / masks). | [bit_and](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/BitFunctions) |
| `bit_or` | `bit_or(X,Y,...)` | Bitwise OR. | [bit_or](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/BitFunctions) |
| `bit_xor` | `bit_xor(X,Y,...)` | Bitwise XOR. | [bit_xor](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/BitFunctions) |
| `bit_not` | `bit_not(X,Y)` | Invert bits. Y is the optional bitmask (default 2^53-1). | [bit_not](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/BitFunctions) |
| `bit_shift_left` | `bit_shift_left(X, offset)` | Logical left shift. | [bit_shift_left](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/BitFunctions) |
| `bit_shift_right` | `bit_shift_right(X, offset)` | Logical right shift. | [bit_shift_right](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/BitFunctions) |

---

## Trigonometry and hyperbolic

Rare in detections. Citation: [Trig and Hyperbolic functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions)

| Name | Syntax | Docs | Citation |
| --- | --- | --- | --- |
| `acos` | `acos(X)` | Arc cosine of X, in [0, pi] radians. | [acos](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `acosh` | `acosh(X)` | Arc hyperbolic cosine of X radians. | [acosh](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `asin` | `asin(X)` | Arc sine of X, in [-pi/2, +pi/2] radians. | [asin](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `asinh` | `asinh(X)` | Arc hyperbolic sine of X radians. | [asinh](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `atan` | `atan(X)` | Arc tangent of X, in [-pi/2, +pi/2] radians. | [atan](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `atan2` | `atan2(Y,X)` | Arc tangent of Y, X, in [-pi, +pi] radians. | [atan2](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `atanh` | `atanh(X)` | Arc hyperbolic tangent of X radians. | [atanh](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `cos` | `cos(X)` | Cosine of an angle of X radians. | [cos](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `cosh` | `cosh(X)` | Hyperbolic cosine of X radians. | [cosh](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `hypot` | `hypot(X,Y)` | Hypotenuse of a right triangle with legs X and Y. | [hypot](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `sin` | `sin(X)` | Sine of X. | [sin](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `sinh` | `sinh(X)` | Hyperbolic sine of X radians. | [sinh](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `tan` | `tan(X)` | Tangent of X radians. | [tan](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |
| `tanh` | `tanh(X)` | Hyperbolic tangent of X radians. | [tanh](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TrigandHyperbolicFunctions) |

---

## Detection snippets

```spl
| eval user=lower(coalesce(user, src_user, User, TargetUserName))
| eval process_name=lower(mvindex(split(process,"\\"),-1))
| eval is_lolbin=if(match(original_file_name,"(?i)cmd\\.exe"), "true", "false")
| eval age=now()-_time
| where cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("192.168.0.0/16", src_ip)
| eval firstTime=strftime(firstTime,"%Y-%m-%dT%H:%M:%S")
```

```spl
| eval hash=lower(coalesce(file_hash, MD5, SHA256))
| where match(process, "(?i)(-enc|-encodedcommand|frombase64string)")
| eval cmd_len=len(process)
```
