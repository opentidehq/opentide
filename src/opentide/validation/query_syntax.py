"""Offline query syntax validation.

Platform query validators construct live clients and need tenant credentials and
vendor SDKs. The published tutorial and every generated CI pipeline run
``opentide validate query``, so the default path has to work from a stock install
with no extras and no tenant. This module performs a language-aware structural
check — delimiter balance, string termination, pipeline shape, dangling
operators — entirely in-process.

It is deliberately *not* a full grammar. It catches the syntax mistakes that a
detection engineer actually makes while authoring YAML, and it never reports a
query as semantically correct: callers surface ``mode: offline-syntax`` so an
agent or a CI log can tell the difference between "parses" and "runs".
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from opentide.core.object_fields import as_body

KQL = "kql"
SPL = "spl"
S1QL = "s1ql"
LUCENE = "lucene"

PLATFORM_QUERY_LANGUAGES: dict[str, str] = {
    "sentinel": KQL,
    "defender_for_endpoint": KQL,
    "splunk": SPL,
    "sentinel_one": S1QL,
    "carbon_black_cloud": LUCENE,
}

#: The platforms whose queries can be checked at all. CrowdStrike and HarfangLab
#: expose no query language, so their capability entry is ``can_validate False``.
QUERY_VALIDATION_PLATFORMS: frozenset[str] = frozenset(PLATFORM_QUERY_LANGUAGES)

LANGUAGE_LABELS = {KQL: "KQL", SPL: "SPL", S1QL: "S1QL", LUCENE: "Lucene"}

_PIPELINE_LANGUAGES = frozenset({KQL, SPL, S1QL})
#: Only KQL forbids a leading ``|``. SPL generating commands (``| tstats``,
#: ``| inputlookup``, ``| makeresults``, ``| from``) *must* start with one, and
#: S1QL accepts a leading stage too, so flagging those is a false positive on
#: correct content — and the offline check is the default path for CI.
_LEADING_PIPE_LANGUAGES = frozenset({KQL})
_BRACKET_PAIRS = {"(": ")", "[": "]", "{": "}"}
_CLOSING_BRACKETS = {value: key for key, value in _BRACKET_PAIRS.items()}
_LINE_COMMENTS: dict[str, tuple[str, ...]] = {KQL: ("//",), S1QL: ("//",)}
_BLOCK_COMMENTS: dict[str, tuple[str, str]] = {SPL: ("```", "```")}
#: Lucene's standard parser only knows the double-quoted phrase, so an
#: apostrophe inside a Carbon Black value is data, not an unterminated literal.
_STRING_DELIMITERS: dict[str, tuple[str, ...]] = {
    KQL: ('"', "'"),
    SPL: ('"', "'"),
    S1QL: ('"', "'"),
    LUCENE: ('"',),
}
#: KQL verbatim literals (``@"C:\dir\"``) take the backslash literally and
#: escape a quote by doubling it.
_VERBATIM_PREFIX_LANGUAGES = frozenset({KQL})
#: KQL multi-line literals: no escapes, and quotes or brackets inside are data.
_MULTILINE_STRINGS: dict[str, str] = {KQL: "```"}
#: Lucene escapes any special character with a backslash outside a phrase, so
#: ``process_cmdline:*iex\(*`` holds no bracket and ``*\"http*`` no string.
_BARE_ESCAPE_LANGUAGES = frozenset({LUCENE})
#: S1QL accepts ``||`` for ``OR``; it is not an empty stage between two pipes.
_DOUBLE_PIPE_OR_LANGUAGES = frozenset({S1QL})
#: Lucene ranges mix inclusive and exclusive ends: ``[1 TO 5}``, ``{1 TO 5]``.
_RANGE_OPENERS: dict[str, frozenset[str]] = {LUCENE: frozenset("[{")}
# Stands in for a string body: keeps the literal one token, carries no syntax.
_STRING_FILLER = "0"

# Conservative: only tokens that cannot legally end a query in any of the four
# languages, so a valid-but-unusual query is never reported.
_DANGLING_TOKENS = frozenset(
    {"and", "or", "not", "&&", "||", "=", "==", "!=", "<", ">", "<=", ">=", ",", "+"}
)


@dataclass(frozen=True)
class SyntaxFinding:
    """One structural problem located in a query string."""

    code: str
    message: str
    line: int
    column: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "line": self.line,
            "column": self.column,
        }


@dataclass(frozen=True)
class QuerySpec:
    """A query string extracted from one rule's platform configuration."""

    uuid: str
    rule: str
    platform: str
    language: str
    field: str
    query: str


@dataclass
class QuerySyntaxReport:
    """Aggregate result for one platform across the selected rules."""

    platform: str
    language: str
    rules: int = 0
    checked: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "language": self.language,
            "rules": self.rules,
            "checked": self.checked,
            "findings": list(self.findings),
        }


def query_language(platform: str) -> str | None:
    """Query language for *platform*, or ``None`` when it cannot be validated."""
    return PLATFORM_QUERY_LANGUAGES.get(platform)


def language_label(language: str) -> str:
    return LANGUAGE_LABELS.get(language, language.upper())


def _position(text: str, index: int) -> tuple[int, int]:
    prefix = text[:index]
    line = prefix.count("\n") + 1
    column = index - (prefix.rfind("\n") + 1) + 1
    return line, column


def _finding(code: str, message: str, text: str, index: int) -> SyntaxFinding:
    line, column = _position(text, index)
    return SyntaxFinding(code=code, message=message, line=line, column=column)


def _blank(text: str, filler: str = " ") -> str:
    """Replace every character except newlines so positions stay aligned."""
    return "".join("\n" if char == "\n" else filler for char in text)


def _scan_string(text: str, start: int, *, verbatim: bool = False) -> int | None:
    """Index of the quote closing the string opened at *start*, if any.

    In a verbatim literal the backslash is an ordinary character and the only
    escape is a doubled delimiter, so ``@"C:\\Windows\\"`` terminates where it
    looks like it does rather than swallowing the rest of the query.
    """
    delimiter = text[start]
    index = start + 1
    while index < len(text):
        char = text[index]
        if verbatim:
            if char == delimiter:
                if text.startswith(delimiter * 2, index):
                    index += 2
                    continue
                return index
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char == delimiter:
            return index
        index += 1
    return None


def _mask(query: str, language: str) -> tuple[str, list[SyntaxFinding]]:
    """Blank comments and string bodies so structural checks see only syntax."""
    findings: list[SyntaxFinding] = []
    masked: list[str] = []
    line_comments = _LINE_COMMENTS.get(language, ())
    block_comment = _BLOCK_COMMENTS.get(language)
    delimiters = _STRING_DELIMITERS[language]
    verbatim_prefix = language in _VERBATIM_PREFIX_LANGUAGES
    multiline = _MULTILINE_STRINGS.get(language)
    bare_escapes = language in _BARE_ESCAPE_LANGUAGES
    index = 0
    length = len(query)
    while index < length:
        if multiline is not None and query.startswith(multiline, index):
            end = query.find(multiline, index + len(multiline))
            if end == -1:
                findings.append(
                    _finding(
                        "unterminated_string",
                        f"Unterminated {multiline} multi-line string literal",
                        query,
                        index,
                    )
                )
                masked.append(_blank(query[index:]))
                break
            body_start = index + len(multiline)
            stop = end + len(multiline)
            masked.append(multiline + _blank(query[body_start:end], _STRING_FILLER) + multiline)
            index = stop
            continue
        if bare_escapes and query[index] == "\\":
            masked.append(_blank(query[index : index + 2], _STRING_FILLER))
            index += 2
            continue
        if block_comment is not None and query.startswith(block_comment[0], index):
            opening, closing = block_comment
            end = query.find(closing, index + len(opening))
            if end == -1:
                findings.append(
                    _finding("unterminated_comment", "Unterminated comment block", query, index)
                )
                masked.append(_blank(query[index:]))
                break
            stop = end + len(closing)
            masked.append(_blank(query[index:stop]))
            index = stop
            continue
        if any(query.startswith(marker, index) for marker in line_comments):
            end = query.find("\n", index)
            if end == -1:
                masked.append(_blank(query[index:]))
                break
            masked.append(_blank(query[index:end]))
            index = end
            continue
        char = query[index]
        verbatim = verbatim_prefix and char == "@" and query[index + 1 : index + 2] in delimiters
        if verbatim:
            masked.append("@")
            index += 1
            char = query[index]
        if char in delimiters:
            end = _scan_string(query, index, verbatim=verbatim)
            if end is None:
                findings.append(
                    _finding(
                        "unterminated_string",
                        f"Unterminated {char} string literal",
                        query,
                        index,
                    )
                )
                masked.append(_blank(query[index:]))
                break
            # Keep the quotes: a query ending in a literal must not look like a
            # dangling operator once the body is gone.
            masked.append(char + _blank(query[index + 1 : end], _STRING_FILLER) + query[end])
            index = end + 1
            continue
        masked.append(char)
        index += 1
    return "".join(masked), findings


def _closes(opening: str, closing: str, language: str) -> bool:
    range_openers = _RANGE_OPENERS.get(language, frozenset())
    if opening in range_openers:
        return closing in {_BRACKET_PAIRS[other] for other in range_openers}
    return _BRACKET_PAIRS[opening] == closing


def _check_delimiters(masked: str, language: str) -> list[SyntaxFinding]:
    findings: list[SyntaxFinding] = []
    stack: list[tuple[str, int]] = []
    for index, char in enumerate(masked):
        if char in _BRACKET_PAIRS:
            stack.append((char, index))
            continue
        if char not in _CLOSING_BRACKETS:
            continue
        if not stack:
            findings.append(
                _finding(
                    "unexpected_closing_bracket",
                    f"Closing '{char}' has no matching opening bracket",
                    masked,
                    index,
                )
            )
            continue
        opening, opening_index = stack.pop()
        if not _closes(opening, char, language):
            findings.append(
                _finding(
                    "bracket_mismatch",
                    f"'{opening}' is closed by '{char}'",
                    masked,
                    opening_index,
                )
            )
    findings.extend(
        _finding("unclosed_bracket", f"'{opening}' is never closed", masked, index)
        for opening, index in stack
    )
    return findings


def _pipeline_segments(masked: str, language: str) -> Iterator[tuple[int, str]]:
    double_pipe_is_or = language in _DOUBLE_PIPE_OR_LANGUAGES
    start = 0
    index = 0
    while index < len(masked):
        if masked[index] != "|":
            index += 1
            continue
        if double_pipe_is_or and masked.startswith("||", index):
            index += 2
            continue
        yield start, masked[start:index]
        start = index + 1
        index += 1
    yield start, masked[start:]


def _check_pipeline(masked: str, language: str) -> list[SyntaxFinding]:
    segments = list(_pipeline_segments(masked, language))
    if len(segments) == 1:
        return []
    findings: list[SyntaxFinding] = []
    label = language_label(language)
    last = len(segments) - 1
    for position, (start, segment) in enumerate(segments):
        if segment.strip():
            continue
        if position == 0:
            if language in _LEADING_PIPE_LANGUAGES:
                findings.append(
                    _finding("leading_pipe", f"{label} query starts with '|'", masked, start)
                )
        elif position == last:
            findings.append(
                _finding("trailing_pipe", f"{label} query ends with '|'", masked, start)
            )
        else:
            findings.append(
                _finding("empty_pipeline_stage", "Empty stage between '|'", masked, start)
            )
    return findings


def _check_dangling_operator(masked: str) -> list[SyntaxFinding]:
    trimmed = masked.rstrip()
    if not trimmed:
        return []
    tail = trimmed.split()[-1]
    if tail.lower() not in _DANGLING_TOKENS:
        return []
    index = len(trimmed) - len(tail)
    return [_finding("dangling_operator", f"Query ends with the operator '{tail}'", masked, index)]


def check_query(query: str, language: str) -> list[SyntaxFinding]:
    """Structural findings for *query* in *language*; empty means it parses."""
    if not query or not query.strip():
        return [SyntaxFinding("empty_query", "Query is empty", 1, 1)]
    masked, findings = _mask(query, language)
    if findings:
        # Masking blanks everything after an unterminated literal, so structural
        # checks on the remainder would report positions that mean nothing.
        return list(findings)
    findings.extend(_check_delimiters(masked, language))
    if language in _PIPELINE_LANGUAGES:
        findings.extend(_check_pipeline(masked, language))
    findings.extend(_check_dangling_operator(masked))
    return findings


def _spec(
    *, uuid: str, rule: str, platform: str, language: str, field_path: str, query: str
) -> QuerySpec:
    return QuerySpec(
        uuid=uuid,
        rule=rule,
        platform=platform,
        language=language,
        field=field_path,
        query=query,
    )


def _sentinel_one_specs(
    config: Mapping[str, Any], *, uuid: str, rule: str, language: str
) -> list[QuerySpec]:
    """SentinelOne holds S1QL inside ``condition``, not a flat ``query`` field."""
    base = "configurations.sentinel_one.condition"
    condition = config.get("condition")
    if not isinstance(condition, Mapping):
        return []
    specs: list[QuerySpec] = []
    single = condition.get("single_event")
    if isinstance(single, Mapping) and isinstance(single.get("query"), str):
        specs.append(
            _spec(
                uuid=uuid,
                rule=rule,
                platform="sentinel_one",
                language=language,
                field_path=f"{base}.single_event.query",
                query=single["query"],
            )
        )
    correlation = condition.get("correlation")
    if isinstance(correlation, Mapping):
        sub_queries = correlation.get("sub_queries")
        for position, sub in enumerate(sub_queries if isinstance(sub_queries, list) else []):
            if isinstance(sub, Mapping) and isinstance(sub.get("query"), str):
                specs.append(
                    _spec(
                        uuid=uuid,
                        rule=rule,
                        platform="sentinel_one",
                        language=language,
                        field_path=f"{base}.correlation.sub_queries[{position}].query",
                        query=sub["query"],
                    )
                )
    return specs


def extract_queries(platform: str, uuid: str, body: Any) -> list[QuerySpec]:
    """Every query string *platform* would deploy from one rule body."""
    language = query_language(platform)
    if language is None:
        return []
    resolved = as_body(body)
    configurations = resolved.get("configurations")
    if not isinstance(configurations, Mapping):
        return []
    config = configurations.get(platform)
    if not isinstance(config, Mapping):
        return []
    rule = str(resolved.get("name") or resolved.get("title") or uuid)
    if platform == "sentinel_one":
        return _sentinel_one_specs(config, uuid=uuid, rule=rule, language=language)
    # Splunk accepts the legacy flat `search` field alongside `query`.
    for candidate in ("query", "search"):
        value = config.get(candidate)
        if isinstance(value, str):
            return [
                _spec(
                    uuid=uuid,
                    rule=rule,
                    platform=platform,
                    language=language,
                    field_path=f"configurations.{platform}.{candidate}",
                    query=value,
                )
            ]
    return []


def validate_platform_queries(
    platform: str,
    rules: Mapping[str, Any],
    *,
    uuids: frozenset[str] | None = None,
) -> QuerySyntaxReport:
    """Run the offline syntax check over every *platform* query in *rules*."""
    language = query_language(platform)
    if language is None:
        raise ValueError(f"query validation not supported for {platform}")
    report = QuerySyntaxReport(platform=platform, language=language)
    for uuid, body in sorted(rules.items()):
        if uuids is not None and uuid not in uuids:
            continue
        specs = extract_queries(platform, uuid, body)
        if not specs:
            continue
        report.rules += 1
        for spec in specs:
            report.checked += 1
            for finding in check_query(spec.query, language):
                report.findings.append(
                    {
                        "uuid": spec.uuid,
                        "rule": spec.rule,
                        "field": spec.field,
                        **finding.to_dict(),
                    }
                )
    return report
