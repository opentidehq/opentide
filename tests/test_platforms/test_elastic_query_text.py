"""Tests for reading ES|QL and EQL text past comments and strings (#616)."""

from __future__ import annotations

import pytest

from opentide.platforms.elastic.query_text import (
    eql_is_sequence,
    eql_maxspan,
    esql_aggregates,
    esql_has_metadata_id,
    esql_sources,
    mask_query,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a // b\nc", "a     \nc"),
        ("a /* b */ c", "a         c"),
        ("/* a /* b */ c */ d", "                  d"),
        ("/* a\nb */ c", "    \n     c"),
        ('x "a|b" y', 'x "   " y'),
        ('x "a\\"|b" y', 'x "     " y'),
        ('x """a\\"|b""" y', 'x """     """ y'),
        ('x "// not a comment" y', 'x "                " y'),
        ('x """a"""" y', 'x """ """" y'),
        ("x `a|``b` y", "x `     ` y"),
        ("x /* unterminated", "x                "),
        ('x "unterminated', 'x "            '),
    ],
)
def test_mask_query_blanks_comments_and_literals(text: str, expected: str) -> None:
    masked = mask_query(text)
    assert masked == expected
    assert len(masked) == len(text)


def test_mask_query_can_keep_string_contents() -> None:
    text = 'FROM "logs-*" // x\n| LIMIT 1'
    assert mask_query(text, keep_strings=True) == ('FROM "logs-*"     \n| LIMIT 1')


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("FROM logs-* | WHERE `a|b` == 1", "logs-*"),
        ("FROM logs-* /* | METADATA */ METADATA _id", "logs-*"),
        ("  from\n  logs-a ,logs-b", "logs-a,logs-b"),
        ('FROM "logs|*"', "logs|*"),
        # `metadata` inside an index pattern is not the METADATA keyword.
        ("FROM logs-metadata-* | WHERE x", "logs-metadata-*"),
        ("FROM .kibana-metadata, logs-* METADATA _id", ".kibana-metadata,logs-*"),
        # Leading SET statements come before the source command.
        ('SET time_zone = "UTC"; FROM logs-* | LIMIT 1', "logs-*"),
        ('SET a = 1;\nSET b = "x;y";\nFROM logs-*', "logs-*"),
        # A FROM subquery is not an index source, and its pipe is not the end.
        ("FROM logs-*, (FROM other | WHERE x) | LIMIT 1", "logs-*"),
        ("FROM (FROM a | WHERE x), logs-* METADATA _id | LIMIT 1", "logs-*"),
    ],
)
def test_esql_sources(query: str, expected: str) -> None:
    assert esql_sources(query) == expected


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("FROM logs-* | STATS c = COUNT(*)", True),
        ("FROM logs-*\n| stats c = count(*) by host.name", True),
        ("FROM logs-* | INLINE STATS c = COUNT(*) BY host.name | WHERE c > 5", False),
        ("FROM logs-* | INLINESTATS c = COUNT(*) BY host.name", False),
        ("FROM logs-* // | STATS c = COUNT(*)\n| WHERE x", False),
        ("FROM logs-* /* /* nested */ | STATS c = COUNT(*) */ | WHERE x", False),
        ('FROM logs-* | WHERE message == """| STATS c""" ', False),
        ("FROM logs-* | WHERE `x|STATS` == 1", False),
        ("FROM logs-* | EVAL stats = 1", False),
    ],
)
def test_esql_aggregates(query: str, expected: bool) -> None:
    assert esql_aggregates(query) is expected


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("FROM logs-* METADATA _id | WHERE x", True),
        ("FROM logs-* metadata _version, _id", True),
        ("// add METADATA _id later\nFROM logs-* | WHERE x", False),
        ("FROM logs-* /* METADATA _id */ | WHERE x", False),
        ('FROM logs-* | WHERE message == "METADATA _id"', False),
    ],
)
def test_esql_has_metadata_id(query: str, expected: bool) -> None:
    assert esql_has_metadata_id(query) is expected


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("sequence by host.id [process where true] [network where true]", True),
        ("// rare chain\nSEQUENCE with maxspan=5m [a where true] [b where true]", True),
        ('process where process.name : "sequence.exe"', False),
        ('process where process.name : """sequence"""', False),
        ("/* sequence */ process where true", False),
        # Elasticsearch's EQL grammar nests block comments, as ES|QL does.
        ("/* a /* b */ sequence */ process where true", False),
    ],
)
def test_eql_is_sequence(query: str, expected: bool) -> None:
    assert eql_is_sequence(query) is expected


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("sequence with maxspan=500ms [a where true] [b where true]", ("500ms", 500)),
        ("sequence with maxspan=30s [a where true]", ("30s", 30_000)),
        ("sequence with maxspan = 2h [a where true]", ("2h", 7_200_000)),
        ("sequence with maxspan=1d [a where true]", ("1d", 86_400_000)),
        ("sequence with maxspan=5m [a where true]", ("5m", 300_000)),
        ('sequence with maxspan=1m [a where x : "maxspan=1d"] // maxspan=2d', ("1m", 60_000)),
        ("sequence with maxspan=5min [a where true]", None),
        ("sequence [a where true] [b where true]", None),
        ("/* x /* y */ maxspan=1d */ sequence with maxspan=1m [a where true]", ("1m", 60_000)),
    ],
)
def test_eql_maxspan(query: str, expected: tuple[str, int] | None) -> None:
    assert eql_maxspan(query) == expected
