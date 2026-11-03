"""A Carbon Black Cloud query is checked against Carbon Black's process search
fields (language-server#162): a near miss is `cbc_unknown_field` with the
field as the suggestion, and the same text as Elastic Lucene is not."""

from __future__ import annotations

from opentide.analysis import check_query


def test_a_misspelt_carbon_black_field_is_named_with_the_field() -> None:
    findings = check_query("process_nmae:cmd.exe", language="lucene", platform="carbon_black_cloud")
    unknown = [f for f in findings if f.code == "cbc_unknown_field"]
    assert len(unknown) == 1, findings
    assert unknown[0].suggestion == "process_name"
    assert unknown[0].severity == "warning"


def test_the_right_field_and_elastic_lucene_get_no_such_finding() -> None:
    right = check_query("process_name:cmd.exe", language="lucene", platform="carbon_black_cloud")
    assert not [f for f in right if f.code == "cbc_unknown_field"]
    elastic = check_query("process_nmae:cmd.exe", language="lucene", platform="elastic")
    assert not [f for f in elastic if f.code == "cbc_unknown_field"]
