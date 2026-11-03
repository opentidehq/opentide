"""Block macros and lists expanded as Falco's rule loader does (sysdig-1.0, Expansion).

``resolve_list`` cases follow ``falcosecurity/falco`` ``userspace/engine/rule_loader_compiler.cpp``.
"""

from __future__ import annotations

from typing import Any

import pytest

from opentide.platforms.sysdig.expansion import (
    Expander,
    ExpansionError,
    check_definitions,
    is_exception_operator,
    is_list_comparison,
    is_modified_operator,
    join_lines,
    normalize_comp,
    quote_item,
    resolve_list,
    substitute_macros,
    tokenize,
)

# --- resolve_list, ported from Falco --------------------------------------------------------


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        # a delimiter on each side: ( ) , = blank, start, end
        ("proc.name in (shells)", "proc.name in ( bash, sh )"),
        ("proc.name in (shells, zsh)", "proc.name in ( bash, sh , zsh)"),
        ("proc.name in (zsh,shells)", "proc.name in (zsh, bash, sh )"),
        ("x = shells", "x = bash, sh "),
        ("x=shells", "x= bash, sh "),
        ("shells", "bash, sh "),
        ("shells and y", "bash, sh and y"),
        ("proc.name in (zsh,\tshells\n)", "proc.name in (zsh, bash, sh )"),
        # a name inside another identifier is not an occurrence
        ("myshells = 1 and shells_x = 2", "myshells = 1 and shells_x = 2"),
        ("proc.name in (myshells, shells)", "proc.name in (myshells, bash, sh )"),
        # inside a quoted string, Falco replaces a delimited occurrence too
        ('proc.cmdline contains "run shells now"', 'proc.cmdline contains "run bash, sh now"'),
        ('proc.cmdline contains "shells"', 'proc.cmdline contains "shells"'),
    ],
)
def test_resolve_list_follows_falco(condition: str, expected: str) -> None:
    assert resolve_list(condition, "shells", ["bash", "sh"]) == (
        expected,
        condition != expected,
    )


def test_resolve_list_replaces_every_occurrence() -> None:
    text, used = resolve_list("a in (l) or b in (l)", "l", ["x"])
    assert (text, used) == ("a in ( x ) or b in ( x )", True)


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("proc.name in (bash, none)", "proc.name in (bash  )"),
        ("proc.name in (none, bash)", "proc.name in (   bash)"),
        ("proc.name in (none)", "proc.name in (  )"),
        ("proc.name in (a, none, b)", "proc.name in (a  , b)"),
    ],
)
def test_an_empty_list_removes_one_comma_left_first(condition: str, expected: str) -> None:
    assert resolve_list(condition, "none", [])[0] == expected


@pytest.mark.parametrize(
    ("item", "quoted"),
    [
        ("bash", "bash"),
        ("a b", '"a b"'),
        ('"sh -c uname"', '"sh -c uname"'),
        ("'sh -c uname'", "'sh -c uname'"),
        ("x,y", "x,y"),  # Falco quotes on a space only
        ("tab\there", "tab\there"),
    ],
)
def test_quote_item_quotes_a_space_only(item: str, quoted: str) -> None:
    assert quote_item(item) == quoted


def test_items_with_spaces_are_quoted_in_the_condition() -> None:
    expander = Expander(lists={"cmds": ["sh -c uname", "'already quoted'", "id"]})
    assert expander.expand("proc.cmdline in (cmds)") == (
        "proc.cmdline in ( \"sh -c uname\", 'already quoted', id )"
    )


# --- lists: flattening and definition order --------------------------------------------------


def test_an_item_naming_an_earlier_list_is_flattened() -> None:
    expander = Expander(lists={"gnu": ["egrep", "fgrep"], "greps": ["grep", "gnu"]})
    assert expander.lists["greps"] == ["grep", "egrep", "fgrep"]
    assert expander.expand("proc.name in (greps)") == "proc.name in ( grep, egrep, fgrep )"


def test_a_list_naming_a_later_list_expands_in_the_later_pass() -> None:
    """Falco 0.45.2: compile_list_infos keeps `l2` as written, then resolve_list runs for
    l1 and l2 in turn over the condition, so l2's pass expands it."""
    expander = Expander(lists={"l1": ["l2", "bash"], "l2": ["zsh", "fish"]})
    assert expander.lists["l1"] == ["l2", "bash"]
    assert expander.expand("proc.name in (l1)") == "proc.name in ( zsh, fish , bash )"
    assert expander.self_references() == []


def test_a_list_naming_itself_keeps_its_name_as_a_literal() -> None:
    """resolve_list never re-scans what it just inserted."""
    expander = Expander(lists={"l1": ["bash", "l1"]})
    assert expander.expand("proc.name in (l1)") == "proc.name in ( bash, l1 )"
    assert expander.self_references() == ["l1"]


def test_exception_values_follow_the_same_passes() -> None:
    forward = Expander(lists={"l1": ["l2", "bash"], "l2": ["zsh", "fish"]})
    assert forward.exception({"name": "e", "fields": "proc.name", "values": ["l1", "sh"]})[
        "values"
    ] == ["zsh", "fish", "bash", "sh"]
    own = Expander(lists={"l1": ["bash", "l1"]})
    out = own.exception(
        {"name": "e", "fields": ["proc.name"], "comps": ["in"], "values": [["l1"], [["l1", "x"]]]}
    )
    assert out["values"] == [[["bash", "l1"]], [["bash", "l1", "x"]]]


def test_numbers_are_items_as_written() -> None:
    expander = Expander(lists={"ports": [22, 2222]})
    assert expander.expand("fd.sport in (ports)") == "fd.sport in ( 22, 2222 )"


# --- macros ----------------------------------------------------------------------------------


def test_macro_becomes_its_condition_in_parentheses() -> None:
    expander = Expander({"spawned": "evt.type in (execve, execveat)"})
    assert expander.expand("spawned and container") == (
        "(evt.type in (execve, execveat)) and container"
    )


def test_a_macro_sees_earlier_macros_and_every_list() -> None:
    expander = Expander(
        {"grep_commands": "(proc.name in (greps))", "grep_more": "grep_commands and x"},
        {"gnu": ["egrep", "fgrep"], "greps": ["grep", "gnu"]},
    )
    assert expander.expand("grep_more") == "(((proc.name in ( grep, egrep, fgrep ))) and x)"


@pytest.mark.parametrize(
    "macros",
    [
        {"a": "b and x.y = 1", "b": "x.z = 2"},  # a later macro
        {"a": "a and x.y = 1"},  # itself
        {"a": "not (x.y = 1 or a)"},
    ],
)
def test_a_macro_using_itself_or_a_later_macro_is_out_of_order(macros: dict[str, str]) -> None:
    with pytest.raises(ExpansionError) as caught:
        Expander(macros)
    assert caught.value.code == "sysdig_definition_order"


@pytest.mark.parametrize(
    "condition",
    [
        "proc.name = nc",
        "proc.args startswith nc",
        "proc.name in (nc, ncat)",
        "proc.name startswith oneof (nc, x)",
        'proc.cmdline contains "nc"',
        "tolower(proc.name) = nc",
        "proc.pname = val(nc.field)",
        "proc.aname[nc] = x",
        "proc.name exists and not nc_other",
    ],
)
def test_values_fields_and_strings_are_not_macro_positions(condition: str) -> None:
    assert Expander({"nc": "proc.name = netcat"}).expand(condition) == condition


def test_macros_in_check_positions_after_not_and_parentheses() -> None:
    expander = Expander({"m": "x.y = 1"})
    assert expander.expand("not m and (m or not(m))") == (
        "not (x.y = 1) and ((x.y = 1) or not((x.y = 1)))"
    )


def test_names_the_block_does_not_define_stay_as_written() -> None:
    expander = Expander({"mine": "proc.name = x"}, {"mylist": ["a"]})
    condition = "spawned_process and container and proc.name in (shell_binaries, mylist)"
    assert expander.expand(condition) == (
        "spawned_process and container and proc.name in (shell_binaries, a )"
    )


def test_substitute_keeps_every_character() -> None:
    text = 'proc.aname[2]="sshd" and fd.name in (/etc/shadow, "a b") or not x!=1'
    assert substitute_macros(text, lambda name: None) == text
    assert "".join(token.text for token in tokenize(text)) == text


def test_multiline_conditions_join_with_single_spaces() -> None:
    assert join_lines("  a\n   and b  \n\n and c\n") == "a and b and c"


# --- exceptions ------------------------------------------------------------------------------

LISTS = {"shells": ["bash", "sh"], "none": []}


def _exception(entry: dict[str, Any]) -> dict[str, Any]:
    return Expander(lists=LISTS).exception({"name": "e", **entry})


def test_a_single_field_value_naming_a_list_is_spliced() -> None:
    assert _exception({"fields": "proc.name", "values": ["shells", "zsh", "none"]}) == {
        "name": "e",
        "fields": "proc.name",
        "values": ["bash", "sh", "zsh"],
    }


def test_a_value_list_member_naming_a_list_is_spliced() -> None:
    out = _exception(
        {
            "fields": ["proc.name", "proc.pname"],
            "comps": ["in", "="],
            "values": [[["shells", "zsh"], "x"]],
        }
    )
    assert out["values"] == [[["bash", "sh", "zsh"], "x"]]


@pytest.mark.parametrize("comp", ["in", "pmatch", "intersects", "startswith oneof", " in "])
def test_a_single_value_list_name_under_a_list_comparison_is_the_value_list(comp: str) -> None:
    out = _exception({"fields": ["proc.name"], "comps": [comp], "values": [["shells"]]})
    assert out["comps"] == [comp.strip()]
    assert out["values"] == [[["bash", "sh"]]]


@pytest.mark.parametrize(
    "entry",
    [
        {"fields": ["proc.name"], "comps": ["="], "values": [["shells"]]},
        {"fields": ["proc.name"], "values": [["shells"]]},
        {"fields": ["proc.cmdline"], "comps": ["contains"], "values": [["run shells"]]},
        {"fields": ["proc.name"], "comps": ["in"], "values": [[["x", "a shells"]]]},
        {"fields": "proc.cmdline", "values": ["run shells"]},
        {"fields": "proc.cmdline", "values": ["shells=1"]},
    ],
)
def test_a_list_name_anywhere_else_in_a_value_is_refused(entry: dict[str, Any]) -> None:
    with pytest.raises(ExpansionError) as caught:
        _exception(entry)
    assert caught.value.code == "sysdig_list_in_value"


def test_values_without_list_names_are_sent_as_written() -> None:
    entry = {"fields": ["proc.name", "fd.sport"], "comps": ["in", ">"], "values": [["sh", 22]]}
    assert _exception(entry)["values"] == [["sh", 22]]
    assert _exception({"fields": ["x.y"], "values": [["myshells"]]})["values"] == [["myshells"]]


def test_check_definitions_reports_the_first_code() -> None:
    with pytest.raises(ExpansionError) as caught:
        check_definitions(
            {}, LISTS, ["x.y = 1"], [{"name": "e", "fields": "x.y", "values": ["a shells"]}]
        )
    assert caught.value.code == "sysdig_list_in_value"


# --- operators ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("op", "modified"),
    [
        ("startswith oneof", True),
        ("= anyof", True),
        ("== allof", True),
        ("regex oneof", True),
        ("in oneof", False),
        ("< anyof", False),
        ("startswith  oneof", False),
        ("startswith someof", False),
        ("startswith", False),
    ],
)
def test_modified_operators_follow_str_to_cmpop_with_modifier(op: str, modified: bool) -> None:
    assert is_modified_operator(op) is modified


@pytest.mark.parametrize(
    "op",
    ["exists", "<", "<=", ">", ">=", "=", "==", "!=", "bcontains", "iglob", "regex", "intersects"],
)
def test_every_falco_operator_is_an_exception_operator(op: str) -> None:
    assert is_exception_operator(op)


def test_list_comparisons_and_normalization() -> None:
    assert is_list_comparison("pmatch")
    assert is_list_comparison("contains allof")
    assert not is_list_comparison("contains")
    assert normalize_comp(" \tin\n") == "in"
