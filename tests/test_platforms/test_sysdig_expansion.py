"""Block macros and lists expanded into the Falco condition (sysdig-1.0, Expansion)."""

from __future__ import annotations

import pytest

from opentide.platforms.sysdig.expansion import (
    Expander,
    ExpansionError,
    check_cycles,
    format_item,
    join_lines,
    tokenize,
)


def test_tokens_keep_every_character() -> None:
    text = 'proc.aname[2]="sshd" and fd.name in (/etc/shadow, "a b") or not x!=1'
    assert "".join(token.text for token in tokenize(text)) == text


def test_field_argument_stays_in_its_word() -> None:
    words = [
        t.text for t in tokenize("json.value[/a/b]=x and proc.aname[2] = y") if t.kind == "word"
    ]
    assert words == ["json.value[/a/b]", "x", "and", "proc.aname[2]", "y"]


def test_macro_becomes_its_condition_in_parentheses() -> None:
    expander = Expander({"spawned": "evt.type in (execve, execveat)"})
    assert expander.expand("spawned and container") == (
        "(evt.type in (execve, execveat)) and container"
    )


def test_list_in_a_value_list_becomes_its_items() -> None:
    expander = Expander(lists={"shells": ["bash", "sh"]})
    assert expander.expand("proc.name in (shells, zsh)") == "proc.name in (bash, sh, zsh)"


@pytest.mark.parametrize("operator", ["in", "intersects", "pmatch"])
def test_every_list_operator_expands(operator: str) -> None:
    expander = Expander(lists={"paths": ["/etc", "/bin"]})
    assert expander.expand(f"fd.name {operator} (paths)") == f"fd.name {operator} (/etc, /bin)"


def test_names_the_block_does_not_define_stay_as_written() -> None:
    expander = Expander({"mine": "proc.name = x"}, {"mylist": ["a"]})
    condition = "spawned_process and container and proc.name in (shell_binaries, mylist)"
    assert expander.expand(condition) == (
        "spawned_process and container and proc.name in (shell_binaries, a)"
    )


def test_quoted_strings_and_comparison_values_are_never_expanded() -> None:
    expander = Expander({"nc": "proc.name = netcat"}, {"nc_list": ["x"]})
    condition = 'proc.cmdline contains "nc" and proc.name = nc and proc.args startswith nc'
    assert expander.expand(condition) == condition


def test_a_value_list_without_block_lists_is_left_untouched() -> None:
    expander = Expander(lists={"other": ["a"]})
    condition = "proc.name in (bash,sh ,  zsh)"
    assert expander.expand(condition) == condition


def test_expansion_recurses_through_macros_and_lists() -> None:
    expander = Expander(
        {"grep_commands": "(proc.name in (grep_binaries))", "grep_more": "grep_commands and x"},
        {"grep_binaries": ["grep", "gnu_grep"], "gnu_grep": ["egrep", "fgrep"]},
    )
    assert expander.expand("grep_more") == "(((proc.name in (grep, egrep, fgrep))) and x)"


def test_an_empty_list_drops_out_of_the_value_list() -> None:
    expander = Expander(lists={"none": []})
    assert expander.expand("proc.name in (none, bash)") == "proc.name in (bash)"


def test_multiline_conditions_join_with_single_spaces() -> None:
    assert join_lines("  a\n   and b  \n\n and c\n") == "a and b and c"


@pytest.mark.parametrize(
    ("item", "written"),
    [
        ("bash", "bash"),
        ("a b", '"a b"'),
        ("x,y", '"x,y"'),
        ('"sh -c uname"', '"sh -c uname"'),
        ('say "hi"', '"say \\"hi\\""'),
        (8080, "8080"),
    ],
)
def test_list_items_are_quoted_as_falco_reads_them(item: object, written: str) -> None:
    assert format_item(item) == written


@pytest.mark.parametrize(
    ("macros", "lists"),
    [
        ({"a": "b", "b": "a"}, {}),
        ({"a": "a and x"}, {}),
        ({}, {"l": ["m"], "m": ["l"]}),
        ({"a": "proc.name in (l)"}, {"l": ["l"]}),
    ],
)
def test_a_cycle_is_reported_with_its_code(macros: dict, lists: dict) -> None:
    with pytest.raises(ExpansionError) as caught:
        check_cycles(macros, lists, [])
    assert caught.value.code == "sysdig_definition_cycle"
