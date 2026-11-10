"""HarfangLab YARA: one kind per block, the signature form, and their codes (harfanglab-1.0 1.2).

The fixtures under ``tests/fixtures/harfanglab`` are copies of the specification
repository's (``fixtures/platforms`` and ``fixtures/invalid``).
"""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.platform import HarfangLabConfig
from opentide.models.platform_configs import HarfangLabYara
from opentide.models.rule import DetectionRule
from opentide.platforms.harfanglab import yara
from opentide.platforms.harfanglab.deployer import HarfangLabDeploy

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "harfanglab"
TENANT: Any = SimpleNamespace(setup=SimpleNamespace(source_id="source-1"))

SIGNATURE = (
    'rule Cmd_String {\n  meta:\n    context = "file"\n'
    '  strings:\n    $a = "cmd.exe"\n  condition:\n    $a\n}\n'
)
DECOMPOSED = {
    "meta": {"context": ["file"], "os": "Windows"},
    "strings": '$a = "cmd.exe" ascii\n',
    "condition": "$a\n",
}
SIGMA = {
    "logsource": {"category": "process_creation", "product": "windows"},
    "selections": [{"name": "selection", "field": "Image", "value": "cmd.exe"}],
    "condition": "selection",
}


def _load(name: str) -> dict[str, Any]:
    return yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))


def _block(**keys: Any) -> dict[str, Any]:
    return {"status": "STAGING", **keys}


def _message(block: dict[str, Any]) -> str:
    with pytest.raises(ValidationError) as caught:
        HarfangLabConfig.model_validate(block)
    return str(caught.value)


def _rule(name: str = "Cmd String", **yara_block: Any) -> dict[str, Any]:
    data = _load("harfanglab-yara.yaml")
    data["name"] = name
    if yara_block:
        data["configurations"]["harfanglab"]["yara"] = yara_block
    return data


# --- the model -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["harfanglab-yara-signature.yaml", "harfanglab-yara.yaml", "harfanglab-sigma.yaml"],
)
def test_the_specification_fixtures_load(name: str) -> None:
    rule = load_rule_from_dict(_load(name))
    assert rule.platform_configs().harfanglab is not None


def test_the_signature_form_keeps_the_text() -> None:
    block = load_rule_from_dict(_load("harfanglab-yara-signature.yaml")).platform_configs()
    assert block.harfanglab is not None and block.harfanglab.yara is not None
    loaded = block.harfanglab.yara
    assert loaded.signature is not None and loaded.signature.startswith('import "pe"\n')
    assert (loaded.meta, loaded.strings, loaded.condition, loaded.imports) == (None,) * 4


@pytest.mark.parametrize(
    ("fixture", "code"),
    [
        ("invalid/rule-harfanglab-sigma-and-yara.yaml", "harfanglab_rule_kind"),
        ("invalid/rule-harfanglab-yara-both-forms.yaml", "harfanglab_yara_form"),
        ("invalid/rule-harfanglab-yara-include.yaml", "yara_include"),
    ],
)
def test_the_specification_invalid_fixtures_fail_with_their_code(fixture: str, code: str) -> None:
    with pytest.raises(ValidationError) as caught:
        DetectionRule.model_validate(_load(fixture))
    assert code in str(caught.value)


@pytest.mark.parametrize(
    ("code", "block"),
    [
        ("harfanglab_rule_kind", _block(sigma=SIGMA, yara={"signature": SIGNATURE})),
        ("harfanglab_rule_kind", _block(sigma=SIGMA, yara=DECOMPOSED)),
        ("harfanglab_yara_form", _block(yara={"signature": SIGNATURE, **DECOMPOSED})),
        ("harfanglab_yara_form", _block(yara={"signature": SIGNATURE, "imports": ["pe"]})),
        # A key written in the block chooses its form, even empty (m4).
        ("harfanglab_yara_form", _block(yara={"signature": SIGNATURE, "imports": None})),
        ("harfanglab_yara_form", _block(yara={"signature": SIGNATURE, "meta": None})),
        ("yara_empty_signature", _block(yara={"signature": None})),
        (
            "harfanglab_yara_section_header",
            _block(yara={**DECOMPOSED, "strings": 'strings:\n  $a = "x"\n'}),
        ),
        (
            "harfanglab_yara_section_header",
            _block(yara={**DECOMPOSED, "condition": "condition:\n  $a\n"}),
        ),
        (
            "harfanglab_yara_section_header",
            _block(yara={**DECOMPOSED, "strings": 'rule inner {\n  $a = "x"\n'}),
        ),
        (
            "harfanglab_yara_section_header",
            _block(yara={**DECOMPOSED, "condition": "$a\nprivate rule x {"}),
        ),
        ("harfanglab_yara_import", _block(yara={**DECOMPOSED, "imports": ["pe", "androguard"]})),
        ("harfanglab_yara_import", _block(yara={**DECOMPOSED, "imports": ["PE"]})),
        ("yara_include", _block(yara={"signature": 'include "a.yar"\n' + SIGNATURE})),
        ("yara_empty_signature", _block(yara={"signature": "  \n"})),
        ("yara_empty_signature", _block(yara={"signature": "// rule commented_out {}\n"})),
        (
            "yara_empty_signature",
            _block(yara={"signature": "private rule a { condition: true }\n"}),
        ),
        (
            "yara_empty_signature",
            _block(yara={"signature": "global rule a { condition: true }\n"}),
        ),
        ("yara_duplicate_rule", _block(yara={"signature": SIGNATURE + SIGNATURE})),
        (
            "yara_duplicate_rule",
            _block(
                yara={"signature": "private rule a { condition: true }\nrule a { condition: true }"}
            ),
        ),
    ],
)
def test_each_code_fails_the_block(code: str, block: dict[str, Any]) -> None:
    assert code in _message(block)


@pytest.mark.parametrize(
    "block",
    [
        _block(),
        _block(sigma=SIGMA),
        _block(yara=DECOMPOSED),
        _block(yara={**DECOMPOSED, "imports": sorted(yara.YARA_MODULES)}),
        _block(yara={"signature": SIGNATURE}),
        # A rule header, include or a duplicate inside a comment or a string is text.
        _block(yara={"signature": '/* include "a.yar"\nrule Cmd_String { */\n' + SIGNATURE}),
        _block(yara={"signature": SIGNATURE.replace('"cmd.exe"', '"rule Cmd_String {"')}),
        _block(yara={"signature": "rule a { condition: #rule in (0..10) }\n"}),
        # A rule written after a closing brace on one line is still read.
        _block(yara={"signature": "rule a { condition: true } rule b { condition: true }"}),
        # A kind set to null is not set.
        _block(sigma=None, yara={"signature": SIGNATURE}),
    ],
)
def test_a_block_of_one_kind_and_one_form_validates(block: dict[str, Any]) -> None:
    assert isinstance(HarfangLabConfig.model_validate(block), HarfangLabConfig)


@pytest.mark.parametrize("missing", ["meta", "strings", "condition"])
def test_the_decomposed_form_still_requires_its_keys(missing: str) -> None:
    keys = {key: value for key, value in DECOMPOSED.items() if key != missing}
    with pytest.raises(ValidationError) as caught:
        HarfangLabYara.model_validate(keys)
    assert f"missing {missing}" in str(caught.value)


def test_the_decomposed_form_still_requires_meta_context_and_os() -> None:
    with pytest.raises(ValidationError):
        HarfangLabYara.model_validate({**DECOMPOSED, "meta": {"os": "Windows"}})
    with pytest.raises(ValidationError):
        HarfangLabYara.model_validate({**DECOMPOSED, "meta": {"context": ["file"]}})


def test_codes_are_reported_together() -> None:
    message = _message(_block(sigma=SIGMA, yara={"signature": 'include "x"\n', **DECOMPOSED}))
    for code in ("harfanglab_rule_kind", "harfanglab_yara_form", "yara_include"):
        assert code in message


@pytest.mark.parametrize(
    "name", ["Condition", "Détection", "rule", "Them", "for", "a" * 129, "1" + "a" * 123]
)
def test_a_decomposed_rule_name_libyara_refuses_fails(name: str) -> None:
    with pytest.raises(ValidationError) as caught:
        DetectionRule.model_validate(_rule(name=name))
    assert "harfanglab_yara_rule_name" in str(caught.value)


@pytest.mark.parametrize(
    "name", ["Cmd String", "2024 loader", "Condition check", "a-b.c", "a" * 128, "1" + "a" * 122]
)
def test_a_decomposed_rule_name_libyara_takes_validates(name: str) -> None:
    assert DetectionRule.model_validate(_rule(name=name)).name == name


def test_the_rule_name_does_not_matter_in_the_signature_form() -> None:
    rule = DetectionRule.model_validate(_rule(name="Détection", signature=SIGNATURE))
    assert rule.name == "Détection"


# --- the YARA scan -------------------------------------------------------------------


def test_the_derived_rule_name_is_the_deployers() -> None:
    assert yara.derived_rule_name("My Rule-Name.v2") == "my_rule_name_v2"
    assert yara.derived_rule_name("2024 Loader") == "rule_2024_loader"
    assert yara.derived_rule_name("Détection") == "détection"


def test_the_signature_is_aliased_only_when_written_as_an_alias() -> None:
    aliased = (FIXTURES / "invalid" / "rule-yara-signature-alias.yaml").read_text(encoding="utf-8")
    assert yara.signature_is_aliased(aliased)
    # The same text, written in the block, with the anchor kept elsewhere.
    written = (FIXTURES / "harfanglab-yara-signature.yaml").read_text(encoding="utf-8")
    assert not yara.signature_is_aliased(written)
    anchored_here = written.replace("signature: |", "signature: &sig |")
    assert not yara.signature_is_aliased(anchored_here + "extra: *sig\n")
    assert not yara.signature_is_aliased("key: [unclosed\n")


@pytest.mark.parametrize(
    "text",
    [
        # An alias of the whole yara mapping (m1).
        "x: &y\n  signature: |\n    rule a { condition: true }\n"
        "configurations:\n  harfanglab:\n    yara: *y\n",
        # An alias of the harfanglab block.
        "x: &h\n  yara:\n    signature: rule a\nconfigurations:\n  harfanglab: *h\n",
        # A merge key brings the signature in.
        "x: &y\n  signature: rule a\nconfigurations:\n  harfanglab:\n    yara:\n      <<: *y\n",
        "x: &y\n  signature: rule a\nconfigurations:\n  harfanglab:\n    yara:\n      <<: [*y]\n",
    ],
    ids=["yara-mapping", "block", "merge", "merge-list"],
)
def test_a_signature_under_an_aliased_node_is_aliased(text: str) -> None:
    assert yaml.safe_load(text)["configurations"]["harfanglab"]
    assert yara.signature_is_aliased(text)


def test_a_merge_key_does_not_alias_a_signature_written_in_place() -> None:
    text = (
        "x: &y\n  signature: rule a\n"
        "configurations:\n  harfanglab:\n    yara:\n      <<: *y\n"
        "      signature: rule b\n"
    )
    assert not yara.signature_is_aliased(text)


#: One signature, written in each scalar style: where lint points the context advisory.
_BODY = 'rule a {\n  meta:\n    context = "disk"\n  condition:\n    true\n}\n'
_BLOCK = "".join(f"        {line}\n" for line in _BODY.splitlines())
_STYLED = {
    "literal": "signature: |\n" + _BLOCK,
    "literal-strip": "signature: |-\n" + _BLOCK,
    "literal-keep": "signature: |+\n\n" + _BLOCK,
    "folded": "signature: >\n" + _BLOCK,
    "folded-strip": "signature: >-\n" + _BLOCK,
    "single": 'signature: \'rule a { meta:\n        context = "disk"\n'
    "        condition: true }'\n",
    "double": 'signature: "rule a { meta:\n        context = \\"disk\\"\n'
    '        condition: true }"\n',
}


@pytest.mark.parametrize("style", list(_STYLED))
def test_the_advisory_line_is_right_in_every_scalar_style(style: str) -> None:
    text = "configurations:\n  harfanglab:\n    yara:\n      " + _STYLED[style]
    site = yara.signature_in(text)
    assert site is not None
    [advisory] = list(yara.advisories(site.value))
    assert advisory.code == "harfanglab_yara_context"
    assert "context" in text.splitlines()[site.line_of(advisory.offset)]


def test_no_signature_is_found_without_one() -> None:
    assert yara.signature_in("configurations:\n  harfanglab:\n    sigma: {}\n") is None
    assert yara.signature_in("key: [unclosed\n") is None


@pytest.mark.parametrize(
    ("signature", "expected"),
    [
        (SIGNATURE, []),
        ('rule a {\n  meta:\n    context = "file.pe"\n  condition:\n    true\n}', []),
        ('rule a {\n  meta:\n    context = "memory"\n  condition:\n    true\n}', []),
        ("private rule a {\n  condition:\n    true\n}\n" + SIGNATURE, []),
        ("rule a {\n  condition:\n    true\n}", ["yara_meta_missing"]),
        ("global rule a {\n  condition:\n    true\n}\n" + SIGNATURE, ["yara_meta_missing"]),
        (
            'rule a {\n  meta:\n    author = "x"\n  strings:\n    $c = "context = \\"file\\""\n'
            "  condition:\n    $c\n}",
            ["yara_meta_missing"],
        ),
        (
            'rule a {\n  meta:\n    context = "disk"\n  condition:\n    true\n}',
            ["harfanglab_yara_context"],
        ),
        (
            'rule a {\n  meta:\n    context = "file, memory"\n  condition:\n    true\n}',
            ["harfanglab_yara_context"],
        ),
        # Any comma-joined list of the five contexts, without blanks (harfanglab-1.0 1.3).
        ('rule a {\n  meta:\n    context = "file.pe,memory"\n  condition:\n    true\n}', []),
        ('rule a {\n  meta:\n    context = "memory,file.elf,file"\n  condition:\n    true\n}', []),
        (
            'rule a {\n  meta:\n    context = "file,"\n  condition:\n    true\n}',
            ["harfanglab_yara_context"],
        ),
        (
            'rule a {\n  meta:\n    context = ""\n  condition:\n    true\n}',
            ["harfanglab_yara_context"],
        ),
        # A context that is not a string is set, and wrong (m2).
        (
            "rule a {\n  meta:\n    context = 1\n  condition:\n    true\n}",
            ["harfanglab_yara_context"],
        ),
        (
            "rule a {\n  meta:\n    context = true\n  condition:\n    true\n}",
            ["harfanglab_yara_context"],
        ),
    ],
)
def test_the_profile_advisories(signature: str, expected: list[str]) -> None:
    assert [advisory.code for advisory in yara.advisories(signature)] == expected


@pytest.mark.parametrize(
    ("signature", "deployed"),
    [
        ("rule a { condition: true }", "rule a { condition: true }\n"),
        ("rule a { condition: true }\n", "rule a { condition: true }\n"),
        # Trailing blank lines are content: sent as written (m6).
        ("rule a { condition: true }\n\n\n", "rule a { condition: true }\n\n\n"),
        ("rule a { condition: true }\r\n\r\n", "rule a { condition: true }\n\n"),
        ("rule a { condition: true }  ", "rule a { condition: true }  \n"),
        ("rule a {\r\n condition: true\r\n}\r\n", "rule a {\n condition: true\n}\n"),
        ("rule a {\r condition: true\r}", "rule a {\n condition: true\n}\n"),
        ("\n// lead\nrule a { condition: true }", "\n// lead\nrule a { condition: true }\n"),
    ],
)
def test_the_deployed_signature_is_verbatim_but_for_line_endings(
    signature: str, deployed: str
) -> None:
    assert yara.deployed_signature(signature) == deployed


# --- deploy --------------------------------------------------------------------------

#: What compile_yara_deployment sent for harfanglab-yara.yaml before the signature form;
#: the decomposed form is unchanged.
DECOMPOSED_CONTENT = """\
import "pe"

rule harfanglab_yara_platform_block {
    meta:
        id = "00000000-0000-4000-8003-000000000018"
        title = "HarfangLab YARA platform block"
        description = "HarfangLab YARA scan rule.\\n"
        author = ""
        date = "2026-01-01"
        modified = "2026-01-02"
        context = "file.pe"
        os = "Windows"
        arch = "x86,x64"
        classification = "trojan"
        score = 70
        confidence = "moderate"
    strings:
        $a = "cmd.exe" ascii
    condition:
        $a
}"""

SIGNATURE_CONTENT = """\
import "pe"

private rule MZ_Header {
  condition:
    uint16(0) == 0x5A4D
}

rule Loader_Stage1 : loader {
  meta:
    description = "Stage-1 loader with an encrypted config blob"
    context = "file,memory"
  strings:
    $cfg = { 43 46 47 21 [4-16] 00 01 }
    $mutex = "Global\\\\qx-7731" ascii wide
  condition:
    MZ_Header and pe.number_of_sections > 3 and all of them
}
"""


def _compiled(data: dict[str, Any]) -> Any:
    return HarfangLabDeploy().compile_yara_deployment(load_rule_from_dict(data), TENANT)


def test_the_decomposed_form_content_is_unchanged() -> None:
    assert _compiled(_load("harfanglab-yara.yaml")).content == DECOMPOSED_CONTENT


def test_the_signature_form_content_is_the_signature() -> None:
    assert _compiled(_load("harfanglab-yara-signature.yaml")).content == SIGNATURE_CONTENT


def test_the_signature_form_adds_and_rewrites_nothing() -> None:
    data = _load("harfanglab-yara-signature.yaml")
    data["configurations"]["harfanglab"]["tags"] = ["attack.execution"]
    data["metadata"]["author"] = "someone"
    content = _compiled(data).content
    assert content == SIGNATURE_CONTENT
    assert "id =" not in content and "score" not in content


@pytest.mark.parametrize(
    "fixture",
    ["harfanglab-yara.yaml", "harfanglab-yara-signature.yaml"],
    ids=["decomposed", "signature"],
)
def test_the_yara_payload(fixture: str, snapshot: Any) -> None:
    """Every payload field but `content` is built the same way for both forms."""
    assert vars(_compiled(_load(fixture))) == snapshot


def test_both_forms_share_the_payload_fields() -> None:
    decomposed = vars(_compiled(_load("harfanglab-yara.yaml")))
    signature = vars(_compiled(_load("harfanglab-yara-signature.yaml")))
    for payload in (decomposed, signature):
        payload.pop("content")
        payload.pop("name")
    assert decomposed == signature


def test_a_signature_deploys_by_metadata_uuid() -> None:
    data = _load("harfanglab-yara-signature.yaml")
    rule = load_rule_from_dict(copy.deepcopy(data))
    service = SimpleNamespace(calls=[])
    service.create_or_update_yara_rule = lambda rule, rule_id: service.calls.append(
        (rule.content, rule_id)
    )
    HarfangLabDeploy().deploy_mdr(data=rule, service=service, tenant_config=TENANT)
    assert service.calls == [(SIGNATURE_CONTENT, data["metadata"]["uuid"])]


@pytest.mark.parametrize(
    ("contexts", "os", "expected"),
    [
        (["file"], "Windows", None),
        (["file", "memory"], "Linux", None),
        (["memory"], "Unknown", None),
        # `file` stays `file` for an OS deploy does not map, which is still a context.
        (["file"], "Solaris", None),
        (["disk"], "Windows", "harfanglab_yara_context"),
        (["file", "disk"], "MacOS", "harfanglab_yara_context"),
        (["file memory"], "Windows", "harfanglab_yara_context"),
        ([], "Windows", "yara_meta_missing"),
        ("file", "Windows", None),  # not a list: the schema check's finding
    ],
)
def test_the_decomposed_context_advisory(contexts: Any, os: str, expected: str | None) -> None:
    """harfanglab-1.0 1.3: the advisory applies to the context the decomposed form deploys."""
    found = yara.decomposed_advisory(contexts, os)
    assert (found[0] if found else None) == expected


def test_the_decomposed_context_is_what_deploy_writes() -> None:
    data = _load("harfanglab-yara.yaml")
    data["configurations"]["harfanglab"]["yara"]["meta"]["context"] = ["file", "memory"]
    content = _compiled(data).content
    assert f'context = "{yara.decomposed_context(["file", "memory"], "Windows")}"' in content


def test_the_decomposed_context_is_found_with_its_line() -> None:
    text = (FIXTURES / "harfanglab-yara.yaml").read_text(encoding="utf-8")
    found = yara.decomposed_context_in(text)
    assert found is not None
    contexts, os, line = found
    assert (contexts, os) == (["file"], "Windows")
    assert "context:" in text.splitlines()[line]
    signature = (FIXTURES / "harfanglab-yara-signature.yaml").read_text(encoding="utf-8")
    assert yara.decomposed_context_in(signature) is None


# --- re-review regressions (R1–R4) ---------------------------------------------------

_REGEXP_RULE = (
    'rule {name} {{\n  meta:\n    context = "file"\n  strings:\n'
    "    $r = /firewall add rule name=/\n  condition:\n    $r\n}}\n"
)


def test_a_rule_header_inside_a_regexp_is_not_a_rule() -> None:
    """R1: `rule name=` in a regexp was read as a rule named `name`."""
    signature = _REGEXP_RULE.format(name="a") + _REGEXP_RULE.format(name="b")
    assert yara.signature_codes(signature) == set()
    assert list(yara.advisories(signature)) == []
    one = (
        'rule a {\n  meta:\n    context = "file"\n  strings:\n'
        "    $r = /advfirewall firewall add rule name=/ nocase\n  condition:\n    $r\n}\n"
    )
    assert list(yara.advisories(one)) == []


def test_an_include_inside_a_regexp_is_not_an_include() -> None:
    signature = (
        'rule a {\n  meta:\n    context = "file"\n  strings:\n'
        '    $r = /include "stdio.h"/\n  condition:\n    $r\n}\n'
    )
    assert yara.signature_codes(signature) == set()


def test_a_regexp_after_matches_is_blanked_and_division_is_not_a_regexp() -> None:
    signature = (
        'rule a {\n  meta:\n    context = "file"\n  condition:\n'
        "    pe.sections[0].name matches /rule b \\/x/ and filesize / 2 > 1\n}\n"
        'rule c {\n  meta:\n    context = "file"\n  condition:\n    filesize / 4 > 2\n}\n'
    )
    assert [header.name for header in yara.rule_headers(signature)] == ["a", "c"]
    assert yara.signature_codes(signature) == set()


def test_an_include_after_a_regexp_is_still_found() -> None:
    signature = (
        'include "x.yar"\nrule a {\n  meta:\n    context = "file"\n  strings:\n'
        "    $r = /a\\/b/\n  condition:\n    $r\n}\n"
    )
    assert yara.signature_codes(signature) == {"yara_include"}


def test_the_alias_check_ignores_unrelated_deep_aliases() -> None:
    """R2: a file of nested aliases elsewhere made the walk exponential (52 s, then OOM)."""
    import time

    lines = ["x-l0: &l0 [" + ", ".join(["x"] * 10) + "]"]
    for level in range(1, 8):
        lines.append(f"x-l{level}: &l{level} [" + ", ".join([f"*l{level - 1}"] * 10) + "]")
    rule = (FIXTURES / "harfanglab-yara-signature.yaml").read_text(encoding="utf-8")
    text = "\n".join(lines) + "\n" + rule
    started = time.perf_counter()
    assert not yara.signature_is_aliased(text)
    assert time.perf_counter() - started < 2
    aliased = text + "other: &sig 'rule x { condition: true }'\n"
    assert not yara.signature_is_aliased(aliased)


def test_a_double_quoted_signature_points_at_its_written_line() -> None:
    """R3: an escaped double-quoted signature reported the advisory on its first line."""
    text = (
        "configurations:\n  harfanglab:\n    yara:\n"
        '      signature: "rule a {\\n  meta:\\n\n'
        "        \n"
        '        \\    context=\\"disk\\"\\n\n'
        '        condition: true }"\n'
    )
    site = yara.signature_in(text)
    assert site is not None
    [advisory] = list(yara.advisories(site.value))
    assert advisory.code == "harfanglab_yara_context"
    assert 'context=\\"disk' in text.splitlines()[site.line_of(advisory.offset)]


@pytest.mark.parametrize(
    "written",
    [
        '"a \\x41\\u0042\\U00000043 b"',
        "'it''s a\n\n  b'",
        "plain words\n  folded  here",
        '"tab\\tand \\\\ slash \\/"',
    ],
)
def test_flow_positions_cover_each_decoded_character(written: str) -> None:
    text = "k: " + written + "\n"
    node = yaml.compose(text).value[0][1]
    positions = yara._flow_positions(
        text, node.start_mark.index, node.end_mark.index, node.style or ""
    )
    assert len(positions) == len(node.value)


def test_a_long_rule_name_names_the_rule_and_the_limit() -> None:
    """R4: the 128-character case read like a keyword or character problem."""
    name = "a" * 140
    with pytest.raises(ValidationError) as caught:
        DetectionRule.model_validate(_rule(name=name))
    message = str(caught.value)
    assert "harfanglab_yara_rule_name" in message
    assert "140 characters long" in message and "at most 128" in message
    assert f"rule {name!r}" in message
    assert "keyword" in yara.rule_name_problem("Condition")
    assert "'é'" in yara.rule_name_problem("Détection")
