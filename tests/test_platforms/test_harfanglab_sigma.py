"""The Sigma rule HarfangLab receives is valid YAML that reads back as the rule."""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from opentide.platforms.harfanglab.client import SigmaRuleBuilder

RULE_ID = "00000000-0000-4000-8000-000000000001"


def _build(title: str = "Rule", description: str = "Detects it", value: Any = "x") -> str:
    return SigmaRuleBuilder.build_sigma_yaml(
        title=title,
        description=description,
        rule_id=RULE_ID,
        logsource_category="process_creation",
        logsource_product="windows",
        selections=[
            {"name": "selection", "field": "CommandLine", "modifiers": ["contains"], "value": value}
        ],
        condition="selection",
    )


@pytest.mark.parametrize(
    "title", ["Mimikatz: sekurlsa", "Rule # 2", "'quoted'", "- dash", "yes", "[bracketed]"]
)
def test_any_title_reads_back(title: str) -> None:
    """``title: Mimikatz: sekurlsa`` was invalid YAML; HarfangLab refused the rule."""
    assert yaml.safe_load(_build(title=title))["title"] == title


@pytest.mark.parametrize(
    "value",
    [
        "IEX (New-Object Net.WebClient).DownloadString('http",
        "yes",
        "no",
        "null",
        "42",
        "C:\\Windows\\",
        "a: b",
        "-enc",
        ["it's", "yes", "*.ps1"],
        True,
        7,
    ],
)
def test_any_value_reads_back_as_itself(value: Any) -> None:
    """A single quote inside a quoted value broke the YAML; ``yes`` read as ``True``."""
    detection = yaml.safe_load(_build(value=value))["detection"]
    assert detection["selection"]["CommandLine|contains"] == value


def test_a_multi_line_description_reads_back() -> None:
    description = "First line: with a colon\n  indented second line\n"
    assert yaml.safe_load(_build(description=description))["description"] == description


def test_the_rule_keeps_the_sigma_layout() -> None:
    text = SigmaRuleBuilder.build_sigma_yaml(
        title="Suspicious cmd",
        description="Line one\nLine two\n",
        rule_id=RULE_ID,
        logsource_category="process_creation",
        logsource_product="windows",
        selections=[
            {
                "name": "selection",
                "field": "Image",
                "modifiers": ["endswith"],
                "value": "\\cmd.exe",
            },
            {"name": "selection", "field": "CommandLine", "value": ["/c", "/k"]},
            {"name": "filter", "field": "User", "modifiers": [], "value": "SYSTEM"},
        ],
        condition="selection and not filter",
        level="high",
        status="stable",
        tags=["attack.t1059"],
        false_positives=["Admin scripts"],
        author="detection@example.test",
    )
    assert text == (
        "title: Suspicious cmd\n"
        f"id: {RULE_ID}\n"
        "description: |\n"
        "    Line one\n"
        "    Line two\n"
        "author: detection@example.test\n"
        "status: stable\n"
        "tags:\n"
        "    - attack.t1059\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    selection:\n"
        "        Image|endswith: \\cmd.exe\n"
        "        CommandLine:\n"
        "            - /c\n"
        "            - /k\n"
        "    filter:\n"
        "        User: SYSTEM\n"
        "    condition: selection and not filter\n"
        "falsepositives:\n"
        "    - Admin scripts\n"
        "level: high\n"
    )
