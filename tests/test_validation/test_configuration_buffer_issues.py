"""`configuration_buffer_issues`: what the editor shows for a configuration buffer (#730).

The language server's configuration checker. It adds the layers an editor
has to `configuration_text_issues`: the parent instance, an open
`deployment.toml`, and the `configurations/sharing/` directory.
"""

from __future__ import annotations

from pathlib import Path

from opentide.validation.configuration import configuration_buffer_issues

COMPLETE_BLOCK = """\
[[misp]]
name = "misp-lab"
url = "https://misp.example"
api_key = "${MISP_KEY}"
max_tlp = "amber"
"""


def _configurations(root: Path) -> Path:
    directory = root / ".opentide" / "configurations"
    directory.mkdir(parents=True)
    return directory


def _codes(path: Path, text: str, open_buffers: list[tuple[str, str]] | None = None) -> list[str]:
    issues = configuration_buffer_issues(str(path), text, open_buffers or [])
    return [issue.code for issue in issues]


def test_a_complete_block_is_clean(tmp_path: Path) -> None:
    sharing = _configurations(tmp_path) / "sharing.toml"
    assert _codes(sharing, COMPLETE_BLOCK) == []


def test_the_parent_instance_completes_a_partial_override(tmp_path: Path) -> None:
    parent = _configurations(tmp_path)
    (parent / "sharing.toml").write_text(COMPLETE_BLOCK, encoding="utf-8")
    inner = _configurations(tmp_path / "inner")
    override = '[[misp]]\nname = "misp-lab"\nenabled = true\n'

    assert _codes(inner / "sharing.toml", override) == []
    # The same two keys where no parent instance holds the block: the
    # required keys are missing. (`a/b`'s parent, `a`, has no `.opentide`.)
    alone = _codes(tmp_path / "a" / "b" / ".opentide" / "configurations" / "sharing.toml", override)
    assert alone.count("missing_field") == 3


def test_an_open_deployment_buffer_decides_the_statuses(tmp_path: Path) -> None:
    configurations = _configurations(tmp_path)
    sharing = configurations / "sharing.toml"
    text = COMPLETE_BLOCK + 'rule_statuses = ["CANARY"]\n'
    assert "rule_status_unknown" in _codes(sharing, text)

    deployment = (str(configurations / "deployment.toml"), '[[statuses]]\nname = "CANARY"\n')
    assert _codes(sharing, text, [deployment]) == []
    # An open buffer that is not TOML yet: the file on disk decides.
    broken = (str(configurations / "deployment.toml"), "[[statuses]\n")
    assert "rule_status_unknown" in _codes(sharing, text, [broken])


def test_a_sharing_directory_is_reported_on_sharing_toml(tmp_path: Path) -> None:
    configurations = _configurations(tmp_path)
    (configurations / "sharing").mkdir()
    assert _codes(configurations / "sharing.toml", COMPLETE_BLOCK) == ["sharing_directory"]


def test_a_literal_api_key_is_a_warning_that_does_not_repeat_it(tmp_path: Path) -> None:
    sharing = _configurations(tmp_path) / "sharing.toml"
    text = COMPLETE_BLOCK.replace("${MISP_KEY}", "literal-secret")
    issues = configuration_buffer_issues(str(sharing), text)
    assert [(issue.code, issue.severity) for issue in issues] == [("api_key_literal", "warning")]
    assert "literal-secret" not in issues[0].message


def test_a_file_without_a_model_gets_nothing(tmp_path: Path) -> None:
    configurations = _configurations(tmp_path)
    assert _codes(configurations / "resources.toml", "x = 1\n") == []
    assert _codes(configurations / "lint.toml", "x = 1\n") == []
