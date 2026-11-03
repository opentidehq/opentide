"""Platform configuration files the configuration check accepts never crash a command (#736).

- A third-party `platforms/<id>.toml` (a plugin's platform) has no rule block in
  opentide: `validate`, schema generation and the editor's catalog skip it.
- `[tide]` is not a platform table: CoreTIDE's identity table is gone, so it is an
  unknown key, never read for a platform's name, identifier or `enabled`.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from opentide.analysis import own_catalog
from opentide.cli import app
from opentide.validation.configuration import configuration_text_issues


def _workspace(root: Path, files: dict[str, str]) -> Path:
    (root / "objects").mkdir(parents=True)
    platforms = root / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    for name, text in files.items():
        (platforms / name).write_text(text, encoding="utf-8")
    return root


def _validate(repo: Path) -> dict[str, object]:
    result = CliRunner().invoke(
        app,
        ["--json", "--repo", str(repo), "validate"],
        env={"OPENTIDE_REPO_ROOT": str(repo), "OPENTIDE_TIDE_WORKSPACE": None},
    )
    assert "Traceback" not in result.output, result.output
    assert "error[internal]" not in result.output, result.output
    return json.loads(result.stdout)


def test_a_third_party_platform_file_does_not_crash_validate(tmp_path: Path) -> None:
    repo = _workspace(tmp_path, {"acme.toml": "[platform]\nenabled = true\n"})
    document = _validate(repo)
    assert "failure" not in document or not document["failure"], document


def test_a_third_party_platform_file_does_not_stop_the_editor_catalog(tmp_path: Path) -> None:
    repo = _workspace(tmp_path, {"acme.toml": "[platform]\nenabled = true\n"})
    catalogs = own_catalog(repo)
    assert "fields.json" in catalogs


def test_a_tide_table_is_an_unknown_key_and_is_not_read(tmp_path: Path) -> None:
    text = "[tide]\nenabled = true\n"
    repo = _workspace(tmp_path, {"sentinel.toml": text})
    # The editor's catalog generates: `[tide]` does not enable Sentinel.
    catalogs = own_catalog(repo)
    assert "fields.json" in catalogs
    issues = configuration_text_issues(
        repo / ".opentide" / "configurations" / "platforms" / "sentinel.toml", text
    )
    assert [(issue.code, issue.field_path) for issue in issues] == [("unknown_key", ("tide",))]
