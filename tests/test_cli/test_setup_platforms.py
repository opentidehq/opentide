"""Tests for setup platforms command module."""

from __future__ import annotations

import importlib
import shlex
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.platforms import PlatformsSetupOptions, run_platforms_setup
from opentide.platforms.enabled import SYSTEM_KEYS, enable_platform_command


def test_run_platforms_setup_writes_enabled_toml(tmp_path: Path) -> None:
    result = run_platforms_setup(
        PlatformsSetupOptions(path=tmp_path, platforms=[DetectionPlatform.sentinel], yes=True)
    )
    out = tmp_path / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    assert out.is_file()
    assert "enabled = true" in out.read_text(encoding="utf-8")
    assert result["message"] == "Platform configuration files created"


def test_run_platforms_setup_keeps_comments_in_an_existing_file(tmp_path: Path) -> None:
    """#350: a second ``setup platforms`` replaced the file and dropped comments."""
    dest = tmp_path / ".opentide" / "configurations" / "platforms"
    dest.mkdir(parents=True)
    existing = dest / "sentinel.toml"
    existing.write_text(
        "# tenant note\n[platform]\nenabled = false\n# keep this\n",
        encoding="utf-8",
    )
    result = run_platforms_setup(
        PlatformsSetupOptions(path=tmp_path, platforms=[DetectionPlatform.sentinel], yes=True)
    )
    text = existing.read_text(encoding="utf-8")
    assert "# tenant note" in text
    assert "# keep this" in text
    assert "enabled = true" in text
    assert result["message"] == "Platform enabled flags updated"
    assert result["updated"] == [".opentide/configurations/platforms/sentinel.toml"]
    again = run_platforms_setup(
        PlatformsSetupOptions(path=tmp_path, platforms=[DetectionPlatform.sentinel], yes=True)
    )
    assert again["message"] == "Platform configuration files already present"
    assert existing.read_text(encoding="utf-8") == text


def test_run_platforms_setup_requires_platform() -> None:
    with pytest.raises(ValueError, match="Choose at least one platform"):
        run_platforms_setup(PlatformsSetupOptions(platforms=[]))


@pytest.mark.parametrize("system", SYSTEM_KEYS)
def test_enable_advice_is_a_working_setup_platforms_call(system: str, tmp_path: Path) -> None:
    """#414: advice named ``--defender_for_endpoint``, and Elastic had no flag at all."""
    command = enable_platform_command(system)
    assert command.startswith("opentide setup platforms --")
    argv = [*shlex.split(command)[1:], str(tmp_path), "--yes"]
    result = CliRunner().invoke(app, ["--json", *argv])
    assert result.exit_code == 0, result.stdout + result.stderr
    out = tmp_path / ".opentide" / "configurations" / "platforms" / f"{system}.toml"
    assert "enabled = true" in out.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("module", "entry", "system"),
    [
        ("opentide.extraction.mde_importer", "_import_defender_rules", "defender_for_endpoint"),
        ("opentide.extraction.sentinel_importer", "_import_sentinel_rules", "sentinel"),
    ],
    ids=["defender", "sentinel"],
)
def test_importer_tenant_advice_comes_from_the_shared_command(
    module: str, entry: str, system: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The importers spelled the flag by hand, so a renamed flag would not reach them."""
    importer = importlib.import_module(module)
    logged: list[dict[str, object]] = []
    no_tenants = {
        "Configurations.Systems.DefenderForEndpoint.tenants": [],
        "Configurations.Systems.Sentinel.tenants": [],
    }
    monkeypatch.setattr(importer, "Opentide", MagicMock(**no_tenants))
    monkeypatch.setattr(
        importer, "logger", MagicMock(critical=lambda _event, **fields: logged.append(fields))
    )
    monkeypatch.setattr(importer, "enable_platform_command", lambda key: f"setup --renamed-{key}")
    with pytest.raises(RuntimeError, match="tenants"):
        getattr(importer, entry)()
    assert [fields["advice"] for fields in logged] == [f"run 'setup --renamed-{system}'"]
