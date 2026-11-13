"""CLI E2E: setup skills discover/show are subcommands, not a PATH."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json, stub_remote_skills_manifest

pytestmark = pytest.mark.cli_e2e


@pytest.fixture(autouse=True)
def _remote_skills_catalogue(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_remote_skills_manifest(monkeypatch)
    yield


def test_skills_discover_json(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli("setup", "skills", "discover", "--path", str(tide_corpus_repo))
    payload = assert_json_ok(result)
    assert payload["count"] >= 1
    slugs = {item["slug"] for item in payload["skills"]}
    assert "opentide-detection-rule" in slugs
    assert "detection-engineering" in slugs
    assert payload["manifest_source"] == "remote"


def test_skills_discover_human_table(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli(
        "setup",
        "skills",
        "discover",
        "--path",
        str(tide_corpus_repo),
        json_output=False,
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    combined = result.stdout + result.stderr
    assert "DEPRECATED" not in combined
    assert "opentide-detection-rule" in combined or "opentide Skills" in combined


def test_skills_show_json(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli(
        "setup",
        "skills",
        "show",
        "opentide-detection-rule",
        "--path",
        str(tide_corpus_repo),
    )
    payload = assert_json_ok(result)
    assert payload["skill"]["slug"] == "opentide-detection-rule"


_CATALOGUE_COPY = (
    b"---\nname: detection-engineering\ndescription: catalogue copy\n---\n# catalogue\n"
)


def test_skills_install_uses_packaged_authoring_and_agents_template(
    invoke_cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#399/#405: reference-only downloads and the skills-repo AGENTS.md are gone.

    ``detection-engineering`` installs the catalogue's copy (the one ``discover``
    describes). ``opentide-detection-rule`` comes from the package even though this
    catalogue lists it. The catalogue is a stub: whether its live content is free of
    retired identifiers is checked in opentidehq/skills' own CI.
    """
    from opentide.cli.services.setup import skills as skills_mod

    fetched: list[str] = []
    monkeypatch.setattr(skills_mod, "list_github_paths", lambda prefix, **_: [f"{prefix}/SKILL.md"])

    def _fetch(path: str, **_: object) -> bytes:
        fetched.append(path)
        return _CATALOGUE_COPY

    monkeypatch.setattr(skills_mod, "fetch_github_bytes", _fetch)
    result = invoke_cli(
        "setup",
        "skills",
        "--generic",
        "--yes",
        "--name",
        "SOC Detections",
        "--install",
        "detection-engineering",
        "--install",
        "opentide-detection-rule",
        "--path",
        str(tmp_path),
        repo=tmp_path,
    )
    payload = assert_json_ok(result)
    assert payload["skills"] == ["detection-engineering", "opentide-detection-rule"]
    assert "warnings" not in payload
    assert fetched == ["skills/detection-engineering/SKILL.md"]
    engineering = (
        tmp_path / ".agents" / "skills" / "detection-engineering" / "SKILL.md"
    ).read_bytes()
    rule = (tmp_path / ".agents" / "skills" / "opentide-detection-rule" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    agents = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert engineering == _CATALOGUE_COPY
    assert rule.startswith("---\nname: opentide-detection-rule\n")
    assert "objects/rules/" in rule
    assert "mdr::" not in rule
    assert "Schemas/Templates" not in rule
    assert "Configurations/systems" not in rule
    assert "SOC Detections" in agents
    assert "# remote agents" not in agents


def test_skills_show_missing_json(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli(
        "setup",
        "skills",
        "show",
        "no-such-skill-xyz",
        "--path",
        str(tide_corpus_repo),
    )
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert payload.get("ok") is False
    assert "error" in payload
