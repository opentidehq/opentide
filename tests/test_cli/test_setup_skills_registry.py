"""Tests for bundled and remote skills catalogue helpers."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from opentide.cli.services.setup import skills_registry as registry


@pytest.fixture(autouse=True)
def _clear_manifest_cache() -> None:
    registry.load_manifest.cache_clear()
    yield
    registry.load_manifest.cache_clear()


def test_load_manifest_reads_bundle() -> None:
    source, ref, entries = registry.load_manifest()
    assert source == "OpenTideHQ/skills"
    assert ref
    assert entries
    assert all(entry.slug for entry in entries)


def test_skill_entry_to_dict() -> None:
    entry = registry.SkillEntry(name="Demo", slug="demo", description="Example skill")
    payload = entry.to_dict(installed=True)
    assert payload == {
        "name": "Demo",
        "slug": "demo",
        "description": "Example skill",
        "installed": True,
        "path": ".agents/skills/demo/",
    }


def test_discover_skills_filters_by_query(tmp_path: Path) -> None:
    result = registry.discover_skills(tmp_path, query="detection-engineering")
    assert result["count"] == 1
    assert result["skills"][0]["slug"] == "detection-engineering"


def test_discover_skills_installed_only(tmp_path: Path) -> None:
    installed = tmp_path / ".agents" / "skills" / "detection-engineering"
    installed.mkdir(parents=True)
    (installed / "SKILL.md").write_text("# detection-engineering\n", encoding="utf-8")
    result = registry.discover_skills(tmp_path, installed_only=True)
    assert result["count"] >= 1
    assert all(skill["installed"] for skill in result["skills"])


def test_show_skill_found_and_missing(tmp_path: Path) -> None:
    found = registry.show_skill(tmp_path, "detection-engineering")
    assert found["skill"]["slug"] == "detection-engineering"
    assert "install_hint" in found

    missing = registry.show_skill(tmp_path, "no-such-skill-xyz")
    assert "error" in missing


def test_load_manifest_refresh_falls_back_on_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom() -> tuple[str, str, list[registry.SkillEntry]]:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(registry, "_fetch_remote_manifest", _boom)
    source, ref, entries = registry.load_manifest(refresh=True)
    assert source == "OpenTideHQ/skills"
    assert entries


def test_parse_manifest_skips_invalid_skill_rows() -> None:
    source, ref, entries = registry._parse_manifest(
        {
            "source": "OpenTideHQ/skills",
            "ref": "main",
            "skills": [{"slug": "valid", "name": "Valid", "description": "ok"}, "bad", {}],
        }
    )
    assert source == "OpenTideHQ/skills"
    assert ref == "main"
    assert [e.slug for e in entries] == ["valid"]


def test_fetch_remote_manifest_parses_frontmatter(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = json.loads(registry._MANIFEST_PATH.read_text(encoding="utf-8"))
    slug = manifest["skills"][0]["slug"]
    body = "---\nname: Remote Name\ndescription: Remote description\n---\n# body\n"

    class _Response:
        def read(self) -> bytes:
            return body.encode("utf-8")

    monkeypatch.setattr(registry.urllib.request, "urlopen", lambda *a, **k: _Response())
    source, ref, entries = registry._fetch_remote_manifest()
    assert source == "OpenTideHQ/skills"
    match = next(e for e in entries if e.slug == slug)
    assert match.name == "Remote Name"
    assert match.description == "Remote description"
