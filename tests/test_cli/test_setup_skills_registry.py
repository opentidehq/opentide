"""Tests for bundled and remote skills catalogue helpers."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from opentide.cli.services.setup import skills_registry as registry


@pytest.fixture(autouse=True)
def _clear_manifest_cache() -> None:
    registry.clear_manifest_cache()
    yield
    registry.clear_manifest_cache()


def test_load_manifest_reads_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    infos: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        registry.logger,
        "info",
        lambda event, **kwargs: infos.append((event, kwargs)),
    )
    warnings: list[str] = []
    monkeypatch.setattr(
        registry.logger,
        "warning",
        lambda event, **kwargs: warnings.append(str(event)),
    )
    manifest = registry.load_manifest()
    assert manifest.source == "OpenTideHQ/skills"
    assert manifest.ref
    assert manifest.entries
    assert all(entry.slug for entry in manifest.entries)
    assert manifest.manifest_source == "bundled"
    assert infos
    assert infos[0][0] == "skills_manifest_remote_unavailable"
    assert warnings == []


def test_load_manifest_remote_first(monkeypatch: pytest.MonkeyPatch) -> None:
    remote_entries = [
        registry.SkillEntry(name="Remote", slug="remote-skill", description="from github")
    ]

    def _remote(**_: object) -> tuple[str, str, list[registry.SkillEntry]]:
        return "OpenTideHQ/skills", "feature-branch", remote_entries

    monkeypatch.setattr(registry, "_fetch_remote_manifest", _remote)
    manifest = registry.load_manifest()
    assert manifest.manifest_source == "remote"
    assert manifest.ref == "feature-branch"
    assert [e.slug for e in manifest.entries] == ["remote-skill"]


def test_load_manifest_refresh_success(monkeypatch: pytest.MonkeyPatch) -> None:
    remote_entries = [registry.SkillEntry(name="Fresh", slug="fresh", description="new")]

    def _remote(**_: object) -> tuple[str, str, list[registry.SkillEntry]]:
        return "OpenTideHQ/skills", "main", remote_entries

    monkeypatch.setattr(registry, "_fetch_remote_manifest", _remote)
    manifest = registry.load_manifest(refresh=True)
    assert manifest.manifest_source == "remote"
    assert manifest.manifest_refreshed is True


def test_load_manifest_refresh_falls_back_on_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    manifest = registry.load_manifest(refresh=True)
    assert manifest.manifest_source == "bundled"
    assert manifest.manifest_refreshed is False
    assert manifest.entries
    # Failed refresh must replace TTL cache so follow-up calls match the fallback.
    cached = registry.load_manifest()
    assert cached.manifest_source == "bundled"
    assert [e.slug for e in cached.entries] == [e.slug for e in manifest.entries]


def test_parse_manifest_rejects_foreign_source() -> None:
    source, ref, entries = registry._parse_manifest(
        {
            "source": "evil/skills",
            "ref": "main",
            "skills": [{"slug": "x", "name": "X", "description": ""}],
        }
    )
    assert source == "OpenTideHQ/skills"
    assert ref == "main"
    assert [e.slug for e in entries] == ["x"]


def test_manifest_ttl_cache_avoids_double_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def _remote(**_: object) -> tuple[str, str, list[registry.SkillEntry]]:
        nonlocal calls
        calls += 1
        return (
            "OpenTideHQ/skills",
            "main",
            [registry.SkillEntry(name="One", slug="one", description="")],
        )

    monkeypatch.setattr(registry, "_fetch_remote_manifest", _remote)
    registry.load_manifest()
    registry.load_manifest()
    assert calls == 1


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


def test_discover_skills_filters_by_query(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    entries = [
        registry.SkillEntry(name="Alpha", slug="alpha", description="first skill"),
        registry.SkillEntry(name="Beta", slug="beta", description="second skill"),
    ]
    monkeypatch.setattr(
        registry,
        "load_manifest",
        lambda **_: registry.ManifestLoadResult(
            source="OpenTideHQ/skills",
            ref="main",
            entries=entries,
            manifest_source="bundled",
            manifest_refreshed=False,
        ),
    )
    result = registry.discover_skills(tmp_path, query="alpha")
    assert result["count"] == 1
    assert result["skills"][0]["slug"] == "alpha"
    assert result["manifest_source"] == "bundled"
    assert result["manifest_refreshed"] is False


def test_discover_skills_installed_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    installed = tmp_path / ".agents" / "skills" / "detection-engineering"
    installed.mkdir(parents=True)
    (installed / "SKILL.md").write_text("# detection-engineering\n", encoding="utf-8")
    result = registry.discover_skills(tmp_path, installed_only=True)
    assert result["count"] >= 1
    assert all(skill["installed"] for skill in result["skills"])


def test_show_skill_found_and_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    found = registry.show_skill(tmp_path, "detection-engineering")
    assert found["skill"]["slug"] == "detection-engineering"
    assert "install_hint" in found
    assert found["manifest_source"] == "bundled"

    missing = registry.show_skill(tmp_path, "no-such-skill-xyz")
    assert "error" in missing


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


def test_fetch_remote_manifest_parses_json(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "source": "OpenTideHQ/skills",
        "ref": "release-1",
        "skills": [{"slug": "alpha", "name": "Alpha", "description": "first"}],
    }

    monkeypatch.setattr(
        registry,
        "fetch_github_bytes",
        lambda path, **_: json.dumps(payload).encode("utf-8") if path == "manifest.json" else None,
    )
    result = registry._fetch_remote_manifest()
    assert result is not None
    source, ref, entries = result
    assert source == "OpenTideHQ/skills"
    assert ref == "release-1"
    assert entries[0].slug == "alpha"


def test_bundled_skill_dir_rejects_path_segments() -> None:
    assert registry.bundled_skill_dir("") is None
    assert registry.bundled_skill_dir("../configurations") is None
    assert registry.bundled_skill_dir("manifest.json") is None
    starter = registry.bundled_skill_dir("opentide-detection-rule")
    assert starter is not None
    assert (starter / "SKILL.md").is_file()


def test_fetch_github_bytes_unauthenticated(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class _Response:
        def read(self) -> bytes:
            return b"ok"

    def _urlopen(request: object, **_: object) -> _Response:
        captured["request"] = request
        return _Response()

    monkeypatch.setattr(registry.urllib.request, "urlopen", _urlopen)
    result = registry.fetch_github_bytes("manifest.json")
    assert result == b"ok"
    request = captured["request"]
    assert "Authorization" not in getattr(request, "headers", {})


@pytest.mark.parametrize(
    "exc",
    [urllib.error.URLError("offline"), OSError("connection reset")],
)
def test_fetch_github_bytes_returns_none_on_network_errors(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    def _boom(*_: object, **__: object) -> None:
        raise exc

    monkeypatch.setattr(registry.urllib.request, "urlopen", _boom)
    assert registry.fetch_github_bytes("manifest.json") is None


def test_bundled_manifest_missing_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(registry, "_MANIFEST_PATH", tmp_path / "missing-manifest.json")
    source, ref, entries = registry._load_bundled_manifest()
    assert source == "OpenTideHQ/skills"
    assert ref == "main"
    assert entries == []
    assert registry._bundled_ref_hint() == "main"


def test_fetch_remote_manifest_returns_none_when_github_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "fetch_github_bytes", lambda *_, **__: None)
    assert registry._fetch_remote_manifest() is None


def test_fetch_remote_manifest_returns_none_on_invalid_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "fetch_github_bytes", lambda *_, **__: b"not-json{")
    assert registry._fetch_remote_manifest() is None
