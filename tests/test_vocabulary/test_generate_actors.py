"""Actor vocabulary generation helpers."""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest

from opentide.vocabulary import generate_actors


def test_load_misp_galaxy_parses_values() -> None:
    payload = {
        "values": [
            {
                "uuid": "u1",
                "value": "APT1",
                "description": "Group",
                "meta": {"synonyms": ["Comment Crew"]},
            }
        ]
    }
    response = BytesIO(json.dumps(payload).encode("utf-8"))

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return response.read()

    with patch("opentide.vocabulary.generate_actors.urlopen", return_value=_FakeResponse()):
        actors = generate_actors._load_misp_galaxy("https://example/galaxy.json")

    assert len(actors) == 1
    assert actors[0]["name"] == "APT1"
    assert actors[0]["alias"] == ["Comment Crew"]
    assert actors[0]["tide.vocab.stages"] == "misp"


def test_generate_actors_vocabs_merges_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vocab_dir = tmp_path / "vocabs"
    stix_dir = tmp_path / "attack" / "stix"
    vocab_dir.mkdir()
    stix_dir.mkdir(parents=True)
    (vocab_dir / "actors.vocab.toml").write_text('key = "id"\nkeys = []\n', encoding="utf-8")
    (stix_dir / "manifest.json").write_text(
        json.dumps({"version": "14.0", "fetched_at": "2026-01-01T00:00:00Z"}),
        encoding="utf-8",
    )

    monkeypatch.setattr(generate_actors, "_vocab_dir", lambda: vocab_dir)
    monkeypatch.setattr(generate_actors, "_stix_dir", lambda: stix_dir)
    monkeypatch.setattr(generate_actors, "_default_misp_url", lambda: None)
    monkeypatch.setattr(generate_actors, "parse_groups", lambda _bundle, prefix: [{"id": prefix}])
    monkeypatch.setattr(generate_actors, "load_stix_bundle", lambda _path: {"objects": []})
    monkeypatch.setattr(
        generate_actors,
        "read_vocab_document",
        lambda _path: {"field": "actors", "key": "id", "keys": []},
    )
    monkeypatch.setattr(generate_actors, "write_vocab_file", lambda _path, _doc: None)

    for name in ("enterprise-attack.json", "ics-attack.json", "mobile-attack.json"):
        (stix_dir / name).write_text("{}", encoding="utf-8")

    count = generate_actors.generate_actors_vocabs()
    assert count == 3
