"""STIX bundle fetch helpers."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from opentide.vocabulary import fetch_stix


def test_normalise_release_version_strips_prefixes() -> None:
    assert fetch_stix._normalise_release_version("ATT&CK-v14.0") == "14.0"
    assert fetch_stix._normalise_release_version("v15.1") == "15.1"
    assert fetch_stix._normalise_release_version("custom") == "custom"


def test_http_get_json_uses_parse_json() -> None:
    payload = b'{"ok": true}'
    with patch("opentide.vocabulary.fetch_stix.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = payload
        assert fetch_stix._http_get_json("https://example.com/data") == {"ok": True}


def test_http_download_writes_bytes(tmp_path: Path) -> None:
    with patch("opentide.vocabulary.fetch_stix.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = b"bundle"
        dest = tmp_path / "enterprise-attack.json"
        fetch_stix._http_download("https://example.com/bundle", dest)
    assert dest.read_bytes() == b"bundle"


def test_fetch_latest_attack_stix_writes_manifest(tmp_path: Path) -> None:
    release = {
        "tag_name": "ATT&CK-v14.0",
        "assets": [
            {"name": "enterprise-attack.json", "browser_download_url": "https://example/e.json"},
            {"name": "mobile-attack.json", "browser_download_url": "https://example/m.json"},
            {"name": "ics-attack.json", "browser_download_url": "https://example/i.json"},
        ],
    }

    def _fake_get_json(url: str) -> dict:
        assert "github" in url
        return release

    def _fake_download(url: str, dest: Path) -> None:
        dest.write_text(json.dumps({"type": "bundle"}), encoding="utf-8")

    with (
        patch.object(fetch_stix, "_http_get_json", side_effect=_fake_get_json),
        patch.object(fetch_stix, "_http_download", side_effect=_fake_download),
    ):
        manifest = fetch_stix.fetch_latest_attack_stix(tmp_path)

    assert manifest["version"] == "14.0"
    assert set(manifest["bundles"]) == {"enterprise", "mobile", "ics"}
    assert (tmp_path / "manifest.json").is_file()
