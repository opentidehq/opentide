"""Fetch MITRE ATT&CK STIX bundles from GitHub."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

GITHUB_API = "https://api.github.com/repos/mitre-attack/attack-stix-data/releases/latest"
BUNDLE_FILES = {
    "enterprise": "enterprise-attack/enterprise-attack.json",
    "mobile": "mobile-attack/mobile-attack.json",
    "ics": "ics-attack/ics-attack.json",
}


def _http_get_json(url: str) -> Any:
    request = Request(url, headers={"Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


def _http_download(url: str, dest: Path) -> None:
    request = Request(url)
    with urlopen(request, timeout=300) as response:
        dest.write_bytes(response.read())


def _normalise_release_version(tag: str) -> str:
    for prefix in ("ATT&CK-v", "ATT&CK-V", "v"):
        if tag.startswith(prefix):
            return tag[len(prefix) :]
    return tag


def fetch_latest_attack_stix(output_dir: Path) -> dict[str, Any]:
    """Download latest ATT&CK STIX bundles and write a manifest."""
    release = _http_get_json(GITHUB_API)
    tag = str(release.get("tag_name", "unknown"))
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "version": _normalise_release_version(tag),
        "tag": tag,
        "fetched_at": datetime.now(UTC).isoformat(),
        "bundles": {},
    }

    for key, relative in BUNDLE_FILES.items():
        asset_url = (
            f"https://github.com/mitre-attack/attack-stix-data/releases/download/"
            f"{tag}/{Path(relative).name}"
        )
        for asset in release.get("assets", []):
            if asset.get("name") == Path(relative).name:
                asset_url = asset["browser_download_url"]
                break

        dest = output_dir / Path(relative).name
        _http_download(asset_url, dest)
        manifest["bundles"][key] = {
            "path": dest.name,
            "url": asset_url,
        }

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
