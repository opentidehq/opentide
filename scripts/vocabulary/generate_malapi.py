#!/usr/bin/env python3
"""Regenerate the MalAPI vocabulary by scraping https://malapi.io.

This was ``opentide.extraction.malapi``, which ran the whole scrape at import
time (#539). BeautifulSoup is not an opentide dependency, so pull it in for the
run:

    uv run --with beautifulsoup4 --with lxml python scripts/vocabulary/generate_malapi.py
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from opentide.vocabulary.io import read_vocab_document, write_vocab_file
from opentide.vocabulary.lifecycle import merge_vocab_keys

SPECIFICATIONS_ENV = "OPENTIDE_SPECIFICATIONS_ROOT"
MALAPI_URL = "https://malapi.io"
API_DETAILS_FIELD_MAPPING = {
    "Function Name": "name",
    "Description": "description",
    "Library": "library",
    "Associated Attacks": "tide.vocab.stages",
    "Documentation": "link",
}
# Field order of the canonical file's keys. Only the order is kept: the first run
# rewrites the whole file in dump_vocab_document's layout (blank lines, arrays).
KEY_FIELD_ORDER = ("version", "name", "description", "link", "tide.vocab.stages")
TIMEOUT_SECONDS = 30
# malapi.io answers 429, with no Retry-After, after a short burst and then serves
# roughly one page a minute. The backoff waits that out, so a full run takes hours.
PAUSE_SECONDS = 3.0
RETRY = Retry(
    total=10, backoff_factor=2, backoff_max=300, status_forcelist=(429, 500, 502, 503, 504)
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _specifications_root() -> Path:
    repo_root = _repo_root()
    configured = os.environ.get(SPECIFICATIONS_ENV, str(repo_root.parent / "specifications"))
    return Path(configured).expanduser().resolve()


def _sync_bundled_vocabularies(specifications_root: Path) -> None:
    sync_script = _repo_root() / "scripts" / "build" / "sync_vocabularies.py"
    env = os.environ.copy()
    env[SPECIFICATIONS_ENV] = str(specifications_root)
    subprocess.run([sys.executable, str(sync_script)], check=True, env=env)


def _session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=RETRY))
    return session


def fetch_stages_and_apis(session: requests.Session) -> tuple[list[dict[str, str]], list[str]]:
    """Read the attack categories and every API name from the MalAPI front page."""
    page = session.get(MALAPI_URL, timeout=TIMEOUT_SECONDS)
    page.raise_for_status()
    table = BeautifulSoup(page.text, "lxml").find("table", id="main-table")
    if table is None:
        raise ValueError(f"No main-table on {MALAPI_URL}")

    stages = [
        {"name": th.text.strip(), "description": th.find("img")["title"].strip()}
        for th in table.find_all("th")
    ]
    apis: set[str] = set()
    for row in table.find_all("tr")[1:]:
        for body in row.find_all("tbody"):
            apis.update(link.text.strip() for link in body.find_all("a"))
    return stages, sorted(apis)


def fetch_win_api_details(session: requests.Session, api: str) -> dict[str, Any]:
    """Scrape one ``/winapi/<api>`` page into a vocabulary key."""
    page = session.get(f"{MALAPI_URL}/winapi/{api}", timeout=TIMEOUT_SECONDS)
    page.raise_for_status()
    soup = BeautifulSoup(page.text, "html.parser")

    details: dict[str, Any] = {}
    for detail in soup.find_all("div", {"class": "detail-container"}):
        heading = detail.find("div", attrs={"class": "heading"})
        content = detail.find("div", attrs={"class": "content"})
        if heading and content:
            field = API_DETAILS_FIELD_MAPPING.get(heading.text.strip())
            if field:
                details[field] = content.text.strip()
    if not details:
        raise ValueError(f"Empty parsed API: {api}")

    library = details.pop("library", None)
    if library:
        details["description"] += f"\nLibrary : `{library}`"
    stages = details.get("tide.vocab.stages")
    if stages:
        names = [line.strip() for line in stages.splitlines() if line.strip()]
        details["tide.vocab.stages"] = names if len(names) > 1 else names[0]
    return {field: details[field] for field in KEY_FIELD_ORDER if field in details}


def build_document(
    existing: dict[str, Any],
    stages: list[dict[str, str]],
    keys: list[dict[str, Any]],
    unfetched: Sequence[str] = (),
) -> dict[str, Any]:
    """Merge scraped *keys* into *existing* with RFC 0003 per-key versions.

    Live existing keys named in *unfetched* are carried over unchanged, so an
    aborted run does not mark the APIs it never reached as removed.
    """
    existing_keys = existing.get("keys") or []
    skipped = set(unfetched)
    carried = [
        key for key in existing_keys if key.get("name") in skipped and not key.get("removed")
    ]
    lifecycle = merge_vocab_keys(existing_keys, [*keys, *carried], key_field="name")
    document = dict(existing)
    document["stages"] = stages
    document["keys"] = [
        {**{field: key[field] for field in KEY_FIELD_ORDER if field in key}, **key}
        for key in lifecycle.keys
    ]
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate the MalAPI vocabulary")
    parser.parse_args()
    specifications_root = _specifications_root()
    output_path = specifications_root / "vocabularies" / "malapi.vocab.toml"

    session = _session()
    stages, apis = fetch_stages_and_apis(session)
    keys = []
    unfetched: list[str] = []
    for index, api in enumerate(apis, start=1):
        print(f"[{index}/{len(apis)}] {api}")
        try:
            keys.append(fetch_win_api_details(session, api))
        except (
            requests.exceptions.RetryError,
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
        ) as exc:
            # Hours into a run, keep what was fetched instead of discarding it.
            print(f"malapi: stopped at {api}: {exc}", file=sys.stderr)
            unfetched = apis[index - 1 :]
            break
        time.sleep(PAUSE_SECONDS)

    document = build_document(read_vocab_document(output_path), stages, keys, unfetched)
    write_vocab_file(output_path, document)
    if unfetched:
        print(
            f"malapi: {len(unfetched)} of {len(apis)} APIs not fetched, their entries left "
            f"as they were in {output_path}; bundle not synced, rerun to finish",
            file=sys.stderr,
        )
        return 1
    _sync_bundled_vocabularies(specifications_root)
    print(f"malapi: {len(document['keys'])} entries")
    print(f"synced bundle from: {output_path.parent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
