#!/usr/bin/env python3
"""Release helpers for the opentide language server.

    release.py version              print the workspace version
    release.py check vX.Y.Z         the tag, every crate pin, and CHANGELOG.md agree
    release.py bump X.Y.Z           set the workspace version and the internal pins
    release.py notes X.Y.Z          print the CHANGELOG.md section for a version
    release.py vendor [--clean]     copy each crate's shared assets into crates/*/assets
    release.py publish              publish every crate to crates.io, dependencies first
    release.py trust WORKFLOW       register WORKFLOW as each crate's trusted publisher

Crates embed catalogs, grammars, and highlight queries from the repository root.
Cargo packages only what sits inside a crate, so `vendor` copies the files each
crate reads (every `OPENTIDE_ASSETS` path in its sources, plus the directories in
`[package.metadata.opentide] assets`) into `crates/<name>/assets/`, where build.rs
looks when the workspace root is not there. `vendor --clean` removes the copies.

`publish` can be re-run: it skips each crate whose version crates.io already has, and
waits out the rate limit crates.io puts on brand-new crates, so a first release that
stops partway resumes where it stopped.

`trust` registers this repository's WORKFLOW (e.g. release.yml) as the trusted
publisher of every published crate, with a crates.io token that has the
trusted-publishing scope in CRATES_IO_TOKEN, so later releases publish with the
workflow's OIDC identity instead of a stored token. Crates already registered are
left alone; without a token it does nothing.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "Cargo.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
ASSET_INCLUDE = re.compile(r'env!\("OPENTIDE_ASSETS"\),\s*"/([^"]+)"')
# Shipped in every crate: the licence the manifests name, and the third-party notices.
LEGAL = ["LICENSE", "NOTICE"]


def workspace_version() -> str:
    return tomllib.loads(WORKSPACE.read_text())["workspace"]["package"]["version"]


def internal_pins() -> dict[str, str]:
    deps = tomllib.loads(WORKSPACE.read_text())["workspace"]["dependencies"]
    return {
        name: spec.get("version", "")
        for name, spec in deps.items()
        if isinstance(spec, dict) and "path" in spec
    }


def changelog_section(version: str) -> str | None:
    text = CHANGELOG.read_text()
    match = re.search(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |^\[[^\]]+\]: |\Z)",
        text,
        re.M | re.S,
    )
    return match.group(1).strip() if match else None


def check(tag: str) -> list[str]:
    version = workspace_version()
    problems = []
    if tag != f"v{version}":
        problems.append(f"tag {tag} does not match workspace version {version}")
    for name, pin in internal_pins().items():
        if pin != f"={version}":
            problems.append(f"{name} is pinned to {pin or 'no version'}, not ={version}")
    if not changelog_section(version):
        problems.append(f"CHANGELOG.md has no section for {version}")
    return problems


def bump(version: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        sys.exit(f"not a version: {version}")
    text = WORKSPACE.read_text()
    text = re.sub(
        r'(\[workspace\.package\]\nversion = )"[^"]+"', rf'\1"{version}"', text, count=1
    )
    text = re.sub(
        r'(opentide-[a-z]+ = \{ path = "[^"]+", version = )"=[^"]+"', rf'\1"={version}"', text
    )
    WORKSPACE.write_text(text)
    subprocess.run(["cargo", "update", "--workspace"], cwd=ROOT, check=True)


def publishable_crates() -> list[dict]:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    # `publish = false` reads as an empty registry list.
    return [p for p in json.loads(out)["packages"] if p.get("publish") != []]


def crate_assets(package: dict) -> list[str]:
    crate = Path(package["manifest_path"]).parent
    found = set()
    for source in crate.glob("src/**/*.rs"):
        found.update(ASSET_INCLUDE.findall(source.read_text()))
    meta = (package.get("metadata") or {}).get("opentide") or {}
    found.update(meta.get("assets", []))
    return sorted(found)


def vendor(clean: bool) -> None:
    for package in publishable_crates():
        crate = Path(package["manifest_path"]).parent
        target = crate / "assets"
        shutil.rmtree(target, ignore_errors=True)
        for name in LEGAL:
            (crate / name).unlink(missing_ok=True)
        if clean:
            continue
        for name in LEGAL:
            shutil.copy2(ROOT / name, crate / name)
        assets = crate_assets(package)
        for rel in assets:
            src = ROOT / rel
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dest)
            elif src.is_file():
                shutil.copy2(src, dest)
            else:
                sys.exit(f"{package['name']}: {rel} does not exist")
        if assets:
            print(f"{package['name']}: {len(assets)} asset paths")


def publish_order(packages: list[dict]) -> list[dict]:
    """Workspace crates with each one after the crates it depends on."""
    names = {p["name"] for p in packages}
    by_name = {p["name"]: p for p in packages}
    ordered: list[dict] = []
    seen: set[str] = set()

    def visit(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        for dep in by_name[name]["dependencies"]:
            if dep["name"] in names and dep.get("kind") != "dev":
                visit(dep["name"])
        ordered.append(by_name[name])

    for package in packages:
        visit(package["name"])
    return ordered


def index_path(name: str) -> str:
    """The crate's file in the crates.io sparse index."""
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def on_crates_io(name: str, version: str) -> bool:
    url = f"https://index.crates.io/{index_path(name)}"
    request = urllib.request.Request(url, headers={"User-Agent": "opentide-lsp release.py"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            lines = response.read().decode().splitlines()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise
    return any(json.loads(line)["vers"] == version for line in lines if line.strip())


# crates.io lets an account publish a few new crates at once, then one every ten minutes.
RATE_LIMIT_WAIT = 11 * 60
RATE_LIMIT_TRIES = 12


def publish() -> None:
    version = workspace_version()
    for package in publish_order(publishable_crates()):
        name = package["name"]
        if on_crates_io(name, version):
            print(f"{name} {version} is already on crates.io")
            continue
        for attempt in range(1, RATE_LIMIT_TRIES + 1):
            result = subprocess.run(
                ["cargo", "publish", "-p", name, "--allow-dirty"],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            if result.returncode == 0:
                break
            output = (result.stdout + result.stderr).lower()
            if "429" not in output and "rate limit" not in output:
                sys.exit(f"cargo publish -p {name} failed")
            if attempt == RATE_LIMIT_TRIES:
                sys.exit(f"{name}: still rate limited after {attempt} tries; re-run to resume")
            print(f"{name}: rate limited, retrying in {RATE_LIMIT_WAIT // 60} minutes")
            time.sleep(RATE_LIMIT_WAIT)


CRATES_IO_API = "https://crates.io/api/v1"


def crates_io(method: str, path: str, token: str, body: dict | None = None) -> dict:
    request = urllib.request.Request(
        f"{CRATES_IO_API}{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": token,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "opentide-lsp release.py (https://github.com/opentidehq/language-server)",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(f"{method} {path}: HTTP {error.code} {detail}") from None


def trust(workflow: str) -> None:
    token = os.environ.get("CRATES_IO_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not token:
        print("CRATES_IO_TOKEN is unset: trusted publishing not registered")
        return
    if "/" not in repository:
        sys.exit("GITHUB_REPOSITORY must be owner/name")
    owner, name = repository.split("/", 1)
    failed = []
    for package in publish_order(publishable_crates()):
        crate = package["name"]
        if not on_crates_io(crate, package["version"]):
            print(f"{crate}: not on crates.io yet, skipped")
            continue
        try:
            listed = crates_io("GET", f"/trusted_publishing/github_configs?crate={crate}", token)
            if any(
                c["repository_owner"].lower() == owner.lower()
                and c["repository_name"].lower() == name.lower()
                and c["workflow_filename"] == workflow
                for c in listed.get("github_configs", [])
            ):
                print(f"{crate}: {repository} {workflow} is already trusted")
                continue
            crates_io(
                "POST",
                "/trusted_publishing/github_configs",
                token,
                {
                    "github_config": {
                        "crate": crate,
                        "repository_owner": owner,
                        "repository_name": name,
                        "workflow_filename": workflow,
                        "environment": None,
                    }
                },
            )
            print(f"{crate}: trusts {repository} {workflow}")
        except RuntimeError as error:
            print(f"{crate}: {error}", file=sys.stderr)
            failed.append(crate)
    if failed:
        sys.exit(f"trusted publishing not registered for {', '.join(failed)}")


def main(argv: list[str]) -> None:
    match argv:
        case ["version"]:
            print(workspace_version())
        case ["check", tag]:
            problems = check(tag)
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            if problems:
                sys.exit(1)
            print(f"{tag} is consistent")
        case ["bump", version]:
            bump(version)
        case ["notes", version]:
            section = changelog_section(version.removeprefix("v"))
            if section is None:
                sys.exit(f"CHANGELOG.md has no section for {version}")
            print(section)
        case ["vendor"]:
            vendor(clean=False)
        case ["vendor", "--clean"]:
            vendor(clean=True)
        case ["publish"]:
            publish()
        case ["trust", workflow]:
            trust(workflow)
        case _:
            sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
