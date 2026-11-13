#!/usr/bin/env python3
"""The release train's helpers: crates, npm packages and the GitHub Release assets.

    release.py version              print the workspace version
    release.py tag                  print the release tag of the workspace version (vX.Y.Z)
    release.py check TAG            the tag and every crate pin agree with the workspace version
    release.py lockstep VERSION [--npm NPM_VERSION]
                                    the crates, their pins and the npm packages carry one version
    release.py npm-version VERSION  write VERSION into every npm package of the release
                                    (X.Y.Z, X.Y.Z-rc.N, or a CI build's X.Y.Z-dev.N)
    release.py prerelease TAG       print true for a release candidate tag, else false
    release.py asset-version TAG    print the version the asset names carry (vX.Y.Z[-rc.N])
    release.py assets TAG           print the name of every asset the tag's release carries
    release.py check-assets DIR TAG DIR holds exactly the tag's assets
    release.py bump X.Y.Z[-rc.N]    set the workspace version and the internal pins
    release.py vendor [--clean]     copy each crate's shared assets into crates/*/assets
    release.py publish              publish every crate to crates.io, dependencies first
    release.py trust WORKFLOW       register WORKFLOW as each crate's trusted publisher
    release.py crate-patch DIR OUT  unpack DIR's .crate files into OUT, with a cargo config
                                    that resolves them in place of crates.io's
    release.py sums DIR             write DIR/SHA256SUMS for every file in DIR
    release.py verify-sums DIR      DIR/SHA256SUMS lists exactly DIR's files, each digest right
    release.py unpublished TAG      fail when the tag's GitHub Release already has assets

opentide releases one product version (UC-5.5, #840): the Python wheel, the
crates, the npm packages and the binaries all carry it, and one tag, `vX.Y.Z`
(or `vX.Y.Z-rc.N`, a release candidate), publishes them all from
`.github/workflows/publish.yml`. The engine's own tag series (`engine-v*`,
`engine-release.yml`) ended there. The assets keep the names language-server
gave them, `v` and the version (`highlights-v0.24.0.zip`), so an editor that
pinned one finds the next by version.

`lockstep` is the check that keeps the one version: the workspace version in
Cargo.toml is the release's (`bump` sets it with the internal pins), and every
npm package of the release (`@opentide/opentide`, its native packages, the
`opentide` alias, `@opentide/lsp-client` and `@opentide/lsp-worker`) carries
one version, its dependencies on each other included. The tree keeps the npm
packages at a placeholder version, `npm-version` writes the release's into
them in the workflow, and `lockstep --npm` checks the result. The Python
package's version is the tag's (hatch-vcs), which `scripts/build/release.py`
checks against CHANGELOG.md.

Crates embed catalogs, grammars, and highlight queries from the repository root.
Cargo packages only what sits inside a crate, so `vendor` copies the files each
crate reads (every `OPENTIDE_ASSETS` path in its sources, plus the directories in
`[package.metadata.opentide] assets`) into `crates/<name>/assets/`, where build.rs
looks when the workspace root is not there. `vendor --clean` removes the copies.

`publish` uploads each crate's package with `cargo publish --no-verify`: it builds
nothing where the publishing tokens are (the release workflow's `checks` job
built every package, with no token). It can be re-run: it skips each crate
whose version crates.io already has, and waits out the rate limit crates.io puts
on brand-new crates, so a first release that stops partway resumes where it
stopped. A release candidate's crates are crates.io pre-releases
(`X.Y.Z-rc.N`, for the Rust-core transition): the workflow runs `bump
X.Y.Z-rc.N` in its own checkout, so the branch keeps `X.Y.Z`, then packages and
publishes as for a release. crates.io can yank a version, never delete it.

`trust` registers this repository's WORKFLOW (publish.yml) as the trusted
publisher of every published crate, with a crates.io token that has the
trusted-publishing scope in CRATES_IO_TOKEN, so later releases publish with the
workflow's OIDC identity instead of a stored token. Crates already registered are
left alone; without a token it does nothing.

`crate-patch` lets `cargo install` build the facade from its package before any
crate of the version is on crates.io (the release workflow's smoke test): it
unpacks every `.crate` and writes `OUT/config.toml`, whose `[patch.crates-io]`
names each unpacked crate.

`sums` writes `SHA256SUMS` in DIR, in `sha256sum` format, for every file DIR holds
(the GitHub Release's assets), so `sha256sum -c SHA256SUMS` checks a download. It
fails on a subdirectory or a name `sha256sum -c` cannot read back, rather than
leave an asset out.

`verify-sums` checks a downloaded release the other way round: SHA256SUMS lists
every file in DIR and no other, and each digest matches. `sha256sum -c` checks
only the names the file lists, so an asset with no line passes it.

`unpublished` fails when the GitHub Release of the tag (in GITHUB_REPOSITORY)
already carries assets, a draft's included: the release workflow never uploads
over them. A rebuild does not reproduce the zips byte for byte, and consumers
pin the published digests (SHA256SUMS, an editor's pinned highlights). No
release, or one with notes only, passes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10, which opentide's tests also run on
    import tomli as tomllib  # an opentide dependency there

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "Cargo.toml"
ASSET_INCLUDE = re.compile(r'env!\("OPENTIDE_ASSETS"\),\s*"/([^"]+)"')
# Shipped in every crate: the licence the manifests name, and the third-party notices.
LEGAL = ["LICENSE", "NOTICE"]
SUMS = "SHA256SUMS"
TAG = re.compile(r"v(?P<version>\d+\.\d+\.\d+)(?:-rc\.(?P<rc>[1-9]\d*))?")
# The targets the release builds its binaries for (engine-release-build.yml, job
# `native`): one `opentide` and one `opentide-lsp` each, `.exe` on Windows. No musl
# target: the maintainer decided against musl builds (docs/internal/publishing.md,
# "The release train"), so neither the binaries, the wheels (no musllinux) nor the
# npm packages ship one.
TARGETS = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
]
# The standalone binaries, each built for every target: the command line
# (`cargo install opentide --features cli`) and the language server.
BINARIES = ["opentide", "opentide-lsp"]
# Every release carries these besides the binaries and the versioned zips: the
# licences, the WASI build, the installers of the binaries (scripts/install/),
# and SHA256SUMS.
FIXED_ASSETS = [
    "LICENSE",
    "NOTICE",
    "THIRD-PARTY-LICENSES.html",
    "WASI-LIBC-LICENSES.txt",
    "opentide-lsp-wasm32-wasip1.wasm",
    "opentide-installer.sh",
    "opentide-installer.ps1",
    SUMS,
]
# The CycloneDX SBOMs scripts/engine/sbom.py writes, one per artifact (#843):
# the opentide-lsp binaries and WASI build, the browser build, the two lsp npm
# packages, the `opentide` binaries and crate, the @opentide/opentide npm
# package, and the PyPI wheel.
SBOM_ASSETS = [
    "opentide-lsp.cdx.json",
    "opentide-wasm.cdx.json",
    "opentide-lsp-client.cdx.json",
    "opentide-lsp-worker.cdx.json",
    "opentide.cdx.json",
    "opentide-node.cdx.json",
    "opentide-wheel.cdx.json",
]
# The npm packages a release publishes, each directory with its package.json:
# @opentide/opentide's native packages first (it depends on them), then the
# package, its `opentide` alias, and the language server's two packages.
NPM_NODE = ROOT / "bindings" / "node"
NPM_LSP = [ROOT / "packages" / "lsp-client", ROOT / "packages" / "lsp-worker"]


def npm_native_dirs() -> list[Path]:
    """The native packages of @opentide/opentide, one per target (`bindings/node/npm/`)."""
    return sorted(path for path in (NPM_NODE / "npm").iterdir() if path.is_dir())


def npm_packages() -> list[Path]:
    """Every npm package of the release, in the order it is published."""
    return [*npm_native_dirs(), NPM_NODE, NPM_NODE / "alias", *NPM_LSP]


def workspace_version() -> str:
    return tomllib.loads(WORKSPACE.read_text())["workspace"]["package"]["version"]


def internal_pins() -> dict[str, str]:
    """The workspace's dependencies on its own crates, with their version
    requirement. A path dependency without a version (the test harnesses,
    `opentide-compare` and `opentide-cassette`, which are never published) is
    left out: cargo strips it from a published manifest, and a published
    crate that needed it would fail `cargo package`."""
    deps = tomllib.loads(WORKSPACE.read_text())["workspace"]["dependencies"]
    return {
        name: spec["version"]
        for name, spec in deps.items()
        if isinstance(spec, dict) and "path" in spec and "version" in spec
    }


def parse_tag(tag: str) -> tuple[str, int | None]:
    """The version of a release tag and its release-candidate number (None for a
    release). Anything but `vX.Y.Z` or `vX.Y.Z-rc.N` is an error, the engine's
    old `engine-vX.Y.Z` included: that series ended with the release train."""
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError(f"{tag!r} is not a release tag (vX.Y.Z or vX.Y.Z-rc.N)")
    rc = match.group("rc")
    return match.group("version"), int(rc) if rc else None


def asset_version(tag: str) -> str:
    """What the asset names carry: the tag (`v0.24.0`, `v0.24.0-rc.1`)."""
    parse_tag(tag)
    return tag


def binary_asset(binary: str, tag: str, target: str) -> str:
    """The asset name of `binary` built for `target`: `opentide-lsp-v0.24.0-<target>`."""
    ext = ".exe" if "windows" in target else ""
    return f"{binary}-{asset_version(tag)}-{target}{ext}"


def expected_assets(tag: str) -> list[str]:
    """Every asset of the tag's GitHub Release, sorted: what language-server's
    releases carried (but the musl binaries), with this tag's version in the
    versioned names, the `opentide` binaries and their installers, and the
    SBOMs."""
    v = asset_version(tag)
    names = [*FIXED_ASSETS, *SBOM_ASSETS, f"highlights-{v}.zip", f"opentide-wasm-web-{v}.zip"]
    for binary in BINARIES:
        names.extend(binary_asset(binary, tag, target) for target in TARGETS)
    return sorted(names)


def check_assets(directory: Path, tag: str) -> list[str]:
    """What differs between `directory`'s files and the tag's asset set."""
    present = {entry.name for entry in directory.iterdir()}
    expected = set(expected_assets(tag))
    problems = [f"missing asset: {name}" for name in sorted(expected - present)]
    problems += [f"unexpected asset: {name}" for name in sorted(present - expected)]
    problems += [
        f"{name} is not a file"
        for name in sorted(present & expected)
        if not (directory / name).is_file()
    ]
    return problems


def crate_problems(version: str) -> list[str]:
    """What keeps the crates from releasing `version` (X.Y.Z): the workspace
    version and every internal pin are the release's."""
    problems = []
    workspace = workspace_version()
    if workspace != version:
        problems.append(
            f"the workspace version in Cargo.toml is {workspace}, not {version}: "
            f"run `scripts/engine/release.py bump {version}` in the release's pull request"
        )
    for name, pin in internal_pins().items():
        if pin != f"={version}":
            problems.append(f"{name} is pinned to {pin}, not ={version}")
    return problems


def check(tag: str) -> list[str]:
    """The tag's version is the workspace version, and every pin agrees."""
    try:
        tagged, _ = parse_tag(tag)
    except ValueError as error:
        return [str(error)]
    return crate_problems(tagged)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def npm_problems(expected: str | None = None) -> list[str]:
    """What breaks the npm packages' one version: a package at another version
    than @opentide/opentide (or than `expected`), or a dependency between them
    that names another."""
    main = read_json(NPM_NODE / "package.json")
    version = expected if expected is not None else main["version"]
    problems = []
    for directory in npm_packages():
        manifest = read_json(directory / "package.json")
        if manifest["version"] != version:
            problems.append(f"{manifest['name']} is at {manifest['version']}, not {version}")
    natives = {read_json(d / "package.json")["name"] for d in npm_native_dirs()}
    optional = main.get("optionalDependencies", {})
    if set(optional) != natives:
        problems.append(
            f"{main['name']}'s optionalDependencies {sorted(optional)} are not its "
            f"native packages {sorted(natives)}"
        )
    for name, wanted in sorted(optional.items()):
        if wanted != version:
            problems.append(f"{main['name']} depends on {name}@{wanted}, not {version}")
    alias = read_json(NPM_NODE / "alias" / "package.json")
    if alias.get("dependencies") != {main["name"]: version}:
        problems.append(
            f"{alias['name']} depends on {alias.get('dependencies')}, not {main['name']}@{version}"
        )
    return problems


def set_npm_version(version: str) -> None:
    """Write `version` into every npm package of the release and their
    dependencies on each other (what the tree holds is a placeholder)."""
    # X.Y.Z, a candidate's X.Y.Z-rc.N (smoke-tested, not published), or a CI
    # build's X.Y.Z-dev.N (ci.yml's `packages` artifacts, never published).
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-(?:rc|dev)\.[1-9]\d*)?", version):
        sys.exit(f"npm-version: not a release version: {version}")
    main_name = read_json(NPM_NODE / "package.json")["name"]
    for directory in npm_packages():
        path = directory / "package.json"
        manifest = read_json(path)
        manifest["version"] = version
        if "optionalDependencies" in manifest:
            manifest["optionalDependencies"] = dict.fromkeys(
                manifest["optionalDependencies"], version
            )
        if main_name in manifest.get("dependencies", {}):
            manifest["dependencies"][main_name] = version
        path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def bump(version: str) -> None:
    """Set the workspace version and every internal pin to `version`: X.Y.Z in
    a release's pull request, or X.Y.Z-rc.N in a candidate's workflow checkout
    only (its crates are crates.io pre-releases; the branch keeps X.Y.Z)."""
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", version):
        sys.exit(f"not a version: {version}")
    text = WORKSPACE.read_text()
    text = re.sub(r'(\[workspace\.package\]\nversion = )"[^"]+"', rf'\1"{version}"', text, count=1)
    text = re.sub(
        r'(opentide-[a-z-]+ = \{ path = "[^"]+", version = )"=[^"]+"', rf'\1"={version}"', text
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
    request = urllib.request.Request(url, headers={"User-Agent": "opentide release.py"})
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


#: crates.io's answer when a trusted-publishing token tries to create a crate.
NEW_CRATE_REFUSAL = "trusted publishing tokens do not support creating new crates"


def use_new_crate_token(env: dict[str, str]) -> bool:
    """Whether a refused new crate can be retried with NEW_CRATE_TOKEN (a stored token).

    Only once per crate: the retry's environment already uses that token.
    """
    token = env.get("NEW_CRATE_TOKEN", "")
    return bool(token) and env.get("CARGO_REGISTRY_TOKEN") != token


def crate_patch(packages: Path, out: Path) -> Path:
    """Unpack every `.crate` in `packages` into `out` and write `out/config.toml`,
    whose `[patch.crates-io]` resolves each crate to its unpacked package: what
    `cargo install --config out/config.toml --path out/opentide-X.Y.Z` builds
    is the packages, before crates.io has them. The config's path."""
    crates = sorted(packages.glob("*.crate"))
    if not crates:
        raise ValueError(f"{packages} holds no .crate file")
    out.mkdir(parents=True, exist_ok=True)
    lines = ["[patch.crates-io]"]
    for crate in crates:
        with tarfile.open(crate, "r:gz") as archive:
            # Each package is one directory, `<name>-<version>/`.
            top = {member.name.split("/", 1)[0] for member in archive.getmembers()}
            if len(top) != 1:
                raise ValueError(f"{crate.name} is not one package directory: {sorted(top)}")
            archive.extractall(out, filter="data")
        directory = out / top.pop()
        name = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))["package"][
            "name"
        ]
        lines.append(f"{name} = {{ path = {json.dumps(directory.resolve().as_posix())} }}")
    config = out / "config.toml"
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return config


def publish() -> None:
    version = workspace_version()
    for package in publish_order(publishable_crates()):
        name = package["name"]
        if on_crates_io(name, version):
            print(f"{name} {version} is already on crates.io")
            continue
        env = dict(os.environ)
        for attempt in range(1, RATE_LIMIT_TRIES + 1):
            result = subprocess.run(
                # No verify build: this runs where the OIDC token and the registry
                # tokens are, and a build runs every dependency's build script.
                # The verify job built each crate from its package, with neither.
                ["cargo", "publish", "-p", name, "--allow-dirty", "--no-verify"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            if result.returncode == 0:
                break
            output = (result.stdout + result.stderr).lower()
            if NEW_CRATE_REFUSAL in output and use_new_crate_token(env):
                print(f"{name} is a new crate: publishing it with the stored token")
                env = {**env, "CARGO_REGISTRY_TOKEN": env["NEW_CRATE_TOKEN"]}
                continue
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
            "User-Agent": "opentide release.py (https://github.com/opentidehq/opentide)",
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


def sha256sums(directory: Path) -> str:
    """`sha256sum` lines for every file in `directory`, sorted by name.

    A release's assets are one flat directory: a subdirectory, or a name with
    whitespace or a backslash (which `sha256sum` escapes), is an error rather
    than an asset the sums would leave out.
    """
    lines = []
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        if entry.name == SUMS:
            continue
        if not entry.is_file():
            raise ValueError(f"{entry} is not a file; release assets are one flat directory")
        if re.search(r"[\s\\]", entry.name):
            raise ValueError(f"{entry.name!r}: sha256sum cannot read back this name")
        digest = hashlib.sha256()
        with entry.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        lines.append(f"{digest.hexdigest()}  {entry.name}\n")
    if not lines:
        raise ValueError(f"{directory} has no assets")
    return "".join(lines)


def verify_sums(directory: Path) -> list[str]:
    """What is wrong with `directory`'s SHA256SUMS as the record of every file
    beside it: a line `sha256sum` would not write, a file it does not list, a
    name it lists that is not there, or a digest that does not match."""
    sums = directory / SUMS
    if not sums.is_file():
        return [f"{sums} is missing"]
    problems = []
    listed: dict[str, str] = {}
    for number, line in enumerate(sums.read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](\S+)", line)
        if not match:
            problems.append(f"{SUMS}:{number}: not a sha256sum line: {line!r}")
            continue
        digest, name = match.groups()
        if name in listed:
            problems.append(f"{SUMS}:{number}: {name} is listed twice")
        listed[name] = digest
    present = {entry.name for entry in directory.iterdir() if entry.name != SUMS}
    for name in sorted(present - listed.keys()):
        problems.append(f"{name} has no line in {SUMS}")
    for name in sorted(listed.keys() - present):
        problems.append(f"{name} is in {SUMS} but not an asset")
    for name in sorted(present & listed.keys()):
        entry = directory / name
        if not entry.is_file():
            problems.append(f"{name} is not a file")
            continue
        digest = hashlib.sha256()
        with entry.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != listed[name]:
            problems.append(f"{name}: the digest does not match {SUMS}")
    if not listed and not problems:
        problems.append(f"{SUMS} lists no asset")
    return problems


def published_assets(tag: str, repo: str) -> list[str]:
    """The asset names of the GitHub Release of `tag` in `repo`: none when it
    has no release. A `gh` failure other than a missing release raises, so an
    outage is never read as "not released"."""
    result = subprocess.run(
        ["gh", "release", "view", tag, "--repo", repo, "--json", "assets"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        if "release not found" in result.stderr.lower():
            return []
        raise RuntimeError(f"gh release view {tag}: {result.stderr.strip()}")
    return [asset["name"] for asset in json.loads(result.stdout).get("assets", [])]


def write_sums(directory: Path) -> Path:
    target = directory / SUMS
    target.write_text(sha256sums(directory), encoding="utf-8", newline="\n")
    return target


def main(argv: list[str]) -> None:
    match argv:
        case ["version"]:
            print(workspace_version())
        case ["tag"]:
            print(f"v{workspace_version()}")
        case ["lockstep", version]:
            problems = crate_problems(version)
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            if problems:
                sys.exit(1)
            print(f"the crates are at {version}")
        case ["lockstep", version, "--npm", npm_version]:
            problems = crate_problems(version) + npm_problems(npm_version)
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            if problems:
                sys.exit(1)
            print(f"the crates are at {version}, the npm packages at {npm_version}")
        case ["npm-version", version]:
            set_npm_version(version)
            print(f"the npm packages are at {version}")
        case ["prerelease", tag]:
            try:
                print("false" if parse_tag(tag)[1] is None else "true")
            except ValueError as error:
                sys.exit(f"prerelease: {error}")
        case ["asset-version", tag]:
            try:
                print(asset_version(tag))
            except ValueError as error:
                sys.exit(f"asset-version: {error}")
        case ["assets", tag]:
            try:
                print("\n".join(expected_assets(tag)))
            except ValueError as error:
                sys.exit(f"assets: {error}")
        case ["check-assets", directory, tag]:
            try:
                problems = check_assets(Path(directory), tag)
            except (OSError, ValueError) as error:
                sys.exit(f"check-assets: {error}")
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            if problems:
                sys.exit(1)
            print(f"{directory} holds the {len(expected_assets(tag))} assets of {tag}")
        case ["check", tag]:
            problems = check(tag)
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            if problems:
                sys.exit(1)
            print(f"{tag} is consistent")
        case ["bump", version]:
            bump(version)
        case ["vendor"]:
            vendor(clean=False)
        case ["vendor", "--clean"]:
            vendor(clean=True)
        case ["publish"]:
            publish()
        case ["crate-patch", packages, out]:
            try:
                print(crate_patch(Path(packages), Path(out)))
            except (OSError, ValueError) as error:
                sys.exit(f"crate-patch: {error}")
        case ["trust", workflow]:
            trust(workflow)
        case ["sums", directory]:
            try:
                target = write_sums(Path(directory))
            except (OSError, ValueError) as error:
                sys.exit(f"sums: {error}")
            print(f"wrote {target}")
        case ["verify-sums", directory]:
            problems = verify_sums(Path(directory))
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            if problems:
                sys.exit(1)
            print(f"{Path(directory) / SUMS} covers every asset")
        case ["unpublished", tag]:
            repo = os.environ.get("GITHUB_REPOSITORY", "")
            if not repo:
                sys.exit("unpublished: set GITHUB_REPOSITORY (owner/name)")
            try:
                names = published_assets(tag, repo)
            except RuntimeError as error:
                sys.exit(f"unpublished: {error}")
            if names:
                sys.exit(
                    f"error: {tag} is already released with {len(names)} assets; a rebuild would "
                    "replace the digests consumers pinned. Resume the registries with Run "
                    f"workflow and checkout_ref={tag}; fix anything else with a patch release. "
                    "A draft that never published can be deleted, then released again."
                )
            print(f"{tag} has no published assets")
        case _:
            sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
