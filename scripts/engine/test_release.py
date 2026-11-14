"""Tests for scripts/engine/release.py (tags, the asset set, checksums, the one
version) and for the shape of the release train, .github/workflows/publish.yml,
and the asset build it shares with ci.yml's dry run, engine-release-build.yml
(language-server#196, opentide#801, #840).

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release


class Sha256SumsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def asset(self, name: str, data: bytes) -> None:
        (self.dir / name).write_bytes(data)

    def test_every_asset_is_listed_sorted_in_sha256sum_format(self) -> None:
        self.asset("opentide-lsp-v1.0.0-x86_64-unknown-linux-gnu", b"\x7fELF")
        self.asset("highlights-v1.0.0.zip", b"PK")
        self.asset("NOTICE", b"notice\n")
        target = release.write_sums(self.dir)
        self.assertEqual(target.name, "SHA256SUMS")
        lines = target.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            [line.split("  ", 1)[1] for line in lines],
            ["NOTICE", "highlights-v1.0.0.zip", "opentide-lsp-v1.0.0-x86_64-unknown-linux-gnu"],
        )
        self.assertIn(f"{hashlib.sha256(b'PK').hexdigest()}  highlights-v1.0.0.zip", lines)

    def test_rewriting_does_not_list_the_sums_file_itself(self) -> None:
        self.asset("LICENSE", b"EUPL")
        release.write_sums(self.dir)
        release.write_sums(self.dir)
        text = (self.dir / "SHA256SUMS").read_text(encoding="utf-8")
        self.assertNotIn("SHA256SUMS", text)
        self.assertEqual(len(text.splitlines()), 1)

    @unittest.skipUnless(shutil.which("sha256sum"), "coreutils sha256sum is not installed")
    def test_sha256sum_check_passes_and_catches_a_changed_asset(self) -> None:
        self.asset("opentide-lsp-wasm32-wasip1.wasm", b"\0asm")
        self.asset("THIRD-PARTY-LICENSES.html", b"<html></html>")
        release.write_sums(self.dir)
        check = ["sha256sum", "--check", "--strict", "SHA256SUMS"]
        ok = subprocess.run(check, cwd=self.dir, capture_output=True, check=False)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.asset("THIRD-PARTY-LICENSES.html", b"tampered")
        bad = subprocess.run(check, cwd=self.dir, capture_output=True, check=False)
        self.assertNotEqual(bad.returncode, 0)

    def test_a_subdirectory_is_an_error_not_a_skipped_asset(self) -> None:
        self.asset("LICENSE", b"EUPL")
        (self.dir / "licenses").mkdir()
        with self.assertRaises(ValueError):
            release.sha256sums(self.dir)

    def test_a_name_sha256sum_would_escape_is_an_error(self) -> None:
        self.asset("bad name.zip", b"PK")
        with self.assertRaises(ValueError):
            release.sha256sums(self.dir)

    def test_an_empty_directory_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            release.sha256sums(self.dir)

    def test_the_cli_writes_the_file(self) -> None:
        self.asset("NOTICE", b"n")
        script = Path(release.__file__)
        done = subprocess.run(
            [sys.executable, str(script), "sums", str(self.dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((self.dir / "SHA256SUMS").is_file())


class VerifySumsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / "highlights-v1.0.0.zip").write_bytes(b"PK")
        (self.dir / "NOTICE").write_bytes(b"n")
        release.write_sums(self.dir)

    def test_the_sums_of_every_asset_pass(self) -> None:
        self.assertEqual(release.verify_sums(self.dir), [])

    def test_an_asset_the_sums_leave_out_fails(self) -> None:
        # What sha256sum --check --strict lets through: a published asset with no line.
        (self.dir / "opentide-lsp-v0.9.0-x86_64-unknown-linux-gnu").write_bytes(b"stale")
        problems = release.verify_sums(self.dir)
        self.assertEqual(
            problems, ["opentide-lsp-v0.9.0-x86_64-unknown-linux-gnu has no line in SHA256SUMS"]
        )

    def test_a_listed_asset_that_is_missing_or_changed_fails(self) -> None:
        (self.dir / "NOTICE").unlink()
        (self.dir / "highlights-v1.0.0.zip").write_bytes(b"tampered")
        problems = release.verify_sums(self.dir)
        self.assertIn("NOTICE is in SHA256SUMS but not an asset", problems)
        self.assertIn("highlights-v1.0.0.zip: the digest does not match SHA256SUMS", problems)

    def test_a_missing_or_malformed_sums_file_fails(self) -> None:
        (self.dir / "SHA256SUMS").write_text("not a sum\n", encoding="utf-8")
        self.assertTrue(release.verify_sums(self.dir))
        (self.dir / "SHA256SUMS").unlink()
        self.assertEqual(release.verify_sums(self.dir), [f"{self.dir / 'SHA256SUMS'} is missing"])

    def test_the_cli_fails_on_an_unlisted_asset(self) -> None:
        script = Path(release.__file__)
        run = [sys.executable, str(script), "verify-sums", str(self.dir)]
        ok = subprocess.run(run, capture_output=True, text=True, check=False)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        (self.dir / "extra.wasm").write_bytes(b"\0asm")
        bad = subprocess.run(run, capture_output=True, text=True, check=False)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("extra.wasm has no line in SHA256SUMS", bad.stderr)


class UnpublishedTest(unittest.TestCase):
    """`release.py unpublished TAG`: a release that already carries assets is
    never uploaded again. Its zips do not rebuild byte for byte, and consumers
    pin the published digests."""

    def gh(self, returncode: int, stdout: str = "", stderr: str = "") -> mock.MagicMock:
        done = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)
        return mock.patch.object(release.subprocess, "run", return_value=done)

    def release_json(self, names: list[str], draft: bool = False) -> str:
        return json.dumps({"isDraft": draft, "assets": [{"name": n} for n in names]})

    def test_a_release_with_assets_is_published(self) -> None:
        with self.gh(0, self.release_json(["SHA256SUMS", "highlights-v1.0.0.zip"])) as run:
            self.assertEqual(
                release.published_assets("v1.0.0", "o/r"), ["SHA256SUMS", "highlights-v1.0.0.zip"]
            )
        args = run.call_args.args[0]
        self.assertEqual(args[:4], ["gh", "release", "view", "v1.0.0"])
        self.assertIn("o/r", args)
        # One from before SHA256SUMS (#196) too: its assets were downloaded as they are.
        with self.gh(0, self.release_json(["opentide-lsp-v0.9.1-x86_64-unknown-linux-gnu"])):
            self.assertTrue(release.published_assets("v0.9.1", "o/r"))

    def test_no_release_or_one_without_assets_is_not(self) -> None:
        with self.gh(1, stderr="release not found\n"):
            self.assertEqual(release.published_assets("v1.0.0", "o/r"), [])
        # Notes only: created by hand, or backfilled.
        with self.gh(0, self.release_json([])):
            self.assertEqual(release.published_assets("v1.0.0", "o/r"), [])

    def test_a_gh_failure_is_an_error_not_an_unreleased_tag(self) -> None:
        with self.gh(1, stderr="HTTP 502: Bad Gateway\n"), self.assertRaises(RuntimeError):
            release.published_assets("v1.0.0", "o/r")

    def test_the_cli_refuses_a_released_tag(self) -> None:
        env = {"GITHUB_REPOSITORY": "o/r"}
        with (
            mock.patch.dict(release.os.environ, env),
            self.gh(0, self.release_json(["SHA256SUMS"])),
            self.assertRaises(SystemExit) as refused,
        ):
            release.main(["unpublished", "v1.0.0"])
        self.assertIn("checkout_ref=v1.0.0", str(refused.exception.code))
        with mock.patch.dict(release.os.environ, env), self.gh(1, stderr="release not found"):
            release.main(["unpublished", "v1.0.0"])


class PublishTest(unittest.TestCase):
    def test_cargo_publish_builds_nothing(self) -> None:
        # The job holds an OIDC token and the registry tokens: a verify build
        # would run every dependency's build script with them. The verify job
        # already built each crate from its package.
        crates = [{"name": "opentide-core"}, {"name": "opentide-lsp"}]
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with (
            mock.patch.object(release, "workspace_version", return_value="1.0.0"),
            mock.patch.object(release, "publishable_crates", return_value=crates),
            mock.patch.object(release, "publish_order", side_effect=lambda c: c),
            mock.patch.object(release, "on_crates_io", return_value=False),
            mock.patch.object(release.subprocess, "run", return_value=done) as run,
        ):
            release.publish()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 2, commands)
        for command in commands:
            self.assertEqual(command[:2], ["cargo", "publish"], command)
            self.assertIn("--no-verify", command)


class BumpTest(unittest.TestCase):
    """`bump` sets the workspace version and the pins: X.Y.Z in a release's
    pull request, X.Y.Z-rc.N in a candidate's workflow checkout (its crates
    are crates.io pre-releases)."""

    def _bump(self, version: str) -> str:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        workspace = root / "Cargo.toml"
        workspace.write_text(
            '[workspace.package]\nversion = "1.2.3"\n\n[workspace.dependencies]\n'
            'opentide-core = { path = "crates/opentide-core", version = "=1.2.3" }\n'
            'opentide-compare = { path = "crates/opentide-compare" }\n',
            encoding="utf-8",
        )
        done = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(release, "WORKSPACE", workspace),
            mock.patch.object(release.subprocess, "run", return_value=done) as run,
        ):
            release.bump(version)
        self.assertEqual(run.call_args.args[0], ["cargo", "update", "--workspace"])
        return workspace.read_text(encoding="utf-8")

    def test_a_release_version(self) -> None:
        text = self._bump("1.3.0")
        self.assertIn('version = "1.3.0"', text)
        self.assertIn('version = "=1.3.0"', text)
        self.assertIn('opentide-compare = { path = "crates/opentide-compare" }', text)

    def test_a_candidates_pre_release_version(self) -> None:
        text = self._bump("1.3.0-rc.2")
        self.assertIn('[workspace.package]\nversion = "1.3.0-rc.2"', text)
        self.assertIn(
            'opentide-core = { path = "crates/opentide-core", version = "=1.3.0-rc.2" }', text
        )

    def test_anything_else_is_refused(self) -> None:
        for version in ["1.3", "v1.3.0", "1.3.0-rc.0", "1.3.0-dev.1", "1.3.0-beta.1"]:
            with self.subTest(version=version), self.assertRaises(SystemExit):
                self._bump(version)


class CratePatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def crate(self, name: str, version: str) -> None:
        import tarfile

        source = self.dir / "src" / f"{name}-{version}"
        source.mkdir(parents=True)
        (source / "Cargo.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "{version}"\n', encoding="utf-8"
        )
        packages = self.dir / "packages"
        packages.mkdir(exist_ok=True)
        with tarfile.open(packages / f"{name}-{version}.crate", "w:gz") as archive:
            archive.add(source, arcname=source.name)

    def test_every_package_is_unpacked_and_patched_in(self) -> None:
        self.crate("opentide", "1.2.3")
        self.crate("opentide-core", "1.2.3")
        config = release.crate_patch(self.dir / "packages", self.dir / "out")
        text = config.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("[patch.crates-io]\n"))
        for name in ["opentide", "opentide-core"]:
            unpacked = (self.dir / "out" / f"{name}-1.2.3").resolve().as_posix()
            self.assertIn(f'{name} = {{ path = "{unpacked}" }}', text)
            self.assertTrue((self.dir / "out" / f"{name}-1.2.3" / "Cargo.toml").is_file())

    def test_no_package_is_an_error(self) -> None:
        (self.dir / "packages").mkdir()
        with self.assertRaises(ValueError):
            release.crate_patch(self.dir / "packages", self.dir / "out")


class LockstepTest(unittest.TestCase):
    """One product version: the crates and their pins, and every npm package."""

    def test_the_crates_are_at_the_release_version(self) -> None:
        with (
            mock.patch.object(release, "workspace_version", return_value="1.2.3"),
            mock.patch.object(release, "internal_pins", return_value={"opentide-core": "=1.2.3"}),
        ):
            self.assertEqual(release.crate_problems("1.2.3"), [])
            self.assertEqual(release.check("v1.2.3-rc.1"), [])
            problems = release.crate_problems("1.2.4")
        self.assertEqual(len(problems), 2, problems)
        self.assertIn("release.py bump 1.2.4", problems[0])
        self.assertIn("opentide-core is pinned to =1.2.3, not =1.2.4", problems[1])

    def test_the_workspace_pins_every_published_crate_to_its_version(self) -> None:
        version = release.workspace_version()
        self.assertEqual(release.crate_problems(version), [])
        # The test harnesses are path dependencies without a version: never
        # published, so not pinned.
        pins = release.internal_pins()
        self.assertNotIn("opentide-compare", pins)
        self.assertNotIn("opentide-cassette", pins)
        self.assertIn("opentide-schema-derive", pins)

    def test_the_tree_keeps_the_npm_packages_at_one_placeholder(self) -> None:
        main = json.loads((release.NPM_NODE / "package.json").read_text(encoding="utf-8"))
        node = [d for d in release.npm_packages() if d not in release.NPM_TYPESCRIPT]
        versions = {
            json.loads((d / "package.json").read_text(encoding="utf-8"))["version"] for d in node
        }
        self.assertEqual(versions, {main["version"]})

    def test_npm_version_writes_every_package_and_their_dependencies(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        node = root / "bindings" / "node"
        shutil.copytree(release.NPM_NODE / "npm", node / "npm")
        shutil.copy(release.NPM_NODE / "package.json", node / "package.json")
        (node / "alias").mkdir()
        shutil.copy(release.NPM_NODE / "alias" / "package.json", node / "alias" / "package.json")
        typescript = []
        for source in release.NPM_TYPESCRIPT:
            target = root / "packages" / source.name
            target.mkdir(parents=True)
            shutil.copy(source / "package.json", target / "package.json")
            typescript.append(target)
        with (
            mock.patch.object(release, "NPM_NODE", node),
            mock.patch.object(release, "NPM_TYPESCRIPT", typescript),
        ):
            self.assertTrue(release.npm_problems("1.2.3-rc.1"))
            release.set_npm_version("1.2.3-rc.1")
            self.assertEqual(release.npm_problems("1.2.3-rc.1"), [])
            alias = json.loads((node / "alias" / "package.json").read_text(encoding="utf-8"))
            self.assertEqual(alias["dependencies"], {"@opentide/opentide": "1.2.3-rc.1"})
            # A native package left behind at another version fails the check.
            native = min((node / "npm").iterdir()) / "package.json"
            manifest = json.loads(native.read_text(encoding="utf-8"))
            manifest["version"] = "1.2.2"
            native.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(
                release.npm_problems("1.2.3-rc.1"),
                [f"{manifest['name']} is at 1.2.2, not 1.2.3-rc.1"],
            )
            # A CI build's development version (ci.yml's `packages` artifacts).
            release.set_npm_version("1.2.3-dev.42")
            self.assertEqual(release.npm_problems("1.2.3-dev.42"), [])
            for bad in ["1.2", "1.2.3-dev.0", "1.2.3-beta.1", "v1.2.3"]:
                with self.subTest(version=bad), self.assertRaises(SystemExit):
                    release.set_npm_version(bad)

    def test_the_wasi_host_is_released_at_the_version_of_the_rest(self) -> None:
        # @opentide/wasi-host speaks the serve protocol of the opentide it
        # ships with: the extension pins it with the .wasm, so it carries the
        # release's one version, as the language server's packages do.
        names = {
            json.loads((d / "package.json").read_text(encoding="utf-8"))["name"]: d
            for d in release.npm_packages()
        }
        self.assertIn("@opentide/wasi-host", names)
        self.assertEqual(names["@opentide/wasi-host"], release.ROOT / "packages" / "wasi-host")
        # The tree keeps the TypeScript packages at one placeholder of their own.
        versions = {
            json.loads((d / "package.json").read_text(encoding="utf-8"))["version"]
            for d in release.NPM_TYPESCRIPT
        }
        self.assertEqual(len(versions), 1, versions)
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        node = root / "bindings" / "node"
        shutil.copytree(release.NPM_NODE / "npm", node / "npm")
        shutil.copy(release.NPM_NODE / "package.json", node / "package.json")
        (node / "alias").mkdir()
        shutil.copy(release.NPM_NODE / "alias" / "package.json", node / "alias" / "package.json")
        typescript = []
        for source in release.NPM_TYPESCRIPT:
            target = root / "packages" / source.name
            target.mkdir(parents=True)
            shutil.copy(source / "package.json", target / "package.json")
            typescript.append(target)
        with (
            mock.patch.object(release, "NPM_NODE", node),
            mock.patch.object(release, "NPM_TYPESCRIPT", typescript),
        ):
            release.set_npm_version("1.2.3")
            host = root / "packages" / "wasi-host" / "package.json"
            self.assertEqual(json.loads(host.read_text(encoding="utf-8"))["version"], "1.2.3")
            self.assertEqual(release.npm_problems("1.2.3"), [])
            # Left behind at another version, it fails the lockstep check.
            manifest = json.loads(host.read_text(encoding="utf-8"))
            manifest["version"] = "1.2.2"
            host.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(
                release.npm_problems("1.2.3"), ["@opentide/wasi-host is at 1.2.2, not 1.2.3"]
            )

    def test_no_musl_package(self) -> None:
        names = [d.name for d in release.npm_native_dirs()]
        self.assertEqual(len(names), len(release.TARGETS))
        self.assertFalse([n for n in names if "musl" in n])
        self.assertFalse([t for t in release.TARGETS if "musl" in t])


WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "publish.yml"
BUILD = WORKFLOWS / "engine-release-build.yml"
PACKAGES = WORKFLOWS / "build-packages.yml"


def workflow_jobs(path: Path = WORKFLOW) -> dict[str, str]:
    """Each job of a workflow as its lines, comments left out: the job keys
    are the two-space-indented keys under `jobs:` (no YAML parser, which the
    CI Python lacks)."""
    text = path.read_text(encoding="utf-8")
    jobs: dict[str, list[str]] = {}
    name = None
    for line in text.split("\njobs:\n", 1)[1].splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            name = match.group(1)
            jobs[name] = []
        elif name is not None:
            jobs[name].append(line)
    return {job: "\n".join(lines) for job, lines in jobs.items()}


def all_jobs() -> dict[str, str]:
    """The jobs of the release workflow and the two it calls; their names do
    not collide."""
    release, build, packages = (
        workflow_jobs(WORKFLOW),
        workflow_jobs(BUILD),
        workflow_jobs(PACKAGES),
    )
    assert not release.keys() & build.keys(), release.keys() & build.keys()
    assert not release.keys() & packages.keys(), release.keys() & packages.keys()
    assert not build.keys() & packages.keys(), build.keys() & packages.keys()
    return {**release, **build, **packages}


def workflow_header(path: Path = WORKFLOW) -> str:
    return path.read_text(encoding="utf-8").split("\njobs:\n", 1)[0]


# language-server v0.11.0's GitHub Release (its SHA256SUMS, and SHA256SUMS),
# without the musl binaries: no musl build ships (the maintainer's decision).
V0_11_0_ASSETS = [
    "LICENSE",
    "NOTICE",
    "SHA256SUMS",
    "THIRD-PARTY-LICENSES.html",
    "WASI-LIBC-LICENSES.txt",
    "highlights-v0.11.0.zip",
    "opentide-lsp-v0.11.0-aarch64-apple-darwin",
    "opentide-lsp-v0.11.0-aarch64-pc-windows-msvc.exe",
    "opentide-lsp-v0.11.0-aarch64-unknown-linux-gnu",
    "opentide-lsp-v0.11.0-x86_64-apple-darwin",
    "opentide-lsp-v0.11.0-x86_64-pc-windows-msvc.exe",
    "opentide-lsp-v0.11.0-x86_64-unknown-linux-gnu",
    "opentide-lsp-wasm32-wasip1.wasm",
    "opentide-wasm-web-v0.11.0.zip",
]

# What the release train adds: the `opentide` binaries, their installers, and
# the SBOMs scripts/engine/sbom.py writes.
PRODUCT_ASSETS = [
    "opentide-v0.11.0-aarch64-apple-darwin",
    "opentide-v0.11.0-aarch64-pc-windows-msvc.exe",
    "opentide-v0.11.0-aarch64-unknown-linux-gnu",
    "opentide-v0.11.0-x86_64-apple-darwin",
    "opentide-v0.11.0-x86_64-pc-windows-msvc.exe",
    "opentide-v0.11.0-x86_64-unknown-linux-gnu",
    "opentide-installer.sh",
    "opentide-installer.ps1",
]
SBOM_ASSETS = [
    "opentide-lsp.cdx.json",
    "opentide-wasm.cdx.json",
    "opentide-lsp-client.cdx.json",
    "opentide-lsp-worker.cdx.json",
    "opentide-wasi-host.cdx.json",
    "opentide.cdx.json",
    "opentide-node.cdx.json",
    "opentide-wheel.cdx.json",
]


class TagTest(unittest.TestCase):
    def test_release_tags_and_release_candidates(self) -> None:
        self.assertEqual(release.parse_tag("v0.24.0"), ("0.24.0", None))
        self.assertEqual(release.parse_tag("v0.24.1-rc.1"), ("0.24.1", 1))
        self.assertEqual(release.parse_tag("v1.2.3-rc.12"), ("1.2.3", 12))
        self.assertEqual(release.asset_version("v0.24.1-rc.1"), "v0.24.1-rc.1")

    def test_an_engine_tag_or_a_malformed_one_is_refused(self) -> None:
        # The engine's own tag series ended with the release train.
        for tag in [
            "engine-v0.11.0",
            "0.11.0",
            "v0.11",
            "v0.11.0-rc.0",
            "v0.11.0-beta.1",
            "v0.11.0-rc.1x",
            "v0.11.0\n",
        ]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.parse_tag(tag)

    def test_the_asset_set_is_language_servers_last_with_the_trains_additions(self) -> None:
        # language-server's assets keep their names (editors pin them); the
        # musl binaries are gone, the `opentide` binaries, installers and
        # SBOMs (#843) are new.
        names = V0_11_0_ASSETS + PRODUCT_ASSETS + SBOM_ASSETS
        self.assertEqual(sorted(release.expected_assets("v0.11.0")), sorted(names))
        rc = release.expected_assets("v0.11.1-rc.1")
        self.assertEqual(sorted(rc), sorted(a.replace("v0.11.0", "v0.11.1-rc.1") for a in names))
        self.assertFalse([a for a in rc if "musl" in a])

    def test_check_assets_names_what_is_missing_or_extra(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for name in release.expected_assets("v1.0.0"):
            (tmp / name).write_bytes(b"x")
        self.assertEqual(release.check_assets(tmp, "v1.0.0"), [])
        # The same files are the wrong set for another version.
        self.assertTrue(release.check_assets(tmp, "v1.0.1"))
        (tmp / "opentide-lsp-v1.0.0-x86_64-apple-darwin").unlink()
        (tmp / "stray.txt").write_bytes(b"x")
        self.assertEqual(
            release.check_assets(tmp, "v1.0.0"),
            [
                "missing asset: opentide-lsp-v1.0.0-x86_64-apple-darwin",
                "unexpected asset: stray.txt",
            ],
        )

    def test_check_matches_the_workspace(self) -> None:
        with (
            mock.patch.object(release, "workspace_version", return_value="1.2.3"),
            mock.patch.object(release, "internal_pins", return_value={"opentide-core": "=1.2.3"}),
        ):
            self.assertEqual(release.check("v1.2.3-rc.1"), [])
            self.assertEqual(release.check("v1.2.3"), [])
            self.assertEqual(len(release.check("v1.2.4-rc.1")), 2)
            self.assertEqual(len(release.check("engine-v1.2.3")), 1)

    def test_the_cli_prints_the_tag_and_whether_it_is_a_candidate(self) -> None:
        script = str(Path(release.__file__))
        run = [sys.executable, script]

        def out(*args: str) -> str:
            done = subprocess.run([*run, *args], capture_output=True, text=True, check=True)
            return done.stdout.strip()

        self.assertEqual(out("tag"), f"v{release.workspace_version()}")
        self.assertEqual(out("prerelease", "v1.0.0"), "false")
        self.assertEqual(out("prerelease", "v1.0.0-rc.3"), "true")
        self.assertEqual(out("asset-version", "v1.0.0"), "v1.0.0")
        self.assertIn("the crates are at", out("lockstep", release.workspace_version()))
        bad = subprocess.run(
            [*run, "prerelease", "engine-v1.0.0"], capture_output=True, text=True, check=False
        )
        self.assertEqual(bad.returncode, 1)

    def test_the_cli_fails_on_a_missing_or_an_extra_asset(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for name in release.expected_assets("v1.0.0"):
            (tmp / name).write_bytes(b"x")
        run = [sys.executable, str(Path(release.__file__)), "check-assets", str(tmp)]
        ok = subprocess.run([*run, "v1.0.0"], capture_output=True, text=True, check=False)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        (tmp / "stray.txt").write_bytes(b"x")
        extra = subprocess.run([*run, "v1.0.0"], capture_output=True, text=True, check=False)
        self.assertEqual(extra.returncode, 1)
        self.assertIn("unexpected asset: stray.txt", extra.stderr)
        (tmp / "stray.txt").unlink()
        (tmp / "NOTICE").unlink()
        missing = subprocess.run([*run, "v1.0.0"], capture_output=True, text=True, check=False)
        self.assertEqual(missing.returncode, 1)
        self.assertIn("missing asset: NOTICE", missing.stderr)

    def test_the_native_matrix_builds_every_target(self) -> None:
        native = workflow_jobs(BUILD)["native"]
        built = re.findall(r"^\s+target: (\S+)$", native, re.MULTILINE)
        self.assertEqual(built, release.TARGETS)
        npm = workflow_jobs(PACKAGES)["npm-native"]
        self.assertEqual(
            sorted(re.findall(r"^\s+target: (\S+)$", npm, re.MULTILINE)), sorted(release.TARGETS)
        )
        platforms = re.findall(r"^\s+platform: (\S+)$", npm, re.MULTILINE)
        self.assertEqual(sorted(platforms), [d.name for d in release.npm_native_dirs()])


# A target: a name, or an expression such as `${{ matrix.target }}`.
TARGET = r"\$\{\{[^}]*\}\}|[^\s$-]\S*"


def targets_added(body: str) -> set[str]:
    """The targets a job's `rustup target add` lines add."""
    return {
        name
        for listed in re.findall(rf"rustup target add((?: (?:{TARGET}))+)", body)
        for name in re.findall(TARGET, listed)
    }


class ReleaseWorkflowTest(unittest.TestCase):
    def test_targets_added_reads_names_and_expressions(self) -> None:
        body = (
            "rustup target add ${{ matrix.target }}\n"
            "rustup target add wasm32-unknown-unknown wasm32-wasip1\n"
            "rustup toolchain install --target thumbv6m-none-eabi\n"
        )
        self.assertEqual(
            targets_added(body),
            {"${{ matrix.target }}", "wasm32-unknown-unknown", "wasm32-wasip1"},
        )

    def test_only_attest_and_the_registries_can_mint_an_oidc_token(self) -> None:
        # crates.io and npm trust publish.yml as a whole: a token from any job
        # of it publishes.
        jobs = workflow_jobs()
        minting = sorted(job for job, body in jobs.items() if "id-token: write" in body)
        self.assertEqual(minting, ["attest", "crates", "npm", "pypi"])
        self.assertNotIn("id-token", workflow_header())
        for job in minting:
            # Every job states its permissions, so none inherits a token.
            self.assertIn("permissions:", jobs[job], job)
        # The asset and package builds, which ci.yml also runs, hold none.
        self.assertNotIn("id-token", BUILD.read_text(encoding="utf-8"))
        self.assertNotIn("id-token", PACKAGES.read_text(encoding="utf-8"))
        self.assertNotIn("secrets.", PACKAGES.read_text(encoding="utf-8"))
        self.assertRegex(jobs["packages"], r"permissions:\n      contents: read\n")
        self.assertRegex(jobs["release-assets"], r"permissions:\n      contents: read\n")
        # There is no crates dry-run job: a candidate's crates are published.
        self.assertNotIn("crates-dry-run", jobs)

    def test_every_rust_job_installs_the_pinned_release_with_the_targets_it_builds(
        self,
    ) -> None:
        # cargo in the checkout runs the release rust-toolchain.toml pins, whatever
        # the runner's default is: a toolchain installed by name (`stable`, with the
        # job's targets) would leave that release without them. rustup ignores
        # `--target` and `--component` on an install with no name, so each target
        # a job builds comes from `rustup target add`, which with no toolchain
        # named adds it to the pinned release. (A build from the sdist, which
        # leaves the pin out, runs pip with the runner's Rust, as a user's does.)
        # The package builds (build-packages.yml) are stricter: they run
        # scripts/build/install-rust.sh, which installs that release by name
        # with the minimal profile, without the file's components, adds the
        # target and names the release in RUSTUP_TOOLCHAIN, so that rustup
        # installs nothing mid-build (tests/test_ci/test_workflows.py).
        install = "rustup toolchain install --profile minimal --no-self-update"
        script = "scripts/build/install-rust.sh"
        target = r"--target (\$\{\{[^}]*\}\}|\S+)"
        jobs = all_jobs()
        built: dict[str, set[str]] = {}
        rust = sorted(
            job
            for job, body in jobs.items()
            if re.search(
                r"\bcargo (?:build|run|install|package|publish)\b|build-wasm\.sh|build\.mjs"
                r"|release\.py (?:vendor|publish)",
                body,
            )
        )
        self.assertEqual(
            rust,
            [
                "checks",
                "crates",
                "highlights",
                "licences",
                "native",
                "npm-native",
                "sbom",
                "smoke-cargo",
                "smoke-registries",
                "wasm",
            ],
        )
        by_script = sorted(job for job, body in jobs.items() if script in body)
        self.assertEqual(by_script, ["npm-native", "wheels"])
        # npm-native cross-compiles: the script adds its target.
        self.assertIn(f'{script} "${{TARGET}}"', jobs["npm-native"])
        for job, body in jobs.items():
            self.assertNotIn("dtolnay/rust-toolchain", body, job)
            self.assertNotRegex(body, r"rustup (?:default|override)|cargo \+", job)
            installs = re.findall(r"rustup toolchain install(.*)", body)
            expected = 1 if job in rust and job not in by_script else 0
            self.assertEqual(len(installs), expected, (job, installs))
            if not installs:
                continue
            # No toolchain name and nothing rustup would ignore: the bare install
            # of the one rust-toolchain.toml pins.
            self.assertEqual(f"rustup toolchain install{installs[0]}".strip(), install, job)
            added = targets_added(body)
            self.assertFalse(re.search(r"rustup target add.* (?:--toolchain|\+)", body), job)
            built[job] = {
                name
                for line in body.splitlines()
                if re.search(r"\bcargo (?:build|run|clippy|test|check|package)\b", line)
                for name in re.findall(target, line)
            }
            self.assertLessEqual(built[job], added, job)
        # The matrix build cross-compiles for x86_64-apple-darwin and the like.
        self.assertEqual(built["native"], {"${{ matrix.target }}"})
        # npm-native adds its target through the script, with TARGET its matrix's.
        self.assertIn("TARGET: ${{ matrix.target }}", jobs["npm-native"])
        # build-wasm.sh adds its own targets, but the job states them.
        self.assertEqual(targets_added(jobs["wasm"]), {"wasm32-unknown-unknown", "wasm32-wasip1"})

    def test_native_adds_its_target_to_the_pinned_toolchain(self) -> None:
        # rust-toolchain.toml pins the compiler, so a target installed for
        # another toolchain (dtolnay's `targets:` on stable) is not the one
        # cargo builds with: the cross builds failed with "can't find crate
        # for `std`" (v0.13.0). The target is added with rustup in the checkout.
        native = all_jobs()["native"]
        self.assertIn("rustup target add ${{ matrix.target }}", native)
        self.assertNotRegex(native, r"targets:\s*\$\{\{ matrix\.target \}\}")
        self.assertLess(native.index("actions/checkout"), native.index("rustup target add"))

    def test_the_attest_job_builds_and_runs_nothing(self) -> None:
        attest = workflow_jobs()["attest"]
        steps = attest[attest.index("    steps:") :]
        self.assertNotIn("run:", steps)
        self.assertNotRegex(steps, r"\bcargo\b")
        self.assertNotIn("actions/checkout", attest)
        uses = {u.split("@")[0] for u in re.findall(r"uses: (\S+)", attest)}
        self.assertEqual(uses, {"actions/download-artifact", "actions/attest-build-provenance"})
        # Every artifact: the Release's assets, the wheels and sdist, the
        # crates and the npm tarballs.
        subjects = ["dist/release/*", "dist/python/*", "dist/crates/*.crate", "dist/npm/*/*.tgz"]
        for subject in subjects:
            self.assertIn(subject, attest)

    def test_nothing_publishes_before_every_smoke_test_passed(self) -> None:
        jobs = workflow_jobs()
        needs = re.search(r"^    needs: \[(.*)\]$", jobs["attest"], re.MULTILINE)
        assert needs is not None
        smokes = sorted(
            job for job in jobs if job.startswith("smoke-") and job != "smoke-registries"
        )
        self.assertEqual(
            smokes, ["smoke-cargo", "smoke-installer", "smoke-npm", "smoke-sdist", "smoke-wheel"]
        )
        self.assertLessEqual(set(smokes), set(needs.group(1).split(", ")))
        # A dry run and an internal candidate stop before attest, and so
        # before every write after it.
        self.assertIn(
            "if: needs.guard.outputs.channel == 'release' || needs.guard.outputs.channel == 'rc'",
            jobs["attest"],
        )
        self.assertIn("needs.attest.result == 'success'", jobs["verify-assets"])

    def test_the_npm_smoke_installs_from_a_local_registry(self) -> None:
        jobs = workflow_jobs()
        smoke = jobs["smoke-npm"]
        self.assertIn("os: [ubuntu-latest, macos-latest, windows-latest]", smoke)
        self.assertIn(
            'node scripts/engine/npm-local-registry/test.mjs --version "${NPM_VERSION}" '
            '--tarballs "${RUNNER_TEMP}/npm"',
            smoke,
        )
        # The registry is the script's own: the job publishes nothing itself
        # and cannot mint the token npm's trusted publishing needs.
        self.assertNotRegex(smoke, r"\bnpm (?:publish|pu)\b")
        self.assertNotIn("id-token", smoke)
        # Every native package ships the licence, which the pack checks.
        pack = workflow_jobs(PACKAGES)["npm-pack"]
        self.assertIn('cp bindings/node/LICENSE "${dir}"', pack)
        self.assertIn("grep -qx 'package/LICENSE'", pack)
        # ci.yml's full set runs the same test on the tree's packages.
        ci = workflow_jobs(WORKFLOWS / "ci.yml")["npm-install"]
        self.assertIn("node scripts/engine/npm-local-registry/test.mjs", ci)
        self.assertIn('--pack "${RUNNER_TEMP}/npm"', ci)
        self.assertIn('release.py npm-version "${version}"', ci)

    def test_the_local_registry_has_no_uplink_and_pinned_tools(self) -> None:
        here = Path(__file__).resolve().parent / "npm-local-registry"
        script = (here / "test.mjs").read_text(encoding="utf-8")
        self.assertIn("'uplinks: {}'", script)
        self.assertNotIn("proxy:", script)
        self.assertIn("'--listen', `127.0.0.1:${port}`", script)
        manifest = json.loads((here / "package.json").read_text(encoding="utf-8"))
        self.assertTrue(manifest["private"])
        lock = json.loads((here / "package-lock.json").read_text(encoding="utf-8"))
        root = lock["packages"][""]["dependencies"]
        self.assertEqual(root, manifest["dependencies"])
        for name, version in manifest["dependencies"].items():
            # Exact versions, and the lock holds those.
            self.assertRegex(version, r"^\d+\.\d+\.\d+$", name)
            self.assertEqual(lock["packages"][f"node_modules/{name}"]["version"], version)
        for path, entry in lock["packages"].items():
            if path:
                self.assertTrue(entry["resolved"].startswith("https://registry.npmjs.org/"), path)
                self.assertTrue(entry["integrity"].startswith("sha512-"), path)

    def test_cargo_about_runs_without_an_oidc_token(self) -> None:
        jobs = all_jobs()
        builds = [job for job, body in jobs.items() if "cargo install" in body]
        self.assertTrue(builds)
        for job in builds:
            self.assertNotIn("id-token", jobs[job], job)

    def test_the_registries_publish_only_once_the_published_assets_verified(self) -> None:
        jobs = workflow_jobs()
        verify_assets = jobs["verify-assets"]
        self.assertIn("sha256sum", verify_assets)
        self.assertIn("gh attestation verify", verify_assets)
        # It runs when resuming too, when the release job is skipped.
        self.assertIn("needs.release.result == 'skipped'", verify_assets)
        for job in ["pypi", "crates", "npm"]:
            needs = re.search(r"^    needs: \[(.*)\]$", jobs[job], re.MULTILINE)
            self.assertIsNotNone(needs, job)
            self.assertIn("verify-assets", needs.group(1).split(", "), job)
            # The implicit success(): every job it needs succeeded.
            self.assertNotIn("always()", jobs[job], job)
            self.assertNotIn("!cancelled()", jobs[job], job)
        # The release job does not check: verify-assets does, for both paths.
        self.assertNotIn("gh attestation verify", jobs["release"])

    def test_a_release_candidate_is_a_pre_release_on_github_pypi_and_crates_io(self) -> None:
        """For the Rust-core transition: a candidate publishes pre-releases on
        GitHub, PyPI and crates.io, and nothing on npm."""
        jobs = workflow_jobs()
        # crates.io: every crate at X.Y.Z-rc.N, a pre-release, as for a release
        # (never for an internal candidate or a dry run).
        self.assertRegex(
            jobs["crates"],
            r"\n    if: needs\.guard\.outputs\.channel == 'release' "
            r"\|\| needs\.guard\.outputs\.channel == 'rc'\n",
        )
        bump = 'python3 scripts/engine/release.py bump "${VERSION}"'
        for job in ["checks", "crates"]:
            body = jobs[job]
            self.assertIn("if: needs.guard.outputs.version != needs.guard.outputs.base", body)
            self.assertIn("VERSION: ${{ needs.guard.outputs.version }}", body)
            # Before anything is packaged or published.
            self.assertLess(body.index(bump), body.index("release.py vendor"), job)
        self.assertLess(
            jobs["crates"].index(bump),
            jobs["crates"].index("python3 scripts/engine/release.py publish"),
        )
        self.assertIn(
            '--path "${RUNNER_TEMP}/packages/opentide-${CRATES_VERSION}"', jobs["smoke-cargo"]
        )
        self.assertIn("CRATES_VERSION: ${{ needs.guard.outputs.version }}", jobs["smoke-cargo"])
        # PyPI: real PyPI, the one environment; no TestPyPI anywhere.
        self.assertRegex(jobs["pypi"], r"environment:\n      name: pypi\n")
        self.assertNotIn("test.pypi.org", WORKFLOW.read_text(encoding="utf-8"))
        self.assertNotIn("testpypi", WORKFLOW.read_text(encoding="utf-8"))
        publish_step = jobs["pypi"][jobs["pypi"].index("- name: Publish to PyPI") :]
        publish_step = publish_step[: publish_step.index("- name:", 1)]
        self.assertNotIn("if:", publish_step)
        # npm: a release only, under `latest`.
        self.assertIn("if: needs.guard.outputs.channel == 'release'", jobs["npm"])
        self.assertIn("--provenance --access public --tag latest", jobs["npm"])
        self.assertNotIn("next", jobs["npm"])
        smoke = jobs["smoke-registries"]
        self.assertIn("needs.npm.result == 'skipped' && needs.guard.outputs.channel == 'rc'", smoke)
        npx = smoke[smoke.index("- name: npx @opentide/opentide --version") :]
        self.assertIn("if: env.CHANNEL == 'release'", npx.splitlines()[1])
        self.assertIn('cargo install opentide --version "=${VERSION}"', smoke)
        # GitHub: a pre-release, never Latest; a release is Latest by default.
        attach = jobs["release"]
        self.assertIn("flags+=(--prerelease --latest=false)", attach)
        self.assertIn('"${flags[@]}"', attach)

    def test_the_release_ships_the_set_the_asset_build_checked(self) -> None:
        assets = workflow_jobs(BUILD)["assets"]
        lines = [line.strip() for line in assets.splitlines()]
        # Whole lines in a `set -euo pipefail` step: nothing turns a failure into a pass.
        for gate in [
            'python3 scripts/engine/release.py check-assets dist "${TAG}"',
            "python3 scripts/engine/release.py verify-sums dist",
        ]:
            self.assertIn(gate, lines)
        self.assertIn("set -euo pipefail", lines)
        for job in [assets, workflow_jobs()["verify-assets"]]:
            self.assertNotRegex(job, r"\|\|\s*(?:true|:)\b")
        self.assertLess(assets.index("release.py sums dist"), assets.index("check-assets"))
        self.assertIn("name: release-assets", assets)
        for job in ["attest", "release"]:
            self.assertIn("name: release-assets", workflow_jobs()[job], job)

    def test_the_licence_scan_reads_every_engine_asset_in_full(self) -> None:
        assets = workflow_jobs(BUILD)["assets"]
        lines = [line.strip() for line in assets.splitlines()]
        self.assertIn("bash scripts/engine/license-scan.sh dist", lines)
        # Only the product's files (the `opentide` binaries, which carry the
        # package's data) are scanned as a product, and before they join dist.
        self.assertLess(
            assets.index("license-scan.sh --product"), assets.index("mv product/* dist/")
        )

    def test_a_released_tag_is_never_uploaded_again(self) -> None:
        attach = workflow_jobs()["release"]
        guard = attach.index('python3 scripts/engine/release.py unpublished "${TAG}"')
        self.assertLess(guard, attach.index("gh release create"))
        self.assertNotIn("gh release upload", attach)
        self.assertNotIn("--clobber", attach)
        self.assertNotIn("delete-asset", attach)

    def test_run_workflow_releases_from_development_only(self) -> None:
        guard = workflow_jobs()["guard"]
        refuse = guard.index("Run the release from development, not")
        self.assertLess(guard.index('"${GITHUB_REF}" != "refs/heads/development" ]]'), refuse)
        self.assertEqual(guard[refuse:].splitlines()[1].strip(), "exit 1")
        # A candidate may also run from integration/unified-core, and from
        # nowhere else; check-candidate still holds it above the last release.
        candidate = guard.index('if [[ -z "${RELEASE_CANDIDATE}" ]]; then')
        self.assertLess(candidate, refuse)
        refuse_rc = guard.index(
            "Run a release candidate from integration/unified-core or development, not"
        )
        self.assertLess(
            guard.index(
                '"${GITHUB_REF}" != "refs/heads/integration/unified-core" && '
                '"${GITHUB_REF}" != "refs/heads/development"'
            ),
            refuse_rc,
        )
        self.assertEqual(guard[refuse_rc:].splitlines()[1].strip(), "exit 1")
        self.assertLess(refuse_rc, guard.index("check-candidate", refuse_rc))
        # An internal candidate: the same two branches, and check-candidate.
        refuse_internal = guard.index(
            "Run an internal candidate from integration/unified-core or development, not"
        )
        self.assertEqual(guard[refuse_internal:].splitlines()[1].strip(), "exit 1")
        self.assertLess(refuse_internal, guard.index("check-candidate", refuse_internal))
        # A public candidate is refused while the internal channel exists.
        self.assertIn("public_candidates=false", guard)
        self.assertLess(guard.index("public release candidates are disabled", candidate), refuse_rc)
        # A release or a candidate never reuses a tag; resuming one needs its Release.
        self.assertIn('git rev-parse -q --verify "refs/tags/${tag}"', guard)
        self.assertIn("has no GitHub Release to resume", guard)
        # One product version: the crates are at the tag's.
        self.assertIn('python scripts/engine/release.py lockstep "${base}"', guard)
        self.assertIn('python scripts/build/release.py check "${tag}"', guard)
        self.assertIn('python scripts/build/release.py check-candidate "${tag}"', guard)

    def test_verify_assets_may_read_the_attestations_and_write_nothing(self) -> None:
        verify_assets = workflow_jobs()["verify-assets"]
        permissions = re.search(
            r"^    permissions:\n((?:      .*\n)+)", verify_assets + "\n", re.MULTILINE
        )
        assert permissions is not None, "verify-assets states its permissions"
        self.assertEqual(
            sorted(permissions.group(1).split()),
            sorted(["contents:", "read", "attestations:", "read"]),
        )

    def test_the_published_assets_are_checked_against_every_line_of_the_sums(self) -> None:
        verify_assets = workflow_jobs()["verify-assets"]
        self.assertIn("python3 scripts/engine/release.py verify-sums published", verify_assets)

    def test_every_attestation_check_names_the_release_workflow(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        readme = (WORKFLOW.parents[2] / "crates" / "opentide-lsp" / "README.md").read_text(
            encoding="utf-8"
        )
        for source in [text, readme]:
            checks = re.findall(r"gh attestation verify (?:[^\n]*\\\n)*[^\n]*", source)
            self.assertTrue(checks)
            for check in checks:
                self.assertIn("--cert-identity-regex", check)

    @staticmethod
    def _identity(channel: str) -> re.Pattern[str]:
        lines = [
            line.strip()
            for line in workflow_jobs()["verify-assets"].splitlines()
            if re.match(r"\s*(?:repo_re|branch_re|identity)=", line)
            or re.match(r'\s*if \[ "\$\{CHANNEL\}" = "rc" \]; then branch_re=', line)
        ]
        assert len(lines) == 4, lines
        script = "\n".join([*lines, 'printf %s "$identity"'])
        env = {"GITHUB_REPOSITORY": "opentidehq/opentide", "TAG": "v1.2.3", "CHANNEL": channel}
        env["PATH"] = "/usr/bin:/bin"
        done = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, env=env, check=True
        )
        return re.compile(done.stdout)

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_a_candidates_identity_is_publish_yml_on_integration_or_development(self) -> None:
        identity = self._identity("rc")
        workflows = "https://github.com/opentidehq/opentide/.github/workflows"
        workflow = f"{workflows}/publish.yml"
        for branch in ["development", "integration/unified-core"]:
            self.assertTrue(identity.fullmatch(f"{workflow}@refs/heads/{branch}"), branch)
        for other in [
            f"{workflow}@refs/heads/main",
            f"{workflow}@refs/heads/feature",
            f"{workflow}@refs/heads/integration/unified-core-x",
            f"{workflow}@refs/heads/integration/other",
            f"{workflow}@refs/tags/v1.2.3-rc.1",
            f"{workflows}/ci.yml@refs/heads/integration/unified-core",
            workflow.replace("opentidehq", "someone") + "@refs/heads/integration/unified-core",
        ]:
            self.assertIsNone(identity.fullmatch(other), (identity.pattern, other))

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_the_identity_is_publish_yml_on_development(self) -> None:
        identity = self._identity("release")
        readme = (WORKFLOW.parents[2] / "crates" / "opentide-lsp" / "README.md").read_text(
            encoding="utf-8"
        )
        found = re.search(r"--cert-identity-regex '([^']+)'", readme)
        assert found is not None, "README.md documents the identity"
        documented = re.compile(found.group(1))
        workflows = "https://github.com/opentidehq/opentide/.github/workflows"
        workflow = f"{workflows}/publish.yml"
        for pattern in [identity, documented]:
            self.assertTrue(
                pattern.fullmatch(f"{workflow}@refs/heads/development"), pattern.pattern
            )
            for other in [
                f"{workflow}@refs/heads/main",
                f"{workflow}@refs/heads/feature",
                f"{workflow}@refs/heads/integration/unified-core",
                f"{workflow}@refs/tags/v1.2.3",
                f"{workflows}/ci.yml@refs/heads/development",
                f"{workflows}/engine-release-build.yml@refs/heads/development",
                f"{workflows}/engine-release.yml@refs/heads/development",
                workflow.replace("opentidehq", "someone") + "@refs/heads/development",
                "https://github.com/opentidehq/language-server/.github/workflows/release.yml"
                "@refs/heads/main",
            ]:
                self.assertIsNone(pattern.fullmatch(other), (pattern.pattern, other))


if __name__ == "__main__":
    unittest.main()
