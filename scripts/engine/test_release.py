"""Tests for scripts/engine/release.py (tags, the asset set, checksums, the one
version) and for the shape of the release train, .github/workflows/publish.yml,
and the release pipeline it shares with ci.yml, release-pipeline.yml
(language-server#196, opentide#801, #840).

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path
from unittest import mock

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

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


class LegalFilesTest(unittest.TestCase):
    """Every package that carries the engine ships NOTICE and the licence files it
    cites, at the paths it names (#1753)."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        for rel, text in {
            "LICENSE": "eupl\n",
            "NOTICE": "ECS (data/catalogs/ecs/LICENSE.txt,\ndata/catalogs/ecs/NOTICE)\n",
            "data/catalogs/ecs/LICENSE.txt": "apache\n",
            "data/catalogs/ecs/NOTICE": "elastic\n",
        }.items():
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_text(text, encoding="utf-8")
        patcher = mock.patch.object(release, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_cited_files_follow_license_and_notice(self) -> None:
        self.assertEqual(
            release.legal_files(),
            ["LICENSE", "NOTICE", "data/catalogs/ecs/LICENSE.txt", "data/catalogs/ecs/NOTICE"],
        )

    def test_copy_then_remove_leaves_the_directory_as_it_was(self) -> None:
        package = self.root / "pkg"
        package.mkdir()
        (package / "index.js").write_text("", encoding="utf-8")
        release.copy_legal(package)
        self.assertEqual(
            (package / "data/catalogs/ecs/LICENSE.txt").read_text(encoding="utf-8"), "apache\n"
        )
        release.remove_legal(package)
        self.assertEqual(sorted(p.name for p in package.iterdir()), ["index.js"])

    def test_a_cited_file_that_does_not_exist_stops_the_copy(self) -> None:
        (self.root / "data/catalogs/ecs/NOTICE").unlink()
        with self.assertRaises(SystemExit):
            release.copy_legal(self.root / "pkg")

    def test_the_bundle_holds_each_cited_file_under_its_path(self) -> None:
        target = self.root / "bundle.txt"
        self.assertEqual(
            release.legal_bundle(target),
            ["data/catalogs/ecs/LICENSE.txt", "data/catalogs/ecs/NOTICE"],
        )
        self.assertEqual(
            target.read_text(encoding="utf-8"),
            "==> data/catalogs/ecs/LICENSE.txt <==\n\napache\n\n"
            "==> data/catalogs/ecs/NOTICE <==\n\nelastic\n\n",
        )

    def test_the_release_builds_and_checks_the_bundle(self) -> None:
        jobs = workflow_jobs(PIPELINE)
        bundle = "release.py legal-bundle legal/THIRD-PARTY-DATA-LICENSES.txt"
        self.assertIn(bundle, jobs["sources"])
        self.assertIn("release.py legal pkg", jobs["wasm"])
        self.assertIn(release.DATA_LICENSES, release.FIXED_ASSETS)

    def test_the_repository_ships_every_file_its_notice_cites(self) -> None:
        patcher = mock.patch.object(release, "ROOT", Path(__file__).resolve().parents[2])
        patcher.start()
        self.addCleanup(patcher.stop)
        files = release.legal_files()
        self.assertIn("data/catalogs/carbon_black/NOTICE", files)
        self.assertTrue(all((release.ROOT / rel).is_file() for rel in files), files)


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

    def gh_sequence(self, *answers: tuple[int, str, str]) -> mock.MagicMock:
        done = [
            subprocess.CompletedProcess([], code, stdout=out, stderr=err)
            for code, out, err in answers
        ]
        return mock.patch.object(release.subprocess, "run", side_effect=done)

    def test_an_untagged_draft_a_failed_release_left_is_deleted(self) -> None:
        # The draft, then the tag's ref: 404, then the delete.
        with self.gh_sequence(
            (0, json.dumps({"isDraft": True, "publishedAt": None}), ""),
            (1, "", "gh: Not Found (HTTP 404)\n"),
            (0, "", ""),
            (1, "", "release not found\n"),
        ) as run:
            self.assertTrue(release.delete_stale_draft("v1.0.0", "o/r"))
        delete = run.call_args_list[2].args[0]
        self.assertEqual(delete[:4], ["gh", "release", "delete", "v1.0.0"])
        self.assertNotIn("--cleanup-tag", delete)

    def test_two_stale_drafts_of_one_tag_are_both_deleted(self) -> None:
        draft = (0, json.dumps({"isDraft": True, "publishedAt": None}), "")
        gone = (1, "", "gh: Not Found (HTTP 404)\n")
        with self.gh_sequence(
            draft, gone, (0, "", ""), draft, gone, (0, "", ""), (1, "", "release not found\n")
        ) as run:
            self.assertTrue(release.delete_stale_draft("v1.0.0", "o/r"))
        self.assertEqual(run.call_count, 7)

    def test_a_published_release_whose_tag_was_deleted_is_kept(self) -> None:
        # GitHub turns it back into a draft; consumers may have pinned its assets.
        published = {"isDraft": True, "publishedAt": "2026-11-25T16:00:00Z"}
        with self.gh_sequence((0, json.dumps(published), "")) as run:
            self.assertFalse(release.delete_stale_draft("v1.0.0", "o/r"))
        self.assertEqual(run.call_count, 1)

    def test_a_tagged_draft_or_a_published_release_is_kept(self) -> None:
        # An internal candidate: a draft whose tag exists.
        with self.gh_sequence((0, json.dumps({"isDraft": True}), ""), (0, "{}", "")) as run:
            self.assertFalse(release.delete_stale_draft("v1.0.0-rc.6", "o/r"))
        self.assertEqual(run.call_count, 2)
        with self.gh_sequence((0, json.dumps({"isDraft": False}), "")) as run:
            self.assertFalse(release.delete_stale_draft("v1.0.0", "o/r"))
        self.assertEqual(run.call_count, 1)
        with self.gh_sequence((1, "", "release not found\n")):
            self.assertFalse(release.delete_stale_draft("v1.0.0", "o/r"))

    def test_an_outage_never_reads_as_no_tag(self) -> None:
        with (
            self.gh_sequence(
                (0, json.dumps({"isDraft": True}), ""), (1, "", "HTTP 502: Bad Gateway\n")
            ),
            self.assertRaises(RuntimeError),
        ):
            release.delete_stale_draft("v1.0.0", "o/r")

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


class RateLimitWaitTest(unittest.TestCase):
    """`publish` waits until the time crates.io names, not a fixed eleven minutes."""

    NOW = release.dt.datetime(2026, 11, 20, 12, 0, 0, tzinfo=release.dt.timezone.utc)
    MESSAGE = (
        "error: failed to publish to registry at https://crates.io\n\nCaused by:\n"
        "  the remote server responded with an error (status 429 Too Many Requests): "
        "You have published too many new crates in a short period of time. "
        "Please try again after {when} or email help@crates.io to have your limit increased."
    )

    def wait(self, when: str) -> int:
        return release.rate_limit_wait(self.MESSAGE.format(when=when), self.NOW)

    def test_the_named_time_plus_a_margin(self) -> None:
        self.assertEqual(
            self.wait("Fri, 20 Nov 2026 12:03:30 GMT"), 210 + release.RATE_LIMIT_MARGIN
        )

    def test_a_time_past_waits_the_margin_only(self) -> None:
        self.assertEqual(self.wait("Fri, 20 Nov 2026 11:00:00 GMT"), release.RATE_LIMIT_MARGIN)

    def test_a_far_time_is_capped(self) -> None:
        self.assertEqual(self.wait("Sat, 21 Nov 2026 12:00:00 GMT"), release.RATE_LIMIT_MAX_WAIT)

    def test_an_offset_is_honoured(self) -> None:
        self.assertEqual(
            self.wait("Fri, 20 Nov 2026 14:05:00 +0200"), 300 + release.RATE_LIMIT_MARGIN
        )

    def test_no_time_or_an_unreadable_one_falls_back_to_the_fixed_wait(self) -> None:
        for output in (
            "error: 429 Too Many Requests",
            "rate limit exceeded, please try again after a while",
            self.MESSAGE.format(when="Fri, 99 Nov 2026 12:03:30 GMT"),
            self.MESSAGE.format(when="Xyz, 20 Foo 2026 12:03:30 GMT"),
        ):
            with self.subTest(output=output):
                self.assertEqual(release.rate_limit_wait(output, self.NOW), release.RATE_LIMIT_WAIT)

    def test_publish_sleeps_for_the_named_time_and_flushes(self) -> None:
        limited = subprocess.CompletedProcess(
            [], 101, stdout="", stderr=self.MESSAGE.format(when="Fri, 20 Nov 2026 12:03:30 GMT")
        )
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        clock = release.dt.datetime(2026, 11, 20, 12, 0, 0, tzinfo=release.dt.timezone.utc)
        real_datetime = release.dt.datetime

        class FrozenDatetime(real_datetime):
            @classmethod
            def now(cls, tz=None):  # type: ignore[override]
                return clock

        printed: list[tuple[tuple, dict]] = []
        with (
            mock.patch.object(release, "workspace_version", return_value="1.0.0"),
            mock.patch.object(release, "publishable_crates", return_value=[{"name": "c"}]),
            mock.patch.object(release, "publish_order", side_effect=lambda c: c),
            mock.patch.object(release, "on_crates_io", return_value=False),
            mock.patch.object(release.dt, "datetime", FrozenDatetime),
            mock.patch.object(release.subprocess, "run", side_effect=[limited, done]),
            mock.patch.object(release.time, "sleep") as sleep,
            mock.patch("builtins.print", side_effect=lambda *a, **k: printed.append((a, k))),
        ):
            release.publish()
        sleep.assert_called_once_with(210 + release.RATE_LIMIT_MARGIN)
        self.assertTrue(printed)
        for args, kwargs in printed:
            self.assertTrue(kwargs.get("flush"), args)


class CreatedWithTokenTest(unittest.TestCase):
    """The workflow registers trusted publishing only when the trusted login
    failed or a crate was created with the stored token: `publish` says so."""

    def run_publish(self, results: list[subprocess.CompletedProcess], env: dict[str, str]):
        output = Path(tempfile.mkdtemp()) / "output"
        self.addCleanup(shutil.rmtree, output.parent)
        env = {**env, "GITHUB_OUTPUT": str(output)}
        with (
            mock.patch.dict(release.os.environ, env, clear=True),
            mock.patch.object(release, "workspace_version", return_value="1.0.0"),
            mock.patch.object(release, "publishable_crates", return_value=[{"name": "c"}]),
            mock.patch.object(release, "publish_order", side_effect=lambda c: c),
            mock.patch.object(release, "on_crates_io", return_value=False),
            mock.patch.object(release.subprocess, "run", side_effect=results),
        ):
            release.publish()
        return output.read_text(encoding="utf-8") if output.exists() else ""

    def test_a_crate_created_with_the_stored_token_is_noted(self) -> None:
        refused = subprocess.CompletedProcess(
            [], 101, stdout="", stderr=f"error: {release.NEW_CRATE_REFUSAL}"
        )
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        out = self.run_publish(
            [refused, done], {"CARGO_REGISTRY_TOKEN": "oidc", "NEW_CRATE_TOKEN": "stored"}
        )
        self.assertEqual(out, "created_with_token=true\n")

    def test_a_crate_published_with_the_trusted_token_is_not(self) -> None:
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        out = self.run_publish([done], {"CARGO_REGISTRY_TOKEN": "oidc", "NEW_CRATE_TOKEN": ""})
        self.assertEqual(out, "")


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
        fuzz = root / "fuzz"
        fuzz.mkdir()
        (fuzz / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        (fuzz / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        done = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(release, "WORKSPACE", workspace),
            mock.patch.object(release, "ROOT", root),
            mock.patch.object(release.subprocess, "run", return_value=done) as run,
        ):
            release.bump(version)
        # The workspace's lock, then fuzz/'s, which pins the same crates
        # (a stale one fails `cargo deny`, which runs --locked).
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["cargo", "update", "--workspace"],
                ["cargo", "update", "--workspace", "--manifest-path", str(fuzz / "Cargo.toml")],
            ],
        )
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


class PypiVersionTest(unittest.TestCase):
    """`pypi-version` writes a wheel's version (PEP 440) into the Python
    package's crate, in Cargo's spelling, which maturin reads back as PEP 440."""

    MANIFEST = (
        '[package]\nname = "opentide-native"\n# A comment.\nversion.workspace = true\n'
        'edition = "2024"\n\n[dependencies]\nserde = { version = "1" }\n'
    )

    LOCK = (
        '[[package]]\nname = "opentide-lsp"\nversion = "0.12.0"\n\n'
        '[[package]]\nname = "opentide-native"\nversion = "0.12.0"\n'
        'dependencies = [\n "opentide",\n]\n'
    )

    def _set(self, version: str) -> str:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        manifest = root / "Cargo.toml"
        manifest.write_text(self.MANIFEST, encoding="utf-8")
        lock = root / "Cargo.lock"
        lock.write_text(self.LOCK, encoding="utf-8")
        with (
            mock.patch.object(release, "PYTHON_BINDING", manifest),
            mock.patch.object(release, "LOCK", lock),
            mock.patch.object(release.subprocess, "run") as run,
        ):
            release.set_pypi_version(version)
        run.assert_not_called()
        # The lock carries the same version: a --locked build accepts it.
        cargo = release.cargo_version(version)
        self.assertEqual(
            lock.read_text(encoding="utf-8"),
            self.LOCK.replace(
                'name = "opentide-native"\nversion = "0.12.0"',
                f'name = "opentide-native"\nversion = "{cargo}"',
            ),
        )
        return manifest.read_text(encoding="utf-8")

    def test_each_wheel_version_in_cargos_spelling(self) -> None:
        for pypi, cargo in [
            ("1.0.0", "1.0.0"),
            ("1.0.0rc1", "1.0.0-rc.1"),
            ("0.12.0.dev2474", "0.12.0-dev.2474"),
        ]:
            with self.subTest(pypi=pypi):
                text = self._set(pypi)
                self.assertEqual(
                    text, self.MANIFEST.replace("version.workspace = true", f'version = "{cargo}"')
                )

    def test_a_version_already_written_is_replaced(self) -> None:
        self.MANIFEST = self.MANIFEST.replace("version.workspace = true", 'version = "1.0.0"')
        self.assertIn('version = "1.0.0-rc.2"', self._set("1.0.0rc2"))

    def test_anything_else_is_refused(self) -> None:
        for version in ["1.0", "v1.0.0", "1.0.0-rc.1", "1.0.0rc0", "1.0.0.dev0", "1.0.0b1"]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                self._set(version)


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
        # The test harness is a path dependency without a version: never
        # published, so not pinned.
        pins = release.internal_pins()
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
#: The one release pipeline publish.yml and ci.yml call: every build, the
#: assembled artifacts, the smoke tests and the antivirus gate.
PIPELINE = WORKFLOWS / "release-pipeline.yml"


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
    """The jobs of the release workflow and the three it calls; their names do
    not collide."""
    workflows = [workflow_jobs(path) for path in (WORKFLOW, PIPELINE)]
    jobs: dict[str, str] = {}
    for each in workflows:
        assert not jobs.keys() & each.keys(), jobs.keys() & each.keys()
        jobs.update(each)
    return jobs


def workflow_header(path: Path = WORKFLOW) -> str:
    return path.read_text(encoding="utf-8").split("\njobs:\n", 1)[0]


# language-server v0.11.0's GitHub Release (its SHA256SUMS, and SHA256SUMS),
# without the musl binaries (no musl build ships) and without the Windows
# binaries (no standalone Windows executable ships: the maintainer's decisions).
V0_11_0_ASSETS = [
    "LICENSE",
    "NOTICE",
    "SHA256SUMS",
    "THIRD-PARTY-LICENSES.html",
    "WASI-LIBC-LICENSES.txt",
    "highlights-v0.11.0.zip",
    "opentide-lsp-v0.11.0-aarch64-apple-darwin",
    "opentide-lsp-v0.11.0-aarch64-unknown-linux-gnu",
    "opentide-lsp-v0.11.0-x86_64-apple-darwin",
    "opentide-lsp-v0.11.0-x86_64-unknown-linux-gnu",
    "opentide-lsp-wasm32-wasip1.wasm",
    "opentide-wasm-web-v0.11.0.zip",
]

# What the release train adds: the `opentide` binaries, their installer, the
# command line's WASI module (one for every platform, named without a version:
# the VS Code extension pins this exact name), the licence files NOTICE cites
# (#1753), and the SBOMs scripts/engine/sbom.py writes.
PRODUCT_ASSETS = [
    "opentide-wasm32-wasip1.wasm",
    "THIRD-PARTY-DATA-LICENSES.txt",
    "opentide-v0.11.0-aarch64-apple-darwin",
    "opentide-v0.11.0-aarch64-unknown-linux-gnu",
    "opentide-v0.11.0-x86_64-apple-darwin",
    "opentide-v0.11.0-x86_64-unknown-linux-gnu",
    "opentide-installer.sh",
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
        # musl binaries are gone, the `opentide` binaries, installer and
        # SBOMs (#843) are new.
        names = V0_11_0_ASSETS + PRODUCT_ASSETS + SBOM_ASSETS
        self.assertEqual(sorted(release.expected_assets("v0.11.0")), sorted(names))
        rc = release.expected_assets("v0.11.1-rc.1")
        self.assertEqual(sorted(rc), sorted(a.replace("v0.11.0", "v0.11.1-rc.1") for a in names))
        self.assertFalse([a for a in rc if "musl" in a])
        # No standalone Windows executable, and no PowerShell installer.
        self.assertFalse([a for a in rc if "windows" in a or a.endswith((".exe", ".ps1"))])

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
        # The platform builds, at most two jobs per platform: between them each
        # target builds its wheel and its npm addon once, and the binaries once
        # (not on Windows).
        native = workflow_jobs(PIPELINE)["native"]
        cells = re.findall(
            r"target: (\S+), binaries: (\w+), addon: (\w+), wheel: (\w+), npm: (\S+), tag:", native
        )

        def built(flag: int) -> list[str]:
            return [cell[0] for cell in cells if cell[flag] == "true"]

        self.assertEqual(sorted(built(3)), sorted(release.TARGETS))
        self.assertEqual(sorted(built(2)), sorted(release.TARGETS))
        self.assertEqual(built(1), release.BINARY_TARGETS)
        self.assertFalse([t for t in built(1) if "windows" in t])
        self.assertEqual(len({t for t, *_ in cells}), len(release.TARGETS))
        self.assertLessEqual(max(sum(1 for c in cells if c[0] == t) for t, *_ in cells), 2)
        platforms = [cell[4] for cell in cells if cell[2] == "true"]
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


def step_script(job: str, step: str) -> str:
    """The `run:` body of the named step of a publish.yml job, dedented, as the
    runner's shell gets it (comment lines left out, as `workflow_jobs` does)."""
    text = workflow_jobs()[job]
    start = text.index(f"- name: {step}\n")
    body = text[text.index("        run: |\n", start) + len("        run: |\n") :]
    lines = []
    for line in body.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines)) + "\n"


class FakeRegistry:
    """A local npm registry: `routes` maps a request path to (status, body), or
    to None for a server that hangs up without answering."""

    def __init__(self, routes: dict[str, tuple[int, bytes] | None]) -> None:
        routes_ = routes

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                route = routes_.get(self.path)
                if route is None:
                    self.close_connection = True
                    self.connection.close()
                    return
                status, body = route
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> FakeRegistry:
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        ).start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


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
        for path in (PIPELINE,):
            self.assertNotIn("id-token", path.read_text(encoding="utf-8"), path.name)
            self.assertNotIn("secrets.", path.read_text(encoding="utf-8"), path.name)
        self.assertRegex(jobs["build"], r"permissions:\n      contents: read\n")
        self.assertRegex(
            PIPELINE.read_text(encoding="utf-8"), r"(?m)^permissions:\n  contents: read\n"
        )
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
        # The platform builds (release-pipeline.yml's `native`) are stricter: they run
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
                r"|release\.py (?:vendor|publish)|kind: \[.*\bcargo\b",
                body,
            )
        )
        self.assertEqual(
            rust,
            [
                "crates",
                "native",
                "smoke-registries",
                # `cargo install` from the crate packages (smoke_release.sh cargo).
                "smoke-sources",
                # The crate packages, cargo-about, cargo-cyclonedx.
                "sources",
                "wasm",
            ],
        )
        by_script = sorted(job for job, body in jobs.items() if script in body)
        self.assertEqual(by_script, ["native"])
        # The wheel builds with maturin-action, which installs rust-toolchain.toml's
        # release itself in the manylinux container on Linux: no other toolchain is named.
        wheels = jobs["native"]
        self.assertIn("uses: PyO3/maturin-action@", wheels)
        self.assertNotIn("rust-toolchain:", wheels)
        # Every build of the platform job (the binaries' cross builds on macOS
        # too) uses the target the script added.
        self.assertIn(f'{script} "${{TARGET}}"', jobs["native"])
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
        self.assertEqual(
            {
                name
                for line in jobs["native"].splitlines()
                if re.search(r"\bcargo build\b|build\.mjs", line)
                for name in re.findall(target, line)
            },
            {'"${TARGET}"'},
        )
        self.assertIn("TARGET: ${{ matrix.target }}", jobs["native"])
        # build-wasm.sh adds its own targets, but the job states them.
        self.assertEqual(targets_added(jobs["wasm"]), {"wasm32-unknown-unknown", "wasm32-wasip1"})

    def test_native_adds_its_target_to_the_pinned_toolchain(self) -> None:
        # rust-toolchain.toml pins the compiler, so a target installed for
        # another toolchain (dtolnay's `targets:` on stable) is not the one
        # cargo builds with: the cross builds failed with "can't find crate
        # for `std`" (v0.13.0). The target is added with rustup in the checkout.
        native = all_jobs()["native"]
        self.assertIn('scripts/build/install-rust.sh "${TARGET}"', native)
        self.assertNotRegex(native, r"targets:\s*\$\{\{ matrix\.target \}\}")
        self.assertLess(native.index("actions/checkout"), native.index("install-rust.sh"))

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
        for job in ("attest", "internal-release"):
            needs = re.search(r"^    needs: \[(.*)\]$", jobs[job], re.MULTILINE)
            assert needs is not None
            # `build` passes only when its smoke matrix and every build passed.
            self.assertIn("build", needs.group(1).split(", "), job)
        self.assertIn("uses: ./.github/workflows/release-pipeline.yml", jobs["build"])
        built = workflow_jobs(PIPELINE)

        def needs(job: str) -> set[str]:
            found = re.search(r"^    needs: (?:\[(.*)\]|(\S+))$", built[job], re.MULTILINE)
            assert found is not None, job
            return set((found.group(1) or found.group(2)).split(", ")) - {"plan"}

        # The platform smoke and the antivirus gate verify what `assemble` put
        # together, which needs every build; the builds from source start as
        # soon as `sources` packed them. Each verify job exists once.
        builds = {"native", "wasm", "sources"}
        self.assertEqual(needs("assemble"), builds)
        for job in ("smoke", "av-scan", "av-defender"):
            self.assertEqual(needs(job), {"assemble"}, job)
        self.assertEqual(needs("smoke-sources"), {"sources"})
        self.assertEqual(
            set(built),
            {"plan", *builds, "assemble", "smoke", "smoke-sources", "av-scan", "av-defender"},
        )
        # Each of the six platforms; then the sdist and the crate packages,
        # built from source; the PyPI dist's shape in `assemble`.
        self.assertEqual(len(re.findall(r"- \{ name: [\w-]+, os: ", built["smoke"])), 6)
        self.assertIn("smoke_release.sh platform", built["smoke"])
        self.assertIn("kind: [sdist, cargo]", built["smoke-sources"])
        self.assertIn("smoke_release.sh shape", built["assemble"])
        # Each platform cell installs that platform's wheel.
        self.assertIn("name: wheels-${{ matrix.name }}", built["smoke"])
        # The antivirus gate scans every artifact, once.
        for job in ("av-scan", "av-defender"):
            self.assertIn(
                'pattern: "{wheels-*,sdist,npm-packages,crates,release-assets}"', built[job]
            )
        # A dry run and an internal candidate stop before attest, and so
        # before every write after it.
        self.assertIn(
            "if: needs.guard.outputs.channel == 'release' || needs.guard.outputs.channel == 'rc'",
            jobs["attest"],
        )
        self.assertIn("needs.attest.result == 'success'", jobs["verify-assets"])

    def test_the_npm_smoke_installs_from_a_local_registry(self) -> None:
        smoke = workflow_jobs(PIPELINE)["smoke"]
        self.assertIn("name: npm-packages", smoke)
        script = (Path(__file__).resolve().parents[1] / "build" / "smoke_release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'node scripts/engine/npm-local-registry/test.mjs --version "${NPM_VERSION}" '
            '--tarballs "${artifacts}/npm"',
            script,
        )
        # The registry is the script's own: the job publishes nothing itself
        # and cannot mint the token npm's trusted publishing needs.
        self.assertNotRegex(smoke, r"\bnpm (?:publish|pu)\b")
        self.assertNotIn("id-token", smoke)
        # Every package that carries the engine ships the licence, NOTICE and the
        # licence files NOTICE cites (#1753), which the pack checks.
        pack = workflow_jobs(PIPELINE)["assemble"]
        self.assertIn("release.py legal bindings/node bindings/node/npm/*/", pack)
        self.assertIn("release.legal_files()", pack)
        self.assertIn("npm/1-native/*.tgz npm/2-package/*.tgz", pack)
        # ci.yml runs this smoke on the release tier and the nightly: its
        # `release` job is this build, so no job of its own repeats the test.
        ci = workflow_jobs(WORKFLOWS / "ci.yml")
        self.assertIn("uses: ./.github/workflows/release-pipeline.yml", ci["release"])
        self.assertIn("needs.changes.outputs.mode == 'nightly'", ci["release"])
        self.assertNotIn("npm-local-registry/test.mjs", "\n".join(ci.values()))

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
            # The implicit success(): every job it needs succeeded. The job's own
            # condition only (a step may run after a failed step of its job).
            header = jobs[job].split("\n    steps:\n", 1)[0]
            self.assertNotIn("always()", header, job)
            self.assertNotIn("!cancelled()", header, job)
        # The release job does not check: verify-assets does, for both paths.
        self.assertNotIn("gh attestation verify", jobs["release"])

    def test_a_release_candidate_is_a_pre_release_on_github_pypi_crates_io_and_npm(self) -> None:
        """For the Rust-core transition: a candidate publishes pre-releases on
        GitHub, PyPI, crates.io and npm (under `next`, never `latest`)."""
        jobs = workflow_jobs()
        # crates.io: every crate at X.Y.Z-rc.N, a pre-release, as for a release
        # (never for an internal candidate or a dry run).
        self.assertRegex(
            jobs["crates"],
            r"\n    if: needs\.guard\.outputs\.channel == 'release' "
            r"\|\| needs\.guard\.outputs\.channel == 'rc'\n",
        )
        bump = 'python3 scripts/engine/release.py bump "${VERSION}"'
        crates = jobs["crates"]
        self.assertIn("if: needs.guard.outputs.version != needs.guard.outputs.base", crates)
        self.assertIn("VERSION: ${{ needs.guard.outputs.version }}", crates)
        # Before anything is packaged or published.
        self.assertLess(crates.index(bump), crates.index("release.py vendor"))
        publish = crates.index("python3 scripts/engine/release.py publish")
        self.assertLess(crates.index(bump), publish)
        # The packages the build makes and smoke-tests carry the candidate's
        # version too: release-pipeline.yml's `sources` bumps the crate packages to it.
        self.assertIn("crates-version: ${{ needs.guard.outputs.version }}", jobs["build"])
        built = workflow_jobs(PIPELINE)
        package = built["sources"]
        self.assertIn(
            "if: needs.plan.outputs.crates != needs.plan.outputs.workspace",
            package,
        )
        self.assertIn("VERSION: ${{ needs.plan.outputs.crates }}", package)
        self.assertLess(package.index(bump), package.index("release.py vendor"))
        self.assertIn("CRATES_VERSION: ${{ needs.plan.outputs.crates }}", built["smoke-sources"])
        script = (Path(__file__).resolve().parents[1] / "build" / "smoke_release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('--path "${tmp}/packages/opentide-${CRATES_VERSION}"', script)
        # PyPI: real PyPI, the one environment; no TestPyPI anywhere.
        self.assertRegex(jobs["pypi"], r"environment:\n      name: pypi\n")
        self.assertNotIn("test.pypi.org", WORKFLOW.read_text(encoding="utf-8"))
        self.assertNotIn("testpypi", WORKFLOW.read_text(encoding="utf-8"))
        publish_step = jobs["pypi"][jobs["pypi"].index("- name: Publish to PyPI") :]
        publish_step = publish_step[: publish_step.index("- name:", 1)]
        self.assertNotIn("if:", publish_step)
        # npm: a release under `latest`, a candidate under `next` (a deliberate
        # change from "a release only": the candidates publish to npm too).
        npm = jobs["npm"]
        self.assertRegex(
            npm,
            r"\n    if: needs\.guard\.outputs\.channel == 'release' "
            r"\|\| needs\.guard\.outputs\.channel == 'rc'\n",
        )
        self.assertIn("CHANNEL: ${{ needs.guard.outputs.channel }}", npm)
        self.assertIn('if [ "${CHANNEL}" = "rc" ]; then dist_tag=next; fi', npm)
        self.assertIn('--provenance --access public --tag "${dist_tag}"', npm)
        # `latest` is the default and never spelled for a candidate: the one
        # publish command takes the tag from the channel, and the tag and the
        # version are checked against each other first.
        self.assertEqual(len(re.findall(r"\bnpm publish\b", npm)), 1)
        self.assertIn("refusing to publish it under next", npm)
        self.assertIn("refusing to publish it under latest", npm)
        self.assertLess(npm.index("refusing to publish it under next"), npm.index("npm publish"))
        self.assertLess(npm.index("refusing to publish it under latest"), npm.index("npm publish"))
        # Trusted publishing (OIDC, no token) with provenance, in both channels.
        self.assertNotIn("NODE_AUTH_TOKEN", npm)
        self.assertNotIn("secrets.", npm)
        smoke = jobs["smoke-registries"]
        self.assertIn("&& needs.npm.result == 'success' }}", smoke)
        self.assertNotIn("needs.npm.result == 'skipped'", smoke)
        # npx by the exact version, in both channels; a candidate's dist-tag is checked.
        npx = smoke[smoke.index("- name: npx @opentide/opentide --version") :]
        self.assertNotIn("if:", npx.splitlines()[1])
        self.assertIn('npx --yes "@opentide/opentide@${VERSION}" --version', npx)
        # The dist-tags of every package are the npm job's, not one package's here.
        self.assertNotIn("dist-tags", smoke)
        self.assertIn("- name: dist-tags of every package", npm)
        self.assertIn("a candidate must not be", npm)
        self.assertIn('cargo install opentide --version "=${VERSION}"', smoke)
        # GitHub: a pre-release, never Latest; a release is Latest by default.
        attach = jobs["release"]
        self.assertIn("flags+=(--prerelease --latest=false)", attach)
        self.assertIn('"${flags[@]}"', attach)

    def test_trust_registers_only_when_needed_and_never_fails_the_run(self) -> None:
        """Every crate trusts publish.yml and the token is deleted after the
        first publish: a run with the secret gone must not fail on the trust
        step. It runs only when the trusted login failed or a crate was created
        with the stored token, and a failure there is a warning."""
        crates = workflow_jobs()["crates"]
        steps = crates.split("      - name: ")
        trust = next(step for step in steps if step.startswith("register trusted publishing"))
        publish = next(step for step in steps if step.startswith("publish to crates.io"))
        login = next(step for step in steps if step.startswith("crates.io login"))
        # The login may fail without failing the job; the trust step reads its outcome
        # (`conclusion` is `success` under continue-on-error).
        self.assertIn("continue-on-error: true", login)
        self.assertIn("id: trusted", login)
        self.assertIn("id: publish", publish)
        condition = re.search(r"^        if: (.*)$", trust, re.MULTILINE)
        self.assertIsNotNone(condition, trust)
        self.assertEqual(
            condition.group(1),
            "${{ !cancelled() && (steps.trusted.outcome != 'success' "
            "|| steps.publish.outputs.created_with_token == 'true') }}",
        )
        # A failure is a warning, not an error: the step's command cannot fail the step.
        self.assertIn("if ! python3 scripts/engine/release.py trust publish.yml; then", trust)
        self.assertIn("::warning::", trust)
        self.assertNotIn("::error::", trust)
        self.assertNotIn("continue-on-error", trust)
        # The output the condition reads is the one release.py writes.
        self.assertIn("created_with_token=true", Path(release.__file__).read_text(encoding="utf-8"))
        # The log keeps its order.
        self.assertIn('PYTHONUNBUFFERED: "1"', publish)

    def test_every_resume_message_names_development(self) -> None:
        """development holds this publish.yml (the integration merge replaced the stub),
        so a resume is a Run workflow on development or its repository_dispatch."""
        text = WORKFLOW.read_text(encoding="utf-8")
        pypi = workflow_jobs()["pypi"]
        resume = "gh workflow run publish.yml --repo opentidehq/opentide --ref development"
        self.assertIn(resume, pypi)
        # A re-run of the failed jobs comes first: it reuses the run's artifacts.
        self.assertIn("gh run rerun {run_id} --failed", pypi)
        self.assertLess(pypi.index("gh run rerun"), pypi.index(resume))
        self.assertIn("Run workflow on development with checkout_ref=v{version}", pypi)
        self.assertIn("event_type=publish", pypi)
        self.assertIn("-f checkout_ref=v{version}", pypi)
        self.assertNotIn("GITHUB_REF_NAME", pypi)
        header = workflow_header()
        self.assertIn("--ref development", header)
        self.assertNotIn("--ref integration/unified-core", header)
        self.assertNotIn("stub", header)
        self.assertRegex(text, r"(?m)^  repository_dispatch:")

    def test_the_release_ships_the_set_the_asset_build_checked(self) -> None:
        assets = workflow_jobs(PIPELINE)["assemble"]
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
        assets = workflow_jobs(PIPELINE)["assemble"]
        lines = [line.strip() for line in assets.splitlines()]
        self.assertIn("bash scripts/engine/license-scan.sh dist", lines)
        # Only the product's files (the `opentide` binaries, which carry the
        # package's data) are scanned as a product, and before they join dist.
        self.assertLess(
            assets.index("license-scan.sh --product"), assets.index("mv product/* dist/")
        )

    def test_a_released_tag_is_never_uploaded_again(self) -> None:
        attach = workflow_jobs()["release"]
        # Only an untagged draft (never published) is cleared, then nothing is
        # uploaded to a release that has assets: the uploads go to the draft
        # this step creates, and only publishing it creates the tag.
        stale = attach.index('python3 scripts/engine/release.py stale-draft "${TAG}"')
        guard = attach.index('python3 scripts/engine/release.py unpublished "${TAG}"')
        create = attach.index('gh release create "${TAG}"')
        upload = attach.index('gh release upload "${TAG}"')
        publish = attach.index('gh release edit "${TAG}"')
        self.assertLess(stale, guard)
        self.assertLess(guard, create)
        self.assertLess(create, upload)
        self.assertLess(upload, publish)
        self.assertIn("--draft \\\n", attach[create:upload])
        self.assertIn("publish=(--draft=false)", attach[upload:publish])
        self.assertEqual(attach.count("gh release upload"), 1)
        self.assertNotIn("delete-asset", attach)
        self.assertNotIn("gh release delete", attach)

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
        # Public candidates are on (1.0.0-rc.N); the refusal stays behind the
        # switch, so turning them off again needs no other change.
        self.assertIn("public_candidates=true", guard)
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

    def test_the_command_line_wasi_module_is_a_release_asset(self) -> None:
        """The VS Code extension pins `opentide-wasm32-wasip1.wasm` by name and
        SHA-256 (docs/internal/vscode-wasi.md): the name is fixed."""
        name = "opentide-wasm32-wasip1.wasm"
        self.assertEqual(release.CLI_WASM_ASSET, name)
        # One module for every platform, with no version in its name, whatever the tag.
        for tag in ["v1.0.0", "v1.0.0-rc.3"]:
            assets = release.expected_assets(tag)
            self.assertEqual(assets.count(name), 1, tag)
        self.assertIn(name, release.expected_assets("v1.0.0-rc.3"))
        # The language server's WASI build keeps its own name beside it.
        self.assertIn("opentide-lsp-wasm32-wasip1.wasm", release.expected_assets("v1.0.0"))
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for asset in release.expected_assets("v1.0.0-rc.3"):
            (tmp / asset).write_bytes(b"x")
        (tmp / name).unlink()
        self.assertEqual(release.check_assets(tmp, "v1.0.0-rc.3"), [f"missing asset: {name}"])
        # SHA256SUMS lists it: sums and verify-sums cover every file of the directory.
        (tmp / name).write_bytes(b"\0asm\1\0\0\0")
        release.write_sums(tmp)
        self.assertIn(f"  {name}\n", (tmp / "SHA256SUMS").read_text(encoding="utf-8"))
        self.assertEqual(release.verify_sums(tmp), [])

    def test_the_asset_build_makes_the_module_with_the_releases_version(self) -> None:
        wasm = workflow_jobs(PIPELINE)["wasm"]
        build = wasm[wasm.index("- name: build the opentide command line (wasm32-wasip1)") :]
        build = build[: build.index("\n      - name:", 1)]
        # build-wasm.sh cli, with the version the binaries report (the tag without its v).
        self.assertIn("run: bash scripts/engine/build-wasm.sh cli", build)
        # The version is the job's variable (every WebAssembly build has it, below).
        self.assertIn(
            "      OPENTIDE_BUILD_VERSION: ${{ needs.plan.outputs.semver }}\n",
            wasm.split("    steps:\n", 1)[0],
        )
        self.assertEqual(
            set(
                re.findall(
                    r"^\s+OPENTIDE_BUILD_VERSION: (.*)$",
                    workflow_jobs(PIPELINE)["native"],
                    re.MULTILINE,
                )
            ),
            {"${{ needs.plan.outputs.semver }}"},
        )
        # The size budget (the .vsix's 15 MiB, gzipped) stays in the script the job runs.
        script = (Path(__file__).resolve().parent / "build-wasm.sh").read_text(encoding="utf-8")
        self.assertIn("budget=$((15 * 1024 * 1024))", script)
        self.assertIn("if ((gz > budget)); then", script)
        self.assertIn('OPENTIDE_BUILD_VERSION="${OPENTIDE_BUILD_VERSION:-', script)
        # Smoke-tested under wasmtime, from a pinned and checked download, before
        # it is packaged: `--version` prints the candidate.
        smoke = wasm[wasm.index("- name: smoke test opentide.wasm under wasmtime") :]
        smoke = smoke[: smoke.index("\n      - name:", 1)]
        self.assertRegex(smoke, r"WASMTIME_SHA256: [0-9a-f]{64}\n")
        self.assertIn("sha256sum -c -", smoke)
        self.assertIn('"${wasmtime}" run "${module}" --version', smoke)
        self.assertIn('grep -qF "${OPENTIDE_BUILD_VERSION}" <<< "${out}"', smoke)
        self.assertIn("set -euo pipefail", smoke)
        self.assertLess(wasm.index("build-wasm.sh cli"), wasm.index("under wasmtime"))
        self.assertLess(wasm.index("under wasmtime"), wasm.index("- name: package"))
        # Packaged under the fixed name, as a product asset: it carries the
        # command line's package data, which the licence scan reads as a
        # product's (the oracle scan of the engine assets would refuse it).
        package = wasm[wasm.index("- name: package") :]
        self.assertIn(
            'cp target/wasm32-wasip1/wasi/opentide.wasm "product/opentide-wasm32-wasip1.wasm"',
            package,
        )
        self.assertIn("name: product-asset-opentide-wasm", package)
        assets = workflow_jobs(PIPELINE)["assemble"]
        self.assertIn("pattern: product-asset-*", assets)
        self.assertLess(
            assets.index("license-scan.sh --product product"), assets.index("mv product/* dist/")
        )
        # release-assets (SHA256SUMS, check-assets, the attestations and the
        # published-asset checks all read the directory) carries it: no
        # per-file list in any of them but check-assets'.
        subject = workflow_jobs()["attest"]
        self.assertIn("dist/release/*", subject)
        self.assertIn("for asset in published/*; do", workflow_jobs()["verify-assets"])
        # Its SBOM is the facade's: the same opentide-cli crate.
        self.assertIn("opentide.cdx.json", release.SBOM_ASSETS)

    def _preflight(self, channel: str, statuses: dict[str, int]) -> tuple[int, str, list[str]]:
        """Run the guard's npm check against a local registry that answers each
        package name with its status in `statuses` (404 when it names none);
        the exit status, the output and the paths asked for."""
        guard = workflow_jobs()["guard"]
        step = guard[guard.index("- name: Every npm package exists on npm") :]
        heredoc = step[step.index("python3 - <<'PY'\n") + len("python3 - <<'PY'\n") :]
        script = textwrap.dedent(heredoc[: heredoc.index("\n          PY")])
        asked: list[str] = []

        class Registry(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                asked.append(self.path)
                name = self.path.lstrip("/").replace("%2F", "/").replace("%2f", "/")
                code = statuses.get(name, 404)
                self.send_response(code)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args: object) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        env = {
            **os.environ,
            "CHANNEL": channel,
            "NPM_REGISTRY": f"http://127.0.0.1:{server.server_address[1]}",
            "NPM_RETRY_SECONDS": "0",
        }
        done = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=Path(release.__file__).resolve().parents[2],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return done.returncode, done.stdout + done.stderr, asked

    def test_every_npm_package_is_the_eleven_the_preflight_asks_for(self) -> None:
        names = sorted(
            read["name"]
            for read in (release.read_json(d / "package.json") for d in release.npm_packages())
        )
        self.assertEqual(len(names), 11)
        self.assertEqual(
            names,
            sorted(
                [
                    "@opentide/lsp-client",
                    "@opentide/lsp-worker",
                    "@opentide/opentide",
                    "@opentide/opentide-darwin-arm64",
                    "@opentide/opentide-darwin-x64",
                    "@opentide/opentide-linux-arm64-gnu",
                    "@opentide/opentide-linux-x64-gnu",
                    "@opentide/opentide-win32-arm64-msvc",
                    "@opentide/opentide-win32-x64-msvc",
                    "@opentide/wasi-host",
                    "opentide",
                ]
            ),
        )
        # The guard's check asks for exactly those (the registry's `%2F` for the slash).
        code, output, asked = self._preflight("rc", dict.fromkeys(names, 200))
        self.assertEqual(code, 0, output)
        self.assertEqual(sorted(p.lstrip("/").replace("%2F", "/") for p in asked), names)

    def test_the_guard_refuses_a_candidate_or_release_when_an_npm_package_is_missing(self) -> None:
        names = [release.read_json(d / "package.json")["name"] for d in release.npm_packages()]
        present = dict.fromkeys(names, 200)
        for channel in ["rc", "release"]:
            self.assertEqual(self._preflight(channel, present)[0], 0, channel)
            absent = {**present, "@opentide/wasi-host": 404, "@opentide/opentide-darwin-x64": 404}
            code, output, _ = self._preflight(channel, absent)
            self.assertEqual(code, 1, channel)
            # A clear error that names every missing package, and points at the steps.
            self.assertIn("::error::These npm packages do not exist on npm yet:", output)
            self.assertIn("@opentide/wasi-host", output)
            self.assertIn("@opentide/opentide-darwin-x64", output)
            self.assertNotIn("@opentide/lsp-client,", output)
            self.assertIn("docs/internal/publishing.md, step 10.5", output)

    def test_the_preflight_does_not_read_an_outage_as_a_missing_package(self) -> None:
        names = [release.read_json(d / "package.json")["name"] for d in release.npm_packages()]
        outage = {**dict.fromkeys(names, 200), "opentide": 503}
        code, output, _ = self._preflight("rc", outage)
        self.assertEqual(code, 1)
        self.assertIn("Could not read opentide (503)", output)
        self.assertNotIn("do not exist on npm yet", output)

    def test_a_dry_run_reports_missing_npm_packages_without_failing(self) -> None:
        code, output, _ = self._preflight("dry-run", {})
        self.assertEqual(code, 0, output)
        self.assertIn("::warning::These npm packages do not exist on npm yet:", output)
        self.assertNotIn("::error::", output)

    def test_the_npm_preflight_runs_in_the_guard_before_anything_is_built(self) -> None:
        jobs = workflow_jobs()
        guard = jobs["guard"]
        step = guard[guard.index("- name: Every npm package exists on npm") :]
        self.assertIn(
            "if: steps.version.outputs.channel == 'release' || "
            "steps.version.outputs.channel == 'rc' || steps.version.outputs.channel == 'dry-run'",
            step.splitlines()[1],
        )
        # An internal candidate publishes nothing and does not look; no token, no secret.
        self.assertNotIn("internal", step.split("run: |", 1)[0])
        self.assertNotIn("id-token", guard)
        self.assertNotIn("secrets.", step)
        self.assertNotRegex(step, r"\bnpm (?:view|publish)\b")  # the registry's JSON, no CLI login
        self.assertNotIn("Authorization", step)
        # Every job that builds or publishes waits for the guard; `build` is what
        # the registries' jobs need (through verify-assets and attest).
        self.assertIn("needs: guard", jobs["build"])
        for job in ["attest", "pypi", "crates", "npm"]:
            self.assertIn("guard", jobs[job], job)
        # Trusted-publisher configuration cannot be read without a login: said so.
        self.assertIn("Not checked (it needs the maintainer's npm login)", step)
        self.assertIn("trusted publisher", step)

    # --- The npm job and the guard, run (not read) --------------------------

    def _npm_packages_dir(self, versions: dict[str, str] | str) -> Path:
        """A temp directory with `npm/<n>-<kind>/<package>.tgz` for each of the
        eleven packages, each file holding its package.json (what the stub `tar`
        prints); `versions` is one version for all, or per package."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for directory in release.npm_packages():
            name = release.read_json(directory / "package.json")["name"]
            if directory in release.npm_native_dirs():
                kind = "1-native"
            elif directory == release.NPM_NODE:
                kind = "2-package"
            elif directory.name == "alias":
                kind = "3-alias"
            else:
                kind = "4-lsp"
            version = versions if isinstance(versions, str) else versions[name]
            target = tmp / "npm" / kind
            target.mkdir(parents=True, exist_ok=True)
            (target / f"{name.replace('/', '-')}-{version}.tgz").write_text(
                json.dumps({"name": name, "version": version}), encoding="utf-8"
            )
        return tmp

    def _run_with_stubs(
        self,
        script: str,
        cwd: Path,
        channel: str,
        tags: dict[str, dict[str, str]] | None = None,
        published: list[str] | None = None,
    ) -> tuple[int, str, list[str]]:
        """Run a step's bash with stub `npm`, `tar` and `sleep` first on PATH:
        the exit status, the output, and the `npm` command lines run. `tags`
        maps a package to the dist-tags `npm view <pkg> dist-tags --json` prints;
        `published` lists the `name@version`s `npm view` already knows."""
        stubs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, stubs)
        (stubs / "npm").write_text(
            "#!/usr/bin/env bash\n"
            'echo "$*" >> "$NPM_LOG"\n'
            'case "$1" in\n'
            "  view)\n"
            '    if [ "$3" = "version" ]; then grep -qxF -- "$2" "$PUBLISHED"; exit $?; fi\n'
            '    if [ "$3" = "dist-tags" ]; then cat "$TAGS_DIR/${2//\\//_}"; fi ;;\n'
            "esac\n",
            encoding="utf-8",
        )
        (stubs / "tar").write_text('#!/usr/bin/env bash\ncat "$2"\n', encoding="utf-8")
        (stubs / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        for stub in stubs.iterdir():
            stub.chmod(0o755)
        tags_dir = stubs / "tags"
        tags_dir.mkdir()
        for package, document in (tags or {}).items():
            (tags_dir / package.replace("/", "_")).write_text(
                json.dumps(document), encoding="utf-8"
            )
        (stubs / "published").write_text("\n".join(published or []) + "\n", encoding="utf-8")
        log = stubs / "npm.log"
        log.write_text("", encoding="utf-8")
        env = {
            **os.environ,
            "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
            "CHANNEL": channel,
            "NPM_LOG": str(log),
            "TAGS_DIR": str(tags_dir),
            "PUBLISHED": str(stubs / "published"),
        }
        done = subprocess.run(
            ["bash", "-c", script], cwd=cwd, env=env, capture_output=True, text=True, check=False
        )
        return (
            done.returncode,
            done.stdout + done.stderr,
            log.read_text(encoding="utf-8").splitlines(),
        )

    def test_every_webassembly_build_reports_the_releases_version(self) -> None:
        """rc.2's browser zip reported 1.0.0, not 1.0.0-rc.2: opentide-core reads
        OPENTIDE_BUILD_VERSION at compile time, so every WebAssembly build (the
        browser module, the language server's WASI module and the command line's)
        needs it. It is the `wasm` job's own variable, once, so no step can leave
        it out."""
        wasm = workflow_jobs(PIPELINE)["wasm"]
        header, steps = wasm.split("    steps:\n", 1)
        self.assertIn("      OPENTIDE_BUILD_VERSION: ${{ needs.plan.outputs.semver }}\n", header)
        self.assertEqual(len(re.findall(r"OPENTIDE_BUILD_VERSION:", wasm)), 1)
        # Every build runs in that job through build-wasm.sh, which passes the
        # environment on to cargo and never clears it.
        self.assertEqual(
            re.findall(r"bash scripts/engine/build-wasm\.sh(?: \w+)*", steps),
            ["bash scripts/engine/build-wasm.sh", "bash scripts/engine/build-wasm.sh cli"],
        )
        script = (Path(__file__).resolve().parent / "build-wasm.sh").read_text(encoding="utf-8")
        self.assertNotIn("env -i", script)
        self.assertNotIn("unset OPENTIDE_BUILD_VERSION", script)
        # The compiled-in version is that variable, for the crates all three share.
        core = (Path(__file__).resolve().parents[2] / "crates/opentide-core/src/lib.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn('option_env!("OPENTIDE_BUILD_VERSION")', core)
        # The smoke test reads the same variable for the expected version.
        smoke = steps[steps.index("- name: smoke test opentide.wasm under wasmtime") :]
        self.assertIn('grep -qF "${OPENTIDE_BUILD_VERSION}"', smoke)

    def test_the_licence_file_covers_every_target_the_release_builds(self) -> None:
        """THIRD-PARTY-LICENSES.html is the licence file of every module: cargo-about
        lists a crate only for the targets about.toml names, and `wasi` (a
        dependency of the command line's WASI module alone) is on none of the
        native ones. The `wasm` job's targets are in the list."""
        root = Path(__file__).resolve().parents[2]
        about = tomllib.loads((root / "about.toml").read_text(encoding="utf-8"))
        native = {
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        }
        wasm = targets_added(workflow_jobs(PIPELINE)["wasm"])
        self.assertEqual(wasm, {"wasm32-unknown-unknown", "wasm32-wasip1"})
        self.assertEqual(set(about["targets"]), native | wasm)
        # The licences job renders it for the workspace, from this file.
        licences = workflow_jobs(PIPELINE)["sources"]
        self.assertIn("cargo about generate --workspace about.hbs", licences)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("node"), "bash and node are needed")
    def test_the_publish_loop_publishes_every_tarball_under_the_channels_tag(self) -> None:
        script = step_script("npm", "publish")
        names = sorted(
            release.read_json(d / "package.json")["name"] for d in release.npm_packages()
        )
        for channel, version, tag in [
            ("rc", "1.0.0-rc.3", "next"),
            ("release", "1.0.0", "latest"),
        ]:
            with self.subTest(channel=channel):
                packages = self._npm_packages_dir(version)
                code, output, log = self._run_with_stubs(script, packages, channel)
                self.assertEqual(code, 0, output)
                published = [line for line in log if line.startswith("publish ")]
                self.assertEqual(len(published), 11, published)
                # Each of the eleven tarballs, once, with the exact flags and tag.
                tarballs = sorted(
                    str(p.relative_to(packages)) for p in packages.glob("npm/*/*.tgz")
                )
                self.assertEqual(
                    sorted(published),
                    sorted(
                        f"publish {tarball} --provenance --access public --tag {tag}"
                        for tarball in tarballs
                    ),
                )
                self.assertEqual(
                    sorted(Path(line.split()[1]).name for line in published),
                    sorted(f"{name.replace('/', '-')}-{version}.tgz" for name in names),
                )
                # Natives first (@opentide/opentide depends on them), the lsp packages last.
                self.assertIn(
                    "-darwin-",
                    published[0]
                    + published[1]
                    + published[2]
                    + published[3]
                    + published[4]
                    + published[5],
                )
                self.assertIn("lsp", published[-1] + published[-2])
                # `latest` is never spelled for a candidate, nor `next` for a release.
                other = "latest" if tag == "next" else "next"
                self.assertFalse([line for line in published if f"--tag {other}" in line])

    @unittest.skipUnless(shutil.which("bash") and shutil.which("node"), "bash and node are needed")
    def test_the_publish_loop_refuses_a_version_that_does_not_fit_the_channel(self) -> None:
        script = step_script("npm", "publish")
        names = [release.read_json(d / "package.json")["name"] for d in release.npm_packages()]
        # One tarball of the wrong kind, the last to be read: nothing may have
        # been published before the refusal (every tarball is checked first).
        for channel, good, bad, message in [
            ("rc", "1.0.0-rc.3", "1.0.0", "refusing to publish it under next"),
            ("rc", "1.0.0-rc.3", "1.0.0-beta.1", "refusing to publish it under next"),
            ("release", "1.0.0", "1.0.0-rc.3", "refusing to publish it under latest"),
        ]:
            with self.subTest(channel=channel, bad=bad):
                versions = dict.fromkeys(names, good)
                versions["@opentide/wasi-host"] = bad
                packages = self._npm_packages_dir(versions)
                code, output, log = self._run_with_stubs(script, packages, channel)
                self.assertEqual(code, 1, output)
                self.assertIn(message, output)
                self.assertIn("@opentide/wasi-host@" + bad, output)
                self.assertFalse([line for line in log if line.startswith("publish ")], log)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("node"), "bash and node are needed")
    def test_the_publish_loop_skips_a_version_npm_has(self) -> None:
        script = step_script("npm", "publish")
        packages = self._npm_packages_dir("1.0.0-rc.3")
        code, output, log = self._run_with_stubs(
            script, packages, "rc", published=["@opentide/lsp-client@1.0.0-rc.3"]
        )
        self.assertEqual(code, 0, output)
        self.assertIn("@opentide/lsp-client@1.0.0-rc.3 is already published", output)
        self.assertEqual(len([line for line in log if line.startswith("publish ")]), 10)
        self.assertFalse(
            [line for line in log if line.startswith("publish ") and "lsp-client" in line]
        )

    @unittest.skipUnless(shutil.which("bash") and shutil.which("node"), "bash and node are needed")
    def test_every_package_is_checked_for_its_dist_tags(self) -> None:
        script = step_script("npm", "dist-tags of every package")
        names = [release.read_json(d / "package.json")["name"] for d in release.npm_packages()]
        # A candidate: next is the candidate for all eleven, latest is not.
        packages = self._npm_packages_dir("1.0.0-rc.3")
        good = {n: {"latest": "0.0.0", "next": "1.0.0-rc.3"} for n in names}
        code, output, log = self._run_with_stubs(script, packages, "rc", tags=good)
        self.assertEqual(code, 0, output)
        asked = sorted(line.split()[1] for line in log if line.endswith("dist-tags --json"))
        self.assertEqual(asked, sorted(names))
        # One package whose next is behind fails, naming it.
        behind = {**good, "@opentide/wasi-host": {"latest": "0.0.0", "next": "1.0.0-rc.2"}}
        code, output, _ = self._run_with_stubs(script, packages, "rc", tags=behind)
        self.assertEqual(code, 1, output)
        self.assertIn("@opentide/wasi-host: the registry's dist-tags are", output)
        # A candidate that took `latest` too fails.
        latest = {**good, "opentide": {"latest": "1.0.0-rc.3", "next": "1.0.0-rc.3"}}
        code, output, _ = self._run_with_stubs(script, packages, "rc", tags=latest)
        self.assertEqual(code, 1, output)
        self.assertIn("opentide@1.0.0-rc.3 is also latest", output)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("node"), "bash and node are needed")
    def test_after_a_release_a_next_that_trails_latest_is_named_with_its_fix(self) -> None:
        script = step_script("npm", "dist-tags of every package")
        names = [release.read_json(d / "package.json")["name"] for d in release.npm_packages()]
        packages = self._npm_packages_dir("1.0.0")
        done = {n: {"latest": "1.0.0", "next": "1.0.0"} for n in names}
        code, output, _ = self._run_with_stubs(script, packages, "release", tags=done)
        self.assertEqual(code, 0, output)
        self.assertNotIn("::warning::", output)
        trailing = {**done, "@opentide/opentide": {"latest": "1.0.0", "next": "1.0.0-rc.4"}}
        code, output, _ = self._run_with_stubs(script, packages, "release", tags=trailing)
        self.assertEqual(code, 0, output)  # the npm-dist-tags job moves it next
        self.assertIn("next trails latest for 1 packages: the npm-dist-tags job moves it", output)
        self.assertNotIn("::warning::", output)
        # A release whose latest is not the release fails.
        stale = {**done, "@opentide/wasi-host": {"latest": "0.0.0", "next": "0.0.0"}}
        code, output, _ = self._run_with_stubs(script, packages, "release", tags=stale)
        self.assertEqual(code, 1, output)

    def test_after_a_release_npm_next_follows_it_with_its_own_token(self) -> None:
        job = workflow_jobs()["npm-dist-tags"]
        self.assertIn("uses: ./.github/workflows/npm-dist-tags.yml", job)
        self.assertIn("needs: [guard, npm]", job)
        self.assertIn("if: needs.guard.outputs.channel == 'release'", job)
        self.assertIn("from_release: true", job)
        # The token lives in its own environment; publish.yml never names it.
        self.assertNotIn("NPM_DIST_TAG_TOKEN", WORKFLOW.read_text(encoding="utf-8"))
        moves = workflow_jobs(WORKFLOWS / "npm-dist-tags.yml")["next"]
        self.assertIn("environment: npm-dist-tags", moves)
        self.assertIn("release.py npm-names", moves)
        self.assertIn('npm dist-tag add "${name}@${VERSION}" next', moves)
        # next follows a published release only, never a candidate.
        self.assertLess(
            moves.index("latest is ${latest:-unset}, not ${VERSION}"), moves.index("npm dist-tag add")
        )

    def test_npm_names_lists_every_package_a_release_publishes(self) -> None:
        done = subprocess.run(
            [sys.executable, str(release.ROOT / "scripts" / "engine" / "release.py"), "npm-names"],
            capture_output=True,
            text=True,
            check=True,
        )
        names = done.stdout.split()
        self.assertEqual(
            names, [release.read_json(d / "package.json")["name"] for d in release.npm_packages()]
        )
        self.assertEqual(len(names), 11)

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_a_candidate_never_moves_next_backwards(self) -> None:
        script = step_script("npm", "next never moves backwards")
        path = "/@opentide%2Fopentide"

        def run(version: str, nxt: str | None) -> tuple[int, str]:
            tags = {"latest": "0.0.0"} if nxt is None else {"latest": "0.0.0", "next": nxt}
            body = json.dumps({"name": "@opentide/opentide", "dist-tags": tags}).encode()
            with FakeRegistry({path: (200, body)}) as registry:
                done = subprocess.run(
                    ["bash", "-c", script],
                    env={
                        **os.environ,
                        "VERSION": version,
                        "NPM_REGISTRY": registry.url,
                        "NPM_RETRY_SECONDS": "0",
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
            return done.returncode, done.stdout + done.stderr

        # Forward, equal and no next at all publish.
        for version, nxt in [
            ("1.0.0-rc.3", None),
            ("1.0.0-rc.3", "1.0.0-rc.2"),
            ("1.0.0-rc.3", "1.0.0-rc.3"),
            ("1.0.1-rc.1", "1.0.0"),
            ("1.1.0-rc.1", "1.0.0-rc.9"),
            ("1.0.0-rc.10", "1.0.0-rc.9"),
        ]:
            code, output = run(version, nxt)
            self.assertEqual(code, 0, (version, nxt, output))
        # Backwards fails, whatever the spelling of the numbers.
        for version, nxt in [
            ("1.0.0-rc.3", "1.0.0-rc.4"),
            ("1.0.0-rc.9", "1.0.0-rc.10"),
            ("1.0.0-rc.5", "1.0.0"),
            ("1.0.0-rc.5", "1.1.0-rc.1"),
        ]:
            code, output = run(version, nxt)
            self.assertEqual(code, 1, (version, nxt, output))
            self.assertIn(f"npm's next is already {nxt}, newer than {version}", output)
            self.assertIn("Nothing was published to npm", output)
        # A registry that cannot be read does not pass the check.
        with FakeRegistry({path: (503, b"{}")}) as registry:
            done = subprocess.run(
                ["bash", "-c", script],
                env={
                    **os.environ,
                    "VERSION": "1.0.0-rc.3",
                    "NPM_REGISTRY": registry.url,
                    "NPM_RETRY_SECONDS": "0",
                },
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("not checked, so not published", done.stdout + done.stderr)
        # It runs for a candidate only, before the publish step.
        npm = workflow_jobs()["npm"]
        step = npm[npm.index("- name: next never moves backwards") :]
        self.assertIn("if: env.CHANNEL == 'rc'", step.splitlines()[1])
        self.assertLess(
            npm.index("- name: next never moves backwards"), npm.index("- name: publish")
        )

    def test_a_resume_of_a_candidate_before_the_first_npm_candidate_is_refused(self) -> None:
        guard = workflow_jobs()["guard"]
        snippet = re.search(r"if python3 -c '([^']+)' \"\$\{tag\}\"; then", guard)
        assert snippet is not None, "the guard checks the resumed candidate"

        def refused(tag: str) -> bool:
            done = subprocess.run(
                [sys.executable, "-c", snippet.group(1), tag], capture_output=True, check=False
            )
            return done.returncode == 0

        for tag in ["v1.0.0-rc.1", "v1.0.0-rc.2", "v0.28.2-rc.9"]:
            self.assertTrue(refused(tag), tag)
        for tag in ["v1.0.0-rc.3", "v1.0.0-rc.4", "v1.0.0-rc.10", "v1.0.1-rc.1", "v1.1.0-rc.1"]:
            self.assertFalse(refused(tag), tag)
        # It sits in the resume branch, after the switch and before the channel is set to rc.
        resume = guard[guard.index('elif [[ -n "${CHECKOUT_REF}" ]]; then') :]
        resume = resume[: resume.index('elif [[ "${DRY_RUN}"')]
        self.assertLess(
            resume.index("public release candidates are disabled"), resume.index(snippet.group(0))
        )
        self.assertLess(resume.index(snippet.group(0)), resume.index("channel=rc"))
        self.assertIn(
            "is older than v1.0.0-rc.3, the first candidate that publishes to npm", resume
        )

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_the_preflight_survives_a_refused_or_dropped_connection(self) -> None:
        names = [release.read_json(d / "package.json")["name"] for d in release.npm_packages()]
        script = step_script("guard", "Every npm package exists on npm")
        root = Path(release.__file__).resolve().parents[2]

        def run(registry_url: str, channel: str) -> tuple[int, str]:
            done = subprocess.run(
                ["bash", "-c", script],
                cwd=root,
                env={
                    **os.environ,
                    "CHANNEL": channel,
                    "NPM_REGISTRY": registry_url,
                    "NPM_RETRY_SECONDS": "0",
                },
                capture_output=True,
                text=True,
                check=False,
            )
            return done.returncode, done.stdout + done.stderr

        # Connection refused: nothing listens on the port (a closed one).
        probe = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), http.server.BaseHTTPRequestHandler
        )
        refused = f"http://127.0.0.1:{probe.server_address[1]}"
        probe.server_close()
        code, output = run(refused, "rc")
        self.assertEqual(code, 1, output)
        self.assertIn("Could not read", output)
        self.assertIn("Connection refused", output)
        self.assertNotIn("do not exist on npm yet", output)  # an outage is not "missing"
        # The server hangs up without an answer (RemoteDisconnected is an HTTPException).
        quoted = {"/" + name.replace("/", "%2F"): None for name in names}
        with FakeRegistry(quoted) as registry:
            code, output = run(registry.url, "release")
        self.assertEqual(code, 1, output)
        self.assertIn("Could not read", output)
        self.assertIn("RemoteDisconnected", output)
        # A dry run only warns.
        code, output = run(refused, "dry-run")
        self.assertEqual(code, 0, output)
        self.assertIn("::warning::Could not read", output)

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
                f"{workflows}/release-pipeline.yml@refs/heads/development",
                f"{workflows}/engine-release.yml@refs/heads/development",
                workflow.replace("opentidehq", "someone") + "@refs/heads/development",
                "https://github.com/opentidehq/language-server/.github/workflows/release.yml"
                "@refs/heads/main",
            ]:
                self.assertIsNone(pattern.fullmatch(other), (pattern.pattern, other))


if __name__ == "__main__":
    unittest.main()
