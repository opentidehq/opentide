"""Tests for scripts/engine/release.py (tags, the asset set, checksums) and for the
shape of the engine's Release workflows, .github/workflows/engine-release.yml and
the asset build it shares with ci.yml's dry run, engine-release-build.yml
(language-server#196, opentide#801).

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

from __future__ import annotations

import hashlib
import itertools
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
        self.assertIn("publish_only", str(refused.exception.code))
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


WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "engine-release.yml"
BUILD = WORKFLOWS / "engine-release-build.yml"


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
    """The jobs of both workflows; their names do not collide."""
    release, build = workflow_jobs(WORKFLOW), workflow_jobs(BUILD)
    assert not release.keys() & build.keys(), release.keys() & build.keys()
    return {**release, **build}


def workflow_header(path: Path = WORKFLOW) -> str:
    return path.read_text(encoding="utf-8").split("\njobs:\n", 1)[0]


# language-server v0.11.0's GitHub Release (its SHA256SUMS, and SHA256SUMS).
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
    "opentide-lsp-v0.11.0-aarch64-unknown-linux-musl",
    "opentide-lsp-v0.11.0-x86_64-apple-darwin",
    "opentide-lsp-v0.11.0-x86_64-pc-windows-msvc.exe",
    "opentide-lsp-v0.11.0-x86_64-unknown-linux-gnu",
    "opentide-lsp-v0.11.0-x86_64-unknown-linux-musl",
    "opentide-lsp-wasm32-wasip1.wasm",
    "opentide-wasm-web-v0.11.0.zip",
]


class TagTest(unittest.TestCase):
    def test_engine_tags_and_release_candidates(self) -> None:
        self.assertEqual(release.parse_tag("engine-v0.11.0"), ("0.11.0", None))
        self.assertEqual(release.parse_tag("engine-v0.11.1-rc.1"), ("0.11.1", 1))
        self.assertEqual(release.parse_tag("engine-v1.2.3-rc.12"), ("1.2.3", 12))
        self.assertEqual(release.asset_version("engine-v0.11.1-rc.1"), "v0.11.1-rc.1")

    def test_an_opentide_tag_or_a_malformed_one_is_refused(self) -> None:
        # `v*` tags are opentide's releases here.
        for tag in [
            "v0.11.0",
            "engine-0.11.0",
            "engine-v0.11",
            "engine-v0.11.0-rc.0",
            "engine-v0.11.0-beta.1",
            "engine-v0.11.0-rc.1x",
            "engine-v0.11.0\n",
        ]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.parse_tag(tag)

    def test_the_asset_set_is_language_servers_last_with_the_version_substituted(self) -> None:
        self.assertEqual(sorted(release.expected_assets("engine-v0.11.0")), sorted(V0_11_0_ASSETS))
        rc = release.expected_assets("engine-v0.11.1-rc.1")
        self.assertEqual(
            sorted(rc), sorted(a.replace("v0.11.0", "v0.11.1-rc.1") for a in V0_11_0_ASSETS)
        )

    def test_check_assets_names_what_is_missing_or_extra(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for name in release.expected_assets("engine-v1.0.0"):
            (tmp / name).write_bytes(b"x")
        self.assertEqual(release.check_assets(tmp, "engine-v1.0.0"), [])
        # The same files are the wrong set for another version.
        self.assertTrue(release.check_assets(tmp, "engine-v1.0.1"))
        (tmp / "opentide-lsp-v1.0.0-x86_64-apple-darwin").unlink()
        (tmp / "stray.txt").write_bytes(b"x")
        self.assertEqual(
            release.check_assets(tmp, "engine-v1.0.0"),
            [
                "missing asset: opentide-lsp-v1.0.0-x86_64-apple-darwin",
                "unexpected asset: stray.txt",
            ],
        )

    def test_check_matches_the_workspace_and_a_candidate_needs_no_section(self) -> None:
        with (
            mock.patch.object(release, "workspace_version", return_value="1.2.3"),
            mock.patch.object(release, "internal_pins", return_value={"opentide-core": "=1.2.3"}),
            mock.patch.object(release, "changelog_section", return_value=None),
        ):
            self.assertEqual(release.check("engine-v1.2.3-rc.1"), [])
            self.assertEqual(
                release.check("engine-v1.2.3"), ["CHANGELOG.md has no section for 1.2.3"]
            )
            self.assertEqual(
                release.check("engine-v1.2.4-rc.1"),
                ["tag engine-v1.2.4-rc.1 does not match workspace version 1.2.3"],
            )
            self.assertEqual(len(release.check("v1.2.3")), 1)

    def test_a_candidates_notes_fall_back_to_unreleased(self) -> None:
        sections = {"1.2.3": None, "Unreleased": "### Fixed\n\n- **A fix.**"}
        with mock.patch.object(release, "changelog_section", side_effect=sections.get):
            notes = release.notes("engine-v1.2.3-rc.2")
        assert notes is not None
        self.assertTrue(notes.startswith("Release candidate 2 of 1.2.3."))
        self.assertIn("- **A fix.**", notes)
        # An empty section of its own is no notes either.
        sections["1.2.3"] = ""
        with mock.patch.object(release, "changelog_section", side_effect=sections.get):
            self.assertIn("- **A fix.**", release.notes("engine-v1.2.3-rc.2") or "")
        with mock.patch.object(release, "changelog_section", return_value="body"):
            self.assertEqual(release.notes("engine-v1.2.3"), "body")
            self.assertEqual(release.notes("1.2.3"), "body")

    def test_the_cli_prints_the_tag_and_whether_it_is_a_candidate(self) -> None:
        script = str(Path(release.__file__))
        run = [sys.executable, script]

        def out(*args: str) -> str:
            done = subprocess.run([*run, *args], capture_output=True, text=True, check=True)
            return done.stdout.strip()

        self.assertEqual(out("tag"), f"engine-v{release.workspace_version()}")
        self.assertEqual(out("prerelease", "engine-v1.0.0"), "false")
        self.assertEqual(out("prerelease", "engine-v1.0.0-rc.3"), "true")
        self.assertEqual(out("asset-version", "engine-v1.0.0"), "v1.0.0")
        bad = subprocess.run(
            [*run, "prerelease", "v1.0.0"], capture_output=True, text=True, check=False
        )
        self.assertEqual(bad.returncode, 1)

    def test_the_native_matrix_builds_every_target(self) -> None:
        native = workflow_jobs(BUILD)["native"]
        built = re.findall(r"^\s+target: (\S+)$", native, re.MULTILINE)
        self.assertEqual(built, release.TARGETS)


class ReleaseWorkflowTest(unittest.TestCase):
    def test_only_attest_crates_and_npm_can_mint_an_oidc_token(self) -> None:
        # crates.io and npm trust release.yml as a whole: a token from any job
        # of it publishes.
        jobs = workflow_jobs()
        minting = sorted(job for job, body in jobs.items() if "id-token: write" in body)
        self.assertEqual(minting, ["attest", "crates", "npm"])
        self.assertNotIn("id-token", workflow_header())
        for job in minting:
            # Every job states its permissions, so none inherits a token.
            self.assertIn("permissions:", jobs[job], job)
        # The asset build, which ci.yml also runs on pull requests, holds none.
        self.assertNotIn("id-token", BUILD.read_text(encoding="utf-8"))
        self.assertRegex(jobs["build"], r"permissions:\n      contents: read\n")

    def test_every_rust_job_installs_the_pinned_release_with_the_targets_it_builds(
        self,
    ) -> None:
        # cargo in the checkout runs the release rust-toolchain.toml pins, whatever
        # the runner's default is: a toolchain installed by name (`stable`, with the
        # job's targets) would leave that release without them.
        install = "rustup toolchain install --profile minimal --no-self-update"
        target = r"--target (\$\{\{[^}]*\}\}|\S+)"
        jobs = all_jobs()
        built: dict[str, set[str]] = {}
        rust = sorted(
            job
            for job, body in jobs.items()
            if re.search(r"\bcargo\b|build-wasm\.sh|release\.py (?:vendor|publish)", body)
        )
        self.assertEqual(rust, ["crates", "highlights", "licences", "native", "verify", "wasm"])
        for job, body in jobs.items():
            self.assertNotIn("dtolnay/rust-toolchain", body, job)
            self.assertNotRegex(body, r"rustup (?:default|override)|cargo \+", job)
            installs = re.findall(rf"{re.escape(install)}(.*)", body)
            self.assertEqual(len(installs), 1 if job in rust else 0, (job, installs))
            if not installs:
                continue
            # No toolchain name: rustup installs the one rust-toolchain.toml pins.
            args = re.sub(r"\$\{\{[^}]*\}\}", "EXPR", installs[0]).split()
            valued = {"--target", "--component", "--profile", "-t", "-c"}
            names = [
                arg
                for before, arg in itertools.pairwise(["--", *args])
                if not arg.startswith("-") and before not in valued
            ]
            self.assertEqual(names, [], job)
            # `rustup toolchain install` with no name installs the file's toolchain
            # and ignores `--target` (the first dry run failed on it): the job
            # adds its targets with `rustup target add`.
            self.assertNotIn("--target", installs[0], job)
            installed = {
                name
                for listed in re.findall(r"rustup target add ([^\n]+)", body)
                for name in re.findall(r"\$\{\{[^}]*\}\}|\S+", listed)
            }
            built[job] = {
                name
                for line in body.splitlines()
                if re.search(r"\bcargo (?:build|run|clippy|test|check|package)\b", line)
                for name in re.findall(target, line)
            }
            self.assertLessEqual(built[job], installed, job)
        # The matrix build cross-compiles for x86_64-apple-darwin, musl and the like.
        self.assertEqual(built["native"], {"${{ matrix.target }}"})

    def test_the_attest_job_builds_and_runs_nothing(self) -> None:
        attest = workflow_jobs()["attest"]
        self.assertNotIn("run:", attest)
        self.assertNotIn("cargo", attest)
        self.assertNotIn("actions/checkout", attest)
        uses = re.findall(r"uses: (\S+)", attest)
        self.assertEqual(
            [u.split("@")[0] for u in uses],
            ["actions/download-artifact", "actions/attest-build-provenance"],
        )

    def test_cargo_about_runs_without_an_oidc_token(self) -> None:
        jobs = all_jobs()
        builds = [job for job, body in jobs.items() if "cargo install" in body]
        self.assertTrue(builds)
        for job in builds:
            self.assertNotIn("id-token", jobs[job], job)

    def test_crates_and_npm_publish_only_once_the_published_assets_verified(self) -> None:
        jobs = workflow_jobs()
        verify_assets = jobs["verify-assets"]
        self.assertIn("sha256sum", verify_assets)
        self.assertIn("gh attestation verify", verify_assets)
        # It runs for publish_only too, when the release job is skipped.
        self.assertIn("inputs.publish_only && needs.release.result == 'skipped'", verify_assets)
        for job in ["crates", "npm"]:
            needs = re.search(r"^    needs: \[(.*)\]$", jobs[job], re.MULTILINE)
            self.assertIsNotNone(needs, job)
            self.assertIn("verify-assets", needs.group(1).split(", "), job)
        # crates runs under always() for publish_only: it must ask for the check itself.
        self.assertIn("needs.verify-assets.result == 'success'", jobs["crates"])
        # npm keeps the implicit success(): every job it needs succeeded.
        self.assertNotIn("always()", jobs["npm"])
        # The release job no longer checks: verify-assets does, for both paths.
        self.assertNotIn("gh attestation verify", jobs["release"])

    def test_a_release_candidate_is_a_pre_release_and_publishes_no_package(self) -> None:
        jobs = workflow_jobs()
        for job in ["crates", "npm"]:
            self.assertIn("needs.verify.outputs.prerelease == 'false'", jobs[job], job)
        attach = jobs["release"]
        self.assertIn("flags+=(--prerelease)", attach)
        # opentide's release stays the repository's latest.
        self.assertIn("flags=(--latest=false)", attach)
        self.assertIn('"${flags[@]}"', attach)

    def test_the_release_ships_the_set_the_asset_build_checked(self) -> None:
        assets = workflow_jobs(BUILD)["assets"]
        self.assertIn('python3 scripts/engine/release.py check-assets dist "${TAG}"', assets)
        self.assertLess(assets.index("release.py sums dist"), assets.index("check-assets"))
        self.assertIn("name: release-assets", assets)
        for job in ["attest", "release"]:
            self.assertIn("name: release-assets", workflow_jobs()[job], job)

    def test_a_released_tag_is_never_uploaded_again(self) -> None:
        jobs = workflow_jobs()
        # A re-run of a tag push stops before it builds anything.
        verify = jobs["verify"]
        push = verify.index('if [ "${GITHUB_EVENT_NAME}" = "push" ]; then')
        dispatch = verify.index("else", push)
        self.assertIn(
            'python3 scripts/engine/release.py unpublished "${tag}"', verify[push:dispatch]
        )
        # And the release job checks again before it replaces anything: a
        # single job can be re-run on its own.
        attach = jobs["release"]
        guard = attach.index('python3 scripts/engine/release.py unpublished "${TAG}"')
        self.assertLess(attach.index("gh release create"), guard)
        self.assertLess(guard, attach.index("gh release upload"))
        self.assertNotIn("--clobber", attach)
        self.assertNotIn("delete-asset", attach)

    def test_run_workflow_never_releases_a_version_already_tagged(self) -> None:
        # A tag whose own run failed before its release: a dispatch would build
        # another commit, attach it to the tag's and publish its crates.
        verify = workflow_jobs()["verify"]
        dispatch = verify[verify.index('if [ "${GITHUB_REF}" != "refs/heads/development" ]') :]
        guard = 'git ls-remote --exit-code --tags origin "refs/tags/${tag}"'
        self.assertIn(guard, dispatch)
        self.assertLess(dispatch.index("PUBLISH_ONLY"), dispatch.index(guard))

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

    def test_every_attestation_check_names_the_release_workflow_and_its_ref(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        readme = (WORKFLOW.parents[2] / "crates" / "opentide-lsp" / "README.md").read_text(
            encoding="utf-8"
        )
        for source in [text, readme]:
            checks = re.findall(r"gh attestation verify (?:[^\n]*\\\n)*[^\n]*", source)
            self.assertTrue(checks)
            for check in checks:
                self.assertIn("--cert-identity-regex", check)

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_the_identity_is_engine_release_yml_on_development_or_the_tag(self) -> None:
        lines = [
            line.strip()
            for line in workflow_jobs()["verify-assets"].splitlines()
            if re.match(r"\s*(repo_re|tag_re|identity)=", line)
        ]
        self.assertEqual(len(lines), 3, lines)
        script = "\n".join([*lines, 'printf %s "$identity"'])
        env = {"GITHUB_REPOSITORY": "opentidehq/opentide", "TAG": "engine-v1.2.3"}
        env["PATH"] = "/usr/bin:/bin"
        done = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, env=env, check=True
        )
        identity = re.compile(done.stdout)
        readme = (WORKFLOW.parents[2] / "crates" / "opentide-lsp" / "README.md").read_text(
            encoding="utf-8"
        )
        found = re.search(r"--cert-identity-regex '([^']+)'", readme)
        assert found is not None, "README.md documents the identity"
        documented = re.compile(found.group(1).replace(r"vX\.Y\.Z", r"v1\.2\.3"))
        workflows = "https://github.com/opentidehq/opentide/.github/workflows"
        workflow = f"{workflows}/engine-release.yml"
        for pattern in [identity, documented]:
            self.assertTrue(
                pattern.fullmatch(f"{workflow}@refs/heads/development"), pattern.pattern
            )
            self.assertTrue(
                pattern.fullmatch(f"{workflow}@refs/tags/engine-v1.2.3"), pattern.pattern
            )
            for other in [
                f"{workflow}@refs/heads/main",
                f"{workflow}@refs/heads/feature",
                f"{workflow}@refs/tags/engine-v1.2.4",
                f"{workflow}@refs/tags/v1.2.3",
                f"{workflow}@refs/tags/engine-v1x2x3",
                f"{workflows}/ci.yml@refs/heads/development",
                f"{workflows}/engine-release-build.yml@refs/heads/development",
                f"{workflows}/publish-pypi.yml@refs/tags/engine-v1.2.3",
                workflow.replace("opentidehq", "someone") + "@refs/heads/development",
                "https://github.com/opentidehq/language-server/.github/workflows/release.yml"
                "@refs/heads/main",
            ]:
                self.assertIsNone(pattern.fullmatch(other), (pattern.pattern, other))


if __name__ == "__main__":
    unittest.main()
