"""Tests for scripts/release.py's release-asset checksums (#196).

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release  # noqa: E402  (the script sits next to this test)


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


if __name__ == "__main__":
    unittest.main()
