"""``opentide explorer`` through a real ``npx``, against a stand-in package.

The stand-in has the published package's two bins, so a command line that
cannot tell npx which bin to run fails here the way it would against npm.
It records its arguments instead of running ``next build``, which keeps the
test offline; ``OPENTIDE_EXPLORER_PACKAGE`` points npx at it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

from opentide.cli.services.explorer import (
    PACKAGE_ENV,
    ExplorerToolchainError,
    find_node_toolchain,
)

pytestmark = pytest.mark.cli_e2e

try:
    find_node_toolchain()
except ExplorerToolchainError as exc:
    pytestmark = [pytestmark, pytest.mark.skip(reason=str(exc))]

_BIN = """\
#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
const [command, ...rest] = process.argv.slice(2);
const option = (name) => rest[rest.indexOf(name) + 1];
const exportsDir = option("--exports-dir");
if (!fs.existsSync(path.join(exportsDir, "explorer.bundle.json"))) {
  console.error("Missing required export");
  process.exit(1);
}
fs.mkdirSync(option("--output"), { recursive: true });
fs.writeFileSync(path.join(option("--output"), "index.html"), "<html></html>");
console.log(`built ${command}`);
const record = { command, rest, cwd: process.cwd() };
fs.writeFileSync(process.env.STUB_EXPLORER_LOG, JSON.stringify(record));
"""


@pytest.fixture
def stub_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    package = tmp_path / "stub-explorer"
    (package / "bin").mkdir(parents=True)
    manifest = {
        "name": "@opentide/explorer",
        "version": "0.5.0",
        "type": "module",
        "bin": {
            "opentide-explorer": "./bin/opentide-explorer.mjs",
            "opentide-explorer-build": "./bin/build.mjs",
        },
    }
    (package / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    for name in ("opentide-explorer.mjs", "build.mjs"):
        script = package / "bin" / name
        script.write_text(_BIN, encoding="utf-8")
        script.chmod(0o755)
    log = tmp_path / "stub-explorer.json"
    monkeypatch.setenv(PACKAGE_ENV, str(package))
    monkeypatch.setenv("STUB_EXPLORER_LOG", str(log))
    monkeypatch.setenv("npm_config_cache", str(tmp_path / "npm-cache"))
    monkeypatch.setenv("npm_config_offline", "true")
    return log


def test_explorer_build_exports_then_builds(
    invoke_cli, tide_corpus_repo: Path, stub_package: Path
) -> None:
    result = invoke_cli("explorer", "build", "--base-path", "/corpus")
    payload = assert_json_ok(result)
    # The package's own output went to stderr: stdout parsed as one JSON document.
    assert "built build" not in result.stdout
    repo = tide_corpus_repo.resolve()
    exports = repo / ".opentide" / "exports"
    assert (exports / "explorer.bundle.json").is_file()
    assert (repo / "out" / "explorer" / "index.html").is_file()
    assert payload["output"] == str(repo / "out" / "explorer")
    record = json.loads(stub_package.read_text(encoding="utf-8"))
    assert record["command"] == "build"
    assert record["rest"] == [
        "--exports-dir",
        str(exports),
        "--output",
        str(repo / "out" / "explorer"),
        "--base-path",
        "/corpus",
    ]
    assert os.path.samefile(record["cwd"], repo)


def test_explorer_build_reports_a_failing_package(
    invoke_cli, tide_corpus_repo: Path, stub_package: Path, tmp_path: Path
) -> None:
    broken = tmp_path / "stub-explorer" / "bin" / "opentide-explorer.mjs"
    broken.write_text("#!/usr/bin/env node\nprocess.exit(3);\n", encoding="utf-8")
    result = invoke_cli("explorer", "build")
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert payload["exit_status"] == 3
    assert "build exited with status 3" in payload["message"]
