"""CLI regressions for pip compileall next to bundled configuration TOMLs."""

from __future__ import annotations

import compileall
import json
import shutil
from pathlib import Path

from tests.test_cli.conftest import _clear_runtime_caches
from typer.testing import CliRunner

from opentide.cli import app
from opentide.core.files import resolve_configurations
from opentide.core.root import get_data_root

runner = CliRunner()


def _compiled_data_root(tmp_path: Path) -> Path:
    dest = tmp_path / "bundled-data"
    shutil.copytree(get_data_root(), dest)
    compileall.compile_dir(str(dest / "configurations"), quiet=1, force=True)
    pyc_files = list((dest / "configurations").rglob("*.pyc"))
    assert pyc_files, "expected pip-style bytecode next to bundled configs"
    return dest


def test_info_survives_compiled_bundled_data(
    tmp_path: Path, monkeypatch, tide_corpus_repo: Path
) -> None:
    """Reproduce the 0.1.0 PyPI config crash: ``.pyc`` magic is not UTF-8 TOML.

    Full ``validate`` / ``generate`` against a pip-installed wheel runs in
    ``tests/test_cli/e2e/test_wheel_install_regression.py`` (subprocess). In-process
    validate under pytest-cov trips libyaml ``ConstructorError`` unrelated to this bug.
    """
    dest = _compiled_data_root(tmp_path)
    monkeypatch.setenv("OPENTIDE_DATA_ROOT", str(dest))
    _clear_runtime_caches()
    try:
        configs = resolve_configurations()
        assert "global" in configs or "paths" in configs
        assert configs.get("platforms") or configs.get("systems")

        info = runner.invoke(app, ["--json", "--repo", str(tide_corpus_repo), "info"])
        combined = info.stdout + info.stderr + str(info.exception)
        assert "UnicodeDecodeError" not in combined
        assert "codec can't decode" not in combined
        assert info.exit_code == 0, combined
        payload = json.loads(info.stdout)
        assert payload.get("ok") is True
        assert "counts" in payload
    finally:
        _clear_runtime_caches()
