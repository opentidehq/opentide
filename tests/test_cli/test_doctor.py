"""``opentide doctor``: every check in its pass, warn, fail and skip states, mocked."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from rich.console import Console
from tests.result_models_support import assert_matches_model
from tests.test_cli.conftest import clear_runtime_caches, parse_cli_json
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services import doctor
from opentide.cli.services.doctor import Check, DoctorContext

_SGR = re.compile(r"\x1b\[[0-9;]*m")

SECRET = "s3cr3t-Value-never-printed"

SENTINEL_TOML = """\
[platform]
enabled = true
identifier = "sentinel"

[[tenants]]
name = "prod"
[tenants.setup]
ssl = true
workspace_name = "literal-name"
azure_client_id = "$DOCTOR_TEST_CLIENT_ID"
azure_client_secret = "$DOCTOR_TEST_CLIENT_SECRET"

[[tenants]]
name = "lab"
[tenants.setup]
workspace_name = "lab"
"""


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "detections"
    (root / ".opentide" / "configurations" / "platforms").mkdir(parents=True)
    (root / "objects" / "rules").mkdir(parents=True)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(root))
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("OPENTIDE_PROXY", raising=False)
    clear_runtime_caches()
    return root


def _enable_sentinel(root: Path) -> None:
    path = root / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    path.write_text(SENTINEL_TOML, encoding="utf-8")
    clear_runtime_caches()


def _ctx(root: Path, **kwargs: object) -> DoctorContext:
    return DoctorContext(workspace=root, **kwargs)  # ty: ignore[invalid-argument-type]


def _only(checks: list[Check]) -> Check:
    assert len(checks) == 1, checks
    return checks[0]


# --------------------------------------------------------------------------- python and versions


def test_python_passes_on_this_interpreter(workspace: Path) -> None:
    assert _only(doctor.check_python(_ctx(workspace))).status == "pass"


def test_python_fails_below_the_minimum(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.sys, "version_info", (3, 9, 18, "final", 0))
    check = _only(doctor.check_python(_ctx(workspace)))
    assert (check.code, check.status) == ("python_version", "fail")
    assert "3.9.18" in check.message


def test_opentide_version_reports_the_installed_version(workspace: Path) -> None:
    from opentide import __version__

    check = _only(doctor.check_opentide_version(_ctx(workspace)))
    assert check.message == f"opentide {__version__}"


@pytest.mark.parametrize(
    ("latest", "status"),
    [("999.0.0", "warn"), ("0.0.1", "pass")],
    ids=["newer", "older"],
)
def test_latest_version(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, latest: str, status: str
) -> None:
    monkeypatch.setattr(doctor, "fetch_latest_version", lambda: latest)
    check = _only(doctor.check_latest_version(_ctx(workspace)))
    assert check.status == status
    if status == "warn":
        assert check.fix == doctor.UPGRADE_COMMAND
        assert "999.0.0" in check.message


def test_latest_version_degrades_to_a_warning_offline(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unreachable() -> str:
        raise OSError("network is unreachable")

    monkeypatch.setattr(doctor, "fetch_latest_version", unreachable)
    check = _only(doctor.check_latest_version(_ctx(workspace)))
    assert (check.status, check.code) == ("warn", "opentide_latest")
    assert "OSError" in check.message


def test_latest_version_is_skipped_with_offline(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(doctor, "fetch_latest_version", pytest.fail)
    assert _only(doctor.check_latest_version(_ctx(workspace, offline=True))).status == "skip"


def test_fetch_latest_version_reads_pypi_with_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"info": {"version": "1.2.3"}}

    def fake_get(url: str, timeout: object) -> _Response:
        seen.update(url=url, timeout=timeout)
        return _Response()

    monkeypatch.setattr("requests.get", fake_get)
    assert doctor.fetch_latest_version(timeout=1.5) == "1.2.3"
    assert seen == {"url": doctor.PYPI_URL, "timeout": (1.5, 1.5)}


# --------------------------------------------------------------------------- workspace and git


def test_workspace_states(tmp_path: Path, workspace: Path) -> None:
    found = _only(doctor.check_workspace(_ctx(workspace)))
    assert (found.status, found.code) == ("pass", "workspace")
    assert "found from the current directory" in found.message
    explicit = _only(doctor.check_workspace(_ctx(workspace, workspace_explicit=True)))
    assert "set by --repo or OPENTIDE_REPO_ROOT" in explicit.message

    bare = tmp_path / "bare"
    (bare / "objects").mkdir(parents=True)
    assert _only(doctor.check_workspace(_ctx(bare))).status == "warn"

    empty = tmp_path / "empty"
    empty.mkdir()
    missing = _only(doctor.check_workspace(_ctx(empty)))
    assert missing.status == "fail"
    assert missing.fix and "opentide setup" in missing.fix


def test_git_missing_is_a_warning(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    check = _only(doctor.check_git(_ctx(workspace)))
    assert (check.code, check.status) == ("git", "warn")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def test_git_outside_a_repository(workspace: Path, git_home: Path) -> None:
    checks = {check.code: check for check in doctor.check_git(_ctx(workspace))}
    assert checks["git"].status == "pass"
    assert checks["git_repository"].status == "warn"
    assert checks["git_repository"].fix == f"git init {workspace}"


def test_paths_are_relative_to_the_current_directory(
    workspace: Path, git_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(workspace)
    found = _only(doctor.check_workspace(_ctx(workspace)))
    assert found.message.startswith("Workspace ./ has .opentide/"), found.message
    outside = {check.code: check for check in doctor.check_git(_ctx(workspace))}
    assert outside["git_repository"].message == "./ is not in a git repository"
    assert outside["git_repository"].fix == "git init ./"

    _git(workspace, "init", "-q", "-b", "trunk")
    (workspace / "objects").mkdir(exist_ok=True)
    monkeypatch.chdir(workspace / "objects")
    inside = {check.code: check for check in doctor.check_git(_ctx(workspace))}
    assert inside["git_repository"].message == "Repository .. has no origin remote; on trunk"

    monkeypatch.chdir(workspace.parent)
    below = _only(doctor.check_workspace(_ctx(workspace)))
    assert below.message.startswith(f"Workspace {workspace.name} has"), below.message
    assert str(workspace.parent) not in below.message


def test_git_default_branch_states(workspace: Path, git_home: Path) -> None:
    _git(workspace, "init", "-q", "-b", "trunk")
    checks = {check.code: check for check in doctor.check_git(_ctx(workspace))}
    assert checks["git_repository"].status == "pass"
    assert "no origin remote; on trunk" in checks["git_repository"].message

    _git(workspace, "remote", "add", "origin", "https://example.test/detections.git")
    unknown = {check.code: check for check in doctor.check_git(_ctx(workspace))}
    assert unknown["git_repository"].status == "warn"
    assert unknown["git_repository"].fix == "git remote set-head origin --auto"

    _git(workspace, "commit", "-q", "--allow-empty", "-m", "init")
    _git(workspace, "update-ref", "refs/remotes/origin/trunk", "HEAD")
    _git(workspace, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
    known = {check.code: check for check in doctor.check_git(_ctx(workspace))}
    assert known["git_repository"].status == "pass"
    assert known["git_repository"].message.endswith("default branch trunk")


# --------------------------------------------------------------------------- generated artefacts


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A workspace whose templates and schemas this version generated."""
    root = tmp_path_factory.mktemp("generated") / "detections"
    (root / ".opentide").mkdir(parents=True)
    (root / "objects").mkdir()
    env = {"OPENTIDE_REPO_ROOT": str(root), "OPENTIDE_TIDE_WORKSPACE": str(root)}
    clear_runtime_caches()
    result = CliRunner().invoke(
        app, ["--json", "--repo", str(root), "generate", "templates", "schemas"], env=env
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    clear_runtime_caches()
    return root


def test_templates_and_schemas_fresh(generated: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(generated))
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    clear_runtime_caches()
    assert _only(doctor.check_templates(_ctx(generated))).status == "pass"
    assert _only(doctor.check_schemas(_ctx(generated))).status == "pass"


def test_templates_stale_and_missing(
    generated: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil

    copy = tmp_path / "copy"
    shutil.copytree(generated, copy)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(copy))
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    clear_runtime_caches()
    template = copy / ".opentide" / "templates" / "threat.1.0.template.yaml"
    template.write_text(template.read_text(encoding="utf-8") + "# edited\n", encoding="utf-8")
    stale = _only(doctor.check_templates(_ctx(copy)))
    assert stale.status == "warn"
    assert "threat.1.0.template.yaml" in stale.message
    assert stale.fix and stale.fix.startswith("opentide generate templates")

    template.unlink()
    missing = _only(doctor.check_templates(_ctx(copy)))
    assert missing.status == "warn"
    assert "missing" in missing.message

    (copy / ".opentide" / "schemas" / "rule.1.0.schema.json").unlink()
    schemas = _only(doctor.check_schemas(_ctx(copy)))
    assert (schemas.status, schemas.fix) == ("warn", "opentide generate schemas")
    assert "rule.1.0.schema.json" in schemas.message


def _generate_templates(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run ``generate templates`` in *root* the way a user does, then point the runtime at it."""
    env = {"OPENTIDE_REPO_ROOT": str(root), "OPENTIDE_TIDE_WORKSPACE": str(root)}
    clear_runtime_caches()
    result = CliRunner().invoke(
        app, ["--json", "--repo", str(root), "generate", "templates"], env=env
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(root))
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    clear_runtime_caches()


def _lint_workspace(tmp_path: Path, lint_toml: str) -> Path:
    root = tmp_path / "detections"
    configurations = root / ".opentide" / "configurations"
    configurations.mkdir(parents=True)
    (root / "objects").mkdir()
    (configurations / "lint.toml").write_text(lint_toml, encoding="utf-8")
    return root


def test_templates_fresh_when_lint_toml_changes_the_required_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``generate templates`` renders ``[metadata].required`` live; doctor must compare alike."""
    root = _lint_workspace(tmp_path, '[metadata]\nrequired = ["author"]\n')
    _generate_templates(root, monkeypatch)
    check = _only(doctor.check_templates(_ctx(root)))
    assert (check.status, check.message) == ("pass", "Templates match the installed version")


def test_templates_not_compared_when_lint_toml_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _lint_workspace(tmp_path, '[metadata]\nrequired = ["author"]\n')
    _generate_templates(root, monkeypatch)
    (root / ".opentide" / "configurations" / "lint.toml").write_text(
        '[metadata]\nrequired = ["owner"]\n', encoding="utf-8"
    )
    clear_runtime_caches()
    check = _only(doctor.check_templates(_ctx(root)))
    assert check.status == "warn"
    assert "owner" in check.message
    assert check.fix and "lint.toml" in check.fix


# --------------------------------------------------------------------------- platforms


def test_no_platform_enabled_is_a_warning(workspace: Path) -> None:
    check = _only(doctor.check_platforms(_ctx(workspace)))
    assert (check.code, check.status) == ("platforms_enabled", "warn")
    assert doctor.check_platform_sdks(_ctx(workspace)) == []
    assert doctor.check_credentials(_ctx(workspace)) == []


def test_enabled_platform_and_its_sdk(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_sentinel(workspace)
    assert _only(doctor.check_platforms(_ctx(workspace))).message == "Enabled: sentinel"
    monkeypatch.setattr(doctor, "_importable", lambda module: None)
    ok = _only(doctor.check_platform_sdks(_ctx(workspace)))
    assert (ok.status, ok.subject) == ("pass", "sentinel")

    monkeypatch.setattr(
        doctor,
        "_importable",
        lambda module: "ModuleNotFoundError: no azure" if module.startswith("azure") else None,
    )
    broken = _only(doctor.check_platform_sdks(_ctx(workspace)))
    assert broken.status == "fail"
    assert broken.fix == doctor.REINSTALL_COMMAND
    assert "azure.identity" in broken.message


def test_importable_reports_why() -> None:
    assert doctor._importable("json") is None
    reason = doctor._importable("opentide_no_such_module_for_doctor")
    assert reason is not None and reason.startswith("ModuleNotFoundError")


def test_credentials_report_presence_never_values(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_sentinel(workspace)
    env = {"DOCTOR_TEST_CLIENT_ID": SECRET}
    checks = {check.subject: check for check in doctor.check_credentials(_ctx(workspace, env=env))}
    prod = checks["sentinel/prod"]
    assert prod.status == "warn"
    assert prod.message == "sentinel/prod: 1 of 2 variables unset: DOCTOR_TEST_CLIENT_SECRET"
    assert checks["sentinel/lab"].status == "pass"

    env["DOCTOR_TEST_CLIENT_SECRET"] = SECRET
    complete = {
        check.subject: check for check in doctor.check_credentials(_ctx(workspace, env=env))
    }
    assert complete["sentinel/prod"].status == "pass"
    rendered = json.dumps([check.to_dict() for check in complete.values()])
    assert SECRET not in rendered
    assert "literal-name" not in rendered


def test_credentials_skip_a_platform_without_tenants(workspace: Path) -> None:
    path = workspace / ".opentide" / "configurations" / "platforms" / "splunk.toml"
    path.write_text('[platform]\nenabled = true\nidentifier = "splunk"\n', encoding="utf-8")
    clear_runtime_caches()
    check = _only(doctor.check_credentials(_ctx(workspace)))
    assert (check.status, check.subject) == ("skip", "splunk")
    assert check.fix and "[[tenants]]" in check.fix


# --------------------------------------------------------------------------- proxy


def test_no_proxy_set_is_skipped(workspace: Path) -> None:
    assert _only(doctor.check_proxy(_ctx(workspace, env={}))).status == "skip"


def test_proxy_reachable_hides_credentials(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, int]] = []
    monkeypatch.setattr(doctor, "connect", lambda host, port: seen.append((host, port)))
    env = {"HTTPS_PROXY": f"http://alice:{SECRET}@proxy.example.test:3128", "NO_PROXY": "pypi.org"}
    check = _only(doctor.check_proxy(_ctx(workspace, env=env)))
    assert check.status == "pass"
    assert seen == [("proxy.example.test", 3128)]
    assert SECRET not in check.message and "alice" not in check.message
    shown = re.match(r"Proxy (\S+) accepts connections", check.message)
    assert shown is not None, check.message
    assert shown.group(1) == "http://proxy.example.test:3128"
    assert "NO_PROXY" in check.message


def test_proxy_unreachable_fails(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(host: str, port: int) -> None:
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(doctor, "connect", refuse)
    env = {"https_proxy": f"https://bob:{SECRET}@proxy.example.test"}
    check = _only(doctor.check_proxy(_ctx(workspace, env=env)))
    assert (check.code, check.status) == ("proxy", "fail")
    assert SECRET not in check.message
    assert "ConnectionRefusedError" in check.message


def test_proxy_offline_and_without_host(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor, "connect", pytest.fail)
    env = {"HTTP_PROXY": "http://proxy.example.test:8080"}
    assert _only(doctor.check_proxy(_ctx(workspace, env=env, offline=True))).status == "skip"
    assert (
        _only(doctor.check_proxy(_ctx(workspace, env={"HTTP_PROXY": "http://:8080"}))).status
        == "fail"
    )


def test_connect_opens_a_tcp_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []

    class _Socket:
        def __enter__(self) -> _Socket:
            return self

        def __exit__(self, *args: object) -> None:
            calls.append(("closed",))

    def fake(address: tuple[str, int], timeout: float) -> _Socket:
        calls.append((address, timeout))
        return _Socket()

    monkeypatch.setattr(doctor.socket, "create_connection", fake)
    doctor.connect("proxy.example.test", 3128, timeout=0.5)
    assert calls == [(("proxy.example.test", 3128), 0.5), ("closed",)]


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        ("http://user:pass@proxy:8080", "http://proxy:8080"),
        ("proxy.internal:3128", "http://proxy.internal:3128"),
        ("http://[::1]:8080", "http://[::1]:8080"),
        # An unencoded "/", "#" or "?" in the password must not end the host early.
        ("http://alice:s3cr/etPW@proxy.example:8080", "http://proxy.example:8080"),
        ("http://alice:s3cr#etPW@proxy.example:8080", "http://proxy.example:8080"),
        ("http://alice:s3cr?etPW@proxy.example:8080", "http://proxy.example:8080"),
        ("http://alice:p@ss@proxy.example:8080/", "http://proxy.example:8080"),
        ("socks5h://proxy.example", "socks5h://proxy.example"),
        ("http://proxy.example:notaport", doctor.UNPARSEABLE_URL),
        ("http://proxy.example:99999", doctor.UNPARSEABLE_URL),
        ("ht tp://alice:secret@proxy", doctor.UNPARSEABLE_URL),
    ],
)
def test_redact_url(url: str, shown: str) -> None:
    assert doctor.redact_url(url) == shown
    assert "s3cr" not in shown and "secret" not in shown


def test_proxy_with_a_slash_in_the_password_connects_to_the_host(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, int]] = []
    monkeypatch.setattr(doctor, "connect", lambda host, port: seen.append((host, port)))
    env = {"HTTPS_PROXY": "http://alice:s3cr/etPW@proxy.example:8080"}
    check = _only(doctor.check_proxy(_ctx(workspace, env=env)))
    assert check.status == "pass"
    assert seen == [("proxy.example", 8080)]
    assert "s3cr" not in check.message


def test_unparseable_proxy_fails_without_echoing_it(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(doctor, "connect", pytest.fail)
    env = {"HTTPS_PROXY": f"http://alice:{SECRET}@proxy.example:port"}
    check = _only(doctor.check_proxy(_ctx(workspace, env=env)))
    assert (check.status, check.message) == ("fail", "The proxy URL cannot be parsed")


# --------------------------------------------------------------------------- editor and MCP


def test_vscode_settings_and_snippets(workspace: Path) -> None:
    from opentide.cli.services.setup.vscode import build_yaml_schema_mappings

    checks = {check.code: check for check in doctor.check_vscode(_ctx(workspace))}
    assert checks["vscode_settings"].status == "skip"
    assert checks["vscode_snippets"].status == "skip"

    vscode = workspace / ".vscode"
    vscode.mkdir()
    settings = vscode / "settings.json"
    settings.write_text("{not json", encoding="utf-8")
    invalid = {check.code: check for check in doctor.check_vscode(_ctx(workspace))}
    assert invalid["vscode_settings"].status == "warn"
    assert "not valid JSON" in invalid["vscode_settings"].message

    settings.write_text('{"yaml.schemas": {"other.json": "x/**"}}', encoding="utf-8")
    unmapped = {check.code: check for check in doctor.check_vscode(_ctx(workspace))}
    assert unmapped["vscode_settings"].status == "warn"

    settings.write_text('{"editor.tabSize": 2}', encoding="utf-8")
    none = {check.code: check for check in doctor.check_vscode(_ctx(workspace))}
    assert "maps no yaml.schemas" in none["vscode_settings"].message

    mapped = {"yaml.schemas": build_yaml_schema_mappings(workspace=workspace)}
    settings.write_text(json.dumps(mapped) + "\n// comment\n", encoding="utf-8")
    (vscode / "model-templates.code-snippets").write_text("{}", encoding="utf-8")
    good = {check.code: check for check in doctor.check_vscode(_ctx(workspace))}
    assert good["vscode_settings"].status == "pass"
    assert good["vscode_snippets"].status == "pass"


def _mcp(path: Path, command: str = "opentide", args: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    server = {"command": command, "args": args if args is not None else ["mcp", "start"]}
    path.write_text(json.dumps({"mcpServers": {"opentide": server}}), encoding="utf-8")


def test_mcp_config_states(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _only(doctor.check_mcp(_ctx(workspace))).status == "skip"

    _mcp(workspace / ".cursor" / "mcp.json")
    monkeypatch.setattr(doctor.shutil, "which", lambda name: f"/usr/bin/{name}")
    ok = _only(doctor.check_mcp(_ctx(workspace)))
    assert (ok.status, ok.message) == ("pass", "MCP configured for Cursor")

    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert _only(doctor.check_mcp(_ctx(workspace))).status == "warn"

    # A host's own file listing other servers only does not hide a working one.
    _mcp(workspace / ".mcp.json", args=["serve"])
    monkeypatch.setattr(doctor.shutil, "which", lambda name: f"/usr/bin/{name}")
    mixed = _only(doctor.check_mcp(_ctx(workspace)))
    assert mixed.status == "pass"
    assert mixed.message == "MCP configured for Cursor (.mcp.json has no opentide server)"

    (workspace / ".cursor" / "mcp.json").unlink()
    broken = _only(doctor.check_mcp(_ctx(workspace)))
    assert broken.status == "warn"
    assert ".mcp.json" in broken.message


def test_mcp_check_reads_the_files_setup_writes() -> None:
    from opentide.cli.services.setup.mcp import MCP_OUTPUT_PATHS

    assert set(doctor.MCP_HOST_LABELS) == set(MCP_OUTPUT_PATHS)


# --------------------------------------------------------------------------- configuration


def _break_sentinel(root: Path) -> Path:
    path = root / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    path.write_text(f'[platform]\nenabled = true\nsecret = "{SECRET}\nnext = 1\n', "utf-8")
    clear_runtime_caches()
    return path


def test_configuration_loads(workspace: Path) -> None:
    empty = _only(doctor.check_configuration(_ctx(workspace)))
    assert (empty.code, empty.status) == ("configuration", "pass")
    _enable_sentinel(workspace)
    check = _only(doctor.check_configuration(_ctx(workspace)))
    assert (check.status, check.message) == ("pass", "1 configuration file loads")


def test_broken_configuration_names_the_file_and_line(workspace: Path) -> None:
    _break_sentinel(workspace)
    check = _only(doctor.check_configuration(_ctx(workspace)))
    assert check.status == "fail"
    assert check.message.startswith(
        ".opentide/configurations/platforms/sentinel.toml line 3 is not valid TOML: "
    )
    assert SECRET not in check.message
    assert check.fix and "sentinel.toml line 3" in check.fix


def test_configuration_that_fails_elsewhere_names_the_exception_only(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(ctx: DoctorContext) -> dict:
        raise KeyError(SECRET)

    monkeypatch.setattr(doctor, "_configurations", explode)
    check = _only(doctor.check_configuration(_ctx(workspace)))
    assert (check.status, check.message) == ("fail", "The configuration does not load (KeyError)")


def test_toml_problem_reports_unreadable_files(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_bytes(b"\xff\xfe")
    assert doctor._toml_problem(path) == (None, "it is not UTF-8")
    assert doctor._toml_problem(tmp_path / "missing.toml") == (
        None,
        "it cannot be read (FileNotFoundError)",
    )
    path.write_text("a = 1\n", encoding="utf-8")
    assert doctor._toml_problem(path) is None


def test_broken_configuration_skips_the_checks_that_read_it(workspace: Path) -> None:
    _break_sentinel(workspace)
    payload = doctor.run_doctor(_ctx(workspace, offline=True, env={}))
    statuses = {check["code"]: check["status"] for check in payload["checks"]}
    assert statuses["configuration"] == "fail"
    for code in (
        "templates_fresh",
        "schemas_fresh",
        "platforms_enabled",
        "platform_sdk",
        "credentials",
        "vscode_settings",
        "vscode_snippets",
    ):
        assert statuses[code] == "skip", code
    # Every code reported is one the documentation lists.
    documented = {code for codes in doctor.CHECK_CODES.values() for code in codes}
    assert set(statuses) <= documented
    assert SECRET not in json.dumps(payload)


# --------------------------------------------------------------------------- the whole run


def _fixed(*checks: Check):
    return [lambda ctx, check=check: [check] for check in checks]


def test_run_doctor_summarises_and_fails_on_any_failure(workspace: Path) -> None:
    payload = doctor.run_doctor(
        _ctx(workspace),
        _fixed(
            Check("a", "pass", "fine"),
            Check("b", "warn", "hmm", "fix b"),
            Check("c", "fail", "broken", "fix c"),
            Check("d", "skip", "not set up"),
        ),
    )
    assert payload["status"] == "failed"
    assert payload["_exit_code"] == 1
    assert payload["_failure_code"] == doctor.CHECKS_FAILED
    assert payload["message"] == "1 check failed · 1 passed, 1 warning, 1 skipped"
    assert [check["code"] for check in payload["checks"]] == ["a", "b", "c", "d"]
    assert set(payload["checks"][0]) == {"code", "status", "message", "fix", "subject"}


def test_run_doctor_warnings_exit_zero(workspace: Path) -> None:
    payload = doctor.run_doctor(
        _ctx(workspace), _fixed(Check("a", "pass", "fine"), Check("b", "warn", "hmm"))
    )
    assert payload["status"] == "issues"
    assert "_exit_code" not in payload
    assert payload["message"] == "1 warning · 1 passed"
    clean = doctor.run_doctor(_ctx(workspace), _fixed(Check("a", "pass", "fine")))
    assert (clean["status"], clean["message"]) == ("completed", "1 check passed")


def test_a_check_that_raises_is_reported_as_failed(workspace: Path) -> None:
    def check_boom(ctx: DoctorContext) -> list[Check]:
        raise RuntimeError(f"kaput {SECRET}")

    payload = doctor.run_doctor(_ctx(workspace), [check_boom])
    assert payload["checks"][0]["code"] == "boom"
    assert payload["checks"][0]["status"] == "fail"
    # The exception text can quote what the check read, so only its type is shown.
    assert payload["checks"][0]["message"] == "The check itself failed (RuntimeError)"
    assert SECRET not in json.dumps(payload)


def test_a_check_that_raises_reports_its_documented_codes(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(ctx: DoctorContext) -> dict:
        raise ValueError("no")

    monkeypatch.setattr(doctor, "_configurations", boom)
    monkeypatch.setattr(
        "opentide.cli.services.setup.vscode.build_yaml_schema_mappings",
        lambda **kwargs: boom(None),  # ty: ignore[invalid-argument-type]
    )
    (workspace / ".vscode").mkdir()
    (workspace / ".vscode" / "settings.json").write_text("{}", encoding="utf-8")
    checks = doctor._guarded(doctor.check_vscode, _ctx(workspace))
    assert [(check.code, check.status) for check in checks] == [
        ("vscode_settings", "fail"),
        ("vscode_snippets", "fail"),
    ]
    assert set(doctor.CHECK_CODES) == set(doctor.CHECKS)


def test_render_checks_prints_status_message_code_and_fix() -> None:
    console = Console(record=True, width=200, color_system=None)
    doctor.render_checks(
        console,
        [
            Check("a", "pass", "fine").to_dict(),
            Check("b", "fail", "broken", "do this").to_dict(),
            Check("c", "skip", "not set up", "opentide setup mcp").to_dict(),
        ],
    )
    text = console.export_text()
    assert "✓ fine · a" in text
    assert "✗ broken · b\n  → do this" in text
    # Skipped is ○, never the plan's "disable" glyph ``-``.
    assert "○ not set up · c\n  → opentide setup mcp" in text


def test_render_checks_falls_back_on_an_ascii_stream() -> None:
    import io

    stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
    console = Console(file=stream, width=200, color_system=None)
    doctor.render_checks(
        console,
        [Check("a", "pass", "fine").to_dict(), Check("c", "skip", "not set up", "x").to_dict()],
    )
    stream.flush()
    text = stream.buffer.getvalue().decode("ascii")  # ty: ignore[unresolved-attribute]
    assert text == "ok fine - a\no not set up - c\n  -> x\n"


def test_outcome_separator_follows_the_stream_encoding(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import sys

    checks = (Check("a", "pass", "fine"), Check("b", "skip", "later"))
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="ascii"))
    payload = doctor.run_doctor(_ctx(workspace), checks=_fixed(*checks))
    assert payload["message"] == "1 check passed - 1 skipped"


# --------------------------------------------------------------------------- the command


@pytest.fixture
def stub_checks(monkeypatch: pytest.MonkeyPatch):
    def install(*checks: Check) -> None:
        monkeypatch.setattr(doctor, "CHECKS", tuple(_fixed(*checks)))

    return install


def test_doctor_json_envelope(workspace: Path, stub_checks) -> None:
    stub_checks(Check("a", "pass", "fine"), Check("b", "warn", "hmm", "fix b"))
    result = CliRunner().invoke(app, ["--json", "--repo", str(workspace), "doctor", "--offline"])
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["command"] == "doctor"
    assert payload["checks"][1] == {
        "code": "b",
        "status": "warn",
        "message": "hmm",
        "fix": "fix b",
        "subject": None,
    }
    assert payload["summary"] == {
        "checks": 2,
        "passed": 1,
        "warnings": 1,
        "failed": 0,
        "skipped": 0,
    }
    assert payload["failure"] is None


def test_doctor_exits_one_when_a_check_fails(workspace: Path, stub_checks) -> None:
    stub_checks(Check("a", "fail", "broken", "repair"))
    result = CliRunner().invoke(app, ["--json", "--repo", str(workspace), "doctor"])
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert payload["failure"]["code"] == "doctor_checks_failed"

    plain = CliRunner().invoke(app, ["--no-color", "--repo", str(workspace), "doctor"])
    assert plain.exit_code == 1
    out = _SGR.sub("", plain.stdout)
    assert "✗ broken · a" in out or "x broken · a" in out
    assert "error: 1 check failed · 0 passed" in _SGR.sub("", plain.stderr)


def test_doctor_real_checks_offline_never_print_secrets(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_sentinel(workspace)
    monkeypatch.setenv("DOCTOR_TEST_CLIENT_ID", SECRET)
    monkeypatch.setenv("DOCTOR_TEST_CLIENT_SECRET", SECRET)
    monkeypatch.setenv("HTTPS_PROXY", f"http://carol:{SECRET}@127.0.0.1:9")
    result = CliRunner().invoke(app, ["--json", "--repo", str(workspace), "doctor", "--offline"])
    assert SECRET not in result.stdout + result.stderr
    payload = parse_cli_json(result)
    # The document matches DoctorResult and the schema `opentide commands` publishes.
    assert_matches_model(payload)
    codes = {check["code"] for check in payload["checks"]}
    assert {
        "python_version",
        "opentide_version",
        "opentide_latest",
        "workspace",
        "git",
        "configuration",
        "templates_fresh",
        "schemas_fresh",
        "platforms_enabled",
        "platform_sdk",
        "credentials",
        "proxy",
        "vscode_settings",
        "vscode_snippets",
        "mcp_config",
    } <= codes

    human = CliRunner().invoke(app, ["--no-color", "--repo", str(workspace), "doctor", "--offline"])
    assert SECRET not in human.stdout + human.stderr
    assert "sentinel/prod: all 2 variables set · credentials" in _SGR.sub("", human.stdout)
