"""Platform plugins on the Rust core (UC-4.5, #835).

The sample plugin, ``tests/fixtures/plugin_platform`` (the platform ``acme``),
is installed into a site folder of its own, as an installer would: its package
and a ``.dist-info`` with its ``opentide.platforms`` entry point. Each run is the
Rust command line in the Python package (``python -m opentide.cli.rust``), in a
child process whose ``PYTHONPATH`` holds that folder, against a stand-in Acme
tenant on 127.0.0.1 that answers from ``cassette.json`` and records what it was
sent. Nothing reaches a real host.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import materialise_corpus

from opentide import plugins

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "plugin_platform"
CASSETTE = json.loads((FIXTURE / "cassette.json").read_text(encoding="utf-8"))
VALID_RULE = "7f0c2a51-3a9e-4d7e-9d6b-2f1a8c0e5a01"
INVALID_RULE = "7f0c2a51-3a9e-4d7e-9d6b-2f1a8c0e5a02"
TOKEN = "acme-test-token"

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


class StandIn:
    """An Acme tenant that answers a cassette's exchanges in order and records each request."""

    def __init__(self, exchanges: list[dict[str, Any]]) -> None:
        self.exchanges = exchanges
        self.received: list[dict[str, Any]] = []
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8") if length else ""
                stand_in.received.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "body": json.loads(body) if body else None,
                    }
                )
                index = len(stand_in.received) - 1
                if index < len(stand_in.exchanges):
                    response = stand_in.exchanges[index]["response"]
                else:
                    response = {"status": 500, "body": {"error": "not in the cassette"}}
                payload = json.dumps(response["body"]).encode("utf-8")
                self.send_response(response["status"])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_PUT = _answer
            do_POST = _answer
            do_DELETE = _answer

            def log_message(self, format: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host!s}:{port}"

    def __enter__(self) -> StandIn:
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def requests(self) -> list[dict[str, Any]]:
        """The cassette's requests, to compare with :attr:`received`."""
        return [exchange["request"] for exchange in self.exchanges]


@pytest.fixture
def plugin_site(tmp_path: Path) -> Path:
    """The sample plugin installed in a site folder: its package and its ``.dist-info``."""
    site = tmp_path / "site"
    shutil.copytree(FIXTURE / "src" / "acme_opentide", site / "acme_opentide")
    info = site / "acme_opentide-0.1.0.dist-info"
    info.mkdir()
    info.joinpath("METADATA").write_text(
        "Metadata-Version: 2.1\nName: acme-opentide\nVersion: 0.1.0\n", encoding="utf-8"
    )
    info.joinpath("entry_points.txt").write_text(
        "[opentide.platforms]\nacme = acme_opentide:AcmePlatform\n", encoding="utf-8"
    )
    return site


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """The tide corpus with the Acme platform enabled and two Acme rules."""
    repo = materialise_corpus(tmp_path / "workspace")
    shutil.copy(
        FIXTURE / "workspace" / "acme.toml",
        repo / ".opentide" / "configurations" / "platforms" / "acme.toml",
    )
    rules = repo / "Objects" / "Detection Rules"
    for name in ("rule-acme-process.yaml", "rule-acme-invalid.yaml"):
        shutil.copy(FIXTURE / "workspace" / name, rules / name)
    return repo


_CI_VARIABLES = frozenset({"CI", "GITHUB_ACTIONS", "TF_BUILD", "GITLAB_CI"})


def _env(site: Path | None, repo: Path, url: str = "http://127.0.0.1:9") -> dict[str, str]:
    env = {
        name: value
        for name, value in os.environ.items()
        if name.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
        and not name.startswith(("OPENTIDE_", "PYTEST_"))
        # A run in CI would refuse a create outside the production job
        # (deployment_state_unpersisted): these runs are local ones.
        and name not in _CI_VARIABLES
    }
    if site is not None:
        env["PYTHONPATH"] = os.pathsep.join([str(site), env.get("PYTHONPATH", "")]).rstrip(
            os.pathsep
        )
    env.update(
        {
            "OPENTIDE_REPO_ROOT": str(repo),
            "ACME_URL": url,
            "ACME_TOKEN": TOKEN,
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "NO_COLOR": "1",
        }
    )
    return env


def _run(
    args: list[str], env: dict[str, str], cwd: Path, *, module: str = "opentide.cli.rust"
) -> tuple[int, dict[str, Any]]:
    done = subprocess.run(
        [sys.executable, "-m", module, "--json", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    assert done.stdout.strip(), done.stderr
    return done.returncode, json.loads(done.stdout)


def test_the_sample_plugin_is_discovered_with_what_it_can_do(
    plugin_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(plugin_site))
    found = {entry["id"]: entry for entry in plugins._discover()}
    assert set(found) == {"acme"}
    acme = found["acme"]
    assert acme["error"] is None
    assert isinstance(acme["plugin"], plugins.PlatformPlugin)
    assert {key: acme[key] for key in ("deploy", "validate", "query", "configuration")} == {
        "deploy": True,
        "validate": True,
        "query": True,
        "configuration": True,
    }


@pytest.mark.parametrize("module", ["opentide.cli.rust", "opentide"])
def test_validate_reports_the_plugin_models_findings_at_their_positions(
    plugin_site: Path, workspace: Path, module: str
) -> None:
    # `python -m opentide` is the console script's launcher: under the default
    # engine, validate of a workspace that enables a plugin's platform runs on
    # the Rust core, which checks the plugin's blocks (UC-4.5c).
    code, document = _run(["validate"], _env(plugin_site, workspace), workspace, module=module)
    assert code == 1
    issues = document["report"]["issues"]
    acme = [issue for issue in issues if issue["field_path"][:2] == ["configurations", "acme"]]
    by_field = {tuple(issue["field_path"]): issue for issue in acme}
    # The valid rule's block is the plugin's, not an extra key.
    assert all(issue["object_uuid"] == INVALID_RULE for issue in acme), acme
    severity = by_field[("configurations", "acme", "severity")]
    assert severity["code"] == "schema_validation"
    assert severity["message"].startswith("acme: Input should be a valid integer")
    source = (workspace / "Objects" / "Detection Rules" / "rule-acme-invalid.yaml").read_text(
        encoding="utf-8"
    )
    lines = source.splitlines()
    assert lines[severity["line"] - 1].strip() == "severity: high"
    assert severity["column"] == lines[severity["line"] - 1].index("high") + 1
    colour = by_field[("configurations", "acme", "colour")]
    assert colour["message"] == "acme: Extra inputs are not permitted"
    assert lines[colour["line"] - 1].strip().startswith("colour")
    assert not any("acme" in warning for warning in document.get("warnings", []))


def _deploy(
    site: Path, repo: Path, url: str, strategy: str = "PREVIEW", *extra: str
) -> tuple[int, dict[str, Any]]:
    return _run(
        ["deploy", "--platform", "acme", "--strategy", strategy, "--uuid", VALID_RULE, *extra],
        _env(site, repo, url),
        repo,
    )


def _shard(repo: Path) -> Path:
    return repo / ".opentide" / "states" / "deployment" / f"{VALID_RULE}.json"


def _record(repo: Path, remote_id: str) -> None:
    """Deployment state holding *remote_id* for the sample rule on the ``lab`` tenant."""
    shard = _shard(repo)
    shard.parent.mkdir(parents=True, exist_ok=True)
    shard.write_text(
        json.dumps(
            {
                "object_uuid": VALID_RULE,
                "platforms": {"acme": {"lab": remote_id}},
                "schema": "deployment.state::1.0",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _set_status(repo: Path, status: str) -> None:
    rule = repo / "Objects" / "Detection Rules" / "rule-acme-process.yaml"
    text = rule.read_text(encoding="utf-8")
    rule.write_text(
        text.replace("acme:\n    status: STAGING", f"acme:\n    status: {status}"),
        encoding="utf-8",
    )


_SDK_VALIDATE = """
import json, sys
import opentide
validation = opentide.Workspace.open(sys.argv[1]).validate(check="schema", queries="off")
print(json.dumps(validation.report))
"""


@pytest.mark.parametrize("installed", [True, False])
def test_the_sdk_validate_checks_a_plugin_block_with_the_plugins_model(
    plugin_site: Path, workspace: Path, installed: bool
) -> None:
    # opentide.Workspace.validate runs the CLI's check of plugin blocks
    # (UC-4.5b): with the plugin, its findings inside the block; without it,
    # the block is an extra key, as before.
    done = subprocess.run(
        [sys.executable, "-c", _SDK_VALIDATE, str(workspace)],
        cwd=workspace,
        env=_env(plugin_site if installed else None, workspace),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    issues = json.loads(done.stdout)["issues"]
    acme = {
        (issue["object_uuid"], tuple(issue["field_path"])): issue["message"]
        for issue in issues
        if issue["field_path"][:2] == ["configurations", "acme"]
    }
    if installed:
        assert acme[(INVALID_RULE, ("configurations", "acme", "severity"))].startswith(
            "acme: Input should be a valid integer"
        )
        assert acme[(INVALID_RULE, ("configurations", "acme", "colour"))] == (
            "acme: Extra inputs are not permitted"
        )
        assert not any(uuid == VALID_RULE for uuid, _ in acme), acme
    else:
        assert {uuid for uuid, _ in acme} == {VALID_RULE, INVALID_RULE}
        assert all(field == ("configurations", "acme") for _, field in acme)


def test_the_sample_plugin_creates_a_rule_and_records_its_id(
    plugin_site: Path, workspace: Path
) -> None:
    with StandIn(CASSETTE["deploy"]) as tenant:
        code, document = _deploy(plugin_site, workspace, tenant.url)
    assert code == 0, document
    assert tenant.received == tenant.requests()
    [result] = document["results"]
    assert {key: result[key] for key in ("platform", "tenant", "id", "status")} == {
        "platform": "acme",
        "tenant": "lab",
        "id": VALID_RULE,
        "status": "deployed",
    }
    assert [change["action"] for change in document["changes"]] == ["create"]
    state = json.loads(_shard(workspace).read_text(encoding="utf-8"))
    assert state["platforms"] == {"acme": {"lab": "acme-rule-17"}}


@pytest.mark.parametrize(
    ("scenario", "status", "strategy", "action"),
    [
        ("deploy_update", "STAGING", "PREVIEW", "update"),
        ("deploy_disable", "DISABLED", "RELEASE", "disable"),
        ("deploy_delete", "REMOVED", "RELEASE", "delete"),
    ],
)
def test_the_sample_plugin_changes_the_rule_deployment_state_names(
    plugin_site: Path, workspace: Path, scenario: str, status: str, strategy: str, action: str
) -> None:
    _record(workspace, "acme-rule-17")
    _set_status(workspace, status)
    with StandIn(CASSETTE[scenario]) as tenant:
        code, document = _deploy(plugin_site, workspace, tenant.url, strategy)
    assert code == 0, document
    assert tenant.received == tenant.requests()
    assert [change["action"] for change in document["changes"]] == [action]
    if action == "delete":
        # The id is forgotten, and the shard with it.
        assert not _shard(workspace).exists()
    else:
        state = json.loads(_shard(workspace).read_text(encoding="utf-8"))
        assert state["platforms"] == {"acme": {"lab": "acme-rule-17"}}


def test_a_refused_deploy_fails_the_run_with_the_tenants_reason(
    plugin_site: Path, workspace: Path
) -> None:
    with StandIn(CASSETTE["deploy_refused"]) as tenant:
        code, document = _deploy(plugin_site, workspace, tenant.url)
    assert code == 1
    assert tenant.received == tenant.requests()
    [result] = document["results"]
    assert result["status"] == "failed"
    assert result["error"] == (
        'PlatformRefused: Acme answered 422: {"error": "severity 3 needs a playbook"}'
    )
    assert not _shard(workspace).exists()
    # The token reaches the tenant, never the report.
    assert TOKEN not in json.dumps(document)


def test_a_dry_run_sends_nothing(plugin_site: Path, workspace: Path) -> None:
    with StandIn([]) as tenant:
        code, document = _run(
            ["deploy", "--platform", "acme", "--strategy", "PREVIEW", "--all", "--dry-run"],
            _env(plugin_site, workspace, tenant.url),
            workspace,
        )
    assert code == 0, document
    assert tenant.received == []
    assert set(document["plan"]) == {"acme"}
    assert {change["action"] for change in document["changes"]} == {"create"}
    assert not _shard(workspace).exists()


@pytest.mark.parametrize(("scenario", "valid"), [("validate", True), ("validate_invalid", False)])
def test_the_sample_plugin_checks_a_rules_query_on_the_tenant(
    plugin_site: Path, workspace: Path, scenario: str, valid: bool
) -> None:
    with StandIn(CASSETTE[scenario]) as tenant:
        code, document = _run(
            ["validate", "query", "--live", "--platform", "acme", "--uuid", VALID_RULE],
            _env(plugin_site, workspace, tenant.url),
            workspace,
        )
    assert tenant.received == tenant.requests()
    assert code == (0 if valid else 1), document
    assert document["supported"] is True
    assert document["valid"] is valid
    [result] = document["results"]
    assert result["valid"] is valid
    assert result["errors"] == ([] if valid else ["unknown field name"])


def test_the_sample_plugin_runs_a_query(plugin_site: Path, workspace: Path) -> None:
    with StandIn(CASSETTE["query"]) as tenant:
        code, document = _run(
            [
                "query",
                "--platform",
                "acme",
                "--from",
                "2026-11-01T00:00:00Z",
                "--to",
                "2026-11-02T00:00:00Z",
                "--limit",
                "2",
                "process | head",
            ],
            _env(plugin_site, workspace, tenant.url),
            workspace,
        )
    assert code == 0, document
    assert tenant.received == tenant.requests()
    [result] = document["results"]
    assert result["rows"] == [
        {"host": "ws-1", "process": "cmd.exe", "count": 4},
        {"host": "ws-2", "process": "powershell.exe", "count": 1},
    ]
    assert result["truncated"] is True
    assert document["row_count"] == 2


@pytest.mark.parametrize("engine", ["rust", "", None])
def test_the_console_script_routes_a_plugin_run_to_the_rust_core(
    plugin_site: Path, workspace: Path, engine: str | None
) -> None:
    # OPENTIDE_ENGINE=rust, blank or unset (the default engine): only the
    # Rust core reaches a plugin, so a plugin run goes there (UC-4.5b).
    env = _env(plugin_site, workspace)
    if engine is not None:
        env["OPENTIDE_ENGINE"] = engine
    with StandIn(CASSETTE["deploy"]) as tenant:
        env["ACME_URL"] = tenant.url
        code, document = _run(
            ["deploy", "--platform", "acme", "--strategy", "PREVIEW", "--uuid", VALID_RULE],
            env,
            workspace,
            module="opentide",
        )
    assert code == 0, document
    assert tenant.received == tenant.requests()


def test_the_python_engine_keeps_the_python_command_line(
    plugin_site: Path, workspace: Path
) -> None:
    # OPENTIDE_ENGINE=python is the Python command line, which knows the
    # built-in platforms only: it refuses the plugin's name, and sends nothing.
    env = _env(plugin_site, workspace)
    env["OPENTIDE_ENGINE"] = "python"
    with StandIn([]) as tenant:
        env["ACME_URL"] = tenant.url
        code, document = _run(
            ["deploy", "--platform", "acme", "--strategy", "PREVIEW", "--uuid", VALID_RULE],
            env,
            workspace,
            module="opentide",
        )
    assert code == 2, document
    assert tenant.received == []


def test_the_default_engine_queries_a_plugin_through_python_m_opentide(
    plugin_site: Path, workspace: Path
) -> None:
    # `python -m opentide` (the console script's launcher) under the default
    # engine: a query on the plugin's platform runs on Rust.
    with StandIn(CASSETTE["query"]) as tenant:
        code, document = _run(
            [
                "query",
                "--platform",
                "acme",
                "--from",
                "2026-11-01T00:00:00Z",
                "--to",
                "2026-11-02T00:00:00Z",
                "--limit",
                "2",
                "process | head",
            ],
            _env(plugin_site, workspace, tenant.url),
            workspace,
            module="opentide",
        )
    assert code == 0, document
    assert tenant.received == tenant.requests()
    assert document["row_count"] == 2


def test_the_python_engine_reports_a_plugin_block_as_an_extra_key(
    plugin_site: Path, workspace: Path
) -> None:
    # OPENTIDE_ENGINE=python is the escape hatch: the Python implementation,
    # which cannot load a plugin, as before UC-4.5c.
    env = _env(plugin_site, workspace)
    env["OPENTIDE_ENGINE"] = "python"
    code, document = _run(["validate"], env, workspace, module="opentide")
    assert code == 1
    extra = [
        issue
        for issue in document["report"]["issues"]
        if issue["field_path"][:2] == ["configurations", "acme"]
    ]
    assert {issue["object_uuid"] for issue in extra} == {VALID_RULE, INVALID_RULE}
    assert all(issue["field_path"] == ["configurations", "acme"] for issue in extra), extra


def test_compare_refuses_to_validate_a_plugin_workspace(plugin_site: Path, workspace: Path) -> None:
    # The two implementations cannot agree on a plugin's blocks (UC-4.5c).
    env = _env(plugin_site, workspace)
    env["OPENTIDE_ENGINE"] = "compare"
    code, document = _run(["validate"], env, workspace, module="opentide")
    assert code == 2
    assert document["failure"]["code"] == "usage_error"
    assert document["failure"]["message"].startswith(
        "OPENTIDE_ENGINE=compare cannot compare opentide validate on this workspace: "
        "it enables acme, from a platform plugin"
    )


def test_without_the_plugin_installed_the_workspace_is_told(workspace: Path) -> None:
    code, document = _run(["validate"], _env(None, workspace), workspace)
    assert code == 1
    assert (
        "acme is enabled, but no installed opentide.platforms plugin provides it"
        in (document["warnings"])
    )
    extra = [
        issue
        for issue in document["report"]["issues"]
        if issue["field_path"] == ["configurations", "acme"]
    ]
    assert {issue["object_uuid"] for issue in extra} == {VALID_RULE, INVALID_RULE}


# The SDK layer's side of the boundary, called as the binding calls it.


class _Broken(plugins.PlatformPlugin):
    def run_query(
        self, tenant: plugins.Tenant, request: plugins.QueryRequest
    ) -> plugins.QueryResult:
        raise ValueError("boom")

    def deploy(
        self, tenant: plugins.Tenant, request: plugins.DeployRequest
    ) -> plugins.DeployResult:
        raise plugins.PlatformAuthenticationError("bad key", "401")


_TENANT = json.dumps(
    {
        "platform": "broken",
        "name": "t",
        "setup": {"token": "x"},
        "lists": {"index": ["a"]},
        "verify_tls": True,
        "timeout": 5,
    }
)
_QUERY = json.dumps(
    {
        "text": "q",
        "language": "",
        "start": "a",
        "end": "b",
        "limit": 1,
        "index": [],
        "data_view": None,
        "timeout": 3,
    }
)


def test_a_plugins_failures_cross_as_errors_not_crashes() -> None:
    broken = _Broken()
    failed = json.loads(plugins._invoke(broken, "run_query", _TENANT, _QUERY))
    assert failed == {"error": {"kind": "failed", "message": "ValueError: boom"}}
    auth = json.loads(
        plugins._invoke(
            broken,
            "deploy",
            _TENANT,
            json.dumps({"rule_id": "r", "operation": "create", "body": {}}),
        )
    )
    assert auth == {"error": {"kind": "authentication", "message": "bad key", "detail": "401"}}
    unsupported = json.loads(plugins._invoke(broken, "validate_query", _TENANT, _QUERY))
    assert unsupported["error"]["message"].startswith("NotImplementedError")
    assert json.loads(plugins._invoke(broken, "check_configuration", "{}")) == {
        "ok": {"findings": []}
    }
    assert plugins.capabilities(broken) == {
        "deploy": True,
        "validate": False,
        "query": True,
        "configuration": False,
    }


def test_an_entry_point_names_a_plugin_class_instance_or_factory() -> None:
    instance = _Broken()
    assert plugins._instance(_Broken).__class__ is _Broken
    assert plugins._instance(instance) is instance
    assert plugins._instance(lambda: instance) is instance
    with pytest.raises(TypeError, match=r"is not an opentide\.plugins\.PlatformPlugin"):
        plugins._instance(object())
    with pytest.raises(TypeError):
        plugins._instance(lambda: 1)


def test_a_wrong_result_type_is_reported() -> None:
    class Wrong(plugins.PlatformPlugin):
        def run_query(self, tenant: plugins.Tenant, request: plugins.QueryRequest) -> Any:
            return {"rows": []}

        def validate_query(self, tenant: plugins.Tenant, request: plugins.QueryRequest) -> Any:
            return plugins.LiveCheck(
                warnings=["slow"], result=plugins.QueryResult(rows=[{"a": 1}], columns=None)
            )

        def deploy(self, tenant: plugins.Tenant, request: plugins.DeployRequest) -> Any:
            return None

    wrong = Wrong()
    answer = json.loads(plugins._invoke(wrong, "run_query", _TENANT, _QUERY))
    assert answer["error"]["message"] == "TypeError: run_query returned dict, not QueryResult"
    checked = json.loads(plugins._invoke(wrong, "validate_query", _TENANT, _QUERY))["ok"]
    assert checked["warnings"] == ["slow"]
    assert checked["result"]["rows"] == [{"a": 1}]
    assert checked["result"]["columns"] is None
    deployed = json.loads(
        plugins._invoke(
            wrong, "deploy", _TENANT, json.dumps({"rule_id": "r", "operation": "create", "body": 1})
        )
    )
    assert deployed["error"]["message"] == "TypeError: deploy returned NoneType, not DeployResult"


def test_entry_points_that_cannot_be_plugins_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    info = tmp_path / "bad_plugins-0.1.dist-info"
    info.mkdir()
    info.joinpath("METADATA").write_text(
        "Metadata-Version: 2.1\nName: bad-plugins\nVersion: 0.1\n", encoding="utf-8"
    )
    info.joinpath("entry_points.txt").write_text(
        "[opentide.platforms]\nBad-Name = json:loads\nmissing = no_such_module:Plugin\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    found = {entry["id"]: entry for entry in plugins._discover()}
    assert "lower case letters" in found["Bad-Name"]["error"]
    assert found["missing"]["error"].startswith("ModuleNotFoundError")


def test_the_routing_covers_plugin_runs_only_when_the_plugin_is_installed(
    plugin_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.cli.engines import RUST_COMMANDS, plugin_platforms

    # Every deploy runs on Rust since UC-4.4c (#834): a plugin run is what
    # `compare` refuses, as it reaches the plugin's tenant.
    deploy = RUST_COMMANDS[("deploy",)]
    query = RUST_COMMANDS[("query",)]
    assert not deploy.plugin_run(["--platform", "acme", "--dry-run"])
    assert not query.covers(["--platform", "acme", "q"])
    monkeypatch.syspath_prepend(str(plugin_site))
    assert plugin_platforms() == frozenset({"acme"})
    assert deploy.plugin_run(["--platform", "acme", "--dry-run"])
    assert deploy.plugin_run(["--platform=acme", "--uuid", "x"])
    assert not deploy.plugin_run(["--platform", "sentinel", "--all"])
    assert not deploy.plugin_run(["--platform", "acme", "--platform", "other"])
    assert query.covers(["--platform", "acme", "q"])
    assert query.covers(["--platform=acme", "q"])
    assert not query.covers(["--platform", "acme", "--platform", "other"])
    # A rule's query goes to Rust too, which refuses it on a plugin's platform
    # with engine_not_ported (the rule's block is the plugin's to read).
    assert query.covers(["--platform", "acme", "--rule", "r"])
    live = RUST_COMMANDS[("validate", "query")]
    assert live.covers(["--live", "--platform", "acme"])
    assert not RUST_COMMANDS[("lint",)].plugin_run(["--platform", "acme"])
