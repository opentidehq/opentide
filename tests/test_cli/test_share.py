"""opentide share against the corpus and a fake MISP client."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from tests.test_sharing.test_engine import FakeMisp

from opentide.sharing.client import RemoteEvent, TemplateView
from opentide.sharing.constants import OPENTIDE_TEMPLATE_VERSION, REQUIRED_TEMPLATE_RELATIONS

ORG_BLOCK = "00000000-0000-4000-8aaa-000000000001"
KEY = "share-test-secret"


class _Persistent(FakeMisp):
    events: list[RemoteEvent] = []

    def __init__(self, url: str, api_key: str, *, verify_ssl: bool = True) -> None:
        super().__init__()
        self.url = url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.org = ORG_BLOCK
        self.events = _Persistent.events
        self.template = TemplateView(
            True,
            OPENTIDE_TEMPLATE_VERSION,
            frozenset(REQUIRED_TEMPLATE_RELATIONS),
            frozenset({"threat", "objective", "rule"}),
        )


def _write_sharing(repo: Path, *, enabled: bool = True, key: str = "${MISP_LAB_KEY}") -> None:
    path = repo / ".opentide" / "configurations" / "sharing.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "[[misp]]",
                'name = "lab"',
                'url = "https://misp.example/base"',
                f'api_key = "{key}"',
                'max_tlp = "green"',
                f"enabled = {str(enabled).lower()}",
                f'organisation_uuid = "{ORG_BLOCK}"',
                'object_types = ["objective"]',
                "publish = false",
                "verify_ssl = true",
                "",
            ]
        ),
        encoding="utf-8",
    )


@pytest.fixture(autouse=True)
def _reset_events() -> None:
    _Persistent.events = []


def test_targets_never_print_the_api_key(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_sharing(tide_corpus_repo, key=KEY)
    monkeypatch.setenv("MISP_LAB_KEY", KEY)
    listed = invoke_cli("share", "targets", repo=tide_corpus_repo)
    assert listed.exit_code == 0, listed.stdout
    payload = json.loads(listed.stdout)
    assert payload["targets"] == [
        {
            "integration": "misp",
            "name": "lab",
            "enabled": True,
            "max_tlp": "green",
            "url": "https://misp.example/base",
        }
    ]
    assert KEY not in listed.stdout


def test_preview_makes_no_request_and_push_records_a_line(
    invoke_cli,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_sharing(tide_corpus_repo)
    monkeypatch.setenv("MISP_LAB_KEY", KEY)
    monkeypatch.setattr("opentide.sharing.engine.PyMispClient", _Persistent)
    preview = invoke_cli("share", "preview", "--type", "objective", repo=tide_corpus_repo)
    assert preview.exit_code == 0, preview.stdout
    body = json.loads(preview.stdout)
    assert body["records"]
    assert all(
        record["action"] in {"created", "skipped_tlp", "skipped_type"} for record in body["records"]
    )
    assert _Persistent.events == []
    assert not (tide_corpus_repo / ".opentide" / "states" / "sharing.jsonl").exists()

    pushed = invoke_cli("share", "push", "--type", "objective", repo=tide_corpus_repo)
    assert pushed.exit_code == 0, pushed.stdout
    created = json.loads(pushed.stdout)
    assert any(record["action"] == "created" for record in created["records"])
    assert KEY not in pushed.stdout
    ledger = tide_corpus_repo / ".opentide" / "states" / "sharing.jsonl"
    assert ledger.is_file()
    assert KEY not in ledger.read_text(encoding="utf-8")

    again = invoke_cli("share", "push", "--type", "objective", repo=tide_corpus_repo)
    assert again.exit_code == 0, again.stdout
    second = json.loads(again.stdout)
    assert any(record["action"] == "unchanged" for record in second["records"])


def test_unknown_target_and_unconfirmed_delete_are_preflight(
    invoke_cli,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_sharing(tide_corpus_repo)
    monkeypatch.setenv("MISP_LAB_KEY", KEY)
    monkeypatch.setattr("opentide.sharing.engine.PyMispClient", _Persistent)
    unknown = invoke_cli("share", "push", "--target", "missing", repo=tide_corpus_repo)
    assert unknown.exit_code == 1
    assert "No sharing target matched" in unknown.stdout
    assert _Persistent.events == []
    unconfirmed = invoke_cli(
        "share", "retract", "--delete", "--type", "objective", repo=tide_corpus_repo
    )
    assert unconfirmed.exit_code == 1
    assert "Pass --yes" in unconfirmed.stdout


def test_disabled_target_and_unknown_type(invoke_cli, tide_corpus_repo: Path) -> None:
    _write_sharing(tide_corpus_repo, enabled=False)
    disabled = invoke_cli("share", "status", "--target", "lab", repo=tide_corpus_repo)
    assert disabled.exit_code == 1
    unknown = invoke_cli("share", "preview", "--type", "playbook", repo=tide_corpus_repo)
    assert unknown.exit_code == 2


def test_share_help_lists_the_subcommands(cli_runner, monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli import app

    # GitHub Actions forces color, and a narrow width ellipsizes `--changed`.
    monkeypatch.setenv("COLUMNS", "120")
    monkeypatch.setenv("LINES", "40")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    result = cli_runner.invoke(app, ["share", "--help"])
    assert result.exit_code == 0
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    for name in ("push", "preview", "status", "retract", "targets", "--changed"):
        assert name in plain
    push = cli_runner.invoke(app, ["share", "push", "--help"])
    assert push.exit_code == 0
    assert "--changed" in push.stdout
    preview = cli_runner.invoke(app, ["share", "preview", "--help"])
    assert preview.exit_code == 0
    assert "--changed" not in preview.stdout


def test_usage_and_config_preflight(invoke_cli, tide_corpus_repo: Path) -> None:
    workers = invoke_cli("share", "push", "--workers", "0", repo=tide_corpus_repo)
    assert workers.exit_code == 2
    assert "at least 1" in workers.stdout

    path = tide_corpus_repo / ".opentide" / "configurations" / "sharing.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[[misp]]\nname = "lab"\n', encoding="utf-8")
    invalid = invoke_cli("share", "targets", repo=tide_corpus_repo)
    assert invalid.exit_code == 1
    body = json.loads(invalid.stdout)
    assert body["preflight"] == "sharing_config"
    assert body["issues"]


def test_scope_filters_and_unset_key(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_sharing(tide_corpus_repo, enabled=False)
    none = invoke_cli("share", "push", repo=tide_corpus_repo)
    assert none.exit_code == 1
    assert json.loads(none.stdout)["preflight"] == "scope_no_match"

    _write_sharing(tide_corpus_repo)
    monkeypatch.setenv("MISP_LAB_KEY", KEY)
    monkeypatch.setattr("opentide.sharing.engine.PyMispClient", _Persistent)
    status = invoke_cli("share", "status", repo=tide_corpus_repo)
    assert status.exit_code == 0, status.stdout
    objective = "00000000-0000-4000-8002-000000000001"
    relative = "objects/objectives/objective-0001-credential-access.yaml"
    selected = invoke_cli(
        "share",
        "--target",
        "lab",
        "--target",
        "lab",
        "--uuid",
        objective,
        "--file",
        relative,
        "--dry-run",
        repo=tide_corpus_repo,
        extra_env={"VALIDATION_ERROR_RAISED": "1", "VALIDATION_WARNING_RAISED": "1"},
    )
    assert selected.exit_code == 0, selected.stdout
    records = json.loads(selected.stdout)["records"]
    assert records
    assert {record["object_uuid"] for record in records} == {objective}
    assert _Persistent.events == []

    _write_sharing(tide_corpus_repo, key="${MISP_MISSING_KEY}")
    unset = invoke_cli("share", "push", "--type", "objective", repo=tide_corpus_repo)
    assert unset.exit_code == 1
    assert json.loads(unset.stdout)["preflight"] == "api_key_unset"


def test_human_tables_and_retract(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_sharing(tide_corpus_repo, key=KEY)
    monkeypatch.setattr("opentide.sharing.engine.PyMispClient", _Persistent)
    listed = invoke_cli("share", "targets", repo=tide_corpus_repo, json_output=False)
    assert listed.exit_code == 0, listed.stdout
    rendered = listed.stdout + listed.stderr
    assert "Sharing targets" in listed.stdout
    assert "lab" in listed.stdout
    assert KEY not in rendered
    assert "literal" in rendered.lower()

    pushed = invoke_cli(
        "share", "push", "--type", "objective", repo=tide_corpus_repo, json_output=False
    )
    assert pushed.exit_code == 0, pushed.stdout
    assert "Share" in pushed.stdout
    assert "created" in pushed.stdout

    empty = invoke_cli(
        "share", "status", "--target", "missing", repo=tide_corpus_repo, json_output=False
    )
    assert empty.exit_code == 1

    removed = invoke_cli(
        "share",
        "retract",
        "--delete",
        "--yes",
        "--type",
        "objective",
        repo=tide_corpus_repo,
    )
    assert removed.exit_code == 0, removed.stdout
    assert any(record["action"] == "retracted" for record in json.loads(removed.stdout)["records"])
    ledger = tide_corpus_repo / ".opentide" / "states" / "sharing.jsonl"
    text = ledger.read_text(encoding="utf-8") if ledger.is_file() else ""
    assert "00000000-0000-4000-8002" not in text


def test_invalid_object_is_a_validation_failure(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_sharing(tide_corpus_repo)
    monkeypatch.setenv("MISP_LAB_KEY", KEY)
    monkeypatch.setattr("opentide.sharing.engine.PyMispClient", _Persistent)
    broken = tide_corpus_repo / "objects" / "objectives" / "objective-0099-broken.yaml"
    broken.write_text(
        "\n".join(
            [
                "name: Broken Objective",
                "metadata:",
                "  uuid: 00000000-0000-4000-8002-000000000099",
                "  schema: objective::1.0",
                "  version: 1",
                "  created: 2026-01-01",
                "  modified: 2026-01-02",
                "  tlp: clear",
                "",
            ]
        ),
        encoding="utf-8",
    )
    result = invoke_cli(
        "share",
        "push",
        "--uuid",
        "00000000-0000-4000-8002-000000000099",
        repo=tide_corpus_repo,
    )
    assert result.exit_code == 1, result.stdout
    record = json.loads(result.stdout)["records"][0]
    assert record["action"] == "failed"
    assert record["reason"] == "validation_error"
    assert _Persistent.events == []


def test_validator_attaches_path_and_scope_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from opentide.cli.services.share import _validator, render_share
    from opentide.sharing.document import load_document
    from opentide.validation.issues import ValidationIssue, ValidationReport

    path = tmp_path / "objective.yaml"
    path.write_text(
        "\n".join(
            [
                "name: Broken",
                "metadata:",
                "  uuid: 00000000-0000-4000-8002-000000000099",
                "  schema: objective::1.0",
                "",
            ]
        ),
        encoding="utf-8",
    )
    document = load_document(path.read_bytes(), path=path)
    parsed = ValidationReport(
        ok=False,
        issues=[
            ValidationIssue(
                code="yaml_parse",
                message="Could not parse object YAML: bad",
                file_path=path,
            )
        ],
    )
    monkeypatch.setattr("opentide.cli.services.share.run_validation", lambda **_kwargs: parsed)
    validate = _validator([document])
    assert validate is not None
    assert validate(document) == "Could not parse object YAML: bad"

    unmatched = ValidationReport(
        ok=False,
        issues=[
            ValidationIssue(
                code="scope_no_match",
                message="No objects matched the validation scope",
            )
        ],
    )
    monkeypatch.setattr("opentide.cli.services.share.run_validation", lambda **_kwargs: unmatched)
    validate = _validator([document])
    assert validate is not None
    assert validate(document) == "No objects matched the validation scope"
    render_share(
        {
            "records": [
                "skip",
                {"object_uuid": document.uuid, "target": "lab", "action": "failed"},
            ]
        }
    )


def test_catalogue_ignores_a_malformed_index(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from opentide.cli.services.share import _catalogue, _validator
    from opentide.core.registry import OpenTide
    from opentide.sharing.document import TideDocument

    assert _validator([TideDocument("", {}, None, "missing")]) is None

    present = tmp_path / "present.yaml"
    present.write_bytes(b"name: Present\nmetadata:\n  uuid: abc\n  schema: threat::1.0\n")
    missing = tmp_path / "gone.yaml"
    index = {
        "objects": {
            "threat": "not-a-mapping",
            "objective": {"gone": {"name": "Gone"}, "blank": {"name": "Blank"}},
            "rule": {},
        },
        "file_paths": {"gone": str(missing), "blank": ""},
        "parse_errors": [
            "skip",
            {},
            {"path": ""},
            {"path": str(present)},
            {"path": str(present)},
        ],
    }
    monkeypatch.setattr(OpenTide, "initialise", lambda: None)
    monkeypatch.setattr(OpenTide, "_index", index)
    documents = _catalogue()
    assert any(document.parse_error == "missing" for document in documents)
    assert any(document.path == present for document in documents)

    monkeypatch.setattr(
        OpenTide,
        "_index",
        {"objects": {"threat": {"x": {}}}, "file_paths": ["nope"]},
    )
    unpathed = _catalogue()
    assert len(unpathed) == 1
    assert unpathed[0].parse_error == "missing"


def _ci_env(**overrides: str) -> dict[str, str]:
    """Isolate one CI platform. Click keeps runner variables that are not replaced."""
    env = {
        "CI": "",
        "GITHUB_ACTIONS": "",
        "GITHUB_EVENT_NAME": "",
        "TF_BUILD": "",
        "BUILD_REASON": "",
        "CI_PIPELINE_SOURCE": "",
    }
    env.update(overrides)
    return env


_OUTSIDE_CI = _ci_env()
_GITHUB_PUSH = _ci_env(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="push")
_OBJECTIVE = "objects/objectives/objective-0001-credential-access.yaml"
_OBJECTIVE_UUID = "00000000-0000-4000-8002-000000000001"


def _forbid_diff(_plan: object) -> list[str]:
    raise AssertionError("diff_calculation must not run")


def test_changed_stops_before_git_or_http(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("opentide.deployment.git_repo.diff_calculation", _forbid_diff)
    monkeypatch.setattr("opentide.sharing.engine.PyMispClient", _Persistent)
    _write_sharing(tide_corpus_repo)
    monkeypatch.setenv("MISP_LAB_KEY", KEY)

    outside = invoke_cli("share", "push", "--changed", repo=tide_corpus_repo, extra_env=_OUTSIDE_CI)
    assert outside.exit_code == 1, outside.stdout
    assert json.loads(outside.stdout)["preflight"] == "changed_outside_ci"
    assert _Persistent.events == []

    for event in ("pull_request", "pull_request_target"):
        pull = invoke_cli(
            "share",
            "push",
            "--changed",
            repo=tide_corpus_repo,
            extra_env=_ci_env(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME=event),
        )
        assert pull.exit_code == 1, pull.stdout
        assert json.loads(pull.stdout)["preflight"] == "changed_on_pull_request"

    gitlab = invoke_cli(
        "share",
        "push",
        "--changed",
        repo=tide_corpus_repo,
        extra_env=_ci_env(CI="true", CI_PIPELINE_SOURCE="merge_request_event"),
    )
    assert json.loads(gitlab.stdout)["preflight"] == "changed_on_pull_request"

    azure = invoke_cli(
        "share",
        "push",
        "--changed",
        repo=tide_corpus_repo,
        extra_env=_ci_env(TF_BUILD="True", BUILD_REASON="PullRequest"),
    )
    assert json.loads(azure.stdout)["preflight"] == "changed_on_pull_request"

    unknown = invoke_cli(
        "share",
        "push",
        "--changed",
        "--target",
        "missing",
        repo=tide_corpus_repo,
        extra_env=_GITHUB_PUSH,
    )
    assert unknown.exit_code == 1
    assert json.loads(unknown.stdout)["preflight"] == "scope_no_match"

    _write_sharing(tide_corpus_repo, enabled=False)
    idle = invoke_cli("share", "push", "--changed", repo=tide_corpus_repo, extra_env=_GITHUB_PUSH)
    assert idle.exit_code == 0, idle.stdout
    assert "No enabled sharing target" in idle.stdout
    assert _Persistent.events == []

    path = tide_corpus_repo / ".opentide" / "configurations" / "sharing.toml"
    path.write_text('[[misp]]\nname = "lab"\n', encoding="utf-8")
    invalid = invoke_cli("share", "push", "--changed", repo=tide_corpus_repo, extra_env=_OUTSIDE_CI)
    assert json.loads(invalid.stdout)["preflight"] == "sharing_config"


def test_changed_uses_the_production_diff(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MISP_LAB_KEY", KEY)
    monkeypatch.setattr("opentide.sharing.engine.PyMispClient", _Persistent)
    _write_sharing(tide_corpus_repo)
    nested = tide_corpus_repo / "objects" / "objectives" / "nested" / "extra.yaml"
    nested.parent.mkdir(parents=True)
    nested.write_text("name: Nested\n", encoding="utf-8")
    seen: list[object] = []

    def _diff(plan: object) -> list[str]:
        seen.append(plan)
        return [
            _OBJECTIVE,
            "objects/objectives/nested/extra.yaml",
            "objects/objectives/notes.txt",
        ]

    monkeypatch.setattr("opentide.deployment.git_repo.diff_calculation", _diff)
    pushed = invoke_cli("share", "push", "--changed", repo=tide_corpus_repo, extra_env=_GITHUB_PUSH)
    assert pushed.exit_code == 0, pushed.stdout
    records = json.loads(pushed.stdout)["records"]
    assert {record["object_uuid"] for record in records} == {_OBJECTIVE_UUID}
    assert any(record["action"] == "created" for record in records)
    assert len(_Persistent.events) == 1
    assert seen

    _Persistent.events = []

    def _empty(_plan: object) -> list[str]:
        return []

    monkeypatch.setattr("opentide.deployment.git_repo.diff_calculation", _empty)
    empty = invoke_cli("share", "push", "--changed", repo=tide_corpus_repo, extra_env=_GITHUB_PUSH)
    assert empty.exit_code == 0, empty.stdout
    assert "No changed objects to share" in empty.stdout
    assert _Persistent.events == []
    azure = invoke_cli(
        "share",
        "push",
        "--changed",
        repo=tide_corpus_repo,
        extra_env=_ci_env(TF_BUILD="True", BUILD_REASON="IndividualCI"),
    )
    assert azure.exit_code == 0, azure.stdout
    assert "No changed objects to share" in azure.stdout
    gitlab = invoke_cli(
        "share",
        "push",
        "--changed",
        repo=tide_corpus_repo,
        extra_env=_ci_env(CI="true", CI_PIPELINE_SOURCE="push"),
    )
    assert gitlab.exit_code == 0, gitlab.stdout
    assert "No changed objects to share" in gitlab.stdout

    monkeypatch.setattr("opentide.deployment.git_repo.diff_calculation", _diff)
    narrowed = invoke_cli(
        "share",
        "push",
        "--changed",
        "--type",
        "rule",
        repo=tide_corpus_repo,
        extra_env=_GITHUB_PUSH,
    )
    assert narrowed.exit_code == 0, narrowed.stdout
    assert "No changed objects to share" in narrowed.stdout
    assert _Persistent.events == []

    def _boom(_plan: object) -> list[str]:
        raise Exception("Could not find git commit abc")

    monkeypatch.setattr("opentide.deployment.git_repo.diff_calculation", _boom)
    missing = invoke_cli(
        "share", "push", "--changed", repo=tide_corpus_repo, extra_env=_GITHUB_PUSH
    )
    assert missing.exit_code == 1, missing.stdout
    body = json.loads(missing.stdout)
    assert body["preflight"] == "changed_diff"
    assert "Could not find git commit abc" in body["message"]
    assert _Persistent.events == []


def test_changed_path_filter_keeps_direct_yaml_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.cli.services.share import (
        _PREFLIGHT,
        _changed_files,
        _direct_object_files,
        _intersect_changed,
    )
    from opentide.sharing.engine import ShareFilters

    objective = tmp_path / "objects" / "objectives"
    objective.mkdir(parents=True)
    good = objective / "one.yaml"
    good.write_text(
        "metadata:\n  uuid: 00000000-0000-4000-8002-000000000001\n  schema: objective::1.0\n",
        encoding="utf-8",
    )
    nested = objective / "nested" / "two.yml"
    nested.parent.mkdir()
    nested.write_text("metadata:\n  uuid: 00000000-0000-4000-8002-000000000002\n", encoding="utf-8")
    (objective / "notes.txt").write_text("skip", encoding="utf-8")
    changed = [
        "objects/objectives/one.yaml",
        good,
        "objects/objectives/nested/two.yml",
        "objects/objectives/notes.txt",
        "objects/objectives/missing.yaml",
        "",
        3,
    ]
    selected = _direct_object_files(tmp_path, changed)
    assert selected == [good.resolve()]
    assert _direct_object_files(tmp_path, "objects/objectives/one.yaml") == []

    other = ShareFilters(uuids=frozenset({"00000000-0000-4000-8002-000000000099"}))
    assert _intersect_changed(tmp_path, selected, other) == []
    same = ShareFilters(uuids=frozenset({"00000000-0000-4000-8002-000000000001"}))
    assert _intersect_changed(tmp_path, selected, same) == selected
    files = ShareFilters(files=frozenset({tmp_path / "elsewhere.yaml"}))
    assert _intersect_changed(tmp_path, selected, files) == []

    real_resolve = Path.resolve

    def _resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self.name == "boom.yaml":
            raise OSError("unreadable")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", _resolve)
    assert _direct_object_files(tmp_path, ["objects/objectives/boom.yaml"]) == []

    real_read = Path.read_bytes

    def _read(self: Path, *args: object, **kwargs: object) -> bytes:
        if self.name == "one.yaml":
            raise OSError("unreadable")
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", _read)
    assert _intersect_changed(tmp_path, [good.resolve()], same) == []

    def _blank(_plan: object) -> list[str]:
        raise Exception("   ")

    monkeypatch.setattr("opentide.deployment.git_repo.diff_calculation", _blank)
    narrowed, stop = _changed_files(tmp_path, None)
    assert narrowed is None
    assert stop == _PREFLIGHT["changed_diff"]
