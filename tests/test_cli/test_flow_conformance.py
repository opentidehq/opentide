"""Spec conformance of the flow commands.

What a dry run claims, how a plan fails, what help ends with.

Each test pins one deviation the spec audit or the end-to-end run found, so it
cannot come back unnoticed.
"""

from __future__ import annotations

import ast
import io
import json
import logging
import re
from pathlib import Path

import pytest
import typer.main
import yaml
from rich.console import Console
from tests.corpus_support import TIDE_CORPUS_ROOT
from typer.testing import CliRunner

from opentide.cli.context import CliContext
from opentide.cli.output import CommandResult, emit_result
from opentide.cli.services import deploy as _deploy_service
from opentide.cli.services import deploy_plan
from opentide.cli.ui import plan as _plan_ui
from opentide.cli.ui.mode import OutputMode, set_mode
from opentide.cli.ui.plan import plan_view
from opentide.cli.ui.progress import Checklist, Step, checklist_table
from opentide.core.root import get_repo_root
from opentide.loading.rule_loader import load_rule_from_dict

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "opentide"
_SGR = re.compile(r"\x1b\[[0-9;]*m")


def _console(width: int = 100, *, human: bool = False) -> Console:
    return Console(
        record=True,
        width=width,
        file=io.StringIO(),
        force_terminal=human,
        color_system="truecolor" if human else None,
    )


# --------------------------------------------------------------------------
# Deploy: a rule that does not compile
# --------------------------------------------------------------------------

_CORPUS_RULE = TIDE_CORPUS_ROOT / "Objects/Detection Rules/rule-0001-sentinel-kql.yaml"


def _rule_without_response():
    data = yaml.safe_load(_CORPUS_RULE.read_text(encoding="utf-8"))
    data.pop("response")
    return load_rule_from_dict(data, file=_CORPUS_RULE)


def test_an_empty_response_block_is_a_diagnostic_not_a_python_error(tide_corpus_repo) -> None:
    """``response:`` left empty raised ``AttributeError: 'NoneType' object …`` (E2E 1)."""
    from opentide.deployment.preview import preview_rule_deployment

    rule = _rule_without_response()
    preview = preview_rule_deployment("sentinel", rule)
    assert preview["status"] == "failed"
    assert preview["code"] == "compile_empty_block"
    assert preview["error"] == "`response` is empty, so Sentinel cannot read `alert_severity`"
    assert "alert_severity" in str(preview["help"])
    for leak in ("AttributeError", "NoneType", "TideRuleDataModelErrors", rule.metadata.uuid):
        assert leak not in preview["error"]
    assert preview["file"] == str(_CORPUS_RULE)


def test_a_missing_field_names_the_field_once_without_the_rule(tide_corpus_repo) -> None:
    from opentide.deployment.preview import compile_diagnostic
    from opentide.platforms.sentinel.deployer import SentinelCompileError

    rule = _rule_without_response()
    error = SentinelCompileError(rule, "compile_missing_field", "grouping is missing", "add it")
    assert compile_diagnostic(error) == ("compile_missing_field", "grouping is missing", "add it")
    # A live deploy's log still names the rule.
    assert rule.metadata.uuid in str(error) and "add it" in str(error)


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (
            AttributeError("'NoneType' object has no attribute 'title'", name="title", obj=None),
            "compile_empty_block",
        ),
        (KeyError("tenant"), "compile_failed"),
    ],
)
def test_python_errors_are_described_not_printed(error: Exception, code: str) -> None:
    from opentide.deployment.preview import compile_diagnostic

    found, message, _ = compile_diagnostic(error)
    assert found == code
    assert type(error).__name__ not in message


def test_compile_diagnostics_are_workspace_relative(tide_corpus_repo) -> None:
    root = get_repo_root()
    source = root / "rules" / "x.yaml"
    payloads = {
        "sentinel": [
            {"uuid": "u", "name": "n", "api_request": {}},
            {
                "uuid": "v",
                "name": "m",
                "status": "failed",
                "code": "c",
                "error": "e",
                "help": "h",
                "file": str(source),
            },
        ]
    }
    (diagnostic,) = _deploy_service.compile_diagnostics(payloads)
    assert diagnostic["path"] == "rules/x.yaml"
    assert diagnostic["file_path"] == str(source)
    assert (diagnostic["code"], diagnostic["message"], diagnostic["help"]) == ("c", "e", "h")


def test_a_diagnostic_prints_its_code_file_and_help_once(tmp_path: Path, monkeypatch) -> None:
    """A rule the dry run cannot compile prints as #641's code frame, not ``  --> path``."""
    monkeypatch.chdir(tmp_path)
    console = Console(file=io.StringIO(), width=200, color_system=None, force_terminal=False)
    _plan_ui.render_plan_diagnostics(
        console,
        {
            "diagnostics": [
                {
                    "code": "compile_missing_field",
                    "severity": "error",
                    "message": "configurations.sentinel.grouping is missing",
                    "help": "Sentinel needs grouping",
                    "file_path": str(tmp_path / "objects/rules/r.yaml"),
                    "name": "Rule",
                    "uuid": "00000000-0000-4000-8003-000000000001",
                }
            ]
        },
    )
    text = console.file.getvalue()
    assert text.splitlines() == [
        "error[compile_missing_field]: configurations.sentinel.grouping is missing",
        "  ╭─▶ objects/rules/r.yaml",
        "  ╰─ help: Sentinel needs grouping",
        "",
    ]
    assert "00000000" not in text and "Rule" not in text


def test_a_compile_frame_quotes_names_like_every_other_frame() -> None:
    """``error[compile_empty_block]: `response` is empty…`` printed Markdown code spans
    where other frames quote 'names' (post-merge end-to-end run). JSON keeps them."""
    diagnostic = _plan_ui.plan_diagnostic(
        {
            "code": "compile_empty_block",
            "message": "`response` is empty, so Sentinel cannot read `alert_severity`",
            "help": "set `response.alert_severity`",
        }
    )
    assert diagnostic.message == "'response' is empty, so Sentinel cannot read 'alert_severity'"
    assert diagnostic.help == "set 'response.alert_severity'"


def test_a_diagnostic_without_a_file_names_its_rule(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    diagnostic = _plan_ui.plan_diagnostic(
        {"code": "compile_failed", "message": "Sentinel cannot compile this rule", "name": "Rule"}
    )
    assert diagnostic.severity == "error"
    assert diagnostic.path is None and diagnostic.notes == (("rule", "Rule"),)


def test_a_failed_plan_prints_its_tally_without_error_and_exits_1(capsys) -> None:
    """``error: Plan: …`` read as if the tally itself had failed (E2E 4)."""
    set_mode(OutputMode.PLAIN)
    result = CommandResult.from_payload(
        {
            "status": "failed",
            "message": (
                "Plan: 0 to create, 0 to update, 1 to create or update, 0 to disable, 0 to delete"
            ),
            "error": "1 rule would fail to deploy",
            "_outcome_kind": "plan",
            "_exit_code": 1,
        }
    )
    with pytest.raises(SystemExit) as exc:
        emit_result(CliContext(json_output=False), result)
    captured = capsys.readouterr()
    assert exc.value.code == 1
    assert captured.out.startswith("Plan: 0 to create")
    assert "error" not in captured.out + captured.err
    assert all(len(line) <= 100 for line in captured.out.splitlines())
    assert result.failure is not None and result.failure.message == "1 rule would fail to deploy"


def test_the_plan_scope_moves_to_the_header() -> None:
    changes = [
        deploy_plan.PlannedChange("sentinel", "prod", "u", "Rule", "STAGING", "upsert"),
    ]
    assert deploy_plan.plan_message(changes) == (
        "Plan: 0 to create, 0 to update, 1 to create or update, 0 to disable, 0 to delete"
    )
    console = _console()
    console.print(
        plan_view(
            [c.to_dict() for c in changes], strategies=["PREVIEW"], scope="1 platform, 1 tenant"
        )
    )
    header = console.export_text().splitlines()[0]
    assert (
        header == "Deploy plan · strategy PREVIEW · 1 platform, 1 tenant · dry run, nothing is sent"
    )


def test_a_dry_run_defers_unset_variables_to_one_warning(caplog, monkeypatch) -> None:
    """A dry run printed ``error: Environment variable missing`` and exited 0 (E2E 5)."""
    from opentide.core.environment import DebugHelpers, defer_missing_envvars

    monkeypatch.setattr(DebugHelpers, "is_debug", staticmethod(lambda: False))
    name = "OPENTIDE_TEST_UNSET_FOR_DRY_RUN"
    with caplog.at_level(logging.DEBUG), defer_missing_envvars() as unset:
        DebugHelpers.fetch_config_envvar({"secret": f"${name}", "again": f"${name}"})
    assert unset == [name]
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert (
        _deploy_service.unset_variables_warning([name])
        == f"a real deploy would need ${name}, which is unset"
    )
    assert _deploy_service.unset_variables_warning(["A", "B", "C"]) == (
        "a real deploy would need $A, $B and $C, which are unset"
    )
    # 13 names in one sentence broke mid-name at 100 columns (post-merge run).
    assert _deploy_service.unset_variables_warning([f"V{i}" for i in range(13)]) == (
        "a real deploy would need 13 variables that are unset: $V0, $V1, $V2 and 10 more; "
        "opentide doctor lists them by tenant"
    )


def test_a_checklist_without_steps_draws_nothing() -> None:
    """The live display started empty, so a dry-run plan opened with a blank line (E2E 18)."""
    console = _console(human=True)
    with Checklist(console, mode=OutputMode.HUMAN, quiet=False):
        pass
    assert console.file.getvalue() == ""


def test_finished_step_counts_align_on_their_numbers() -> None:
    """``1 file`` sat right-aligned, out of the column (E2E 18)."""
    steps = [
        Step("docs", count=7, status="ok", where="docs/"),
        Step("schemas", count=12, status="ok", where=".opentide/schemas/"),
        Step("snippets", count=1, unit="file", status="ok", where=".vscode/"),
    ]
    console = _console()
    console.print(checklist_table(steps))
    lines = console.export_text().splitlines()
    # The units line up; the numbers are right-aligned before them.
    assert len({line.index(" file") for line in lines}) == 1, lines


# --------------------------------------------------------------------------
# Dry runs claim nothing
# --------------------------------------------------------------------------


def test_migrate_objects_dry_run_is_a_plan(tmp_path: Path) -> None:
    from opentide.cli.services.migrate_objects import run_migrate_objects

    (tmp_path / "Objects" / "Detection Rules").mkdir(parents=True)
    (tmp_path / "Objects" / "Detection Rules" / "r.yaml").write_text("name: r\n", encoding="utf-8")
    result = run_migrate_objects(tmp_path, apply=False)
    assert str(result["message"]).startswith("Would move")
    assert result["_outcome_kind"] == "plan"
    applied = run_migrate_objects(tmp_path, apply=True)
    assert "_outcome_kind" not in applied


def test_share_preview_is_a_plan() -> None:
    from opentide.cli.services.share import _from_run
    from opentide.sharing.report import ShareRecord, ShareRun

    run = ShareRun(records=(ShareRecord(object_uuid="u", target="misp", action="created"),))
    config = type("Config", (), {"issues": ()})()
    preview = _from_run(run, config, mode="preview")
    assert preview["message"].startswith("Would share")
    assert preview["_outcome_kind"] == "plan"
    assert "_outcome_kind" not in _from_run(run, config)


def test_rules_unreviewed_on_an_empty_catalogue_claims_nothing(tmp_path: Path) -> None:
    """``✓ Every rule reviewed in the last 90 days`` on zero rules (D20)."""
    from opentide.cli.services.rules import run_unreviewed

    result = run_unreviewed(tmp_path, older_than="90d")
    assert (result["message"], result["status"]) == ("No rules yet", "skipped")
    (step,) = result["_next_actions"]
    assert step["command"].startswith("opentide ")
    (tmp_path / "objects" / "rules").mkdir(parents=True)
    (tmp_path / "objects" / "rules" / "r.yaml").write_text(
        "metadata:\n  schema: rule::1.1\n  reviewed: 2999-01-01\n", encoding="utf-8"
    )
    assert run_unreviewed(tmp_path, older_than="90d")["message"].startswith("Every rule reviewed")


# --------------------------------------------------------------------------
# "MDR" is retired from what people read
# --------------------------------------------------------------------------

_LOG_LEVELS = {"debug", "info", "warning", "error", "critical", "exception"}


def test_no_log_event_says_mdr() -> None:
    """Event slugs are rendered as text (``Mdr skipped for strategy``) and read in JSON logs.

    (D5)
    """
    found = []
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _LOG_LEVELS
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and re.search(r"(?<![a-z])mdrs?(?![a-z])", node.args[0].value)
            ):
                found.append(f"{path.relative_to(SRC)}: {node.args[0].value}")
    assert found == []


def test_generated_text_says_rule_not_mdr() -> None:
    for path in (
        SRC / "documentation" / "parts" / "sections.py",
        SRC / "export" / "attack_navigator_layer.py",
        SRC / "data" / "configurations" / "deployment.toml",
    ):
        assert "MDR" not in path.read_text(encoding="utf-8"), path


# --------------------------------------------------------------------------
# Help
# --------------------------------------------------------------------------


def _visible(command, path: str = ""):
    for name, child in (getattr(command, "commands", None) or {}).items():
        if child.hidden:
            continue
        full = f"{path} {name}".strip()
        yield full, child
        yield from _visible(child, full)


def test_every_visible_option_has_help() -> None:
    """88 options printed a bare flag in ``--help`` (E2E 16)."""
    from opentide.cli.root import app

    root = typer.main.get_group(app)
    missing = [
        f"{path or 'opentide'} {param.opts[0]}"
        for path, command in [("", root), *_visible(root)]
        for param in command.params
        if param.param_type_name == "option"
        and not getattr(param, "hidden", False)
        and not (param.help or "").strip()
    ]
    assert missing == []


@pytest.mark.parametrize("argv", [["--help"], ["deploy", "--help"], ["setup", "skills", "--help"]])
def test_help_ends_with_one_newline_and_single_spaced_examples(argv, monkeypatch) -> None:
    from opentide.cli.root import app

    monkeypatch.setenv("NO_COLOR", "1")
    result = CliRunner().invoke(app, argv, terminal_width=100)
    assert result.exit_code == 0, result.output
    text = _SGR.sub("", result.stdout)
    assert text.endswith("\n") and not text.endswith("\n\n"), repr(text[-80:])
    examples = text[text.index(" Examples") :].splitlines()[1:]
    assert examples and all(line.startswith("   $ opentide") for line in examples)
    assert "Disable Rich" not in text


def _command_tree() -> list[dict]:
    from opentide.cli.root import app

    result = CliRunner().invoke(app, ["--json", "commands"])
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)["commands"]


def test_help_reads_as_text_not_markup() -> None:
    """Four help screens printed docstring markup (``.env.example``), and eight of 55
    summaries ended in a period where the rest do not (post-merge end-to-end run)."""
    commands = _command_tree()
    markup = [c["path"] for c in commands if "``" in (c["help"] or "") + (c["summary"] or "")]
    assert markup == []
    periods = [c["path"] for c in commands if (c["summary"] or "").endswith(".")]
    assert periods == []


def test_a_long_list_of_choices_gets_a_short_metavar() -> None:
    """``<sentinel|splunk|…>`` broke mid-word in ``new rule --help`` (``defender_for_endpo``)
    and ``setup --help`` (``<github|gitlab|azure|no`` / ``ne>``) (post-merge run)."""
    from opentide.cli.root import app

    root = typer.main.get_group(app)
    crowded = [
        f"{path} {param.opts[0]}"
        for path, command in _visible(root)
        for param in command.params
        if param.param_type_name == "option"
        and not getattr(param, "hidden", False)
        and len("|".join(getattr(param.type, "choices", None) or ())) > 24
        and param.metavar is None
    ]
    assert crowded == []


def test_root_help_names_no_library() -> None:
    from opentide.cli.root import app

    result = CliRunner().invoke(app, ["--help"], terminal_width=100, env={"NO_COLOR": "1"})
    assert "Disable colour" in _SGR.sub("", result.stdout)


# --------------------------------------------------------------------------
# JSON stays one document
# --------------------------------------------------------------------------


def test_plan_json_keeps_the_scope_in_summary() -> None:
    changes = [deploy_plan.PlannedChange("sentinel", "prod", "u", "Rule", "STAGING", "upsert")]
    summary = deploy_plan.plan_summary(changes, ["sentinel"], 1)
    assert (summary["platforms"], summary["tenants"]) == (1, 1)
    json.dumps(summary)


# --------------------------------------------------------------------------
# Home screen
# --------------------------------------------------------------------------


def _home_facts(**changes):
    from opentide.cli.ui.home import HomeFacts

    facts = dict(
        version="0.18.0",
        workspace=Path.cwd(),
        git="main, clean",
        catalogue={"rules": 1, "threats": 1, "objectives": 1},
        schemas=True,
        platforms={"sentinel": 0},
    )
    facts.update(changes)
    return HomeFacts(**facts)


def _yellow_text(console: Console) -> list[str]:
    """The text of every run drawn in yellow (SGR 33)."""
    return re.findall(r"\x1b\[(?:\d+;)*33m([^\x1b]*)", console.export_text(styles=True))


@pytest.mark.parametrize("schemas", [True, False])
def test_the_home_screen_keeps_yellow_for_warnings(schemas: bool) -> None:
    """``(no tenant yet)`` and ``none enabled`` were yellow; the brand has no yellow (D21)."""
    from opentide.cli.ui.home import home_view

    set_mode(OutputMode.HUMAN)
    for facts in (
        _home_facts(schemas=schemas),
        _home_facts(platforms={}, schemas=schemas),
        _home_facts(workspace=None, schemas=schemas),
    ):
        console = _console(human=True)
        console.print(home_view(console, facts))
        assert _yellow_text(console) in ([], ["! "]), _yellow_text(console)
        if schemas or facts.workspace is None:
            assert _yellow_text(console) == []


@pytest.mark.parametrize("width", [60, 70])
def test_narrow_home_screens_drop_descriptions_rather_than_wrap(width: int) -> None:
    """Next steps wrapped mid-phrase at 70 and 60 columns (D21, E2E 7)."""
    from opentide.cli.ui.home import home_view

    set_mode(OutputMode.HUMAN)
    facts = _home_facts(schemas=False)  # the longest suggestions
    console = _console(width, human=True)
    console.print(home_view(console, facts))
    text = console.export_text()
    lines = [line.rstrip() for line in text.splitlines()]
    suggested = lines[lines.index(next(line for line in lines if "Suggested next" in line)) + 1 :]
    commands = [line.strip() for line in suggested if line.strip().startswith("opentide")]
    assert commands[0] == "opentide generate"
    assert all(len(line) <= width for line in lines)
    assert "--json <command> for agents" in text


def test_a_wide_home_screen_keeps_the_descriptions() -> None:
    from opentide.cli.ui.home import home_view

    set_mode(OutputMode.HUMAN)
    console = _console(100, human=True)
    console.print(home_view(console, _home_facts(schemas=False)))
    assert "schemas, templates and editor snippets" in console.export_text()


# --------------------------------------------------------------------------
# Setup wizard
# --------------------------------------------------------------------------


def test_the_setup_plan_reads_like_the_prompts(tmp_path: Path, monkeypatch) -> None:
    """Raw keys (``github``, ``vscode``, ``skip``) and an absolute path (E2E 12)."""
    from opentide.cli.enums import CiPlatform, DetectionPlatform, McpHost
    from opentide.cli.services.setup import orchestrator
    from opentide.cli.services.setup.orchestrator import SetupOptions

    monkeypatch.chdir(tmp_path)
    console = _console()
    monkeypatch.setattr(orchestrator, "get_stdout_console", lambda: console)
    options = SetupOptions(path=tmp_path, run_repo=True)
    options.platforms = [DetectionPlatform.sentinel]
    options.ci, options.run_ci = CiPlatform.github, True
    options.mcp_hosts, options.run_mcp = [McpHost.vscode], True
    orchestrator._print_setup_plan(options)
    lines = console.export_text().splitlines()
    assert lines[0] == "" and lines[-1] == ""
    assert lines[1] == "Setup plan"
    rows = {line.split("   ")[0].strip(): line.split("   ", 1)[1].strip() for line in lines[2:-1]}
    assert rows == {
        "Repository": f"this folder ({tmp_path.name})",
        "Platforms": "Microsoft Sentinel",
        "CI/CD": "GitHub Actions",
        "MCP": "VS Code",
        "Agent skills": "none",
    }
    assert str(tmp_path) not in console.export_text()


def test_setup_in_the_current_folder_says_here(tmp_path: Path, monkeypatch) -> None:
    """``✓ Created Wizard Demo in .`` (E2E 12)."""
    from opentide.cli.ui.setup import setup_outcome

    monkeypatch.chdir(tmp_path)
    result = {"path": str(tmp_path), "scaffolded": True, "name": "Wizard Demo", "files": []}
    message, actions = setup_outcome(result)
    assert message == "Created Wizard Demo here"
    assert not any(action.command.startswith("cd ") for action in actions)
    (tmp_path / "sub").mkdir()
    message, _ = setup_outcome({**result, "path": str(tmp_path / "sub")})
    assert message == "Created Wizard Demo in ./sub"


def test_a_prompt_shows_its_validation_message_under_the_field(monkeypatch) -> None:
    """prompt_toolkit grew the answer row to the bottom of the terminal (E2E 12)."""
    from opentide.cli.services.setup import interactive

    seen = []

    def unsafe_ask(self):
        seen.extend(
            window.dont_extend_height() for window in self.application.layout.find_all_windows()
        )
        return "answer"

    monkeypatch.setattr(interactive.Question, "unsafe_ask", unsafe_ask)
    assert interactive.ask_text("Name", validate=interactive.require_text("a name")) == "answer"
    assert seen and all(seen)


def test_ctrl_c_in_a_prompt_prints_nothing_of_its_own(monkeypatch, capsys) -> None:
    """questionary printed ``Cancelled by user`` before the CLI's own line (D25)."""
    from opentide.cli.services.setup import interactive

    def interrupted(self, patch_stdout: bool = False):
        raise KeyboardInterrupt

    monkeypatch.setattr(interactive.Question, "unsafe_ask", interrupted)
    with pytest.raises(KeyboardInterrupt):
        interactive.ask_confirm("Apply?")
    captured = capsys.readouterr()
    assert captured.out + captured.err == ""


@pytest.mark.parametrize("mode", [{"AI_AGENT": "test-agent"}, {}])
def test_every_setup_refusal_names_its_flags(mode, tmp_path: Path, monkeypatch) -> None:
    """Plain and agent modes named no flag; ``--json`` did (D13)."""
    from opentide.cli.root import app

    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    result = CliRunner().invoke(app, ["setup", "--path", str(tmp_path)], env=mode)
    assert result.exit_code == 2, result.output
    assert "Run 'opentide setup' with --yes and explicit flags (--platform, --ci)." in (
        " ".join(result.stderr.split())
    )


def test_the_plan_draws_on_an_ascii_stream() -> None:
    """A literal ``…`` in the plan crashed ``PYTHONIOENCODING=ascii`` (D10)."""
    changes = [
        deploy_plan.PlannedChange(
            "sentinel", None, "00000000-0000-4000-8003-000000000001", "Rule", "STAGING", "upsert"
        ).to_dict()
    ]
    console = _console()
    console.print(plan_view(changes, scope="1 platform, 0 tenants", encoding="ascii"))
    text = console.export_text()
    text.encode("ascii")
    assert "...000000000001" in text
