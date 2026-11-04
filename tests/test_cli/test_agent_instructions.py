"""What agents are told to run must run: instruction files, skills, MCP text and docs.

The instruction files ``opentide setup skills`` writes teach the agent output
contract. Every ``opentide`` command line they, the bundled skills, the MCP
server's ``next_actions`` and ``INSTRUCTIONS``, and the agent docs quote is
parsed as Click would run it (:func:`tests.agent_command_support.parse_error`),
so an agent that pastes one never meets a usage error from the parser.
``tests/test_cli/e2e/test_agent_commands_e2e.py`` runs the read-only ones.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import typer.main
from tests.agent_command_support import (
    AGENT_DOCS,
    commands_in_markdown,
    instruction_sources,
    parse_error,
    unique,
)
from tests.corpus_support import CORPUS_RULE_UUIDS, clear_runtime_caches

from opentide.cli import app
from opentide.cli.services.setup.templates import (
    ENTRYPOINT_TEMPLATES,
    SKILL_PACKS,
    render_agent_entrypoint,
    setup_data_root,
)

ROOT = Path(__file__).resolve().parents[2]
_CONTEXT = {"name": "SOC Detections", "org": "SecOps", "description": "Rules for SOC"}
#: What every entrypoint must teach, in the words the JSON output uses.
_CONTRACT = ("opentide --json", "failure.code", "fix", "next_actions", "opentide explain")
_TAGLINE = "spec-driven development for agentic detection engineering"
_DEPLOY_PREVIEW = "opentide deploy --dry-run --strategy PREVIEW --all"
_AGENT_SECTION = "## Running opentide as an agent"


@pytest.fixture(scope="module")
def root() -> object:
    return typer.main.get_command(app)


@pytest.mark.parametrize("name", sorted(ENTRYPOINT_TEMPLATES))
def test_entrypoint_renders_every_placeholder(name: str) -> None:
    text = render_agent_entrypoint(name, _CONTEXT)
    assert "SOC Detections" in text
    assert "SecOps" in text
    # The Quick start deploy line names a strategy: without one, deploy exits 2.
    assert _DEPLOY_PREVIEW in text
    assert not re.search(r"\{[a-z_]+\}", text), "an unrendered placeholder is left"


@pytest.mark.parametrize("name", sorted(ENTRYPOINT_TEMPLATES))
def test_entrypoint_teaches_the_agent_output_contract(name: str) -> None:
    text = render_agent_entrypoint(name, _CONTEXT)
    for phrase in _CONTRACT:
        assert phrase in text, phrase
    assert _TAGLINE in text
    assert "MDR" not in text
    assert "exit code first" in text
    # People own merges and real deployments.
    assert "--dry-run" in text
    assert "merge" in text


def _skill_pack() -> Path:
    """The bundled skill pack, by the name the setup templates list.

    ``detection-ops`` today; ``detection-workflow`` once #634 renames it.
    """
    (pack,) = sorted(SKILL_PACKS)
    return setup_data_root() / "skills" / pack / "SKILL.md"


def test_skill_pack_teaches_the_agent_output_contract() -> None:
    text = _skill_pack().read_text(encoding="utf-8")
    assert _AGENT_SECTION in text
    for phrase in _CONTRACT:
        assert phrase in text, phrase


def test_only_the_skill_pack_holds_the_agent_section() -> None:
    """The section is found in the pack whatever the pack is called."""
    holders = [
        path
        for path in sorted((setup_data_root() / "skills").rglob("SKILL.md"))
        if _AGENT_SECTION in path.read_text(encoding="utf-8")
    ]
    assert holders == [_skill_pack()]


@pytest.mark.parametrize(
    "path",
    sorted((setup_data_root() / "skills" / "authoring").rglob("SKILL.md")),
    ids=lambda path: path.parent.name,
)
def test_authoring_skills_check_with_json(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert "opentide --json validate" in text
    assert "fix" in text
    assert "opentide explain" in text


# --------------------------------------------------------------------------
# Every quoted command parses
# --------------------------------------------------------------------------


def _assert_all_parse(root: object, sources: dict[str, list[str]]) -> int:
    failures = [
        f"{source}: {command!r}: {error}"
        for source, commands in sources.items()
        for command in commands
        if (error := parse_error(root, command)) is not None
    ]
    assert not failures, "\n".join(failures)
    return sum(len(commands) for commands in sources.values())


def test_the_parser_rejects_what_an_agent_would_trip_on(root: object) -> None:
    """The check is real: each of these is a usage error, and the fixed form is not."""
    for bad in (
        "opentide deploy --dry-run --strategy PREVIEW --all --platform nowhere",
        "opentide info vocab surface extra",
        "opentide validate --nope",
        "opentide validate query --platform nowhere --live",
        "opentide setup skills discover --query",
        "opentide explain a b",
    ):
        assert parse_error(root, bad) is not None, bad
    for good in (
        "opentide --json deploy --dry-run --strategy PREVIEW --all --platform sentinel",
        "opentide validate --json --strict --type rule",
        "opentide validate query --platform sentinel --live --file <rule file>",
        "opentide setup ci github --no-staging --yes",
    ):
        assert parse_error(root, good) is None, good


def test_instruction_files_and_skills_quote_commands_that_parse(root: object) -> None:
    sources = {
        name: unique(commands_in_markdown(text)) for name, text in instruction_sources().items()
    }
    assert _assert_all_parse(root, sources) > 20


def test_agent_docs_quote_commands_that_parse(root: object) -> None:
    sources = {
        str(path): unique(commands_in_markdown((ROOT / path).read_text(encoding="utf-8")))
        for path in AGENT_DOCS
    }
    assert _assert_all_parse(root, sources) > 20


def test_mcp_instructions_and_descriptions_quote_commands_that_parse(root: object) -> None:
    import asyncio

    from opentide.mcp_server.server import INSTRUCTIONS, mcp

    texts = {"INSTRUCTIONS": INSTRUCTIONS}
    texts.update(
        {f"tool {tool.name}": tool.description or "" for tool in asyncio.run(mcp.list_tools())}
    )
    from opentide.cli.commands import ROOT_COMMANDS

    names = "|".join(re.escape(spec.name) for spec in ROOT_COMMANDS)
    # Prose says "an opentide command line"; only a root command name starts one.
    pattern = re.compile(rf"(opentide (?:--json )?(?:{names})\b[^.;,)\n]*)")
    sources = {name: unique(pattern.findall(text)) for name, text in texts.items()}
    _assert_all_parse(root, sources)


def test_mcp_next_actions_quote_commands_that_parse(root: object, tide_corpus_repo: Path) -> None:
    from opentide.mcp_server import tools

    rule = tide_corpus_repo / "objects/rules/rule-0001-sentinel-kql.yaml"
    uuid = CORPUS_RULE_UUIDS["sentinel"]
    payloads = {
        "validate_rule (clean)": tools.tool_validate_rule(uuid),
        "validate_rule (missing)": tools.tool_validate_rule("00000000-0000-4000-8fff-0000000000ff"),
        "validate_query (refused)": tools.tool_validate_query("x", "elastic"),
    }
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("  tlp: clear\n", "  tlp: clearr\n", 1),
        encoding="utf-8",
    )
    clear_runtime_caches()
    payloads["validate_rule (broken)"] = tools.tool_validate_rule(uuid)
    payloads["validation_report (broken)"] = tools.tool_validation_report(
        file="objects/rules/rule-0001-sentinel-kql.yaml", object_type="rule"
    )
    sources = {
        name: [action["command"] for action in payload["next_actions"]]
        for name, payload in payloads.items()
    }
    assert all(sources.values()), sources
    assert _assert_all_parse(root, sources) >= 7
