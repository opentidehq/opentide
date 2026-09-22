"""Golden tests for the ``opentide`` invocations printed in ``docs/``.

Issue #270: the tutorial e2e suite copied YAML fences and ran a hard-coded
command list, so no test ever read the commands the pages actually print. Every
sample-versus-reality bug in #247 — plus `--path` (#248), `--json` placement
(#257) and `opentide explorer build` (#202) — sat in a fenced block that CI
rendered but never executed.

Two gates here, in increasing cost:

* resolution — every documented invocation parses against the live Typer
  command tree, which is cheap enough to run over all 200-odd of them;
* execution — the read-only subset really runs against a scaffolded repo and
  has to produce exactly one JSON document.
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.docs_commands import (
    DOCS,
    ROOT,
    DocCommand,
    documented_commands,
    fenced_blocks,
    iter_shell_lines,
    normalise,
    resolve,
    split_invocations,
)
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

# Extraction and resolution are pure and cheap, so they run in the unit matrix
# on every supported Python; only the tests that execute the CLI against a
# scaffolded repository carry `cli_e2e`.

DOC_COMMANDS = documented_commands()

#: Roots whose documented samples are safe to execute: they read the
#: repository and write only inside it. `deploy` and `generate extract` reach
#: for a vendor API, `setup` and `migrate` rewrite the tree out from under the
#: other cases, and `--live` query validation needs credentials.
EXECUTABLE_ROOTS = frozenset({"validate", "lint", "info", "generate"})
SKIPPED_SUBCOMMANDS = frozenset({"extract", "inflight"})
#: Tokens standing in for something the reader substitutes.
PLACEHOLDER_MARKERS = ("<", "/path/to/", "...", "$")


def _is_executable(command: DocCommand) -> bool:
    positional = [token for token in command.argv if not token.startswith("-")]
    if not positional or positional[0] not in EXECUTABLE_ROOTS:
        return False
    if len(positional) > 1 and positional[1] in SKIPPED_SUBCOMMANDS:
        return False
    if "--live" in command.argv:
        return False
    return not any(marker in token for token in command.argv for marker in PLACEHOLDER_MARKERS)


EXECUTABLE_COMMANDS = [command for command in DOC_COMMANDS if _is_executable(command)]


def _identify(command: DocCommand) -> str:
    return f"{command.page}:{command.line}"


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


def test_the_docs_tree_actually_yields_commands() -> None:
    """A parser that silently matches nothing would make every gate below pass."""
    assert len(DOC_COMMANDS) > 150
    assert len({command.page for command in DOC_COMMANDS}) > 10


def test_shell_lines_come_only_from_shell_fences() -> None:
    text = "\n".join(
        [
            "```yaml",
            "opentide: not-a-command",
            "```",
            "```bash",
            "opentide validate",
            "```",
            "```text",
            "opentide also-not-a-command",
            "```",
        ]
    )
    assert [line for _, line in iter_shell_lines(text)] == ["opentide validate"]


def test_backslash_continuations_are_joined() -> None:
    text = "```bash\nopentide setup --yes \\\n  --platform sentinel\n```"
    (line,) = [line for _, line in iter_shell_lines(text)]
    assert normalise(next(split_invocations(line))) == ("setup", "--yes", "--platform", "sentinel")


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("$ opentide validate", ("validate",)),
        ("OPENTIDE_REPO_ROOT=/tmp opentide validate", ("validate",)),
        ("if opentide --json validate > out.json; then", ("--json", "validate")),
        ("opentide --json info | jq .counts", ("--json", "info")),
        ("opentide validate && opentide lint", ("validate",)),
    ],
)
def test_prompt_env_and_redirect_noise_is_stripped(line: str, expected: tuple[str, ...]) -> None:
    assert normalise(next(split_invocations(line))) == expected


def test_non_opentide_commands_are_ignored() -> None:
    assert normalise(["pip", "install", "opentide"]) is None
    assert normalise(["cd", "detections"]) is None


@pytest.mark.parametrize(
    "opener",
    ['```bash title="Validate"', "````bash", "~~~bash", "```console"],
)
def test_fences_with_info_strings_and_other_markers_are_recognised(opener: str) -> None:
    """An unrecognised opener made its closer look like an opener, inverting the page."""
    closer = opener.split()[0].rstrip("abcdefghijklmnopqrstuvwxyz")
    text = "\n".join([opener, "opentide validate", closer, "opentide not-in-a-fence"])
    assert [line for _, line in iter_shell_lines(text)] == ["opentide validate"]


def test_a_shorter_fence_inside_a_longer_one_does_not_close_it() -> None:
    text = "\n".join(["````markdown", "```bash", "opentide quoted", "```", "````"])
    assert list(iter_shell_lines(text)) == []


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("opentide --json info 2>/dev/null", [("--json", "info")]),
        ("opentide validate 2>&1 | tee log", [("validate",), None]),
        ("opentide info|jq .counts", [("info",), None]),
        ("opentide validate;opentide lint", [("validate",), ("lint",)]),
        ("rules=$(opentide --json info)", [None, ("--json", "info")]),
        ('echo "a|b" | opentide lint', [None, ("lint",)]),
        ("opentide validate --uuid <uuid>", [("validate", "--uuid", "<uuid>")]),
    ],
)
def test_operators_without_spaces_and_fd_redirects_are_split(
    line: str, expected: list[tuple[str, ...] | None]
) -> None:
    """``2>/dev/null`` used to be read as a positional; ``a|b`` as one token."""
    assert [normalise(argv) for argv in split_invocations(line)] == expected


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["uv", "run", "opentide", "validate"], ("validate",)),
        (["uv", "run", "--with", "x", "opentide", "lint"], ("lint",)),
        (["uvx", "--from", "opentide", "opentide", "info"], ("info",)),
        (["pipx", "run", "opentide", "validate"], ("validate",)),
        (["uv", "run", "opentide-mcp"], None),
        (["uv", "run", "pytest"], None),
    ],
)
def test_launcher_prefixes_do_not_hide_an_invocation(
    argv: list[str], expected: tuple[str, ...] | None
) -> None:
    """A ``uv run opentide …`` sample was skipped, so it could drift unchecked."""
    assert normalise(argv) == expected


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


@pytest.mark.parametrize("command", DOC_COMMANDS, ids=_identify)
def test_every_documented_command_resolves(command: DocCommand) -> None:
    """A published invocation must parse against the CLI that ships with it."""
    problems = resolve(command.argv)
    assert not problems, f"{command}\n  " + "\n  ".join(problems)


@pytest.mark.parametrize(
    ("argv", "fragment"),
    [
        # #202: emitted into CI templates, never registered as a command.
        (("explorer", "build"), "no subcommand 'explorer'"),
        # #257: --json lives on the root callback only.
        (("validate", "--json"), "no option '--json'"),
        (("setup", "--json", "repo"), "no option '--json'"),
        # A flag that never existed must not quietly pass.
        (("validate", "--strict", "--make-it-work"), "no option '--make-it-work'"),
        (("generate", "nonsense"), "no subcommand 'nonsense'"),
        # Value checks: what Click rejects after it has found the command.
        (("validate", "query", "--platform", "sentinal"), "does not accept 'sentinal'"),
        (("validate", "query", "--platform"), "--platform requires a value"),
        (("setup", "ci", "jenkins"), "does not accept 'jenkins'"),
        (("setup", "ci"), "missing required argument"),
        (("validate", "--strict=yes"), "is a flag and takes no value"),
    ],
)
def test_resolution_rejects_commands_the_cli_does_not_have(
    argv: tuple[str, ...], fragment: str
) -> None:
    """Negative control: the gate above is only worth its runtime if it fails."""
    problems = resolve(argv)
    assert any(fragment in problem for problem in problems), problems


@pytest.mark.parametrize(
    "argv",
    [
        ("--json", "validate", "--strict"),
        ("setup", "hooks", "--path", "."),
        ("setup", "hooks", "."),
        ("--json", "info", "--technique", "T1059", "coverage"),
        ("--json", "info", "coverage", "--technique", "T1059"),
        ("validate", "query", "--platform", "sentinel"),
        ("validate", "query", "--platform=splunk"),
        ("validate", "query", "--platform", "<platform>"),
        ("setup", "ci", "github"),
        ("setup", "ci", "--help"),
        ("generate", "explorer"),
    ],
)
def test_resolution_accepts_the_forms_the_cli_supports(argv: tuple[str, ...]) -> None:
    """Positive control: the gate must not reject valid argv either."""
    assert resolve(argv) == []


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


#: Host variables that change what a command does; a developer shell or CI
#: runner exporting any of them must not change what the samples produce.
_LEAKY_ENV = (
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "OPENTIDE_DATA_ROOT",
    "DEPLOYMENT_PLAN",
    "INFLIGHT_PATHS",
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TF_BUILD",
    "DEBUG",
    "NO_COLOR",
    "FORCE_COLOR",
    "PY_COLORS",
    "CLICOLOR_FORCE",
)


@pytest.fixture(scope="module")
def _pristine_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Scaffold and generate once; tests get a copy, never this tree."""
    from tests.test_cli.e2e.helpers import write_tutorial_objects

    repo = tmp_path_factory.mktemp("documented") / "detections"
    run_repo_setup(RepoSetupOptions(path=repo, name="Documented", yes=True))
    write_tutorial_objects(repo)
    result = CliRunner().invoke(
        app, ["--repo", str(repo), "--json", "generate"], env=dict.fromkeys(_LEAKY_ENV)
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    return repo


@pytest.fixture
def documented_repo(
    _pristine_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """A private copy of the documented repo, used as the working directory.

    ``generate docs`` and friends write into the repo, and a sample with a
    relative ``--output`` writes into the cwd: shared, the samples depended on
    each other's order and could write into the source checkout.
    """
    repo = tmp_path / "detections"
    shutil.copytree(_pristine_repo, repo)
    for name in _LEAKY_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(repo)
    yield repo


def _lines_in_order(sample: str, live: str) -> list[str]:
    """Sample lines missing from *live*, matched as whole lines and in order."""
    live_lines = [line.strip() for line in live.splitlines()]
    missing: list[str] = []
    cursor = 0
    for line in (line.strip() for line in sample.splitlines()):
        if not line:
            continue
        try:
            cursor = live_lines.index(line, cursor) + 1
        except ValueError:
            missing.append(line)
    return missing


@pytest.mark.cli_e2e
@pytest.mark.parametrize("command", EXECUTABLE_COMMANDS, ids=_identify)
def test_documented_commands_emit_one_json_document(
    command: DocCommand, documented_repo: Path
) -> None:
    """Run the read-only samples for real; --json owes exactly one object.

    The sample is allowed to fail — troubleshooting pages print commands that
    are supposed to — but not to raise, and not to interleave prose with the
    document a caller parses.
    """
    argv = ["--repo", str(documented_repo)]
    if "--json" not in command.argv:
        argv.append("--json")
    argv.extend(command.argv)
    result = CliRunner().invoke(app, argv)
    assert result.exception is None or isinstance(result.exception, SystemExit), (
        f"{command}\n{result.stdout}{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict), command
    assert "ok" in payload, f"{command} produced no result envelope"


def test_at_least_one_page_of_samples_is_executed() -> None:
    """Guard the filter above from quietly shrinking to nothing."""
    assert len(EXECUTABLE_COMMANDS) > 20


# --------------------------------------------------------------------------
# Output samples
# --------------------------------------------------------------------------


_RULE = re.compile(r"─+ (?P<title>.+?) ─+")


def _rules_as_headers(output: str) -> str:
    """Each Rich rule `─── Title ───` as the `== Title ==` header `--no-color` prints."""
    return "\n".join(
        f"== {match['title']} ==" if (match := _RULE.fullmatch(line.strip())) else line
        for line in output.splitlines()
    )


@pytest.mark.cli_e2e
@pytest.mark.parametrize("colour", [False, True], ids=["no-color", "colour"])
@pytest.mark.parametrize("page", ["docs/usage/tutorial.md", "docs/usage/quickstart.md"])
def test_documented_generate_output_matches_the_live_pipeline(
    page: str, colour: bool, documented_repo: Path
) -> None:
    """Issue #247: both pages printed a checkmark list the CLI never emitted.

    The pages show the `--no-color` headers and say a colour terminal draws
    each one as a rule; both forms must carry the documented phases in order.
    """
    blocks = fenced_blocks(ROOT / page, "text")
    sample = next(block for block in blocks if "generation" in block)
    argv = ["--repo", str(documented_repo), "generate"]
    result = CliRunner().invoke(app, argv if colour else ["--no-color", *argv])
    assert result.exit_code == 0, result.stdout + result.stderr
    # Phase headers go to stderr, the closing status to stdout; the page shows
    # the terminal view, which is both interleaved. `stdout + stderr` would put
    # the closing line first and fail the ordering check for the wrong reason.
    live = _rules_as_headers(result.output) if colour else result.output
    missing = _lines_in_order(sample, live)
    assert not missing, (
        f"{page} documents lines `generate` does not print as whole lines in this order: "
        f"{missing}\n--- live ---\n{live}"
    )


@pytest.mark.cli_e2e
def test_info_json_carries_the_documented_envelope(documented_repo: Path) -> None:
    """Issue #247: the reference claimed `info` had no `ok` wrapper."""
    sample = next(
        block for block in fenced_blocks(DOCS / "cli" / "info.md", "json") if "version" in block
    )
    documented = json.loads(sample)
    result = CliRunner().invoke(app, ["--repo", str(documented_repo), "--json", "info"])
    assert result.exit_code == 0, result.stdout + result.stderr
    live = json.loads(result.stdout)
    missing = set(documented) - set(live)
    undocumented = set(live) - set(documented)
    assert not missing, f"documented keys missing from `info`: {missing}"
    assert not undocumented, f"`info` returns keys docs/cli/info.md does not show: {undocumented}"
    assert live["ok"] is True
    assert live["status"] == "completed"


@pytest.mark.cli_e2e
def test_tutorial_query_validation_sample_is_offline(documented_repo: Path) -> None:
    """The tutorial promises an offline parse; #239 made that true."""
    sample = next(
        block
        for block in fenced_blocks(ROOT / "docs/usage/tutorial.md", "text")
        if "syntax validation" in block
    )
    result = CliRunner().invoke(
        app, ["--repo", str(documented_repo), "validate", "query", "--platform", "sentinel"]
    )
    live = result.output
    assert "Offline KQL syntax validation" in live
    missing = _lines_in_order(sample, live)
    assert not missing, f"tutorial sample lines not printed in order: {missing}\n{live}"
