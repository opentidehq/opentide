"""Golden tests for the ``opentide`` invocations printed in ``docs/``.

Issue #270: the tutorial e2e suite copied YAML fences and ran a hard-coded
command list, so no test ever read the commands the pages actually print. Every
sample-versus-reality bug in #247 — plus `--path` (#248), `--json` placement
(#257) and `opentide explorer build` (#202) — sat in a fenced block that CI
rendered but never executed.

Three gates here, in increasing cost:

* resolution — every documented invocation parses against the live Typer
  command tree, which is cheap enough to run over all 200-odd of them;
* execution — the read-only subset really runs against a scaffolded repo and
  has to produce exactly one JSON document;
* output samples — a ``text`` / ``json`` fence tagged ``output-of="opentide …"``
  runs that command against the same repo and must match what it prints and
  the exit code it returns (#299).
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from click.testing import Result
from tests.docs_commands import (
    DOCS,
    ROOT,
    DocCommand,
    DocOutput,
    documented_commands,
    documented_outputs,
    fenced_blocks,
    heading_line,
    iter_shell_lines,
    normalise,
    outputs_in,
    resolve,
    section_prose,
    split_invocations,
    stated_exit_codes,
)
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import DetectionPlatform
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


def _is_executable(argv: tuple[str, ...], roots: frozenset[str] = EXECUTABLE_ROOTS) -> bool:
    positional = [token for token in argv if not token.startswith("-")]
    if not positional or positional[0] not in roots:
        return False
    if len(positional) > 1 and positional[1] in SKIPPED_SUBCOMMANDS:
        return False
    if "--live" in argv:
        return False
    return not any(marker in token for token in argv for marker in PLACEHOLDER_MARKERS)


EXECUTABLE_COMMANDS = [command for command in DOC_COMMANDS if _is_executable(command.argv)]

DOC_OUTPUTS = documented_outputs()
#: An output sample may also pair with `deploy`: its tests stub the vendor
#: boundary, so a sample cannot reach a platform API.
SAMPLE_ROOTS = EXECUTABLE_ROOTS | {"deploy"}


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


_PAIRED_PAGE = "\n".join(
    [
        "# Page",
        "## Deploy metadata",
        "It exits `2`.",
        "```bash",
        "opentide deploy metadata --platform splunk",
        "```",
        '```text output-of="opentide deploy metadata --platform splunk" exit=2',
        "FATAL: not implemented",
        "```",
        "```text",
        "untagged, so never compared",
        "```",
        '```bash output-of="opentide info"',
        "opentide info",
        "```",
        "## Next",
        "Unrelated prose that exits `0`.",
    ]
)


def _where(output: DocOutput) -> str:
    return f"{output.page}:{output.line}"


def test_output_samples_are_paired_through_the_fence_info_string() -> None:
    (output,) = outputs_in(_PAIRED_PAGE, "docs/example.md")
    assert output.argv == ("deploy", "metadata", "--platform", "splunk")
    assert output.exit_code == 2
    assert (output.language, output.line) == ("text", 7)
    assert output.sample == "FATAL: not implemented"
    assert output.prose.splitlines() == ["## Deploy metadata", "It exits `2`."]


def test_a_sample_without_an_exit_attribute_documents_success() -> None:
    (output,) = outputs_in('```json output-of="opentide --json info"\n{}\n```', "docs/x.md")
    assert (output.argv, output.exit_code) == (("--json", "info"), 0)


def test_a_sample_naming_no_single_opentide_command_has_no_argv() -> None:
    text = '```text output-of="opentide validate && opentide lint"\nOK\n```'
    (output,) = outputs_in(text, "docs/x.md")
    assert output.argv is None


def test_a_heading_inside_a_fence_does_not_start_a_section() -> None:
    text = "## Real\nprose\n```text\n## sample output, not a heading\n```\nmore prose"
    assert section_prose(text, 6) == "## Real\nprose\nmore prose"
    assert heading_line(text, "Real") == 1
    with pytest.raises(LookupError):
        heading_line(text, "sample output")


@pytest.mark.parametrize(
    ("prose", "expected"),
    [
        ("It deploys nothing and exits `2`.", {2}),
        ("reports `skipped` with exit `0`", {0}),
        ("the exit code `1` fails CI", {1}),
        ("exits non-zero with “not implemented”", set()),
        ("Non-zero [exit codes](./exit-codes.md) signal errors.", set()),
    ],
)
def test_stated_exit_codes_read_the_backticked_form(prose: str, expected: set[int]) -> None:
    assert stated_exit_codes(prose) == expected


def test_the_docs_tree_pairs_output_samples() -> None:
    """Guard the attribute parser: the pages fixed for #299 must yield their samples."""
    fixed = {"docs/cli/deploy.md", "docs/usage/troubleshooting.md", "docs/usage/tutorial.md"}
    assert fixed <= {output.page for output in DOC_OUTPUTS}
    assert any(output.exit_code for output in DOC_OUTPUTS)


@pytest.mark.parametrize("output", DOC_OUTPUTS, ids=_where)
def test_every_output_sample_pairs_with_a_command_its_page_prints(output: DocOutput) -> None:
    """The sample must be the output of a command the reader was told to run."""
    assert output.argv is not None, f"{output}: output-of must name one `opentide` command"
    printed = {command.argv for command in DOC_COMMANDS if command.page == output.page}
    assert output.argv in printed, f"{output}: no shell fence on the page runs this command"
    assert _is_executable(output.argv, SAMPLE_ROOTS), f"{output}: the harness cannot run it"
    if output.language == "json":
        json.loads(output.sample)


@pytest.mark.parametrize("output", [o for o in DOC_OUTPUTS if o.exit_code], ids=_where)
def test_a_failing_sample_states_its_exit_code(output: DocOutput) -> None:
    """Issue #299: troubleshooting said `deploy metadata` logs intent; it exits `2`."""
    assert output.exit_code in stated_exit_codes(output.prose), (
        f"{output} documents exit {output.exit_code}, but its section never says "
        f"it exits `{output.exit_code}`:\n{output.prose}"
    )


@pytest.mark.parametrize(
    ("documented", "live", "expected"),
    [
        ({"a": 1}, {"a": 1, "b": 2}, []),
        ({"a": "..."}, {"a": {"deep": [1]}}, []),
        ({"a": ["..."]}, {"a": [1, 2]}, []),
        ({"a": [1]}, {"a": [1, 2]}, ["$.a: documented 1 item(s), returned 2"]),
        ({"a": {"b": 1}}, {"a": {"c": 1}}, ["$.a.b: documented, not returned"]),
        ({"ok": True}, {"ok": 1}, ["$.ok: documented True, returned 1"]),
        ([{"uuid": "x"}], [{"uuid": "y"}], ["$[0].uuid: documented 'x', returned 'y'"]),
    ],
)
def test_json_samples_match_as_a_subset(documented: Any, live: Any, expected: list[str]) -> None:
    assert _json_mismatches(documented, live) == expected


def test_a_colour_run_reads_back_as_the_no_color_view() -> None:
    """Only the two forms colour redraws are rewritten; other panels are drawn either way."""
    issues = ["╭─ Validation issues ─╮", "│ rule.yaml: bad uuid │", "╰─────────────────────╯"]
    colour = [
        "───────── MDR Deployment ─────────",
        "╭───────────── FATAL ─────────────╮",
        "│                                 │",
        "│  Metadata deployment is not     │",
        "│  implemented for splunk         │",
        "│                                 │",
        "╰─────────────────────────────────╯",
        *issues,
    ]
    assert _no_color_view("\n".join(colour)).splitlines() == [
        "== MDR Deployment ==",
        "FATAL: Metadata deployment is not implemented for splunk",
        *issues,
    ]


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
    """Scaffold and generate once; tests get a copy, never this tree.

    The scaffold is the tutorial's own `opentide setup` (§1), Sentinel enabled,
    so a sample that deploys sees the repository the page describes.
    """
    from tests.test_cli.e2e.helpers import write_tutorial_objects

    repo = tmp_path_factory.mktemp("documented") / "detections"
    run_repo_setup(
        RepoSetupOptions(
            path=repo,
            name="Tutorial Detections",
            org="Example Corp",
            platforms=[DetectionPlatform.sentinel],
            yes=True,
        )
    )
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
_FATAL_TOP = re.compile(r"╭─+ FATAL ─+╮")
_PANEL_ROW = re.compile(r"│(?P<text>.*)│")


def _no_color_view(output: str) -> str:
    """A colour run read back as the `--no-color` view the pages print.

    Colour draws each `== Title ==` header as a Rich rule `─── Title ───`, and
    a failure's `FATAL: message` as a panel titled FATAL around the message
    (`emit_fatal`), wrapped onto more rows when it is too long for one.
    """
    view: list[str] = []
    fatal: list[str] | None = None
    for line in output.splitlines():
        stripped = line.strip()
        if fatal is not None:
            if row := _PANEL_ROW.fullmatch(stripped):
                if text := row["text"].strip():
                    fatal.append(text)
                continue
            view.append("FATAL: " + " ".join(fatal))
            fatal = None
            if stripped.startswith("╰"):
                continue
        if _FATAL_TOP.fullmatch(stripped):
            fatal = []
        elif rule := _RULE.fullmatch(stripped):
            view.append(f"== {rule['title']} ==")
        else:
            view.append(line)
    return "\n".join(view)


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
    live = _no_color_view(result.output) if colour else result.output
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


#: A documented JSON value spelled like this stands for whatever is returned.
_ELIDED = ("...", "…")


def _json_mismatches(documented: Any, live: Any, path: str = "$") -> list[str]:
    """Where *live* departs from *documented*, read as a subset of it.

    Objects may return keys the sample leaves out; lists must match item for
    item unless the sample is a single elided item; scalars must be equal and
    of the same type, so `true` is not satisfied by `1`.
    """
    if isinstance(documented, str) and documented in _ELIDED:
        return []
    if isinstance(documented, dict):
        if not isinstance(live, dict):
            return [f"{path}: documented an object, returned {live!r}"]
        problems: list[str] = []
        for key, value in documented.items():
            if key in live:
                problems.extend(_json_mismatches(value, live[key], f"{path}.{key}"))
            else:
                problems.append(f"{path}.{key}: documented, not returned")
        return problems
    if isinstance(documented, list):
        if not isinstance(live, list):
            return [f"{path}: documented a list, returned {live!r}"]
        if len(documented) == 1 and isinstance(documented[0], str) and documented[0] in _ELIDED:
            return []
        if len(documented) != len(live):
            return [f"{path}: documented {len(documented)} item(s), returned {len(live)}"]
        return [
            problem
            for index, (expected, actual) in enumerate(zip(documented, live, strict=True))
            for problem in _json_mismatches(expected, actual, f"{path}[{index}]")
        ]
    if type(documented) is not type(live) or documented != live:
        return [f"{path}: documented {documented!r}, returned {live!r}"]
    return []


@pytest.fixture
def stub_deployers(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Stand in for the vendor boundary so a sample can never reach a platform API.

    Only `DeployTide` is replaced: the plan, the payload preview, and what the
    command prints are the real ones.
    """
    deployers: dict[str, MagicMock] = {}

    class _StubDeployTide:
        def mdr_for(self, platforms: Any) -> dict[str, MagicMock]:
            return {name: deployers.setdefault(name, MagicMock()) for name in platforms}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _StubDeployTide)
    return deployers


def _run_sample(output: DocOutput, repo: Path, *, colour: bool) -> Result:
    assert output.argv is not None, output
    root = ["--repo", str(repo)] if colour else ["--repo", str(repo), "--no-color"]
    return CliRunner().invoke(app, [*root, *output.argv])


def _sample_mismatches(output: DocOutput, result: Result, *, colour: bool) -> list[str]:
    if output.language == "json":
        return _json_mismatches(json.loads(output.sample), json.loads(result.stdout))
    live = _no_color_view(result.output) if colour else result.output
    return _lines_in_order(output.sample, live)


_OUTPUT_CASES = [
    pytest.param(output, colour, id=f"{_where(output)}-{'colour' if colour else 'no-color'}")
    for output in DOC_OUTPUTS
    for colour in ((False, True) if output.language == "text" else (False,))
]


@pytest.mark.cli_e2e
@pytest.mark.parametrize(("output", "colour"), _OUTPUT_CASES)
def test_documented_output_samples_match_the_live_command(
    output: DocOutput, colour: bool, documented_repo: Path, stub_deployers: dict[str, MagicMock]
) -> None:
    """Issue #299: deploy, troubleshooting and tutorial samples showed output 0.5.0 never printed.

    A text sample must appear as whole lines, in order, in the terminal view
    (stderr and stdout interleaved; a colour run read back as `--no-color`).
    A JSON sample is a subset of the one document on stdout.
    """
    result = _run_sample(output, documented_repo, colour=colour)
    assert result.exception is None or isinstance(result.exception, SystemExit), (
        f"{output}\n{result.output}"
    )
    assert result.exit_code == output.exit_code, (
        f"{output} documents exit {output.exit_code}, the command returned "
        f"{result.exit_code}\n{result.output}"
    )
    mismatches = _sample_mismatches(output, result, colour=colour)
    assert not mismatches, (
        f"{output}\n  " + "\n  ".join(mismatches) + f"\n--- live ---\n{result.output}"
    )
    if "--dry-run" in (output.argv or ()):
        for deployer in stub_deployers.values():
            deployer.deploy.assert_not_called()


_PRE_0_5_0_DEPLOY_SAMPLE = "\n".join(
    [
        '```text output-of="opentide deploy --platform sentinel --dry-run"',
        "deploy (dry-run): sentinel",
        "  Sentinel KQL Rule  STAGING  → would create/update",
        "deploy: 1 rule planned, 0 applied (dry-run)",
        "```",
    ]
)


@pytest.mark.cli_e2e
def test_the_sample_issue_299_reported_fails_the_output_check(
    documented_repo: Path, stub_deployers: dict[str, MagicMock]
) -> None:
    """Negative control: docs/cli/deploy.md's 0.5.0 sample, paired with its command."""
    (stale,) = outputs_in(_PRE_0_5_0_DEPLOY_SAMPLE, "docs/cli/deploy.md")
    result = _run_sample(stale, documented_repo, colour=False)
    assert result.exit_code == 0, result.output
    assert _sample_mismatches(stale, result, colour=False) == [
        "deploy (dry-run): sentinel",
        "Sentinel KQL Rule  STAGING  → would create/update",
        "deploy: 1 rule planned, 0 applied (dry-run)",
    ]


@pytest.mark.cli_e2e
def test_troubleshooting_states_the_exit_code_deploy_metadata_returns(
    documented_repo: Path,
) -> None:
    """Issue #299: the page said `deploy metadata` "signals intent in logs"; it exits 2."""
    text = (DOCS / "usage" / "troubleshooting.md").read_text(encoding="utf-8")
    prose = section_prose(text, heading_line(text, "`deploy metadata`"))
    result = CliRunner().invoke(
        app, ["--repo", str(documented_repo), "deploy", "metadata", "--platform", "splunk"]
    )
    assert result.exit_code == 2, result.output
    assert stated_exit_codes(prose) == {result.exit_code}, prose
