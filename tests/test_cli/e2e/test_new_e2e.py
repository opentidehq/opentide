"""CLI E2E: ``opentide new`` on the tutorial workspace validates clean after ``generate``."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import TUTORIAL, write_tutorial_objects

from opentide.platforms.enabled import SYSTEM_KEYS

pytestmark = pytest.mark.cli_e2e

THREAT_UUID = "00000000-0000-4000-8001-000000000001"
OBJECTIVE_UUID = "00000000-0000-4000-8002-000000000001"

#: Git reads these in place of a global config: the author ``new`` records.
GIT_AUTHOR = {
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "user.name",
    "GIT_CONFIG_VALUE_0": "Tutorial Author",
}


@pytest.fixture
def tutorial(invoke_cli, tmp_path: Path) -> Path:
    fresh = tmp_path / "tutorial-detections"
    setup = invoke_cli(
        "setup",
        "--yes",
        "--name",
        "Tutorial Detections",
        "--org",
        "Example Corp",
        "--platform",
        "sentinel",
        "--path",
        str(fresh),
        repo=tmp_path,
    )
    assert_json_ok(setup)
    write_tutorial_objects(fresh, markdown=TUTORIAL.read_text(encoding="utf-8"))
    return fresh


def test_every_family_and_platform_validates_after_new_and_generate(
    invoke_cli, tutorial: Path
) -> None:
    created: list[dict] = []
    threat = invoke_cli(
        "new", "threat", "--name", "Credential Dumping", repo=tutorial, extra_env=GIT_AUTHOR
    )
    created.append(assert_json_ok(threat))
    objective = invoke_cli(
        "new",
        "objective",
        "--name",
        "Detect Credential Dumping",
        "--threat",
        THREAT_UUID,
        repo=tutorial,
        extra_env=GIT_AUTHOR,
    )
    created.append(assert_json_ok(objective))
    for platform in SYSTEM_KEYS:
        rule = invoke_cli(
            "new",
            "rule",
            "--name",
            f"LSASS Access {platform}",
            "--platform",
            platform,
            "--objective",
            OBJECTIVE_UUID,
            repo=tutorial,
            extra_env=GIT_AUTHOR,
        )
        created.append(assert_json_ok(rule))

    for payload in created:
        assert (tutorial / payload["path"]).is_file()
        assert payload["author"] == "Tutorial Author"
        assert payload["organisation"]["name"] == "Example Corp"
        assert (
            payload["next_actions"][0]["command"]
            == f"opentide --json validate --file {payload['path']}"
        )
    assert created[0]["path"] == "objects/threats/credential-dumping.yaml"
    assert created[1]["path"] == "objects/objectives/detect-credential-dumping.yaml"
    assert THREAT_UUID in (tutorial / created[1]["path"]).read_text(encoding="utf-8")

    assert_json_ok(invoke_cli("generate", repo=tutorial))
    validate = invoke_cli("validate", "--strict", repo=tutorial)
    report = assert_json_ok(validate)["report"]
    assert report["ok"] is True, report
    # Placeholder values pass validation but are marked, so CI's lint --strict
    # fails until someone replaces them.
    marked = invoke_cli("lint", "--strict", repo=tutorial)
    assert marked.exit_code == 1
    findings = parse_cli_json(marked)["findings"]
    assert findings
    assert {finding["code"] for finding in findings} == {"placeholder"}
    threat_findings = {
        finding["message"].split(" ", 1)[0]
        for finding in findings
        if finding["path"] == created[0]["path"]
    }
    # Items of a list are named by their key and index.
    assert {"surface[0]", "mitre_attack[0]"} <= threat_findings, threat_findings
    clean = assert_json_ok(
        invoke_cli("lint", "--strict", "--check", "filenames", "--check", "metadata", repo=tutorial)
    )
    assert clean["count"] == 0, clean["findings"]


def test_rules_validate_when_every_platform_is_enabled(invoke_cli, tmp_path: Path) -> None:
    """Enabled platforms give the generated schema more enums; the values must still be valid."""
    fresh = tmp_path / "all-platforms"
    platforms = [arg for key in SYSTEM_KEYS for arg in ("--platform", key)]
    assert_json_ok(invoke_cli("setup", "--yes", *platforms, "--path", str(fresh), repo=tmp_path))
    for platform in SYSTEM_KEYS:
        rule = invoke_cli(
            "new", "rule", "--name", f"Rule {platform}", "--platform", platform, repo=fresh
        )
        payload = assert_json_ok(rule)
        assert not any("not enabled" in warning for warning in payload.get("warnings", []))
        # Every block holds detection logic to replace, not just enabled and status.
        assert any(
            path.startswith(f"configurations.{platform}.") for path in payload["placeholders"]
        ), payload["placeholders"]
    assert_json_ok(invoke_cli("generate", repo=fresh))
    report = assert_json_ok(invoke_cli("validate", "--strict", repo=fresh))["report"]
    assert report["ok"] is True, report


#: Platforms whose dry run compiles the real request body offline. The others
#: preview the block as written, so a compile cannot fail there.
OFFLINE_COMPILE = ("sentinel", "elastic")


@pytest.mark.parametrize("platform", OFFLINE_COMPILE)
def test_scaffolded_rule_compiles_in_a_dry_run(
    invoke_cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    """new → validate → deploy --dry-run compiles, with only the status moved on.

    The block starts at the INERT status, which deploy skips; a person moves it
    to a PREVIEW status to try it. Every other value, placeholders included,
    must already compile.
    """
    for name in ("CI", "GITHUB_ACTIONS", "TF_BUILD"):
        monkeypatch.delenv(name, raising=False)
    # A failed compile sets this in os.environ; setenv first so teardown removes it.
    monkeypatch.setenv("DEPLOYMENT_ERROR_RAISED", "")
    monkeypatch.delenv("DEPLOYMENT_ERROR_RAISED")
    fresh = tmp_path / platform
    assert_json_ok(invoke_cli("setup", "--yes", "--platform", platform, "--path", str(fresh)))
    payload = assert_json_ok(
        invoke_cli("new", "rule", "--name", "Scaffolded", "--platform", platform, repo=fresh)
    )
    report = assert_json_ok(invoke_cli("validate", "--strict", repo=fresh))["report"]
    assert report["ok"] is True, report

    rule = fresh / payload["path"]
    text = rule.read_text(encoding="utf-8")
    assert "status: DESIGN" in text
    rule.write_text(text.replace("status: DESIGN", "status: DEVELOPMENT"), encoding="utf-8")
    result = invoke_cli(
        "deploy", "--dry-run", "--strategy", "PREVIEW", "--all", "--platform", platform, repo=fresh
    )
    deploy = parse_cli_json(result)
    assert deploy["plan"][platform] == [payload["uuid"]], deploy
    [preview] = deploy["payloads"][platform]
    assert preview.get("status") != "failed", preview
    assert result.exit_code == 0, deploy
    if platform == "elastic":
        # Elastic falls back to the raw block when its compile fails; only the
        # compiled body carries a risk score.
        assert "risk_score" in preview["api_request"], preview
    else:
        assert preview["api_request"]["properties"]["displayName"] == "Scaffolded"


def test_new_without_a_name_refuses_to_prompt(invoke_cli, tutorial: Path) -> None:
    result = invoke_cli("new", "rule", repo=tutorial)
    assert result.exit_code == 2
    failure = parse_cli_json(result)["failure"]
    assert failure["code"] == "usage_needs_input"
    assert failure["argument"] == "--name"
    assert [path.name for path in (tutorial / "objects" / "rules").glob("*.yaml")] == [
        "sentinel-kql-rule.yaml"
    ]


def test_new_generates_missing_templates_first(invoke_cli, tutorial: Path) -> None:
    templates = tutorial / ".opentide" / "templates"
    for path in templates.glob("*.template.yaml"):
        path.unlink()
    result = invoke_cli("new", "threat", "--name", "Fresh Threat", repo=tutorial)
    payload = assert_json_ok(result)
    assert "templates" in payload["generated"]
    assert (templates / "threat.1.0.template.yaml").is_file()
    assert_json_ok(invoke_cli("validate", "--strict", "--file", payload["path"], repo=tutorial))


def _configure_filenames(workspace: Path, body: str) -> None:
    config = workspace / ".opentide" / "configurations" / "lint.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(f"[filenames]\n{body}\n", encoding="utf-8")


def test_new_names_the_file_by_the_configured_style(invoke_cli, tutorial: Path) -> None:
    """``style = "name"`` scaffolds a file ``lint`` accepts, and a taken name gets the uuid."""
    name = "[SEN][AWS]Some rule[TenantA+TenantB]"
    _configure_filenames(tutorial, 'style = "name"')
    first = assert_json_ok(
        invoke_cli("new", "threat", "--name", name, repo=tutorial, extra_env=GIT_AUTHOR)
    )
    assert first["path"] == f"objects/threats/{name}.yaml"
    second = assert_json_ok(
        invoke_cli("new", "threat", "--name", name, repo=tutorial, extra_env=GIT_AUTHOR)
    )
    assert second["path"] == f"objects/threats/{name}-{second['uuid'][:8]}.yaml"
    assert_json_ok(invoke_cli("generate", repo=tutorial))
    findings = parse_cli_json(invoke_cli("lint", "--check", "filenames", repo=tutorial))["findings"]
    # The tutorial's own files keep their slugs; the scaffolded ones are not reported.
    assert {item["path"] for item in findings} == {
        "objects/threats/simulated-actor.yaml",
        "objects/objectives/credential-access-objective.yaml",
        "objects/rules/sentinel-kql-rule.yaml",
    }


@pytest.mark.parametrize("style", ["slug", "none"])
def test_new_keeps_the_slug_for_slug_and_none(invoke_cli, tutorial: Path, style: str) -> None:
    _configure_filenames(tutorial, f'style = "{style}"')
    payload = assert_json_ok(
        invoke_cli("new", "threat", "--name", "Some Actor", repo=tutorial, extra_env=GIT_AUTHOR)
    )
    assert payload["path"] == "objects/threats/some-actor.yaml"


def test_new_warns_when_the_file_misses_the_configured_pattern(invoke_cli, tutorial: Path) -> None:
    _configure_filenames(tutorial, "pattern = '^\\[SEN\\].+$'")
    miss = assert_json_ok(
        invoke_cli("new", "threat", "--name", "Some Actor", repo=tutorial, extra_env=GIT_AUTHOR)
    )
    assert any("[filenames].pattern" in text for text in miss["warnings"]), miss["warnings"]
    _configure_filenames(tutorial, "style = \"name\"\npattern = '^\\[SEN\\].+$'")
    hit = assert_json_ok(
        invoke_cli("new", "threat", "--name", "[SEN]Actor", repo=tutorial, extra_env=GIT_AUTHOR)
    )
    assert not any("[filenames].pattern" in text for text in hit.get("warnings", []))


def test_new_with_an_invalid_lint_toml_exits_2_before_writing(invoke_cli, tutorial: Path) -> None:
    assert_json_ok(invoke_cli("generate", repo=tutorial))
    _configure_filenames(tutorial, 'style = "camel"')
    before = sorted(path.name for path in (tutorial / "objects" / "threats").iterdir())
    result = invoke_cli("new", "threat", "--name", "Some Actor", repo=tutorial)
    assert result.exit_code == 2, result.output
    assert "lint.toml [filenames].style" in parse_cli_json(result)["message"]
    assert sorted(path.name for path in (tutorial / "objects" / "threats").iterdir()) == before
