"""``lint.toml``: per-check ``enabled`` and ``severity``, and ``[metadata].required`` (#489)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import LintCheck
from opentide.cli.services.lint import run_lint
from opentide.core.lint_config import (
    CHECK_NAMES,
    DEFAULT_REQUIRED_METADATA,
    FilenameConfig,
    FilenameStyle,
    LintConfig,
    LintConfigError,
    expected_stem,
    load_lint_config,
    metadata_keys,
    parse_lint_config,
)

runner = CliRunner()

_BARE = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
"""


def _write_object(root: Path, filename: str, body: str = _BARE) -> None:
    dest = root / "objects" / "threats" / filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(body, encoding="utf-8")


def _write_lint_toml(root: Path, text: str) -> None:
    dest = root / ".opentide" / "configurations" / "lint.toml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")


def test_check_names_match_the_cli_enum() -> None:
    assert tuple(item.value for item in LintCheck) == CHECK_NAMES


def test_bundled_defaults_reproduce_unconfigured_lint(tmp_path: Path) -> None:
    config = load_lint_config(tmp_path)
    assert config.required_metadata == DEFAULT_REQUIRED_METADATA == ("author", "organisation")
    assert config.enabled_checks() == ["filenames", "metadata", "placeholders", "queries"]
    assert all(config.check(name).severity is None for name in CHECK_NAMES)


def test_no_lint_table_parses_to_defaults() -> None:
    assert parse_lint_config(None) == LintConfig()


def test_workspace_required_replaces_the_default(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["author", "tlp"]\n')
    (finding,) = run_lint(tmp_path)["findings"]
    assert finding["message"] == "Recommended metadata missing: author, tlp"


def test_empty_required_silences_the_metadata_check(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, "[metadata]\nrequired = []\n")
    result = run_lint(tmp_path)
    assert result["count"] == 0
    assert result["checks"] == ["filenames", "metadata", "placeholders", "queries"]


def test_required_counts_empty_lists_and_strings_as_missing(tmp_path: Path) -> None:
    body = _BARE + "  author: '  '\n  contributors: []\n  version: 1\n"
    _write_object(tmp_path, "simulated-actor.yaml", body)
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["author", "contributors", "version"]\n')
    (finding,) = run_lint(tmp_path)["findings"]
    assert finding["message"] == "Recommended metadata missing: author, contributors"


def test_disabled_check_does_not_run(tmp_path: Path) -> None:
    _write_object(tmp_path, "Simulated Actor.yaml")
    _write_lint_toml(tmp_path, "[metadata]\nenabled = false\n")
    result = run_lint(tmp_path)
    assert result["checks"] == ["filenames", "placeholders", "queries"]
    assert [item["check"] for item in result["findings"]] == ["filenames"]


def test_check_flag_wins_over_a_disabled_check(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, "[metadata]\nenabled = false\n")
    result = run_lint(tmp_path, checks=[LintCheck.metadata])
    assert result["checks"] == ["metadata"]
    assert result["count"] == 1


def test_every_check_disabled_passes(tmp_path: Path) -> None:
    _write_object(tmp_path, "Simulated Actor.yaml")
    _write_lint_toml(
        tmp_path,
        "[metadata]\nenabled = false\n[filenames]\nenabled = false\n"
        "[placeholders]\nenabled = false\n[queries]\nenabled = false\n",
    )
    result = run_lint(tmp_path, strict=True)
    assert result["checks"] == []
    assert result["status"] == "completed"


def test_severity_override_applies_to_each_finding_of_the_check(tmp_path: Path) -> None:
    _write_object(tmp_path, "Simulated Actor.yaml")
    _write_lint_toml(tmp_path, '[metadata]\nseverity = "error"\n')
    findings = {item["check"]: item["severity"] for item in run_lint(tmp_path)["findings"]}
    assert findings == {"metadata": "error", "filenames": "warning"}


def test_explicit_config_argument_skips_the_workspace(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, "[metadata]\nrequired = []\n")
    config = parse_lint_config({"metadata": {"required": ["author"]}})
    (finding,) = run_lint(tmp_path, config=config)["findings"]
    assert finding["message"] == "Recommended metadata missing: author"


def test_metadata_keys_cover_every_schema() -> None:
    keys = metadata_keys()
    assert {"author", "organisation", "contributors", "schema", "reviewed"} <= set(keys)
    assert "schema_id" not in keys


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (
            {"metadata": {"required": ["author", "autor", "org"]}},
            r"lint\.toml \[metadata\]\.required: unknown metadata field\(s\) 'autor', 'org'\. "
            r"Known fields: uuid, schema, ",
        ),
        ({"metadata": {"required": "author"}}, r"required must be a list of metadata keys"),
        ({"metadatas": {}}, r"unknown check\(s\) 'metadatas'\. Known checks: filenames, metadata"),
        ({"metadata": {"requried": []}}, r"\[metadata\]: unknown key\(s\) 'requried'"),
        ({"filenames": {"required": []}}, r"\[filenames\]: unknown key\(s\) 'required'"),
        ({"filenames": {"enabled": "no"}}, r"\[filenames\]\.enabled must be true or false"),
        ({"filenames": {"severity": "fatal"}}, r"severity must be one of error, warning, info"),
        (
            {"filenames": {"style": "snake"}},
            r"lint\.toml \[filenames\]\.style must be one of slug, name, none, got 'snake'",
        ),
        ({"filenames": {"style": True}}, r"\[filenames\]\.style must be one of slug, name, none"),
        ({"filenames": {"pattern": 3}}, r"\[filenames\]\.pattern must be a string, got 3"),
        ({"filenames": {"pattern": ""}}, r"\[filenames\]\.pattern must not be empty"),
        (
            {"filenames": {"pattern": "[unclosed"}},
            r"lint\.toml \[filenames\]\.pattern: invalid regular expression '\[unclosed'",
        ),
        ({"metadata": {"style": "name"}}, r"\[metadata\]: unknown key\(s\) 'style'"),
        ({"queries": {"pattern": "x"}}, r"\[queries\]: unknown key\(s\) 'pattern'"),
        ({"filenames": True}, r"\[filenames\] must be a table"),
        (["metadata"], r"must hold tables"),
    ],
)
def test_bad_config_names_the_key(raw: object, match: str) -> None:
    with pytest.raises(LintConfigError, match=match):
        parse_lint_config(raw)


def test_unknown_required_field_fails_the_command(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["author", "owner"]\n')
    result = runner.invoke(app, ["--json", "--repo", str(tmp_path), "lint"])
    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "unknown metadata field(s) 'owner'" in payload["message"]


def test_unknown_required_field_fails_the_human_command(tmp_path: Path) -> None:
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["owner"]\n')
    result = runner.invoke(app, ["--no-color", "--repo", str(tmp_path), "lint"])
    assert result.exit_code == 2
    assert "unknown metadata field(s) 'owner'" in result.output


def test_required_skips_keys_the_object_schema_cannot_hold(tmp_path: Path) -> None:
    # ``reviewed`` exists only on rule::1.1 metadata; threat::1.0 forbids it,
    # so demanding it of a threat is a finding no author can fix.
    _write_object(tmp_path, "simulated-actor.yaml", _BARE + "  author: Jane\n")
    rule = tmp_path / "objects" / "rules" / "simulated-rule.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "name: Simulated Rule\nmetadata:\n"
        "  uuid: 00000000-0000-4000-8001-000000000002\n"
        "  schema: rule::1.1\n  author: Jane\n",
        encoding="utf-8",
    )
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["author", "reviewed"]\n')
    findings = run_lint(tmp_path)["findings"]
    assert [(item["path"], item["message"]) for item in findings] == [
        ("objects/rules/simulated-rule.yaml", "Recommended metadata missing: reviewed")
    ]


def test_unparsable_lint_toml_is_framed_like_any_config_file(tmp_path: Path) -> None:
    _write_lint_toml(tmp_path, "[metadata\n")
    result = runner.invoke(app, ["--json", "--repo", str(tmp_path), "lint"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["failure"]["code"] == "config_parse"


# --- [filenames] style and pattern (#699) ---------------------------------------------------

_BRACKETED = """\
name: '[SEN][AWS]Some rule[TenantA+TenantB]'
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
"""
_BRACKETED_STEM = "[SEN][AWS]Some rule[TenantA+TenantB]"
_BRACKETED_PATTERN = r"^\[(SEN|XDR)\]\[[^\]]+\].+\[[^\]]+\]$"


def _filenames_toml(root: Path, body: str) -> None:
    _write_lint_toml(root, f"[filenames]\n{body}\n")


def _threats(root: Path) -> list[str]:
    return sorted(path.name for path in (root / "objects" / "threats").iterdir())


def test_filenames_default_to_the_slug_with_no_pattern(tmp_path: Path) -> None:
    config = load_lint_config(tmp_path)
    assert config.filenames == FilenameConfig(style="slug", pattern=None)
    assert parse_lint_config({"filenames": {"enabled": True}}).filenames == FilenameConfig()


def test_filenames_style_and_pattern_parse() -> None:
    config = parse_lint_config({"filenames": {"style": "name", "pattern": "[A-Z].*"}})
    assert config.filenames.style == "name"
    assert config.filenames.pattern is not None
    assert config.filenames.pattern.pattern == "[A-Z].*"


@pytest.mark.parametrize(
    ("name", "style", "expected"),
    [
        ("Simulated Actor", "slug", "simulated-actor"),
        ("Simulated Actor", "name", "Simulated Actor"),
        (_BRACKETED_STEM, "name", _BRACKETED_STEM),
        # Characters a Windows file name cannot hold are removed, as safe_file_name does.
        ('Who: "me"? <a|b>*', "name", "Who me ab"),
        ("a/b\\c", "name", "abc"),
        # Windows drops a trailing dot or space, Unix hides a leading dot.
        ("  Rule name. ", "name", "Rule name"),
        (".hidden rule", "name", "hidden rule"),
        ("Tab\there\x00", "name", "Tabhere"),
        ("???", "name", None),
        ("..", "name", None),
        ("Simulated Actor", "none", None),
    ],
)
def test_expected_stem(name: str, style: FilenameStyle, expected: str | None) -> None:
    assert expected_stem(name, style) == expected


def test_style_name_passes_a_file_named_after_the_object(tmp_path: Path) -> None:
    _write_object(tmp_path, f"{_BRACKETED_STEM}.yaml", _BRACKETED)
    _filenames_toml(tmp_path, 'style = "name"')
    result = run_lint(tmp_path, checks=[LintCheck.filenames])
    assert result["count"] == 0, result["findings"]


def test_style_name_reports_a_differing_stem_and_fix_is_idempotent(tmp_path: Path) -> None:
    _write_object(tmp_path, "some-rule.yaml", _BRACKETED)
    _filenames_toml(tmp_path, 'style = "name"')
    (finding,) = run_lint(tmp_path, checks=[LintCheck.filenames])["findings"]
    assert finding["code"] == "filename_mismatch"
    assert finding["expected"] == f"objects/threats/{_BRACKETED_STEM}.yaml"
    assert "does not match name" in str(finding["message"])
    assert "slugify" not in str(finding["message"])

    fixed = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    assert fixed["fixed"] == 1
    assert _threats(tmp_path) == [f"{_BRACKETED_STEM}.yaml"]
    again = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    assert (again["count"], again["fixed"]) == (0, 0)
    assert _threats(tmp_path) == [f"{_BRACKETED_STEM}.yaml"]


def test_style_name_is_case_sensitive_and_fix_renames_a_case_only_difference(
    tmp_path: Path,
) -> None:
    _write_object(tmp_path, "[sen][aws]some rule[tenanta+tenantb].yaml", _BRACKETED)
    _filenames_toml(tmp_path, 'style = "name"')
    assert run_lint(tmp_path, checks=[LintCheck.filenames])["count"] == 1
    assert run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)["fixed"] == 1
    assert _threats(tmp_path) == [f"{_BRACKETED_STEM}.yaml"]


def test_style_name_collision_uses_a_uuid_suffix(tmp_path: Path) -> None:
    _write_object(tmp_path, f"{_BRACKETED_STEM}.yaml", _BRACKETED)
    other = _BRACKETED.replace(
        "00000000-0000-4000-8001-000000000001", "11111111-1111-4111-8111-111111111111"
    )
    _write_object(tmp_path, "other.yaml", other)
    _filenames_toml(tmp_path, 'style = "name"')
    (finding,) = run_lint(tmp_path, checks=[LintCheck.filenames])["findings"]
    assert finding["expected"] == f"objects/threats/{_BRACKETED_STEM}-11111111.yaml"
    assert run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)["fixed"] == 1
    assert _threats(tmp_path) == [f"{_BRACKETED_STEM}-11111111.yaml", f"{_BRACKETED_STEM}.yaml"]
    assert run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)["count"] == 0


def test_style_name_treats_names_that_differ_only_by_case_as_one_file(tmp_path: Path) -> None:
    """``Rule`` and ``rule`` are one file on macOS and Windows: the second gets a suffix."""
    _write_object(tmp_path, "Some Rule.yaml", _BRACKETED.replace(_BRACKETED_STEM, "Some Rule"))
    lower = _BRACKETED.replace(_BRACKETED_STEM, "some rule").replace(
        "00000000-0000-4000-8001-000000000001", "22222222-2222-4222-8222-222222222222"
    )
    _write_object(tmp_path, "other.yaml", lower)
    _filenames_toml(tmp_path, 'style = "name"')
    (finding,) = run_lint(tmp_path, checks=[LintCheck.filenames])["findings"]
    assert finding["expected"] == "objects/threats/some rule-22222222.yaml"


def test_style_name_with_nothing_to_name_a_file_after_is_not_compared(tmp_path: Path) -> None:
    _write_object(tmp_path, "whatever.yaml", _BRACKETED.replace(_BRACKETED_STEM, "???"))
    _filenames_toml(tmp_path, 'style = "name"')
    assert run_lint(tmp_path, checks=[LintCheck.filenames])["count"] == 0


def test_style_none_skips_the_name_comparison_but_keeps_the_other_findings(
    tmp_path: Path,
) -> None:
    _write_object(tmp_path, "whatever-i-like.yaml", _BRACKETED)
    _write_object(tmp_path, "unnamed.yaml", "metadata: {}\n")
    _write_object(tmp_path, "broken.yaml", "name: [unclosed\n")
    _write_object(tmp_path, "team/nested.yaml", "name: Other\nmetadata: {}\n")
    _filenames_toml(tmp_path, 'style = "none"')
    result = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    codes = sorted(str(item["code"]) for item in result["findings"])
    assert codes == ["name_missing", "nested_object_file", "yaml_parse"]
    assert result["fixed"] == 0
    assert "whatever-i-like.yaml" in _threats(tmp_path)
    (missing,) = (item for item in result["findings"] if item["code"] == "name_missing")
    assert missing["message"] == "Object has no name; cannot check filename"


def test_pattern_passes_a_matching_stem(tmp_path: Path) -> None:
    _write_object(tmp_path, f"{_BRACKETED_STEM}.yaml", _BRACKETED)
    _filenames_toml(tmp_path, f"style = \"none\"\npattern = '{_BRACKETED_PATTERN}'")
    assert run_lint(tmp_path, checks=[LintCheck.filenames])["count"] == 0


def test_pattern_reports_a_stem_that_does_not_match_and_is_not_fixable(tmp_path: Path) -> None:
    _write_object(tmp_path, "Some rule.yaml", _BRACKETED)
    _filenames_toml(tmp_path, f"style = \"none\"\npattern = '{_BRACKETED_PATTERN}'")
    for fix in (False, True):
        result = run_lint(tmp_path, checks=[LintCheck.filenames], fix=fix)
        (finding,) = result["findings"]
        assert finding["code"] == "filename_pattern"
        assert finding["check"] == "filenames"
        assert finding["severity"] == "warning"
        assert finding["path"] == "objects/threats/Some rule.yaml"
        assert finding["uuid"] == "00000000-0000-4000-8001-000000000001"
        assert "expected" not in finding
        assert "fixed" not in finding
        assert _BRACKETED_PATTERN in str(finding["help"])
        assert result["fixed"] == 0
        assert "_next_actions" not in result
    assert _threats(tmp_path) == ["Some rule.yaml"]


def test_pattern_is_matched_against_the_whole_stem(tmp_path: Path) -> None:
    _write_object(tmp_path, "abc-extra.yaml", _BRACKETED)
    _filenames_toml(tmp_path, 'style = "none"\npattern = "abc"')
    assert run_lint(tmp_path, checks=[LintCheck.filenames])["count"] == 1
    _filenames_toml(tmp_path, 'style = "none"\npattern = "abc.*"')
    assert run_lint(tmp_path, checks=[LintCheck.filenames])["count"] == 0


def test_pattern_severity_follows_the_filenames_table(tmp_path: Path) -> None:
    _write_object(tmp_path, "x.yaml", _BRACKETED)
    _filenames_toml(tmp_path, 'style = "none"\npattern = "y"\nseverity = "error"')
    (finding,) = run_lint(tmp_path, checks=[LintCheck.filenames])["findings"]
    assert finding["severity"] == "error"


def test_pattern_applies_together_with_style(tmp_path: Path) -> None:
    _write_object(tmp_path, "some-rule.yaml", _BRACKETED)
    _filenames_toml(tmp_path, f"style = \"name\"\npattern = '{_BRACKETED_PATTERN}'")
    findings = run_lint(tmp_path, checks=[LintCheck.filenames])["findings"]
    assert [item["code"] for item in findings] == ["filename_mismatch", "filename_pattern"]
    # --fix renames to the stem the name gives, and the pattern is judged by that stem.
    fixed = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    assert [(item["code"], item.get("fixed")) for item in fixed["findings"]] == [
        ("filename_mismatch", True)
    ]
    assert run_lint(tmp_path, checks=[LintCheck.filenames])["count"] == 0


def test_pattern_that_the_renamed_stem_misses_is_reported_at_the_new_path(
    tmp_path: Path,
) -> None:
    _write_object(tmp_path, "some-rule.yaml", _BRACKETED)
    _filenames_toml(tmp_path, 'style = "name"\npattern = "^no match$"')
    findings = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)["findings"]
    assert [item["code"] for item in findings] == ["filename_mismatch", "filename_pattern"]
    assert {item["path"] for item in findings} == {f"objects/threats/{_BRACKETED_STEM}.yaml"}
    assert f"{_BRACKETED_STEM}.yaml" in str(findings[1]["message"])


def test_pattern_applies_to_an_unnamed_object(tmp_path: Path) -> None:
    _write_object(tmp_path, "unnamed.yaml", "metadata: {}\n")
    _filenames_toml(tmp_path, 'pattern = "y"')
    findings = run_lint(tmp_path, checks=[LintCheck.filenames])["findings"]
    assert [item["code"] for item in findings] == ["name_missing", "filename_pattern"]


def test_default_filenames_findings_are_unchanged_by_the_new_keys(tmp_path: Path) -> None:
    _write_object(tmp_path, "Simulated Actor.yaml", _BARE)
    plain = run_lint(tmp_path, checks=[LintCheck.filenames])
    _filenames_toml(tmp_path, 'style = "slug"')
    explicit = run_lint(tmp_path, checks=[LintCheck.filenames])
    assert plain["findings"] == explicit["findings"]
    (finding,) = plain["findings"]
    assert finding["message"] == (
        "Filename 'Simulated Actor.yaml' does not match slugify(name)='simulated-actor'"
    )


def test_bad_style_or_pattern_fails_the_command_naming_the_key(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    for body, needle in (
        ('style = "camel"', "lint.toml [filenames].style must be one of slug, name, none"),
        ("pattern = 7", "lint.toml [filenames].pattern must be a string"),
        ('pattern = "(["', "lint.toml [filenames].pattern: invalid regular expression"),
    ):
        _filenames_toml(tmp_path, body)
        result = runner.invoke(app, ["--json", "--repo", str(tmp_path), "lint"])
        assert result.exit_code == 2, result.output
        payload = json.loads(result.stdout)
        assert payload["ok"] is False
        assert needle in payload["message"]


def test_check_filenames_runs_a_disabled_check_with_its_style(tmp_path: Path) -> None:
    _write_object(tmp_path, "some-rule.yaml", _BRACKETED)
    _filenames_toml(tmp_path, 'enabled = false\nstyle = "name"')
    assert run_lint(tmp_path)["checks"] == ["metadata", "placeholders", "queries"]
    (finding,) = run_lint(tmp_path, checks=[LintCheck.filenames])["findings"]
    assert finding["expected"] == f"objects/threats/{_BRACKETED_STEM}.yaml"
