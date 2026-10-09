"""Shared OpenTide CLI steps used across CI platform renderers."""

from __future__ import annotations

import re
from pathlib import Path

from opentide.ci.discovery import platforms_config_dir
from opentide.ci.models import CiRenderOptions
from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS

_ENV_REF = re.compile(r"\$([A-Z][A-Z0-9_]*)")
_PLATFORMS_DIR = Path(__file__).resolve().parents[1] / "data" / "configurations" / "platforms"


def pip_install(options: CiRenderOptions) -> str:
    return f'pip install "opentide=={options.opentide_version}"'


def query_platforms(options: CiRenderOptions) -> list[str]:
    return [p for p in options.platforms if p in QUERY_VALIDATION_PLATFORMS]


def platform_credential_names() -> list[str]:
    """Environment variables referenced by bundled platform configuration.

    Setup writes those references commented out. CI still has to provide them
    once a tenant block is uncommented. ``OPENTIDE_SECRETS`` is not one of them.
    """
    names: set[str] = set()
    for path in sorted(_PLATFORMS_DIR.glob("*.toml")):
        names.update(_ENV_REF.findall(path.read_text(encoding="utf-8")))
    return sorted(names)


def platform_credential_names_for(platform: str) -> list[str]:
    """Environment variables referenced by one bundled platform file."""
    path = _PLATFORMS_DIR / f"{platform}.toml"
    if not path.is_file():
        return []
    return sorted(set(_ENV_REF.findall(path.read_text(encoding="utf-8"))))


def _toml_without_comments(text: str) -> str:
    """Drop TOML comments so a remark cannot invent a credential reference."""
    out: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        char = text[i]
        if char in "\"'":
            quote = char
            if text.startswith(quote * 3, i):
                end = text.find(quote * 3, i + 3)
                if end == -1:
                    out.append(text[i:])
                    break
                out.append(text[i : end + 3])
                i = end + 3
                continue
            end = i + 1
            while end < length:
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == quote:
                    end += 1
                    break
                end += 1
            out.append(text[i:end])
            i = end
            continue
        if char == "#":
            while i < length and text[i] != "\n":
                i += 1
            continue
        out.append(char)
        i += 1
    return "".join(out)


def workspace_credential_names(repo: Path, platform: str) -> list[str]:
    """``$VAR`` names in the enabled platform file, ignoring comments and literals."""
    path = platforms_config_dir(repo) / f"{platform}.toml"
    if not path.is_file():
        return []
    text = _toml_without_comments(path.read_text(encoding="utf-8"))
    return sorted(set(_ENV_REF.findall(text)))


def query_validation_command(platform: str, *, repo: Path | None = None) -> str:
    """Tenant query check.

    The guard lists ``$VAR`` references in the workspace platform file. A
    literal value is not a credential, and a comment is not a reference. No
    references means the live check runs with no guard. A skip exits 2 so it
    cannot be read as a check that ran.
    """
    live = f"opentide validate query --platform {platform} --live"
    names = workspace_credential_names(repo, platform) if repo is not None else []
    if not names:
        return live
    clauses = " || ".join(f'[ -z "${name}" ]' for name in names)
    listed = " ".join(names)
    skip = f"echo skip {platform} live query validation {listed}; exit 2"
    return f"if {clauses}; then {skip}; else {live}; fi"


def object_validate_commands() -> list[str]:
    """The catalogue gate. Warnings fail, and a misnamed file fails too."""
    return ["opentide validate --strict", "opentide lint --strict"]


def validate_commands(options: CiRenderOptions) -> list[str]:
    steps = object_validate_commands()
    for platform in query_platforms(options):
        steps.append(query_validation_command(platform, repo=options.repo))
    return steps


def core_cli_steps(options: CiRenderOptions) -> list[str]:
    """Validate and generate commands run after pip install."""
    return [*validate_commands(options), "opentide generate"]


def _deploy_steps(plan: str) -> list[str]:
    return [
        f"opentide deploy --dry-run --plan {plan}",
        f"opentide deploy --plan {plan} --skip-unconfigured",
    ]


def staging_deploy_steps(options: CiRenderOptions) -> list[str]:
    if not options.staging:
        return []
    return _deploy_steps("STAGING")


def production_deploy_steps(options: CiRenderOptions) -> list[str]:
    return _deploy_steps("PRODUCTION")


def github_deploy_env() -> str:
    """Map each platform credential into the GitHub Actions secret store."""
    lines = ["env:"]
    for name in platform_credential_names():
        lines.append(f"  {name}: ${{{{ secrets.{name} }}}}")
    return "\n".join(lines)


def document_steps(options: CiRenderOptions) -> list[str]:
    if not options.docs_enabled:
        return []
    return [f"opentide generate docs --output {options.docs_output}"]


def inflight_generate_steps(options: CiRenderOptions | None = None) -> list[str]:
    """Write per-UUID preview shards for objects changed in the current PR/MR."""
    _ = options
    return ["opentide generate inflight"]


def inflight_prune_steps(options: CiRenderOptions | None = None) -> list[str]:
    """Drop inflight shards superseded after merge to the default branch."""
    _ = options
    return ["opentide generate inflight prune"]


def header_comment(options: CiRenderOptions) -> str:
    lines = [
        f"# Generated by OpenTide — regenerate with `opentide setup ci {options.ci}`",
        "# Platform credentials are read from the environment. Set these in the CI secret store:",
    ]
    lines.extend(f"#   {name}" for name in platform_credential_names())
    return "\n".join(lines) + "\n"
