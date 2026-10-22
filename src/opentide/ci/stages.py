"""Shared opentide CLI steps used across CI platform renderers."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from opentide.ci.discovery import platforms_config_dir
from opentide.ci.models import CiRenderOptions
from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS

_ENV_REF = re.compile(r"\$([A-Z][A-Z0-9_]*)")
_PLATFORMS_DIR = Path(__file__).resolve().parents[1] / "data" / "configurations" / "platforms"
# Tenant URLs and ``$VAR`` references live anywhere under this directory
# (``platforms/``, legacy ``systems/``, and a root ``platforms.toml``).
_WORKSPACE_CONFIG_DIR = ".opentide/configurations"


def pip_install(options: CiRenderOptions) -> str:
    return f'pip install "opentide=={options.opentide_version}"'


#: Printed when the default branch has no configuration to restore.
NO_REVIEWED_CONFIG_NOTE = (
    "The default branch has no .opentide/configurations yet, so no tenant is reviewed."
    " Skipped without using platform credentials."
)

#: Printed for a platform whose file on the default branch declares no tenant.
NO_REVIEWED_TENANT_NOTE = (
    "The default branch has no {platform} tenant yet, so no tenant is reviewed."
    " Skipped {platform} live query validation without using platform credentials."
)


def trusted_platform_config_commands(branch: str) -> list[str]:
    """Replace workspace configuration with the default branch's copy.

    ``branch`` is a shell word naming the default branch: a name passed
    through :func:`shlex.quote`, or a quoted CI variable such as
    ``"$CI_DEFAULT_BRANCH"``.

    Pull-request jobs check out the pull request. A tenant ``url`` in that
    tree, or a ``$VAR`` reference pointed at any credential the job exported,
    is where the next live validation or staging deploy sends the secret.
    Deleting the directory first drops files that exist only on the pull
    request. ``git checkout`` then writes the reviewed tree.

    The fetch is shallow only when the checkout already is. ``--depth`` on a
    full clone makes it shallow, and the staging deploy can then no longer
    find the pull request's merge base.

    When the default branch has no configuration yet (the pull request that
    adds it), the commands print :data:`NO_REVIEWED_CONFIG_NOTE` and
    ``exit 0``. They must therefore share one shell with the commands they
    guard, so that the exit skips those too.
    """
    path = shlex.quote(_WORKSPACE_CONFIG_DIR)
    reviewed = f"FETCH_HEAD:{_WORKSPACE_CONFIG_DIR}"
    return [
        f"rm -rf -- {path}",
        'if [ "$(git rev-parse --is-shallow-repository)" = true ]; '
        f"then git fetch --depth=1 origin {branch}; else git fetch origin {branch}; fi",
        f"if ! git cat-file -e {shlex.quote(reviewed)} 2>/dev/null; "
        f'then echo "{NO_REVIEWED_CONFIG_NOTE}"; exit 0; fi',
        f"git checkout FETCH_HEAD -- {path}",
    ]


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
    """Tenant query check of the rule files this run changed.

    ``--changed`` reads the pull or merge request's diff, or the push's, as the
    deploy job of the same run does; without it every rule in the catalogue was
    sent on every run. No ``--strategy``: each changed rule is checked on the
    tenants that accept the strategy its status maps to, the tenants a deploy
    sends it to. A changed ``INERT``, ``DISABLEMENT`` or ``DELETION`` rule
    sends no query.

    The guard lists ``$VAR`` references in the workspace platform file. A
    literal value is not a credential, and a comment is not a reference. No
    references means the live check runs with no guard. A skip exits 2 so it
    cannot be read as a check that ran.
    """
    live = f"opentide validate query --platform {platform} --live --changed"
    names = workspace_credential_names(repo, platform) if repo is not None else []
    if not names:
        return live
    clauses = " || ".join(f'[ -z "${name}" ]' for name in names)
    listed = " ".join(names)
    skip = f"echo skip {platform} live query validation {listed}; exit 2"
    return f"if {clauses}; then {skip}; else {live}; fi"


def reviewed_query_validation_command(platform: str, *, repo: Path | None = None) -> str:
    """:func:`query_validation_command` for a tenant the default branch has.

    Runs after :func:`trusted_platform_config_commands`. A platform's first
    tenant reaches the default branch through a pull request, and that pull
    request's check reads the default branch's file, where ``[[tenants]]`` is
    still commented out as setup writes it. The live check would fail there
    and tell the author to add the tenant they just added, so the step prints
    :data:`NO_REVIEWED_TENANT_NOTE` and exits 0 instead, as
    ``deploy --skip-unconfigured`` does.

    Any uncommented line that mentions ``tenants`` runs the check, which then
    fails as before if it declares no tenant. Only a file with no such line,
    or no file, is skipped.
    """
    config = shlex.quote(f"{_WORKSPACE_CONFIG_DIR}/platforms/{platform}.toml")
    note = NO_REVIEWED_TENANT_NOTE.format(platform=platform)
    check = query_validation_command(platform, repo=repo)
    return f"if grep -qs '^[^#]*tenants' {config}; then {check}; else echo \"{note}\"; fi"


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


def _deploy_steps(strategy: str) -> list[str]:
    return [
        f"opentide deploy --dry-run --strategy {strategy}",
        f"opentide deploy --strategy {strategy} --skip-unconfigured",
    ]


def staging_deploy_steps(options: CiRenderOptions) -> list[str]:
    """The pull or merge request job deploys the rules whose status maps to PREVIEW."""
    if not options.staging:
        return []
    return _deploy_steps("PREVIEW")


def production_deploy_steps(options: CiRenderOptions) -> list[str]:
    """The default-branch job deploys RELEASE rules and retires DISABLEMENT and DELETION ones."""
    return _deploy_steps("RELEASE")


#: The share job's command. Every provider runs it after the production job,
#: on a checkout of the default branch's tip, so ``--changed`` covers the
#: push and the promotion write-back the production job committed (#590).
SHARE_COMMAND = "opentide share push --changed"


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
        f"# Generated by opentide — regenerate with `opentide setup ci {options.ci}`",
        "# Platform credentials are read from the environment. Set these in the CI secret store:",
    ]
    lines.extend(f"#   {name}" for name in platform_credential_names())
    return "\n".join(lines) + "\n"
