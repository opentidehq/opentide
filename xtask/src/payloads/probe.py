"""What the oracle (the frozen Python CLI) would send for every rule.

Run by `cargo xtask payloads diff --against python` with the oracle's
interpreter, isolated (`python -I probe.py REQUEST RESULT`), once per fixture
workspace. REQUEST is JSON: {"repo": DIR, "rules": [{"uuid", "path"}]}, the
rules the Rust index holds. Each is read as the registry reads it
(`load_rule_from_dict`); a rule the data model refuses is reported as
`unloadable`, with why. For every other rule, and every platform block it has
whose body opentide compiles from the rule alone (Sentinel, Elastic), the
probe writes:

- `compile`: the body `compile_offline` gives (the dry run's tenant), as
  compact JSON in the oracle's key order, or the error a dry run reports
  (`compile_diagnostic`: code, message, help);
- `tenants`: the same for each configured tenant of the platform (Sentinel's
  tenant name selects exclusions; Elastic's `setup` adds index, tags and
  suppression);
- `preview`: the dry run's payload entry (`preview_rule_deployment`).

Standard library and the oracle only; no output on stdout is relied on.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from typing import Any

PLATFORMS = ("sentinel", "elastic")
DISPLAY = {"sentinel": "Sentinel", "elastic": "Elastic"}


def compact(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def body_for(platform: str, rule: Any, tenant: Any) -> object:
    """The body of *rule* on *platform*: the dry run's, or *tenant*'s."""
    if tenant is None:
        from opentide.deployment.preview import compile_offline

        return compile_offline(platform, rule)
    if platform == "sentinel":
        from opentide.platforms.sentinel.deployer import SentinelDeploy

        return SentinelDeploy().compile_deployment(service=None, data=rule, tenant=tenant.name)
    from opentide.platforms.elastic.compile import compile_rule

    return compile_rule(rule, tenant)


def outcome(platform: str, rule: Any, tenant: Any = None) -> dict[str, object]:
    from opentide.deployment.preview import compile_diagnostic

    try:
        body = body_for(platform, rule, tenant)
    except Exception as exc:  # every failure is an outcome to compare
        code, message, hint = compile_diagnostic(exc, DISPLAY[platform])
        return {"error": {"code": code, "message": message, "help": hint}}
    return {"body": compact(body)}


def main() -> int:
    request_path, result_path = sys.argv[1], sys.argv[2]
    with open(request_path, encoding="utf-8") as handle:
        request = json.load(handle)
    repo = request["repo"]
    os.chdir(repo)
    os.environ["OPENTIDE_REPO_ROOT"] = repo

    from pathlib import Path

    from opentide.core.environment import defer_missing_envvars
    from opentide.core.io import load_yaml
    from opentide.core.registry import Opentide
    from opentide.deployment.preview import preview_rule_deployment
    from opentide.loading.rule_loader import load_rule_from_dict

    rules: list[dict[str, object]] = []
    unloadable: list[dict[str, str]] = []
    with (
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()),
        defer_missing_envvars(),
    ):
        Opentide.initialise()
        systems = Opentide.Configurations.Systems
        tenants: dict[str, list[Any]] = {}
        for platform, attribute in (("sentinel", "Sentinel"), ("elastic", "Elastic")):
            try:
                tenants[platform] = list(
                    getattr(getattr(systems, attribute), "tenants", None) or []
                )
            except Exception:  # a platform file the oracle refuses has no tenants
                tenants[platform] = []
        for listed in request["rules"]:
            uuid, path = listed["uuid"], Path(listed["path"])
            try:
                rule = load_rule_from_dict(load_yaml(path), file=path)
            except Exception as exc:  # the oracle refuses the rule
                unloadable.append({"uuid": uuid, "error": f"{type(exc).__name__}: {exc}"})
                continue
            if rule.configurations is None:
                continue
            for platform in PLATFORMS:
                if getattr(rule.configurations, platform, None) is None:
                    continue
                entry: dict[str, object] = {
                    "uuid": str(uuid),
                    "file": str(getattr(rule, "file", "") or ""),
                    "platform": platform,
                    "compile": outcome(platform, rule),
                    "preview": compact(preview_rule_deployment(platform, rule)),
                }
                entry["tenants"] = [
                    {"tenant": tenant.name, **outcome(platform, rule, tenant)}
                    for tenant in tenants[platform]
                ]
                rules.append(entry)
    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump({"rules": rules, "unloadable": unloadable}, handle, ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
