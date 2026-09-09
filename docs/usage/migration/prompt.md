---
title: CoreTide migration prompt
description: Copy-paste LLM prompt for migrating legacy CoreTide submodule repositories to opentide.
---

# CoreTide migration prompt

OpenTide no longer ships `opentide migrate`. For the few repositories still on CoreTide git submodules, paste the prompt below into your agent (Cursor, Claude Code, Copilot, and so on) and review every diff.

See also the [migration guide](./index.md) for background and verification steps.

## Prompt

```text
You are migrating a detection-as-code repository from CoreTide (git submodule) to the opentide PyPI package.

Goals:
1. Remove the CoreTide submodule and all sys.path hacks.
2. Replace legacy Python imports and Orchestration scripts with opentide CLI/SDK.
3. Regenerate CI and agent tooling using opentide setup subcommands.
4. Leave detection YAML content unchanged unless a mechanical path/import fix is required.

Steps:
1. Dependencies
   - Remove CoreTide submodule: git submodule deinit, git rm CoreTide, clean .git/modules.
   - Add pyproject/requirements: `opentide>=0.1` (one package — enable platforms with `opentide setup platforms`, not pip extras).
   - Set OPENTIDE_REPO_ROOT to the detection content root in CI and local dev.

2. Replace imports
   - Engines.modules.tide.DataTide / IndexTide → from opentide import OpenTide; OpenTide.initialise()
   - TideModels / MDR types → opentide.models (DetectionRule, etc.)
   - DeployTide → OpenTide.Platforms or opentide deploy CLI
   - Remove: import sys, git; sys.path.append(...)

3. Replace Orchestration scripts
   - Orchestration/validate.py → opentide validate [--strict]
   - Orchestration/generate.py → opentide generate
   - Orchestration/document.py → opentide generate docs [--output docs] [--flavor github]
   - Orchestration/deploy.py → opentide deploy
   - Query validation: opentide validate query --platform <sentinel|defender_for_endpoint|splunk|sentinel_one|carbon_black_cloud>

4. Repository layout
   - Ensure .opentide/configurations/platforms/*.toml exist (opentide setup platforms --sentinel …).
   - Content under objects/ (lowercase) with metadata.uuid on each object.

5. CI/CD
   - Remove submodules: recursive checkout.
   - Regenerate pipeline: opentide setup ci github (or gitlab/azure).
   - Typical job order: pip install 'opentide==0.1.0' → opentide validate → validate query per enabled platform → opentide generate → opentide generate docs --output docs → deploy stages.
   - Do not reference opentide mutate, opentide migrate, or top-level opentide document/export/extract (use generate docs/exports/extract).

6. Agents and IDE
   - opentide setup mcp --cursor --vscode (as needed)
   - opentide setup skills discover then opentide setup skills --yes --install <slugs>
   - Remove references to vendored detection-ops skill packs.

7. Verification checklist
   - pip install 'opentide==0.1.0' succeeds
   - opentide validate --strict passes
   - opentide generate completes
   - CI YAML contains no CoreTide checkout or python Orchestration/*.py
   - No remaining CoreTide imports or sys.path manipulation

Output: a concise migration plan, file-by-file diffs, and commands to run locally before opening a PR.
```

## Related

- [Migration guide](./index.md)
- [Repository setup](../repository-setup.md)
- [CLI setup](../../cli/setup.md)
