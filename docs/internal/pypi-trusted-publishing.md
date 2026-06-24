---
title: PyPI trusted publishing
description: OIDC trusted publishing setup for PyPI releases.
---

# PyPI Trusted Publishing Setup (Human Action Required)

Phase 8 CI workflows (`.github/workflows/publish-pypi.yml`, `ci.yml` TestPyPI job) use **OIDC Trusted Publishing** — no API tokens in the repository.

## Org-admin checklist

1. Create PyPI projects: `opentide` (production) and optionally a TestPyPI counterpart.
2. Configure Trusted Publisher on each PyPI project:
   - Owner: `OpenTideHQ`
   - Repository: `opentide`
   - Workflow: `publish-pypi.yml` (releases) / `ci.yml` (TestPyPI on `development`)
   - Environment: `pypi` / `testpypi`
3. Create GitHub Environments `pypi` and `testpypi` in `OpenTideHQ/opentide` with required reviewers if desired.

Until steps 1–3 are complete, publish jobs will fail at the OIDC exchange step. This is expected and does not block merging Phase 8 code.
