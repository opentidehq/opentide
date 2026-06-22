---
description: "Use when picking up, implementing, or reviewing a Project TideKit phase issue (#61–#71). Covers agent pickup protocol, start gates, PR contract, and verification."
applyTo: ""
---

# TideKit Phase Pickup

## When to Use

- Starting work on any TideKit phase ([#61](https://github.com/OpenTideHQ/CoreTide/issues/61)–[#71](https://github.com/OpenTideHQ/CoreTide/issues/71))
- Reviewing a phase PR for contract compliance
- Resuming interrupted phase work

Epic: [#60 Project TideKit](https://github.com/OpenTideHQ/CoreTide/issues/60) · Fleet guide: [`AGENTS.md`](../../AGENTS.md)

> Issues are tracked on **OpenTideHQ/CoreTide** during migration. Implementation may land in CoreTide and/or this `opentide` repo depending on phase — follow the issue's file paths.

---

## Pickup Protocol

### 1. Confirm eligibility

```bash
gh issue view <N> --repo OpenTideHQ/CoreTide --json title,state,labels,milestone
git fetch origin && git checkout development && git pull
```

Check the issue's **Depends on** field. Every upstream phase must be **merged** to `development`. If not, stop and pick a different phase.

### 2. Read the full issue

Every groomed phase contains:

| Section | Purpose |
|---------|---------|
| **Agent Execution Contract** | Branch name, PR title, blast radius, behaviour-change policy |
| **Context Primer** | Verified file paths, line numbers, corrections from grooming |
| **Objective** | What to achieve |
| **Acceptance Criteria** | Checkbox list — your Definition of Done |
| **Verification** | Copy-paste commands to run before opening PR |
| **Guardrails** | What not to touch |

Trust **Context Primer corrections** over stale line numbers elsewhere in the issue.

### 3. Create working branch

Use the branch name from the Agent Execution Contract:

```bash
git checkout development
git pull origin development
git checkout -b refactor/tidekit-phase<N>-<slug>   # or feat/… per issue
```

### 4. Implement

- Tick acceptance criteria as you complete them
- One logical concern per commit; conventional commit messages
- **No scope creep** — if you find unrelated bugs, note them in the PR or file a separate issue
- Phase 4 (#65) may land as stacked sub-PRs — each must keep pipelines green

### 5. Verify

Run the issue's **Verification** block plus any commands in [`AGENTS.md`](../../AGENTS.md) for that phase. All must pass.

### 6. Open PR

| Field | Value |
|-------|-------|
| **Base** | `development` |
| **Title** | From Agent Execution Contract (conventional commit form) |
| **Body** | Summary · Changes · Backwards Compatibility · Testing · `Closes #<N>` |

Use draft PRs only for early visibility. Convert to ready when all criteria are met.

### 7. Stop

Do **not** continue to the next phase in the same branch or PR.

---

## Parallel Phases (6 & 7)

After Phase 5 (#66) merges, Phase 6 (#67 CLI) and Phase 7 (#68 MCP) may run concurrently:

| Phase | Package | Coordination |
|-------|---------|--------------|
| #67 | `src/opentide/cli/` | Touch shared `core/` only with care |
| #68 | `src/opentide/mcp_server/` | Independent of CLI |

Phase 8 (#69) requires **both** #67 and #68 merged.

---

## Phase Quick Reference

| Phase | Issue | Branch (canonical) | Behaviour change? |
|-------|-------|-------------------|-------------------|
| 0 | #61 | `refactor/tidekit-phase0-remove-cdm-bdr-lookups` | Removal + bug fix only |
| 1 | #62 | `refactor/tidekit-phase1-decompose-monoliths` | None (cut/paste) |
| 2 | #63 | `refactor/tidekit-phase2-naming-architecture` | None (rename + façade) |
| 3 | #64 | `refactor/tidekit-phase3-vocabulary-rebuild` | Bug fixes change schema output |
| 4 | #65 | `feat/tidekit-phase4-pydantic-migration` | Internal; outputs byte-equivalent |
| 5 | #66 | `feat/tidekit-phase5-package-structure` | Layout/packaging only |
| 6 | #67 | `feat/tidekit-phase6-cli` | Additive |
| 7 | #68 | `feat/tidekit-phase7-mcp-server` | Additive |
| 8 | #69 | `feat/tidekit-phase8-pypi-distribution` | Release tooling |
| 9 | #71 | `feat/tidekit-phase9-tests-and-docs` | Additive (tests/docs) |

[#70](https://github.com/OpenTideHQ/CoreTide/issues/70) is closed — use #65 for Phase 4.

---

## Definition of Ready / Done

**Ready** (before starting):
- [ ] All Depends-on phases merged
- [ ] `development` checked out and current
- [ ] Issue read in full; Context Primer understood
- [ ] Branch created from contract

**Done** (before marking PR ready):
- [ ] Every acceptance criterion checked
- [ ] Verification commands pass
- [ ] No secrets in diff
- [ ] PR targets `development` with `Closes #<N>`
- [ ] British English in new comments/docs

---

## Capability Reminder

Seven deployers, five query validators. When implementing CLI (#67), MCP (#68), or platform registration (#65–#66):

```python
# CrowdStrike and HarfangLab — deploy only
assert platform.can_validate is False
assert platform.validator is None
```

Return `supported: False` for query validation on these platforms — never raise or fake a result.
