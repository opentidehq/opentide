---
description: "Mandatory backlog sync between opentide PRs and OpenTideHQ/CoreTide TideKit issues (#60–#71)."
applyTo: ""
---

# TideKit Backlog Sync

Planning and acceptance criteria live on **OpenTideHQ/CoreTide**. Implementation PRs land in **OpenTideHQ/opentide**. Agents must keep both in sync.

Epic: [#60 Project TideKit](https://github.com/OpenTideHQ/CoreTide/issues/60)

---

## 1. Before starting work

```bash
gh issue view <N> --repo OpenTideHQ/CoreTide --json title,body,labels
gh issue list --repo OpenTideHQ/CoreTide --label tidekit --state open
gh pr list --repo OpenTideHQ/opentide --state open
```

Confirm no duplicate PR exists for your phase. If one is open, coordinate or take it over — do not open a second PR for the same phase.

---

## 2. When opening a PR

```bash
gh pr create --repo OpenTideHQ/opentide \
  --base development \
  --head "<your-branch>" \
  --title "refactor: Phase <N> — <short title>" \
  --body "$(cat <<'EOF'
## Summary
<what changed>

## Test plan
- [ ] verification commands from CoreTide issue

Closes OpenTideHQ/CoreTide#<phase-issue>
EOF
)"
```

Then comment on the phase issue:

```bash
gh issue comment <phase-issue> --repo OpenTideHQ/CoreTide --body "$(cat <<'EOF'
## Status: PR open

**PR**: https://github.com/OpenTideHQ/opentide/pull/<N>
**Branch**: `<type>/tidekit-phase<N>-<slug>`

### Acceptance criteria progress
- [x] item done
- [ ] item remaining

### Verification
```
<paste command output summary>
```

### Gaps / blockers
- <none or list>
EOF
)"
```

---

## 3. During work (significant pushes)

Add a short progress comment when checklist items flip or CI status changes:

```bash
gh issue comment <phase-issue> --repo OpenTideHQ/CoreTide --body "**Progress**: CI green; IndentFullDumper consolidated. Remaining: rename MyDumper."
```

---

## 4. After merge to `development`

```bash
# Comment on phase issue
gh issue comment <phase-issue> --repo OpenTideHQ/CoreTide --body "$(cat <<'EOF'
## Status: Merged

**PR**: https://github.com/OpenTideHQ/opentide/pull/<N> (merged <YYYY-MM-DD>)
All acceptance criteria met on `development`.
EOF
)"

# Close only when truly done (optional — epic tracks overall programme)
gh issue close <phase-issue> --repo OpenTideHQ/CoreTide --comment "Merged via opentide PR #<N>."
```

Refresh epic #60 orchestration snapshot:

```bash
gh issue comment 60 --repo OpenTideHQ/CoreTide --body "$(cat <<'EOF'
## TideKit orchestration snapshot — <YYYY-MM-DD>

**Repo**: https://github.com/OpenTideHQ/opentide

### PRs
| # | Title | State | Notes |
|---|-------|-------|-------|
| 1 | chore: import CoreTide development baseline | Merged | |
| … | | | |

### Phase matrix (0–9)
| Phase | Issue | Status |
|-------|-------|--------|
| 0 | #61 | Merged |
| 1 | #62 | Not started |
| … | | |

### Human blockers
- PyPI trusted publishing: GitHub `pypi` environment + PyPI trusted publisher for `OpenTideHQ/opentide`

### Next actions
1. …
EOF
)"
```

---

## 5. Status comment template (phases not yet started)

For phases #62–#71 with no work yet:

```bash
gh issue comment <phase-issue> --repo OpenTideHQ/CoreTide --body "**Status**: Not started — blocked until upstream phase merged to opentide \`development\`."
```

Valid status strings: `Not started` · `In progress` · `PR open` · `Merged`

---

## 6. Labels

- Keep `tidekit` on all programme issues.
- Keep `agent-ready` on groomed, pickup-ready phases.
- Do not strip labels when syncing status.

---

## 7. Edit issue body (optional)

To tick acceptance criteria in the issue body itself:

```bash
gh issue edit <phase-issue> --repo OpenTideHQ/CoreTide --body-file /path/to/updated-body.md
```

Prefer comments for frequent updates; edit body only when closing out a phase.
