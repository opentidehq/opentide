# Unified Core, Phase 1 wave A: common brief

You work on epic opentidehq/opentide#790, "One Rust core for opentide" (Unified Core), in the repository opentidehq/opentide. Correctness beats speed: a wrong port that passes review is the worst outcome.

## Where the code is
- All epic work lands on the branch **`integration/unified-core`**, not on `development`. Phase 0 is merged there: the Cargo workspace, xtask, goldens (`tests/golden`, 1188 recorded cases of the frozen Python CLI), the comparator and the approved-diffs ledger (`tests/golden/APPROVED_DIFFS.toml`), corpora and the fault catalogue (`tests/corpora`), benchmarks, coverage gates, cargo-deny and the opentide-schema skeleton (ADR 0001).
- The plan is `docs/internal/unified-core.md`, now on `development` and on integration. Its decisions are D-1..D-8, its invariants §3, its correctness strategy §5, and its work plan §6. The ADRs are `docs/internal/adr/0001..0008`.
- Read first:
  - the root `AGENTS.md`;
  - `crates/AGENTS.md`, `xtask/AGENTS.md`, `.github/AGENTS.md`;
  - the skills that match your work: `rust`, `rust-engine`, `golden`, `review-checklist`, `catalogs`, `tree-sitter` and any others that apply;
  - your item's GitHub issue, including its comments: some comments add acceptance items. Use `mcp__github__issue_read` (load it via ToolSearch).
- The local clone is /home/user/opentide (remote `origin`). Work in your own git worktree under /home/user/wt/<name> from `origin/integration/unified-core`. Never use the main clone's working tree.

## The engineering principle (from the user; overrides everything below)
- **Never port a Python library to Rust.** Use a well-known, high-performance crate from the Rust ecosystem for the job and adapt the code around it. For example:
  - strsim, or what clap uses, for string similarity and suggestions;
  - saphyr or another established YAML crate for YAML;
  - toml_edit for TOML;
  - serde, schemars, garde, clap, tracing.
- **Correctness first, never Python-compatibility for its own sake.** The oracle tells us what opentide does today; it does not oblige us to reproduce Python or library quirks. Where the Rust crate's correct behaviour differs from the oracle, keep the Rust behaviour. Record the difference in `tests/golden/APPROVED_DIFFS.toml` (reason, issue, CHANGELOG bold lead) and list it in the PR under "## Intended behaviour changes". Examples: different "did you mean" suggestions, YAML 1.2 instead of PyYAML's YAML 1.1 quirks.
- **The user's clarification:** preserve the previous CLI's behaviour in general, but details may change: this is not a 1:1 match requirement. YAML follows the Rust crate's YAML 1.2 semantics. Booleans are only `true` and `false`; `yes`, `no`, `on` and `off` are plain strings, and are therefore errors where a boolean is expected. That is accepted, so do not flag it. Record it once as an approved diff, with a CHANGELOG entry, and move on. The same applies to the other YAML 1.1 quirks.
- Only a change to a plan §3 invariant (a contract other programs rely on: exit codes, failure codes, the JSON envelope, diagnostic codes, workspace file formats, `opentide --json commands`) still needs the stop-and-report path. List it under "## Needs a maintainer" with the evidence, and keep going on everything else.

## Non-negotiable rules
- The frozen Python CLI (`tests/golden/ORACLE`, opentide 0.23.0) is the oracle. Recordings are generated, never hand-edited.
- Never weaken, skip, xfail or delete a test to get green. Never loosen a gate, a lint or a coverage threshold, and never add an exclude list.
- An intended behaviour change goes in `tests/golden/APPROVED_DIFFS.toml`, with a reason, an issue and a changelog entry. Anything else that differs is a bug.
- Do not change a plan §3 invariant (CLI contract, exit codes, failure codes, `opentide --json commands`, diagnostic codes, cross-repo contracts, MCP, workspace formats, SDK import paths, platforms, security). If an item seems to need that, stop that part and report it with the evidence.
- Secrets never appear in code, logs, recordings, fixtures or PR text.
- Never merge any PR unless your instructions explicitly say so. Never push to `integration/unified-core`, `development` or another item's branch. No force-push. No model identifiers in commits, PRs or code.
- Use the GitHub MCP tools; the gh CLI is allowed only for `gh api` search.

## Disk and build hygiene (the disk is shared and small: about 20 GB free)
- Use your own Cargo target pool, exactly the one your instructions name: `CARGO_TARGET_DIR=/home/user/wt/.target/<pool>`.
- Also set `CARGO_INCREMENTAL=0` and `CARGO_PROFILE_DEV_DEBUG=line-tables-only`.
- When a pool passes from another agent to you, run `git ls-files -z | xargs -0 touch -c` in your worktree first.
- pytest always gets `--basetemp=/home/user/wt/<name>-pt`; delete it after each run. Never touch other agents' directories.
- Check `df -h /` before big builds. If under 4 GB, stop and report rather than fill the disk.

## Process
1. Implement completely, with tests at the level each feature is used. Each fix gets a regression test that fails without it. Compare against the oracle wherever the issue says so.
2. Before pushing, run:
   - the item's own verification commands;
   - `cargo fmt --all --check`;
   - `cargo clippy --workspace --all-targets -- -D warnings` (the pinned toolchain);
   - `cargo nextest run --workspace` (or `-p` for the crates you touch plus their dependents);
   - `cargo xtask check-layers`;
   - for Python changes, the affected pytest areas.
   `scripts/ci-local.sh --full` is best; its GitLab-lint download is refused here.
3. **Commits.** Use Conventional Commits with a scope. End each message with exactly:

   ```
   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
   Claude-Session: https://claude.ai/code/session_01KgFkhfkQUHnNBCGz3hcLif
   ```

4. **The PR.**
   - Base: `integration/unified-core`. Title: `[UC-x.y] <conventional summary>`.
   - Body: the headings of `.github/pull_request_template.md`, plus "Closes #<issue>" (or "Refs #<issue>" when a criterion needs a maintainer). Then "## Acceptance criteria", each ticked only with its command, SHA and output excerpt. Then "## Review", "## Needs a maintainer" and "## Questions".
   - End the body with exactly:

     ```
     🤖 Generated with [Claude Code](https://claude.com/claude-code)

     https://claude.ai/code/session_01KgFkhfkQUHnNBCGz3hcLif
     ```

5. **CI.** Make sure a CI run actually exists for your head: GitHub sometimes drops push events. Check with `mcp__github__actions_list` list_workflow_runs on your branch. If none appears, dispatch `ci.yml` (and `golden.yml` if your change touches its paths) with `actions_run_trigger` run_workflow on your branch. Drive CI to green: read the failed logs, reproduce, fix at the root. A runner tool download failing with HTTP 5xx may be re-run once.
6. **Cleanup.** Keep the item's pool between its stages; the stages run one after another and reuse it. Remove any extra worktree you made, but not the item's main worktree. The final stage of each item deletes the pool and the worktrees.
