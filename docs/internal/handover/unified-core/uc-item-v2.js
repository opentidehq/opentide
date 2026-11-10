export const meta = {
  name: 'uc-item',
  description: 'One Unified Core item: implement (or continue), verify with two lenses, skeptic, fix, recheck. Ecosystem crates only, no Python ports.',
  phases: [
    { title: 'Implement' }, { title: 'Verify' }, { title: 'Skeptic' }, { title: 'Fix' }, { title: 'Recheck' },
  ],
}

const BRIEF = '/tmp/claude-0/-home-user/e9836ff1-e7fa-5638-b4f5-86e718ee9fb8/scratchpad/wave/phase1-brief.md'
const COMMON = 'Read ' + BRIEF + ' first and follow it exactly. Its first section, "The engineering principle", comes from the user and overrides everything else, including the issue text: never port a Python library to Rust; use well-known, high-performance Rust crates and adapt the rest; preserve the previous CLI behaviour in general, but details may change; record intended output differences in APPROVED_DIFFS.toml.'
const it = args

const PR_SCHEMA = { type: 'object', properties: { pr: { type: 'integer' }, branch: { type: 'string' }, head: { type: 'string' }, ci_green: { type: 'boolean' }, worktree: { type: 'string' }, summary: { type: 'string' }, open_questions: { type: 'array', items: { type: 'string' } } }, required: ['pr', 'branch', 'head', 'ci_green', 'summary'] }
const FINDINGS = { type: 'object', properties: { findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['major', 'minor', 'nit'] }, summary: { type: 'string' }, evidence: { type: 'string' }, fix: { type: 'string' } }, required: ['id', 'severity', 'summary', 'evidence', 'fix'] } } }, required: ['findings'] }
const VERDICT = { type: 'object', properties: { confirmed: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string' }, summary: { type: 'string' }, evidence: { type: 'string' }, fix: { type: 'string' } }, required: ['id', 'severity', 'summary', 'fix'] } }, refuted: { type: 'array', items: { type: 'string' } } }, required: ['confirmed', 'refuted'] }
const FIXED = { type: 'object', properties: { head: { type: 'string' }, ci_green: { type: 'boolean' }, outcomes: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, outcome: { type: 'string' } }, required: ['id', 'outcome'] } } }, required: ['head', 'ci_green', 'outcomes'] }
const READY = { type: 'object', properties: { ready: { type: 'boolean' }, head: { type: 'string' }, ci_green: { type: 'boolean' }, unresolved: { type: 'array', items: { type: 'string' } }, notes: { type: 'string' } }, required: ['ready', 'head', 'ci_green', 'unresolved', 'notes'] }

const tag = it.id.replace('UC-', '')
let pr = it.pr ? { pr: it.pr, branch: it.branch, head: it.head || '', ci_green: true, worktree: '/home/user/wt/' + it.name, summary: 'existing PR' } : null

if (!pr) {
  phase('Implement')
  pr = await agent(COMMON + '\n\nYou implement ' + it.id + ' (issue #' + it.issue + ') of epic #790. Read the issue and all its comments in full; its Scope, Acceptance criteria and Verification are the contract, as amended by the engineering principle.\n' + (it.resume || '') + '\n' + it.scope +
    '\n\nSetup:\n- worktree /home/user/wt/' + it.name + ' on branch ' + it.branch + ' from origin/integration/unified-core. If the worktree or branch already exists, continue there: inspect git status and the log first, keep earlier work that is right, and never force-push.\n- target pool /home/user/wt/.target/' + it.name + '.\n\nIn the PR body, add "## Crates chosen", with each crate, its version and why it was chosen (maturity, performance, licence; cargo deny must pass). Add "## Intended behaviour changes", listing every approved diff with its reason.\nOpen the PR as a draft early (or reuse the existing one). Drive it to complete, with every acceptance criterion evidenced, or marked "Needs a maintainer" or "superseded by the engineering principle", with exact reasons. Get CI green (make sure the runs exist), then mark it ready.\nSelf-review against the review-checklist first. Keep the worktree and pool. Return the PR fields.',
    { label: it.id + ':implement', phase: 'Implement', schema: PR_SCHEMA })
  if (!pr) return { id: it.id, error: 'implement failed' }
}

phase('Verify')
const ctx = 'PR #' + pr.pr + ' (' + it.id + ', issue #' + it.issue + ') in opentidehq/opentide, branch ' + pr.branch + ', base integration/unified-core. Fetch the branch head yourself.'
const lenses = await parallel([
  () => agent(COMMON + '\n\nYou are an independent verifier; you did not write this code. ' + ctx +
    '\nLens: ACCEPTANCE + INVARIANTS + PRINCIPLE.\n- Check every acceptance criterion and scope bullet, as amended by the principle. Re-run the verification commands in a detached worktree /home/user/wt/' + it.name + '-va. Use your own pool /home/user/wt/.target/' + it.name + '-va and delete it afterwards. Check df first; stop if under 4 GB.\n- Check that no Python library was ported, and that no hand-written code replaces what a well-known crate does.\n- Check that section 3 contract outputs still match the oracle: exit codes, failure codes, the envelope, the commands listing, diagnostic codes, workspace formats. Every other output difference must be in APPROVED_DIFFS.toml (reason, issue, changelog) and listed in the PR.\n- Check the security rules, cargo deny and layering.\nReport only real, evidenced defects. Remove your worktree. Return findings with ids V' + tag + '-A-n.',
    { label: it.id + ':verify-acceptance', phase: 'Verify', schema: FINDINGS }),
  () => agent(COMMON + '\n\nYou are an independent verifier; you did not write this code. ' + ctx +
    '\nLens: TEST STRENGTH + CORRECTNESS.\n- Mutate the key decisions one at a time and see whether a test fails. Use a detached worktree /home/user/wt/' + it.name + '-vs with your own pool /home/user/wt/.target/' + it.name + '-vs (delete it afterwards; check df first; stop if under 4 GB). Revert every mutation.\n- Look for panics on hostile input (fuzz briefly if a target exists), unicode column bugs and swallowed errors.\nReport each surviving mutation or defect with evidence. Remove your worktree. Return findings with ids V' + tag + '-S-n.',
    { label: it.id + ':verify-strength', phase: 'Verify', schema: FINDINGS }),
])
const findings = lenses.filter(Boolean).flatMap(l => l.findings || [])

let confirmed = []
if (findings.length) {
  const v = await agent(COMMON + '\n\nYou are a skeptic. For PR #' + pr.pr + ' (' + it.id + ', branch ' + pr.branch + '), try to REFUTE each finding by reading the code and reproducing it. Keep only real ones, merge duplicates and correct the severity. Drop any finding that only asks to reproduce Python behaviour for its own sake. A missing approved-diff record for an intended change IS a defect.\nFindings:\n' + JSON.stringify(findings, null, 1),
    { label: it.id + ':skeptic', phase: 'Skeptic', schema: VERDICT })
  confirmed = (v && v.confirmed) || []
}

let outcomes = []
if (confirmed.length) {
  const fx = await agent(COMMON + (it.fixResume ? '\n\n' + it.fixResume : '') + '\n\nFix the confirmed verification findings on PR #' + pr.pr + ' (' + it.id + ', branch ' + pr.branch + '). Use worktree /home/user/wt/' + it.name + ' (create it from the branch if missing) and pool /home/user/wt/.target/' + it.name + '; touch the files first.\n- Each fix gets a regression test that fails without it.\n- Record each id and its outcome in the PR body\'s Review table.\n- Merge origin/integration/unified-core in before the final push (no rebase).\n- Push and get CI green (make sure the runs exist).\nFindings:\n' + JSON.stringify(confirmed, null, 1),
    { label: it.id + ':fix', phase: 'Fix', schema: FIXED })
  outcomes = (fx && fx.outcomes) || []
}

const rc = await agent(COMMON + '\n\nFinal recheck of PR #' + pr.pr + ' (' + it.id + ', branch ' + pr.branch + ').\nConfirmed findings: ' + JSON.stringify(confirmed) + '\nOutcomes: ' + JSON.stringify(outcomes) +
  '\n1. Verify each fix (reproduction or mutation) in a detached worktree /home/user/wt/' + it.name + '-rc, with pool /home/user/wt/.target/' + it.name + ' (touch the files first).\n2. Check the head contains origin/integration/unified-core. If not, merge it in (no rebase), push, and wait for CI.\n3. Check CI is green on the head (the runs must exist; dispatch them if missing).\n4. Check the PR is marked ready, and its "Intended behaviour changes" and "Crates chosen" sections are current.\n5. Do NOT merge.\n6. Clean up /home/user/wt/' + it.name + '* and the pools /home/user/wt/.target/' + it.name + '*.\nReturn READY.',
  { label: it.id + ':recheck', phase: 'Recheck', schema: READY })
return { id: it.id, issue: it.issue, pr: pr.pr, branch: pr.branch, findings: findings.length, confirmed: confirmed.length, recheck: rc }
