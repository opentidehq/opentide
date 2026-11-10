Dashboard: https://claude.ai/artifact/AVp4whTgBTQiVWgNiHSoV3 (Dashboard type; content in its store)
Update the dashboard at EVERY state change (wave start, PR open, verification result, merge, decision) - the user asked for this explicitly.
Datasets (attached JSON files): items, epic, prs, history, decisions, events. Page: files/index.html (one-writer page).
Update procedure:
 1. cd /home/user/dash; ./upd.py item <ID> stage=... (items use the field "stage", not "status")...; ./upd.py pr '#N' k=v...; ./upd.py decision <ID> status=Done|new ...; ./upd.py event "..."; ./upd.py snapshot (every check-in).
 2. Artifact publish url=<dash> asset=true file_path=<changed json> (one call per JSON) -> /_blob/<id>
 3. ArtifactData get datasets/<id> for version; batch update {source.url, updated{at,by}, edit{via,at}} with if_version.
Session list: /tmp/claude-0/-home-user/e9836ff1-e7fa-5638-b4f5-86e718ee9fb8/scratchpad/wave/sessions.txt
Dataset versions are tracked in /home/user/dash/versions.json (bump after each batch).
Verification workflow (run per ready PR): scriptPath /root/.claude/projects/-home-user/e9836ff1-e7fa-5638-b4f5-86e718ee9fb8/workflows/scripts/uc-verify-wf_f8c22b26-4b7.js with args {prs:[{pr,item,issue,branch,base,notes}]}. Confirmed findings -> send to the owning cloud session to fix.
Integration branch: integration/unified-core (from development f41fe5e5). Merge flow: merge integration into the PR branch (resolve cross-PR conflicts, run tests), push, retarget the PR base to integration/unified-core, wait for green CI, run uc-verify, merge with merge_method=merge.
Merged so far: 13 PRs incl. #857 (2a25998e).
Tests chart (datasets/tests): after each merge, run `python3 tests_point.py`, then upload tests.json (Artifact publish asset=true) and update datasets/tests (source.url, updated, edit) with if_version.
- Never SendMessage a running workflow agent (it spawns a duplicate). Stop the workflow, then resume it with an edited prompt.
- Disk: the uv cache keeps a ~37 MB opentide wheel per sync (it grew to 5.5 GB). `uv cache clean opentide` frees it safely, since venvs hardlink their copies.
- Disk: pools pile up older builds of the same test executables (uc16 reached 11 GB). scratchpad/prune-stale-tests.sh <pool> keeps the newest build of each test; a background guard runs it below 5.5 GB.
- Also free: verifier pools (<item>-vs, <item>-va) left after their stage, untouched for 15+ min; and uv cache prune.
- Pools also pile up old library builds (lib*.rlib/.rmeta, many hashes per crate): keep the newest 2 per name and remove older ones untouched for 20+ min (scratchpad/uc14-old-libs.txt shows how).
