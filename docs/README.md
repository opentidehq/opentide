# Documentation authoring guide

opentide documentation lives in this directory and is published on **[opentide.org](https://opentide.org/docs)** by [opentidehq/website](https://github.com/opentidehq/website). Four top-level sections become sidebar tabs:

| Tab | Directory | Audience |
|-----|-----------|----------|
| Usage | `usage/` | Human operators — setup, workflows, concepts |
| CLI | `cli/` | Command-line reference |
| MCP | `mcp/` | Agent and editor integrations |
| SDK | `sdk/` | Python API consumers |

Internal maintainer docs (test plan, publishing) live in `internal/` and are excluded from the public site tree.

## Conventions

### Frontmatter

Every page starts with YAML frontmatter:

```yaml
---
title: Page title
description: One sentence for cards, SEO, and LLM context
---
```

Optional fields for the Fumadocs site:

```yaml
icon: Terminal          # Lucide icon name
full: true              # full-width layout
---
```

### Navigation (`meta.json`)

Each folder may contain `meta.json` to control sidebar order. Root tabs set `"root": true`.

```json
{
  "root": true,
  "title": "CLI",
  "description": "Technical CLI reference",
  "icon": "Terminal",
  "pages": ["index", "global-options", "setup"]
}
```

Use Fumadocs separators: `"---Section name---"`. External links: `"external:[Label](https://…)"`.

### File names

- Use **kebab-case** filenames.
- Folder index pages: `index.md`.
- Prefer `.md` over `.mdx` unless a page needs React components.

### When code changes

Update docs in the **same PR** when you change:

| Code area | Doc location |
|-----------|--------------|
| CLI commands / flags | `docs/cli/` |
| MCP tools / resources | `docs/mcp/` |
| Public Python API | `docs/sdk/` |
| Setup / onboarding flows | `docs/usage/` |
| Platform capabilities | `docs/usage/concepts/platforms.md` |

Run `scripts/validate-docs.sh` before pushing doc changes.

### Output samples

Show output you captured, not output you expect. Pair a `text` or `json` fence with the command that prints it by naming the command in the fence's info string, and add `exit=N` when the command is meant to fail:

````markdown
```bash
opentide deploy metadata --platform splunk
```

```text output-of="opentide deploy metadata --platform splunk" exit=2
error: Metadata deployment is not implemented for splunk
```
````

`tests/test_docs/test_docs_commands_golden.py` runs every paired command against a repository scaffolded as in the [tutorial](./usage/tutorial.md), with vendor APIs stubbed. It fails when:

- the command is not in a shell fence on the same page, or is not one the harness runs (`validate`, `lint`, `info`, `generate`, `deploy`);
- the command returns a code other than `exit=` (`0` when absent), or a non-zero `exit=` sits in a section that never says it exits `` `N` ``;
- a `text` line is not printed whole and in order, reading stdout and stderr interleaved as a terminal shows them. Write the `--no-color` view; a colour run must carry the same lines, with its rules read back as `== Title ==`. A duration (`1.2s`, `2m05s`) matches any duration, because it changes on every run;
- a `json` value differs from the document returned. Objects may return keys the sample leaves out, and `"..."` stands for any value.

A sample of a failure the finished tutorial does not produce names the edit it needs with `state=NAME`, and the harness makes that edit to its copy of the repository before running the command:

| `state=` | Edit to `objects/rules/sentinel-kql-rule.yaml` |
|----------|------------------------------------------------|
| `dangling-reference` | `detection_model` names an objective that does not exist, as in tutorial step 7 |

The edits live in `REPO_STATES` in the golden test. Add one there instead of leaving a failure sample unchecked.

Pairing is required, not optional, for anything that reads like CLI output. Under `cli/` and `usage/`, a `text`, `json`, or unlabelled fence that holds a result-envelope key (`"ok"` or `"status"`), or a line starting with an outcome glyph (`✓ `, `✗ `, `! `, `→ `), `error: `, `warning: `, `Skipped: `, `DEPRECATED `, `== … ==`, or a label older releases printed (`OK `, `SKIPPED `, `WARNING `, `FATAL`), must carry `output-of=`. If no command the harness runs can print it, mark it `illustrative` instead and say in the prose that it is not captured output:

````markdown
```text illustrative
warning: …
```
````

Prefer a `state=` over `illustrative`: an illustrative sample is never compared with anything, so it can drift. MCP pages are exempt, because no `opentide` command prints an MCP tool call or response.

None of these attributes renders: Fumadocs reads only `title`, `tab`, `noCopy` and `lineNumbers` from fence meta, and GitHub reads only the language.

### Terminal recordings (tapes)

Screenshots of the CLI are not taken by hand. Each one is a [VHS](https://github.com/charmbracelet/vhs) tape in [`tapes/`](./tapes/) that types the commands into a real terminal and writes a GIF of the run and a PNG of its last screen to `assets/cli/`:

| Tape | Records | Writes |
|------|---------|--------|
| `tutorial.tape` | Tutorial steps 1, 2 and 6: `setup --yes`, `generate`, `validate` | `tutorial.gif`, `tutorial.png` |
| `validate-failure.tape` | Tutorial step 7: `validate` on a dangling `detection_model` | `validate-failure.gif`, `validate-failure.png` |
| `deploy-plan.tape` | Tutorial step 9: the deploy plan of a dry run | `deploy-plan.gif`, `deploy-plan.png` |
| `home.tape` | `opentide` with no command, in the tutorial repository | `home.gif`, `home.png` |
| `setup-wizard.tape` | The interactive `setup` wizard in an empty directory | `setup-wizard.gif`, `setup-welcome.png`, `setup-wizard.png` |

The `tapes` job in [`.github/workflows/docs.yml`](../.github/workflows/docs.yml) renders every tape when docs, tapes or the CLI's output code change, fails when one no longer runs, and uploads what it rendered as the `cli-tapes` artifact. It never commits.

**Refresh the committed images** after a change to what a recorded command prints. Download the artifact from the pull request's Docs run and commit it over the old files:

```bash
gh run download <run-id> --name cli-tapes --dir docs/assets/cli
git add docs/assets/cli
```

Or render locally from the repository root. You need VHS 0.12.1, ttyd, ffmpeg, Chrome or Chromium, and the JetBrains Mono font; `opentide` comes from the checkout:

```bash
uv sync
export PATH="$PWD/.venv/bin:$PATH"
vhs docs/tapes/home.tape            # one tape
for tape in docs/tapes/*.tape; do vhs "$tape"; done
```

As root (in a container), set `VHS_NO_SANDBOX=1` so Chrome starts.

**Add a tape** by copying one that is closest to what you need:

- Keep the settings block as it is: shell, font, size, padding, margin, the Reflex Blue frame and the white theme are pinned in every tape so renders match. Change `Width` and `Height` only to fit the output without wrapping.
- Keep `Env OPENTIDE_OUTPUT "human"`, so the tape records what a person sees even when CI or a coding agent runs it.
- Build the repository off camera with `Hide`, [`tapes/tutorial_repo.py`](./tapes/tutorial_repo.py) and `clear`, then `Show`. The script scaffolds the tutorial repository, writes its objects from the tutorial page, and can generate, commit, or break it the way a `state=` sample does.
- After each command, `Wait+Screen /…/` for text it must print, then `Wait` for the prompt. A command that crashes or prints something else then times out the tape and fails the job. `Wait+Screen` reads the first screenful only; once output scrolls, wait on the current line (`Wait+Line`) or check a file the command wrote.
- Name the outputs after the tape, under `docs/assets/cli/`, and end with `Screenshot`, then a short `Sleep` so VHS captures it.

**Show a recording** on a page with an absolute URL on `development`, next to the text sample (the sample stays: it is what the golden test checks, and what readers copy):

```markdown
![What the image shows, in words](https://raw.githubusercontent.com/opentidehq/opentide/development/docs/assets/cli/home.png)
```

The website publishes only the four tabs, so a relative path to `assets/` would not resolve there. `scripts/validate-docs.sh` still fails when the file is missing from the checkout. VHS writes GIF, MP4, WebM and PNG, not SVG, so the still of each tape is a PNG.

## Agent maintenance

Agents working on documentation should read [`.agents/skills/docs-maintenance/SKILL.md`](../.agents/skills/docs-maintenance/SKILL.md).

## Fumadocs site repository

**Build and deploy are owned by [opentidehq/website](https://github.com/opentidehq/website)** — not this repo. This repository only ships markdown content and structural validation.

Scaffolding notes: [`fumadocs/`](./fumadocs/). The website repo syncs `docs/` at build time.

## Validation

```bash
scripts/validate-docs.sh
```

CI runs the same check via [`.github/workflows/docs.yml`](../.github/workflows/docs.yml) on docs changes.
