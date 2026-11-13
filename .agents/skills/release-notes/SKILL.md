---
name: release-notes
description: >-
  Write and review opentide's release notes: the CHANGELOG.md entries a user-visible change adds
  under [Unreleased], and at a release the public notes in docs/usage/releases.md and the GitHub
  Release body in .github/release-notes/. Covers the headline, Upgrade and Breaking, the Keep a
  Changelog categories in a fixed order, entries with a bold lead, and what opentide.org/releases
  shows. Use when a change needs a changelog entry, when preparing a release's notes, or when
  reviewing either.
---

# Release notes: opentide

How to write what users read about a release. The release procedure itself (versions, tags,
publishing) is [`release-management`](../release-management/SKILL.md).

## The three files

opentide's notes live in three files. All three use the parts the standard below sets out, in
the same order; how each file is laid out is under [The files in detail](#the-files-in-detail).

| File | Written | For | Detail |
|------|---------|-----|--------|
| `CHANGELOG.md` | In each pull request with a user-visible change, under `## [Unreleased]` (AGENTS.md, definition of done) | Maintainers, and users who want the whole record | Every change, with its engineering detail and its issue link |
| `docs/usage/releases.md` | At the release (release-management, Step 1) | Everyone: [opentide.org/releases](https://opentide.org/releases/) renders it | The digest: the headline, the upgrade steps and the changes users notice, about 40 words each |
| `.github/release-notes/vX.Y.Z.md` | At the release | GitHub Release readers | The digest, with the upgrade commands as a fence, a Before/Now table where behaviour changed, and Verify |

## Write it like an announcement

Release notes tell people what shipped. Write them the way you would tell a colleague, not the
way the code is built.

- **Lead with the news.** "Graylog support." comes first. How it works comes after, if at all.
- **Short sentences, one idea each.** If a sentence needs a colon and three commas, split it.
- **Plain words.** "Deploy rules to Graylog", not "Graylog event definitions deploy from a
  `configurations.graylog` block".
- **Name what people see and type**: commands, flags, settings, views, error messages. Leave out
  how the code does it.
- **Read it aloud.** If you run out of breath or have to re-read it, rewrite it.

## The headline

The first paragraph of every version is its headline (the summary).
[opentide.org/releases](https://opentide.org/releases/) shows it large under the version number,
and for most readers it is the only thing they read.

- **One or two short sentences, at most 25 words.**
- **Start with the biggest change, in a few words**: "Graylog support." "`pip install opentide`
  works again." "First release."
- **A second sentence only for the second-biggest change.** The lists below carry the rest.
- **Leave out** upgrade steps, issue links, the versions of other products, which tools run a
  check, supported version ranges beyond the headline one, and "minor", "patch" or "pre-release"
  (the page shows those).

| Instead of | Write |
|------------|-------|
| Graylog event definitions deploy from a `configurations.graylog` block on Graylog 6.3 to 7.2, checked by `validate`, the editor and `opentide tui`. Generated documentation is redesigned, with kill-chain maps and ATT&CK coverage. The engine is language-server 0.14.0. | Graylog support: deploy rules to Graylog 6.3–7.2 as event definitions. Generated documentation is redesigned, with kill-chain maps and ATT&CK coverage. |
| YARA is a language: `.yar` files and the YARA in HarfangLab and Bitdefender rules are checked as libyara 4.5 compiles them, with YARA-X differences flagged, and Bitdefender GravityZone rules are checked against GravityZone's criteria. | YARA support: `.yar` files and the YARA in HarfangLab and Bitdefender rules are checked as you type. |
| `npx @opentide/explorer serve` works: 0.5.0 shipped two commands, so npx could not tell which to run and stopped with "could not determine executable to run". | Fixes `npx @opentide/explorer serve`, which failed with "could not determine executable to run". |

## The parts of a version

Every version has the same parts, in this order, in all four products. Leave out an empty part.
Never add one.

| Part | What goes in it |
|------|-----------------|
| Headline | The first paragraph: what the release is, in at most 25 words |
| **Upgrade** | The steps to take after installing, in order. Only when there is something to do |
| **Breaking** | What stops working the way it did, and what replaces it |
| **Added** | Something people can do that they could not before |
| **Changed** | Existing behaviour that is different, but not broken. Includes a bundled or pinned version people see |
| **Deprecated** | Still works, will be removed. Say what to use instead |
| **Removed** | Gone, and nobody relied on it. If someone could have, it is **Breaking** |
| **Fixed** | Something that did not work as documented, and now does |
| **Security** | A vulnerability fixed, with its advisory id, and whether to upgrade promptly |

**Added** through **Security** are the six types of
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/). **Upgrade** and **Breaking** are
ours, and come first because an upgrading reader needs them first.

[opentide.org/releases](https://opentide.org/releases/) recognises exactly these names: the
Upgrade steps become a numbered panel and each category gets an icon and a count. Any other
heading (Install, Tests, Notes, Highlights, Migration) shows as plain text after the categories.
That is a review finding.

Each change goes in one part. A breaking change is under **Breaking** only, and the step that
deals with it is under **Upgrade**.

## Upgrade

- Numbered steps, in the order to take them. One action per step, starting with a verb, with the
  exact command in backticks.
- A step for some users only starts with who: "If you use Splunk, …".
- Add the reason in a few words when it is not obvious: "Run `opentide setup ci github --yes`, so
  the live query job checks the same variables."
- Nothing to do? Leave the part out. Do not write "Nothing to do".

## Breaking

A change is breaking when something that worked stops working the way it did:

- a command, flag, setting, key, protocol method or API is removed or renamed;
- output, a field or an exit code that scripts read changes;
- validation rejects a file that used to pass;
- a default changes what a run does.

Each entry says what replaces the old behaviour, and **Upgrade** has the step. Before 1.0 a minor
version may break things. A patch breaks only to correct a defect the previous release shipped,
and its headline says so.

## Entries

Each entry is one change, as one list item:

```markdown
- **Graylog queries are checked.** Rule queries, hunts and `opentide-lsp analyze --platform graylog` get Lucene checks tuned for Graylog ([#242](https://github.com/opentidehq/language-server/pull/242)).
```

- **Bold lead first**: the change in at most 10 words, as a user would say it. Readers scan the
  leads. The lead is a complete phrase ("`deploy --uuid` selects the rules to deploy"), not the
  start of a sentence the rest finishes ("**Progress events** with …").
- **Then one or two short sentences**: what it does for the reader, any limit, what to do. About 40
  words in all.
- **Specifics in a nested list** when there are more than two (codes, keys, flags, API items): one
  level, a few words each, about six at most.
- **Link the issue or pull request** at the end of the sentence it belongs to. Another
  repository's: `[opentidehq/opentide#745](https://github.com/opentidehq/opentide/pull/745)`.
  Another product's version, by its release:
  `[language-server 0.10.0](https://github.com/opentidehq/language-server/releases/tag/v0.10.0)`.
- **Present tense, the thing that changed as the subject**: "`lint` checks files that start with a
  byte-order mark", not "We made lint check …". Skip filler like "now", "new" and "finally".
- **What, not how.** Functions, refactors, tests and CI belong in the pull request. If the detail
  does not fit in 40 words, it belongs in the documentation: link to it.
- **A fix names the symptom people search for**: "`deploy` no longer fails with `b'HEAD'` in a
  repository with no commits".
- **Leave out what users never see**: tests, CI, refactors, internal renames, dependency bumps with
  no visible effect, contributor docs. A release with nothing users see has no notes, and is
  usually not a release.

## Groups

A category with more than about eight entries may be split into groups users recognise
("Problems", "Graph and search"), one `####` heading each. Never nest deeper, and never group a
short category.

## Before and after

| Before | After |
|--------|-------|
| **Graylog queries are checked in a Graylog dialect of Lucene.** `configurations.graylog.query`, hunts with `system: graylog` and `opentide-lsp analyze --platform graylog` get Elastic's Lucene checks without the ECS and Kibana KQL advice, plus graylog-1.1's seven codes. | **Graylog queries are checked.** Rule queries, hunts and `opentide-lsp analyze --platform graylog` get Lucene checks tuned for Graylog, plus seven Graylog codes. |
| The ES\|QL TextMate grammar's scope is `source.opentide.esql`, as `docs/EDITORS.md` promised, not `source.esql`, the scope of Elastic's ES\|QL extension (#195). An editor that loaded both grammars kept only one. … | **Breaking**: "**The ES\|QL grammar's scope is `source.opentide.esql`.** It was `source.esql`, which clashed with Elastic's extension (#195)." **Upgrade**: "If your editor includes the ES\|QL grammar by scope, use `source.opentide.esql`." |
| **Fixes.** `deploy` and `--changed` in a repository with no commit yet; a duplicate UUID counted as a load error by `info`; an interrupted `generate` no longer leaves an empty schema. | Three entries under **Fixed**, each with its own lead: "**`deploy` works in a repository with no commits.** …" |
| React component tests in happy-dom, beside a faster unit run (#78). | Nothing: tests are not a change users see. |

## The files in detail

### CHANGELOG.md

```markdown
## [Unreleased]

### Breaking

- **`--plan` is removed.** Pass `--strategy PREVIEW` or `--strategy RELEASE` ([#540](https://github.com/opentidehq/opentide/issues/540)).

### Added

- **`opentide serve` answers CLI commands from one warm process** ([#750](https://github.com/opentidehq/opentide/issues/750)). …
```

- Add entries under `## [Unreleased]`, in the right part, in the pull request that makes the
  change. Keep every part's list free of blank lines
  (`test_the_unreleased_lists_hold_no_blank_lines`).
- The record may carry the detail the digest leaves out, but each entry still starts with a bold
  lead, sits in one part, and links its issue.
- At the release the section becomes `## [X.Y.Z] — YYYY-MM-DD` with its headline paragraph, and
  takes no `### Install`: the install commands are in the other two files.
- Versions before 0.23.0 keep their original engineering summary as a second paragraph, after the
  headline: it is the record.

### docs/usage/releases.md

The page opentide.org/releases renders. Its parts are bold lines rather than headings, so the
page's table of contents lists versions only:

````markdown
## 0.22.0 — 4 November 2026

The opentide VS Code extension is out. Installs are smaller without pandas and numpy, and Windows
on Arm gets a wheel.

**Install**

```bash
pip install opentide==0.22.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide setup vscode --settings --no-generate` to drop the `yaml.schemas` mappings earlier releases wrote.

**Added**

- **`opentide serve` answers CLI commands from one warm process** ([#750](https://github.com/opentidehq/opentide/issues/750)). …

**Fixed**

- …

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0220--2026-11-04) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.22.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.22.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)
````

- The heading is `## X.Y.Z — D Month YYYY`. The newest version is first: `release.py check` and
  `test_the_release_log_leads_with_the_current_release` read it.
- **Install** is those three lines, with the version: the first `opentide==` pin on the page must
  be the current release. Release-specific commands are **Upgrade** steps.
- The CHANGELOG line gives the version's anchor in `CHANGELOG.md`: the version without dots, two
  hyphens, the ISO date (`0220--2026-11-04`). The site shows it as "Full changelog".
- Leave older versions' entries as they are, apart from fixing an error: they are the record of
  what shipped. A headline may be rewritten to this standard: the site shows it large.

### .github/release-notes/vX.Y.Z.md

The GitHub Release body. It opens `# X.Y.Z — D Month YYYY` and "Minor release on 0.21.0." (on
GitHub, nothing else says which kind it is), then the headline. `## Upgrade` holds a fence with the
install and upgrade commands, commented, and a Before/Now table when behaviour that scripts or
files depend on changed. Then `## Breaking`, `## Added`, … in the order below, the CHANGELOG line,
`## Verify` and `## Links` (release-management, Step 1.3).

## One standard, four products

opentide, language-server, vscode-extension and explorer share this standard, and
[opentide.org/releases](https://opentide.org/releases/) renders all four the same way (the
website's `lib/releases.ts` parses them). A change to the standard goes to all four
`release-notes` skills together, and to the website's parser when it adds or renames a part.

## Review checklist

- [ ] The headline is at most 25 words, leads with the biggest change, and reads cleanly aloud.
- [ ] Every action a user must take is an **Upgrade** step, with its command.
- [ ] Everything that stops working as it did is under **Breaking**, with its replacement and an
      **Upgrade** step.
- [ ] Every entry is in the right part, and in one part only.
- [ ] Every entry starts with a bold lead and is about 40 words at most.
- [ ] Sentences are short and plain: no stacked clauses, no internal names.
- [ ] No entry is about tests, CI, refactors or contributor docs.
- [ ] The parts are in the order above, under no other names.
- [ ] Links point at the issue or pull request, and at other products' releases.
