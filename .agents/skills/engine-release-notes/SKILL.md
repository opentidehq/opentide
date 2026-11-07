---
name: release-notes
description: Write and review the language server's release notes in CHANGELOG.md, the GitHub Release body and opentide.org/releases/language-server - the summary, Upgrade and Breaking, the Keep a Changelog categories in a fixed order, and entries with a bold lead that name the protocol methods, settings, codes and API items integrators use. Use when a change needs a changelog entry, when preparing a release's notes, or when reviewing either.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Release notes: the language server

How to write what integrators read about a release. The release procedure itself (version bump,
crates.io, the opentide pin) is `skills/release/SKILL.md`.

## Where they are read

- `CHANGELOG.md` is the only source. Its version section is the GitHub Release body
  (`scripts/release.py notes X.Y.Z`, run by `release.yml`), and
  [opentide.org/releases/language-server](https://opentide.org/releases/language-server/) renders
  it, synced from `main` every hour.
- opentide's own changelog cites the release when it repins the engine (`skills/release`, step 4),
  so the summary is what opentide's users read about it too.

## When they are written

- Each pull request with a user-visible change adds its entries under `## [Unreleased]`, in the
  right part.
- The release pull request renames the section `## [X.Y.Z] - YYYY-MM-DD`, keeps an empty
  `## [Unreleased]` above it, and writes the summary (`skills/release`, step 1).
- One line per list item and per paragraph, no hard wraps; nested items are indented two spaces.

## What a reader wants

Release notes are read by people deciding whether to upgrade, and by people who just did. They
come with three questions, in this order:

1. **Do I have to do anything?** The upgrade steps, and what stops working as it did.
2. **What can I use now, and what behaves differently?**
3. **Is the thing that bit me fixed?**

Write for that reader. Name what they see and type (commands, flags, settings, keys, codes,
views), not how the code does it.

## The parts of a version

Every version has the same parts, in the same order, in all four products. Leave out a part that
would be empty; never add another.

| Part | What goes in it |
|------|-----------------|
| Summary | The first paragraph: one or two sentences, at most 40 words, on what the release does for its users |
| **Upgrade** | The steps a user takes after installing this version, in order. Only when there is something to do |
| **Breaking** | What stops working the way it did, each with what replaces it |
| **Added** | Something users can do that they could not before: a command, flag, setting, view, diagnostic, API |
| **Changed** | Existing behaviour that is different, and is neither new nor broken. A bundled or pinned version users see |
| **Deprecated** | Still works, and will be removed. Say what to use instead |
| **Removed** | Gone, and nobody relied on it. If someone could have, it is **Breaking** |
| **Fixed** | Behaviour that did not match the documentation or the intent, and now does |
| **Security** | A vulnerability fixed or a hardening users should know about, with its advisory id, and whether to upgrade promptly |

These are [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)'s six types, after two
parts of our own, **Upgrade** and **Breaking**, which come first because they are what an
upgrading reader needs first.

[opentide.org/releases](https://opentide.org/releases/) recognises exactly these names. It shows
the summary large, the Upgrade steps as a numbered panel, each category under its icon, label and
count, and the counts again beside every earlier version, so a reader sees what kind of release
it was before opening it. A section with any other name (Install, Tests, Notes, Highlights,
Migration, Internal) renders as plain text after the categories: that is a review finding.

A change belongs to one part. A breaking change is listed under **Breaking** only, not again
under Changed or Removed, and the step that adapts to it is in **Upgrade**.

## The summary

- One or two sentences, at most 40 words. The page shows it large, above everything else.
- Say what the release does for its users, the way they would put it: the one or two changes that
  matter most. The lists carry the rest.
- No upgrade steps (they are **Upgrade**), no issue links, no list of every change.
- Do not restate what the page shows beside it: the version, the date, "minor", "patch",
  "pre-release".

| Instead of | Write |
|------------|-------|
| Minor release. `validate` compiles every rule a deploy would compile, the query checks know the documented tables and their columns, a workspace's `visibility.toml` declares its own tables, indexes and index patterns, and `lint.toml` sets the filename convention. Run `opentide validate` after upgrading: … | `validate` catches what a deploy would reject: it compiles every rule, and the query checks know the documented tables and their columns. |
| The workspace index for editors' catalogue, graph and search views: `opentide/catalog` serves every object with its references, and `opentide/catalogChanged` says when a root's objects change, so … (90 words) | Editors get the workspace index for their catalogue, graph and search views, and placeholder queries from `opentide new` are no longer reported as errors. |

## Upgrade

- A list of steps, in the order to take them. One action per step, starting with its verb, with
  the exact command in backticks.
- A step that applies to some users only starts with its condition: "If you use Splunk, …", "If
  your `visibility.toml` uses the 0.20.0 lists, …".
- Say why in a few words when it is not obvious: "Run `opentide setup ci github --yes`, so the live
  query job guards the same variables."
- Nothing to do: leave the part out. Do not write "Nothing to do".

## Breaking

A change is breaking when something a user has, and that worked, stops working the way it did:

- a command, flag, setting, key, protocol method or API is removed or renamed;
- output, a field or an exit code that scripts read changes;
- validation refuses a file that passed;
- a default changes what a run does.

Each entry names what replaces the old behaviour, and **Upgrade** has the step. Before 1.0 a minor
version may break; a patch breaks only to correct a defect the release before shipped, and its
summary says so.

## Entries

Each entry is one change, as one list item:

```markdown
- **`opentide serve` answers CLI commands from one warm process.** A repeat `validate --file` at
  500 rules takes 0.3 s instead of 1.6 s ([#750](https://github.com/opentidehq/opentide/issues/750)).
```

- **Start with a bold lead**: the change in at most 10 words, as its user would name it. Readers
  scan the leads; the rest is for the one who stops. The lead is a complete phrase on its own
  ("`deploy --uuid` selects the rules a run reads"), not the first words of a sentence the detail
  finishes ("**Progress events** with …").
- **Then at most two sentences**: the effect, the limit, what to do. About 50 words in all, which
  is three lines on the page.
- **Specifics go in a nested list** when there are more than two (the codes, keys, flags or API
  items it covers): one level, a few words each, at most about six.
- **Link the issue or pull request** at the end of the sentence it belongs to. Another
  repository's: `[opentidehq/opentide#745](https://github.com/opentidehq/opentide/pull/745)`. A
  version of another product, by its release:
  `[language-server 0.10.0](https://github.com/opentidehq/language-server/releases/tag/v0.10.0)`.
- **Present tense, active voice**, with the product or the thing that changed as the subject:
  "`lint` checks a file that starts with a byte-order mark", not "We made lint check …". No "now",
  "new" or "finally".
- **What, not how.** The function, the refactor, the test that proves it and the CI change that
  shipped it belong in the pull request. A detail that does not fit in 50 words belongs in the
  documentation: link to it.
- **A fix says what is right now**, and names the symptom a reader would search for: "`deploy` in a
  repository with no commit no longer fails with `b'HEAD'`".
- **Leave out what users do not see**: tests, CI, refactors, internal renames, dependency bumps that
  change nothing they can observe, documentation for contributors. A release with nothing users
  see has no notes, and is usually no release.

## Groups

A category with more than about eight entries may be split into groups by an area users recognise
("Problems", "Graph and search"), one `####` heading each, in the order a user meets them. Never
nest deeper, and never group a category of a few entries.

## Before and after

| Before | After |
|--------|-------|
| The ES\|QL TextMate grammar's scope is `source.opentide.esql`, as `docs/EDITORS.md` promised, not `source.esql`, the scope of Elastic's ES\|QL extension (#195). An editor that loaded both grammars kept only one. An editor that includes the grammar by scope includes `source.opentide.esql` now. The other grammars keep `source.<id>`; `docs/EDITORS.md` says why. HighlightSpec captures are unchanged. | **Breaking**: "**The ES\|QL grammar's scope is `source.opentide.esql`.** It was `source.esql`, Elastic's, so an editor with both extensions kept one grammar (#195)." **Upgrade**: "If your editor includes the ES\|QL grammar by scope, include `source.opentide.esql`." |
| **Fixes.** `deploy` and `--changed` in a repository with no commit yet; a duplicate UUID counted as a load error by `info`; an interrupted `generate` no longer leaves an empty schema. | Three entries under **Fixed**, each with its own lead: "**`deploy` works in a repository with no commit yet.** …" |
| React component tests in happy-dom, beside a faster unit run (#78). | Nothing: tests are not a change users see. |


## In this repository

Editor and tool integrators wiring `opentide-lsp`, the WASM build or the TypeScript packages into
an editor; opentide's maintainers, who compile the crates into opentide; and users of the crates on
crates.io and the packages on npm. So:

- Name the protocol methods, notifications, capabilities, settings, diagnostic codes, file globs
  and package exports a change touches; when there are several, in a nested list.
- Name public API items of the published crates and packages in a nested list ("API:
  `opentide_tide::object_refs`"). Internal types and functions stay out.
- Message shapes belong in `docs/EDITORS.md`: the entry says what changed and links there.
- Breaking here includes a renamed grammar scope, a diagnostic code or default severity that
  changes, a removed setting or RPC, and a changed public API. A renamed HighlightSpec capture is
  never allowed (AGENTS.md, hard rules).

## One standard, four products

opentide, language-server, vscode-extension and explorer share this standard, and
[opentide.org/releases](https://opentide.org/releases/) renders all four the same way (the
website's `lib/releases.ts` parses them). A change to the standard goes to the four
`release-notes` skills together, and to the website's parser when it adds or renames a part.

## Review checklist

- [ ] The summary is one or two sentences, at most 40 words, and says what users get.
- [ ] Every action a user must take is an **Upgrade** step, with its command.
- [ ] Everything that stops working as it did is under **Breaking**, with its replacement and a
      step in **Upgrade**.
- [ ] Every entry is in the right part, and in one part only.
- [ ] Every entry starts with a bold lead and is about 50 words at most.
- [ ] No entry is about tests, CI, refactors or contributor documentation.
- [ ] The parts are in the order above, under no other names.
- [ ] Links point at the issue or pull request, and at other products' releases.
