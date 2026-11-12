---
name: review-checklist
description: opentide's correctness checklist for writing and reviewing code — the defect classes that have actually shipped here (HTTP timeouts and TLS, swallowed errors, exit codes and --json purity, file encodings and line endings, overwriting user files, YAML/KQL/Markdown built from strings, per-tenant settings, CI diff bases, stale caches; in Rust, panics on user input, unsafe, suppressions and layering; behaviour changes without an approved-diffs ledger entry and the other golden and compare rules) plus the definition of done for a change. Use before committing any fix or feature, when reviewing a diff or PR, and when touching platforms/, cli/, sharing/, extraction/, deployment/ or the Rust workspace.
---

# Review checklist — opentide

Each item below is a bug class that reached `development` at least once. Check every diff
against the sections it touches. A finding is real only if you can name the input that
triggers it; drop anything you cannot tie to a trigger.

## Network calls (platforms/, sharing/, extraction/, vulnerability_lookup)

- [ ] **Every request has a timeout.** `requests` and `urllib` wait forever by default, and
      a silent tenant hangs a CI job until the runner kills it. Platform clients build their
      session from `opentide.platforms.transport.TenantSession`; module-level
      `requests.post(...)` token calls and `urlopen` need an explicit `timeout=`.
- [ ] **TLS follows the tenant's `ssl` on every call**, token requests included. Never rely on
      `session.verify` alone with a plain `requests.Session`: `REQUESTS_CA_BUNDLE` /
      `CURL_CA_BUNDLE` replace it (psf/requests#3829). Use `TenantSession(verify=...)` and
      `tenant_tls_verify(...)`.
- [ ] **A non-2xx answer is a failure.** Check the status before parsing; a 3xx the client
      cannot follow (e.g. a gateway's 307) is not success. Don't call `.json()` on an error
      body without guarding for non-JSON.
- [ ] **Read a response stream once.** `body.read()` twice returns `b""` the second time.
- [ ] **Pagination is followed** (`nextLink`, `@odata.nextLink`, `page`), or the limit is
      stated in the docs.
- [ ] **Right URL, right method.** Retries/fallbacks post to the same endpoint as the first
      attempt; a custom urllib handler passes `method=` (a body-less DELETE otherwise
      becomes a GET).

## Errors and exit status

- [ ] **No `except Exception` that turns a failure into success.** "Not found" is a specific
      exception (`KeyError`, a 404); catch that, and let auth/transport errors propagate.
- [ ] **Every failure path sets the failure signal** (`status: failed`, `_exit_code`, the
      `*_ERROR_RAISED` flag the caller reads) and the command exits non-zero.
- [ ] **No retry that hides the original error** (e.g. retrying with another signature on
      `TypeError`); chain with `raise ... from exc`.
- [ ] **`--json` stdout carries only the JSON document.** Logs go to stderr (structlog/Rich);
      no `print()` (`T20` enforces it).
- [ ] **Options are never silently dropped.** A Typer group callback that returns early when
      a subcommand is named discards group-level options; refuse or hand them down
      (see `_hand_down` in `cli/setup_app.py`).
- [ ] **Environment flags are strings.** `os.environ.get("X") == True` is never true; parse
      leniently (`1/true/yes/on`) and never let a foreign convention (`DEBUG=*`) crash startup.

## Files the user owns

- [ ] `encoding="utf-8"` on every text read/write (Windows defaults differ).
- [ ] **Rewriting a user file keeps its line endings**: read bytes and decode, write with
      `newline=""`. Generated shell scripts/hooks are written with `newline="\n"` and compared
      as bytes.
- [ ] **Never overwrite a file the user may have edited** (`.mcp.json`, `AGENTS.md`,
      `CLAUDE.md`, `.pre-commit-config.yaml`, `.vscode/*`): merge into it or skip with a
      warning. After editing structured text, re-parse the result and refuse to write
      invalid output.
- [ ] **Names derived from titles collide**: two rules slug to the same filename, or differ
      only by case on macOS/Windows. Detect the collision (suffix with the UUID) and use
      `Path.samefile` for case-only renames.
- [ ] **State writes are atomic** (temp file + `os.replace`, see `states/deployment.py`).
- [ ] **Paths from data stay inside the workspace** (no `..`, no absolute paths from YAML).

## Serialising data

- [ ] **Build structures and dump them** (`yaml.safe_dump`, `json.dumps`); never concatenate
      YAML from values. Titles with `:`, values like `yes`/`1.0`/`{{Column}}`, quotes and
      backslashes all break or silently change hand-built YAML.
- [ ] **Escape for the target language**: KQL string literals (`\` and `"`), Markdown table
      cells (`|` and newlines), shell arguments (pass lists to `subprocess`, never `shell=True`).
- [ ] **Generated CI YAML never interpolates `${{ github.event.* }}` into `run:`**; pass it
      through `env:`.

## Data shape and configuration

- [ ] **Optional means optional everywhere**: a field the model makes optional must not be
      read with `dict.pop(key)` / `data[key]`, and a YAML block whose keys are all commented
      out loads as `None` — guard `isinstance(block, dict)` before `.get`.
- [ ] **Per-tenant settings are resolved per tenant**, inside the tenant loop — never from
      `tenants[0]` in `__init__`.
- [ ] **Filters only narrow.** `--type`, `--file`, `--tenant` must restrict every step,
      including ledger/state-driven ones (retract, prune).
- [ ] **Validators check what they claim**: `UUID(s, version=4)` does not check the version;
      `x is str` is not `isinstance(x, str)`; `type(x) == dict` excludes ruamel's
      `CommentedMap`.
- [ ] **Recursive walks over YAML handle aliases** (a visited set), and `RecursionError` is
      reported as a parse error, not a crash.

## CI and deployment semantics

- [ ] **Diff bases**: on a PR, `GITHUB_SHA` / `BUILD_SOURCEVERSION` is the merge commit — diff
      from its first parent, not from the merge base. A push may land several commits — use
      the event's `before`, not `HEAD^1`.
- [ ] **Deploy and validate read the files on disk**; preview overlays (inflight shards) are
      for preview output only.
- [ ] **Concurrency groups never cancel pending production runs** — put `concurrency:` on the
      job that needs it, not the workflow.

## Long-lived processes

- [ ] **Caches have an invalidation story.** The MCP server lives for hours: tools that answer
      "is this valid now?" must not serve the index from start-up.

## Rust (crates/, bindings/python/, xtask/)

The workspace's lints catch most of these at compile time; review what they cannot see. The loop
and the lint policy: [`rust`](../rust/SKILL.md), [`crates/AGENTS.md`](../../../crates/AGENTS.md).

- [ ] **No panic on user input.** `unwrap`, `expect`, indexing (`v[i]`, `&s[a..b]`), `as` casts
      that narrow, and arithmetic that overflows on a file, an argument, an environment variable or
      a network answer. Return a diagnostic or a typed error. An `#[expect(clippy::expect_used)]`
      is right only where the value cannot fail (a catalog compiled in, a regex literal), and its
      `reason` says why.
- [ ] **Byte offsets land on char boundaries.** Slicing a `&str` at a byte offset taken from an
      LSP position, a column or a search panics inside a multi-byte character. Convert through
      `opentide_core` ([`rust-engine`](../rust-engine/SKILL.md)), and test with `é`, a CJK and a
      non-BMP character.
- [ ] **`unsafe` only where allowed**, in `opentide-syntax` or `opentide-wasm`, each block with a
      `// SAFETY:` comment that states the invariant. Anywhere else, `unsafe` fails review even if
      the crate's lints were changed to accept it.
- [ ] **Every suppression names its reason**: `#[expect(lint, reason = "...")]` on the narrowest
      item, rather than `#[allow]`, and never a crate-wide allow to quiet one site. Growing the
      workspace allow-list in `Cargo.toml` is a decision of its own, never part of a fix.
- [ ] **Dependencies point down the layer table.** `cargo xtask check-layers` passes. A new crate
      is placed in `xtask/layers.toml` in the same change, with its reason. Moving a crate between
      layers to get green is a design change, not a fix.
- [ ] **Engines stay I/O-free.** No `std::fs`, environment or network in the engine crates'
      `src/`; the host passes text in (`scripts/engine/check-io-free.sh`).
- [ ] **`Cargo.lock` changes only with a dependency change.** CI builds with `--locked`.
- [ ] **No test was weakened to get green**: no new `#[ignore]`, no deleted test or loosened
      assertion, no `pytest.skip` / `xfail`, no retry.
- [ ] **Errors keep their meaning.** A public error is a typed enum mapped to a stable code, or in
      an engine crate an `opentide_core::Diagnostic` with its code; `anyhow` stays in binaries. A
      diagnostic code is a constant in `opentide_core::codes`, never a second string at the call
      site.

## Goldens and compare (unified core)

The Python CLI at the frozen tag is the oracle; the rules: [`golden`](../golden/SKILL.md).

- [ ] **A behaviour change has a ledger entry.** A Rust port that prints, writes or exits
      differently from the oracle needs an entry in `tests/golden/APPROVED_DIFFS.toml` with its
      reason, its issue and its `CHANGELOG.md` entry. Without one, the difference is a bug.
- [ ] **Recordings are re-recorded, never hand-edited**: `tests/golden/cases/`, `blobs/` and
      `COVERAGE.md`. Each changed recording has a cause in the same pull request: a new or changed
      case in `cases.toml`, a fixture change, a normalisation rule with its unit test, or a new
      oracle in a PR of its own.
- [ ] **The comparison is not loosened.** A normalisation rule hides only a value that differs
      between two runs of the same case, and is code in `xtask/src/golden/normalise.rs` with a unit
      test; no widened rule; no ledger entry broader than the difference; no stale
      entry; no skipped, deleted or `#[ignore]`d case.
- [ ] **No plan §3 invariant moves** in a port: the CLI contract, the command tree, diagnostic
      codes, cross-repository contracts, MCP, workspace formats, SDK import paths, platforms, the
      security posture. A change to one is a separate decision with its own changelog entry.
- [ ] **Secrets never reach a recording**: goldens, cassettes, compare reports and fixtures.

## Definition of done

1. A regression test that **fails without the fix** (prove it: stash the fix, run the test)
   and passes with it, next to the existing tests for that module.
2. `scripts/ci-local.sh` green (`--full` before pushing anything that touches `src/` or tests).
   A Rust change also passes `cargo fmt --all --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo xtask check-layers`,
   `cargo nextest run --workspace` and `cargo test --workspace --doc` with the pinned toolchain
   ([`rust`](../rust/SKILL.md)).
3. No new `# noqa` / `# ty: ignore` without a reason on the same line; new and touched
   functions fully annotated.
4. User-visible behaviour change → an entry under `## [Unreleased]` in `CHANGELOG.md`, in
   the right part and the house style ([`release-notes`](../release-notes/SKILL.md): a bold
   lead naming the change or the symptom it fixes, then the effect, then the issue link).
5. CLI/MCP/SDK surface change → docs updated ([`docs-maintenance`](../docs-maintenance/SKILL.md)).
6. Mechanical refactors (formatting, renames, lint autofixes, string splitting) are verified
   behaviour-preserving with `uv run python scripts/ast_equivalence.py <base-rev>`: it lists the
   changed files whose AST differs from the base, ignoring imports and annotations. Review
   every file it prints.

## Related

- [`python-typing`](../python-typing/SKILL.md), [`ruff`](../ruff/SKILL.md) — the static bar
- [`python-testing-patterns`](../python-testing-patterns/SKILL.md) — how to write the regression test
- [`steward`](../steward/SKILL.md) — driving a PR to green
