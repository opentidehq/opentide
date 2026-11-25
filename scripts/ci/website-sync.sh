#!/usr/bin/env bash
# One step of the website sync guard (ci.yml's `website` job).
#
# opentidehq/website syncs this repository's docs/ every hour ("Sync docs and
# deploy", its .github/workflows/sync-docs.yml). A change that passes this
# repository's own checks can still break that job (MDX the site refuses, a
# component it does not know, a frontmatter value its schema rejects), and the
# site then silently stops updating. The `website` job runs the site's own sync
# and checks against this pull request's docs/, so the break fails here.
#
# Usage: scripts/ci/website-sync.sh <sync|test|build|verify> [website-dir]
#
# The website checkout (default: ./website) must already hold this tree's docs/
# at vendor/opentide/docs, the specifications at vendor/specifications, and its
# dependencies (`pnpm install --frozen-lockfile`). Each step's output is kept;
# on failure the website's own error goes to an `::error` annotation and to the
# job summary ($GITHUB_STEP_SUMMARY, when set), and the step exits 1.
set -euo pipefail

step="${1:?usage: website-sync.sh <sync|test|build|verify> [website-dir]}"
website="${2:-website}"
logs="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/website-sync"
mkdir -p "${logs}"
log="${logs}/${step}.log"

case "${step}" in
  # The site's MDX safety check on every synced page: a refusal names the file
  # and the reason ("Refusing to publish MDX ...").
  sync) title="website sync:content"; heading="The website's docs sync refused this tree"
    command=(pnpm sync:content) ;;
  # The site's unit suite, MDX safety and docs-sync tests included. The one test
  # skipped compares the website's own committed vendor gitlinks with
  # content/docs, which this job replaces on purpose.
  test) title="website test"; heading="The website's tests failed on this tree"
    export NODE_OPTIONS="${NODE_OPTIONS:-} --test-skip-pattern=\"workspace committed docs match vendor gitlinks\""
    command=(pnpm test) ;;
  # Compiles every synced page through fumadocs-mdx with the site's frontmatter
  # schema, renders its components and type-checks. `next build`, not
  # `pnpm build`: its prebuild downloads releases and changelogs that do not
  # depend on this tree.
  build) title="website next build"; heading="The website does not build with this tree"
    command=(pnpm exec next build) ;;
  # Every synced page rendered its MDX components in the exported out/.
  verify) title="website verify:docs"; heading="The website's built docs failed verification"
    command=(pnpm verify:docs) ;;
  *) echo "unknown step: ${step} (sync, test, build or verify)" >&2; exit 2 ;;
esac

status=0
(cd "${website}" && "${command[@]}") 2>&1 | tee "${log}" || status=$?
if [[ ${status} -eq 0 ]]; then
  exit 0
fi

# The website's message, without stack frames, ANSI colours or pnpm's noise.
clean="${logs}/${step}.clean.log"
sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' "${log}" \
  | grep -vE '^\s+\[?at |^\s*$|ELIFECYCLE|^> |node:internal|^Node\.js v|^file://|^\s+throw |^\s+\^+\s*$|^\s*\(from ' \
  > "${clean}" || true

case "${step}" in
  test)
    # node:test's failures: the test's name (✖) and its assertion or error.
    message="$(grep -E '^\s*(✖ |not ok |AssertionError|Error|\[?[A-Z][A-Za-z]*Error)' "${clean}" \
      | sed -E 's/^\s+//' | awk '!seen[$0]++' | head -n 12)" ;;
  build)
    # Next's and fumadocs-mdx's errors: from the first "Error"/"Failed" line on.
    message="$(grep -E -A6 -m3 '(^|\s)(Error|error|Failed|failed)\b|Type error' "${clean}" | head -n 20)" ;;
  *)
    # The thrown error's message: the line that starts with it and the lines after.
    message="$(grep -E -A4 -m2 '^[A-Za-z]*Error\b|Refusing|refused' "${clean}" | head -n 12)" ;;
esac
message="${message:-$(tail -n 12 "${clean}")}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## ${heading}"
    echo
    echo "opentidehq/website syncs \`docs/\` every hour; with this change its sync would fail and the site would stop updating."
    echo "The site's \`content/docs/<page>.mdx\` (or \`<page>.mdx\`) is this repository's \`docs/<page>.md\`."
    echo
    echo '```'
    echo "${message}"
    echo '```'
    echo
    echo "<details><summary>The last 40 lines of <code>${command[*]}</code></summary>"
    echo
    echo '```'
    tail -n 40 "${clean}"
    echo '```'
    echo "</details>"
  } >> "${GITHUB_STEP_SUMMARY}"
fi
# One annotation; its message's newlines and % are escaped as workflow commands need.
escaped="$(printf '%s' "${message}" | sed -e 's/%/%25/g' -e 's/\r/%0D/g' | sed -e ':a;N;$!ba;s/\n/%0A/g')"
echo "::error title=${title}::${escaped}"
exit 1
