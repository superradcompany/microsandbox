#!/usr/bin/env bash
# Guard against node-ts SDK docs drift (issue #590).
#
# The node-ts public API surface is captured by sdk/node-ts/native/index.d.ts,
# generated deterministically by NAPI-RS from the #[napi] annotations in
# sdk/node-ts/native/*.rs. When a PR changes that file, the TypeScript SDK
# reference under docs/sdk/typescript/ must be updated in the same PR.
#
# Usage: check-node-sdk-docs-drift.sh <base-ref> [head-ref]
#   Diffs merge-base(base-ref, head-ref)..head-ref. head-ref defaults to HEAD.
#
# Escape hatches for API changes that genuinely need no docs update:
#   - apply the `docs-skip` label to the PR (CI passes DOCS_SKIP=true), or
#   - add a `docs-skip: <reason>` trailer to any commit in the PR.

set -euo pipefail

BASE="${1:?usage: check-node-sdk-docs-drift.sh <base-ref> [head-ref]}"
HEAD="${2:-HEAD}"

API_FILE="sdk/node-ts/native/index.d.ts"
DOCS_PATTERN='^docs/sdk/typescript(/|\.mdx$)'

MERGE_BASE="$(git merge-base "$BASE" "$HEAD")"
CHANGED="$(git diff --name-only "$MERGE_BASE" "$HEAD")"

if ! grep -qxF "$API_FILE" <<<"$CHANGED"; then
  echo "OK: $API_FILE unchanged; no docs update required."
  exit 0
fi

if grep -qE "$DOCS_PATTERN" <<<"$CHANGED"; then
  echo "OK: node-ts API surface and TypeScript SDK docs both updated."
  exit 0
fi

if [[ "${DOCS_SKIP:-}" == "true" ]]; then
  echo "OK: docs check skipped via docs-skip label."
  exit 0
fi

if git log --format=%B "$MERGE_BASE..$HEAD" | grep -qiE '^docs-skip:'; then
  echo "OK: docs check skipped via docs-skip commit trailer."
  exit 0
fi

echo "::error::node-ts public API changed ($API_FILE) without a matching update under docs/sdk/typescript/"
echo
echo "This PR changes the node-ts SDK public surface but does not touch the"
echo "TypeScript SDK reference docs. Update the relevant page(s) under"
echo "docs/sdk/typescript/, or — if this API change genuinely needs no docs"
echo "update — apply the 'docs-skip' PR label or add a 'docs-skip: <reason>'"
echo "trailer to a commit."
echo
echo "Changed declarations in $API_FILE:"
echo "-----------------------------------------------------------------------"
# Full diff of the .d.ts so the author can locate the affected exports;
# capped to keep the log readable on large regenerations.
git diff "$MERGE_BASE" "$HEAD" -- "$API_FILE" | sed -n '5,404p'
if [[ "$(git diff "$MERGE_BASE" "$HEAD" -- "$API_FILE" | wc -l)" -gt 404 ]]; then
  echo "... (truncated; run: git diff $MERGE_BASE $HEAD -- $API_FILE)"
fi
exit 1
