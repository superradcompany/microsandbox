#!/usr/bin/env bash
set -euo pipefail
: "${MSB_BIN:?}" "${MSB_HOME:?}" "${QUAL_ROOT:?}" "${QUAL_SOURCE:?}"
mkdir -p "$QUAL_ROOT"
msb() { "$MSB_BIN" "$@"; }
cleanup() { msb stop compact-neg-tmpfs >/dev/null 2>&1 || true; msb stop compact-neg-owned >/dev/null 2>&1 || true; }
trap cleanup EXIT
refuse() { if "$@"; then echo 'unexpected success' >&2; exit 1; fi; }
msb create -n compact-neg-tmpfs --root-disk tmpfs:128M -m 256M --max-duration 5m alpine
refuse msb modify compact-neg-tmpfs --compact
msb snapshot create compact-neg-tmpfs-snap --from compact-neg-tmpfs --full
refuse msb snapshot save compact-neg-tmpfs-snap "$QUAL_ROOT/tmpfs.tar" --last-layers 1
msb stop compact-neg-tmpfs
cp "$MSB_HOME/sandboxes/$QUAL_SOURCE/upper.ext4" "$QUAL_ROOT/owned.ext4"
msb create -n compact-neg-owned --root-disk "$QUAL_ROOT/owned.ext4:format=raw,fstype=ext4" -m 256M --max-duration 5m alpine
refuse msb modify compact-neg-owned --compact
msb stop compact-neg-owned
refuse msb modify compact-neg-owned --compact
msb snapshot save "$QUAL_SOURCE-4" "$QUAL_ROOT/truncated.tar" --last-layers 2 --plain-tar
truncate -s 2048 "$QUAL_ROOT/truncated.tar"
refuse msb snapshot load "$QUAL_ROOT/truncated.tar" "$QUAL_ROOT/truncated-import" --base "$QUAL_SOURCE-2"
msb snapshot save "$QUAL_SOURCE-4" "$QUAL_ROOT/complete-last.tar" --last-layers 4 --plain-tar
msb snapshot load "$QUAL_ROOT/complete-last.tar" "$QUAL_ROOT/complete-last-import"
msb snapshot save "$QUAL_SOURCE-4" "$QUAL_ROOT/same.tar" --since "$QUAL_SOURCE-4" --plain-tar
msb snapshot load "$QUAL_ROOT/same.tar" "$QUAL_ROOT/same-import" --base "$QUAL_SOURCE-4"
echo 'tmpfs/user-owned rejection, truncated refusal, all-layer standalone and equal-base export PASS'
