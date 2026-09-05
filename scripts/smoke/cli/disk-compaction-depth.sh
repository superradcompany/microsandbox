#!/usr/bin/env bash
set -euo pipefail
: "${MSB_BIN:?}" "${MSB_HOME:?}" "${QUAL_ROOT:?}"
mkdir -p "$QUAL_ROOT"
names=()
msb() { "$MSB_BIN" "$@"; }
cleanup() { for name in "${names[@]}"; do msb stop "$name" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
for layout in managed flat; do
 name="compact-depth-$layout"; names+=("$name"); spec=512M
 [ "$layout" != flat ] || spec=flat:512M
 msb create -n "$name" --root-disk "$spec" -m 128M --max-duration 30m alpine >/dev/null
 msb exec "$name" -- sh -c 'dd if=/dev/urandom of=/payload bs=1048576 count=4 2>/dev/null; sha256sum /payload >/expected; sync'
 for generation in $(seq 1 64); do
  msb exec "$name" -- sh -c "echo $generation >/version; sync" >/dev/null
  msb snapshot create "$name-$generation" --from "$name" --full >"$QUAL_ROOT/$layout-$generation.out" 2>&1
  case $generation in 1|4|16|64)
   msb modify "$name" --compact --dry-run --format json >"$QUAL_ROOT/$layout-depth-$generation.json"
   msb exec "$name" -- sh -c 'sha256sum -c /expected' >/dev/null;;
  esac
 done
 msb modify "$name" --compact --layers 32 --format json | tee "$QUAL_ROOT/$layout-compact-32.json"
 msb exec "$name" -- sh -c 'sha256sum -c /expected && test $(cat /version) = 64 && echo durable >/after && sync'
 msb stop "$name" >/dev/null
 msb modify "$name" --compact --format json | tee "$QUAL_ROOT/$layout-compact-all.json"
 msb start "$name" >/dev/null
 msb exec "$name" -- sh -c 'sha256sum -c /expected && test $(cat /version) = 64 && test $(cat /after) = durable'
 msb stop "$name" >/dev/null
 child="$name-child"; names+=("$child")
 msb create -n "$child" --from-snapshot "$name-16" >/dev/null
 msb exec "$child" -- sh -c 'sha256sum -c /expected && test $(cat /version) = 16'
 msb stop "$child" >/dev/null
 printf '%s depth 1/4/16/64, 65->34->2 layers, restart and old restore PASS\n' "$layout" | tee -a "$QUAL_ROOT/results.txt"
done
