#!/usr/bin/env bash
# Live integration checks. Use a dedicated MSB_HOME; only this script's named VMs are stopped.
set -euo pipefail
: "${MSB_BIN:?}" "${MSB_HOME:?}" "${QUAL_ROOT:?}"
mkdir -p "$QUAL_ROOT/logs"
names=()
msb() { "$MSB_BIN" "$@"; }
cleanup() { for name in "${names[@]}"; do msb stop "$name" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
now() { perl -MTime::HiRes=time -e 'printf "%.6f", time()'; }
measure() {
    local label=$1 start end
    shift
    start=$(now)
    if "$@" >"$QUAL_ROOT/logs/$label.out" 2>"$QUAL_ROOT/logs/$label.err"; then
        end=$(now)
        awk -v label="$label" -v start="$start" -v end="$end" 'BEGIN {printf "%s\tPASS\t%.3f\n",label,(end-start)*1000}' | tee -a "$QUAL_ROOT/results.tsv"
    else
        printf '%s\tFAIL\n' "$label" | tee -a "$QUAL_ROOT/results.tsv"
        cat "$QUAL_ROOT/logs/$label.err" >&2
        return 1
    fi
}
refuse() { if "$@"; then return 1; fi; }
guest() { local name=$1; shift; msb exec "$name" -- sh -c "$*"; }

for layout in managed flat; do
    name="${QUAL_PREFIX:-compact}-$layout"
    names+=("$name")
    spec=512M
    [ "$layout" != flat ] || spec=flat:512M
    measure "$layout-create" msb create -n "$name" --root-disk "$spec" -m 256M --max-duration 20m alpine
    measure "$layout-noop" msb modify "$name" --compact --format json
    measure "$layout-invalid-one" refuse msb modify "$name" --compact --layers 1
    measure "$layout-invalid-mixed" refuse msb modify "$name" --compact --cpus 1
    measure "$layout-seed" guest "$name" 'dd if=/dev/urandom of=/payload bs=1048576 count=8 2>/dev/null; sha256sum /payload >/expected; printf 1 >/version; mkdir -p /dev/shm; echo volatile >/dev/shm/ram-marker; sync'
    for generation in 1 2 3 4; do
        measure "$layout-write-$generation" guest "$name" "printf $generation >/version; sync"
        measure "$layout-checkpoint-$generation" msb snapshot create "$name-$generation" --from "$name" --full
    done
    measure "$layout-dry-run" msb modify "$name" --compact --layers 3 --dry-run --format json
    measure "$layout-dry-run-counts" jq -e '.dry_run and .input_layers == 5 and .selected_layers == 3 and .output_layers == 3' "$QUAL_ROOT/logs/$layout-dry-run.out"
    measure "$layout-invalid-large" refuse msb modify "$name" --compact --layers 99
    measure "$layout-save-complete" msb snapshot save "$name-4" "$QUAL_ROOT/$layout-complete.tar.zst"
    measure "$layout-save-since" msb snapshot save "$name-4" "$QUAL_ROOT/$layout-delta.tar.zst" --since "$name-2"
    measure "$layout-save-last" msb snapshot save "$name-4" "$QUAL_ROOT/$layout-last.tar" --last-layers 2 --plain-tar
    measure "$layout-save-base" msb snapshot save "$name-2" "$QUAL_ROOT/$layout-base.tar.zst"
    measure "$layout-invalid-last-zero" refuse msb snapshot save "$name-4" "$QUAL_ROOT/invalid.tar" --last-layers 0
    measure "$layout-missing-base" refuse msb snapshot load "$QUAL_ROOT/$layout-delta.tar.zst" "$QUAL_ROOT/$layout-missing"
    measure "$layout-wrong-base" refuse msb snapshot load "$QUAL_ROOT/$layout-delta.tar.zst" "$QUAL_ROOT/$layout-wrong" --base "$name-1"
    measure "$layout-load-delta" msb snapshot load "$QUAL_ROOT/$layout-delta.tar.zst" "$QUAL_ROOT/$layout-import" --base "$name-2"
    measure "$layout-load-base-archive" msb snapshot load "$QUAL_ROOT/$layout-last.tar" "$QUAL_ROOT/$layout-base-import" --base "$QUAL_ROOT/$layout-base.tar.zst"

    # A long-running agentd-managed writer remains active across preparation and the switch.
    msb exec "$name" -- sh -c 'i=0; while [ ! -e /writer-stop ]; do i=$((i+1)); echo "$i" >>/writes; sync; done' >"$QUAL_ROOT/logs/$layout-writer.out" 2>"$QUAL_ROOT/logs/$layout-writer.err" &
    writer=$!
    measure "$layout-online-compact" msb modify "$name" --compact --layers 3 --format json
    measure "$layout-stop-writer" guest "$name" 'touch /writer-stop; sync'
    wait "$writer"
    measure "$layout-data-after" guest "$name" 'sha256sum -c /expected && test "$(cat /version)" = 4 && awk "NR != \$1 {exit 1} END {if (NR == 0) exit 1}" /writes'
    measure "$layout-online-counts" jq -e '.input_layers == 5 and .output_layers == 3 and .selected_layers == 3' "$QUAL_ROOT/logs/$layout-online-compact.out"
    measure "$layout-stop" msb stop "$name"
    measure "$layout-offline-compact" msb modify "$name" --compact --format json
    measure "$layout-stopped-snapshot" msb snapshot create "$name-stopped" --from "$name" --integrity
    measure "$layout-stopped-verify" msb snapshot verify "$name-stopped"
    measure "$layout-restart" msb start "$name"
    measure "$layout-restarted-data" guest "$name" 'sha256sum -c /expected && test "$(cat /version)" = 4'
    measure "$layout-post-compact-checkpoint" msb snapshot create "$name-new" --from "$name" --full
    measure "$layout-old-prefix-rejected" refuse msb snapshot save "$name-new" "$QUAL_ROOT/invalid.tar" --since "$name-4"
    measure "$layout-stop-source" msb stop "$name"

    for variant in old full disk stopped; do
        child="$name-$variant-child"
        names+=("$child")
        case "$variant" in
            old) args=(--from-snapshot "$name-2"); version=2;;
            full) args=(--from-snapshot "$QUAL_ROOT/$layout-delta.tar.zst" --snapshot-base "$name-2"); version=4;;
            disk) args=(--from-snapshot "$QUAL_ROOT/$layout-last.tar" --snapshot-base "$QUAL_ROOT/$layout-base.tar.zst" --disk-only); version=4;;
            stopped) args=(--from-snapshot "$name-stopped"); version=4;;
        esac
        measure "$layout-restore-$variant" msb create -n "$child" "${args[@]}"
        measure "$layout-restored-$variant-data" guest "$child" "sha256sum -c /expected && test \"\$(cat /version)\" = $version"
        case "$variant" in
            old|full) measure "$layout-restored-$variant-memory" guest "$child" 'test $(cat /dev/shm/ram-marker) = volatile';;
            disk|stopped) measure "$layout-restored-$variant-cold" guest "$child" 'test ! -e /dev/shm/ram-marker';;
        esac
        measure "$layout-stop-$variant" msb stop "$child"
    done
done
printf 'Live compaction/export checks passed. Timings: %s/results.tsv\n' "$QUAL_ROOT"
