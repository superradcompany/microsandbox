#!/usr/bin/env bash
# Live delayed restore, including the first sample from the captured application.
# Build checkpoint-clock-probe.rs as a static musl executable for the guest architecture, then
# supply MSB_PATH, MSB_HOME, MSB_LIBKRUNFW_PATH, CLOCK_PROBE, CLOCK_OUT and a unique CLOCK_PREFIX.
# Optional: CLOCK_LAYOUT=1G (managed), CLOCK_INCREMENTAL=1, CLOCK_ARCHIVE=1, CLOCK_CPUS=1.
set -euo pipefail
: "${MSB_PATH:?}" "${MSB_HOME:?}" "${MSB_LIBKRUNFW_PATH:?}" "${CLOCK_PROBE:?}" "${CLOCK_OUT:?}" "${CLOCK_PREFIX:?}"
mkdir -p "$CLOCK_OUT"
msb() { "$MSB_PATH" "$@"; }
source_name="$CLOCK_PREFIX-source"
child="$CLOCK_PREFIX-child"
trap 'msb stop "$source_name" >/dev/null 2>&1 || true; msb stop "$child" >/dev/null 2>&1 || true' EXIT
msb run -d -n "$source_name" --root-disk "${CLOCK_LAYOUT:-flat:1G}" --cpus "${CLOCK_CPUS:-4}" --memory 512M alpine -- /bin/sh -c 'while [ ! -x /clock-probe ]; do sleep 0.05; done; exec /clock-probe' >"$CLOCK_OUT/run.out" 2>"$CLOCK_OUT/run.err"
msb copy "$CLOCK_PROBE" "$source_name:/clock-probe"
msb exec "$source_name" -- chmod +x /clock-probe
for _ in $(seq 1 30); do
  if msb exec "$source_name" -- test -s /tmp/clock-records.csv; then break; fi
  sleep 0.05
done
msb snapshot create "$CLOCK_PREFIX-full" --from "$source_name" --full --info >"$CLOCK_OUT/capture.out" 2>"$CLOCK_OUT/capture.err"
snapshot="$CLOCK_PREFIX-full"
if [ "${CLOCK_INCREMENTAL:-0}" = 1 ]; then
  msb snapshot create "$CLOCK_PREFIX-next" --from "$source_name" --full --info >"$CLOCK_OUT/capture-next.out" 2>"$CLOCK_OUT/capture-next.err"
  snapshot="$CLOCK_PREFIX-next"
fi
if [ "${CLOCK_ARCHIVE:-0}" = 1 ]; then
  msb snapshot save "$snapshot" "$CLOCK_OUT/clock.tar.zst"
  snapshot="$CLOCK_OUT/clock.tar.zst"
fi
msb stop "$source_name"
sleep "${CLOCK_DELAY:-8}"
perl -MTime::HiRes=time -e 'printf "%.0f\n", time()*1e9' >"$CLOCK_OUT/restore-start.ns"
msb create -n "$child" --from-snapshot "$snapshot" --info >"$CLOCK_OUT/restore.out" 2>"$CLOCK_OUT/restore.err"
perl -MTime::HiRes=time -e 'printf "%.0f\n", time()*1e9' >"$CLOCK_OUT/restore-end.ns"
sleep 6
msb exec "$child" -- cat /tmp/clock-records.csv >"$CLOCK_OUT/records.csv"
msb stop "$child"
python3 "$(dirname "$0")/checkpoint-clock-analyze.py" "$CLOCK_OUT"
