#!/usr/bin/env bash
# Exercise catalog ownership with an actual 0.6.18 bundle and a candidate CLI.
# Both bundles must be installed beforehand; this test never invokes an installer.
set -euo pipefail

: "${MSB_CATALOG_OLD_BIN:?set the actual v0.6.18 executable path}"
: "${MSB_CATALOG_OLD_FW:?set its matching libkrunfw path}"
: "${MSB_CATALOG_NEW_BIN:?set the candidate executable path}"
: "${MSB_CATALOG_NEW_FW:?set its matching libkrunfw path}"
if ! command -v sqlite3 >/dev/null; then
    command -v python3 >/dev/null
fi

# Keep paths short enough for historical Unix socket names. Never use the real home.
test_home=$(mktemp -d /tmp/msb-cat.XXXXXX)
export MSB_HOME="$test_home"
unset MSB_API_KEY MSB_API_URL
printf 'Isolated catalog test home: %s\n' "$test_home"

old() {
    env MSB_PATH="$MSB_CATALOG_OLD_BIN" MSB_LIBKRUNFW_PATH="$MSB_CATALOG_OLD_FW" "$MSB_CATALOG_OLD_BIN" "$@"
}
current() {
    env MSB_PATH="$MSB_CATALOG_NEW_BIN" MSB_LIBKRUNFW_PATH="$MSB_CATALOG_NEW_FW" "$MSB_CATALOG_NEW_BIN" "$@"
}
sql() {
    if command -v sqlite3 >/dev/null; then
        sqlite3 "$test_home/db/msb.db" "$1"
    else
        # Minimal Linux development images may only have Python's SQLite module.
        python3 - "$test_home/db/msb.db" "$1" <<'PY'
import pathlib
import sqlite3
import sys

with sqlite3.connect(pathlib.Path(sys.argv[1]).as_uri() + "?mode=ro", uri=True) as db:
    for row in db.execute(sys.argv[2]):
        print("|".join("" if value is None else str(value) for value in row))
PY
    fi
}
cleanup() {
    for name in catalog-seed catalog-restored; do
        current stop "$name" >/dev/null 2>&1 || true
        current rm "$name" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

old create alpine:3.21 --name catalog-seed --memory 256M --cpus 1 --max-duration 5m
old exec catalog-seed -- sh -c 'echo catalog-persistent-marker > /root/catalog-marker'
test "$(sql 'SELECT COUNT(*) FROM seaql_migrations')" = 25
history=$(sql 'SELECT version FROM seaql_migrations ORDER BY version')

# The owning CLI must neither migrate beneath a running old VM nor make stop unusable.
if current run alpine:3.21 -- true >"$test_home/active-refusal.log" 2>&1; then
    printf 'FAIL: upgraded a catalog while its old sandbox was running\n' >&2
    exit 1
fi
grep -F 'catalog upgrade requires stopped sandboxes' "$test_home/active-refusal.log"
test "$(sql 'SELECT version FROM seaql_migrations ORDER BY version')" = "$history"
test "$(old exec catalog-seed -- cat /root/catalog-marker)" = catalog-persistent-marker
current stop catalog-seed

# Concurrent first uses serialize migration, and the stopped sandbox's disk survives it.
current run alpine:3.21 -- sh -c 'echo upgrade-a-ok' >"$test_home/start-a.log" 2>&1 &
first=$!
current run alpine:3.21 -- sh -c 'echo upgrade-b-ok' >"$test_home/start-b.log" 2>&1 &
second=$!
wait "$first"
wait "$second"
grep -F upgrade-a-ok "$test_home/start-a.log"
grep -F upgrade-b-ok "$test_home/start-b.log"
test "$(sql 'SELECT COUNT(*) FROM seaql_migrations')" = 27
current start catalog-seed
test "$(current exec catalog-seed -- cat /root/catalog-marker)" = catalog-persistent-marker
current stop catalog-seed

# Exercise the newly enabled snapshot/index path, not just a migration count.
current snapshot create saved --from-sandbox catalog-seed -o "$test_home/saved.msnap"
current restore "$test_home/saved.msnap" --name catalog-restored
test "$(current exec catalog-restored -- cat /root/catalog-marker)" = catalog-persistent-marker
cleanup
test "$(sql 'SELECT COUNT(*) FROM sandbox')" = 0
trap - EXIT
printf 'PASS: active refusal, usable stop, concurrent upgrade, persistent disk, archive restore, cleanup\n'
