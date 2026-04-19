#!/bin/bash
# Defines and enforce max threshold for agentd boot and init sequence useful in CI
set -e

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BOOT_TIME_THRESHOLD_NS=100000000
INIT_TIME_THRESHOLD_NS=100000000

echo "Testing boot performance..."

export PATH="$HOME/.microsandbox/bin:$PATH"

trap '
  echo "Cleaning up timing-test..."
  msb stop timing-test || true
  msb remove timing-test || true
' EXIT

if ! RUST_LOG=info msb create alpine --name timing-test --info 2>&1 | tee /tmp/timing.log; then
  echo "ERROR: msb create failed"
  cat /tmp/timing.log
  exit 1
fi

BOOT_TIME=$(grep -m1 "agent client: connected to relay" /tmp/timing.log | grep -o 'boot_time=[0-9]*' | cut -d= -f2)
INIT_TIME=$(grep -m1 "agent client: connected to relay" /tmp/timing.log | grep -o 'init_time=[0-9]*' | cut -d= -f2)

if [ -z "$BOOT_TIME" ] || [ -z "$INIT_TIME" ]; then
  echo "ERROR: Could not parse timing metrics"
  cat /tmp/timing.log
  exit 1
fi

echo "Boot time: ${BOOT_TIME}ns"
echo "Init time: ${INIT_TIME}ns"

if [ "$BOOT_TIME" -gt "$BOOT_TIME_THRESHOLD_NS" ]; then
  echo "ERROR: Boot time exceeded threshold"
  exit 1
fi

if [ "$INIT_TIME" -gt "$INIT_TIME_THRESHOLD_NS" ]; then
  echo "ERROR: Init time exceeded threshold"
  exit 1
fi

echo "Boot performance test passed!"
