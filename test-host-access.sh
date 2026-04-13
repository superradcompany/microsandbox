#!/bin/bash
set -euo pipefail

# Test host access from microsandbox
echo "=== Testing microsandbox host access ==="

# First test direct host access
echo -e "\n1. Testing host webserver directly:"
if curl -s --connect-timeout 3 http://localhost:4343; then
    echo -e "\n✅ Host server is running"
else
    echo -e "\n⚠️  Host server not running on port 4343. You can start one with:"
    echo "   node -e \"require('http').createServer((_,res)=>res.end('hello world')).listen(4343,'0.0.0.0')\""
fi

MSB_PATH="$HOME/projects/microsandbox/target/debug/msb"

if [ ! -x "$MSB_PATH" ]; then
    echo -e "\n❌ msb binary not found at $MSB_PATH"
    exit 1
fi

echo -e "\n2. Running curl from inside microsandbox (using gateway IP as host alias):"
echo "   Using network policy: allow-all"

# The guest cannot reach host services via 127.0.0.1 (that's the guest's own loopback).
# Instead, use the gateway IP (from the default route) as an alias for the host.
# smoltcp intercepts the connection via any_ip=true and rewrites the gateway IP to
# 127.0.0.1 on the host side before dialing, so host services are reachable.
"$MSB_PATH" run \
    --network-policy allow-all \
    docker.io/node:20 \
    -- sh -c 'GW=$(grep nameserver /etc/resolv.conf | head -1 | awk "{print \$2}"); echo "  Gateway (host alias): $GW"; curl -s --connect-timeout 5 http://$GW:4343'

echo -e "\n✅ Done. If this printed the hello world response it's working correctly."
