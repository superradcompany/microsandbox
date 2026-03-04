# Build agentd as a static Linux binary via Docker.
build-agentd:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p build
    docker build -f Dockerfile.agentd -t microsandbox-agentd-build .
    id=$(docker create microsandbox-agentd-build /dev/null)
    docker cp "$id:/microsandbox-agentd" build/microsandbox-agentd
    docker rm "$id" > /dev/null
    echo "build/microsandbox-agentd"

# Clean build artifacts.
clean:
    rm -rf build
