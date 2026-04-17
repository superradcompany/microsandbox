FROM ubuntu:24.04

LABEL org.opencontainers.image.source="https://github.com/superradcompany/microsandbox"
LABEL org.opencontainers.image.description="Secure microVM sandboxes for running untrusted code"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

COPY build/${TARGETARCH}/msb /usr/local/bin/msb
COPY build/${TARGETARCH}/libkrunfw.so.* /usr/local/lib/

ENV LD_LIBRARY_PATH="/usr/local/lib"

ENTRYPOINT ["msb"]
CMD ["--help"]
