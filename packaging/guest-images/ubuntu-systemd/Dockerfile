ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}

LABEL org.opencontainers.image.source="https://github.com/superradcompany/microsandbox"
LABEL org.opencontainers.image.description="Ubuntu with systemd, ready for microsandbox --init auto"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd \
        systemd-sysv \
        dbus \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

CMD ["/lib/systemd/systemd"]
