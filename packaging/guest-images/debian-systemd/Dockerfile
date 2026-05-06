ARG DEBIAN_VERSION=bookworm
FROM debian:${DEBIAN_VERSION}

LABEL org.opencontainers.image.source="https://github.com/superradcompany/microsandbox"
LABEL org.opencontainers.image.description="Debian with systemd, ready for microsandbox --init auto"
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

# `systemd-sysv` already symlinks /sbin/init -> /lib/systemd/systemd, but be
# explicit so `--init auto` and `--init /sbin/init` both resolve.
CMD ["/lib/systemd/systemd"]
