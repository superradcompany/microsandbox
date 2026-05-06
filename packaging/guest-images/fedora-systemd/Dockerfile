ARG FEDORA_VERSION=40
FROM fedora:${FEDORA_VERSION}

LABEL org.opencontainers.image.source="https://github.com/superradcompany/microsandbox"
LABEL org.opencontainers.image.description="Fedora with systemd, ready for microsandbox --init auto"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Fedora ships systemd by default; ensure dbus and ca-certificates are present
# and bring the package set up to date.
RUN dnf install -y systemd dbus ca-certificates \
    && dnf upgrade --refresh -y \
    && dnf clean all \
    && rm -rf /var/cache/dnf/*

CMD ["/usr/lib/systemd/systemd"]
