ARG ALPINE_VERSION=3.20
FROM alpine:${ALPINE_VERSION}

LABEL org.opencontainers.image.source="https://github.com/superradcompany/microsandbox"
LABEL org.opencontainers.image.description="Alpine with OpenRC + BusyBox init, an alternative to systemd for microsandbox --init"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Alpine's /sbin/init is BusyBox init reading /etc/inittab; OpenRC drives
# the runlevels via that. busybox-openrc registers OpenRC compatible
# init scripts; openrc itself provides rc-service / rc-update.
RUN apk add --no-cache \
        openrc \
        busybox-openrc \
        dbus \
        ca-certificates

CMD ["/sbin/init"]
