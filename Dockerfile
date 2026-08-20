# ZFW installer image.
#
# THIS IMAGE IS A DELIVERY VEHICLE, NOT A RUNTIME.
#
# ZFW is a systemd-sysext module, not a containerised service. The daemon runs
# on the host as `zfw-ui.service`, and its engine drives the host's iptables and
# — crucially — arms the Safe-Apply dead-man via `systemd-run`. A ZFW running
# *inside* a container would have no host systemd to arm that timer with, so the
# one promise the whole design rests on ("a bad rule can never lock you out")
# would silently not exist. We do not ship that.
#
# So this image carries the release payload and installs it onto the host,
# through `nsenter` into the host's own namespaces, where install.sh runs exactly
# as it does from the release tarball. After it finishes, the container is gone
# and ZFW lives on the host as a sysext — dead-man and boot-persistence intact.
#
# Usage (on the ZimaOS host):
#
#   docker run --rm --privileged --pid=host -v /:/host chicohaager/zfw:1.0.24
#
#   --privileged  the payload is installed as root and drives systemd-sysext
#   --pid=host    lets nsenter find PID 1 to enter the host's namespaces
#   -v /:/host    the host filesystem the payload is staged into
#
# The image is multi-arch: each architecture carries the .raw built for it, so
# `docker run` on an arm64 host pulls the arm64 module.

FROM alpine:3.21

# util-linux supplies nsenter; the rest of install.sh needs only a POSIX shell,
# coreutils and sha256sum, which busybox already provides.
RUN apk add --no-cache util-linux

# TARGETARCH is set by buildx per platform (amd64 / arm64) and selects the
# matching module. Nothing is executed at build time, so no emulation is needed.
ARG TARGETARCH

WORKDIR /payload
COPY dist/zfw-${TARGETARCH}.raw        /payload/zfw.raw
COPY dist/zfw-${TARGETARCH}.raw.sha256 /payload/zfw.raw.sha256.orig
COPY engine/zfw                        /payload/zfw
COPY install.sh                        /payload/install.sh
COPY docker-entrypoint.sh              /usr/local/bin/docker-entrypoint.sh

# The build writes the .sha256 with the per-arch filename in it (e.g.
# "…  zfw-amd64.raw"), but the payload is staged as the generic "zfw.raw" that
# install.sh looks for. Rewrite the filename so `sha256sum -c` still verifies
# the module rather than being skipped with a warning.
RUN sed -E 's/ +zfw-[a-z0-9]+\.raw$/  zfw.raw/' /payload/zfw.raw.sha256.orig > /payload/zfw.raw.sha256 \
 && rm /payload/zfw.raw.sha256.orig \
 && chmod 0755 /payload/install.sh /payload/zfw /usr/local/bin/docker-entrypoint.sh \
 && cd /payload && sha256sum -c zfw.raw.sha256

LABEL org.opencontainers.image.title="ZFW Firewall (host installer)" \
      org.opencontainers.image.description="Installer for ZFW, the host firewall for ZimaOS. This image installs a systemd-sysext module onto the host; it is not a long-running service." \
      org.opencontainers.image.source="https://github.com/chicohaager/zfw" \
      org.opencontainers.image.licenses="ISC"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
