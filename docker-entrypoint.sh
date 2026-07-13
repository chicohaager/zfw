#!/bin/sh
# Entrypoint of the ZFW installer image. See the header of the Dockerfile for
# why ZFW is installed onto the host rather than run inside this container.
#
# The job: stage the payload somewhere the host can see, then run the ordinary
# install.sh inside the HOST's namespaces via nsenter. install.sh is used
# unmodified — the same script the release tarball ships — so there is exactly
# one install path to reason about, and it ends with ZFW running on the host as
# a sysext with its dead-man and boot-persistence intact.
set -eu

say() { echo "[zfw-installer] $*"; }
die() { echo "[zfw-installer] ERROR: $*" >&2; exit 1; }

# `uninstall`/`help` are not implemented here on purpose: removing ZFW is
# `zfw revert` on the host followed by deleting /var/lib/extensions/zfw.raw, and
# hiding that behind a container verb would obscure what is actually happening
# to the firewall. Any argument is passed through to install.sh.

# --- preflight ---
# Missing *flags* are reported before missing *host capabilities*: "you forgot
# --privileged" is actionable, "your host does not support sysext" is a dead end,
# and an operator who has forgotten a flag should not be told the second thing.
[ -d /host ] || die "host filesystem not mounted. Re-run with:
  docker run --rm --privileged --pid=host -v /:/host <image>"

[ -e /proc/1/ns/mnt ] || die "cannot see the host's PID 1 — the --pid=host flag is missing. Re-run with:
  docker run --rm --privileged --pid=host -v /:/host <image>"

# Entering the host's mount namespace needs privileges the default container does
# not have. Probe it now, so the failure names the flag instead of surfacing as
# an opaque nsenter error halfway through.
nsenter -t 1 -m -u -i -n -p -- true 2>/dev/null \
  || die "cannot enter the host namespaces — the --privileged flag is missing. Re-run with:
  docker run --rm --privileged --pid=host -v /:/host <image>"

[ -d /host/var/lib/extensions ] || die "/host/var/lib/extensions missing — this host does not support systemd-sysext, which is how ZFW is installed. ZFW targets ZimaOS; see https://github.com/chicohaager/zfw"

# --- stage the payload where the host can reach it ---
# The host's mount namespace cannot see this container's filesystem, so the
# payload has to be copied onto the host first. /run is tmpfs on the host: the
# staging directory disappears on reboot even if cleanup below is interrupted.
STAGE_REL="/run/zfw-install.$$"
STAGE="/host${STAGE_REL}"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT INT TERM

mkdir -p "$STAGE"
chmod 0700 "$STAGE"   # the engine script is about to be root-executed from here
cp /payload/zfw.raw /payload/zfw.raw.sha256 /payload/zfw /payload/install.sh "$STAGE/"

say "payload staged on the host at ${STAGE_REL}"
say "installing into the host's namespaces (systemd-sysext + zfw-ui.service)..."

# --- run the real installer on the host ---
# -m -u -i -n -p: mount, uts, ipc, net and pid namespaces of PID 1, i.e. the
# host proper. install.sh then sees the host's /var/lib/extensions, /DATA,
# systemd-sysext and systemctl exactly as if it had been unpacked from the
# release tarball and run over SSH.
nsenter -t 1 -m -u -i -n -p -- sh "${STAGE_REL}/install.sh" "$@"

say "done — ZFW is installed on the host, not in this container."
say "This container has now exited; ZFW runs as zfw-ui.service (systemd-sysext)."
