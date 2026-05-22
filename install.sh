#!/bin/sh
# install.sh — install or update the ZFW host firewall on a ZimaOS host.
#
# Run this ON the ZimaOS host as root:
#   sh install.sh
# (or, as the unprivileged user:  echo '<password>' | sudo -S sh install.sh)
#
# It installs two pieces and starts the service:
#   1. the sysext module   -> /var/lib/extensions/zfw.raw
#   2. the firewall engine -> /DATA/zfw/zfw   (root:root, 0700)
# then merges the sysext and (re)starts zfw-ui.service. Re-running it
# updates an existing install in place.
set -eu

NAME="zfw"
EXT_DIR="/var/lib/extensions"
ENGINE_DIR="/DATA/zfw"
SERVICE="zfw-ui.service"

say() { echo "[zfw-install] $*"; }
die() { echo "[zfw-install] ERROR: $*" >&2; exit 1; }

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

# find_file echoes the first candidate path that exists, or dies.
find_file() {
	desc="$1"
	shift
	for p in "$@"; do
		[ -f "$p" ] && { echo "$p"; return 0; }
	done
	die "$desc not found (looked in: $*)"
}

# The build bundle (dist/) keeps both payload files next to this script;
# the source repo keeps them in dist/ and engine/. Support both layouts.
RAW="$(find_file 'module zfw.raw' "$SELF_DIR/zfw.raw" "$SELF_DIR/dist/zfw.raw")"
ENGINE="$(find_file 'engine script zfw' "$SELF_DIR/zfw" "$SELF_DIR/engine/zfw")"

# --- preflight ---
[ "$(id -u)" -eq 0 ] || die "must run as root — try:  sudo sh $0"
command -v systemd-sysext >/dev/null 2>&1 || die "systemd-sysext not found"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
[ -d "$EXT_DIR" ] || die "$EXT_DIR missing — host does not support systemd-sysext"

say "module : $RAW"
say "engine : $ENGINE"

# --- verify the module checksum when the .sha256 is shipped alongside ---
if [ -f "$RAW.sha256" ] && command -v sha256sum >/dev/null 2>&1; then
	( cd "$(dirname "$RAW")" && sha256sum -c "$(basename "$RAW").sha256" >/dev/null ) \
		&& say "checksum OK" || die "checksum mismatch on $RAW"
fi

# --- 1. sysext module (atomic replace) ---
cp "$RAW" "$EXT_DIR/$NAME.raw.tmp"
chmod 0644 "$EXT_DIR/$NAME.raw.tmp"
mv "$EXT_DIR/$NAME.raw.tmp" "$EXT_DIR/$NAME.raw"
say "module installed -> $EXT_DIR/$NAME.raw"

# --- 2. firewall engine: root-owned and root-only — it is executed as root,
#        so a non-root-writable path here would be a privilege-escalation hole.
mkdir -p "$ENGINE_DIR"
chown root:root "$ENGINE_DIR"
chmod 0700 "$ENGINE_DIR"
cp "$ENGINE" "$ENGINE_DIR/$NAME.tmp"
chown root:root "$ENGINE_DIR/$NAME.tmp"
chmod 0700 "$ENGINE_DIR/$NAME.tmp"
mv "$ENGINE_DIR/$NAME.tmp" "$ENGINE_DIR/$NAME"
say "engine installed -> $ENGINE_DIR/$NAME (root:root 0700)"

# --- 3. merge the sysext overlay and (re)start the service ---
say "merging sysext overlay..."
systemd-sysext refresh
systemctl daemon-reload
# enable is best-effort: boot-persistence is actually provided by the
# zfw-ui-watchdog timer the daemon installs into /etc on first start
# (a unit that lives only in the sysext loses the boot race otherwise).
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"

# --- 4. verify ---
sleep 2
systemctl is-active --quiet "$SERVICE" || {
	systemctl --no-pager --lines=20 status "$SERVICE" || true
	die "$SERVICE did not start — see the status output above"
}
say "done — $SERVICE is active"
say "open the ZFW Firewall tile in the ZimaOS dashboard, or browse to"
say "  http://<this-host>/modules/zfw/index.html"
