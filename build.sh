#!/bin/sh
# Build a zfw.raw sysext module from this repo.
# Requirements on the build host:
#   - go 1.22+
#   - squashfs-tools (mksquashfs)
# Output: dist/zfw.raw + dist/zfw.raw.sha256
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/dist"
RAW="$ROOT/raw"
NAME="zfw"
VERSION="${VERSION:-$(cat "$ROOT/VERSION" 2>/dev/null || echo dev)}"

echo "=== zfw module build ==="
echo "Version: $VERSION"

# 1. Format-check, vet, test, then compile the Go daemon (cgo-free, static).
echo "[1/4] gofmt + go vet + test + build..."
mkdir -p "$RAW/usr/bin"
cd "$ROOT"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "  ERROR: gofmt needed for:" >&2
  echo "$unformatted" >&2
  exit 1
fi
go vet ./...
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build \
    -trimpath \
    -ldflags="-s -w -X github.com/chicohaager/zfw/internal/buildinfo.Version=$VERSION" \
    -o "$RAW/usr/bin/zfwd" \
    ./cmd/zfwd
chmod +x "$RAW/usr/bin/zfwd"
echo "  -> $(ls -lh "$RAW/usr/bin/zfwd" | awk '{print $5}')"

# 2. Verify the sysext / CasaOS layout.
echo "[2/4] Verifying layout..."
required="
$RAW/usr/lib/extension-release.d/extension-release.$NAME
$RAW/usr/lib/systemd/system/zfw-ui.service
$RAW/usr/share/casaos/modules/$NAME.json
$RAW/usr/share/casaos/www/modules/$NAME/index.html
$RAW/usr/share/casaos/www/modules/$NAME/app.js
$RAW/usr/share/casaos/www/modules/$NAME/styles.css
$RAW/usr/share/casaos/www/modules/$NAME/appicon.svg
$RAW/usr/bin/zfwd
"
missing=0
for f in $required; do
  if [ ! -e "$f" ]; then
    echo "  MISSING: $f"
    missing=1
  fi
done
[ $missing -eq 0 ] || { echo "Layout incomplete, aborting."; exit 1; }

# 3. Pack as squashfs. ZimaOS kernel 6.12.x has no zstd/xz — gzip is mandatory.
echo "[3/4] Packing squashfs (gzip)..."
mkdir -p "$DIST"
rm -f "$DIST/$NAME.raw" "$DIST/$NAME.raw.sha256"
mksquashfs "$RAW" "$DIST/$NAME.raw" \
  -all-root \
  -comp gzip \
  -noappend \
  -no-progress \
  >/dev/null
( cd "$DIST" && sha256sum "$NAME.raw" > "$NAME.raw.sha256" )

# 4. Assemble the install bundle so dist/ is a self-contained installer:
#    the module, the engine script and install.sh side by side.
echo "[4/4] Assembling install bundle..."
cp "$ROOT/engine/zfw" "$DIST/zfw"
cp "$ROOT/install.sh" "$DIST/install.sh"
chmod 0755 "$DIST/zfw" "$DIST/install.sh"

echo
echo "=== Done ==="
ls -lh "$DIST/"
