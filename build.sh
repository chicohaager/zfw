#!/bin/sh
# Build a zfw.raw sysext module from this repo.
# Requirements on the build host:
#   - go 1.22+
#   - squashfs-tools (mksquashfs)
#   - GNU tar (for the reproducible packaging flags)
# Optional (degrades gracefully if missing):
#   - github.com/CycloneDX/cyclonedx-gomod for SBOM generation
# Output: dist/zfw.raw + dist/zfw.raw.sha256 + dist/zfw-<v>.tar.gz [+ dist/sbom.json]
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/dist"
RAW="$ROOT/raw"
NAME="zfw"
VERSION="${VERSION:-$(cat "$ROOT/VERSION" 2>/dev/null || echo dev)}"

# SOURCE_DATE_EPOCH locks every timestamp (build embedded, tar entry mtimes,
# squashfs mkfs/all-time) to one fixed instant so two clean builds of the
# same source tree produce byte-identical artifacts. Default: the last
# commit's author date; if not in a git checkout, fall back to the VERSION
# file's mtime, which is stable across rebuilds of the same release.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  if SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --pretty=%ct 2>/dev/null)" && [ -n "$SOURCE_DATE_EPOCH" ]; then
    :
  else
    SOURCE_DATE_EPOCH="$(stat -c %Y "$ROOT/VERSION" 2>/dev/null || date +%s)"
  fi
fi
export SOURCE_DATE_EPOCH

echo "=== zfw module build ==="
echo "Version: $VERSION"
echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"

# 1. Format-check, vet, test, then compile the Go daemon (cgo-free, static).
echo "[1/4] gofmt + go vet + test + build..."
mkdir -p "$RAW/usr/bin"
cd "$ROOT"
# Single source of truth for the OpenAPI spec lives in docs/; the handlers
# package embeds it via //go:embed. Copy fresh on every build so the two
# copies cannot drift.
cp "$ROOT/docs/openapi.yaml" "$ROOT/internal/handlers/openapi.yaml"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "  ERROR: gofmt needed for:" >&2
  echo "$unformatted" >&2
  exit 1
fi
go vet ./...
go test ./...
# Flags chosen for reproducibility:
#   -trimpath:    strip the build host's filesystem layout from the binary
#   -buildvcs=false: don't embed git VCS info (commit hash, dirty flag)
#                    that would otherwise change every commit
#   -s -w:        drop the symbol and debug tables (also shrinks the binary)
#   -X Version=… : pin the version string
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build \
    -trimpath \
    -buildvcs=false \
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

# Lock every file in the squashfs payload to SOURCE_DATE_EPOCH so the
# resulting raw image hashes identically across rebuilds.
find "$RAW" -exec touch -d "@$SOURCE_DATE_EPOCH" {} +

# 3. Pack as squashfs. ZimaOS kernel 6.12.x has no zstd/xz — gzip is mandatory.
echo "[3/4] Packing squashfs (gzip, reproducible)..."
mkdir -p "$DIST"
rm -f "$DIST/$NAME.raw" "$DIST/$NAME.raw.sha256"
mksquashfs "$RAW" "$DIST/$NAME.raw" \
  -all-root \
  -comp gzip \
  -noappend \
  -no-progress \
  -no-exports \
  >/dev/null
  # Timestamps come from $SOURCE_DATE_EPOCH (exported above); mksquashfs
  # refuses to combine that env var with explicit -mkfs-time/-all-time.
( cd "$DIST" && sha256sum "$NAME.raw" > "$NAME.raw.sha256" )

# Optional SBOM. cyclonedx-gomod is small and Go-installable; if absent we
# print a hint instead of failing — the rest of the build is unaffected.
if command -v cyclonedx-gomod >/dev/null 2>&1; then
  echo "  generating CycloneDX SBOM..."
  cyclonedx-gomod app -json -licenses -output "$DIST/sbom.json" ./cmd/zfwd >/dev/null 2>&1 \
    && echo "  SBOM -> $DIST/sbom.json" \
    || echo "  WARN: cyclonedx-gomod failed; skipping SBOM"
else
  echo "  (SBOM skipped — install with: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest)"
fi

# 4. Pack the complete hand-off package: module + engine + installer + docs.
echo "[4/4] Packing release package (reproducible tar)..."
PKG="$NAME-$VERSION"
rm -rf "$DIST/$PKG"
rm -f "$DIST"/*.tar.gz "$DIST"/*.tar.gz.sha256
mkdir -p "$DIST/$PKG"
cp "$DIST/$NAME.raw" "$DIST/$NAME.raw.sha256" \
   "$ROOT/engine/zfw" "$ROOT/install.sh" \
   "$ROOT/README.md" "$ROOT/BEST-PRACTICES.md" "$ROOT/SECURITY-REPORT.md" \
   "$DIST/$PKG/"
[ -f "$DIST/sbom.json" ] && cp "$DIST/sbom.json" "$DIST/$PKG/sbom.json"
chmod 0755 "$DIST/$PKG/install.sh" "$DIST/$PKG/zfw"
# Lock mtimes on every file we just copied so the tar entries are identical
# across rebuilds.
find "$DIST/$PKG" -exec touch -d "@$SOURCE_DATE_EPOCH" {} +
# GNU-tar reproducible flags: fixed owner, sorted name order, locked mtime,
# strip extended attributes (atime/ctime) that would otherwise leak host
# state into the tarball.
( cd "$DIST" && tar \
    --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -czf "$PKG.tar.gz" "$PKG" )
rm -rf "$DIST/$PKG"
( cd "$DIST" && sha256sum "$PKG.tar.gz" > "$PKG.tar.gz.sha256" )

echo
echo "=== Done ==="
ls -lh "$DIST/"
echo
echo "tarball sha256: $(cat "$DIST/$PKG.tar.gz.sha256")"
