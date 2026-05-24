#!/bin/sh
# Build zfw.raw sysext modules + release tarballs for one or more arches.
# Requirements on the build host:
#   - go 1.22+
#   - squashfs-tools (mksquashfs)
#   - GNU tar (for the reproducible packaging flags)
# Optional (degrades gracefully if missing):
#   - github.com/CycloneDX/cyclonedx-gomod for SBOM generation
# Outputs (per arch, default amd64+arm64):
#   - dist/zfw-<arch>.raw                + dist/zfw-<arch>.raw.sha256
#   - dist/zfw-<v>-<arch>.tar.gz         + dist/zfw-<v>-<arch>.tar.gz.sha256
# Override the arch list with:  ARCHES="amd64" sh build.sh
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/dist"
RAW="$ROOT/raw"
NAME="zfw"
VERSION="${VERSION:-$(cat "$ROOT/VERSION" 2>/dev/null || echo dev)}"
ARCHES="${ARCHES:-amd64 arm64}"

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
echo "Version:           $VERSION"
echo "Arches:            $ARCHES"
echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"

# 1. Format-check, vet, test (run once — independent of arch).
echo "[1/4] gofmt + go vet + test..."
mkdir -p "$RAW/usr/bin" "$DIST"
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

# 2. Optional SBOM. cyclonedx-gomod is small and Go-installable; if absent we
# print a hint instead of failing. The SBOM is arch-independent (Go module
# graph) so generate once and ship it alongside the tarballs.
rm -f "$DIST"/*.tar.gz "$DIST"/*.tar.gz.sha256 "$DIST"/zfw-*.raw "$DIST"/zfw-*.raw.sha256
if command -v cyclonedx-gomod >/dev/null 2>&1; then
  echo "[2/4] Generating CycloneDX SBOM..."
  cyclonedx-gomod app -json -licenses -output "$DIST/sbom.json" ./cmd/zfwd >/dev/null 2>&1 \
    && echo "  SBOM -> $DIST/sbom.json" \
    || { echo "  WARN: cyclonedx-gomod failed; skipping SBOM"; rm -f "$DIST/sbom.json"; }
else
  echo "[2/4] SBOM skipped (install with: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest)"
fi

# 3/4. Per-arch build + pack loop.
arch_count="$(echo "$ARCHES" | wc -w)"
arch_idx=0
for arch in $ARCHES; do
  arch_idx=$((arch_idx + 1))
  echo "[3/4] [$arch_idx/$arch_count] Building daemon for $arch..."
  # Flags chosen for reproducibility:
  #   -trimpath:    strip the build host's filesystem layout from the binary
  #   -buildvcs=false: don't embed git VCS info (commit hash, dirty flag)
  #                    that would otherwise change every commit
  #   -s -w:        drop the symbol and debug tables (also shrinks the binary)
  #   -X Version=… : pin the version string
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -X github.com/chicohaager/zfw/internal/buildinfo.Version=$VERSION" \
      -o "$RAW/usr/bin/zfwd" \
      ./cmd/zfwd
  chmod +x "$RAW/usr/bin/zfwd"
  echo "  -> $(ls -lh "$RAW/usr/bin/zfwd" | awk '{print $5}')"

  # Verify the sysext / CasaOS layout.
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

  # Pack as squashfs. ZimaOS kernel 6.12.x has no zstd/xz — gzip is mandatory.
  echo "[4/4] [$arch_idx/$arch_count] Packing squashfs + tarball for $arch..."
  rm -f "$DIST/$NAME-$arch.raw" "$DIST/$NAME-$arch.raw.sha256"
  mksquashfs "$RAW" "$DIST/$NAME-$arch.raw" \
    -all-root \
    -comp gzip \
    -noappend \
    -no-progress \
    -no-exports \
    >/dev/null
    # Timestamps come from $SOURCE_DATE_EPOCH (exported above); mksquashfs
    # refuses to combine that env var with explicit -mkfs-time/-all-time.
  ( cd "$DIST" && sha256sum "$NAME-$arch.raw" > "$NAME-$arch.raw.sha256" )

  # Pack the complete hand-off package: module + engine + installer + docs.
  PKG="$NAME-$VERSION-$arch"
  rm -rf "$DIST/$PKG"
  mkdir -p "$DIST/$PKG"
  # install.sh expects a generic filename (zfw.raw, zfw.raw.sha256); the
  # arch suffix lives in the tarball name, not inside the payload. So we
  # copy the per-arch raw under its generic name and regenerate the .sha256
  # against that name (the checksum's body stays the same).
  cp "$DIST/$NAME-$arch.raw" "$DIST/$PKG/$NAME.raw"
  ( cd "$DIST/$PKG" && sha256sum "$NAME.raw" > "$NAME.raw.sha256" )
  cp "$ROOT/engine/zfw" "$ROOT/install.sh" \
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
done

echo
echo "=== Done ==="
ls -lh "$DIST/"
echo
for arch in $ARCHES; do
  echo "tarball sha256 ($arch): $(cat "$DIST/$NAME-$VERSION-$arch.tar.gz.sha256")"
done
