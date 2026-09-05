#!/bin/sh
# Build zfw.raw sysext modules + release tarballs for one or more arches.
# Requirements on the build host:
#   - go 1.27.1 (pinned by the go directive in go.mod; an older go in PATH
#     downloads and switches to it automatically, GOTOOLCHAIN=auto)
#   - squashfs-tools (mksquashfs)
#   - GNU tar (for the reproducible packaging flags)
# Optional (degrades gracefully if missing):
#   - github.com/CycloneDX/cyclonedx-gomod for SBOM generation
# Outputs (per arch, default amd64+arm64):
#   - dist/zfw-<arch>.raw                + dist/zfw-<arch>.raw.sha256
#   - dist/zfw-<v>-<arch>.tar.gz         + dist/zfw-<v>-<arch>.tar.gz.sha256
# Override the arch list with:  ARCHES="amd64" sh build.sh
set -eu
# Reproducibility does not stop at timestamps: file modes inside the squashfs
# and the tarball come from the build host's umask (a checkout under umask
# 002 has group-writable files, CI under 022 does not), and the two builds
# then differ in every checksum while every byte of content is identical —
# measured while cutting v1.0.25. Fix the umask here and normalise the modes
# of everything packed below, so the artifacts depend on the source alone.
umask 022

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

# Pin every go invocation in this script — including the ones cyclonedx-gomod
# makes on its own — to the exact toolchain named in go.mod. GOTOOLCHAIN=auto
# gets the daemon build right, but when the go in PATH is older it fails on
# the SBOM step: cyclonedx-gomod runs `go list -m` inside GOROOT/src, whose
# go.mod says `go 1.27` (no patch level), and the older go then tries to
# download a toolchain called "go1.27", which does not exist. Naming the
# version explicitly makes the switch unconditional and the build
# independent of what happens to be installed on the host.
GOTOOLCHAIN="go$(awk '/^go /{print $2; exit}' "$ROOT/go.mod")"
export GOTOOLCHAIN

echo "=== zfw module build ==="
echo "Version:           $VERSION"
echo "Toolchain:         $GOTOOLCHAIN ($(go version))"
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
  # The positional argument is the MODULE directory; the main package is
  # named with -main, relative to it. Passing ./cmd/zfwd as the module dir
  # made every run fail with "not a go module" — silently, because stderr
  # went to /dev/null and the WARN line scrolled by — so no release up to
  # v1.0.24 actually shipped an SBOM. -noserial/-notimestamp keep the file
  # byte-identical across rebuilds; it travels inside the tarball, and the
  # CI reproducibility check hashes the tarball.
  # CGO_ENABLED/GOOS are recorded in the SBOM as build properties, so set
  # them to what the daemon is really built with below (GOARCH stays the
  # host's: one SBOM serves both arches, the module graph is identical).
  if CGO_ENABLED=0 GOOS=linux cyclonedx-gomod app -json -licenses -noserial -notimestamp \
       -main cmd/zfwd -output "$DIST/sbom.json" "$ROOT" 2>"$DIST/sbom.err"; then
    rm -f "$DIST/sbom.err"
    echo "  SBOM -> $DIST/sbom.json"
  else
    echo "  WARN: cyclonedx-gomod failed; skipping SBOM:" >&2
    sed 's/^/    /' "$DIST/sbom.err" >&2
    rm -f "$DIST/sbom.json" "$DIST/sbom.err"
  fi
else
  echo "[2/4] SBOM skipped (install with: go install -trimpath github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0 — same pin and flag as ci.yml, or the SBOM's tool hash differs from CI's)"
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
$RAW/usr/share/casaos/www/modules/$NAME/logo.png
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
  # resulting raw image hashes identically across rebuilds — and to a fixed
  # mode (dirs 755, files 644, the daemon 755), see the umask note above.
  find "$RAW" -type d -exec chmod 755 {} +
  find "$RAW" -type f -exec chmod 644 {} +
  chmod 755 "$RAW/usr/bin/zfwd"
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
  rm -rf "${DIST:?}/${PKG:?}"
  mkdir -p "$DIST/$PKG"
  # install.sh expects a generic filename (zfw.raw, zfw.raw.sha256); the
  # arch suffix lives in the tarball name, not inside the payload. So we
  # copy the per-arch raw under its generic name and regenerate the .sha256
  # against that name (the checksum's body stays the same).
  cp "$DIST/$NAME-$arch.raw" "$DIST/$PKG/$NAME.raw"
  ( cd "$DIST/$PKG" && sha256sum "$NAME.raw" > "$NAME.raw.sha256" )
  cp "$ROOT/engine/zfw" "$ROOT/install.sh" \
     "$ROOT/README.md" "$ROOT/BEST-PRACTICES.md" "$ROOT/SECURITY-REPORT.md" \
     "$ROOT/THREAT-MODEL.md" "$ROOT/BUG-BOUNTY.md" \
     "$DIST/$PKG/"
  [ -f "$DIST/sbom.json" ] && cp "$DIST/sbom.json" "$DIST/$PKG/sbom.json"
  # Same mode normalisation as for the squashfs payload, same reason.
  chmod 0755 "$DIST/$PKG"
  find "$DIST/$PKG" -type f -exec chmod 0644 {} +
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
  rm -rf "${DIST:?}/${PKG:?}"
  ( cd "$DIST" && sha256sum "$PKG.tar.gz" > "$PKG.tar.gz.sha256" )
done

echo
echo "=== Done ==="
ls -lh "$DIST/"
echo
for arch in $ARCHES; do
  echo "tarball sha256 ($arch): $(cat "$DIST/$NAME-$VERSION-$arch.tar.gz.sha256")"
done
