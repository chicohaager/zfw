#!/bin/sh
# stage-docker-payload.sh <release-dir> <version>
#
# Puts the modules of a *published* release where the Dockerfile copies them
# from (dist/zfw-<arch>.raw + .sha256), so the Docker Hub installer image
# carries exactly the bytes of the GitHub release — not a fresh build.
#
# <release-dir> holds zfw-<version>-<arch>.tar.gz and their .sha256 files
# (the "zfw-release" artifact of the tag's CI build). Every checksum is
# verified on the way: the tarball against its .sha256, the module inside
# against the .sha256 the build wrote next to it.
#
# Used by the `docker` job in .github/workflows/ci.yml; runnable by hand.
set -eu

REL=${1:?usage: stage-docker-payload.sh <release-dir> <version>}
V=${2:?usage: stage-docker-payload.sh <release-dir> <version>}

[ "$V" = "$(cat VERSION)" ] || { echo "version $V != VERSION $(cat VERSION)" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "${WORK:?}"' EXIT
mkdir -p dist

for a in amd64 arm64; do
  ( cd "$REL" && sha256sum -c "zfw-$V-$a.tar.gz.sha256" )
  tar -xzf "$REL/zfw-$V-$a.tar.gz" -C "$WORK"
  ( cd "$WORK/zfw-$V-$a" && sha256sum -c zfw.raw.sha256 )
  cp "$WORK/zfw-$V-$a/zfw.raw" "dist/zfw-$a.raw"
  # build.sh names the per-arch file in its .sha256; the Dockerfile rewrites
  # that name back to zfw.raw, so write it the way build.sh does.
  sed -E "s/ +zfw\.raw\$/  zfw-$a.raw/" "$WORK/zfw-$V-$a/zfw.raw.sha256" > "dist/zfw-$a.raw.sha256"
  ( cd dist && sha256sum -c "zfw-$a.raw.sha256" )
done
