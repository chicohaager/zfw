# ZFW — Mod-Store submission guide

This is the operator runbook for getting ZFW into the IceWhaleTech
Mod-Store so it appears in the ZimaOS web UI's Module Store with a
one-click install. The submission itself is manual because it requires
a GitHub remote on this repo and a forked PR against
`IceWhaleTech/Mod-Store` — both outside the daemon's scope.

The daemon side of v0.5 is complete as of v0.4.0:

- arm64 build (v0.3.7) — reproducible per-arch tarballs.
- rules.json migration helper (v0.3.8) — schema bumps are safe.
- `zpkg` self-update check (v0.3.9) — the Versions tab can announce
  new releases the moment a manifest URL exists.
- multi-host rule sync (v0.3.10) — a fleet of ZimaOS hosts can stay
  in lockstep without manual `scp`.

Once the Mod-Store entry is live, set `ZFW_UPDATE_URL` to its raw
manifest URL on every host so v0.3.9's update banner starts firing.

---

## One-time setup

1. **GitHub remote.** This repo currently has no remote. Create the
   public repo:

   ```sh
   gh repo create chicohaager/zfw --public --source=. --remote=origin --push
   ```

   The committed CI workflow (`.github/workflows/ci.yml`) goes green
   on the first push by construction — lint + test + reproducible
   build + arm64 smoke.

2. **Cut the release so that the tag reproduces the assets.** Two inputs
   besides the source decide the bytes, and both must be settled *before*
   the build that produces the published assets: `SOURCE_DATE_EPOCH`
   (build.sh takes it from the last commit's committer date) and the
   nearest git tag (cyclonedx-gomod stamps the SBOM's main component with
   it; `sbom.json` travels inside the tarball). The checksums, in turn,
   live in `mod-store/zfw.yaml`, which is part of the release commit — so
   the commit is created with a chosen date, tagged, built, amended with
   the checksums *under the same date*, re-tagged, and rebuilt once more
   as the positive control. Done this way for v1.0.25:

   ```sh
   X=$(date +%s)                                   # the release instant
   # …bump VERSION, README block, cache-busters, openapi, Dockerfile, yaml version…
   GIT_AUTHOR_DATE=@$X GIT_COMMITTER_DATE=@$X git commit -a -m "release: vX.Y.Z …"
   git tag -a "v$(cat VERSION)" -m "ZFW v$(cat VERSION)"
   sh build.sh                                     # epoch = $X, SBOM version = the tag
   # copy dist/*.tar.gz.sha256 into mod-store/zfw.yaml, then:
   GIT_AUTHOR_DATE=@$X GIT_COMMITTER_DATE=@$X git commit -a --amend --no-edit
   git tag -d "v$(cat VERSION)"; git tag -a "v$(cat VERSION)" -m "ZFW v$(cat VERSION)"
   rm -rf dist; sh build.sh                        # must reproduce every .sha256
   ```

   Have `cyclonedx-gomod` on `PATH` for this, installed exactly as CI does
   (`go install -trimpath …@v1.12.0`): the SBOM records the tool's own
   binary hash, and without `-trimpath` that hash carries the install
   host's paths. build.sh takes care of the other host-dependent input
   (file modes via umask) itself.

   The tarballs do not contain `mod-store/zfw.yaml`, so the amend changes
   no shipped byte — the rebuild is the proof. Then push branch and tag,
   let CI build the tag (its artifact must carry the same checksums), and
   publish:

   ```sh
   VERSION=$(cat VERSION)
   git push origin "release/v${VERSION}" "v${VERSION}"
   gh release create "v${VERSION}" \
     dist/zfw-${VERSION}-amd64.tar.gz \
     dist/zfw-${VERSION}-amd64.tar.gz.sha256 \
     dist/zfw-${VERSION}-arm64.tar.gz \
     dist/zfw-${VERSION}-arm64.tar.gz.sha256 \
     dist/sbom.json \
     --title "ZFW v${VERSION}" \
     --notes-file <(git log -1 --format=%B "v${VERSION}")
   ```

   The release notes come straight from the body of the release
   commit — keep the commit message tight and reader-facing so
   `gh release create` ships a coherent change-summary without a
   second authoring pass. A release must never be re-cut from a later
   commit (the epoch moves, every byte moves); rebuild from the tag.

3. **`mod-store/zfw.yaml`** carries the checksums pinned in step 2. The
   manifest stays in this repo as source-of-truth between releases;
   the submitted copy in `IceWhaleTech/Mod-Store` is generated from it.

4. **Capture screenshots.** Mod-Store renders the screenshots at
   ~1600×1000 in the listing card. Capture five PNGs and place them
   in `mod-store/screenshots/`:

   - `firewall-tab.png`
   - `rules-tab.png`
   - `exposure-tab.png`
   - `events-tab.png`
   - `audit-tab.png`

   Use the light theme (default since v0.2.14) and a representative
   rule set (the v0.2.9 starter defaults work well). Avoid leaking
   any host IP or hostname that identifies a real production host.

---

## Per-release submission flow

After each release tag (see step 2 above), open a PR against the
Mod-Store fork:

```sh
gh repo fork IceWhaleTech/Mod-Store --clone
cd Mod-Store
git checkout -b zfw-v${VERSION}

# Copy the manifest + screenshots into the Mod-Store directory layout.
# The exact path depends on Mod-Store's category convention; at time
# of writing it is Apps/<category>/<id>/.
mkdir -p Apps/Network/zfw/screenshots
cp /path/to/zfw/mod-store/zfw.yaml Apps/Network/zfw/
cp /path/to/zfw/mod-store/screenshots/*.png Apps/Network/zfw/screenshots/

git add Apps/Network/zfw
git commit -m "Add ZFW v${VERSION} — host firewall for ZimaOS"
git push -u origin "zfw-v${VERSION}"

gh pr create \
  --repo IceWhaleTech/Mod-Store \
  --title "Add ZFW v${VERSION} — host firewall for ZimaOS" \
  --body "$(cat <<'EOF'
ZFW is a standalone ZimaOS module that adds a host firewall — the one
thing the OS does not ship out of the box. Stock ZimaOS has every
iptables chain at ACCEPT, no nftables ruleset, and Samba / NFS /
rpcbind / the built-in VM VNC console / every Docker-published port
reachable from the whole LAN by default.

ZFW closes that gap with:
  - default-drop allowlist on ZFW-IN (host services)
  - blocklist on DOCKER-USER (container ports — never reach INPUT)
  - IPv6 first-class (ZFW-IN6 default-drop with full bypass list)
  - Safe-Apply with 120 s dead-man auto-revert
  - five-tab UI (firewall / rules / exposure / events / audit)
  - reproducible builds + optional CycloneDX SBOM
  - JWT-authed API (ZimaOS session) + CSRF same-origin guard

External-tester sign-off baked into the release: Gelbuilding's
2026-05-24 ZimaBoard validation of v0.2.20, full install +
Safe-Apply + Confirm + reboot-persistence cycle.

Three-round internal security review on file (SECURITY-REPORT.md).

Both amd64 and arm64 artifacts shipped; SHAs in the manifest are
generated by the reproducible build pipeline.
EOF
)"
```

---

## Wiring `ZFW_UPDATE_URL` after submission

Once the Mod-Store PR merges and ZFW is reachable via a stable URL,
set `ZFW_UPDATE_URL` to the raw manifest path so the Versions-tab
banner starts firing on every host. The manifest format is a tiny
JSON document:

```json
{ "version": "0.5.0", "notes": "first v0.6 batch — top-sources widget" }
```

A natural source-of-truth: a `dist/latest.json` file maintained on the
GitHub repo's `main` branch, regenerated on every release. Sample
release-cut step:

```sh
echo "{\"version\":\"${VERSION}\",\"notes\":\"$(git log -1 --pretty=%s)\"}" > dist/latest.json
git add dist/latest.json
git commit -m "release: bump latest.json to ${VERSION}"
git push
```

Then each ZimaOS host sets:

```sh
sudo systemctl edit zfw-ui.service
# [Service]
# Environment=ZFW_UPDATE_URL=https://raw.githubusercontent.com/chicohaager/zfw/main/dist/latest.json
sudo systemctl restart zfw-ui.service
```

(Or set it once in the daemon's systemd unit before publishing v0.5.0
so it ships pre-wired.)

---

## Per-release sanity checklist

Before pushing a release tag:

- [ ] `VERSION` bumped
- [ ] Cache-buster bumped (`?v=` on `styles.css` + `app.js` in `index.html`)
- [ ] `docs/openapi.yaml` `info.version` bumped
- [ ] `README.md` "Current release" badge bumped
- [ ] `mod-store/zfw.yaml` `version` bumped + new SHAs filled in
- [ ] `go test ./...` green
- [ ] `Dockerfile` usage comment + README "Install from Docker Hub" tag bumped
- [ ] `bash build.sh` produces both arches reproducibly (re-run +
      compare `dist/*.tar.gz.sha256` across runs) — **from the tagged
      release commit**, see step 2 above
- [ ] Docker Hub image pushed and its payload verified against
      `dist/zfw-<arch>.raw.sha256` per arch (README, "Building the installer image")
- [ ] Browser-test the UI changes the release introduces

That list is encoded in the project's memory entry
`pre-tarball-checklist` for any future Claude session that picks
up the release-cut work.
