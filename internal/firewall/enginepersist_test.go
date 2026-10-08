package firewall

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests run the real engine script (engine/zfw) — not a stand-in — in an
// unprivileged user + network + mount namespace:
//
//   - the user namespace maps the test user to root, so the engine's
//     secure_file check sees root-owned files exactly as on a host;
//   - the network namespace gives revert() an empty netfilter to work on;
//   - the mount namespace lets the test bind a recording stub over
//     /usr/bin/systemctl and /usr/bin/systemd-run and a tmpfs over
//     /etc/systemd/system, so nothing on the build host is touched.
//
// The "boot" step executes whatever ExecStart= the engine wrote into
// zfw.service — the same command systemd would run at boot and on every
// dockerd restart (the unit is PartOf=docker.service).

const engineHarness = `set -eu
D="$1"; shift
mount -t tmpfs none /etc/systemd/system
mount --bind "$D/stub-systemctl" /usr/bin/systemctl
mount --bind "$D/stub-systemd-run" /usr/bin/systemd-run
mkdir -p /tmp/xt && export XTABLES_LOCKFILE=/tmp/xt/lock
step(){ echo "== $*"; "$@" 2>&1 || echo "exit=$?"; }
boot(){
  local unit=/etc/systemd/system/zfw.service
  [ -f "$unit" ] || { echo "== boot: no unit"; return 0; }
  local cmd; cmd="$(sed -n 's/^ExecStart=//p' "$unit")"
  # The unit names the production path; run the engine under test instead.
  cmd="${cmd/\/DATA\/zfw\/zfw/$D/zfw}"
  echo "== boot: $cmd"; $cmd 2>&1 || echo "exit=$?"
}
compile(){ printf '#!/bin/bash\necho %s >> "%s/ran"\n' "$1" "$D" > "$D/compiled.sh"; chmod 0600 "$D/compiled.sh"; }
ran(){ echo "ran: $(tr '\n' ' ' < "$D/ran" 2>/dev/null)"; : > "$D/ran"; }
`

type engineEnv struct {
	dir string
}

func requireEngineNS(t *testing.T) *engineEnv {
	t.Helper()
	for _, b := range []string{"unshare", "bash"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
	probe := `mount -t tmpfs none /etc/systemd/system && mount --bind /bin/true /usr/bin/systemctl`
	if out, err := exec.Command("unshare", "-U", "-r", "-n", "-m", "bash", "-c", probe).CombinedOutput(); err != nil {
		t.Skipf("unprivileged user+mount namespace unavailable: %v\n%s", err, out)
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "engine", "zfw"))
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "zfw"), src, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"" + d + "/sys.log\"\nexit 0\n"
	for _, n := range []string{"stub-systemctl", "stub-systemd-run"} {
		if err := os.WriteFile(filepath.Join(d, n), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &engineEnv{dir: d}
}

func (e *engineEnv) run(t *testing.T, body string) string {
	t.Helper()
	sp := filepath.Join(e.dir, "scenario.sh")
	if err := os.WriteFile(sp, []byte(engineHarness+body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("unshare", "-U", "-r", "-n", "-m", "bash", sp, e.dir).CombinedOutput()
	if err != nil {
		t.Fatalf("scenario failed: %v\n%s", err, out)
	}
	return string(out)
}

// ranAfter returns the "ran:" line that follows the step header containing
// marker, i.e. which compiled script(s) that step executed.
func ranAfter(out, marker string) string {
	i := strings.Index(out, marker)
	if i < 0 {
		return "<marker " + marker + " not found>"
	}
	m := regexp.MustCompile(`(?m)^ran: ?(.*)$`).FindStringSubmatch(out[i:])
	if m == nil {
		return "<no ran line>"
	}
	return strings.TrimSpace(m[1])
}

// TestBootReplaysOnlyTheConfirmedRuleset is the regression test for the
// boot-persistence gap: zfw.service replayed the *current* compiled.sh, but
// the daemon rewrites that file on every rule save and on every container
// event (dockerwatch). A ruleset saved after the last Confirm — never run
// under the dead-man — went live without one on the next reboot or dockerd
// restart.
func TestBootReplaysOnlyTheConfirmedRuleset(t *testing.T) {
	e := requireEngineNS(t)
	out := e.run(t, `
compile A; step "$D/zfw" apply --safe; ran
step "$D/zfw" commit
compile B                     # saved in the UI, never applied
boot; ran
echo "#mark-after-boot1"
`)
	if got := ranAfter(out, "== boot"); got != "A" {
		t.Errorf("boot replayed %q, want only the confirmed ruleset A\n%s", got, out)
	}
}

// A commit promotes what was applied, not what compiled.sh holds by the time
// the operator clicks Confirm (dockerwatch may have rewritten it meanwhile).
func TestCommitPromotesTheAppliedScriptNotTheCurrentOne(t *testing.T) {
	e := requireEngineNS(t)
	out := e.run(t, `
compile A; step "$D/zfw" apply --safe; ran
compile B                     # dockerwatch recompiled during the 120 s window
step "$D/zfw" commit
boot; ran
`)
	if got := ranAfter(out, "== boot"); got != "A" {
		t.Errorf("boot replayed %q, want A (the script that ran under the dead-man)\n%s", got, out)
	}
}

// An apply without the dead-man is the operator's explicit "make this live",
// so it is what the next boot replays.
func TestPlainApplyIsWhatBootReplays(t *testing.T) {
	e := requireEngineNS(t)
	out := e.run(t, `
compile A; step "$D/zfw" apply --safe; step "$D/zfw" commit; ran
compile C; step "$D/zfw" apply; ran
compile D                     # saved, not applied
boot; ran
`)
	if got := ranAfter(out, "== boot"); got != "C" {
		t.Errorf("boot replayed %q, want C (last plain apply)\n%s", got, out)
	}
}

// Revert and the dead-man switch the firewall off; they must take the
// confirmed copy with them so nothing is replayed.
func TestRevertAndDeadmanDropTheConfirmedCopy(t *testing.T) {
	e := requireEngineNS(t)
	out := e.run(t, `
compile A; step "$D/zfw" apply --safe; step "$D/zfw" commit; ran
step "$D/zfw" revert
[ -e "$D/committed.sh" ] && echo "after-revert: committed present" || echo "after-revert: committed gone"
compile B; step "$D/zfw" apply --safe; step "$D/zfw" commit; ran
step "$D/zfw" _autorevert
[ -e "$D/committed.sh" ] && echo "after-deadman: committed present" || echo "after-deadman: committed gone"
`)
	for _, want := range []string{"after-revert: committed gone", "after-deadman: committed gone"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q\n%s", want, out)
		}
	}
}

// The confirmed copy is executed as root at boot: it gets the same root-exec
// guard as compiled.sh, and the engine writes it root-only.
func TestConfirmedCopyIsGuardedAndRootOnly(t *testing.T) {
	e := requireEngineNS(t)
	out := e.run(t, `
compile A; step "$D/zfw" apply --safe; step "$D/zfw" commit; ran
echo "mode: $(stat -c %a "$D/committed.sh")"
chmod 0666 "$D/committed.sh"
boot; ran
`)
	if !strings.Contains(out, "mode: 600") {
		t.Errorf("committed.sh not written 0600\n%s", out)
	}
	if got := ranAfter(out, "== boot"); got != "" {
		t.Errorf("boot executed a group/world-writable committed.sh (ran %q)\n%s", got, out)
	}
	if !strings.Contains(out, "group/world-writable") {
		t.Errorf("boot refusal does not name the reason\n%s", out)
	}
}

// Migration: a host upgraded from <= v1.0.26 has an enabled unit that still
// says `zfw apply` and no committed.sh. _migrate-persist (run by install.sh)
// rewrites the unit and seeds committed.sh from the compiled.sh present at
// upgrade time, so later rule saves no longer leak into boot.
func TestMigrationFromAnOldUnit(t *testing.T) {
	e := requireEngineNS(t)
	out := e.run(t, `
compile OLD
cat > /etc/systemd/system/zfw.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/DATA/zfw/zfw apply
UNIT
step "$D/zfw" _migrate-persist
grep '^ExecStart=' /etc/systemd/system/zfw.service
compile NEWER                 # saved after the upgrade, never applied
boot; ran
step "$D/zfw" _migrate-persist   # idempotent
`)
	if !strings.Contains(out, "ExecStart=/DATA/zfw/zfw boot") {
		t.Errorf("unit not migrated to the boot verb\n%s", out)
	}
	if got := ranAfter(out, "== boot"); got != "OLD" {
		t.Errorf("boot after migration replayed %q, want OLD (the state at upgrade time)\n%s", got, out)
	}
}

// Without a unit, migration must not create one: persistence stays off on a
// host whose operator never confirmed.
func TestMigrationLeavesUnconfirmedHostsAlone(t *testing.T) {
	e := requireEngineNS(t)
	out := e.run(t, `
compile A
step "$D/zfw" _migrate-persist
[ -e /etc/systemd/system/zfw.service ] && echo "unit: created" || echo "unit: none"
[ -e "$D/committed.sh" ] && echo "committed: created" || echo "committed: none"
`)
	for _, want := range []string{"unit: none", "committed: none"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q\n%s", want, out)
		}
	}
}
