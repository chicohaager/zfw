package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryEngineExecChecksTheFile is the regression guard for the review
// finding that the ZFW-S8 root-exec check only covered Apply.
//
// The engine script at m.Bin is executed as root. Apply refused to run it
// unless it was root-owned and not group/world-writable — but Commit and
// Revert exec the very same file with the very same privileges and skipped
// the check entirely. An actor able to write under /DATA (a container with
// the standard /DATA bind mount is enough) could therefore replace the
// engine, watch Apply reject it, and still get their script run as root the
// moment the operator clicked Confirm or Revert. The guard belongs to the act
// of running that file as root, not to the "apply" verb.
//
// A world-writable engine stands in for the tampered file here: it is the
// property secureRootFile can actually detect when the test does not run as
// root (the ownership half needs a non-root owner, which an unprivileged test
// cannot arrange). Every verb must refuse it.
func TestEveryEngineExecChecksTheFile(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "zfw")
	// 0777: group/world-writable — anyone on the box can rewrite what root runs.
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	m := New(bin, filepath.Join(dir, "zfw.conf"))

	verbs := map[string]func() (string, error){
		"Apply":  func() (string, error) { return m.Apply(context.Background(), true) },
		"Commit": func() (string, error) { return m.Commit(context.Background()) },
		"Revert": func() (string, error) { return m.Revert(context.Background()) },
	}
	for name, call := range verbs {
		t.Run(name, func(t *testing.T) {
			_, err := call()
			if err == nil {
				t.Fatalf("%s executed a group/world-writable engine script as root — "+
					"an attacker who can write it owns the box", name)
			}
			if !strings.Contains(err.Error(), "unsafe") {
				t.Errorf("error = %q, want it to name the refusal so the operator can fix "+
					"the permissions rather than chase a generic exec failure", err)
			}
		})
	}
}

// TestEngineRunsWhenFileIsSafe is the other half: the guard must not block the
// normal path. A 0700 root-owned script executes and its verb reaches the
// engine. secureRootFile demands root ownership, which only a root-run test can
// create — the daemon itself runs as root in production, so that is the real
// configuration. Under an unprivileged `go test` the file would be owned by the
// test user and correctly refused, which says nothing about the guard, so skip.
func TestEngineRunsWhenFileIsSafe(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the positive path requires a root-owned engine script")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "zfw")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho \"verb=$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	m := New(bin, filepath.Join(dir, "zfw.conf"))

	out, err := m.Commit(context.Background())
	if err != nil {
		t.Fatalf("Commit on a 0700 root-owned engine = %v, want nil", err)
	}
	if !strings.Contains(out, "verb=commit") {
		t.Errorf("engine output = %q, want the commit verb to reach the script", out)
	}
}
