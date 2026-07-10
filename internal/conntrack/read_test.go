package conntrack

import (
	"context"
	"strings"
	"testing"
)

// TestReadFailsLoudWhenNoSourceWorks is the guard for the second half of
// issue #1. Pre-v1.0.19 the caller turned any error into an empty list and
// answered HTTP 200, so a host that could not be read looked exactly like a
// host with no connections — and the UI blamed a kernel module that was
// running fine.
//
// The environment is forced into "no source available": PATH is emptied so
// conntrack(8) cannot be found, and the test runs unprivileged so the
// ctnetlink dump is refused with EPERM. /proc/net/nf_conntrack is absent on
// the CI kernel; if a developer's box has it, the read legitimately succeeds
// and the test skips rather than lying about what it proved.
func TestReadFailsLoudWhenNoSourceWorks(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	entries, err := Read(context.Background(), 10)
	if err == nil {
		t.Skipf("a conntrack source is readable in this environment (%d entries) — "+
			"nothing to assert about the all-sources-failed path", len(entries))
	}
	if entries != nil {
		t.Errorf("entries = %v, want nil alongside the error", entries)
	}

	// The joined error must name every source it tried, so an operator can
	// tell "no permission" from "file missing" from "tool not installed".
	for _, want := range []string{"ctnetlink", "/proc/net/nf_conntrack", "conntrack(8)"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q — operator cannot tell which source failed:\n%v", want, err)
		}
	}
}
