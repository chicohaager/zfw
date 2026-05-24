package geo

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// writeZone is a small helper so each test body can stay focused on
// the lookup contract rather than file-creation boilerplate.
func writeZone(t *testing.T, dir, cc string, cidrs []string) {
	t.Helper()
	body := ""
	for _, c := range cidrs {
		body += c + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, cc+".zone"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestLookupNoZonesReturnsEmpty guards the fresh-install behaviour:
// a Manager with no .zone files must return "" for every lookup so
// the UI never paints a flag from stale or absent data.
func TestLookupNoZonesReturnsEmpty(t *testing.T) {
	m := New(t.TempDir())
	if got := m.Lookup(net.ParseIP("8.8.8.8")); got != "" {
		t.Errorf("Lookup on empty Manager = %q, want \"\"", got)
	}
}

// TestLookupHitsCachedZone guards the happy path: an IP that falls
// inside a CIDR from a cached .zone resolves to that file's country
// code. The synthetic .zone file is a single CIDR so the test stays
// readable.
func TestLookupHitsCachedZone(t *testing.T) {
	dir := t.TempDir()
	writeZone(t, dir, "de", []string{"203.0.113.0/24"})
	m := New(dir)
	if got := m.Lookup(net.ParseIP("203.0.113.42")); got != "de" {
		t.Errorf("Lookup = %q, want %q", got, "de")
	}
}

// TestLookupMissesOutsideCIDRReturnsEmpty: an IP outside every cached
// CIDR returns "" even though the Manager has data for other ranges.
// This is the typical "user configured RU but the source is from CA"
// case the UI must handle silently.
func TestLookupMissesOutsideCIDRReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeZone(t, dir, "ru", []string{"5.0.0.0/8"})
	m := New(dir)
	if got := m.Lookup(net.ParseIP("8.8.8.8")); got != "" {
		t.Errorf("Lookup outside RU = %q, want \"\"", got)
	}
}

// TestLookupBatchReturnsEveryKey guards the API contract: the result
// map MUST contain every input key (so UI iteration is nil-safe), and
// unmatched IPs must map to "" rather than be absent.
func TestLookupBatchReturnsEveryKey(t *testing.T) {
	dir := t.TempDir()
	writeZone(t, dir, "us", []string{"192.0.2.0/24"})
	m := New(dir)
	got := m.LookupBatch([]string{"192.0.2.7", "8.8.8.8", "not-an-ip"})
	if len(got) != 3 {
		t.Fatalf("LookupBatch returned %d keys, want 3 (every input must be present)", len(got))
	}
	if got["192.0.2.7"] != "us" {
		t.Errorf("LookupBatch[192.0.2.7] = %q, want us", got["192.0.2.7"])
	}
	if got["8.8.8.8"] != "" {
		t.Errorf("LookupBatch[8.8.8.8] = %q, want \"\" (no data)", got["8.8.8.8"])
	}
	if got["not-an-ip"] != "" {
		t.Errorf("LookupBatch[not-an-ip] = %q, want \"\" (parse failure)", got["not-an-ip"])
	}
}

// TestLookupRebuildsOnNewZone guards the staleness check: adding a
// new .zone after the first Lookup must surface in subsequent
// lookups without restarting the daemon — the user who just
// configured a new country rule should see flags immediately.
func TestLookupRebuildsOnNewZone(t *testing.T) {
	dir := t.TempDir()
	writeZone(t, dir, "de", []string{"203.0.113.0/24"})
	m := New(dir)
	if got := m.Lookup(net.ParseIP("198.51.100.42")); got != "" {
		t.Fatalf("pre-add lookup = %q, want \"\"", got)
	}
	// Add a new country file. Touch is implicit — WriteFile bumps mtime.
	writeZone(t, dir, "ru", []string{"198.51.100.0/24"})
	if got := m.Lookup(net.ParseIP("198.51.100.42")); got != "ru" {
		t.Errorf("post-add lookup = %q, want ru — index did not rebuild", got)
	}
}
