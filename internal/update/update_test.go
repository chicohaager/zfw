package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCompareOrdering locks in the semver-ish comparison used by the
// "update available" check. The exact ordering matters: 0.3.10 must
// be greater than 0.3.9 (lexicographic would get this wrong).
func TestCompareOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.3.6", "0.3.7", -1},
		{"0.3.7", "0.3.6", +1},
		{"0.3.7", "0.3.7", 0},
		{"0.3.9", "0.3.10", -1}, // lexicographic trap
		{"v0.3.7", "0.3.8", -1}, // leading v tolerated
		{"0.3.7-dev", "0.3.7", 0},
		{"1.0", "0.9.99", +1},
		{"0.3", "0.3.0", 0}, // missing trailing components == 0
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestCompareTreatsPreReleaseAsEqual pins the CQ-12 (v1.0.2) documented
// trade-off: pre-release suffixes are stripped, so "1.2.3" == "1.2.3-rc1"
// == "1.2.3+build". The release flow ships no -rc tags so this is a
// non-issue in practice; documented here so a future maintainer
// considering -rc publishing knows to revisit Compare first.
func TestCompareTreatsPreReleaseAsEqual(t *testing.T) {
	if got := Compare("1.2.3", "1.2.3-rc1"); got != 0 {
		t.Errorf("Compare(\"1.2.3\",\"1.2.3-rc1\") = %d, want 0 (suffix stripped)", got)
	}
	if got := Compare("1.2.3-rc1", "1.2.3"); got != 0 {
		t.Errorf("Compare(\"1.2.3-rc1\",\"1.2.3\") = %d, want 0 (suffix stripped)", got)
	}
	if got := Compare("1.2.3-rc1", "1.2.3-rc2"); got != 0 {
		t.Errorf("Compare(\"1.2.3-rc1\",\"1.2.3-rc2\") = %d, want 0 (both suffixes stripped)", got)
	}
	if got := Compare("1.2.3+build1", "1.2.3"); got != 0 {
		t.Errorf("Compare(\"1.2.3+build1\",\"1.2.3\") = %d, want 0 (suffix stripped)", got)
	}
}

// TestCheckOnceParsesManifest is the happy-path: the manifest endpoint
// returns a clean JSON body, the checker stores Latest + Available +
// Notes and clears the Error field.
func TestCheckOnceParsesManifest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"0.4.0","notes":"closes v0.5"}`))
	}))
	defer srv.Close()
	c := New("0.3.9", srv.URL)
	c.CheckOnce(context.Background())
	got := c.Snapshot()
	if got.Latest != "0.4.0" {
		t.Errorf("Latest = %q, want 0.4.0", got.Latest)
	}
	if !got.Available {
		t.Errorf("Available = false, want true (0.3.9 < 0.4.0)")
	}
	if got.Notes != "closes v0.5" {
		t.Errorf("Notes = %q, want %q", got.Notes, "closes v0.5")
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty", got.Error)
	}
	if got.CheckedAt.IsZero() {
		t.Errorf("CheckedAt not stamped")
	}
}

// TestCheckOnceNotAvailableWhenSameVersion guards that current==latest
// surfaces as Available=false (not just "not greater").
func TestCheckOnceNotAvailableWhenSameVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"0.3.9"}`))
	}))
	defer srv.Close()
	c := New("0.3.9", srv.URL)
	c.CheckOnce(context.Background())
	if c.Snapshot().Available {
		t.Errorf("Available = true for matching versions, want false")
	}
}

// TestCheckOnceHandlesHTTPError guards that a 500 from the manifest
// host records an Error and leaves Available=false (don't badge on
// stale data).
func TestCheckOnceHandlesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New("0.3.9", srv.URL)
	c.CheckOnce(context.Background())
	got := c.Snapshot()
	if got.Error == "" {
		t.Fatal("Error not recorded for HTTP 500")
	}
	if !strings.Contains(got.Error, "500") {
		t.Errorf("Error = %q, want it to mention 500", got.Error)
	}
	if got.Available {
		t.Errorf("Available = true after HTTP error, want false")
	}
}

// TestCheckOnceHandlesBadJSON guards that a non-JSON body records an
// Error rather than crashing or setting bogus Latest.
func TestCheckOnceHandlesBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>not json</html>`))
	}))
	defer srv.Close()
	c := New("0.3.9", srv.URL)
	c.CheckOnce(context.Background())
	got := c.Snapshot()
	if got.Error == "" {
		t.Fatal("Error not recorded for non-JSON body")
	}
	if got.Latest != "" {
		t.Errorf("Latest = %q, want empty after parse error", got.Latest)
	}
}

// TestCheckOnceDisabledIsNoop guards that a checker with an empty URL
// performs no network call and reports Disabled().
func TestCheckOnceDisabledIsNoop(t *testing.T) {
	c := New("0.3.9", "")
	if !c.Disabled() {
		t.Fatal("Disabled() = false for empty URL, want true")
	}
	c.CheckOnce(context.Background())
	got := c.Snapshot()
	if got.Latest != "" || got.Available || got.Error != "" {
		t.Errorf("Snapshot after CheckOnce on disabled checker: %+v, want zero-ish", got)
	}
	if !got.CheckedAt.IsZero() {
		t.Errorf("CheckedAt = %v, want zero (no check happened)", got.CheckedAt)
	}
}

// TestCheckOnceRespectsContextCancellation guards that an external
// timeout aborts an in-flight check cleanly.
func TestCheckOnceRespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"version":"0.4.0"}`))
	}))
	defer srv.Close()
	c := New("0.3.9", srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	c.CheckOnce(ctx)
	got := c.Snapshot()
	if got.Error == "" {
		t.Fatal("Error not recorded for cancelled context")
	}
}
