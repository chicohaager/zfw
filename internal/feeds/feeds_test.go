package feeds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Excerpts of the two real feeds as downloaded on 2026-09-05 — the comment
// styles, the bare IP and the "; SBL" trailer are the shapes a parser must
// survive, not ones I typed.
const fireholExcerpt = `#
# firehol_level1
#
# Maintainer      : FireHOL
# Entries         : 3939 subnets, 611184833 unique IPs
#
0.0.0.0/8
1.10.16.0/20
1.19.0.0/16
5.42.92.0/24
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
203.0.113.7
224.0.0.0/3
`

const spamhausExcerpt = `; Spamhaus DROP List 2026/09/04 - (c) 2026 The Spamhaus Project SLU
; https://www.spamhaus.org/drop/drop.txt
; Last-Modified: Fri, 04 Sep 2026 14:20:51 GMT
1.10.16.0/20 ; SBL256894
1.19.0.0/16 ; SBL434604
2.56.192.0/22 ; SBL459831
`

// ageTime is a timestamp older than maxAge, to force a refetch.
func ageTime() time.Time { return time.Now().Add(-2 * maxAge) }

func TestParseEntriesHandlesBothRealFormats(t *testing.T) {
	got := parseEntries([]byte(fireholExcerpt))
	if len(got) != 12 {
		t.Fatalf("firehol excerpt: %d entries, want 12", len(got))
	}
	if s := got[10].String(); s != "203.0.113.7/32" {
		t.Fatalf("bare IP parsed as %q, want 203.0.113.7/32", s)
	}
	got = parseEntries([]byte(spamhausExcerpt))
	if len(got) != 3 || got[2].String() != "2.56.192.0/22" {
		t.Fatalf("spamhaus excerpt: %v", got)
	}
	// IPv6 and garbage are skipped, never fatal.
	if n := len(parseEntries([]byte("2001:db8::/32\nnot-an-ip\n<html>oops</html>\n"))); n != 0 {
		t.Fatalf("garbage parsed to %d entries, want 0", n)
	}
}

// The property the whole package rests on: every bogon firehol_level1 ships
// must be gone after filtering, whatever else the feed contains.
func TestFilteredDropsEveryBogonFireholShips(t *testing.T) {
	kept, dropped := filtered(parseEntries([]byte(fireholExcerpt)))
	if dropped != 8 {
		t.Fatalf("dropped %d, want the 8 special-use entries", dropped)
	}
	for _, n := range kept {
		for _, bad := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
			"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"} {
			if n.String() == bad {
				t.Fatalf("%s survived filtering", bad)
			}
		}
	}
	if len(kept) != 4 {
		t.Fatalf("kept %d, want 4 (1.10.16.0/20 1.19.0.0/16 5.42.92.0/24 203.0.113.7/32)", len(kept))
	}
	// Both directions: an entry inside a protected range and one that
	// contains a protected range are dropped alike.
	kept, dropped = filtered(parseEntries([]byte("192.168.1.0/24\n0.0.0.0/0\n100.100.0.0/16\n198.51.100.0/24\n")))
	if dropped != 3 || len(kept) != 1 || kept[0].String() != "198.51.100.0/24" {
		t.Fatalf("partial/containing entries: kept=%v dropped=%d", kept, dropped)
	}
}

// feedServer serves *body with *status for every path and counts requests.
func feedServer(t *testing.T, body *string, status *int) (*httptest.Server, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(*status)
		_, _ = w.Write([]byte(*body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// bigFeed builds a list with n public /24s plus the firehol bogons.
func bigFeed(n int) string {
	var sb strings.Builder
	sb.WriteString(fireholExcerpt)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "%d.%d.%d.0/24\n", 20+i/65536, (i/256)%256, i%256)
	}
	return sb.String()
}

func newTestManager(t *testing.T, srv *httptest.Server) *Manager {
	t.Helper()
	m := New(t.TempDir())
	m.Source = func(f Feed) string { return srv.URL + "/" + f.ID }
	return m
}

func TestEnsureFetchesRendersAndRecordsMeta(t *testing.T) {
	body, status := bigFeed(300), http.StatusOK
	srv, hits := feedServer(t, &body, &status)
	m := newTestManager(t, srv)
	if err := m.Ensure(context.Background(), []string{"spamhaus_drop"}, nil); err != nil {
		t.Fatal(err)
	}
	if *hits != 1 {
		t.Fatalf("fetched %d times, want 1", *hits)
	}
	out, err := os.ReadFile(m.IpsetPath("spamhaus_drop"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"create zfw-feed-spamhaus_drop hash:net", "flush zfw-feed-spamhaus_drop\n", "add zfw-feed-spamhaus_drop 20.0.0.0/24\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("ipset file lacks %q", want)
		}
	}
	for _, bad := range []string{"10.0.0.0/8", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8"} {
		if strings.Contains(s, " "+bad+"\n") {
			t.Errorf("bogon %s rendered into the set", bad)
		}
	}
	meta, ok := m.Info("spamhaus_drop")
	if !ok || meta.Entries != 304 || meta.Dropped != 8 {
		t.Fatalf("meta = %+v ok=%v, want 304 entries / 8 dropped", meta, ok)
	}
	if fi, err := os.Stat(m.IpsetPath("spamhaus_drop")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("ipset file mode: %v %v", fi.Mode(), err)
	}
	// Second Ensure inside maxAge: served from cache, no request.
	if err := m.Ensure(context.Background(), []string{"spamhaus_drop"}, nil); err != nil || *hits != 1 {
		t.Fatalf("second Ensure: err=%v hits=%d", err, *hits)
	}
}

func TestFetchRefusesOutOfBoundsAndKeepsCache(t *testing.T) {
	body, status := bigFeed(300), http.StatusOK
	srv, _ := feedServer(t, &body, &status)
	m := newTestManager(t, srv)
	if err := m.Ensure(context.Background(), []string{"spamhaus_drop"}, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.listPath("spamhaus_drop"))
	cases := map[string]string{
		"captive portal": "<html><body>Sign in to the network</body></html>",
		"truncated":      bigFeed(5),
		"exploded":       bigFeed(30000),
	}
	for name, payload := range cases {
		body = payload
		if err := os.Chtimes(m.listPath("spamhaus_drop"), ageTime(), ageTime()); err != nil {
			t.Fatal(err)
		}
		var logged string
		err := m.Ensure(context.Background(), []string{"spamhaus_drop"}, func(f string, a ...any) { logged = fmt.Sprintf(f, a...) })
		if err != nil {
			t.Fatalf("%s: Ensure must keep working from the cache, got %v", name, err)
		}
		if !strings.Contains(logged, "outside the feed's bounds") {
			t.Errorf("%s: refusal not logged: %q", name, logged)
		}
		after, _ := os.ReadFile(m.listPath("spamhaus_drop"))
		if string(after) != string(before) {
			t.Fatalf("%s: cache was overwritten", name)
		}
	}
}

func TestEnsureUsesCacheOnNetworkFailure(t *testing.T) {
	body, status := bigFeed(300), http.StatusOK
	srv, _ := feedServer(t, &body, &status)
	m := newTestManager(t, srv)
	if err := m.Ensure(context.Background(), []string{"spamhaus_drop"}, nil); err != nil {
		t.Fatal(err)
	}
	status = http.StatusInternalServerError
	if err := os.Chtimes(m.listPath("spamhaus_drop"), ageTime(), ageTime()); err != nil {
		t.Fatal(err)
	}
	var logged string
	if err := m.Ensure(context.Background(), []string{"spamhaus_drop"}, func(f string, a ...any) { logged = fmt.Sprintf(f, a...) }); err != nil {
		t.Fatalf("cache present, network down: %v", err)
	}
	if !strings.Contains(logged, "HTTP 500") {
		t.Errorf("failure not logged: %q", logged)
	}
	// No cache at all + network down = a real error, not a silent empty set.
	fresh := newTestManager(t, srv)
	if err := fresh.Ensure(context.Background(), []string{"spamhaus_drop"}, nil); err == nil {
		t.Fatal("no cache and HTTP 500: Ensure returned nil")
	}
}

func TestEnsureRejectsUnknownFeedBeforeAnyNetworkCall(t *testing.T) {
	body, status := bigFeed(300), http.StatusOK
	srv, hits := feedServer(t, &body, &status)
	m := newTestManager(t, srv)
	for _, id := range []string{"notincatalogue", "../../etc/passwd", "FIREHOL_LEVEL1", "", "firehol_level1; id"} {
		if err := m.Ensure(context.Background(), []string{id}, nil); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
	if *hits != 0 {
		t.Fatalf("%d network calls for rejected ids, want 0", *hits)
	}
	if entries, _ := os.ReadDir(m.dir); len(entries) != 0 {
		t.Fatalf("files created for rejected ids: %v", entries)
	}
}

func TestCatalogueIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Catalogue {
		if !idRe.MatchString(f.ID) || seen[f.ID] {
			t.Errorf("feed id %q malformed or duplicate", f.ID)
		}
		seen[f.ID] = true
		if !strings.HasPrefix(f.URL, "https://") {
			t.Errorf("feed %s: URL is not https: %s", f.ID, f.URL)
		}
		if f.MinEntries <= 0 || f.MaxEntries <= f.MinEntries {
			t.Errorf("feed %s: bounds [%d,%d] make no sense", f.ID, f.MinEntries, f.MaxEntries)
		}
		if n := SetName(f.ID); len(n) > 31 {
			t.Errorf("feed %s: ipset name %q exceeds 31 bytes", f.ID, n)
		}
		if !IsValidID(f.ID) {
			t.Errorf("feed %s: IsValidID false for a catalogue entry", f.ID)
		}
	}
	if IsValidID("not_there") {
		t.Error("IsValidID accepted an id outside the catalogue")
	}
}
