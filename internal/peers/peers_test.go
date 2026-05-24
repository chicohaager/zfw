package peers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	ps, err := Load(filepath.Join(t.TempDir(), "no-such-file.json"))
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	if len(ps) != 0 {
		t.Errorf("Load on missing file returned %d peers, want 0", len(ps))
	}
}

func TestLoadEmptyFileReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := os.WriteFile(path, []byte("  \n  "), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := Load(path)
	if err != nil {
		t.Fatalf("Load on empty file: %v", err)
	}
	if len(ps) != 0 {
		t.Errorf("Load on empty file returned %d peers, want 0", len(ps))
	}
}

func TestLoadParsesJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	in := []Peer{{Name: "zima-2", URL: "http://x", Token: "s3cret"}}
	b, _ := json.Marshal(in)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(ps) != 1 || ps[0].Name != "zima-2" || ps[0].Token != "s3cret" {
		t.Errorf("Load returned %+v, want %+v", ps, in)
	}
}

// TestSanitizeStripsTokens guards the UI-facing view: tokens must
// never leak through the public list endpoint.
func TestSanitizeStripsTokens(t *testing.T) {
	in := []Peer{
		{Name: "zima-2", URL: "http://x", Token: "s3cret"},
		{Name: "zima-3", URL: "http://y", Token: "another"},
	}
	out := Sanitize(in)
	if len(out) != 2 {
		t.Fatalf("got %d entries, want 2", len(out))
	}
	for i, p := range out {
		if p.Name != in[i].Name || p.URL != in[i].URL {
			t.Errorf("entry %d: %+v, want name=%q url=%q", i, p, in[i].Name, in[i].URL)
		}
	}
	// The Public type has no Token field — round-tripping through JSON
	// must not surface the secret even by accident.
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "s3cret") || strings.Contains(string(b), "another") {
		t.Errorf("Sanitize JSON leaked a token: %s", b)
	}
}

// TestPushHappyPathSendsBearerAndBody guards the on-wire shape: each
// peer gets its own Bearer header and the JSON body verbatim.
func TestPushHappyPathSendsBearerAndBody(t *testing.T) {
	var seenAuth, seenBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		seenBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ps := []Peer{{Name: "zima-2", URL: srv.URL, Token: "s3cret"}}
	body := []byte(`{"rules":[]}`)
	out := Push(context.Background(), srv.Client(), ps, body)
	if len(out) != 1 || !out[0].OK {
		t.Fatalf("Push result: %+v, want one OK", out)
	}
	if seenAuth != "Bearer s3cret" {
		t.Errorf("Authorization header = %q, want %q", seenAuth, "Bearer s3cret")
	}
	if seenBody != string(body) {
		t.Errorf("body = %q, want %q", seenBody, body)
	}
}

// TestPushSurfacesPerPeerError guards that a single bad peer is
// reported as a failure without aborting the rest of the fanout.
func TestPushSurfacesPerPeerError(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusUnauthorized)
	}))
	defer bad.Close()
	ps := []Peer{
		{Name: "zima-2", URL: good.URL, Token: "s3cret"},
		{Name: "zima-3", URL: bad.URL, Token: "s3cret"},
	}
	out := Push(context.Background(), good.Client(), ps, []byte(`{}`))
	if len(out) != 2 {
		t.Fatalf("len(out)=%d, want 2", len(out))
	}
	if !out[0].OK {
		t.Errorf("peer 0 should be OK, got %+v", out[0])
	}
	if out[1].OK {
		t.Errorf("peer 1 should fail, got %+v", out[1])
	}
	if out[1].Code != http.StatusUnauthorized {
		t.Errorf("peer 1 Code=%d, want 401", out[1].Code)
	}
}

// TestPushFailsOnEmptyToken guards the "configured peer with missing
// token" foot-gun — better to surface "token empty" than to send the
// request without a Bearer and let the receiver answer 401.
func TestPushFailsOnEmptyToken(t *testing.T) {
	ps := []Peer{{Name: "zima-2", URL: "http://example.com", Token: ""}}
	out := Push(context.Background(), &http.Client{}, ps, []byte(`{}`))
	if len(out) != 1 || out[0].OK {
		t.Fatalf("Push result: %+v, want one failure", out)
	}
	if !strings.Contains(out[0].Error, "token") {
		t.Errorf("error did not mention token: %q", out[0].Error)
	}
}
