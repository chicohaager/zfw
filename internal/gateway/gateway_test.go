package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// writeURLFile drops a management-URL file and returns its path.
func writeURLFile(t *testing.T, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mgmt.url")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("write url file: %v", err)
	}
	return p
}

// TestMgmtURLNormalises guards the base-URL normalisation: a bare
// host:port gets an http:// scheme, trailing slashes are stripped, and
// an empty/missing file errors rather than producing a bad request URL.
func TestMgmtURLNormalises(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"http://127.0.0.1:8080/", "http://127.0.0.1:8080"},
		{"https://gw.local/v1/", "https://gw.local/v1"},
		{"  127.0.0.1:9000\n", "http://127.0.0.1:9000"},
	}
	for _, c := range cases {
		m := New(writeURLFile(t, c.in), "/v2/zfw", "127.0.0.1:8489")
		got, err := m.mgmtURL()
		if err != nil {
			t.Errorf("mgmtURL(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("mgmtURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	if _, err := New(writeURLFile(t, "   "), "/v2/zfw", "t").mgmtURL(); err == nil {
		t.Error("empty url file did not error")
	}
	if _, err := New(filepath.Join(t.TempDir(), "nope"), "/v2/zfw", "t").mgmtURL(); err == nil {
		t.Error("missing url file did not error")
	}
}

// TestRegisterPostsRoute guards that Register POSTs the path+target as
// JSON to /v1/gateway/routes and treats a non-2xx as an error.
func TestRegisterPostsRoute(t *testing.T) {
	var gotPath, gotTarget string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/gateway/routes" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body struct{ Path, Target string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotPath, gotTarget = body.Path, body.Target
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := New(writeURLFile(t, srv.URL), "/v2/zfw", "127.0.0.1:8489")
	if err := m.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if gotPath != "/v2/zfw" || gotTarget != "127.0.0.1:8489" {
		t.Errorf("registered path=%q target=%q, want /v2/zfw + 127.0.0.1:8489", gotPath, gotTarget)
	}

	// Non-2xx must surface as an error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if err := New(writeURLFile(t, bad.URL), "/v2/zfw", "t").Register(); err == nil {
		t.Error("Register did not error on HTTP 500")
	}
}

// TestLookupTarget guards the JWKS-port-discovery path: LookupTarget
// returns the target for a matching route and errors when the route is
// absent (so the daemon never silently falls back to a wrong port).
func TestLookupTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"path": "/.well-known/jwks.json", "target": "127.0.0.1:37815"},
			{"path": "/v2/other", "target": "127.0.0.1:9000"},
		})
	}))
	defer srv.Close()

	m := New(writeURLFile(t, srv.URL), "/v2/zfw", "t")
	got, err := m.LookupTarget(context.Background(), "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("LookupTarget: %v", err)
	}
	if got != "127.0.0.1:37815" {
		t.Errorf("target = %q, want 127.0.0.1:37815", got)
	}

	if _, err := m.LookupTarget(context.Background(), "/not/registered"); err == nil {
		t.Error("LookupTarget did not error on a missing route")
	}
}
