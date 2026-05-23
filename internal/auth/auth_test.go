package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// signES256 builds a minimal ES256 JWT signed with key.
func signES256(t *testing.T, key *ecdsa.PrivateKey, exp int64) string {
	t.Helper()
	hdr := b64.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload := b64.EncodeToString([]byte(`{"exp":` + strconv.FormatInt(exp, 10) + `}`))
	signingInput := hdr + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64.EncodeToString(sig)
}

// jwksServer serves a JWKS containing pub as its only EC/P-256 key.
func jwksServer(t *testing.T, pub *ecdsa.PublicKey) *httptest.Server {
	t.Helper()
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	body, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256",
			"x": b64.EncodeToString(x), "y": b64.EncodeToString(y),
		}},
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
}

func TestVerifyValidToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	v := NewVerifier(srv.URL)
	tok := signES256(t, key, time.Now().Add(time.Hour).Unix())
	if err := v.Verify(tok); err != nil {
		t.Fatalf("gültiger Token abgelehnt: %v", err)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	v := NewVerifier(srv.URL)
	tok := signES256(t, key, time.Now().Add(-time.Hour).Unix())
	if err := v.Verify(tok); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestVerifyForeignSignature(t *testing.T) {
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwksKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := jwksServer(t, &jwksKey.PublicKey)
	defer srv.Close()
	v := NewVerifier(srv.URL)
	tok := signES256(t, signKey, time.Now().Add(time.Hour).Unix())
	if err := v.Verify(tok); err == nil {
		t.Fatal("token with foreign signature was accepted")
	}
}

func TestVerifyMalformed(t *testing.T) {
	v := NewVerifier("http://127.0.0.1:0")
	if err := v.Verify("not-a-jwt"); err == nil {
		t.Fatal("Nicht-JWT wurde akzeptiert")
	}
}

func TestMiddlewareRejectsMissingToken(t *testing.T) {
	v := NewVerifier("http://127.0.0.1:0")
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), func(p string) bool { return p == "/api/health" })

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/apply", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ohne Token: Status %d, erwartet 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ausgenommener Pfad: Status %d, erwartet 200", rec.Code)
	}
}
