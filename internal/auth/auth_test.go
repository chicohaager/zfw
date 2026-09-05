package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// signES256 builds a minimal ES256 JWT signed with key, carrying an
// accepted access-token issuer so it passes the session-scope check.
func signES256(t *testing.T, key *ecdsa.PrivateKey, exp int64) string {
	return signES256Iss(t, key, exp, sessionIssuers[0])
}

// signES256Iss is signES256 with an explicit `iss` claim so the
// issuer-scoping test can mint a refresh-style token.
func signES256Iss(t *testing.T, key *ecdsa.PrivateKey, exp int64, iss string) string {
	t.Helper()
	hdr := b64.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload := b64.EncodeToString([]byte(
		`{"iss":"` + iss + `","exp":` + strconv.FormatInt(exp, 10) + `}`))
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
	// Bytes() is the uncompressed SEC 1 encoding: 0x04 || X || Y, each
	// coordinate exactly 32 bytes for P-256 — the same shape RFC 7518 fixes
	// for the JWK "x"/"y" members.
	raw, err := pub.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	x, y := raw[1:33], raw[33:65]
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

// TestVerifyAcceptsBothPlatformIssuers pins the issuers by their literal
// names, not via sessionIssuers — a test that read the list back would stay
// green if an entry were dropped, which is exactly the failure that took the
// UI down after the ZimaOS v1.7.1-beta1 rename ("casaos" → "zimaos").
// Measured on .143: v1.7.0-beta1 mints "casaos", v1.7.1-beta1 mints "zimaos";
// hosts of both generations must keep working.
func TestVerifyAcceptsBothPlatformIssuers(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	v := NewVerifier(srv.URL)
	for _, iss := range []string{"casaos", "zimaos"} {
		tok := signES256Iss(t, key, time.Now().Add(time.Hour).Unix(), iss)
		if err := v.Verify(tok); err != nil {
			t.Fatalf("access token with iss %q rejected: %v", iss, err)
		}
	}
}

// TestVerifyRejectsNonSessionIssuer pins the R5 issuer-scoping fix: a
// token with a valid signature, valid expiry, but a non-session `iss`
// (the refresh token's "refresh", verified against a live .143 login)
// must be refused so it cannot authorise the firewall control API.
func TestVerifyRejectsNonSessionIssuer(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	v := NewVerifier(srv.URL)
	tok := signES256Iss(t, key, time.Now().Add(time.Hour).Unix(), "refresh")
	if err := v.Verify(tok); err == nil {
		t.Fatal("refresh-issuer token was accepted as a session")
	}
	// An empty issuer is likewise not a session token.
	tok = signES256Iss(t, key, time.Now().Add(time.Hour).Unix(), "")
	if err := v.Verify(tok); err == nil {
		t.Fatal("issuer-less token was accepted as a session")
	}
	// Widening the accepted set must not turn into "any issuer goes".
	tok = signES256Iss(t, key, time.Now().Add(time.Hour).Unix(), "attacker")
	if err := v.Verify(tok); err == nil {
		t.Fatal("token with an unrelated issuer was accepted as a session")
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

// TestMiddlewareLogsRejection pins that a refused request leaves a trace in
// the journal, naming the reason. Before v1.0.23 it left none: when ZimaOS
// renamed the token issuer, every request failed and the log was silent, so
// the outage could only be diagnosed from the browser console.
func TestMiddlewareLogsRejection(t *testing.T) {
	var buf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(restore)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	v := NewVerifier(srv.URL)
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer "+
		signES256Iss(t, key, time.Now().Add(time.Hour).Unix(), "refresh"))
	req.Header.Set("X-Forwarded-For", "192.0.2.7")
	h.ServeHTTP(httptest.NewRecorder(), req)

	line := buf.String()
	// slog's text handler escapes the quotes around the issuer it quotes back.
	for _, want := range []string{"session rejected", `issuer \"refresh\"`, "/api/status", "192.0.2.7"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line does not mention %q:\n%s", want, line)
		}
	}
	// The token itself must never reach the journal.
	if strings.Contains(line, "eyJ") {
		t.Errorf("log line appears to contain the token:\n%s", line)
	}
}

// TestRejectLogRateLimits pins the counting: rejections are attacker-
// triggerable, so only the first of a burst is written and the rest are
// counted for the next line that gets through.
func TestRejectLogRateLimits(t *testing.T) {
	var l rejectLog
	now := time.Now()

	if ok, n := l.admit(now); !ok || n != 0 {
		t.Fatalf("first rejection: admit=%v suppressed=%d, want true/0", ok, n)
	}
	for i := 0; i < 5; i++ {
		if ok, _ := l.admit(now.Add(time.Second)); ok {
			t.Fatalf("rejection %d within the interval was logged", i)
		}
	}
	ok, n := l.admit(now.Add(rejectLogInterval))
	if !ok || n != 5 {
		t.Fatalf("after the interval: admit=%v suppressed=%d, want true/5", ok, n)
	}
	// The counter resets once it has been reported.
	if ok, n := l.admit(now.Add(2 * rejectLogInterval)); !ok || n != 0 {
		t.Fatalf("next line: admit=%v suppressed=%d, want true/0", ok, n)
	}
}

// A JWK whose coordinate lost its leading zero byte(s) on the wire must still
// yield the same key the big.Int-based construction produced, and a point
// that is not on the curve must be refused rather than installed.
func TestP256PublicKeyPadsShortCoordinatesAndRejectsOffCurve(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	x, y := raw[1:33], raw[33:65]

	full, err := p256PublicKey(x, y)
	if err != nil {
		t.Fatalf("full-length coordinates rejected: %v", err)
	}
	if !full.Equal(&key.PublicKey) {
		t.Fatal("full-length coordinates yielded a different key")
	}

	// Strip leading zero bytes the way an encoder working from a big.Int would.
	trim := func(b []byte) []byte {
		for len(b) > 1 && b[0] == 0 {
			b = b[1:]
		}
		return b
	}
	short, err := p256PublicKey(trim(x), trim(y))
	if err != nil {
		t.Fatalf("leading-zero-stripped coordinates rejected: %v", err)
	}
	if !short.Equal(&key.PublicKey) {
		t.Fatal("padding changed the key")
	}

	// Positive control for the on-curve check: flip a bit of y.
	bad := append([]byte(nil), y...)
	bad[31] ^= 1
	if _, err := p256PublicKey(x, bad); err == nil {
		t.Fatal("off-curve point accepted")
	}
	if _, err := p256PublicKey(append([]byte{0}, raw[1:]...), y); err == nil {
		t.Fatal("33-byte coordinate accepted")
	}
}
