// Package auth verifies ZimaOS session tokens so the firewall control API is
// not reachable unauthenticated. ZimaOS issues ES256 JWTs (the web UI keeps
// one in localStorage.access_token); this package checks a token's signature
// against the platform JWKS and rejects anything unsigned, wrong-algorithm,
// not-yet-valid or expired. The ZimaOS gateway proxies module routes without
// authenticating them, so every module must do this check itself.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwksTTL is how long a fetched key set is reused before a refresh.
const jwksTTL = 10 * time.Minute

// jwksMaxStale caps how long a cached key set may keep being served once
// refreshes start failing. Past this the verifier fails closed rather than
// trusting keys that may since have been rotated or revoked (ZFW-S6).
const jwksMaxStale = 1 * time.Hour

// clockSkew is the tolerance applied when checking the nbf claim.
const clockSkew = 60 * time.Second

// sessionIssuers are the `iss` claims a ZimaOS *access* token may carry.
// The user-service mints other tokens with the SAME signing key — notably
// the long-lived refresh token (iss "refresh", ~7-day expiry). Without an
// issuer check, a refresh token (or any future same-key token type) would
// be accepted as a fully-privileged firewall session. We pin the
// access-token issuers so only a genuine web-session token authorises the
// control API.
//
// ZimaOS renamed the access-token issuer in v1.7.1-beta1: what used to be
// "casaos" is now "zimaos". Both are accepted so ZFW keeps working on
// v1.7.0 and older hosts as well as on v1.7.1+. The refresh token kept its
// own issuer through the rename and stays rejected.
//
// Measured with live logins against .143:
//   - 2026-06-12, v1.7.0-beta1: access iss="casaos",  refresh iss="refresh"
//   - 2026-08-12, v1.7.1-beta1: access iss="zimaos",  refresh iss="refresh"
//     (POST /v1/users/refresh also returns an access token with iss="zimaos")
var sessionIssuers = []string{"casaos", "zimaos"}

// isSessionIssuer reports whether iss identifies a ZimaOS web-session
// access token.
func isSessionIssuer(iss string) bool {
	for _, want := range sessionIssuers {
		if iss == want {
			return true
		}
	}
	return false
}

// b64 is the base64url encoding (no padding) used throughout JWT/JWK.
var b64 = base64.RawURLEncoding

// keyEntry is one JWKS verification key together with its key id (the kid may
// be empty when the JWKS does not label its keys).
type keyEntry struct {
	kid string
	pub *ecdsa.PublicKey
}

// Verifier checks ES256 JWTs against a cached, periodically refreshed JWKS.
type Verifier struct {
	jwksURL string
	http    *http.Client

	mu      sync.RWMutex
	keys    []keyEntry
	fetched time.Time

	rejects rejectLog
}

// NewVerifier returns a Verifier that loads its keys from jwksURL. The HTTP
// client refuses redirects so the JWKS fetch cannot be bounced off-host.
func NewVerifier(jwksURL string) *Verifier {
	return &Verifier{
		jwksURL: jwksURL,
		http: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirect during JWKS fetch refused")
			},
		},
	}
}

// jwk is one JSON Web Key. ZimaOS signs with ES256, so only EC keys matter.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// refreshKeys fetches the JWKS and parses its EC/P-256 keys into the cache.
func (v *Verifier) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return err
	}
	var keys []keyEntry
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		x, errX := b64.DecodeString(k.X)
		y, errY := b64.DecodeString(k.Y)
		if errX != nil || errY != nil {
			continue
		}
		keys = append(keys, keyEntry{
			kid: k.Kid,
			pub: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			},
		})
	}
	if len(keys) == 0 {
		return errors.New("JWKS contains no EC/P-256 key")
	}
	v.mu.Lock()
	v.keys, v.fetched = keys, time.Now()
	v.mu.Unlock()
	return nil
}

// Warm loads the key set once so the first request is not slowed by a fetch.
// A failure is non-fatal — keys are retried lazily on the first verification.
func (v *Verifier) Warm(ctx context.Context) error {
	return v.refreshKeys(ctx)
}

// currentKeys returns the cached keys, refreshing them when stale or absent.
// A refresh failure is tolerated only while the cached set is still younger
// than jwksMaxStale; past that the verifier fails closed.
func (v *Verifier) currentKeys() ([]keyEntry, error) {
	v.mu.RLock()
	keys, fetched := v.keys, v.fetched
	v.mu.RUnlock()
	if len(keys) > 0 && time.Since(fetched) < jwksTTL {
		return keys, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := v.refreshKeys(ctx); err != nil {
		if len(keys) > 0 && time.Since(fetched) < jwksMaxStale {
			return keys, nil // keep serving with the still-recent cached set
		}
		return nil, err
	}
	v.mu.RLock()
	keys = v.keys
	v.mu.RUnlock()
	return keys, nil
}

// Verify checks a raw JWT string: the header is ES256, the r‖s signature
// matches a JWKS key (selected by kid when the token names one) over SHA-256
// of the signing input, and the token is currently within its validity
// window (exp is mandatory, nbf is honoured with a small clock skew).
func (v *Verifier) Verify(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a JWT (three segments expected)")
	}
	hdrRaw, err := b64.DecodeString(parts[0])
	if err != nil {
		return errors.New("header not decodable")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return errors.New("header not readable")
	}
	if hdr.Alg != "ES256" {
		return fmt.Errorf("alg %q not supported (only ES256)", hdr.Alg)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("signature invalid")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	keys, err := v.currentKeys()
	if err != nil {
		return fmt.Errorf("JWKS unavailable: %w", err)
	}
	verified := false
	for _, k := range keys {
		// When the token names a kid, only a key with the same kid may
		// verify it — this keeps key rotation correct. Keys published
		// without a kid stay eligible for any token.
		if hdr.Kid != "" && k.kid != "" && k.kid != hdr.Kid {
			continue
		}
		if ecdsa.Verify(k.pub, digest[:], r, s) {
			verified = true
			break
		}
	}
	if !verified {
		return errors.New("signature matches no JWKS key")
	}

	plRaw, err := b64.DecodeString(parts[1])
	if err != nil {
		return errors.New("payload not decodable")
	}
	var claims struct {
		Iss string `json:"iss"`
		Exp int64  `json:"exp"`
		Nbf int64  `json:"nbf"`
	}
	if err := json.Unmarshal(plRaw, &claims); err != nil {
		return errors.New("payload not readable")
	}
	// Scope the token to a ZimaOS web session: the refresh token and any
	// other token type the user-service mints with the same signing key
	// carry a different `iss`, and must not authorise the control API
	// (R5 open recommendation).
	if !isSessionIssuer(claims.Iss) {
		return fmt.Errorf("token issuer %q not accepted (want one of %v)", claims.Iss, sessionIssuers)
	}
	// A ZimaOS session token must carry an expiry — a token without exp is
	// rejected rather than trusted forever (ZFW-S2).
	if claims.Exp == 0 {
		return errors.New("token without expiry (exp)")
	}
	now := time.Now()
	if now.Unix() >= claims.Exp {
		return errors.New("token expired")
	}
	if claims.Nbf != 0 && now.Add(clockSkew).Unix() < claims.Nbf {
		return errors.New("token not yet valid (nbf)")
	}
	return nil
}

// rejectLogInterval is the minimum spacing between two "session rejected"
// log lines. Rejections are attacker-triggerable, so they are rate-limited
// rather than logged one-for-one; everything suppressed in between is
// counted and reported on the next line that gets through.
const rejectLogInterval = 30 * time.Second

// rejectLog rate-limits the rejection warnings of one Verifier.
//
// Why this exists: until v1.0.23 a rejected session produced no log line at
// all — the reason went into the 401 body and nowhere else. When ZimaOS
// v1.7.1-beta1 renamed the access token's issuer, every request failed and
// `journalctl -u zfw-ui` showed nothing out of the ordinary; the cause was
// only visible in the browser console. One line in the journal would have
// named it outright.
type rejectLog struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int
}

// admit reports whether this rejection should be logged now, and how many
// were suppressed since the last line that was.
func (l *rejectLog) admit(now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < rejectLogInterval {
		l.suppressed++
		return false, 0
	}
	n := l.suppressed
	l.last, l.suppressed = now, 0
	return true, n
}

// logReject writes one rate-limited WARN for a refused request. The reason
// is the verifier's own error — it never contains the token, only what was
// wrong with it (a wrong issuer is named, which is the whole point).
func (v *Verifier) logReject(r *http.Request, reason string) {
	ok, suppressed := v.rejects.admit(time.Now())
	if !ok {
		return
	}
	slog.Warn("session rejected",
		"reason", reason,
		"path", r.URL.Path,
		"client", clientAddr(r),
		"suppressed_since_last", suppressed)
}

// clientAddr names the requester for the log. The daemon binds loopback
// behind the ZimaOS gateway, so RemoteAddr is almost always 127.0.0.1 and
// the real LAN client arrives in X-Forwarded-For. XFF is gateway-set and
// unauthenticated — good enough to identify a machine in a log line, and it
// grants nothing.
func clientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			xff = first
		}
		if s := strings.TrimSpace(xff); s != "" {
			return s
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// Middleware wraps next so every request must carry a valid ZimaOS bearer
// token. exempt(path) may return true for endpoints left open (e.g. health).
func (v *Verifier) Middleware(next http.Handler, exempt func(path string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exempt != nil && exempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		token := bearerToken(r)
		if token == "" {
			v.logReject(r, "no bearer token")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if err := v.Verify(token); err != nil {
			v.logReject(r, err.Error())
			http.Error(w, "invalid session: "+err.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerToken extracts the token from an "Authorization: Bearer <jwt>" header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}
