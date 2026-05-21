// Package auth verifies ZimaOS session tokens so the firewall control API is
// not reachable unauthenticated. ZimaOS issues ES256 JWTs (the web UI keeps
// one in localStorage.access_token); this package checks a token's signature
// against the platform JWKS and rejects anything unsigned, wrong-algorithm or
// expired. The ZimaOS gateway proxies module routes without authenticating
// them, so every module must do this check itself.
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
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwksTTL is how long a fetched key set is reused before a refresh.
const jwksTTL = 10 * time.Minute

// b64 is the base64url encoding (no padding) used throughout JWT/JWK.
var b64 = base64.RawURLEncoding

// Verifier checks ES256 JWTs against a cached, periodically refreshed JWKS.
type Verifier struct {
	jwksURL string
	http    *http.Client

	mu      sync.RWMutex
	keys    []*ecdsa.PublicKey
	fetched time.Time
}

// NewVerifier returns a Verifier that loads its keys from jwksURL.
func NewVerifier(jwksURL string) *Verifier {
	return &Verifier{
		jwksURL: jwksURL,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

// jwk is one JSON Web Key. ZimaOS signs with ES256, so only EC keys matter.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
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
	var keys []*ecdsa.PublicKey
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		x, errX := b64.DecodeString(k.X)
		y, errY := b64.DecodeString(k.Y)
		if errX != nil || errY != nil {
			continue
		}
		keys = append(keys, &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		})
	}
	if len(keys) == 0 {
		return errors.New("JWKS enthält keinen EC/P-256-Schlüssel")
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
// A refresh failure is tolerated as long as a previous key set is cached.
func (v *Verifier) currentKeys() ([]*ecdsa.PublicKey, error) {
	v.mu.RLock()
	keys, fetched := v.keys, v.fetched
	v.mu.RUnlock()
	if len(keys) > 0 && time.Since(fetched) < jwksTTL {
		return keys, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := v.refreshKeys(ctx); err != nil {
		if len(keys) > 0 {
			return keys, nil // keep serving with the cached set
		}
		return nil, err
	}
	v.mu.RLock()
	keys = v.keys
	v.mu.RUnlock()
	return keys, nil
}

// Verify checks a raw JWT string: the header is ES256, the r‖s signature
// matches a JWKS key over SHA-256 of the signing input, and exp is not past.
func (v *Verifier) Verify(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("kein JWT (drei Segmente erwartet)")
	}
	hdrRaw, err := b64.DecodeString(parts[0])
	if err != nil {
		return errors.New("Header nicht dekodierbar")
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return errors.New("Header nicht lesbar")
	}
	if hdr.Alg != "ES256" {
		return fmt.Errorf("alg %q nicht unterstützt (nur ES256)", hdr.Alg)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("Signatur ungültig")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	keys, err := v.currentKeys()
	if err != nil {
		return fmt.Errorf("JWKS nicht verfügbar: %w", err)
	}
	verified := false
	for _, k := range keys {
		if ecdsa.Verify(k, digest[:], r, s) {
			verified = true
			break
		}
	}
	if !verified {
		return errors.New("Signatur stimmt mit keinem JWKS-Schlüssel")
	}

	plRaw, err := b64.DecodeString(parts[1])
	if err != nil {
		return errors.New("Payload nicht dekodierbar")
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(plRaw, &claims); err != nil {
		return errors.New("Payload nicht lesbar")
	}
	if claims.Exp != 0 && time.Now().Unix() >= claims.Exp {
		return errors.New("Token abgelaufen")
	}
	return nil
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
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if err := v.Verify(token); err != nil {
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
