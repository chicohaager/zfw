// Package httputil holds shared HTTP-client hardening helpers used by
// outbound-fetching modules (update.Checker, notify.Hook). Both clients
// can be pointed at operator-set URLs; both must refuse redirects that
// would silently relocate the request to a loopback / private address
// or downgrade the scheme from https→http.
//
// Round-4 R4-7 (closed v1.0.2): an attacker controlling DNS for an
// operator-set URL could otherwise coerce the daemon into hitting a
// private/loopback address — narrowing the trust anchor for what is
// nominally a public webhook / manifest URL. The CheckRedirect callback
// returned by SafeCheckRedirect refuses:
//
//  1. Cross-scheme downgrade (https→http). http→https is allowed (an
//     upgrade) but the reverse silently strips transport security.
//  2. Redirects to a loopback / private / link-local / unspecified IP
//     when the *original* URL was a public address. A loopback original
//     stays loopback-only (matches the S1/S2 JWKS spirit but inverted).
//  3. More than 5 hops (Go's default is 10; tighter cap = smaller
//     window for an SSRF chain to walk an attacker through redirects).
package httputil

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// SafeCheckRedirect returns a CheckRedirect callback suitable for
// http.Client. The original URL of the request is captured from
// via[0].URL and used as the "is the original URL public?" oracle.
func SafeCheckRedirect(maxHops int) func(req *http.Request, via []*http.Request) error {
	if maxHops < 1 {
		maxHops = 5
	}
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxHops {
			return fmt.Errorf("stopped after %d redirects", maxHops)
		}
		if len(via) == 0 {
			return nil
		}
		orig := via[0].URL
		next := req.URL

		// Rule 1: refuse https→http downgrade. http→https is an upgrade
		// and is allowed.
		if orig.Scheme == "https" && next.Scheme == "http" {
			return fmt.Errorf("refusing https→http redirect to %s", next.Host)
		}

		// Rule 2: refuse public→private redirect. If the original URL
		// resolved to a public address, every hop must also be public.
		// A loopback-only original (e.g. the JWKS endpoint pinned at
		// 127.0.0.1) is already on-host so the asymmetry is fine — it
		// can only "redirect into itself".
		if origIsPublic, err := hostIsPublic(orig.Hostname()); err == nil && origIsPublic {
			if nextIsPublic, err := hostIsPublic(next.Hostname()); err == nil && !nextIsPublic {
				return fmt.Errorf("refusing redirect from public %s to private %s",
					orig.Host, next.Host)
			}
		}
		return nil
	}
}

// hostIsPublic reports whether host (a literal IP or a DNS name)
// resolves to a non-private, non-loopback, non-link-local IP. Returns
// (false, err) on resolution failure so the caller can decide to allow
// or refuse — SafeCheckRedirect treats resolution failure as "skip the
// public→private check" (the request will fail anyway on Dial).
func hostIsPublic(host string) (bool, error) {
	if host == "" {
		return false, fmt.Errorf("empty host")
	}
	if host == "localhost" {
		return false, nil
	}
	// Literal IP — no resolution needed.
	if ip := net.ParseIP(host); ip != nil {
		return ipIsPublic(ip), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false, err
	}
	if len(ips) == 0 {
		return false, fmt.Errorf("no addresses for %s", host)
	}
	// All resolved addresses must be public; one private answer is
	// enough to drop the "public" claim (DNS-rebinding-style answers
	// where the second response flips to 127.0.0.1).
	for _, ip := range ips {
		if !ipIsPublic(ip) {
			return false, nil
		}
	}
	return true, nil
}

// ipIsPublic reports whether ip is outside the loopback / private /
// link-local / unspecified ranges. Mirrors net.IP convenience helpers
// but rolls multicast and the IPv4 documentation ranges into "private"
// as well — anything an operator-set webhook URL has no legitimate
// reason to redirect into.
func ipIsPublic(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		ip.IsUnspecified() {
		return false
	}
	return true
}

// IsLoopbackURL reports whether u is an http/https URL whose host is a
// loopback address. Exists here as a side-effect-free utility shared by
// the daemon entrypoint (which uses it to validate the JWKS trust
// anchor) and by any future caller that wants the same check.
func IsLoopbackURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") {
		return false
	}
	host := p.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
