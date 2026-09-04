package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP returns the address a request should be attributed to: the rate limiter's key and
// the IP bound into a session. Both must agree, or a caller could be throttled as one client
// and recorded as another.
//
// trusted is the parsed KY_TRUSTED_PROXIES allowlist. It is empty by default, and then the
// peer address is the answer and every header is ignored: X-Forwarded-For is caller-supplied,
// so honouring it unconditionally lets anyone mint a fresh limiter bucket per request.
//
// When the peer is a trusted proxy, X-Forwarded-For is walked from the right, skipping
// entries that are themselves trusted proxies, and the first untrusted entry wins. Everything
// to its left was appended by a hop we do not trust and may be forged. An entry that does not
// parse as an IP ends the walk and the peer is used, since the rest of the chain sits behind
// something that is not speaking the protocol.
//
// X-Real-IP is ignored outright. It carries no chain, so it cannot be walked; a deployment
// that needs a client IP must forward X-Forwarded-For.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := peerIP(r)
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil || !isTrusted(peerAddr, trusted) {
		return peer
	}

	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			return peer
		}
		addr = addr.Unmap()
		if !isTrusted(addr, trusted) {
			return addr.String()
		}
	}
	return peer
}

// peerIP is the transport peer: the host half of RemoteAddr, normalised so an IPv4-mapped
// IPv6 peer keys the same bucket as the plain IPv4 one.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = strings.Trim(r.RemoteAddr, "[]")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
