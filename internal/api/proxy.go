package api

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Behind a reverse proxy every connection comes from the proxy, so the
// connecting address says nothing about who the user is, and the proxy
// reports the real one in X-Forwarded-For. Those headers are plain text that
// anyone can send, so they are believed only when the connection itself comes
// from an address the operator listed as a trusted proxy, and even then not
// blindly: see clientIP.

// ParseTrustedProxies reads a comma-separated list of addresses and CIDR ranges.
// A range that would trust everyone (a /0) is refused: it would let any client
// choose the address it is rate-limited and logged under.
func ParseTrustedProxies(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		var p netip.Prefix
		if strings.Contains(item, "/") {
			var err error
			if p, err = netip.ParsePrefix(item); err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %v", item, err)
			}
		} else {
			a, err := netip.ParseAddr(item)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q is not an address or a range", item)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		bits := unmappedBits(p)
		if bits <= 0 {
			return nil, fmt.Errorf("trusted proxy %q would trust every address", item)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), bits).Masked()
		if p.Bits() == 0 {
			return nil, fmt.Errorf("trusted proxy %q would trust every address", item)
		}
		out = append(out, p)
	}
	return out, nil
}

// unmappedBits keeps the prefix length meaningful when an IPv4 range was
// written in its IPv4-mapped IPv6 form (::ffff:10.0.0.0/104 is 10.0.0.0/8).
func unmappedBits(p netip.Prefix) int {
	if p.Addr().Is4In6() {
		return p.Bits() - 96
	}
	return p.Bits()
}

func (s *Server) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peer is the address of the connection itself.
func peer(r *http.Request) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// fromProxy reports whether the connection comes from a trusted proxy.
func (s *Server) fromProxy(r *http.Request) bool {
	if len(s.proxies) == 0 {
		return false
	}
	a, ok := peer(r)
	return ok && s.trusted(a)
}

// clientIP is the address of the person behind the request.
//
// Without trusted proxies, or when the connection is not from one, it is the
// connecting address and every forwarded header is ignored. From a trusted
// proxy it is the first address in X-Forwarded-For, reading from the right,
// that is not itself a trusted proxy: the entries to its left were supplied by
// the client and are never used, so a client cannot pick its own address by
// sending a header of its own. Anything unparsable stops the walk at the last
// address that could be believed.
func (s *Server) clientIP(r *http.Request) string {
	p, ok := peer(r)
	if !ok {
		return r.RemoteAddr
	}
	if !s.trusted(p) {
		return p.String()
	}
	hdr := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if hdr == "" {
		return p.String()
	}
	parts := strings.Split(hdr, ",")
	best := p
	for i := len(parts) - 1; i >= 0; i-- {
		a, ok := parseForwarded(parts[i])
		if !ok {
			break
		}
		best = a
		if !s.trusted(a) {
			break
		}
	}
	return best.String()
}

// parseForwarded reads one X-Forwarded-For entry, tolerating a port and the
// brackets some proxies put around IPv6 addresses.
func parseForwarded(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		if a, err := netip.ParseAddr(h); err == nil {
			return a.Unmap(), true
		}
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if a, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil {
			return a.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// requestHost is the host the browser asked for. A trusted proxy may rewrite
// the Host header on its way in and report the original in X-Forwarded-Host;
// that is believed only from a trusted proxy.
func (s *Server) requestHost(r *http.Request) string {
	if s.fromProxy(r) {
		if h := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); h != "" && !strings.ContainsAny(h, " /\\@") {
			return h
		}
	}
	return r.Host
}

// forwardedPlain reports a trusted proxy that says it received the request
// over plain HTTP. With secure cookies on, the browser would silently drop the
// session cookie, so it is better to refuse loudly.
func (s *Server) forwardedPlain(r *http.Request) bool {
	if !s.secure || !s.fromProxy(r) {
		return false
	}
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return proto != "" && !strings.EqualFold(proto, "https")
}
