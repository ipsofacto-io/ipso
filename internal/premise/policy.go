package premise

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

var errURL = errors.New("url")

// parseProbeURL accepts an https URL with an ASCII DNS name, no userinfo, no fragment,
// and a port that is absent or 443. A query string is allowed. A name outside ASCII has to be
// written in punycode: Unicode case folding maps some letters, such as the Kelvin sign, to ASCII,
// so a caller that compares the lowercase host would compare a name other than the one dialed.
func parseProbeURL(raw string) (*url.URL, error) {
	if strings.Contains(raw, "#") {
		return nil, errURL
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil {
		return nil, errURL
	}
	host := parsed.Hostname()
	if host == "" || net.ParseIP(host) != nil || !isASCII(host) {
		return nil, errURL
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return nil, errURL
	}
	return parsed, nil
}

// blockedV4 is every IPv4 range the IANA special-purpose registry marks as not globally reachable,
// except loopback, link-local, multicast, and broadcast, which IsGlobalUnicast already refuses.
var blockedV4 = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
)

// globalV6 is the block IANA delegates for global unicast. It leaves out the unspecified and loopback
// addresses, IPv4-compatible and IPv4-mapped forms, the NAT64 prefix 64:ff9b::/96, unique local
// fc00::/7, and link-local fe80::/10.
var globalV6 = netip.MustParsePrefix("2000::/3")

// blockedV6 is what is left inside globalV6 that is not a public host. 2001::/23 holds the protocol
// assignments, Teredo among them, 2002::/16 is 6to4, and a gateway for either one can reach a private
// IPv4 address that the prefix embeds.
var blockedV6 = mustPrefixes(
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"3fff::/20",
)

func mustPrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, text := range list {
		out[i] = netip.MustParsePrefix(text)
	}
	return out
}

// allowedAddr reports whether ip is a public unicast address.
// Go stores IPv4 as an IPv4-mapped IPv6 address, so a mapped address is judged
// by its IPv4 rules and dialed as IPv4. A mapped private address is refused.
func allowedAddr(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return false
	}
	if addr.Is4() {
		return !inAny(addr, blockedV4)
	}
	return globalV6.Contains(addr) && !inAny(addr, blockedV6)
}

func isASCII(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			return false
		}
	}
	return true
}

func inAny(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Host returns the lowercase host name of a URL that Check accepts, and false for a URL that Check
// refuses with ReasonURL. The name is ASCII, so lowercasing it cannot turn it into another name. A
// trailing dot is kept.
func Host(raw string) (string, bool) {
	parsed, err := parseProbeURL(raw)
	if err != nil {
		return "", false
	}
	return strings.ToLower(parsed.Hostname()), true
}
