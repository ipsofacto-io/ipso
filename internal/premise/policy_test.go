package premise

import (
	"net"
	"testing"
)

func TestAllowedAddr(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"172.15.255.255", true},
		{"100.63.255.255", true},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.31.255.1", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"100.127.255.1", false},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"0.0.0.0", false},
		{"0.1.2.3", false},
		{"255.255.255.255", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"fd12::1", false},
		{"2001:4860:4860::8888", true},
		{"::ffff:1.1.1.1", true},
		{"::ffff:10.0.0.1", false},
		{"::ffff:127.0.0.1", false},
		{"192.0.0.8", false},
		{"192.0.2.1", false},
		{"198.18.0.1", false},
		{"198.19.255.255", false},
		{"198.17.255.255", true},
		{"198.20.0.1", true},
		{"198.51.100.7", false},
		{"203.0.113.9", false},
		{"240.0.0.1", false},
		{"223.255.255.255", true},
		{"::", false},
		{"::10.0.0.1", false},
		{"::1.1.1.1", false},
		{"64:ff9b::a00:1", false},
		{"64:ff9b::101:101", false},
		{"2002:a00:1::", false},
		{"2002:101:101::", false},
		{"2001::1", false},
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", false},
		{"2001:1ff::1", false},
		{"2001:200::1", true},
		{"2001:db8::1", false},
		{"3fff::1", false},
		{"3fff:fff::1", false},
		{"3fff:1000::1", true},
		{"2606:4700:4700::1111", true},
		{"ff02::1", false},
	}
	for _, test := range cases {
		ip := net.ParseIP(test.ip)
		if ip == nil {
			t.Fatalf("parse %s", test.ip)
		}
		if got := allowedAddr(ip); got != test.want {
			t.Errorf("%s allowed = %v, want %v", test.ip, got, test.want)
		}
	}
}

func TestParseProbeURL(t *testing.T) {
	ok := []string{
		"https://example.com/platform/postgres.json",
		"https://example.com/a?b=1",
		"https://example.com:443/a",
	}
	for _, raw := range ok {
		if _, err := parseProbeURL(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	bad := []string{
		"http://example.com/a",
		"https://1.1.1.1/a",
		"https://[::1]/a",
		"https://user:pass@example.com/a",
		"https://example.com/a#frag",
		"https://example.com#",
		"https://example.com:8443/a",
		"https://b\u00fccher.example/a",
		"https://example\u212a.com/a",
	}
	for _, raw := range bad {
		if _, err := parseProbeURL(raw); err == nil {
			t.Errorf("%s was accepted", raw)
		}
	}
}
