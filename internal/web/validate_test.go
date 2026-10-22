package web

import "testing"

func TestValidEndpoint(t *testing.T) {
	for _, ok := range []string{"", "vpn.example.com", "vpn.example.com:51820", "203.0.113.10", "203.0.113.10:51820"} {
		if !validEndpoint(ok) {
			t.Errorf("validEndpoint(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"vpn.example.com:99999", "vpn.example.com:notaport", "bad\nhost", "has space.com", "x:1:2"} {
		if validEndpoint(bad) {
			t.Errorf("validEndpoint(%q) = true, want false", bad)
		}
	}
}

func TestValidHost(t *testing.T) {
	for _, ok := range []string{"1.1.1.1", "vpn.example.com", "localhost"} {
		if !validHost(ok) {
			t.Errorf("validHost(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "a\nb", "has space", "-leading.example.com", "toolonglabel" + string(make([]byte, 64))} {
		if validHost(bad) {
			t.Errorf("validHost(%q) = true, want false", bad)
		}
	}
}

func TestValidAllowedIPs(t *testing.T) {
	for _, ok := range []string{"0.0.0.0/0", "0.0.0.0/0, 10.0.0.0/8", "100.64.0.0/10,fd7a:115c:a1e0::/48"} {
		if !validAllowedIPs(ok) {
			t.Errorf("validAllowedIPs(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "0.0.0.0/0,\n10.0.0.0/8", "not-a-cidr", "10.0.0.0/33", "0.0.0.0/0,"} {
		if validAllowedIPs(bad) {
			t.Errorf("validAllowedIPs(%q) = true, want false", bad)
		}
	}
}
