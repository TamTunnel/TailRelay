package web

import (
	"strings"
	"testing"

	"github.com/TamTunnel/Tailrelay/internal/ts"
)

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

func TestExitNodeWarning(t *testing.T) {
	nodes := func() []ts.ExitNode {
		return []ts.ExitNode{
			{Hostname: "exit-1", IP: "100.64.0.2", Online: true, Selected: true},
			{Hostname: "exit-2", IP: "100.64.0.3", Online: true},
		}
	}
	if w := exitNodeWarning("", nodes()); w != "" {
		t.Errorf("no pin: got %q, want empty", w)
	}
	if w := exitNodeWarning("exit-1", nodes()); w != "" {
		t.Errorf("healthy pin: got %q, want empty", w)
	}
	down := nodes()
	down[0].Online = false
	w := exitNodeWarning("exit-1", down)
	if w == "" || !strings.Contains(w, "OFFLINE") || !strings.Contains(w, "fail-closed") {
		t.Errorf("offline pin: got %q, want fail-closed OFFLINE warning", w)
	}
	gone := nodes()
	gone[0].Selected = false
	// Pin exists in list but not yet selected (transitional) — no warning.
	w = exitNodeWarning("exit-1", gone)
	if w != "" {
		t.Errorf("transitional pin: got %q, want empty (no false alarm during switch)", w)
	}
	// Pin vanished from list entirely — warn.
	vanished := []ts.ExitNode{
		{Hostname: "exit-2", IP: "100.64.0.3", Online: true},
	}
	w = exitNodeWarning("exit-1", vanished)
	if w == "" || !strings.Contains(w, "not active") {
		t.Errorf("vanished pin: got %q, want not-active warning", w)
	}
}
