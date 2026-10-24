package wg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TamTunnel/Tailrelay/internal/state"
)

// natFake records iptables/ip6tables/ip calls. checkFails controls whether
// `-C` reports the rule as missing (for either iptables family).
type natFake struct {
	calls      []string
	checkFails bool
}

func (f *natFake) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "ip" {
		// Record ip rule commands for testing.
		if len(args) > 1 && args[1] == "rule" {
			f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		}
		// Simulate detectWAN for "ip route show".
		if len(args) >= 2 && args[0] == "route" {
			return []byte("default via 10.0.0.1 dev ens3 proto dhcp metric 100\n"), nil
		}
		return []byte{}, nil
	}
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	isCheck := false
	for _, a := range args {
		if a == "-C" {
			isCheck = true
		}
	}
	if (name == "iptables" || name == "ip6tables") && isCheck && f.checkFails {
		return nil, errors.New("exit status 1")
	}
	return nil, nil
}

func v4Settings(ks bool) state.Settings {
	return state.Settings{PoolCIDR: "10.7.0.0/24", KillSwitch: ks}
}

func dualSettings(ks bool) state.Settings {
	return state.Settings{PoolCIDR: "10.7.0.0/24", IPv6Pool: "fd12:3456:789a::/64", KillSwitch: ks}
}

func dropCalls(calls []string, flag string) []string {
	var out []string
	for _, c := range calls {
		if strings.Contains(c, "-j DROP") && strings.Contains(c, "iptables "+flag+" ") {
			out = append(out, c)
		}
	}
	return out
}

const wantDropAdd = "iptables -I FORWARD 1 -i wg0 ! -o tailscale0 -j DROP"
const wantDropDel = "iptables -D FORWARD -i wg0 ! -o tailscale0 -j DROP"

func TestEnsureNATKillSwitchOn(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: true} // rule absent
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	s := v4Settings(true)
	s.ExitNode = "exit-1" // DROP only applies with an exit node selected
	if err := n.ensureNAT(ctx, s); err != nil {
		t.Fatal(err)
	}
	adds := dropCalls(f.calls, "-I")
	if len(adds) != 1 {
		t.Fatalf("expected exactly one DROP -I, got %v", adds)
	}
	if adds[0] != wantDropAdd {
		t.Errorf("got %q, want %q", adds[0], wantDropAdd)
	}
	// The DROP uses -I (insert at top) so it beats the host REJECT-all
	// rule. DROP only matches non-tailscale traffic, so legitimate relay
	// traffic still reaches the ACCEPT rules.
}

func TestEnsureNATKillSwitchOnIdempotent(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: false} // rule already present
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, v4Settings(true)); err != nil {
		t.Fatal(err)
	}
	if adds := dropCalls(f.calls, "-I"); len(adds) != 0 {
		t.Errorf("rule already present but -I was still issued: %v", adds)
	}
}

func TestEnsureNATKillSwitchOffRemoves(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: false} // rule present
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, v4Settings(false)); err != nil {
		t.Fatal(err)
	}
	dels := dropCalls(f.calls, "-D")
	if len(dels) != 1 {
		t.Fatalf("expected exactly one DROP -D, got %v", dels)
	}
	if dels[0] != wantDropDel {
		t.Errorf("got %q, want %q", dels[0], wantDropDel)
	}
	if adds := dropCalls(f.calls, "-I"); len(adds) != 0 {
		t.Errorf("kill switch off but DROP -I issued: %v", adds)
	}
}

func TestEnsureNATKillSwitchOffAbsent(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: true} // rule absent
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, v4Settings(false)); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "-j DROP") && (strings.Contains(c, " -D ") || strings.Contains(c, " -A ")) {
			t.Errorf("rule absent and kill switch off, but mutating call issued: %q", c)
		}
	}
}

func TestTSIfaceExists(t *testing.T) {
	ctx := context.Background()
	f := &natFake{}
	up := &NetOps{Run: f.run, TSIface: "tailscale0"}
	if !up.TSIfaceExists(ctx) {
		t.Error("expected true when `ip link show` succeeds")
	}
	down := &NetOps{Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("exit status 1")
	}, TSIface: "tailscale0"}
	if down.TSIfaceExists(ctx) {
		t.Error("expected false when `ip link show` fails")
	}
	empty := &NetOps{Run: f.run, TSIface: ""}
	if empty.TSIfaceExists(ctx) {
		t.Error("expected false for empty interface name")
	}
}

func ip6Drops(calls []string, flag string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, "ip6tables ") && strings.Contains(c, "-j DROP") &&
			strings.Contains(c, "ip6tables "+flag+" ") {
			out = append(out, c)
		}
	}
	return out
}

const wantV6DropAdd = "ip6tables -I FORWARD 1 -i wg0 ! -o tailscale0 -j DROP"
const wantV6DropDel = "ip6tables -D FORWARD -i wg0 ! -o tailscale0 -j DROP"
const wantV6Masq = "ip6tables -t nat -A POSTROUTING -s fd12:3456:789a::/64 -o tailscale0 -j MASQUERADE"

func TestEnsureNATDualStack(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: true} // nothing present
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	s := dualSettings(true)
	s.ExitNode = "exit-1" // DROP only applies with an exit node selected
	if err := n.ensureNAT(ctx, s); err != nil {
		t.Fatal(err)
	}
	// v6 MASQUERADE for the ULA pool.
	found := false
	for _, c := range f.calls {
		if c == wantV6Masq {
			found = true
		}
	}
	if !found {
		t.Errorf("missing v6 MASQUERADE; calls:\n%s", strings.Join(f.calls, "\n"))
	}
	// v6 kill-switch DROP, exactly once, and last among ip6tables FORWARD -A.
	adds := ip6Drops(f.calls, "-I")
	if len(adds) != 1 || adds[0] != wantV6DropAdd {
		t.Errorf("v6 DROP = %v, want exactly [%s]", adds, wantV6DropAdd)
	}
	// v4 rules still installed alongside.
	if n := len(dropCalls(f.calls, "-I")); n != 1 {
		t.Errorf("expected exactly one v4 DROP -I, got %d", n)
	}
}

func TestEnsureNATDualStackIdempotent(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: false} // everything present
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, dualSettings(true)); err != nil {
		t.Fatal(err)
	}
	if adds := ip6Drops(f.calls, "-A"); len(adds) != 0 {
		t.Errorf("v6 rule present but -A re-issued: %v", adds)
	}
}

func TestEnsureNATDualStackKillSwitchOff(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: false} // rules present
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, dualSettings(false)); err != nil {
		t.Fatal(err)
	}
	dels := ip6Drops(f.calls, "-D")
	if len(dels) != 1 || dels[0] != wantV6DropDel {
		t.Errorf("v6 DROP -D = %v, want exactly [%s]", dels, wantV6DropDel)
	}
}

func TestEnsureNATV4OnlyNoIP6TablesMutations(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: true} // nothing present
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, v4Settings(true)); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "ip6tables ") &&
			(strings.Contains(c, " -A ") || strings.Contains(c, " -D ")) {
			t.Errorf("v4-only settings but ip6tables mutation issued: %q", c)
		}
	}
}

func TestEnsureNATStaleV6DropRemoved(t *testing.T) {
	// v6 pool removed from settings while its DROP rule lingers on the
	// host: Apply must clean it up (fake claims -C succeeds = present).
	ctx := context.Background()
	f := &natFake{checkFails: false}
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, v4Settings(true)); err != nil {
		t.Fatal(err)
	}
	dels := ip6Drops(f.calls, "-D")
	if len(dels) != 1 || dels[0] != wantV6DropDel {
		t.Errorf("stale v6 DROP -D = %v, want exactly [%s]", dels, wantV6DropDel)
	}
}

func TestDetectWAN(t *testing.T) {
	f := &natFake{}
	n := &NetOps{Run: f.run}
	wan, err := n.detectWAN(context.Background())
	if err != nil {
		t.Fatalf("detectWAN: %v", err)
	}
	if wan != "ens3" {
		t.Fatalf("got %q, want ens3", wan)
	}
}

func TestEnsureNATDirectModeAddsWANRules(t *testing.T) {
	f := &natFake{checkFails: true}
	// ip route reports ens3 as the default-route interface.
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return []byte("default via 10.0.0.1 dev ens3 proto dhcp metric 100\n"), nil
		}
		return f.run(ctx, name, args...)
	}
	n := &NetOps{Run: run, Iface: "wg0", TSIface: "tailscale0"}
	s := v4Settings(false) // kill switch off, no exit node
	s.ExitNode = ""
	if err := n.ensureNAT(context.Background(), s); err != nil {
		t.Fatalf("ensureNAT: %v", err)
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{
		"iptables -I FORWARD -i wg0 -o ens3 -j ACCEPT",
		"iptables -I FORWARD -i ens3 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"iptables -t nat -A POSTROUTING -s 10.7.0.0/24 -o ens3 -j MASQUERADE",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing rule %q\ncalls:\n%s", want, joined)
		}
	}
	// No kill-switch DROP installed in direct mode (only -C checks, no -A).
	for _, c := range f.calls {
		if strings.Contains(c, "-I FORWARD 1") && strings.Contains(c, "-j DROP") {
			t.Errorf("direct mode must not install kill-switch DROP, got: %q", c)
		}
	}
}

func TestEnsureNATExitNodeModeNoWANRules(t *testing.T) {
	f := &natFake{checkFails: true}
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	s := v4Settings(true)
	s.ExitNode = "us-homerouter"
	if err := n.ensureNAT(context.Background(), s); err != nil {
		t.Fatalf("ensureNAT: %v", err)
	}
	joined := strings.Join(f.calls, "\n")
	// Must not ADD FORWARD rules for WAN (client traffic stays on tailnet).
	// DELETE calls for stale WAN rules are expected cleanup, not adds —
	// so check for -I/-A (add) specifically, not -D (delete).
	for _, c := range f.calls {
		if (strings.Contains(c, "-I FORWARD") || strings.Contains(c, "-A FORWARD")) && strings.Contains(c, "-o ens3") {
			t.Errorf("exit-node mode must not add WAN FORWARD rules, got: %q\n%s", c, joined)
		}
		if strings.Contains(c, "-A POSTROUTING") && strings.Contains(c, "-o ens3") {
			t.Errorf("exit-node mode must not add WAN MASQUERADE, got: %q\n%s", c, joined)
		}
	}
	if !strings.Contains(joined, "-i wg0 ! -o tailscale0 -j DROP") {
		t.Errorf("exit-node mode with kill switch should keep DROP:\n%s", joined)
	}
}

func TestEnsureNATAddsInputRuleForWGPort(t *testing.T) {
	f := &natFake{checkFails: true}
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	s := v4Settings(true)
	s.ListenPort = 51820
	if err := n.ensureNAT(context.Background(), s); err != nil {
		t.Fatalf("ensureNAT: %v", err)
	}
	joined := strings.Join(f.calls, "\n")
	want := "iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT"
	if !strings.Contains(joined, want) {
		t.Errorf("missing INPUT ACCEPT for WireGuard port, want %q in:\n%s", want, joined)
	}
}

func TestEnsureNATExitNodeAddsFwmarkBypass(t *testing.T) {
	f := &natFake{checkFails: true}
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	s := v4Settings(true)
	s.ExitNode = "us-homerouter"
	s.ListenPort = 51820
	if err := n.ensureNAT(context.Background(), s); err != nil {
		t.Fatalf("ensureNAT: %v", err)
	}
	joined := strings.Join(f.calls, "\n")
	// TailGuard approach: ip rule to send WireGuard fwmark traffic to main
	// table, bypassing Tailscale's exit-node table 52 (pref 5270).
	want := "ip -4 rule add fwmark 51820 lookup main pref 5269"
	if !strings.Contains(joined, want) {
		t.Errorf("exit-node mode must add fwmark bypass rule, want %q in:\n%s", want, joined)
	}
	want6 := "ip -6 rule add fwmark 51820 lookup main pref 5269"
	if !strings.Contains(joined, want6) {
		t.Errorf("exit-node mode must add IPv6 fwmark bypass rule, want %q in:\n%s", want6, joined)
	}
	// Old mangle/MASQUERADE approach must be gone.
	if strings.Contains(joined, "mangle -A OUTPUT") {
		t.Errorf("must not use mangle OUTPUT MARK (use fwmark+ip rule instead):\n%s", joined)
	}
}

func TestEnsureNATExitNodeAddsPoolReturnRoute(t *testing.T) {
	f := &natFake{checkFails: true}
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	s := v4Settings(true)
	s.ExitNode = "us-homerouter"
	s.PoolCIDR = "10.7.0.0/24"
	if err := n.ensureNAT(context.Background(), s); err != nil {
		t.Fatalf("ensureNAT: %v", err)
	}
	joined := strings.Join(f.calls, "\n")
	// The 5268 rule routes de-NATed return traffic (dst=pool) via the main
	// table (which has the wg0 route) BEFORE Tailscale's 5270 catch-all
	// (from all lookup 52). Without it, return packets loop back to the
	// exit node instead of reaching WireGuard clients.
	want := "ip -4 rule add to 10.7.0.0/24 lookup main pref 5268"
	if !strings.Contains(joined, want) {
		t.Errorf("exit-node mode must add pool return route, want %q in:\n%s", want, joined)
	}
}

func TestEnsureNATDirectModeRemovesPoolReturnRoute(t *testing.T) {
	f := &natFake{checkFails: true}
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	s := v4Settings(true)
	s.ExitNode = "" // direct mode
	s.PoolCIDR = "10.7.0.0/24"
	if err := n.ensureNAT(context.Background(), s); err != nil {
		t.Fatalf("ensureNAT: %v", err)
	}
	joined := strings.Join(f.calls, "\n")
	// Direct mode must remove the 5268 rule (no exit node to bypass).
	want := "ip -4 rule del to 10.7.0.0/24 lookup main pref 5268"
	if !strings.Contains(joined, want) {
		t.Errorf("direct mode must remove pool return route, want %q in:\n%s", want, joined)
	}
	// And must NOT add it.
	if strings.Contains(joined, "ip -4 rule add to 10.7.0.0/24 lookup main pref 5268") {
		t.Errorf("direct mode must not add pool return route:\n%s", joined)
	}
}

func TestEnsureNATDirectModeNoFwmarkBypass(t *testing.T) {
	f := &natFake{checkFails: true}
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	s := v4Settings(true)
	s.ExitNode = "" // direct mode
	if err := n.ensureNAT(context.Background(), s); err != nil {
		t.Fatalf("ensureNAT: %v", err)
	}
	joined := strings.Join(f.calls, "\n")
	if strings.Contains(joined, "rule add fwmark") {
		t.Errorf("direct mode must not add fwmark bypass rule:\n%s", joined)
	}
}

// The old mangle/MASQUERADE workaround for the WireGuard socket must never
// come back: socket bypass is done via interface fwmark + ip rule only.
func TestEnsureNATEmitsNoMangleSocketRules(t *testing.T) {
	for _, exitNode := range []string{"", "us-homerouter"} {
		f := &natFake{checkFails: true}
		n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
		s := v4Settings(true)
		s.ExitNode = exitNode
		if err := n.ensureNAT(context.Background(), s); err != nil {
			t.Fatalf("ensureNAT (exitNode=%q): %v", exitNode, err)
		}
		joined := strings.Join(f.calls, "\n")
		if strings.Contains(joined, "mangle") {
			t.Errorf("exitNode=%q: must not emit mangle rules:\n%s", exitNode, joined)
		}
		if strings.Contains(joined, "--sport") {
			t.Errorf("exitNode=%q: must not match on --sport (socket MASQUERADE):\n%s", exitNode, joined)
		}
	}
}
