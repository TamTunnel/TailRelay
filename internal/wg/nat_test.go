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

const wantDropAdd = "iptables -A FORWARD -i wg0 ! -o tailscale0 -j DROP"
const wantDropDel = "iptables -D FORWARD -i wg0 ! -o tailscale0 -j DROP"

func TestEnsureNATKillSwitchOn(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: true} // rule absent
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, v4Settings(true)); err != nil {
		t.Fatal(err)
	}
	adds := dropCalls(f.calls, "-A")
	if len(adds) != 1 {
		t.Fatalf("expected exactly one DROP -A, got %v", adds)
	}
	if adds[0] != wantDropAdd {
		t.Errorf("got %q, want %q", adds[0], wantDropAdd)
	}
	// The DROP must be appended after the ACCEPT rules so legitimate
	// relay traffic matches first: it should be the last FORWARD -A.
	lastForwardAdd := ""
	for _, c := range f.calls {
		if strings.HasPrefix(c, "iptables -A FORWARD") {
			lastForwardAdd = c
		}
	}
	if lastForwardAdd != wantDropAdd {
		t.Errorf("DROP rule is not the last FORWARD append: %q", lastForwardAdd)
	}
}

func TestEnsureNATKillSwitchOnIdempotent(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: false} // rule already present
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, v4Settings(true)); err != nil {
		t.Fatal(err)
	}
	if adds := dropCalls(f.calls, "-A"); len(adds) != 0 {
		t.Errorf("rule already present but -A was still issued: %v", adds)
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
	if adds := dropCalls(f.calls, "-A"); len(adds) != 0 {
		t.Errorf("kill switch off but DROP -A issued: %v", adds)
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

const wantV6DropAdd = "ip6tables -A FORWARD -i wg0 ! -o tailscale0 -j DROP"
const wantV6DropDel = "ip6tables -D FORWARD -i wg0 ! -o tailscale0 -j DROP"
const wantV6Masq = "ip6tables -t nat -A POSTROUTING -s fd12:3456:789a::/64 -o tailscale0 -j MASQUERADE"

func TestEnsureNATDualStack(t *testing.T) {
	ctx := context.Background()
	f := &natFake{checkFails: true} // nothing present
	n := &NetOps{Run: f.run, Iface: "wg0", TSIface: "tailscale0"}
	if err := n.ensureNAT(ctx, dualSettings(true)); err != nil {
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
	adds := ip6Drops(f.calls, "-A")
	if len(adds) != 1 || adds[0] != wantV6DropAdd {
		t.Errorf("v6 DROP -A = %v, want exactly [%s]", adds, wantV6DropAdd)
	}
	last := ""
	for _, c := range f.calls {
		if strings.HasPrefix(c, "ip6tables -A FORWARD") {
			last = c
		}
	}
	if last != wantV6DropAdd {
		t.Errorf("v6 DROP is not the last ip6tables FORWARD append: %q", last)
	}
	// v4 rules still installed alongside.
	if n := len(dropCalls(f.calls, "-A")); n != 1 {
		t.Errorf("expected exactly one v4 DROP -A, got %d", n)
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
