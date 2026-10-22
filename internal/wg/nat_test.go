package wg

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// natFake records iptables/ip calls. checkFails controls whether
// `iptables -C` reports the rule as missing.
type natFake struct {
	calls      []string
	checkFails bool
}

func (f *natFake) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name == "iptables" && len(args) > 0 && args[0] == "-C" && f.checkFails {
		return nil, errors.New("exit status 1")
	}
	return nil, nil
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
	if err := n.ensureNAT(ctx, "10.7.0.0/24", true); err != nil {
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
	if err := n.ensureNAT(ctx, "10.7.0.0/24", true); err != nil {
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
	if err := n.ensureNAT(ctx, "10.7.0.0/24", false); err != nil {
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
	if err := n.ensureNAT(ctx, "10.7.0.0/24", false); err != nil {
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
