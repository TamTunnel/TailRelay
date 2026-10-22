// Package wg manages the WireGuard server: key generation, config file
// rendering, interface lifecycle (ip/wg), IP forwarding and NAT.
package wg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/TamTunnel/Tailrelay/internal/state"
)

// Runner executes an external command. Swappable in tests.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// DefaultRunner runs real commands with a timeout.
func DefaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(redactArgs(args), " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// redactArgs masks secret-bearing arguments (e.g. --authkey=<secret>) so
// they never land in error strings, logs, or UI messages.
func redactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(strings.ToLower(a), "authkey") {
			if eq := strings.Index(a, "="); eq >= 0 {
				out[i] = a[:eq+1] + "<redacted>"
			} else {
				out[i] = "<redacted>"
			}
			continue
		}
		out[i] = a
	}
	return out
}

// --- keys ---

// GeneratePrivateKey returns a base64 WireGuard private key with correct
// X25519 clamping (same as `wg genkey`).
func GeneratePrivateKey() (string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	return base64.StdEncoding.EncodeToString(priv[:]), nil
}

// PublicKeyFromPrivate derives the base64 public key (same as `wg pubkey`).
func PublicKeyFromPrivate(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("decoding private key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes, got %d", len(raw))
	}
	var priv, pub [32]byte
	copy(priv[:], raw)
	var basepoint [32]byte
	copy(basepoint[:], curve25519.Basepoint)
	curve25519.ScalarMult(&pub, &priv, &basepoint)
	return base64.StdEncoding.EncodeToString(pub[:]), nil
}

// --- IP allocation ---

// ServerIP returns the first usable address of the pool (x.x.x.1).
func ServerIP(poolCIDR string) (string, error) {
	ip, _, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return "", err
	}
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("only IPv4 pools are supported, got %q", poolCIDR)
	}
	ip[3] = 1
	return ip.String(), nil
}

// ServerIPv6 returns the server address of the v6 pool (::1).
func ServerIPv6(poolCIDR string) (string, error) {
	ip, _, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return "", err
	}
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		return "", fmt.Errorf("only IPv6 pools are supported, got %q", poolCIDR)
	}
	ip[15] = 1
	return ip.String(), nil
}

// NextClientIPv6 returns the lowest free v6 client address, mirroring
// NextClientIP's mask-awareness. The server takes ::1; clients are allocated
// from ::2 up to the last address of the prefix (IPv6 has no broadcast).
// Pools smaller than /126 can't hold a server plus a client.
func NextClientIPv6(poolCIDR string, taken map[string]bool) (string, error) {
	ip, ipnet, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return "", err
	}
	ip16 := ip.To16()
	if ip16 == nil || ip16.To4() != nil {
		return "", fmt.Errorf("only IPv6 pools are supported, got %q", poolCIDR)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 128 {
		return "", fmt.Errorf("bad IPv6 mask for %q", poolCIDR)
	}
	if ones > 126 {
		return "", fmt.Errorf("pool %s too small for a server + clients (need /126 or larger)", poolCIDR)
	}
	base := new(big.Int).SetBytes(ipnet.IP.To16())
	size := new(big.Int).Lsh(big.NewInt(1), uint(128-ones)) // addresses in prefix
	last := new(big.Int).Add(base, new(big.Int).Sub(size, big.NewInt(1)))
	for h := new(big.Int).Add(base, big.NewInt(2)); h.Cmp(last) <= 0; h.Add(h, big.NewInt(1)) {
		b := h.Bytes()
		var buf [16]byte
		copy(buf[16-len(b):], b)
		cand := net.IP(buf[:]).String()
		if !taken[cand] {
			return cand, nil
		}
	}
	return "", fmt.Errorf("pool %s exhausted", poolCIDR)
}

// NextClientIP returns the lowest free client address. The server takes the
// first usable host (.1); clients are allocated from .2 up to broadcast-1,
// honoring the pool's mask (so a /25 only offers .2–.126, a /16 the full
// range — not just the first /24).
func NextClientIP(poolCIDR string, taken map[string]bool) (string, error) {
	ip, ipnet, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return "", err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("only IPv4 pools are supported, got %q", poolCIDR)
	}
	mask := net.IP(ipnet.Mask).To4()
	if mask == nil {
		return "", fmt.Errorf("only IPv4 pools are supported, got %q", poolCIDR)
	}
	network := ip4.Mask(ipnet.Mask).To4()
	broadcast := net.IPv4(
		network[0]|^mask[0], network[1]|^mask[1],
		network[2]|^mask[2], network[3]|^mask[3],
	).To4()
	n := binary.BigEndian.Uint32(network)
	b := binary.BigEndian.Uint32(broadcast)
	if b < n+3 { // need network, server (.1), and at least one client address
		return "", fmt.Errorf("pool %s too small for a server + clients", poolCIDR)
	}
	for h := n + 2; h < b; h++ { // .2 .. broadcast-1
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], h)
		cand := net.IP(buf[:]).String()
		if !taken[cand] {
			return cand, nil
		}
	}
	return "", fmt.Errorf("pool %s exhausted", poolCIDR)
}

// AddClient creates a client with fresh keys and the next free IP.
func AddClient(st *state.State, name string) (state.Client, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return state.Client{}, fmt.Errorf("client name is empty")
	}
	for _, c := range st.Clients {
		if c.Name == name {
			return state.Client{}, fmt.Errorf("client %q already exists", name)
		}
	}
	taken := map[string]bool{}
	taken6 := map[string]bool{}
	for _, c := range st.Clients {
		taken[c.Address] = true
		if c.AddressV6 != "" {
			taken6[c.AddressV6] = true
		}
	}
	addr, err := NextClientIP(st.Settings.PoolCIDR, taken)
	if err != nil {
		return state.Client{}, err
	}
	var addr6 string
	if v6pool := st.Settings.IPv6Pool; v6pool != "" {
		addr6, err = NextClientIPv6(v6pool, taken6)
		if err != nil {
			return state.Client{}, err
		}
	}
	priv, err := GeneratePrivateKey()
	if err != nil {
		return state.Client{}, err
	}
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		return state.Client{}, err
	}
	psk, err := GeneratePrivateKey() // preshared key: 32 random bytes, base64
	if err != nil {
		return state.Client{}, err
	}
	c := state.Client{
		Name: name, PrivateKey: priv, PublicKey: pub,
		PresharedKey: psk, Address: addr, AddressV6: addr6, CreatedAt: time.Now().UTC(),
	}
	st.Clients = append(st.Clients, c)
	return c, nil
}

// --- config rendering ---

// RenderServerConfig renders wg0.conf for the server.
func RenderServerConfig(st *state.State, iface string) (string, error) {
	serverIP, err := ServerIP(st.Settings.PoolCIDR)
	if err != nil {
		return "", err
	}
	serverAddr := cidrHost(serverIP, st.Settings.PoolCIDR)
	if v6pool := st.Settings.IPv6Pool; v6pool != "" {
		serverIP6, err := ServerIPv6(v6pool)
		if err != nil {
			return "", err
		}
		serverAddr += ", " + cidrHost(serverIP6, v6pool)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by Tailrelay (%s) - do not edit manually; use the web UI\n", iface)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", st.ServerPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", serverAddr)
	fmt.Fprintf(&b, "ListenPort = %d\n", st.Settings.ListenPort)
	fmt.Fprintf(&b, "MTU = %d\n", st.Settings.MTU)
	for _, c := range st.Clients {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "# %s\n", c.Name)
		fmt.Fprintf(&b, "PublicKey = %s\n", c.PublicKey)
		fmt.Fprintf(&b, "PresharedKey = %s\n", c.PresharedKey)
		allowed := c.Address + "/32"
		if c.AddressV6 != "" {
			allowed += ", " + c.AddressV6 + "/128"
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	}
	return b.String(), nil
}

// RenderClientConfig renders the .conf a client imports.
func RenderClientConfig(st *state.State, c state.Client) (string, error) {
	endpoint := st.Settings.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("<server-public-ip>:%d", st.Settings.ListenPort)
	} else if !strings.Contains(endpoint, ":") {
		endpoint = fmt.Sprintf("%s:%d", endpoint, st.Settings.ListenPort)
	}
	clientAddr := cidrHost(c.Address, st.Settings.PoolCIDR)
	if c.AddressV6 != "" {
		clientAddr += ", " + c.AddressV6 + "/128"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Tailrelay client config for %q - import into the WireGuard app\n", c.Name)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", clientAddr)
	fmt.Fprintf(&b, "DNS = %s\n", st.Settings.DNS)
	fmt.Fprintf(&b, "MTU = %d\n", st.Settings.MTU)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", st.ServerPublicKey)
	fmt.Fprintf(&b, "PresharedKey = %s\n", c.PresharedKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", st.Settings.ClientAllowedIPs)
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", st.Settings.Keepalive)
	return b.String(), nil
}

// cidrHost formats "10.7.0.2/24" from a host IP and pool CIDR.
func cidrHost(hostIP, poolCIDR string) string {
	_, ipnet, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return hostIP
	}
	ones, _ := ipnet.Mask.Size()
	return fmt.Sprintf("%s/%d", hostIP, ones)
}

// --- interface lifecycle ---

// NetOps applies WireGuard state to the host via ip/wg/iptables.
type NetOps struct {
	Run     Runner
	Iface   string // wireguard interface, e.g. wg0
	TSIface string // tailscale interface NAT target, e.g. tailscale0
}

// TSIfaceExists reports whether the tailscale interface exists
// (used by the dashboard to derive Tailscale health).
func (n *NetOps) TSIfaceExists(ctx context.Context) bool {
	if n.TSIface == "" {
		return false
	}
	_, err := n.Run(ctx, "ip", "link", "show", "dev", n.TSIface)
	return err == nil
}

// Apply writes wg0.conf and brings the interface + NAT up. Idempotent.
func (n *NetOps) Apply(ctx context.Context, st *state.State, confPath string) error {
	if !n.TSIfaceExists(ctx) {
		return fmt.Errorf("tailscale interface %q not found (is tailscaled running?)", n.TSIface)
	}
	conf, err := RenderServerConfig(st, n.Iface)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(confPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		return err
	}

	serverIP, err := ServerIP(st.Settings.PoolCIDR)
	if err != nil {
		return fmt.Errorf("pool CIDR: %w", err)
	}
	addr := cidrHost(serverIP, st.Settings.PoolCIDR)
	addrs := []string{addr}
	if v6pool := st.Settings.IPv6Pool; v6pool != "" {
		serverIP6, err := ServerIPv6(v6pool)
		if err != nil {
			return fmt.Errorf("IPv6 pool: %w", err)
		}
		addrs = append(addrs, cidrHost(serverIP6, v6pool))
	}

	// Create interface (ignore "exists").
	_, _ = n.Run(ctx, "ip", "link", "add", "dev", n.Iface, "type", "wireguard")
	// ip addr add is idempotent: iproute2 reports duplicates as "File exists"
	// (older) or "Address already assigned" (newer) — both are fine on re-apply.
	addrExists := func(s string) bool {
		ls := strings.ToLower(s)
		return strings.Contains(ls, "exists") || strings.Contains(ls, "already assigned")
	}
	for _, a := range addrs {
		if out, err := n.Run(ctx, "ip", "addr", "add", a, "dev", n.Iface); err != nil &&
			!addrExists(string(out)) && !addrExists(err.Error()) {
			return fmt.Errorf("assigning address %s: %w", a, err)
		}
	}
	if _, err := n.Run(ctx, "ip", "link", "set", "mtu", strconv.Itoa(st.Settings.MTU), "dev", n.Iface); err != nil {
		return fmt.Errorf("setting mtu: %w", err)
	}
	// Sync peers atomically from the rendered config.
	// wg setconf only understands PrivateKey/ListenPort/FwMark in
	// [Interface]; the rendered file also carries wg-quick directives
	// (Address, MTU) which setconf rejects, so feed it a stripped copy.
	setconfPath := confPath + ".setconf"
	if err := os.WriteFile(setconfPath, []byte(StripForSetconf(conf)), 0o600); err != nil {
		return err
	}
	defer os.Remove(setconfPath)
	if _, err := n.Run(ctx, "wg", "setconf", n.Iface, setconfPath); err != nil {
		return fmt.Errorf("wg setconf: %w", err)
	}
	if _, err := n.Run(ctx, "ip", "link", "set", "up", "dev", n.Iface); err != nil {
		return fmt.Errorf("bringing interface up: %w", err)
	}
	if err := n.enableForwarding(ctx, st.Settings.IPv6Pool != ""); err != nil {
		return err
	}
	return n.ensureNAT(ctx, st.Settings)
}

// StripForSetconf removes wg-quick-only directives (Address, MTU, DNS, …)
// from a rendered config so the result is acceptable to `wg setconf`,
// which only understands PrivateKey/ListenPort/FwMark in [Interface].
// Addresses and MTU are applied separately via `ip addr add` / `ip link set`.
func StripForSetconf(conf string) string {
	drop := map[string]bool{
		"address": true, "dns": true, "mtu": true, "table": true,
		"preup": true, "predown": true, "postup": true, "postdown": true,
		"saveconfig": true,
	}
	var b strings.Builder
	for _, line := range strings.Split(conf, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			if i := strings.Index(t, "="); i > 0 {
				if drop[strings.ToLower(strings.TrimSpace(t[:i]))] {
					continue
				}
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func (n *NetOps) enableForwarding(ctx context.Context, wantV6 bool) error {
	if err := n.ensureSysctl(ctx, "net.ipv4.ip_forward"); err != nil {
		return err
	}
	if wantV6 {
		// IPv6 forwarding is best-effort: in a container /proc/sys is
		// typically read-only, and IPv4 operation must not break because
		// of it. The dashboard/settings surface the resulting state.
		if err := n.ensureSysctl(ctx, "net.ipv6.conf.all.forwarding"); err != nil {
			log.Printf("warning: %v", err)
		}
	}
	return nil
}

// procSysBase is /proc/sys in production; tests point it at a temp dir.
var procSysBase = "/proc/sys"

// ensureSysctl makes sure a sysctl key reads "1", writing it only when needed.
// Reading works even when /proc/sys is mounted read-only (the Docker default),
// so a host that already has the value set — e.g. the Docker daemon enabling
// net.ipv4.ip_forward at startup — needs no write at all.
func (n *NetOps) ensureSysctl(ctx context.Context, key string) error {
	path := procSysBase + "/" + strings.ReplaceAll(key, ".", "/")
	if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) == "1" {
		return nil
	}
	if _, err := n.Run(ctx, "sysctl", "-w", key+"=1"); err == nil {
		return nil
	}
	// Fallback: write procfs directly.
	if werr := os.WriteFile(path, []byte("1\n"), 0o644); werr != nil {
		return fmt.Errorf("%s is not enabled and cannot be set from inside the container (read-only /proc/sys); on the host run: sudo sysctl -w %s=1", key, key)
	}
	return nil
}

// ensureNAT installs the FORWARD + MASQUERADE rules wg0 -> <ts-iface> for
// IPv4 (iptables) and, when an IPv6 pool is configured, IPv6 (ip6tables).
// Rules are checked with -C first so Apply stays idempotent.
//
// The kill-switch rule is the fail-closed policy: anything arriving on the
// WireGuard interface that is NOT headed for the tailscale interface is
// dropped. If tailscaled crashes (tailscale0 vanishes) or the pinned exit
// node dies, client traffic stops instead of leaking out the VPS's direct
// WAN. The DROP is appended after the ACCEPTs so legitimate relay traffic
// still matches first; on every re-Apply it stays last. With killSwitch
// off the rule is removed if present (Apply reconciles it from the setting
// every run).
func (n *NetOps) ensureNAT(ctx context.Context, s state.Settings) error {
	tsif := n.TSIface
	type pair struct {
		bin        string
		check, add []string
	}
	var pairs []pair
	addPair := func(bin string, check, add []string) {
		pairs = append(pairs, pair{bin: bin, check: check, add: add})
	}
	addPair("iptables",
		[]string{"-C", "FORWARD", "-i", n.Iface, "-o", tsif, "-j", "ACCEPT"},
		[]string{"-A", "FORWARD", "-i", n.Iface, "-o", tsif, "-j", "ACCEPT"})
	addPair("iptables",
		[]string{"-C", "FORWARD", "-i", tsif, "-o", n.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		[]string{"-A", "FORWARD", "-i", tsif, "-o", n.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"})
	addPair("iptables",
		[]string{"-t", "nat", "-C", "POSTROUTING", "-s", s.PoolCIDR, "-o", tsif, "-j", "MASQUERADE"},
		[]string{"-t", "nat", "-A", "POSTROUTING", "-s", s.PoolCIDR, "-o", tsif, "-j", "MASQUERADE"})
	v6 := s.IPv6Pool != ""
	if v6 {
		addPair("ip6tables",
			[]string{"-C", "FORWARD", "-i", n.Iface, "-o", tsif, "-j", "ACCEPT"},
			[]string{"-A", "FORWARD", "-i", n.Iface, "-o", tsif, "-j", "ACCEPT"})
		addPair("ip6tables",
			[]string{"-C", "FORWARD", "-i", tsif, "-o", n.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			[]string{"-A", "FORWARD", "-i", tsif, "-o", n.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"})
		addPair("ip6tables",
			[]string{"-t", "nat", "-C", "POSTROUTING", "-s", s.IPv6Pool, "-o", tsif, "-j", "MASQUERADE"},
			[]string{"-t", "nat", "-A", "POSTROUTING", "-s", s.IPv6Pool, "-o", tsif, "-j", "MASQUERADE"})
	}
	// Direct mode (no exit node): forward client traffic via the host's
	// WAN interface, not just the tailnet. Without this, clients in
	// "No exit node (direct)" get a handshake but no internet.
	if s.ExitNode == "" {
		wan, err := n.detectWAN(ctx)
		if err != nil {
			return fmt.Errorf("detecting WAN interface for direct mode: %w", err)
		}
		addPair("iptables",
			[]string{"-C", "FORWARD", "-i", n.Iface, "-o", wan, "-j", "ACCEPT"},
			[]string{"-A", "FORWARD", "-i", n.Iface, "-o", wan, "-j", "ACCEPT"})
		addPair("iptables",
			[]string{"-C", "FORWARD", "-i", wan, "-o", n.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			[]string{"-A", "FORWARD", "-i", wan, "-o", n.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"})
		addPair("iptables",
			[]string{"-t", "nat", "-C", "POSTROUTING", "-s", s.PoolCIDR, "-o", wan, "-j", "MASQUERADE"},
			[]string{"-t", "nat", "-A", "POSTROUTING", "-s", s.PoolCIDR, "-o", wan, "-j", "MASQUERADE"})
	}
	for _, p := range pairs {
		if _, err := n.Run(ctx, p.bin, p.check...); err != nil {
			if _, err := n.Run(ctx, p.bin, p.add...); err != nil {
				return fmt.Errorf("%s %s: %w", p.bin, strings.Join(p.add, " "), err)
			}
		}
	}
	// Kill-switch DROP, per family. It only applies when an exit node is
	// selected (traffic must stay on the tailnet); in direct mode the WAN
	// is the intended path, so no DROP. The v6 DROP only exists when the
	// v6 pool is enabled; disabling the pool must also remove a stale v6
	// DROP, so always reconcile both families here.
	wantDrop := s.KillSwitch && s.ExitNode != ""
	for _, bin := range []string{"iptables", "ip6tables"} {
		if bin == "ip6tables" && !v6 {
			// No v6 pool: make sure no stale v6 DROP lingers, then skip.
			n.removeDrop(ctx, bin, tsif)
			continue
		}
		if wantDrop {
			if err := n.ensureDrop(ctx, bin, tsif); err != nil {
				return err
			}
			continue
		}
		if err := n.removeDrop(ctx, bin, tsif); err != nil {
			return err
		}
	}
	return nil
}

// detectWAN returns the host interface carrying the default route
// (e.g. ens3, eth0). Used for direct-mode forwarding.
func (n *NetOps) detectWAN(ctx context.Context) (string, error) {
	out, err := n.Run(ctx, "ip", "route", "show", "default")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i, tok := range f {
			if tok == "dev" && i+1 < len(f) {
				return f[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("no default route found in: %q", strings.TrimSpace(string(out)))
}

// ensureDrop installs the kill-switch DROP if absent.
func (n *NetOps) ensureDrop(ctx context.Context, bin, tsif string) error {
	drop := []string{"FORWARD", "-i", n.Iface, "!", "-o", tsif, "-j", "DROP"}
	check := append([]string{"-C"}, drop...)
	if _, err := n.Run(ctx, bin, check...); err != nil {
		add := append([]string{"-A"}, drop...)
		if _, err := n.Run(ctx, bin, add...); err != nil {
			return fmt.Errorf("%s kill-switch: %w", bin, err)
		}
	}
	return nil
}

// removeDrop deletes the kill-switch DROP if present (best effort check).
func (n *NetOps) removeDrop(ctx context.Context, bin, tsif string) error {
	drop := []string{"FORWARD", "-i", n.Iface, "!", "-o", tsif, "-j", "DROP"}
	check := append([]string{"-C"}, drop...)
	if _, err := n.Run(ctx, bin, check...); err == nil {
		del := append([]string{"-D"}, drop...)
		if _, err := n.Run(ctx, bin, del...); err != nil {
			return fmt.Errorf("%s remove kill-switch: %w", bin, err)
		}
	}
	return nil
}

// Down removes the interface (best effort).
func (n *NetOps) Down(ctx context.Context) error {
	_, err := n.Run(ctx, "ip", "link", "del", "dev", n.Iface)
	return err
}

// PeerInfo is live data from `wg show dump`.
type PeerInfo struct {
	PublicKey     string
	Endpoint      string
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// Dump returns live peer info keyed by public key. A non-nil error means
// the interface is down or `wg` failed — callers use it to mark the
// interface down in the UI rather than reporting it as up.
func (n *NetOps) Dump(ctx context.Context) (map[string]PeerInfo, error) {
	out, err := n.Run(ctx, "wg", "show", n.Iface, "dump")
	if err != nil {
		return nil, fmt.Errorf("wg show %s: %w", n.Iface, err)
	}
	peers := map[string]PeerInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			continue // interface line (4 fields) or blank
		}
		hs, _ := strconv.ParseInt(f[5], 10, 64)
		rx, _ := strconv.ParseUint(f[6], 10, 64)
		tx, _ := strconv.ParseUint(f[7], 10, 64)
		var hst time.Time
		if hs > 0 {
			hst = time.Unix(hs, 0)
		}
		peers[f[1]] = PeerInfo{PublicKey: f[1], Endpoint: f[3], LastHandshake: hst, RxBytes: rx, TxBytes: tx}
	}
	return peers, nil
}
