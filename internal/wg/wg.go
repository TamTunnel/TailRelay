// Package wg manages the WireGuard server: key generation, config file
// rendering, interface lifecycle (ip/wg), IP forwarding and NAT.
package wg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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
	for _, c := range st.Clients {
		taken[c.Address] = true
	}
	addr, err := NextClientIP(st.Settings.PoolCIDR, taken)
	if err != nil {
		return state.Client{}, err
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
		PresharedKey: psk, Address: addr, CreatedAt: time.Now().UTC(),
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
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by Tailrelay (%s) — do not edit manually; use the web UI\n", iface)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", st.ServerPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", cidrHost(serverIP, st.Settings.PoolCIDR))
	fmt.Fprintf(&b, "ListenPort = %d\n", st.Settings.ListenPort)
	fmt.Fprintf(&b, "MTU = %d\n", st.Settings.MTU)
	for _, c := range st.Clients {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "# %s\n", c.Name)
		fmt.Fprintf(&b, "PublicKey = %s\n", c.PublicKey)
		fmt.Fprintf(&b, "PresharedKey = %s\n", c.PresharedKey)
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", c.Address)
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
	var b strings.Builder
	fmt.Fprintf(&b, "# Tailrelay client config for %q — import into the WireGuard app\n", c.Name)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", cidrHost(c.Address, st.Settings.PoolCIDR))
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

	// Create interface (ignore "exists").
	_, _ = n.Run(ctx, "ip", "link", "add", "dev", n.Iface, "type", "wireguard")
	if out, err := n.Run(ctx, "ip", "addr", "add", addr, "dev", n.Iface); err != nil &&
		!strings.Contains(string(out), "exists") && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("assigning address: %w", err)
	}
	if _, err := n.Run(ctx, "ip", "link", "set", "mtu", strconv.Itoa(st.Settings.MTU), "dev", n.Iface); err != nil {
		return fmt.Errorf("setting mtu: %w", err)
	}
	// Sync peers atomically from the rendered config.
	if _, err := n.Run(ctx, "wg", "setconf", n.Iface, confPath); err != nil {
		return fmt.Errorf("wg setconf: %w", err)
	}
	if _, err := n.Run(ctx, "ip", "link", "set", "up", "dev", n.Iface); err != nil {
		return fmt.Errorf("bringing interface up: %w", err)
	}
	if err := n.enableForwarding(ctx); err != nil {
		return err
	}
	return n.ensureNAT(ctx, st.Settings.PoolCIDR, st.Settings.KillSwitch)
}

func (n *NetOps) enableForwarding(ctx context.Context) error {
	if _, err := n.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		// Fallback: write procfs directly.
		if werr := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); werr != nil {
			return fmt.Errorf("enabling ip_forward: %w (sysctl also failed: %v)", werr, err)
		}
	}
	return nil
}

// ensureNAT installs the FORWARD + MASQUERADE rules wg0 -> <ts-iface>.
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
func (n *NetOps) ensureNAT(ctx context.Context, poolCIDR string, killSwitch bool) error {
	tsif := n.TSIface
	rules := [][]string{
		{"-C", "FORWARD", "-i", n.Iface, "-o", tsif, "-j", "ACCEPT"},
		{"-C", "FORWARD", "-i", tsif, "-o", n.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		{"-t", "nat", "-C", "POSTROUTING", "-s", poolCIDR, "-o", tsif, "-j", "MASQUERADE"},
	}
	adds := [][]string{
		{"-A", "FORWARD", "-i", n.Iface, "-o", tsif, "-j", "ACCEPT"},
		{"-A", "FORWARD", "-i", tsif, "-o", n.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		{"-t", "nat", "-A", "POSTROUTING", "-s", poolCIDR, "-o", tsif, "-j", "MASQUERADE"},
	}
	for i, check := range rules {
		if _, err := n.Run(ctx, "iptables", check...); err != nil {
			if _, err := n.Run(ctx, "iptables", adds[i]...); err != nil {
				return fmt.Errorf("iptables %s: %w", strings.Join(adds[i], " "), err)
			}
		}
	}
	dropSpec := []string{"FORWARD", "-i", n.Iface, "!", "-o", tsif, "-j", "DROP"}
	withFlag := func(flag string) []string {
		spec := make([]string, 0, len(dropSpec)+1)
		return append(append(spec, flag), dropSpec...)
	}
	if killSwitch {
		if _, err := n.Run(ctx, "iptables", withFlag("-C")...); err != nil {
			if _, err := n.Run(ctx, "iptables", withFlag("-A")...); err != nil {
				return fmt.Errorf("iptables kill-switch: %w", err)
			}
		}
		return nil
	}
	// Kill switch off: remove the DROP if it's there, so traffic flows.
	if _, err := n.Run(ctx, "iptables", withFlag("-C")...); err == nil {
		if _, err := n.Run(ctx, "iptables", withFlag("-D")...); err != nil {
			return fmt.Errorf("iptables remove kill-switch: %w", err)
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
