// Package config loads Tailrelay's runtime configuration from flags and
// environment variables. Secrets (admin password) are accepted via
// environment only where possible and are never written to disk.
package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Config holds runtime configuration. WireGuard/Tailscale network settings
// live in the state file (editable via the web UI); this is process config.
type Config struct {
	BindAddr       string // address the web UI listens on
	Port           int    // web UI port
	PasswordHash   []byte // bcrypt hash of the admin password, nil = no auth
	StatePath      string // /var/lib/tailrelay/state.json
	ConfPath       string // /etc/wireguard/wg0.conf
	Iface          string // wg0
	TailscaleIface string // tailscale0: interface WireGuard traffic is NATed onto
	// InitialEndpoint pre-seeds the client-facing endpoint on first run,
	// skipping the api.ipify.org auto-detection (see README "Privacy").
	InitialEndpoint string
	// InitialIPv6Pool pre-seeds the IPv6 ULA pool on first run. Empty means
	// "generate a random ULA /64". Validation happens in ensureState.
	InitialIPv6Pool string
	// TLSCert/TLSKey enable HTTPS for the web UI. Both must be set together;
	// public (0.0.0.0) binds without TLS expose the password in cleartext.
	TLSCert string
	TLSKey  string
}

// Defaults.
const (
	DefaultPort           = 8080
	DefaultStatePath      = "/var/lib/tailrelay/state.json"
	DefaultConfPath       = "/etc/wireguard/wg0.conf"
	DefaultIface          = "wg0"
	DefaultTailscaleIface = "tailscale0"
)

// tailnetIPv4 reports whether addr is inside the Tailscale CGNAT range.
func tailnetIPv4(ip net.IP) bool {
	_, tailnet, _ := net.ParseCIDR("100.64.0.0/10")
	return tailnet.Contains(ip)
}

// publicBind reports whether binding bindAddr would expose the UI beyond the
// local machine / tailnet, in which case a password is mandatory.
func publicBind(bindAddr string) bool {
	ip := net.ParseIP(bindAddr)
	if ip == nil {
		return true // hostname: resolve conservatively -> treat as public
	}
	if ip.IsLoopback() || tailnetIPv4(ip) {
		return false
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

// Load parses flags and environment variables. tailscaleIP is used as the
// default bind address when TR_BIND_ADDR is unset; pass "" to fall back to
// 127.0.0.1 (used when tailscaled is not running).
func Load(args []string, tailscaleIP string) (*Config, error) {
	fs := flag.NewFlagSet("tailrelay", flag.ContinueOnError)
	bind := fs.String("bind", "", "address to bind the web UI to (default: tailscale IPv4, or 127.0.0.1)")
	port := fs.Int("port", 0, "web UI port")
	password := fs.String("password", "", "admin password (prefer TR_ADMIN_PASSWORD env var)")
	statePath := fs.String("state", "", "path to state.json")
	confPath := fs.String("conf", "", "path to write wg0.conf")
	iface := fs.String("iface", "", "wireguard interface name")
	tsIface := fs.String("ts-iface", "", "tailscale interface name for NAT (default tailscale0)")
	endpoint := fs.String("endpoint", "", "initial public endpoint host[:port]; skips ipify auto-detection")
	ipv6pool := fs.String("ipv6-pool", "", "initial IPv6 ULA pool CIDR (default: random fd..::/64); empty value handling is in ensureState")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file for the web UI (requires -tls-key)")
	tlsKey := fs.String("tls-key", "", "TLS private key file for the web UI (requires -tls-cert)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	c := &Config{Iface: DefaultIface, Port: DefaultPort, StatePath: DefaultStatePath, ConfPath: DefaultConfPath}

	getenv := func(flagVal, envKey, def string) string {
		if flagVal != "" {
			return flagVal
		}
		if v := os.Getenv(envKey); v != "" {
			return v
		}
		return def
	}

	c.BindAddr = getenv(*bind, "TR_BIND_ADDR", "")
	if c.BindAddr == "" {
		if tailscaleIP != "" {
			c.BindAddr = tailscaleIP
		} else {
			c.BindAddr = "127.0.0.1"
		}
	}
	if p := getenv("", "TR_PORT", ""); p != "" && *port == 0 {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid TR_PORT %q", p)
		}
		c.Port = n
	} else if *port != 0 {
		c.Port = *port
	}
	c.StatePath = getenv(*statePath, "TR_STATE_PATH", DefaultStatePath)
	c.ConfPath = getenv(*confPath, "TR_CONF_PATH", DefaultConfPath)
	c.Iface = getenv(*iface, "TR_IFACE", DefaultIface)
	c.TailscaleIface = getenv(*tsIface, "TR_TAILSCALE_IFACE", DefaultTailscaleIface)
	c.InitialEndpoint = getenv(*endpoint, "TR_ENDPOINT", "")
	c.InitialIPv6Pool = strings.TrimSpace(getenv(*ipv6pool, "TR_IPV6_POOL", ""))
	c.TLSCert = getenv(*tlsCert, "TR_TLS_CERT", "")
	c.TLSKey = getenv(*tlsKey, "TR_TLS_KEY", "")
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, fmt.Errorf("TLS needs both a certificate and a key: set TR_TLS_CERT and TR_TLS_KEY (or neither)")
	}

	pw := *password
	if pw == "" {
		pw = os.Getenv("TR_ADMIN_PASSWORD")
	} else {
		fmt.Fprintln(os.Stderr, "warning: --password exposes the secret in the process list; prefer TR_ADMIN_PASSWORD")
	}
	if pw != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hashing password: %w", err)
		}
		c.PasswordHash = hash
	}

	if publicBind(c.BindAddr) && len(c.PasswordHash) == 0 {
		return nil, fmt.Errorf(
			"refusing to bind %s without a password: set TR_ADMIN_PASSWORD or bind to the tailscale IP / localhost",
			c.BindAddr)
	}
	return c, nil
}

// Addr returns host:port for net/http.
func (c *Config) Addr() string { return net.JoinHostPort(c.BindAddr, strconv.Itoa(c.Port)) }

// TLSEnabled reports whether the web UI serves HTTPS.
func (c *Config) TLSEnabled() bool { return c.TLSCert != "" && c.TLSKey != "" }

// Redacted describes the effective config without secrets, for logging.
func (c *Config) Redacted() string {
	auth := "none (tailnet/localhost gate)"
	if len(c.PasswordHash) > 0 {
		auth = "password"
	}
	tls := "off"
	if c.TLSEnabled() {
		tls = "on"
	}
	return fmt.Sprintf("bind=%s auth=%s tls=%s state=%s conf=%s iface=%s ts-iface=%s",
		c.Addr(), auth, tls, c.StatePath, c.ConfPath, c.Iface, c.TailscaleIface)
}

// ListenEnvHint documents every supported variable for README/--help reuse.
func ListenEnvHint() string {
	return strings.Join([]string{
		"TR_BIND_ADDR     bind address for the web UI (default: `tailscale ip -4`, else 127.0.0.1)",
		"TR_PORT          web UI port (default 8080)",
		"TR_ADMIN_PASSWORD admin password; required when binding beyond localhost/tailnet",
		"TR_STATE_PATH    state file path (default /var/lib/tailrelay/state.json)",
		"TR_CONF_PATH     generated wg0.conf path (default /etc/wireguard/wg0.conf)",
		"TR_IFACE         wireguard interface name (default wg0)",
		"TR_TAILSCALE_IFACE tailscale interface NAT target (default tailscale0)",
		"TR_ENDPOINT      initial endpoint host[:port]; skips the ipify.org lookup on first run",
		"TR_IPV6_POOL     initial IPv6 ULA pool CIDR on first run (default: random fd..::/64)",
		"TR_TLS_CERT      TLS certificate file for the web UI (needs TR_TLS_KEY)",
		"TR_TLS_KEY       TLS private key file for the web UI (needs TR_TLS_CERT)",
	}, "\n")
}
