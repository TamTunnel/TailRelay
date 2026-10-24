// Command tailrelay is an extremely lightweight WireGuard server manager
// that bridges WireGuard clients into a Tailscale tailnet, with a web UI.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TamTunnel/Tailrelay/internal/config"
	"github.com/TamTunnel/Tailrelay/internal/state"
	"github.com/TamTunnel/Tailrelay/internal/ts"
	"github.com/TamTunnel/Tailrelay/internal/web"
	"github.com/TamTunnel/Tailrelay/internal/wg"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatalf("tailrelay: %v", err)
	}
}

func run(args []string) error {
	ctx := context.Background()
	run := wg.DefaultRunner

	// Default bind = tailscale IPv4; fall back to localhost if tailscaled is down.
	tailIP := ts.IP4(ctx, run)
	if tailIP == "" {
		log.Print("warning: `tailscale ip -4` failed; binding web UI to 127.0.0.1 until tailscaled is up")
	}
	cfg, err := config.Load(args, tailIP)
	if err != nil {
		fmt.Fprintln(os.Stderr, config.ListenEnvHint())
		return err
	}
	log.Printf("tailrelay %s: %s", version, cfg.Redacted())

	store := state.NewStore(cfg.StatePath)
	st, err := ensureState(ctx, cfg, store)
	if err != nil {
		return err
	}

	// Re-assert desired Tailscale settings (best effort; UI can fix failures).
	if tstat, err := ts.GetStatus(ctx, run); err == nil && tstat.Running {
		if st.Settings.ExitNode != "" {
			if err := ts.SetExitNode(ctx, run, st.Settings.ExitNode); err != nil {
				log.Printf("warning: re-applying exit node %q: %v", st.Settings.ExitNode, err)
			}
		}
		if st.Settings.Routes != "" {
			if err := ts.SetAdvertiseRoutes(ctx, run, st.Settings.Routes); err != nil {
				log.Printf("warning: re-applying routes %q: %v", st.Settings.Routes, err)
			}
		}
	} else {
		log.Printf("warning: tailscaled not running (%v); bridge controls will show in the UI", err)
	}

	// Bring up WireGuard (best effort: the UI stays usable for config).
	if err := newWG(cfg, run).Apply(ctx, st, cfg.ConfPath); err != nil {
		log.Printf("warning: wireguard apply failed (need root/NET_ADMIN?): %v", err)
	} else {
		log.Printf("wireguard interface %s up", cfg.Iface)
	}

	_, handler, err := web.NewServer(web.Deps{
		Store: store, WG: newWG(cfg, run), TS: run, Conf: cfg, Version: version,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: cfg.Addr(), Handler: handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second}
	if cfg.TLSEnabled() {
		log.Printf("listening on https://%s (TLS)", cfg.Addr())
		return srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	}
	log.Printf("listening on http://%s", cfg.Addr())
	return srv.ListenAndServe()
}

func newWG(cfg *config.Config, run wg.Runner) *wg.NetOps {
	return &wg.NetOps{Run: run, Iface: cfg.Iface, TSIface: cfg.TailscaleIface}
}

// ensureState loads the state file or initializes it on first run.
func ensureState(ctx context.Context, cfg *config.Config, store *state.Store) (*state.State, error) {
	if store.Exists() {
		st, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("loading state: %w", err)
		}
		return st, nil
	}
	priv, err := wg.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	pub, err := wg.PublicKeyFromPrivate(priv)
	if err != nil {
		return nil, err
	}
	st := &state.State{
		ServerPrivateKey: priv,
		ServerPublicKey:  pub,
		Settings:         state.DefaultSettings(),
		Clients:          []state.Client{},
	}
	// Dual-stack by default (WG Easy-style): every install gets its own
	// random ULA /64, or the TR_IPV6_POOL override. Empty is not reachable
	// here — clearing the pool (disabling IPv6) happens in the Settings UI.
	v6pool := strings.TrimSpace(cfg.InitialIPv6Pool)
	if v6pool == "" {
		var err error
		v6pool, err = state.RandomULAPool()
		if err != nil {
			return nil, err
		}
		log.Printf("generated IPv6 ULA pool %s", v6pool)
	} else if !state.ValidIPv6Pool(v6pool) {
		return nil, fmt.Errorf("invalid TR_IPV6_POOL %q: must be an IPv6 CIDR", cfg.InitialIPv6Pool)
	}
	st.Settings.IPv6Pool = v6pool
	st.Settings.ClientAllowedIPs = "0.0.0.0/0, ::/0"
	if ep := strings.TrimSpace(cfg.InitialEndpoint); ep != "" {
		if strings.ContainsAny(ep, " \t\r\n") {
			log.Printf("warning: ignoring invalid TR_ENDPOINT %q (must be host or host:port)", ep)
		} else {
			st.Settings.Endpoint = ep
			log.Printf("using TR_ENDPOINT %s (skipped ipify auto-detection)", ep)
		}
	} else if ip := detectPublicIP(); ip != "" {
		st.Settings.Endpoint = net.JoinHostPort(ip, "51820")
		log.Printf("auto-detected public endpoint %s (override in Settings)", st.Settings.Endpoint)
	}
	if err := store.Save(st); err != nil {
		return nil, fmt.Errorf("saving initial state: %w", err)
	}
	log.Printf("initialized new state at %s", store.Path())
	return st, nil
}

// detectPublicIP best-effort discovers the VPS public IPv4.
func detectPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := string(body)
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}
