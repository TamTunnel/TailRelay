package web

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/TamTunnel/Tailrelay/internal/state"
	"github.com/TamTunnel/Tailrelay/internal/ts"
	"github.com/TamTunnel/Tailrelay/internal/wg"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)

func validName(n string) bool { return nameRe.MatchString(n) }

var labelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// validHost reports whether h is a valid IP or DNS hostname (no
// whitespace/newlines — these values are rendered into client .conf files).
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return true
	}
	for _, label := range strings.Split(h, ".") {
		if !labelRe.MatchString(label) {
			return false
		}
	}
	return true
}

// validEndpoint reports whether s is empty or host[:port].
func validEndpoint(s string) bool {
	if s == "" {
		return true
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, "" // no port present
	}
	if port != "" {
		p, perr := strconv.Atoi(port)
		if perr != nil || p < 1 || p > 65535 {
			return false
		}
	}
	return validHost(host)
}

// validAllowedIPs reports whether s is a comma-separated list of CIDRs.
// Raw CR/LF is rejected outright: the value is rendered verbatim into
// client .conf files, so a newline here would inject config lines.
func validAllowedIPs(s string) bool {
	if strings.ContainsAny(s, "\r\n") {
		return false
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		if _, _, err := net.ParseCIDR(part); err != nil {
			return false
		}
	}
	return true
}

func findClient(st *state.State, name string) *state.Client {
	for i := range st.Clients {
		if st.Clients[i].Name == name {
			return &st.Clients[i]
		}
	}
	return nil
}

type peerView struct {
	Name          string
	Address       string
	AddressV6     string
	LastHandshake string
	Rx, Tx        string
}

// shortErr trims a runner error for UI display (first line only).
func shortErr(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "\n"); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 120 {
		msg = msg[:117] + "..."
	}
	return msg
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// --- dashboard ---

type dashboardData struct {
	pageData
	WG struct {
		Up         bool
		DownReason string
		Iface      string
		Endpoint   string
		Pool       string
		ServerPub  string
	}
	Peers []peerView
	TS    ts.Status
	// TSVersion is the bundled tailscaled version (`tailscale version`),
	// "" when unreachable. Makes a stale Tailscale visible in the UI.
	TSVersion string
	Routes    string
	ExitNodes []ts.ExitNode
	// ExitNodeWarning is set when a pinned exit node is down or not
	// active: relayed traffic is fail-closed (stopped), recovery manual.
	ExitNodeWarning string
	// Kill-switch status: label + pill class ("ok"/"warn"), plus a leak
	// note when the switch is off.
	KillSwitchLabel    string
	KillSwitchPill     string
	KillSwitchLeakNote bool
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	data := dashboardData{pageData: s.baseData(w, r, "Dashboard")}
	data.WG.Iface = s.d.WG.Iface

	st, err := s.d.Store.Load()
	if err != nil {
		data.Err = "loading state: " + err.Error()
		s.render(w, "dashboard.html", data)
		return
	}
	data.WG.Pool = st.Settings.PoolCIDR
	data.WG.ServerPub = st.ServerPublicKey
	data.WG.Endpoint = st.Settings.Endpoint
	if data.WG.Endpoint == "" {
		data.WG.Endpoint = fmt.Sprintf("<public-ip>:%d", st.Settings.ListenPort)
	}

	dump, derr := s.d.WG.Dump(ctx)
	if derr != nil {
		data.WG.Up = false
		data.WG.DownReason = "wireguard interface not responding (" + shortErr(derr) + ")"
	} else {
		data.WG.Up = true
	}
	for _, c := range st.Clients {
		pv := peerView{Name: c.Name, Address: c.Address, AddressV6: c.AddressV6}
		if info, ok := dump[c.PublicKey]; ok {
			if !info.LastHandshake.IsZero() {
				pv.LastHandshake = info.LastHandshake.Local().Format("Jan 2 15:04")
			}
			pv.Rx, pv.Tx = humanBytes(info.RxBytes), humanBytes(info.TxBytes)
		}
		data.Peers = append(data.Peers, pv)
	}
	sort.Slice(data.Peers, func(i, j int) bool { return data.Peers[i].Name < data.Peers[j].Name })

	tsHealthy := false // tailscaled up AND the tailscale interface exists
	if tstat, terr := ts.GetStatus(ctx, s.d.TS); terr == nil {
		data.TS = *tstat
		data.Routes = st.Settings.Routes
		if tstat.Running {
			tsHealthy = s.d.WG.TSIfaceExists(ctx)
			selected := tstat.ExitNodeName
			if selected == "" {
				selected = st.Settings.ExitNode // fall back to the stored choice
			}
			if nodes, nerr := ts.ExitNodes(ctx, s.d.TS, selected); nerr == nil {
				// The --json list path marks every candidate online; the
				// status payload is authoritative for the *selected* node's
				// real state (it knows when the pinned node went down).
				for i := range nodes {
					if nodes[i].Selected {
						nodes[i].Online = tstat.UsingExitNode
					}
				}
				data.ExitNodes = nodes
				data.ExitNodeWarning = exitNodeWarning(st.Settings.ExitNode, nodes)
			}
		}
	} else {
		data.TS.BackendState = "unreachable"
	}
	// Tailscale version is independent of login state; `tailscale version`
	// works even when tailscaled needs login (or is down -> "").
	data.TSVersion = ts.Version(ctx, s.d.TS)
	// Kill-switch status: on+healthy = tunneling; on+down = paused
	// (traffic dropped, not leaked); off = leak risk, said plainly.
	switch {
	case st.Settings.KillSwitch && tsHealthy:
		data.KillSwitchLabel, data.KillSwitchPill = "Active & tunneling", "ok"
	case st.Settings.KillSwitch:
		data.KillSwitchLabel, data.KillSwitchPill = "Paused — Tailscale down", "warn"
	default:
		data.KillSwitchLabel, data.KillSwitchPill = "Kill switch off", "warn"
		data.KillSwitchLeakNote = true
	}
	s.render(w, "dashboard.html", data)
}

// exitNodeWarning reports a fail-closed warning when an exit node is
// pinned but not actively relaying: the node went offline (traffic is
// stopped — never silently rerouted to another node, which would change
// egress IP/location) or it vanished from the candidate list. "" means
// healthy, or no pin set. Recovery is always manual via the picker.
// If the pinned node exists in the list but isn't marked Selected yet,
// it's likely a transitional state (Tailscale still switching) — don't warn.
func exitNodeWarning(pin string, nodes []ts.ExitNode) string {
	if pin == "" {
		return ""
	}
	pinExists := false
	for _, n := range nodes {
		// Flexible match: pin may be short hostname, full MagicDNS, or node ID.
		if n.Hostname == pin || strings.HasSuffix(pin, "."+n.Hostname) || strings.HasSuffix(n.Hostname, "."+pin) {
			pinExists = true
		}
		if n.Selected {
			if n.Online {
				return ""
			}
			return fmt.Sprintf("exit node %q is OFFLINE — WireGuard traffic is fail-closed (stopped, not rerouted). Pick another node below to restore the relay; recovery is manual by design", n.Hostname)
		}
	}
	// No node Selected. If the pin exists in the list, Tailscale is likely
	// still switching — don't false-alarm. Only warn if the pin is gone.
	if pinExists {
		return ""
	}
	return fmt.Sprintf("pinned exit node %q is not active — traffic is fail-closed (stopped). Pick a node below to restore the relay", pin)
}

// --- clients ---

type clientView struct {
	Name      string
	Address   string
	AddressV6 string
	Created   string
	PublicKey string
	Config    string
}

type clientsData struct {
	pageData
	Pool    string
	Clients []clientView
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	st, err := s.d.Store.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := clientsData{pageData: s.baseData(w, r, "Clients"), Pool: st.Settings.PoolCIDR}
	for _, c := range st.Clients {
		conf, cerr := wg.RenderClientConfig(st, c)
		if cerr != nil {
			http.Error(w, cerr.Error(), http.StatusInternalServerError)
			return
		}
		data.Clients = append(data.Clients, clientView{
			Name: c.Name, Address: c.Address, AddressV6: c.AddressV6,
			Created:   c.CreatedAt.Local().Format("2006-01-02"),
			PublicKey: c.PublicKey,
			Config:    conf,
		})
	}
	sort.Slice(data.Clients, func(i, j int) bool { return data.Clients[i].Name < data.Clients[j].Name })
	s.render(w, "clients.html", data)
}

func (s *Server) applyWG(ctx context.Context) error {
	st, err := s.d.Store.Load()
	if err != nil {
		return err
	}
	return s.d.WG.Apply(ctx, st, s.d.Conf.ConfPath)
}

func (s *Server) handleClientAdd(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if !validName(name) {
		redirectErr(w, r, "/clients", fmt.Errorf("invalid name %q: use letters, digits, dash, underscore (max 32)", name))
		return
	}
	var added string
	err := s.d.Store.Update(func(st *state.State) error {
		c, err := wg.AddClient(st, name)
		if err != nil {
			return err
		}
		added = fmt.Sprintf("%s (%s)", c.Name, c.Address)
		if c.AddressV6 != "" {
			added = fmt.Sprintf("%s (%s, %s)", c.Name, c.Address, c.AddressV6)
		}
		return nil
	})
	if err != nil {
		redirectErr(w, r, "/clients", err)
		return
	}
	if err := s.applyWG(r.Context()); err != nil {
		redirectErr(w, r, "/clients", fmt.Errorf("client added but interface apply failed: %w", err))
		return
	}
	redirectMsg(w, r, "/clients", "added client "+added)
}

func (s *Server) handleClientDelete(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	err := s.d.Store.Update(func(st *state.State) error {
		kept := st.Clients[:0]
		found := false
		for _, c := range st.Clients {
			if c.Name == name {
				found = true
				continue
			}
			kept = append(kept, c)
		}
		if !found {
			return fmt.Errorf("client %q not found", name)
		}
		st.Clients = kept
		return nil
	})
	if err != nil {
		redirectErr(w, r, "/clients", err)
		return
	}
	if err := s.applyWG(r.Context()); err != nil {
		redirectErr(w, r, "/clients", fmt.Errorf("client removed but interface apply failed: %w", err))
		return
	}
	redirectMsg(w, r, "/clients", "removed client "+name)
}

func (s *Server) handleClientRename(w http.ResponseWriter, r *http.Request) {
	name, newName := r.FormValue("name"), strings.TrimSpace(r.FormValue("new_name"))
	if !validName(newName) {
		redirectErr(w, r, "/clients", fmt.Errorf("invalid new name %q", newName))
		return
	}
	err := s.d.Store.Update(func(st *state.State) error {
		if findClient(st, newName) != nil {
			return fmt.Errorf("client %q already exists", newName)
		}
		c := findClient(st, name)
		if c == nil {
			return fmt.Errorf("client %q not found", name)
		}
		c.Name = newName
		return nil
	})
	if err != nil {
		redirectErr(w, r, "/clients", err)
		return
	}
	if err := s.applyWG(r.Context()); err != nil {
		redirectErr(w, r, "/clients", fmt.Errorf("renamed but interface apply failed: %w", err))
		return
	}
	redirectMsg(w, r, "/clients", "renamed to "+newName)
}

func (s *Server) handleConf(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	st, err := s.d.Store.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c := findClient(st, name)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	conf, err := wg.RenderClientConfig(st, *c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".conf"))
	w.Write([]byte(conf))
}

func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	st, err := s.d.Store.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c := findClient(st, name)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	conf, err := wg.RenderClientConfig(st, *c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	png, err := qrcode.Encode(conf, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// --- settings ---

type settingsData struct {
	pageData
	S        state.Settings
	ConfPath string
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.d.Store.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "settings.html", settingsData{
		pageData: s.baseData(w, r, "Settings"),
		S:        st.Settings, ConfPath: s.d.Conf.ConfPath,
	})
}

func (s *Server) handleSettingsPost(w http.ResponseWriter, r *http.Request) {
	mtu, _ := strconv.Atoi(r.FormValue("mtu"))
	keepalive, _ := strconv.Atoi(r.FormValue("keepalive"))
	listenPort, _ := strconv.Atoi(r.FormValue("listen_port"))
	ns := state.Settings{
		PoolCIDR:         strings.TrimSpace(r.FormValue("pool_cidr")),
		IPv6Pool:         strings.TrimSpace(r.FormValue("ipv6_pool")),
		DNS:              strings.TrimSpace(r.FormValue("dns")),
		MTU:              mtu,
		Keepalive:        keepalive,
		ListenPort:       listenPort,
		Endpoint:         strings.TrimSpace(r.FormValue("endpoint")),
		ClientAllowedIPs: strings.TrimSpace(r.FormValue("client_allowed_ips")),
		// Unchecked checkboxes don't submit — absence means off.
		KillSwitch: r.FormValue("kill_switch") == "1",
	}
	if _, _, err := net.ParseCIDR(ns.PoolCIDR); err != nil {
		redirectErr(w, r, "/settings", fmt.Errorf("bad pool CIDR: %w", err))
		return
	}
	// Empty IPv6 pool = dual-stack disabled (documented, allowed).
	if !state.ValidIPv6Pool(ns.IPv6Pool) {
		redirectErr(w, r, "/settings", fmt.Errorf("bad IPv6 pool %q: must be empty or an IPv6 CIDR (e.g. fd12:3456:789a::/64)", ns.IPv6Pool))
		return
	}
	if mtu < 1280 || mtu > 9000 {
		redirectErr(w, r, "/settings", fmt.Errorf("MTU must be 1280-9000"))
		return
	}
	if keepalive < 0 || keepalive > 3600 || listenPort < 1 || listenPort > 65535 {
		redirectErr(w, r, "/settings", fmt.Errorf("keepalive/port out of range"))
		return
	}
	if ns.DNS == "" || ns.ClientAllowedIPs == "" {
		redirectErr(w, r, "/settings", fmt.Errorf("DNS and AllowedIPs are required"))
		return
	}
	if !validHost(ns.DNS) {
		redirectErr(w, r, "/settings", fmt.Errorf("bad DNS %q: must be an IP or hostname", ns.DNS))
		return
	}
	if !validEndpoint(ns.Endpoint) {
		redirectErr(w, r, "/settings", fmt.Errorf("bad endpoint %q: must be host or host:port", ns.Endpoint))
		return
	}
	if !validAllowedIPs(ns.ClientAllowedIPs) {
		redirectErr(w, r, "/settings", fmt.Errorf("bad AllowedIPs %q: must be comma-separated CIDRs", ns.ClientAllowedIPs))
		return
	}
	// Changing either pool orphans existing clients (they keep old IPs while
	// the server moves to .1/::1 of the new pool). Refuse until they're gone.
	// This also covers enabling/disabling IPv6: existing clients have no v6
	// address to keep, so the change is only safe with zero clients.
	cur, err := s.d.Store.Load()
	if err != nil {
		redirectErr(w, r, "/settings", fmt.Errorf("loading state: %w", err))
		return
	}
	if ns.PoolCIDR != cur.Settings.PoolCIDR && len(cur.Clients) > 0 {
		redirectErr(w, r, "/settings", fmt.Errorf(
			"cannot change the IP pool while %d client(s) exist — remove them first, then change the pool and re-add", len(cur.Clients)))
		return
	}
	if ns.IPv6Pool != cur.Settings.IPv6Pool && len(cur.Clients) > 0 {
		redirectErr(w, r, "/settings", fmt.Errorf(
			"cannot change the IPv6 pool while %d client(s) exist — remove them first, then change the pool and re-add", len(cur.Clients)))
		return
	}
	// Keep the untouched default AllowedIPs in sync with the v6 toggle:
	// disabling v6 with "::/0" still present would blackhole client IPv6.
	if ns.IPv6Pool == "" && ns.ClientAllowedIPs == "0.0.0.0/0, ::/0" {
		ns.ClientAllowedIPs = "0.0.0.0/0"
	}
	if ns.IPv6Pool != "" && ns.ClientAllowedIPs == "0.0.0.0/0" {
		ns.ClientAllowedIPs = "0.0.0.0/0, ::/0"
	}
	err = s.d.Store.Update(func(st *state.State) error {
		keep := st.Settings.ExitNode
		routes := st.Settings.Routes
		st.Settings = ns
		st.Settings.ExitNode = keep
		st.Settings.Routes = routes
		return nil
	})
	if err != nil {
		redirectErr(w, r, "/settings", err)
		return
	}
	if err := s.applyWG(r.Context()); err != nil {
		redirectErr(w, r, "/settings", fmt.Errorf("saved but interface apply failed: %w", err))
		return
	}
	redirectMsg(w, r, "/settings", "settings saved and interface re-applied")
}

// --- tailscale actions ---

func (s *Server) handleExitNode(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.FormValue("node"))
	// Pin by MagicDNS name only, never by tailnet IP: an `auto:any`-style
	// or IP-based pin would let egress silently hop between nodes. The
	// picker only offers concrete names; reject anything else outright.
	if node != "" && net.ParseIP(node) != nil {
		redirectErr(w, r, "/", fmt.Errorf("exit node must be a tailnet hostname, not an IP address"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := ts.SetExitNode(ctx, s.d.TS, node); err != nil {
		redirectErr(w, r, "/", fmt.Errorf("tailscale set --exit-node: %w", err))
		return
	}
	if err := s.d.Store.Update(func(st *state.State) error {
		st.Settings.ExitNode = node
		return nil
	}); err != nil {
		log.Printf("warning: persisting exit-node choice: %v", err)
	}
	if node == "" {
		redirectMsg(w, r, "/", "exit node cleared")
	} else {
		redirectMsg(w, r, "/", "exit node set to "+node)
	}
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	routes := strings.TrimSpace(r.FormValue("routes"))
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := ts.SetAdvertiseRoutes(ctx, s.d.TS, routes); err != nil {
		redirectErr(w, r, "/", fmt.Errorf("tailscale set --advertise-routes: %w", err))
		return
	}
	if err := s.d.Store.Update(func(st *state.State) error {
		st.Settings.Routes = routes
		return nil
	}); err != nil {
		log.Printf("warning: persisting advertised routes: %v", err)
	}
	redirectMsg(w, r, "/", "advertised routes updated")
}

func (s *Server) handleTailscaleUp(w http.ResponseWriter, r *http.Request) {
	authKey := strings.TrimSpace(r.FormValue("authkey"))
	hostname := strings.TrimSpace(r.FormValue("hostname"))
	if authKey == "" {
		redirectErr(w, r, "/", fmt.Errorf("auth key is required"))
		return
	}
	if err := ts.Up(r.Context(), s.d.TS, authKey, hostname); err != nil {
		// Belt-and-braces: never echo the raw CLI error into the ?err=
		// redirect. Even with --authkey redacted by the runner, secrets
		// have no business in URLs, browser history, or proxy logs.
		log.Printf("tailscale up failed: %v", err)
		redirectErr(w, r, "/", fmt.Errorf("tailscale up failed — check that tailscaled is running and the auth key is valid"))
		return
	}
	redirectMsg(w, r, "/", "tailscale is up")
}

func (s *Server) handleWGApply(w http.ResponseWriter, r *http.Request) {
	if err := s.applyWG(r.Context()); err != nil {
		redirectErr(w, r, "/", fmt.Errorf("apply failed: %w", err))
		return
	}
	redirectMsg(w, r, "/", "wireguard interface re-applied")
}
