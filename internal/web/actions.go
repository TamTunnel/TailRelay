package web

import (
	"context"
	"fmt"
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
	LastHandshake string
	Rx, Tx        string
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
	Peers     []peerView
	TS        ts.Status
	Routes    string
	ExitNodes []ts.ExitNode
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
	if derr == nil && len(dump) >= 0 {
		data.WG.Up = true
	}
	if !data.WG.Up {
		data.WG.DownReason = "interface not found (needs NET_ADMIN / root)"
	}
	for _, c := range st.Clients {
		pv := peerView{Name: c.Name, Address: c.Address}
		if info, ok := dump[c.PublicKey]; ok {
			if !info.LastHandshake.IsZero() {
				pv.LastHandshake = info.LastHandshake.Local().Format("Jan 2 15:04")
			}
			pv.Rx, pv.Tx = humanBytes(info.RxBytes), humanBytes(info.TxBytes)
		}
		data.Peers = append(data.Peers, pv)
	}
	sort.Slice(data.Peers, func(i, j int) bool { return data.Peers[i].Name < data.Peers[j].Name })

	if tstat, terr := ts.GetStatus(ctx, s.d.TS); terr == nil {
		data.TS = *tstat
		data.Routes = st.Settings.Routes
		if tstat.Running {
			if nodes, nerr := ts.ExitNodes(ctx, s.d.TS); nerr == nil {
				data.ExitNodes = nodes
			}
		}
	} else {
		data.TS.BackendState = "unreachable"
	}
	s.render(w, "dashboard.html", data)
}

// --- clients ---

type clientView struct {
	Name      string
	Address   string
	Created   string
	PublicKey string
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
		data.Clients = append(data.Clients, clientView{
			Name: c.Name, Address: c.Address,
			Created:   c.CreatedAt.Local().Format("2006-01-02"),
			PublicKey: c.PublicKey,
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
		DNS:              strings.TrimSpace(r.FormValue("dns")),
		MTU:              mtu,
		Keepalive:        keepalive,
		ListenPort:       listenPort,
		Endpoint:         strings.TrimSpace(r.FormValue("endpoint")),
		ClientAllowedIPs: strings.TrimSpace(r.FormValue("client_allowed_ips")),
	}
	if _, _, err := net.ParseCIDR(ns.PoolCIDR); err != nil {
		redirectErr(w, r, "/settings", fmt.Errorf("bad pool CIDR: %w", err))
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
	err := s.d.Store.Update(func(st *state.State) error {
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
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := ts.SetExitNode(ctx, s.d.TS, node); err != nil {
		redirectErr(w, r, "/", fmt.Errorf("tailscale set --exit-node: %w", err))
		return
	}
	_ = s.d.Store.Update(func(st *state.State) error {
		st.Settings.ExitNode = node
		return nil
	})
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
	_ = s.d.Store.Update(func(st *state.State) error {
		st.Settings.Routes = routes
		return nil
	})
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
		redirectErr(w, r, "/", fmt.Errorf("tailscale up: %w", err))
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
