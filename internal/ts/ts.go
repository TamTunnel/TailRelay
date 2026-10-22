// Package ts wraps the host `tailscale` CLI: status, exit-node selection,
// advertised routes, and `tailscale up`. tailscaled itself is a prerequisite;
// Tailrelay never installs it.
package ts

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Runner executes an external command. Swappable in tests.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExitNode is one candidate from `tailscale exit-node list`.
type ExitNode struct {
	IP       string
	Hostname string
	Country  string
	City     string
	Online   bool
	Selected bool
}

// Status is a trimmed view of `tailscale status --json`.
type Status struct {
	Running       bool     // BackendState == "Running"
	BackendState  string   // Running, NeedsLogin, ...
	Hostname      string   // this node's tailnet hostname
	IPs           []string // this node's tailnet IPs
	UsingExitNode bool
}

// rawStatus mirrors only the fields we need from `tailscale status --json`.
// Go's JSON matching is case-insensitive, so minor key variations are fine.
type rawStatus struct {
	BackendState string `json:"BackendState"`
	Self         *struct {
		HostName     string   `json:"HostName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
	} `json:"Self"`
	ExitNodeStatus *struct {
		Online bool `json:"Online"`
	} `json:"ExitNodeStatus"`
}

// ParseStatus parses `tailscale status --json` output.
func ParseStatus(data []byte) (*Status, error) {
	var raw rawStatus
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing tailscale status: %w", err)
	}
	st := &Status{BackendState: raw.BackendState, Running: raw.BackendState == "Running"}
	if raw.Self != nil {
		st.Hostname = raw.Self.HostName
		st.IPs = raw.Self.TailscaleIPs
	}
	if raw.ExitNodeStatus != nil {
		st.UsingExitNode = raw.ExitNodeStatus.Online
	}
	return st, nil
}

// GetStatus runs `tailscale status --json`.
func GetStatus(ctx context.Context, run Runner) (*Status, error) {
	out, err := run(ctx, "tailscale", "status", "--json")
	if err != nil {
		return nil, err
	}
	return ParseStatus(out)
}

// IP4 returns this node's tailnet IPv4 (`tailscale ip -4`), "" on failure.
func IP4(ctx context.Context, run Runner) string {
	out, err := run(ctx, "tailscale", "ip", "-4")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ParseExitNodeList parses `tailscale exit-node list` text output:
//
//	# IP              HOSTNAME  COUNTRY  CITY      LATITUDE  LONGITUDE  STATUS
//	100.64.1.2        exit-1    US       New York  40.7      -74.0      online
func ParseExitNodeList(data []byte) []ExitNode {
	var nodes []ExitNode
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "IP ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		n := ExitNode{IP: f[0], Hostname: f[1]}
		status := strings.ToLower(f[len(f)-1])
		n.Online = status == "online" || status == "selected"
		n.Selected = status == "selected"
		// Columns: IP HOSTNAME COUNTRY CITY... LATITUDE LONGITUDE STATUS
		// (city may be multi-word, so count back from the end).
		if len(f) >= 6 {
			n.Country = f[2]
			n.City = strings.Join(f[3:len(f)-3], " ")
		}
		nodes = append(nodes, n)
	}
	return nodes
}

// ExitNodes lists exit-node candidates. Tries --json first, falls back to
// the classic text table for older tailscale versions.
func ExitNodes(ctx context.Context, run Runner) ([]ExitNode, error) {
	if out, err := run(ctx, "tailscale", "exit-node", "list", "--json"); err == nil {
		var payload struct {
			ExitNodes []struct {
				ID       string `json:"ID"`
				Hostinfo *struct {
					Hostname string `json:"Hostname"`
				} `json:"Hostinfo"`
				Addresses []string `json:"Addresses"`
			} `json:"ExitNodes"`
		}
		if jerr := json.Unmarshal(out, &payload); jerr == nil && len(payload.ExitNodes) > 0 {
			var nodes []ExitNode
			for _, e := range payload.ExitNodes {
				n := ExitNode{Hostname: e.ID, Online: true}
				if e.Hostinfo != nil && e.Hostinfo.Hostname != "" {
					n.Hostname = e.Hostinfo.Hostname
				}
				if len(e.Addresses) > 0 {
					n.IP = strings.Split(e.Addresses[0], "/")[0]
				}
				nodes = append(nodes, n)
			}
			return nodes, nil
		}
	}
	out, err := run(ctx, "tailscale", "exit-node", "list")
	if err != nil {
		return nil, err
	}
	return ParseExitNodeList(out), nil
}

// SetExitNode selects the exit node WireGuard traffic relays through.
// An empty name clears the exit node.
func SetExitNode(ctx context.Context, run Runner, name string) error {
	_, err := run(ctx, "tailscale", "set", "--exit-node="+name)
	return err
}

// SuggestExitNode picks the first online candidate (used when the stored
// choice no longer exists). Returns "" if none are online.
func SuggestExitNode(nodes []ExitNode) string {
	for _, n := range nodes {
		if n.Online {
			return n.Hostname
		}
	}
	return ""
}

// SetAdvertiseRoutes sets the routes advertised to the tailnet.
func SetAdvertiseRoutes(ctx context.Context, run Runner, routes string) error {
	_, err := run(ctx, "tailscale", "set", "--advertise-routes="+routes)
	return err
}

// Up brings tailscaled up with an auth key. The key is passed only to the
// tailscale CLI and is never persisted by Tailrelay.
func Up(ctx context.Context, run Runner, authKey, hostname string) error {
	args := []string{"up", "--authkey=" + authKey}
	if hostname != "" {
		args = append(args, "--hostname="+hostname)
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	_, err := run(c, "tailscale", args...)
	return err
}
