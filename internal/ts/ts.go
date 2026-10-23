// Package ts wraps the `tailscale` CLI: status, exit-node selection,
// advertised routes, and `tailscale up`. In Docker the container runs its
// own tailscaled (same network namespace as WireGuard); the static binary
// install uses the host's. Either way the CLI talks to the default socket,
// so no path configuration is needed.
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
	// ExitNodeName identifies the selected exit node: its tailnet hostname
	// when known, else the stable node ID. "" when no exit node is in use.
	ExitNodeName string
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
		ID       string `json:"ID"`
		Online   bool   `json:"Online"`
		Hostinfo *struct {
			HostName string `json:"HostName"`
		} `json:"Hostinfo"`
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
		if raw.ExitNodeStatus.Hostinfo != nil && raw.ExitNodeStatus.Hostinfo.HostName != "" {
			st.ExitNodeName = raw.ExitNodeStatus.Hostinfo.HostName
		} else {
			st.ExitNodeName = raw.ExitNodeStatus.ID
		}
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

// Version returns the tailscaled version (`tailscale version`), e.g.
// "1.86.5". "" when the CLI is unreachable. Shown in the UI so a stale
// bundled Tailscale is visible.
func Version(ctx context.Context, run Runner) string {
	out, err := run(ctx, "tailscale", "version")
	if err != nil {
		return ""
	}
	// First line is the bare version: "1.86.5\n  tailscale commit: ..."
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// ParseExitNodeList parses `tailscale exit-node list` text output. Two
// formats exist in the wild:
//
//	# IP              HOSTNAME  COUNTRY  CITY       LATITUDE  LONGITUDE  STATUS      (older)
//	100.64.1.2        exit-1    US       New York   40.7      -74.0      online
//
//	 IP               HOSTNAME                              COUNTRY     CITY      STATUS            (newer)
//	 100.100.1.1      us-homerouter.shrimp-penny.ts.net     -           -         -
//	 100.100.10.5     vp-firestick.shrimp-penny.ts.net      -           -         offline, last seen 368d ago
//
// The STATUS column is located via the header's character offset (it is the
// last column, so trailing whitespace is harmless). Status meanings: "-",
// "online" and "selected" are online; anything else (including
// "offline, last seen …") is offline.
func ParseExitNodeList(data []byte) []ExitNode {
	var nodes []ExitNode
	lines := strings.Split(string(data), "\n")
	statusOff, hasLatLong := -1, false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if statusOff < 0 && strings.Contains(t, "STATUS") {
			// Header row (old format starts with "#"): locate STATUS by
			// character offset; note whether LATITUDE/LONGITUDE columns
			// sit between CITY and STATUS.
			statusOff = strings.Index(line, "STATUS")
			hasLatLong = strings.Contains(t, "LATITUDE")
			continue
		}
		if strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 || strings.EqualFold(f[0], "IP") {
			continue
		}
		n := ExitNode{IP: f[0], Hostname: f[1]}
		var status string
		if statusOff >= 0 && statusOff < len(line) {
			status = strings.TrimSpace(line[statusOff:])
		} else {
			status = f[len(f)-1]
		}
		switch sl := strings.ToLower(status); sl {
		case "-", "online", "selected":
			n.Online = true
			n.Selected = sl == "selected"
		}
		// Country/city are the fields between hostname and status
		// (minus lat/long when that format carries them).
		if len(f) >= 3 {
			n.Country = f[2]
			end := len(f) - len(strings.Fields(status))
			if hasLatLong {
				end -= 2
			}
			if end > 3 {
				n.City = strings.Join(f[3:end], " ")
			}
		}
		nodes = append(nodes, n)
	}
	return nodes
}

// ExitNodes lists exit-node candidates. Tries --json first, falls back to
// the classic text table for older tailscale versions. The selected
// argument (hostname or node ID, from Status.ExitNodeName) marks the
// currently selected node — the --json list itself carries no selection
// state, unlike the text table.
func ExitNodes(ctx context.Context, run Runner, selected string) ([]ExitNode, error) {
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
				n.Selected = selected != "" && (n.Hostname == selected || e.ID == selected)
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
