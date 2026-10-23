package ts

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const sampleStatusJSON = `{
  "BackendState": "Running",
  "Self": {
    "HostName": "vps1",
    "TailscaleIPs": ["100.64.0.5", "fd7a:115c:a1e0::5"]
  },
  "ExitNodeStatus": {"ID": "abc", "Online": true},
  "Peer": {}
}`

func TestParseStatus(t *testing.T) {
	st, err := ParseStatus([]byte(sampleStatusJSON))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Running || st.BackendState != "Running" {
		t.Errorf("running not detected: %+v", st)
	}
	if st.Hostname != "vps1" {
		t.Errorf("hostname = %q", st.Hostname)
	}
	if len(st.IPs) != 2 || st.IPs[0] != "100.64.0.5" {
		t.Errorf("ips = %v", st.IPs)
	}
	if !st.UsingExitNode {
		t.Error("expected UsingExitNode=true")
	}
}

func TestParseStatusNeedsLogin(t *testing.T) {
	st, err := ParseStatus([]byte(`{"BackendState":"NeedsLogin"}`))
	if err != nil {
		t.Fatal(err)
	}
	if st.Running {
		t.Error("should not be running")
	}
}

func TestParseExitNodeList(t *testing.T) {
	out := `# IP              HOSTNAME  COUNTRY  CITY       LATITUDE  LONGITUDE  STATUS
100.64.1.2        exit-1    US       New York   40.7      -74.0      online
100.64.1.3        exit-2    DE       Frankfurt  50.1      8.6        selected
100.64.1.4        exit-3    GB       London     51.5      -0.1       offline
`
	nodes := ParseExitNodeList([]byte(out))
	if len(nodes) != 3 {
		t.Fatalf("got %d nodes, want 3", len(nodes))
	}
	if nodes[0].Hostname != "exit-1" || !nodes[0].Online || nodes[0].Selected {
		t.Errorf("node 0 wrong: %+v", nodes[0])
	}
	if !nodes[1].Selected || !nodes[1].Online {
		t.Errorf("node 1 should be selected+online: %+v", nodes[1])
	}
	if nodes[2].Online || nodes[2].Selected {
		t.Errorf("node 2 should be offline: %+v", nodes[2])
	}
	if nodes[0].Country != "US" || nodes[0].City != "New York" {
		t.Errorf("location parse wrong: %+v", nodes[0])
	}
}

func TestSetExitNodeCommand(t *testing.T) {
	var gotArgs []string
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		gotArgs = append([]string{name}, args...)
		return nil, nil
	}
	if err := SetExitNode(context.Background(), run, "exit-1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"tailscale", "set", "--exit-node=exit-1"}
	if len(gotArgs) != len(want) {
		t.Fatalf("got %v, want %v", gotArgs, want)
	}
	for i := range want {
		if gotArgs[i] != want[i] {
			t.Fatalf("got %v, want %v", gotArgs, want)
		}
	}
	// Clearing passes an empty value (tailscale semantics).
	if err := SetExitNode(context.Background(), run, ""); err != nil {
		t.Fatal(err)
	}
	if gotArgs[2] != "--exit-node=" {
		t.Errorf("clear arg = %q", gotArgs[2])
	}
}

func TestSuggestExitNode(t *testing.T) {
	nodes := []ExitNode{
		{Hostname: "down", Online: false},
		{Hostname: "up", Online: true},
	}
	if got := SuggestExitNode(nodes); got != "up" {
		t.Errorf("got %q, want up", got)
	}
	if got := SuggestExitNode(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestGetStatusError(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("tailscale: command not found")
	}
	if _, err := GetStatus(context.Background(), run); err == nil {
		t.Error("expected error when tailscale CLI fails")
	}
}

func TestVersion(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "tailscale" || len(args) != 1 || args[0] != "version" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return []byte("1.104.2\n  tailscale commit: abc123\n  go version: go1.24.0\n"), nil
	}
	if got := Version(context.Background(), run); got != "1.104.2" {
		t.Errorf("Version() = %q, want %q", got, "1.104.2")
	}
	// Unreachable CLI -> "".
	broken := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("no such file")
	}
	if got := Version(context.Background(), broken); got != "" {
		t.Errorf("Version() on error = %q, want %q", got, "")
	}
}

func TestParseStatusExitNodeName(t *testing.T) {
	st, err := ParseStatus([]byte(`{"BackendState":"Running",
		"ExitNodeStatus":{"ID":"node123","Online":true,"Hostinfo":{"HostName":"exit-1"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if st.ExitNodeName != "exit-1" {
		t.Errorf("ExitNodeName = %q, want exit-1", st.ExitNodeName)
	}
	// No Hostinfo: fall back to the stable node ID.
	st, err = ParseStatus([]byte(`{"BackendState":"Running",
		"ExitNodeStatus":{"ID":"node123","Online":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if st.ExitNodeName != "node123" {
		t.Errorf("ExitNodeName = %q, want node123", st.ExitNodeName)
	}
}

func TestExitNodesSelectedFromJSON(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) == 3 && args[2] == "--json" {
			return []byte(`{"ExitNodes":[
				{"ID":"id1","Hostinfo":{"Hostname":"exit-1"},"Addresses":["100.64.1.2/32"]},
				{"ID":"id2","Hostinfo":{"Hostname":"exit-2"},"Addresses":["100.64.1.3/32"]}
			]}`), nil
		}
		return nil, errors.New("no text fallback in this test")
	}
	nodes, err := ExitNodes(context.Background(), run, "exit-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(nodes))
	}
	if nodes[0].Selected || !nodes[1].Selected {
		t.Errorf("selection wrong: %+v", nodes)
	}
	// Matching by stable ID works too.
	nodes, err = ExitNodes(context.Background(), run, "id1")
	if err != nil {
		t.Fatal(err)
	}
	if !nodes[0].Selected || nodes[1].Selected {
		t.Errorf("ID-based selection wrong: %+v", nodes)
	}
}

func TestParseExitNodeListDashFormat(t *testing.T) {
	// Newer tailscale: no lat/long columns, "-" means online, offline rows
	// carry "offline, last seen …".
	out := ` IP               HOSTNAME                              COUNTRY     CITY      STATUS
 100.100.20.7      home-router.example-net.ts.net     -           -         -
 100.100.20.6     media-player.example-net.ts.net      -           -         offline, last seen 368d ago
 100.100.20.8      vpn-router.example-net.ts.net     -           -         -
`
	nodes := ParseExitNodeList([]byte(out))
	if len(nodes) != 3 {
		t.Fatalf("got %d nodes, want 3", len(nodes))
	}
	if !nodes[0].Online || nodes[0].Selected {
		t.Errorf("node 0 should be online: %+v", nodes[0])
	}
	if !nodes[2].Online {
		t.Errorf("node 2 should be online: %+v", nodes[2])
	}
	if nodes[1].Online || nodes[1].Selected {
		t.Errorf("node 1 should be offline: %+v", nodes[1])
	}
	if nodes[1].City != "-" || nodes[1].Country != "-" {
		t.Errorf("node 1 location should be '- -', got %q %q", nodes[1].Country, nodes[1].City)
	}
	if strings.Contains(nodes[1].City, "offline") {
		t.Errorf("status text leaked into city: %+v", nodes[1])
	}
}
