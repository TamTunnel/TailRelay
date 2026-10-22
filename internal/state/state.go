// Package state persists Tailrelay's WireGuard server state (keys, clients,
// settings) to a flat JSON file with atomic writes and 0600 permissions.
// The admin password and Tailscale auth keys are never stored here.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Client is a WireGuard peer managed by Tailrelay.
type Client struct {
	Name         string    `json:"name"`
	PrivateKey   string    `json:"private_key"`
	PublicKey    string    `json:"public_key"`
	PresharedKey string    `json:"preshared_key"`
	Address      string    `json:"address"`
	CreatedAt    time.Time `json:"created_at"`
}

// Settings are the tunable WireGuard/Tailscale knobs, editable in the UI.
type Settings struct {
	PoolCIDR         string `json:"pool_cidr"`          // e.g. 10.7.0.0/24
	DNS              string `json:"dns"`                // client DNS, e.g. 1.1.1.1
	MTU              int    `json:"mtu"`                // client + interface MTU
	Keepalive        int    `json:"keepalive"`          // PersistentKeepalive seconds
	ListenPort       int    `json:"listen_port"`        // server UDP port
	Endpoint         string `json:"endpoint"`           // host:port clients connect to
	ClientAllowedIPs string `json:"client_allowed_ips"` // default 0.0.0.0/0 (IPv4-only; server has no IPv6 pool)
	ExitNode         string `json:"exit_node"`          // desired tailscale exit node (hostname), "" = none
	Routes           string `json:"routes"`             // routes to advertise, comma-separated
}

// State is the full persisted document.
type State struct {
	ServerPrivateKey string   `json:"server_private_key"`
	ServerPublicKey  string   `json:"server_public_key"`
	Settings         Settings `json:"settings"`
	Clients          []Client `json:"clients"`
}

// DefaultSettings returns sane first-run settings.
func DefaultSettings() Settings {
	return Settings{
		PoolCIDR:         "10.7.0.0/24",
		DNS:              "1.1.1.1",
		MTU:              1420,
		Keepalive:        25,
		ListenPort:       51820,
		Endpoint:         "",
		ClientAllowedIPs: "0.0.0.0/0",
		ExitNode:         "",
		Routes:           "",
	}
}

// Store is a concurrency-safe JSON file store with atomic writes.
type Store struct {
	mu   sync.Mutex
	path string
}

// NewStore returns a Store for path (parent dir is created on Save).
func NewStore(path string) *Store { return &Store{path: path} }

// Path returns the state file path.
func (s *Store) Path() string { return s.path }

// Load reads and parses the state file.
func (s *Store) Load() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.path, err)
	}
	return &st, nil
}

// Save writes st atomically: temp file + fsync + rename, mode 0600.
func (s *Store) Save(st *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// Update loads, applies fn, and saves atomically.
func (s *Store) Update(fn func(*State) error) error {
	st, err := s.Load()
	if err != nil {
		return err
	}
	if err := fn(st); err != nil {
		return err
	}
	return s.Save(st)
}

// Exists reports whether the state file exists.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}
