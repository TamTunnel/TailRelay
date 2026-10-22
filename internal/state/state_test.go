package state

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "state.json")
	s := NewStore(path)
	st := &State{
		ServerPrivateKey: "priv",
		ServerPublicKey:  "pub",
		Settings:         DefaultSettings(),
		Clients: []Client{{
			Name: "laptop", PrivateKey: "a", PublicKey: "b",
			PresharedKey: "c", Address: "10.7.0.2",
			CreatedAt: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC),
		}},
	}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	// Permissions must be 0600: the file holds private keys.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state file perms = %o, want 600", fi.Mode().Perm())
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerPublicKey != "pub" || len(got.Clients) != 1 || got.Clients[0].Name != "laptop" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if !got.Clients[0].CreatedAt.Equal(st.Clients[0].CreatedAt) {
		t.Errorf("timestamp mismatch: %v vs %v", got.Clients[0].CreatedAt, st.Clients[0].CreatedAt)
	}
	if got.Settings.PoolCIDR != "10.7.0.0/24" || got.Settings.MTU != 1420 {
		t.Errorf("settings defaults changed: %+v", got.Settings)
	}
}

func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewStore(path)
	st := &State{ServerPrivateKey: "priv", Settings: DefaultSettings()}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	// No temp files may be left behind after a successful save.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Errorf("expected only state.json, found: %v", entries)
	}
}

func TestUpdate(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "state.json"))
	if err := s.Save(&State{Settings: DefaultSettings()}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error {
		st.Settings.DNS = "9.9.9.9"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Load()
	if got.Settings.DNS != "9.9.9.9" {
		t.Errorf("update did not persist: %q", got.Settings.DNS)
	}
}

func TestLoadMissing(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "nope.json"))
	if _, err := s.Load(); err == nil {
		t.Error("expected error loading missing file")
	}
	if s.Exists() {
		t.Error("Exists() should be false for missing file")
	}
}

func TestDefaultSettingsIPv4Only(t *testing.T) {
	if got := DefaultSettings().ClientAllowedIPs; got != "0.0.0.0/0" {
		t.Errorf("default ClientAllowedIPs = %q, want 0.0.0.0/0 (server is IPv4-only)", got)
	}
}

func TestRandomULAPool(t *testing.T) {
	a, err := RandomULAPool()
	if err != nil {
		t.Fatal(err)
	}
	ip, ipnet, err := net.ParseCIDR(a)
	if err != nil {
		t.Fatalf("not a valid CIDR: %q", a)
	}
	if ones, _ := ipnet.Mask.Size(); ones != 64 {
		t.Errorf("mask = /%d, want /64", ones)
	}
	if ip[0] != 0xfd {
		t.Errorf("first byte = %#02x, want 0xfd (ULA)", ip[0])
	}
	// Global ID must be 40 random bits: two pools must differ.
	b, err := RandomULAPool()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two generated ULA pools are identical")
	}
	// Must be a ULA, not overlapping anything routable.
	if !strings.HasPrefix(a, "fd") {
		t.Errorf("pool %q does not look like a ULA", a)
	}
}

func TestValidIPv6Pool(t *testing.T) {
	for _, ok := range []string{"", "fd12:3456:789a::/64", "fd00::/48", "2001:db8::/32"} {
		if !ValidIPv6Pool(ok) {
			t.Errorf("ValidIPv6Pool(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"10.7.0.0/24", "not-a-cidr", "fd12::/64\n", "fd12:3456:789a::2/128\nInjected"} {
		if ValidIPv6Pool(bad) {
			t.Errorf("ValidIPv6Pool(%q) = true, want false", bad)
		}
	}
}
