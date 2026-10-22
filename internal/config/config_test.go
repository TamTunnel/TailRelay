package config

import "testing"

func TestTLSRequiresBoth(t *testing.T) {
	if _, err := Load([]string{"-bind", "127.0.0.1", "-tls-cert", "c.pem"}, ""); err == nil {
		t.Error("expected error for cert without key")
	}
	if _, err := Load([]string{"-bind", "127.0.0.1", "-tls-key", "k.pem"}, ""); err == nil {
		t.Error("expected error for key without cert")
	}
	c, err := Load([]string{"-bind", "127.0.0.1", "-tls-cert", "c.pem", "-tls-key", "k.pem"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !c.TLSEnabled() {
		t.Error("expected TLS enabled when both cert and key are set")
	}
	c2, err := Load([]string{"-bind", "127.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if c2.TLSEnabled() {
		t.Error("expected TLS disabled when neither is set")
	}
}

func TestIPv6PoolFlagAndEnv(t *testing.T) {
	c, err := Load([]string{"-bind", "127.0.0.1", "-ipv6-pool", "fd00:1234::/64"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.InitialIPv6Pool != "fd00:1234::/64" {
		t.Errorf("flag: got %q", c.InitialIPv6Pool)
	}
	t.Setenv("TR_IPV6_POOL", "fd00:abcd::/48")
	c2, err := Load([]string{"-bind", "127.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if c2.InitialIPv6Pool != "fd00:abcd::/48" {
		t.Errorf("env: got %q", c2.InitialIPv6Pool)
	}
	// Flag wins over env.
	c3, err := Load([]string{"-bind", "127.0.0.1", "-ipv6-pool", "fd00:1::/64"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if c3.InitialIPv6Pool != "fd00:1::/64" {
		t.Errorf("flag-over-env: got %q", c3.InitialIPv6Pool)
	}
	// Unset by default (main.go generates a random ULA then).
	t.Setenv("TR_IPV6_POOL", "")
	c4, err := Load([]string{"-bind", "127.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if c4.InitialIPv6Pool != "" {
		t.Errorf("default: got %q, want empty", c4.InitialIPv6Pool)
	}
}
