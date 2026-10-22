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
