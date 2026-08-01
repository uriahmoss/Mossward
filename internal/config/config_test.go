package config

import (
	"strings"
	"testing"
)

func TestLoadRejectsInvalidCIDR(t *testing.T) {
	t.Setenv("MOSSWARD_ALLOWED_CIDRS", "127.0.0.0/8,not-a-network")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "invalid CIDR") {
		t.Fatalf("expected invalid CIDR error, got %v", err)
	}
}

func TestLoadRejectsEmptyPortAllowlist(t *testing.T) {
	t.Setenv("MOSSWARD_ALLOWED_PORTS", "invalid")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MOSSWARD_ALLOWED_PORTS") {
		t.Fatalf("expected invalid port allowlist error, got %v", err)
	}
}

func TestLoadRejectsInvalidPositiveInteger(t *testing.T) {
	t.Setenv("MOSSWARD_MAX_CONCURRENT", "0")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MOSSWARD_MAX_CONCURRENT") {
		t.Fatalf("expected positive integer error, got %v", err)
	}
}

func TestLoadUsesConfiguredSQLiteAndLegacyPaths(t *testing.T) {
	t.Setenv("MOSSWARD_DATABASE_FILE", "data/test.db")
	t.Setenv("MOSSWARD_DATA_FILE", "data/legacy.json")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseFile != "data/test.db" || cfg.LegacyDataFile != "data/legacy.json" {
		t.Fatalf("unexpected storage paths: %#v", cfg)
	}
}

func TestLoadRejectsInsecureRemoteWebAuthnOrigin(t *testing.T) {
	t.Setenv("MOSSWARD_WEBAUTHN_RP_ID", "mossward.example.com")
	t.Setenv("MOSSWARD_WEBAUTHN_ORIGINS", "http://mossward.example.com")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("expected insecure WebAuthn origin error, got %v", err)
	}
}

func TestLoadRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	t.Setenv("MOSSWARD_TRUSTED_PROXY_CIDRS", "not-a-network")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MOSSWARD_TRUSTED_PROXY_CIDRS") {
		t.Fatalf("expected invalid trusted proxy error, got %v", err)
	}
}

func TestLoadValidatesTransportModes(t *testing.T) {
	tests := []struct {
		name    string
		values  map[string]string
		wantErr string
	}{
		{name: "local rejects public listener", values: map[string]string{"MOSSWARD_LISTEN": "0.0.0.0:8080"}, wantErr: "loopback"},
		{name: "TLS requires certificate files", values: map[string]string{
			"MOSSWARD_TRANSPORT_MODE": "tls", "MOSSWARD_PUBLIC_ORIGIN": "https://mossward.example.com",
			"MOSSWARD_WEBAUTHN_RP_ID": "mossward.example.com", "MOSSWARD_WEBAUTHN_ORIGINS": "https://mossward.example.com",
		}, wantErr: "requires MOSSWARD_TLS_CERT_FILE"},
		{name: "proxy requires trusted proxy", values: map[string]string{
			"MOSSWARD_TRANSPORT_MODE": "proxy", "MOSSWARD_PUBLIC_ORIGIN": "https://mossward.example.com",
			"MOSSWARD_WEBAUTHN_RP_ID": "mossward.example.com", "MOSSWARD_WEBAUTHN_ORIGINS": "https://mossward.example.com",
		}, wantErr: "requires MOSSWARD_TRUSTED_PROXY_CIDRS"},
		{name: "proxy accepts secure configuration", values: map[string]string{
			"MOSSWARD_TRANSPORT_MODE": "proxy", "MOSSWARD_PUBLIC_ORIGIN": "https://mossward.example.com",
			"MOSSWARD_WEBAUTHN_RP_ID": "example.com", "MOSSWARD_WEBAUTHN_ORIGINS": "https://mossward.example.com",
			"MOSSWARD_TRUSTED_PROXY_CIDRS": "10.0.0.10/32",
		}},
		{name: "ACME requires terms acceptance", values: map[string]string{
			"MOSSWARD_TRANSPORT_MODE": "acme", "MOSSWARD_PUBLIC_ORIGIN": "https://mossward.example.com",
			"MOSSWARD_WEBAUTHN_RP_ID": "mossward.example.com", "MOSSWARD_WEBAUTHN_ORIGINS": "https://mossward.example.com",
			"MOSSWARD_ACME_EMAIL": "admin@example.com",
		}, wantErr: "MOSSWARD_ACME_ACCEPT_TOS=true"},
		{name: "ACME accepts public host configuration", values: map[string]string{
			"MOSSWARD_TRANSPORT_MODE": "acme", "MOSSWARD_PUBLIC_ORIGIN": "https://mossward.example.com",
			"MOSSWARD_WEBAUTHN_RP_ID": "example.com", "MOSSWARD_WEBAUTHN_ORIGINS": "https://mossward.example.com",
			"MOSSWARD_ACME_EMAIL": "admin@example.com", "MOSSWARD_ACME_ACCEPT_TOS": "true",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.values {
				t.Setenv(name, value)
			}
			_, err := Load()
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("expected error containing %q, got %v", test.wantErr, err)
			}
		})
	}
}

func TestLoadValidatesAgentListener(t *testing.T) {
	t.Setenv("MOSSWARD_AGENT_LISTEN", ":9443")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MOSSWARD_AGENT_SERVER_NAMES") {
		t.Fatalf("expected missing agent names error, got %v", err)
	}
	t.Setenv("MOSSWARD_AGENT_SERVER_NAMES", "agent.mossward.test,10.0.0.5")
	if _, err := Load(); err != nil {
		t.Fatalf("expected valid agent listener, got %v", err)
	}
}
