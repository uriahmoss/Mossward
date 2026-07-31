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
