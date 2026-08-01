package transport

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestACMEManagerLoadsCacheAndRestrictsHostname(t *testing.T) {
	now := time.Now().UTC()
	certificateFile, keyFile := writeCertificate(t, "mossward.example.com", now.Add(-time.Hour), now.Add(60*24*time.Hour))
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cacheDirectory := t.TempDir()
	cacheFile := filepath.Join(cacheDirectory, "mossward.example.com+rsa")
	if err := os.WriteFile(cacheFile, append(keyPEM, certificatePEM...), 0o600); err != nil {
		t.Fatal(err)
	}

	events := []CertificateEvent{}
	manager := NewACMEManager(ACMEConfig{Hostname: "mossward.example.com", Email: "admin@example.com",
		CacheDir: cacheDirectory, DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}, func(event CertificateEvent) {
		events = append(events, event)
	})
	t.Cleanup(manager.Close)
	status := manager.Status()
	if status.State != "active" || status.ExpiresAt == nil {
		t.Fatalf("expected active cached certificate, got %#v", status)
	}
	manager.serial = ""
	hello := &tls.ClientHelloInfo{ServerName: "mossward.example.com", SignatureSchemes: []tls.SignatureScheme{tls.PSSWithSHA256}}
	certificate, err := manager.GetCertificate(hello)
	if err != nil || certificate == nil || len(events) != 1 || events[0].Action != "issued" {
		t.Fatalf("expected cached issuance event, certificate=%v events=%#v err=%v", certificate != nil, events, err)
	}
	if _, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "unexpected.example.com"}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected hostname policy rejection, got %v", err)
	}
}

func TestACMECacheUsesOwnerOnlyPermissions(t *testing.T) {
	directory := t.TempDir()
	manager := NewACMEManager(ACMEConfig{Hostname: "mossward.example.com", CacheDir: directory,
		DirectoryURL: "https://acme.invalid/directory"}, nil)
	t.Cleanup(manager.Close)
	if err := manager.manager.Cache.Put(t.Context(), "test", []byte("value")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, "test"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 cache file, got %o", info.Mode().Perm())
	}
}

func TestPrepareACMECacheRejectsExposedFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission validation does not apply on Windows")
	}
	directory := filepath.Join(t.TempDir(), "acme")
	if err := PrepareACMECache(directory); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "account-key")
	if err := os.WriteFile(file, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := PrepareACMECache(directory); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("expected exposed cache rejection, got %v", err)
	}
}
