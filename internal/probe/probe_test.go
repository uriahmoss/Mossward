package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestParseProductVersion(t *testing.T) {
	product, version := parseProductVersion("nginx/1.25.4")
	if product != "nginx" || version != "1.25.4" {
		t.Fatalf("unexpected product/version: %q %q", product, version)
	}
}

func TestParseProductVersionFromGenericBanner(t *testing.T) {
	product, version := parseProductVersion("220 ProFTPD 1.3.8 Server ready")
	if product != "ProFTPD" || version != "1.3.8" {
		t.Fatalf("unexpected generic product/version: %q %q", product, version)
	}
}

func TestParseSSHBanner(t *testing.T) {
	product, version := parseSSHBanner("SSH-2.0-OpenSSH_9.6p1")
	if product != "OpenSSH" || version != "9.6p1" {
		t.Fatalf("unexpected SSH product/version: %q %q", product, version)
	}
}

func TestExtractTitle(t *testing.T) {
	if title := extractTitle(`<html><title class="site"> Mossward &amp; Test </title></html>`); title != "Mossward & Test" {
		t.Fatalf("unexpected title: %q", title)
	}
	if title := extractTitle(`<html><title missing-close</html>`); title != "" {
		t.Fatalf("expected malformed title to be ignored, got %q", title)
	}
}

func TestHTTPFindingsIncludeCleartextAndMissingHeaders(t *testing.T) {
	target := model.Target{Name: "app.internal", Address: "127.0.0.1"}
	findings := httpFindings(target, 80, false, http.StatusOK, http.Header{})
	checks := findingIDs(findings)
	if !checks["http.cleartext"] || !checks["http.missing-security-headers"] {
		t.Fatalf("expected cleartext and header findings, got %v", checks)
	}
}

func TestHTTPFindingsAcceptCompleteSecureHeaders(t *testing.T) {
	target := model.Target{Name: "app.internal", Address: "127.0.0.1"}
	headers := http.Header{
		"Content-Security-Policy":   []string{"default-src 'self'"},
		"X-Content-Type-Options":    []string{"nosniff"},
		"Referrer-Policy":           []string{"no-referrer"},
		"Strict-Transport-Security": []string{"max-age=31536000"},
	}
	if findings := httpFindings(target, 443, true, http.StatusOK, headers); len(findings) != 0 {
		t.Fatalf("expected no header findings, got %#v", findings)
	}
}

func TestEvaluateTLSDetectsExpiredAndHostnameMismatch(t *testing.T) {
	target := model.Target{Name: "app.internal", Address: "127.0.0.1"}
	certificate := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "expired"},
		Issuer:    pkix.Name{CommonName: "test-ca"},
		DNSNames:  []string{"different.internal"},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	}
	state := &tls.ConnectionState{
		Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{certificate},
	}
	metadata := tlsMetadata(state)
	findings := tlsConfigurationFindings(target, 443, state, false)
	if metadata["tls_version"] != "TLS 1.3" {
		t.Fatalf("unexpected TLS metadata: %v", metadata)
	}
	checks := findingIDs(findings)
	if !checks["tls.certificate-expired"] || !checks["tls.hostname-mismatch"] {
		t.Fatalf("expected certificate findings, got %v", checks)
	}
}

func TestExposedServiceFinding(t *testing.T) {
	target := model.Target{Name: "db.internal", Address: "127.0.0.1"}
	findings := exposedServiceFindings(target, 6379, "redis")
	if len(findings) != 1 || findings[0].Severity != "high" || !strings.Contains(findings[0].CheckID, "redis") {
		t.Fatalf("unexpected Redis exposure finding: %#v", findings)
	}
}

func TestScopedInspectionDoesNotExpandBeyondTCPReachability(t *testing.T) {
	inspector := New(100 * time.Millisecond)
	connections := 0
	inspector.dialContext = func(context.Context, string, int) (net.Conn, error) {
		connections++
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	observation, _, reachable := inspector.InspectScoped(context.Background(),
		model.Target{Name: "local", Address: "127.0.0.1"}, 8443, []model.WorkerCapability{model.WorkerCapabilityTCPConnect})
	if !reachable || observation.Confidence != "low" || observation.Product != "" || observation.Version != "" {
		t.Fatalf("TCP-only inspection performed undeclared service identification: %#v", observation)
	}
	if connections != 1 {
		t.Fatalf("TCP-only inspection opened %d connections instead of one reachability check", connections)
	}
}

func findingIDs(findings []model.Finding) map[string]bool {
	result := make(map[string]bool)
	for _, finding := range findings {
		result[finding.CheckID] = true
	}
	return result
}
