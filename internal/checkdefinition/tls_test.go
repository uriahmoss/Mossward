package checkdefinition

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEvaluateTLSReportsConfigurationFailures(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	days := 30
	check := tlsCheck(TLSSpec{MinimumVersion: "TLS1.3", DisallowLegacyProtocols: true,
		DisallowedCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, RequireCurrentCertificate: true,
		RequireHostnameMatch: true, MinimumCertificateDaysLeft: &days, Remediation: "Harden TLS."})
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: "other.internal"}, DNSNames: []string{"other.internal"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(10 * 24 * time.Hour)}
	result, err := EvaluateTLS(check, TLSInput{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		Certificate: certificate, Hostname: "app.internal", LegacyProtocolsAccepted: true, ObservedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"below required", "TLS 1.0", "prohibited", "does not match", "fewer than 30"} {
		if !strings.Contains(result.Evidence, expected) {
			t.Fatalf("evidence %q does not contain %q", result.Evidence, expected)
		}
	}
}

func TestEvaluateTLSPassesCompliantState(t *testing.T) {
	now := time.Now().UTC()
	days := 30
	check := tlsCheck(TLSSpec{MinimumVersion: "TLS1.2", DisallowLegacyProtocols: true, RequireCurrentCertificate: true,
		RequireHostnameMatch: true, MinimumCertificateDaysLeft: &days, Remediation: "Harden TLS."})
	certificate := &x509.Certificate{DNSNames: []string{"app.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}
	result, err := EvaluateTLS(check, TLSInput{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		Certificate: certificate, Hostname: "app.internal", ObservedAt: now})
	if err != nil || !result.Passed {
		t.Fatalf("unexpected TLS result: %#v, %v", result, err)
	}
}

func TestDecodeTLSSpecRejectsInvalidRules(t *testing.T) {
	tests := []string{
		`{"minimum_version":"SSL3","remediation":"Fix it."}`,
		`{"disallowed_cipher_suites":["MADE_UP"],"remediation":"Fix it."}`,
		`{"minimum_certificate_days_left":3651,"remediation":"Fix it."}`,
		`{"require_current_certificate":true,"unknown":true,"remediation":"Fix it."}`,
		`{"remediation":"Fix it."}`,
	}
	for _, spec := range tests {
		check := Check{SchemaVersion: SchemaVersion, ID: "mossward.tls.test", Version: "1.0.0", Kind: "tls",
			Title: "TLS test", Severity: "medium", Spec: json.RawMessage(spec)}
		if _, err := DecodeTLSSpec(check); err == nil {
			t.Fatalf("invalid TLS spec was accepted: %s", spec)
		}
	}
}

func tlsCheck(spec TLSSpec) Check {
	encoded, err := json.Marshal(spec)
	if err != nil {
		panic(err)
	}
	return Check{SchemaVersion: SchemaVersion, ID: "mossward.tls.test", Version: "1.0.0", Kind: "tls",
		Title: "TLS test", Severity: "medium", Spec: encoded}
}
