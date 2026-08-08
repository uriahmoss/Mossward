package checkdefinition

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const maxTLSCipherRules = 32

var tlsVersions = map[string]uint16{
	"TLS1.0": tls.VersionTLS10,
	"TLS1.1": tls.VersionTLS11,
	"TLS1.2": tls.VersionTLS12,
	"TLS1.3": tls.VersionTLS13,
}

type TLSSpec struct {
	MinimumVersion             string   `json:"minimum_version,omitempty"`
	DisallowLegacyProtocols    bool     `json:"disallow_legacy_protocols,omitempty"`
	DisallowedCipherSuites     []string `json:"disallowed_cipher_suites,omitempty"`
	RequireCurrentCertificate  bool     `json:"require_current_certificate,omitempty"`
	RequireHostnameMatch       bool     `json:"require_hostname_match,omitempty"`
	MinimumCertificateDaysLeft *int     `json:"minimum_certificate_days_left,omitempty"`
	Remediation                string   `json:"remediation"`
}

type TLSInput struct {
	Version                 uint16
	CipherSuite             uint16
	Certificate             *x509.Certificate
	Hostname                string
	LegacyProtocolsAccepted bool
	ObservedAt              time.Time
}

type TLSResult struct {
	Passed      bool
	Evidence    string
	Remediation string
}

func DecodeTLSSpec(check Check) (TLSSpec, error) {
	if err := Validate(check); err != nil {
		return TLSSpec{}, err
	}
	if check.Kind != "tls" {
		return TLSSpec{}, errors.New("declarative check is not a TLS check")
	}
	var spec TLSSpec
	decoder := json.NewDecoder(bytes.NewReader(check.Spec))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return TLSSpec{}, fmt.Errorf("decode TLS check spec: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return TLSSpec{}, err
	}
	if err := validateTLSSpec(spec); err != nil {
		return TLSSpec{}, err
	}
	return spec, nil
}

func EvaluateTLS(check Check, input TLSInput) (TLSResult, error) {
	if err := requireObservational(check); err != nil {
		return TLSResult{}, err
	}
	spec, err := DecodeTLSSpec(check)
	if err != nil {
		return TLSResult{}, err
	}
	failures := tlsFailures(spec, input)
	return TLSResult{Passed: len(failures) == 0, Evidence: strings.Join(failures, "; "), Remediation: spec.Remediation}, nil
}

func validateTLSSpec(spec TLSSpec) error {
	rules := len(spec.DisallowedCipherSuites)
	if spec.MinimumVersion != "" {
		if _, ok := tlsVersions[spec.MinimumVersion]; !ok {
			return errors.New("TLS check minimum version is unsupported")
		}
		rules++
	}
	for _, enabled := range []bool{spec.DisallowLegacyProtocols, spec.RequireCurrentCertificate, spec.RequireHostnameMatch} {
		if enabled {
			rules++
		}
	}
	if spec.MinimumCertificateDaysLeft != nil {
		if *spec.MinimumCertificateDaysLeft < 0 || *spec.MinimumCertificateDaysLeft > 3650 {
			return errors.New("TLS check minimum certificate days must be between 0 and 3650")
		}
		rules++
	}
	if rules == 0 {
		return errors.New("TLS check spec must declare at least one rule")
	}
	if len(spec.DisallowedCipherSuites) > maxTLSCipherRules {
		return fmt.Errorf("TLS check exceeds the %d-cipher limit", maxTLSCipherRules)
	}
	seen := make(map[string]bool)
	for _, cipher := range spec.DisallowedCipherSuites {
		if !strings.HasPrefix(cipher, "TLS_") || cipherSuiteID(cipher) == 0 || seen[cipher] {
			return errors.New("TLS check contains an invalid or duplicate cipher suite")
		}
		seen[cipher] = true
	}
	if strings.TrimSpace(spec.Remediation) == "" {
		return errors.New("TLS check remediation is required")
	}
	return nil
}

func tlsFailures(spec TLSSpec, input TLSInput) []string {
	var failures []string
	if minimum, ok := tlsVersions[spec.MinimumVersion]; ok && input.Version < minimum {
		failures = append(failures, fmt.Sprintf("negotiated %s is below required %s", tlsVersionName(input.Version), spec.MinimumVersion))
	}
	if spec.DisallowLegacyProtocols && input.LegacyProtocolsAccepted {
		failures = append(failures, "the service accepted TLS 1.0 or TLS 1.1")
	}
	for _, cipher := range spec.DisallowedCipherSuites {
		if tls.CipherSuiteName(input.CipherSuite) == cipher {
			failures = append(failures, fmt.Sprintf("negotiated cipher suite %s is prohibited", cipher))
		}
	}
	return append(failures, certificateFailures(spec, input)...)
}

func certificateFailures(spec TLSSpec, input TLSInput) []string {
	if !spec.RequireCurrentCertificate && !spec.RequireHostnameMatch && spec.MinimumCertificateDaysLeft == nil {
		return nil
	}
	if input.Certificate == nil {
		return []string{"the service did not provide a leaf certificate"}
	}
	now := input.ObservedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var failures []string
	if spec.RequireCurrentCertificate && (now.Before(input.Certificate.NotBefore) || now.After(input.Certificate.NotAfter)) {
		failures = append(failures, "the leaf certificate is outside its validity period")
	}
	if spec.RequireHostnameMatch && (input.Hostname == "" || input.Certificate.VerifyHostname(input.Hostname) != nil) {
		failures = append(failures, fmt.Sprintf("the leaf certificate does not match %q", input.Hostname))
	}
	if spec.MinimumCertificateDaysLeft != nil {
		minimum := time.Duration(*spec.MinimumCertificateDaysLeft) * 24 * time.Hour
		if input.Certificate.NotAfter.Sub(now) <= minimum {
			failures = append(failures, fmt.Sprintf("the leaf certificate has fewer than %d days remaining", *spec.MinimumCertificateDaysLeft))
		}
	}
	return failures
}

func cipherSuiteID(name string) uint16 {
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if suite.Name == name {
			return suite.ID
		}
	}
	return 0
}

func tlsVersionName(version uint16) string {
	for name, candidate := range tlsVersions {
		if candidate == version {
			return name
		}
	}
	return fmt.Sprintf("TLS version 0x%04x", version)
}
