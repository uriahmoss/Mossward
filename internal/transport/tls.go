package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"runtime"
	"time"
)

const CertificateExpiryWarning = 30 * 24 * time.Hour

type CertificateStatus struct {
	ExpiresAt time.Time
	Warn      bool
}

func ValidateCertificate(certificateFile, privateKeyFile, hostname string, now time.Time) (CertificateStatus, error) {
	if err := validatePrivateKeyPermissions(privateKeyFile); err != nil {
		return CertificateStatus{}, err
	}
	pair, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return CertificateStatus{}, fmt.Errorf("load TLS certificate and key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return CertificateStatus{}, fmt.Errorf("parse TLS certificate: %w", err)
	}
	if now.Before(leaf.NotBefore) {
		return CertificateStatus{}, fmt.Errorf("TLS certificate is not valid until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return CertificateStatus{}, fmt.Errorf("TLS certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return CertificateStatus{}, fmt.Errorf("TLS certificate does not cover %q: %w", hostname, err)
	}
	return CertificateStatus{ExpiresAt: leaf.NotAfter, Warn: leaf.NotAfter.Sub(now) <= CertificateExpiryWarning}, nil
}

func validatePrivateKeyPermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect TLS private key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("TLS private key permissions must not grant group or other access")
	}
	return nil
}
