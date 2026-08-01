package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	certificateFile, keyFile := writeCertificate(t, "mossward.example.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	status, err := ValidateCertificate(certificateFile, keyFile, "mossward.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Warn {
		t.Fatal("expected near-expiration warning")
	}
	if _, err := ValidateCertificate(certificateFile, keyFile, "other.example.com", now); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("expected hostname error, got %v", err)
	}
}

func TestValidateCertificateRejectsExpiredCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	certificateFile, keyFile := writeCertificate(t, "mossward.example.com", now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := ValidateCertificate(certificateFile, keyFile, "mossward.example.com", now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiration error, got %v", err)
	}
}

func writeCertificate(t *testing.T, hostname string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "certificate.pem")
	keyFile := filepath.Join(directory, "private-key.pem")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFile, keyFile
}
