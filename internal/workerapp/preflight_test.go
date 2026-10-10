package workerapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestPreflightValidatesIdentityWithoutOpeningState(t *testing.T) {
	directory := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse("spiffe://mossward/scanner-worker/worker-1")
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{ServerURL: "https://offline.invalid", WorkerID: "worker-1", CertificateFile: filepath.Join(directory, "worker.crt"),
		PrivateKeyFile: filepath.Join(directory, "worker.key"), CAFile: filepath.Join(directory, "ca.crt"), StateDirectory: filepath.Join(directory, "state"),
		JobSigningPublicKey: base64.RawStdEncoding.EncodeToString(make([]byte, 32)), AllowedCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []int{443},
		MaxConcurrent: 1, Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}}
	config.applyDefaults()
	for path, contents := range map[string][]byte{config.CertificateFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		config.CAFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), config.PrivateKeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckConfig(config); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("preflight opened state")
	}
	config.WorkerID = "different-worker"
	if err := CheckConfig(config); err == nil {
		t.Fatal("wrong identity accepted")
	}
	config.WorkerID = "worker-1"
	if err := os.WriteFile(config.CAFile, []byte("not a CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckConfig(config); err == nil {
		t.Fatal("untrusted identity accepted")
	}
}
