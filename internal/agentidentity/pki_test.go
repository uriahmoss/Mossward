package agentidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPKIIssuesBoundEndpointCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	pki, err := LoadOrCreatePKI(directory, []string{"agent.mossward.test", "127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	csr := endpointCSR(t)
	serial, certificatePEM, expiresAt, err := pki.IssueEndpoint("endpoint-1", "Workstation", csr, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf := decodeCertificate(t, []byte(certificatePEM))
	if serial != leaf.SerialNumber.String() || !expiresAt.Equal(leaf.NotAfter) {
		t.Fatalf("unexpected issued identity: %s %s", serial, expiresAt)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://mossward/endpoint/endpoint-1" {
		t.Fatalf("endpoint identity was not constrained: %#v", leaf)
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(pki.intermediateCertificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pki.RootPool(), Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("verify endpoint certificate: %v", err)
	}
	serverLeaf, err := x509.ParseCertificate(pki.serverCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := serverLeaf.VerifyHostname("agent.mossward.test"); err != nil {
		t.Fatalf("server certificate hostname: %v", err)
	}
	for _, name := range []string{"root-ca-key.pem", "intermediate-ca-key.pem", "agent-server-key.pem"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is not owner-only: %o", name, info.Mode().Perm())
		}
	}
}

func endpointCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	maliciousURI, _ := url.Parse("spiffe://attacker/admin")
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored"}, DNSNames: []string{"admin.example.com"}, URIs: []*url.URL{maliciousURI}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func decodeCertificate(t *testing.T, value []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(value)
	if block == nil {
		t.Fatal("certificate PEM missing")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
