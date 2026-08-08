package agentapp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mossward/internal/model"
)

type enrollmentResult struct {
	Endpoint       model.Endpoint `json:"endpoint"`
	CertificatePEM string         `json:"certificate_pem"`
	CAChainPEM     string         `json:"ca_chain_pem"`
}
type identityRecord struct {
	EndpointID string `json:"endpoint_id"`
	ExpiresAt  string `json:"expires_at"`
}

func Enroll(config Config, token string) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("endpoint-agent enrollment token is required")
	}
	if err := os.MkdirAll(config.StateDirectory, 0o700); err != nil {
		return fmt.Errorf("create endpoint-agent state directory: %w", err)
	}
	privateKey, csrPEM, keyPEM, err := newIdentityMaterial()
	if err != nil {
		return err
	}
	_ = privateKey
	payload, _ := json.Marshal(map[string]string{"token": token, "csr_pem": string(csrPEM)})
	client, err := enrollmentClient(config.EnrollmentCAFile)
	if err != nil {
		return err
	}
	response, err := client.Post(strings.TrimRight(config.ServerURL, "/")+"/api/agent/enroll", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("enroll endpoint agent: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("endpoint-agent enrollment was rejected with status %d", response.StatusCode)
	}
	var result enrollmentResult
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("decode endpoint-agent enrollment: %w", err)
	}
	if _, err := tls.X509KeyPair([]byte(result.CertificatePEM), keyPEM); err != nil {
		return errors.New("endpoint-agent enrollment returned a certificate that does not match the generated key")
	}
	return saveIdentity(config.StateDirectory, keyPEM, []byte(result.CertificatePEM), []byte(result.CAChainPEM), result.Endpoint)
}

func newIdentityMaterial() (*ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Mossward endpoint agent"}}, key)
	if err != nil {
		return nil, nil, nil, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

func enrollmentClient(caFile string) (*http.Client, error) {
	transport := &http.Transport{}
	if caFile != "" {
		roots, err := loadRoots(caFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}, nil
}
func saveIdentity(directory string, key, certificate, ca []byte, endpoint model.Endpoint) error {
	record, _ := json.Marshal(identityRecord{EndpointID: endpoint.ID, ExpiresAt: endpoint.ExpiresAt.UTC().Format(time.RFC3339)})
	for name, data := range map[string][]byte{"agent-key.pem": key, "agent-cert.pem": certificate, "agent-ca.pem": ca, "identity.json": record} {
		if err := writePrivateFile(filepath.Join(directory, name), data); err != nil {
			return err
		}
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(directory, 0o700)
	}
	return nil
}
func writePrivateFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".mossward-agent-")
	if err != nil {
		return fmt.Errorf("create endpoint-agent identity file: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("install endpoint-agent identity file: %w", err)
	}
	return nil
}
