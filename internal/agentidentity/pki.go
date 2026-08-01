package agentidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	rootLifetime         = 10 * 365 * 24 * time.Hour
	intermediateLifetime = 2 * 365 * 24 * time.Hour
	serverLifetime       = 90 * 24 * time.Hour
	endpointLifetime     = 90 * 24 * time.Hour
	serverRenewBefore    = 30 * 24 * time.Hour
	clockSkewAllowance   = 5 * time.Minute
)

type PKI struct {
	rootCertificate         *x509.Certificate
	intermediateCertificate *x509.Certificate
	intermediateKey         *ecdsa.PrivateKey
	serverCertificate       tls.Certificate
	rootPEM                 []byte
	intermediatePEM         []byte
}

func LoadOrCreatePKI(directory string, serverNames []string, now time.Time) (*PKI, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create agent PKI directory: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, fmt.Errorf("secure agent PKI directory: %w", err)
		}
	}
	rootCertificate, rootKey, rootPEM, err := loadOrCreateCA(directory, "root", nil, nil, now)
	if err != nil {
		return nil, err
	}
	intermediateCertificate, intermediateKey, intermediatePEM, err := loadOrCreateCA(directory, "intermediate", rootCertificate, rootKey, now)
	if err != nil {
		return nil, err
	}
	if err := validateCAHierarchy(rootCertificate, intermediateCertificate, now); err != nil {
		return nil, err
	}
	pki := &PKI{rootCertificate: rootCertificate, rootPEM: rootPEM,
		intermediateCertificate: intermediateCertificate, intermediateKey: intermediateKey, intermediatePEM: intermediatePEM}
	serverCertificate, err := pki.loadOrCreateServerCertificate(directory, serverNames, now)
	if err != nil {
		return nil, err
	}
	pki.serverCertificate = serverCertificate
	return pki, nil
}

func (p *PKI) ServerCertificate() tls.Certificate {
	return p.serverCertificate
}

func (p *PKI) RootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.rootCertificate)
	return pool
}

func (p *PKI) CAChainPEM() string {
	return string(append(append([]byte{}, p.intermediatePEM...), p.rootPEM...))
}

func (p *PKI) IssueEndpoint(id, name string, csrPEM []byte, now time.Time) (string, string, time.Time, error) {
	request, err := parseCSR(csrPEM)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if err := validatePublicKey(request.PublicKey); err != nil {
		return "", "", time.Time{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", time.Time{}, err
	}
	identity, _ := url.Parse("spiffe://mossward/endpoint/" + id)
	expiresAt := minTime(now.Add(endpointLifetime), p.intermediateCertificate.NotAfter)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-clockSkewAllowance), NotAfter: expiresAt, URIs: []*url.URL{identity},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, p.intermediateCertificate, request.PublicKey, p.intermediateKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("issue endpoint certificate: %w", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificatePEM = append(certificatePEM, p.intermediatePEM...)
	return serial.String(), string(certificatePEM), expiresAt, nil
}

func loadOrCreateCA(directory, name string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certificatePath := filepath.Join(directory, name+"-ca.pem")
	keyPath := filepath.Join(directory, name+"-ca-key.pem")
	certificatePEM, certificateErr := os.ReadFile(certificatePath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certificateErr == nil && keyErr == nil {
		if err := validatePrivateFile(keyPath); err != nil {
			return nil, nil, nil, err
		}
		certificate, key, err := parseCA(certificatePEM, keyPEM)
		return certificate, key, certificatePEM, err
	}
	if !errors.Is(certificateErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("agent PKI %s certificate and key must both exist or both be absent", name)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate %s CA key: %w", name, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	lifetime := rootLifetime
	maxPathLen := 1
	commonName := "Mossward Endpoint Root CA"
	if issuer != nil {
		lifetime = intermediateLifetime
		maxPathLen = 0
		commonName = "Mossward Endpoint Issuing CA"
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-clockSkewAllowance), NotAfter: now.Add(lifetime), IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: maxPathLen, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer, issuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create %s CA certificate: %w", name, err)
	}
	certificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode %s CA key: %w", name, err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeExclusive(certificatePath, certificatePEM, 0o644); err != nil {
		return nil, nil, nil, err
	}
	if err := writeExclusive(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, nil, err
	}
	certificate, key, err := parseCA(certificatePEM, keyPEM)
	return certificate, key, certificatePEM, err
}

func parseCA(certificatePEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certificateBlock, _ := pem.Decode(certificatePEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certificateBlock == nil || keyBlock == nil {
		return nil, nil, errors.New("invalid agent CA PEM data")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || !certificate.IsCA {
		return nil, nil, errors.New("invalid agent CA certificate")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse agent CA private key: %w", err)
	}
	key, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(certificate.PublicKey) {
		return nil, nil, errors.New("agent CA certificate and private key do not match")
	}
	return certificate, key, nil
}

func (p *PKI) loadOrCreateServerCertificate(directory string, names []string, now time.Time) (tls.Certificate, error) {
	certificatePath := filepath.Join(directory, "agent-server.pem")
	keyPath := filepath.Join(directory, "agent-server-key.pem")
	if certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath); err == nil {
		if err := validatePrivateFile(keyPath); err != nil {
			return tls.Certificate{}, err
		}
		leaf, parseErr := x509.ParseCertificate(certificate.Certificate[0])
		if parseErr == nil && now.Before(leaf.NotAfter.Add(-serverRenewBefore)) && coversNames(leaf, names) {
			return certificate, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]},
		NotBefore: now.Add(-clockSkewAllowance), NotAfter: minTime(now.Add(serverLifetime), p.intermediateCertificate.NotAfter), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, name := range names {
		if address := net.ParseIP(name); address != nil {
			template.IPAddresses = append(template.IPAddresses, address)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.intermediateCertificate, &key.PublicKey, p.intermediateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), p.intermediatePEM...)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certificatePath, certificatePEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certificatePEM, keyPEM)
}

func validateCAHierarchy(root, intermediate *x509.Certificate, now time.Time) error {
	if now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
		return errors.New("endpoint root CA certificate is not currently valid")
	}
	if now.Before(intermediate.NotBefore) || !now.Before(intermediate.NotAfter) {
		return errors.New("endpoint issuing CA certificate is not currently valid")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("verify endpoint root CA: %w", err)
	}
	if err := intermediate.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("verify endpoint issuing CA: %w", err)
	}
	return nil
}

func validatePrivateFile(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key %q grants group or other access", path)
	}
	return nil
}

func parseCSR(value []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(value)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR must be PEM encoded")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		return nil, errors.New("CSR signature is invalid")
	}
	return request, nil
}

func validatePublicKey(value any) error {
	switch key := value.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() {
			return errors.New("endpoint ECDSA key must use P-256 or P-384")
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return errors.New("endpoint RSA key must be at least 2048 bits")
		}
	default:
		return errors.New("endpoint key type is not supported")
	}
	return nil
}

func coversNames(certificate *x509.Certificate, names []string) bool {
	for _, name := range names {
		if err := certificate.VerifyHostname(name); err != nil {
			return false
		}
	}
	return true
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
