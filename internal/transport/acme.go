package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const acmeRenewBefore = 30 * 24 * time.Hour
const acmeExpiryCritical = 7 * 24 * time.Hour
const acmeHealthInterval = 12 * time.Hour

type ACMEConfig struct {
	Hostname     string
	Email        string
	CacheDir     string
	DirectoryURL string
}

type ACMEStatus struct {
	Mode          string     `json:"mode"`
	Hostname      string     `json:"hostname"`
	State         string     `json:"state"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
}

type CertificateEvent struct {
	Action    string
	Hostname  string
	ExpiresAt time.Time
}

type ACMEManager struct {
	manager       *autocert.Manager
	hostname      string
	onCertificate func(CertificateEvent)
	mu            sync.RWMutex
	status        ACMEStatus
	serial        string
	cancel        context.CancelFunc
}

func PrepareACMECache(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create ACME cache: %w", err)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure ACME cache directory: %w", err)
	}
	return filepath.WalkDir(path, func(filePath string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("ACME cache file %q grants group or other access", filePath)
		}
		return nil
	})
}

func NewACMEManager(cfg ACMEConfig, onCertificate func(CertificateEvent)) *ACMEManager {
	cache := autocert.DirCache(cfg.CacheDir)
	ctx, cancel := context.WithCancel(context.Background())
	service := &ACMEManager{hostname: cfg.Hostname, onCertificate: onCertificate, cancel: cancel,
		status: ACMEStatus{Mode: "acme", Hostname: cfg.Hostname, State: "pending"}}
	manager := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       &observingCache{Cache: cache, onCertificate: service.observeCacheWrite},
		HostPolicy:  autocert.HostWhitelist(cfg.Hostname),
		RenewBefore: acmeRenewBefore,
		Email:       cfg.Email,
		Client:      &acme.Client{DirectoryURL: cfg.DirectoryURL},
	}
	service.manager = manager
	service.loadCachedStatus(cache)
	go service.monitor(ctx)
	return service
}

type observingCache struct {
	autocert.Cache
	onCertificate func([]byte)
}

func (c *observingCache) Put(ctx context.Context, key string, data []byte) error {
	if err := c.Cache.Put(ctx, key, data); err != nil {
		return err
	}
	c.onCertificate(data)
	return nil
}

func (m *ACMEManager) TLSConfig() *tls.Config {
	configuration := m.manager.TLSConfig()
	configuration.MinVersion = tls.VersionTLS12
	configuration.GetCertificate = m.GetCertificate
	return configuration
}

func (m *ACMEManager) HTTPHandler() http.Handler {
	return m.manager.HTTPHandler(http.NotFoundHandler())
}

func (m *ACMEManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), m.hostname) {
		return nil, fmt.Errorf("ACME certificate is not configured for %q", hello.ServerName)
	}
	certificate, err := m.manager.GetCertificate(hello)
	checkedAt := time.Now().UTC()
	if err != nil {
		m.setError(checkedAt, err)
		slog.Error("ACME certificate request failed", "hostname", m.hostname, "error", err)
		return nil, err
	}
	m.recordCertificate(certificate, checkedAt)
	return certificate, nil
}

func (m *ACMEManager) Status() ACMEStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := m.status
	if status.ExpiresAt != nil && time.Until(*status.ExpiresAt) <= acmeRenewBefore {
		status.State = "renewal_due"
	}
	return status
}

func (m *ACMEManager) Close() {
	m.cancel()
}

func (m *ACMEManager) setError(checkedAt time.Time, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.State = "error"
	m.status.LastError = err.Error()
	m.status.LastCheckedAt = &checkedAt
}

func (m *ACMEManager) observeCacheWrite(data []byte) {
	certificate, err := parseCachedCertificate(data)
	if err != nil {
		return
	}
	m.recordCertificate(certificate, time.Now().UTC())
}

func (m *ACMEManager) monitor(ctx context.Context) {
	ticker := time.NewTicker(acmeHealthInterval)
	defer ticker.Stop()
	m.logExpiryRisk(time.Now().UTC())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.logExpiryRisk(now.UTC())
		}
	}
}

func (m *ACMEManager) logExpiryRisk(now time.Time) {
	status := m.Status()
	if status.ExpiresAt == nil {
		return
	}
	remaining := status.ExpiresAt.Sub(now)
	if remaining <= acmeExpiryCritical {
		slog.Error("ACME certificate renewal is overdue", "hostname", m.hostname, "expires_at", *status.ExpiresAt)
		return
	}
	if remaining <= acmeRenewBefore {
		slog.Warn("ACME certificate is awaiting renewal", "hostname", m.hostname, "expires_at", *status.ExpiresAt)
	}
}

func (m *ACMEManager) recordCertificate(certificate *tls.Certificate, checkedAt time.Time) {
	leaf, err := certificateLeaf(certificate)
	if err != nil {
		m.setError(checkedAt, err)
		return
	}
	serial := leaf.SerialNumber.String()
	m.mu.Lock()
	previous := m.serial
	m.serial = serial
	expiresAt := leaf.NotAfter.UTC()
	m.status.State = "active"
	m.status.ExpiresAt = &expiresAt
	m.status.LastError = ""
	m.status.LastCheckedAt = &checkedAt
	m.mu.Unlock()
	if serial == previous {
		return
	}
	action := "issued"
	if previous != "" {
		action = "renewed"
	}
	slog.Info("ACME certificate available", "hostname", m.hostname, "action", action, "expires_at", expiresAt)
	if m.onCertificate != nil {
		m.onCertificate(CertificateEvent{Action: action, Hostname: m.hostname, ExpiresAt: expiresAt})
	}
}

func (m *ACMEManager) loadCachedStatus(cache autocert.Cache) {
	var data []byte
	for _, key := range []string{m.hostname, m.hostname + "+rsa"} {
		cached, err := cache.Get(context.Background(), key)
		if err == nil {
			data = cached
			break
		}
	}
	if len(data) == 0 {
		return
	}
	certificate, err := parseCachedCertificate(data)
	if err != nil {
		slog.Warn("Could not inspect cached ACME certificate", "hostname", m.hostname, "error", err)
		return
	}
	leaf, err := certificateLeaf(certificate)
	if err != nil {
		return
	}
	expiresAt := leaf.NotAfter.UTC()
	m.serial = leaf.SerialNumber.String()
	m.status.State = "active"
	m.status.ExpiresAt = &expiresAt
}

func parseCachedCertificate(data []byte) (*tls.Certificate, error) {
	var certificateDER [][]byte
	var privateKey []byte
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type == "CERTIFICATE" {
			certificateDER = append(certificateDER, block.Bytes)
			continue
		}
		if block.Type == "EC PRIVATE KEY" || block.Type == "RSA PRIVATE KEY" || block.Type == "PRIVATE KEY" {
			privateKey = pem.EncodeToMemory(block)
		}
	}
	if len(certificateDER) == 0 || len(privateKey) == 0 {
		return nil, fmt.Errorf("cached ACME data is incomplete")
	}
	certificatePEM := []byte{}
	for _, der := range certificateDER {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKey)
	return &pair, err
}

func certificateLeaf(certificate *tls.Certificate) (*x509.Certificate, error) {
	if certificate == nil || len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("ACME certificate chain is empty")
	}
	return x509.ParseCertificate(certificate.Certificate[0])
}
