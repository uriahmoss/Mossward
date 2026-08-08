package workerapp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mossward/internal/model"
)

const (
	defaultPollInterval = 15 * time.Second
	defaultProbeTimeout = 5 * time.Second
	defaultOutboxItems  = 10000
	defaultOutboxBytes  = 100 << 20
	maximumConfigBytes  = 1 << 20
)

type Config struct {
	ServerURL           string                   `json:"server_url"`
	WorkerID            string                   `json:"worker_id"`
	CertificateFile     string                   `json:"certificate_file"`
	PrivateKeyFile      string                   `json:"private_key_file"`
	CAFile              string                   `json:"ca_file"`
	JobSigningPublicKey string                   `json:"job_signing_public_key"`
	StateDirectory      string                   `json:"state_directory"`
	AllowedCIDRs        []string                 `json:"allowed_cidrs"`
	AllowedPorts        []int                    `json:"allowed_ports"`
	MaxConcurrent       int                      `json:"max_concurrent"`
	RateLimitPerSecond  int                      `json:"rate_limit_per_second"`
	Capabilities        []model.WorkerCapability `json:"capabilities"`
	PollIntervalSeconds int                      `json:"poll_interval_seconds"`
	ProbeTimeoutSeconds int                      `json:"probe_timeout_seconds"`
	OutboxMaximumItems  int                      `json:"outbox_maximum_items"`
	OutboxMaximumBytes  int64                    `json:"outbox_maximum_bytes"`
}

func LoadConfig(path string) (Config, error) {
	var config Config
	file, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return config, fmt.Errorf("open scanner-worker configuration: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maximumConfigBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("decode scanner-worker configuration: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return config, errors.New("scanner-worker configuration contains trailing data")
	}
	config.applyDefaults()
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

func (c *Config) applyDefaults() {
	if c.PollIntervalSeconds == 0 {
		c.PollIntervalSeconds = int(defaultPollInterval / time.Second)
	}
	if c.ProbeTimeoutSeconds == 0 {
		c.ProbeTimeoutSeconds = int(defaultProbeTimeout / time.Second)
	}
	if c.OutboxMaximumItems == 0 {
		c.OutboxMaximumItems = defaultOutboxItems
	}
	if c.OutboxMaximumBytes == 0 {
		c.OutboxMaximumBytes = defaultOutboxBytes
	}
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.ServerURL) == "" || strings.TrimSpace(c.WorkerID) == "" {
		return errors.New("scanner-worker server URL and worker ID are required")
	}
	serverURL, err := url.Parse(strings.TrimSpace(c.ServerURL))
	if err != nil || serverURL.Scheme != "https" || serverURL.Host == "" || serverURL.User != nil ||
		(serverURL.Path != "" && serverURL.Path != "/") || serverURL.RawQuery != "" || serverURL.Fragment != "" {
		return errors.New("scanner-worker server URL must be an HTTPS origin")
	}
	for label, path := range map[string]string{"certificate": c.CertificateFile, "private key": c.PrivateKeyFile,
		"CA": c.CAFile, "state directory": c.StateDirectory} {
		if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
			return fmt.Errorf("scanner-worker %s path must be absolute", label)
		}
	}
	if _, err := c.JobPublicKey(); err != nil {
		return err
	}
	if len(c.AllowedCIDRs) == 0 || len(c.AllowedPorts) == 0 || c.MaxConcurrent < 1 || c.RateLimitPerSecond < 0 || len(c.Capabilities) == 0 {
		return errors.New("scanner-worker scope, concurrency, rate, and capabilities are required")
	}
	for _, raw := range c.AllowedCIDRs {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return fmt.Errorf("scanner-worker allowed CIDR %q is invalid", raw)
		}
	}
	for _, port := range c.AllowedPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("scanner-worker allowed port %d is invalid", port)
		}
	}
	allowedCapabilities := map[model.WorkerCapability]bool{
		model.WorkerCapabilityTCPConnect: true, model.WorkerCapabilityServiceIdentification: true,
		model.WorkerCapabilityHTTP: true, model.WorkerCapabilityTLS: true, model.WorkerCapabilitySSH: true,
	}
	for _, capability := range c.Capabilities {
		if !allowedCapabilities[capability] {
			return fmt.Errorf("scanner-worker capability %q is unsupported", capability)
		}
	}
	if c.PollIntervalSeconds < 1 || c.ProbeTimeoutSeconds < 1 || c.OutboxMaximumItems < 1 || c.OutboxMaximumBytes < 1 {
		return errors.New("scanner-worker timing and outbox limits must be positive")
	}
	return nil
}

func (c Config) JobPublicKey() (ed25519.PublicKey, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(c.JobSigningPublicKey))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("scanner-worker job-signing public key is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func (c Config) PollInterval() time.Duration {
	return time.Duration(c.PollIntervalSeconds) * time.Second
}
func (c Config) ProbeTimeout() time.Duration {
	return time.Duration(c.ProbeTimeoutSeconds) * time.Second
}

func (c Config) Worker() model.ScannerWorker {
	return model.ScannerWorker{ID: c.WorkerID, Status: model.EndpointActive, AllowedCIDRs: c.AllowedCIDRs,
		AllowedPorts: c.AllowedPorts, MaxConcurrent: c.MaxConcurrent, RateLimitPerSecond: c.RateLimitPerSecond,
		Capabilities: c.Capabilities}
}
