package agentapp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mossward/internal/model"
	"mossward/internal/networkpolicy"
)

const maximumConfigBytes = 1 << 20

type Config struct {
	ServerURL              string                           `json:"server_url"`
	EndpointURL            string                           `json:"endpoint_url"`
	EnrollmentCAFile       string                           `json:"enrollment_ca_file,omitempty"`
	StateDirectory         string                           `json:"state_directory"`
	CheckInIntervalSeconds int                              `json:"check_in_interval_seconds"`
	CollectorAllowlist     []CollectorID                    `json:"collector_allowlist,omitempty"`
	NetworkExclusions      model.NetworkTelemetryExclusions `json:"network_telemetry_exclusions,omitempty"`
	UpdateEnabled          bool                             `json:"update_enabled,omitempty"`
	UpdateSigningKeyID     string                           `json:"update_signing_key_id,omitempty"`
	UpdateSigningPublicKey string                           `json:"update_signing_public_key,omitempty"`
	ModulesEnabled         bool                             `json:"modules_enabled,omitempty"`
	ModulePublishers       []ModulePublisherTrust           `json:"module_publishers,omitempty"`
}

type ModulePublisherTrust struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

func LoadConfig(path string) (Config, error) {
	var config Config
	file, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return config, fmt.Errorf("open endpoint-agent configuration: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maximumConfigBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("decode endpoint-agent configuration: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return config, errors.New("endpoint-agent configuration contains trailing data")
	}
	if config.CheckInIntervalSeconds == 0 {
		config.CheckInIntervalSeconds = 60
	}
	return config, config.Validate()
}

func (c Config) Validate() error {
	for label, raw := range map[string]string{"server": c.ServerURL, "endpoint": c.EndpointURL} {
		value, err := url.Parse(raw)
		if err != nil || value.Scheme != "https" || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" || (value.Path != "" && value.Path != "/") {
			return fmt.Errorf("endpoint-agent %s URL must be an HTTPS origin", label)
		}
	}
	if !filepath.IsAbs(c.StateDirectory) {
		return errors.New("endpoint-agent state directory must be absolute")
	}
	if c.EnrollmentCAFile != "" && !filepath.IsAbs(c.EnrollmentCAFile) {
		return errors.New("endpoint-agent enrollment CA path must be absolute")
	}
	if c.CheckInIntervalSeconds < 15 || c.CheckInIntervalSeconds > 86400 {
		return errors.New("endpoint-agent check-in interval must be between 15 and 86400 seconds")
	}
	if err := validateCollectorAllowlist(c.CollectorAllowlist); err != nil {
		return err
	}
	if _, err := networkpolicy.Normalize(c.NetworkExclusions); err != nil {
		return err
	}
	if _, _, err := c.UpdateTrust(); err != nil {
		return err
	}
	if _, err := c.ModuleTrust(); err != nil {
		return err
	}
	return nil
}

func (c Config) CheckInInterval() time.Duration {
	return time.Duration(c.CheckInIntervalSeconds) * time.Second
}

func (c Config) ModuleDirectory() string { return filepath.Join(c.StateDirectory, "modules") }

func (c Config) ModuleTrust() (map[string]ed25519.PublicKey, error) {
	if !c.ModulesEnabled {
		if len(c.ModulePublishers) != 0 {
			return nil, errors.New("endpoint module trust requires modules_enabled")
		}
		return nil, nil
	}
	if len(c.ModulePublishers) == 0 {
		return nil, errors.New("endpoint module publisher trust is required")
	}
	trusted := make(map[string]ed25519.PublicKey, len(c.ModulePublishers))
	for _, publisher := range c.ModulePublishers {
		if strings.TrimSpace(publisher.KeyID) == "" || trusted[publisher.KeyID] != nil {
			return nil, errors.New("endpoint module publisher key ID is invalid or duplicated")
		}
		decoded, err := base64.RawStdEncoding.DecodeString(publisher.PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("endpoint module publisher public key is invalid")
		}
		trusted[publisher.KeyID] = ed25519.PublicKey(decoded)
	}
	return trusted, nil
}

func (c Config) UpdateStateDirectory() string {
	return filepath.Join(c.StateDirectory, "updates")
}

func (c Config) UpdateTrust() (string, ed25519.PublicKey, error) {
	if !c.UpdateEnabled {
		if c.UpdateSigningKeyID != "" || c.UpdateSigningPublicKey != "" {
			return "", nil, errors.New("endpoint-agent update trust requires update_enabled")
		}
		return "", nil, nil
	}
	if strings.TrimSpace(c.UpdateSigningKeyID) == "" {
		return "", nil, errors.New("endpoint-agent update signing key ID is required")
	}
	decoded, err := base64.RawStdEncoding.DecodeString(c.UpdateSigningPublicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return "", nil, errors.New("endpoint-agent update signing public key is invalid")
	}
	return c.UpdateSigningKeyID, ed25519.PublicKey(decoded), nil
}
