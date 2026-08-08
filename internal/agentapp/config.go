package agentapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maximumConfigBytes = 1 << 20

type Config struct {
	ServerURL              string        `json:"server_url"`
	EndpointURL            string        `json:"endpoint_url"`
	EnrollmentCAFile       string        `json:"enrollment_ca_file,omitempty"`
	StateDirectory         string        `json:"state_directory"`
	CheckInIntervalSeconds int           `json:"check_in_interval_seconds"`
	CollectorAllowlist     []CollectorID `json:"collector_allowlist,omitempty"`
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
	return nil
}

func (c Config) CheckInInterval() time.Duration {
	return time.Duration(c.CheckInIntervalSeconds) * time.Second
}

func (c Config) UpdateStateDirectory() string {
	return filepath.Join(c.StateDirectory, "updates")
}
