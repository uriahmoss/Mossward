package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddress      string
	TransportMode      TransportMode
	PublicOrigin       string
	TLSCertificateFile string
	TLSPrivateKeyFile  string
	ACMEEmail          string
	ACMECacheDirectory string
	ACMEDirectoryURL   string
	ACMEHTTPListen     string
	ACMEAcceptTerms    bool
	AgentListen        string
	AgentPKIDirectory  string
	AgentServerNames   []string
	DatabaseFile       string
	LegacyDataFile     string
	IdentityKeyFile    string
	WebAuthnRPID       string
	WebAuthnOrigins    []string
	TrustedProxyCIDRs  []string
	AllowedCIDRs       []string
	AllowedPorts       map[int]bool
	MaxTargets         int
	MaxConcurrent      int
	QueueSize          int
	ConnectTimeout     time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddress:      env("MOSSWARD_LISTEN", "127.0.0.1:8080"),
		TransportMode:      TransportMode(env("MOSSWARD_TRANSPORT_MODE", string(TransportLocal))),
		PublicOrigin:       env("MOSSWARD_PUBLIC_ORIGIN", "http://localhost:8080"),
		TLSCertificateFile: env("MOSSWARD_TLS_CERT_FILE", ""),
		TLSPrivateKeyFile:  env("MOSSWARD_TLS_KEY_FILE", ""),
		ACMEEmail:          env("MOSSWARD_ACME_EMAIL", ""),
		ACMECacheDirectory: env("MOSSWARD_ACME_CACHE_DIR", "data/acme"),
		ACMEDirectoryURL:   env("MOSSWARD_ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"),
		ACMEHTTPListen:     env("MOSSWARD_ACME_HTTP_LISTEN", ":80"),
		AgentListen:        env("MOSSWARD_AGENT_LISTEN", ""),
		AgentPKIDirectory:  env("MOSSWARD_AGENT_PKI_DIR", "data/agent-pki"),
		AgentServerNames:   splitValues(env("MOSSWARD_AGENT_SERVER_NAMES", "")),
		DatabaseFile:       env("MOSSWARD_DATABASE_FILE", "data/mossward.db"),
		LegacyDataFile:     env("MOSSWARD_DATA_FILE", "data/scans.json"),
		IdentityKeyFile:    env("MOSSWARD_IDENTITY_KEY_FILE", "data/identity.key"),
		WebAuthnRPID:       env("MOSSWARD_WEBAUTHN_RP_ID", "localhost"),
		WebAuthnOrigins:    splitValues(env("MOSSWARD_WEBAUTHN_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080")),
		TrustedProxyCIDRs:  splitValues(env("MOSSWARD_TRUSTED_PROXY_CIDRS", "")),
		AllowedCIDRs: strings.Split(env("MOSSWARD_ALLOWED_CIDRS",
			"127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7"), ","),
		MaxTargets:     256,
		MaxConcurrent:  32,
		QueueSize:      16,
		ConnectTimeout: 800 * time.Millisecond,
	}
	var err error
	if cfg.ACMEAcceptTerms, err = envBool("MOSSWARD_ACME_ACCEPT_TOS", false); err != nil {
		return Config{}, err
	}
	if cfg.MaxTargets, err = envPositiveInt("MOSSWARD_MAX_TARGETS", cfg.MaxTargets); err != nil {
		return Config{}, err
	}
	if cfg.MaxConcurrent, err = envPositiveInt("MOSSWARD_MAX_CONCURRENT", cfg.MaxConcurrent); err != nil {
		return Config{}, err
	}
	if cfg.QueueSize, err = envPositiveInt("MOSSWARD_QUEUE_SIZE", cfg.QueueSize); err != nil {
		return Config{}, err
	}
	timeoutMS, err := envPositiveInt("MOSSWARD_CONNECT_TIMEOUT_MS", int(cfg.ConnectTimeout/time.Millisecond))
	if err != nil {
		return Config{}, err
	}
	cfg.ConnectTimeout = time.Duration(timeoutMS) * time.Millisecond
	cfg.AllowedPorts = parsePorts(env("MOSSWARD_ALLOWED_PORTS", "22,80,443,445,3389,5432,6379,8080,8443"))
	if len(cfg.AllowedPorts) == 0 {
		return Config{}, fmt.Errorf("MOSSWARD_ALLOWED_PORTS must contain at least one valid port")
	}
	for _, raw := range cfg.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(raw)); err != nil {
			return Config{}, fmt.Errorf("invalid CIDR %q in MOSSWARD_ALLOWED_CIDRS: %w", raw, err)
		}
	}
	for _, raw := range cfg.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(raw); err != nil {
			return Config{}, fmt.Errorf("invalid CIDR %q in MOSSWARD_TRUSTED_PROXY_CIDRS: %w", raw, err)
		}
	}
	if err := validateWebAuthn(cfg.WebAuthnRPID, cfg.WebAuthnOrigins); err != nil {
		return Config{}, err
	}
	if err := validateTransport(cfg); err != nil {
		return Config{}, err
	}
	if err := validateAgentListener(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func splitValues(raw string) []string {
	values := []string{}
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func validateWebAuthn(rpID string, origins []string) error {
	if strings.TrimSpace(rpID) == "" || len(origins) == 0 {
		return fmt.Errorf("WebAuthn RP ID and origins are required")
	}
	for _, origin := range origins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("invalid WebAuthn origin %q", origin)
		}
		hostIP := net.ParseIP(parsed.Hostname())
		loopback := parsed.Hostname() == "localhost" || (hostIP != nil && hostIP.IsLoopback())
		if parsed.Scheme != "https" && !loopback {
			return fmt.Errorf("WebAuthn origin %q must use HTTPS outside localhost", origin)
		}
	}
	return nil
}

func envPositiveInt(name string, fallback int) (int, error) {
	raw := env(name, strconv.Itoa(fallback))
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func envBool(name string, fallback bool) (bool, error) {
	raw := env(name, strconv.FormatBool(fallback))
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return value, nil
}

func parsePorts(raw string) map[int]bool {
	ports := make(map[int]bool)
	for _, item := range strings.Split(raw, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(item))
		if err == nil && port > 0 && port <= 65535 {
			ports[port] = true
		}
	}
	return ports
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
