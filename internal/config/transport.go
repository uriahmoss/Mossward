package config

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"
)

type TransportMode string

const (
	TransportLocal TransportMode = "local"
	TransportTLS   TransportMode = "tls"
	TransportACME  TransportMode = "acme"
	TransportProxy TransportMode = "proxy"
)

func validateTransport(cfg Config) error {
	origin, err := parseOrigin(cfg.PublicOrigin)
	if err != nil {
		return err
	}
	if cfg.TransportMode != TransportLocal {
		if err := validateHostedIdentity(cfg, origin); err != nil {
			return err
		}
	}
	switch cfg.TransportMode {
	case TransportLocal:
		return validateLocalTransport(cfg, origin)
	case TransportTLS:
		return validateTLSTransport(cfg, origin)
	case TransportACME:
		return validateACMETransport(cfg, origin)
	case TransportProxy:
		return validateProxyTransport(cfg, origin)
	default:
		return fmt.Errorf("MOSSWARD_TRANSPORT_MODE must be local, tls, acme, or proxy")
	}
}

func validateACMETransport(cfg Config, origin *url.URL) error {
	if origin.Scheme != "https" {
		return fmt.Errorf("acme transport mode requires an HTTPS MOSSWARD_PUBLIC_ORIGIN")
	}
	if net.ParseIP(origin.Hostname()) != nil || isLoopbackHost(origin.Hostname()) {
		return fmt.Errorf("acme transport mode requires a public DNS hostname")
	}
	if strings.TrimSpace(cfg.ACMEEmail) == "" {
		return fmt.Errorf("acme transport mode requires MOSSWARD_ACME_EMAIL")
	}
	address, err := mail.ParseAddress(cfg.ACMEEmail)
	if err != nil || address.Address != cfg.ACMEEmail {
		return fmt.Errorf("MOSSWARD_ACME_EMAIL must be a valid email address")
	}
	directory, err := url.Parse(cfg.ACMEDirectoryURL)
	if err != nil || directory.Scheme != "https" || directory.Host == "" {
		return fmt.Errorf("MOSSWARD_ACME_DIRECTORY_URL must be a valid HTTPS URL")
	}
	if strings.TrimSpace(cfg.ACMECacheDirectory) == "" {
		return fmt.Errorf("acme transport mode requires MOSSWARD_ACME_CACHE_DIR")
	}
	if _, _, err := net.SplitHostPort(cfg.ACMEHTTPListen); err != nil {
		return fmt.Errorf("MOSSWARD_ACME_HTTP_LISTEN must include a host and port: %w", err)
	}
	if !cfg.ACMEAcceptTerms {
		return fmt.Errorf("acme transport mode requires explicit MOSSWARD_ACME_ACCEPT_TOS=true")
	}
	if cfg.TLSCertificateFile != "" || cfg.TLSPrivateKeyFile != "" {
		return fmt.Errorf("manual TLS certificate files are not used in acme transport mode")
	}
	return nil
}

func validateHostedIdentity(cfg Config, origin *url.URL) error {
	host := strings.ToLower(origin.Hostname())
	rpID := strings.ToLower(strings.TrimSpace(cfg.WebAuthnRPID))
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return fmt.Errorf("MOSSWARD_WEBAUTHN_RP_ID must match the public origin host or its parent domain")
	}
	wanted := strings.TrimSuffix(cfg.PublicOrigin, "/")
	for _, configured := range cfg.WebAuthnOrigins {
		if strings.TrimSuffix(configured, "/") == wanted {
			return nil
		}
	}
	return fmt.Errorf("MOSSWARD_WEBAUTHN_ORIGINS must include MOSSWARD_PUBLIC_ORIGIN")
}

func parseOrigin(raw string) (*url.URL, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, fmt.Errorf("MOSSWARD_PUBLIC_ORIGIN must be an HTTP or HTTPS origin without a path, query, or fragment")
	}
	if origin.Scheme != "http" && origin.Scheme != "https" {
		return nil, fmt.Errorf("MOSSWARD_PUBLIC_ORIGIN must use HTTP or HTTPS")
	}
	return origin, nil
}

func validateLocalTransport(cfg Config, origin *url.URL) error {
	host, _, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("MOSSWARD_LISTEN must include a host and port: %w", err)
	}
	address := net.ParseIP(strings.Trim(host, "[]"))
	if host != "localhost" && (address == nil || !address.IsLoopback()) {
		return fmt.Errorf("local transport mode requires a loopback MOSSWARD_LISTEN address")
	}
	if origin.Scheme != "http" || !isLoopbackHost(origin.Hostname()) {
		return fmt.Errorf("local transport mode requires a loopback HTTP MOSSWARD_PUBLIC_ORIGIN")
	}
	if cfg.TLSCertificateFile != "" || cfg.TLSPrivateKeyFile != "" {
		return fmt.Errorf("TLS certificate files are not used in local transport mode")
	}
	return nil
}

func validateTLSTransport(cfg Config, origin *url.URL) error {
	if origin.Scheme != "https" {
		return fmt.Errorf("tls transport mode requires an HTTPS MOSSWARD_PUBLIC_ORIGIN")
	}
	if cfg.TLSCertificateFile == "" || cfg.TLSPrivateKeyFile == "" {
		return fmt.Errorf("tls transport mode requires MOSSWARD_TLS_CERT_FILE and MOSSWARD_TLS_KEY_FILE")
	}
	return nil
}

func validateProxyTransport(cfg Config, origin *url.URL) error {
	if origin.Scheme != "https" {
		return fmt.Errorf("proxy transport mode requires an HTTPS MOSSWARD_PUBLIC_ORIGIN")
	}
	if len(cfg.TrustedProxyCIDRs) == 0 {
		return fmt.Errorf("proxy transport mode requires MOSSWARD_TRUSTED_PROXY_CIDRS")
	}
	if cfg.TLSCertificateFile != "" || cfg.TLSPrivateKeyFile != "" {
		return fmt.Errorf("TLS certificate files are not used in proxy transport mode")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func validateAgentListener(cfg Config) error {
	if cfg.AgentListen == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(cfg.AgentListen); err != nil {
		return fmt.Errorf("MOSSWARD_AGENT_LISTEN must include a host and port: %w", err)
	}
	if strings.TrimSpace(cfg.AgentPKIDirectory) == "" {
		return fmt.Errorf("MOSSWARD_AGENT_PKI_DIR is required when the agent listener is enabled")
	}
	if len(cfg.AgentServerNames) == 0 {
		return fmt.Errorf("MOSSWARD_AGENT_SERVER_NAMES is required when the agent listener is enabled")
	}
	for _, name := range cfg.AgentServerNames {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "/: ") {
			return fmt.Errorf("invalid agent server name %q", name)
		}
	}
	return nil
}
