package probe

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"mossward/internal/model"
)

const (
	maxBannerBytes           = 512
	maxHTTPBytes             = 64 << 10
	bannerTimeout            = 500 * time.Millisecond
	certificateExpiryWarning = 30 * 24 * time.Hour
)

var serviceNames = map[int]string{
	22: "ssh", 80: "http", 443: "https", 445: "smb", 3389: "rdp",
	5432: "postgresql", 6379: "redis", 8080: "http", 8443: "https",
}

var versionPattern = regexp.MustCompile(`(?i)([A-Za-z][A-Za-z0-9._-]*)[/ ]([0-9][0-9A-Za-z._-]*)`)

type Inspector struct {
	timeout time.Duration
}

func New(timeout time.Duration) *Inspector {
	return &Inspector{timeout: timeout}
}

func (i *Inspector) Inspect(ctx context.Context, target model.Target, port int) (model.ServiceObservation, []model.Finding, bool) {
	if !i.reachable(ctx, target.Address, port) {
		return model.ServiceObservation{}, nil, false
	}

	observation := model.ServiceObservation{
		ID:         id(),
		Target:     target.Name,
		Address:    target.Address,
		Port:       port,
		Protocol:   serviceName(port),
		Confidence: "low",
		Evidence:   "A TCP connection completed successfully to the approved IP address.",
		ObservedAt: time.Now().UTC(),
	}
	findings := exposedServiceFindings(target, port, observation.Protocol)

	switch port {
	case 80, 8080:
		observation, findings = i.inspectProtocols(ctx, target, port, observation, findings, false)
	case 443, 8443:
		observation, findings = i.inspectProtocols(ctx, target, port, observation, findings, true)
	case 22:
		observation, findings = i.inspectSSH(ctx, target, port, observation, findings)
	default:
		observation, findings = i.inspectUnknown(ctx, target, port, observation, findings)
	}
	return observation, findings, true
}

func (i *Inspector) inspectProtocols(ctx context.Context, target model.Target, port int, fallback model.ServiceObservation, findings []model.Finding, secure bool) (model.ServiceObservation, []model.Finding) {
	if observation, checks, ok := i.inspectHTTP(ctx, target, port, secure); ok {
		return observation, append(findings, checks...)
	}
	if observation, checks, ok := i.inspectTLS(ctx, target, port); ok {
		return observation, append(findings, checks...)
	}
	return fallback, findings
}

func (i *Inspector) inspectSSH(ctx context.Context, target model.Target, port int, observation model.ServiceObservation, findings []model.Finding) (model.ServiceObservation, []model.Finding) {
	banner := i.readBanner(ctx, target.Address, port)
	if banner == "" {
		return observation, findings
	}
	observation.Protocol = "ssh"
	observation.Confidence = "high"
	observation.Evidence = banner
	observation.Product, observation.Version = parseSSHBanner(banner)
	return observation, appendDisclosureFinding(findings, observation, target, banner)
}

func (i *Inspector) inspectUnknown(ctx context.Context, target model.Target, port int, observation model.ServiceObservation, findings []model.Finding) (model.ServiceObservation, []model.Finding) {
	banner := i.readBanner(ctx, target.Address, port)
	if banner != "" {
		observation = observationFromBanner(observation, banner)
		return observation, appendDisclosureFinding(findings, observation, target, banner)
	}
	if detected, checks, ok := i.inspectTLS(ctx, target, port); ok {
		return detected, append(findings, checks...)
	}
	if detected, checks, ok := i.inspectHTTP(ctx, target, port, false); ok {
		return detected, append(findings, checks...)
	}
	return observation, findings
}

func observationFromBanner(observation model.ServiceObservation, banner string) model.ServiceObservation {
	observation.Evidence = banner
	observation.Confidence = "medium"
	if strings.HasPrefix(strings.ToUpper(banner), "SSH-") {
		observation.Protocol = "ssh"
		observation.Product, observation.Version = parseSSHBanner(banner)
		return observation
	}
	observation.Product, observation.Version = parseProductVersion(banner)
	return observation
}

func appendDisclosureFinding(findings []model.Finding, observation model.ServiceObservation, target model.Target, banner string) []model.Finding {
	if observation.Version == "" {
		return findings
	}
	return append(findings, disclosureFinding(target, observation.Port, observation.Protocol, banner))
}

func (i *Inspector) reachable(ctx context.Context, address string, port int) bool {
	conn, err := i.dial(ctx, address, port)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (i *Inspector) inspectHTTP(ctx context.Context, target model.Target, port int, secure bool) (model.ServiceObservation, []model.Finding, bool) {
	scheme := "http"
	if secure {
		scheme = "https"
	}
	host := requestHost(target)
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			return i.dial(dialCtx, target.Address, port)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Verification is performed explicitly and reported as findings.
			ServerName:         tlsServerName(target),
			MinVersion:         tls.VersionTLS10,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   i.timeout * 3,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return model.ServiceObservation{}, nil, false
	}
	request.Host = net.JoinHostPort(host, strconv.Itoa(port))
	request.Header.Set("User-Agent", "Mossward/0.1 authorized-security-scan")
	response, err := client.Do(request)
	if err != nil {
		return model.ServiceObservation{}, nil, false
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, maxHTTPBytes))

	metadata := map[string]string{
		"status": strconv.Itoa(response.StatusCode),
	}
	if title := extractTitle(string(body)); title != "" {
		metadata["title"] = title
	}
	if server := cleanEvidence(response.Header.Get("Server")); server != "" {
		metadata["server"] = server
	}
	selectedHeaders := map[string]string{
		"content_type":              response.Header.Get("Content-Type"),
		"content_security_policy":   response.Header.Get("Content-Security-Policy"),
		"strict_transport_security": response.Header.Get("Strict-Transport-Security"),
		"x_content_type_options":    response.Header.Get("X-Content-Type-Options"),
		"referrer_policy":           response.Header.Get("Referrer-Policy"),
	}
	for key, value := range selectedHeaders {
		if value = cleanEvidence(value); value != "" {
			metadata[key] = value
		}
	}

	observation := model.ServiceObservation{
		ID:         id(),
		Target:     target.Name,
		Address:    target.Address,
		Port:       port,
		Protocol:   scheme,
		Product:    "HTTP server",
		Confidence: "high",
		Evidence:   fmt.Sprintf("%s returned HTTP %d.", strings.ToUpper(scheme), response.StatusCode),
		Metadata:   metadata,
		ObservedAt: time.Now().UTC(),
	}
	if product, version := parseProductVersion(response.Header.Get("Server")); product != "" {
		observation.Product = product
		observation.Version = version
	}

	findings := httpFindings(target, port, secure, response.Header)
	if observation.Version != "" {
		findings = append(findings, disclosureFinding(target, port, scheme, response.Header.Get("Server")))
	}
	if secure && response.TLS != nil {
		tlsMetadata, tlsFindings := evaluateTLS(target, port, response.TLS)
		for key, value := range tlsMetadata {
			observation.Metadata[key] = value
		}
		findings = append(findings, tlsFindings...)
		if i.supportsLegacyTLS(ctx, target, port) {
			findings = append(findings, newFinding(
				"tls.legacy-protocol", target, port, "tls", "high",
				"Legacy TLS protocol accepted",
				"The service completed a TLS 1.0 or TLS 1.1 handshake.",
				"Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer.",
			))
		}
	}
	return observation, findings, true
}

func (i *Inspector) inspectTLS(ctx context.Context, target model.Target, port int) (model.ServiceObservation, []model.Finding, bool) {
	state, err := i.tlsState(ctx, target, port, tls.VersionTLS10, 0)
	if err != nil {
		return model.ServiceObservation{}, nil, false
	}
	metadata, findings := evaluateTLS(target, port, state)
	observation := model.ServiceObservation{
		ID:         id(),
		Target:     target.Name,
		Address:    target.Address,
		Port:       port,
		Protocol:   "tls",
		Product:    "TLS service",
		Confidence: "high",
		Evidence:   "The service completed a TLS handshake.",
		Metadata:   metadata,
		ObservedAt: time.Now().UTC(),
	}
	if i.supportsLegacyTLS(ctx, target, port) {
		findings = append(findings, newFinding(
			"tls.legacy-protocol", target, port, "tls", "high",
			"Legacy TLS protocol accepted",
			"The service completed a TLS 1.0 or TLS 1.1 handshake.",
			"Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer.",
		))
	}
	return observation, findings, true
}

func (i *Inspector) tlsState(ctx context.Context, target model.Target, port int, minVersion, maxVersion uint16) (*tls.ConnectionState, error) {
	raw, err := i.dial(ctx, target.Address, port)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         tlsServerName(target),
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
	}
	conn := tls.Client(raw, config)
	defer conn.Close()
	handshakeCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	return &state, nil
}

func (i *Inspector) supportsLegacyTLS(ctx context.Context, target model.Target, port int) bool {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if _, err := i.tlsState(ctx, target, port, version, version); err == nil {
			return true
		}
	}
	return false
}

func (i *Inspector) readBanner(ctx context.Context, address string, port int) string {
	conn, err := i.dial(ctx, address, port)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(min(i.timeout, bannerTimeout)))
	reader := bufio.NewReader(io.LimitReader(conn, maxBannerBytes))
	banner, err := reader.ReadString('\n')
	if banner == "" && err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	return cleanEvidence(banner)
}

func (i *Inspector) dial(ctx context.Context, address string, port int) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	dialer := net.Dialer{}
	return dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
}

func httpFindings(target model.Target, port int, secure bool, headers http.Header) []model.Finding {
	var findings []model.Finding
	if !secure {
		findings = append(findings, newFinding(
			"http.cleartext", target, port, "http", "medium",
			"HTTP service is not encrypted",
			"The service responded over cleartext HTTP.",
			"Redirect HTTP to HTTPS and protect the service with a valid TLS certificate.",
		))
	}

	required := []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"}
	if secure {
		required = append(required, "Strict-Transport-Security")
	}
	var missing []string
	for _, header := range required {
		if strings.TrimSpace(headers.Get(header)) == "" {
			missing = append(missing, header)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		findings = append(findings, newFinding(
			"http.missing-security-headers", target, port, protocolName(secure), "low",
			"HTTP security headers are missing",
			"Missing response headers: "+strings.Join(missing, ", ")+".",
			"Configure the application or reverse proxy to return the missing security headers with values appropriate for the application.",
		))
	}
	return findings
}

func evaluateTLS(target model.Target, port int, state *tls.ConnectionState) (map[string]string, []model.Finding) {
	metadata := map[string]string{
		"tls_version":  tlsVersionName(state.Version),
		"cipher_suite": tls.CipherSuiteName(state.CipherSuite),
	}
	if len(state.PeerCertificates) == 0 {
		return metadata, nil
	}
	certificate := state.PeerCertificates[0]
	metadata["certificate_subject"] = certificate.Subject.String()
	metadata["certificate_issuer"] = certificate.Issuer.String()
	metadata["certificate_not_before"] = certificate.NotBefore.UTC().Format(time.RFC3339)
	metadata["certificate_not_after"] = certificate.NotAfter.UTC().Format(time.RFC3339)
	metadata["certificate_dns_names"] = strings.Join(certificate.DNSNames, ", ")

	now := time.Now()
	var findings []model.Finding
	if now.After(certificate.NotAfter) {
		findings = append(findings, newFinding(
			"tls.certificate-expired", target, port, "tls", "high",
			"TLS certificate has expired",
			fmt.Sprintf("The leaf certificate expired at %s.", certificate.NotAfter.UTC().Format(time.RFC3339)),
			"Replace the certificate with a valid certificate and verify automated renewal.",
		))
	} else if certificate.NotAfter.Sub(now) <= certificateExpiryWarning {
		findings = append(findings, newFinding(
			"tls.certificate-expiring", target, port, "tls", "medium",
			"TLS certificate expires soon",
			fmt.Sprintf("The leaf certificate expires at %s.", certificate.NotAfter.UTC().Format(time.RFC3339)),
			"Renew or replace the certificate before expiration and verify automated renewal.",
		))
	}
	verifyName := verificationName(target)
	if verifyName != "" {
		if err := certificate.VerifyHostname(verifyName); err != nil {
			findings = append(findings, newFinding(
				"tls.hostname-mismatch", target, port, "tls", "medium",
				"TLS certificate does not match the target",
				fmt.Sprintf("Certificate identity validation for %q failed: %s.", verifyName, cleanEvidence(err.Error())),
				"Install a certificate whose subject alternative names include the service hostname or IP address.",
			))
		}
	}
	return metadata, findings
}

func exposedServiceFindings(target model.Target, port int, service string) []model.Finding {
	type exposure struct {
		severity string
		title    string
	}
	exposures := map[int]exposure{
		22:   {"low", "SSH administrative service is reachable"},
		445:  {"medium", "SMB service is reachable"},
		3389: {"medium", "Remote Desktop service is reachable"},
		5432: {"medium", "PostgreSQL service is reachable"},
		6379: {"high", "Redis service is reachable"},
	}
	item, ok := exposures[port]
	if !ok {
		return nil
	}
	return []model.Finding{newFinding(
		"service.exposed."+service, target, port, service, item.severity,
		item.title,
		fmt.Sprintf("A TCP connection to %s:%d completed successfully.", target.Address, port),
		"Confirm the service is required and restrict access to explicitly authorized administration or application networks.",
	)}
}

func disclosureFinding(target model.Target, port int, service, evidence string) model.Finding {
	return newFinding(
		"service.version-disclosure", target, port, service, "low",
		"Service version information is disclosed",
		"The service disclosed: "+cleanEvidence(evidence)+".",
		"Suppress detailed product versions in public banners where operationally practical, and keep the service fully patched.",
	)
}

func newFinding(checkID string, target model.Target, port int, service, severity, title, evidence, remediation string) model.Finding {
	return model.Finding{
		ID: id(), CheckID: checkID, Target: target.Name, Address: target.Address,
		Port: port, Service: service, Severity: severity, Title: title,
		Evidence: evidence, Remediation: remediation, ObservedAt: time.Now().UTC(),
	}
}

func parseProductVersion(value string) (string, string) {
	match := versionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(match) != 3 {
		return "", ""
	}
	return match[1], match[2]
}

func parseSSHBanner(value string) (string, string) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) < 3 {
		return "SSH server", ""
	}
	product, version := parseProductVersion(strings.ReplaceAll(parts[2], "_", "/"))
	if product == "" {
		return parts[2], ""
	}
	return product, version
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	openEnd := strings.Index(lower[start:], ">")
	if openEnd < 0 {
		return ""
	}
	contentStart := start + openEnd + 1
	end := strings.Index(lower[contentStart:], "</title>")
	if end < 0 {
		return ""
	}
	title := body[contentStart : contentStart+end]
	title = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(title, "")
	return cleanEvidence(html.UnescapeString(title))
}

func requestHost(target model.Target) string {
	if name, err := netip.ParseAddr(target.Name); err == nil {
		return name.String()
	}
	if strings.Contains(target.Name, "/") || strings.Contains(target.Name, "-") {
		return target.Address
	}
	return strings.TrimSuffix(target.Name, ".")
}

func verificationName(target model.Target) string {
	return requestHost(target)
}

func tlsServerName(target model.Target) string {
	name := requestHost(target)
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	return name
}

func protocolName(secure bool) string {
	if secure {
		return "https"
	}
	return "http"
}

func serviceName(port int) string {
	if name, ok := serviceNames[port]; ok {
		return name
	}
	return "tcp"
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func cleanEvidence(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	return strings.TrimSpace(strings.Join(strings.Fields(value), " "))
}

func id() string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}
