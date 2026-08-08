package agentapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"time"
)

const diagnosticTimeout = 5 * time.Second

type DiagnosticStatus string

const (
	DiagnosticPass    DiagnosticStatus = "pass"
	DiagnosticWarning DiagnosticStatus = "warning"
	DiagnosticError   DiagnosticStatus = "error"
	DiagnosticSkipped DiagnosticStatus = "skipped"
)

type DiagnosticResult struct {
	Name    string           `json:"name"`
	Status  DiagnosticStatus `json:"status"`
	Message string           `json:"message"`
}

type DiagnosticReport struct {
	CheckedAt time.Time          `json:"checked_at"`
	Healthy   bool               `json:"healthy"`
	Results   []DiagnosticResult `json:"results"`
}

func Diagnose(ctx context.Context, config Config, offline bool) DiagnosticReport {
	report := DiagnosticReport{CheckedAt: time.Now().UTC(), Healthy: true}
	report.add(checkStateDirectory(config.StateDirectory))
	certificate, leaf, roots, err := loadIdentity(config.StateDirectory)
	if err != nil {
		report.add(DiagnosticResult{Name: "agent_identity", Status: DiagnosticError, Message: err.Error()})
		report.add(DiagnosticResult{Name: "mtls_connectivity", Status: DiagnosticSkipped, Message: "agent identity is unavailable"})
		return report
	}
	report.add(checkCertificate(leaf, report.CheckedAt))
	if offline {
		report.add(DiagnosticResult{Name: "mtls_connectivity", Status: DiagnosticSkipped, Message: "offline diagnostics requested"})
		return report
	}
	report.add(checkMTLS(ctx, config.EndpointURL, certificate, roots))
	return report
}

func (r *DiagnosticReport) add(result DiagnosticResult) {
	r.Results = append(r.Results, result)
	if result.Status == DiagnosticError {
		r.Healthy = false
	}
}

func checkStateDirectory(path string) DiagnosticResult {
	result := DiagnosticResult{Name: "state_directory", Status: DiagnosticPass, Message: "state directory is accessible"}
	info, err := os.Stat(path)
	if err != nil {
		result.Status, result.Message = DiagnosticError, fmt.Sprintf("inspect state directory: %v", err)
		return result
	}
	if !info.IsDir() {
		result.Status, result.Message = DiagnosticError, "configured state path is not a directory"
		return result
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		result.Status, result.Message = DiagnosticError, "state directory permissions allow group or other access"
	}
	return result
}

func checkCertificate(leaf *x509.Certificate, now time.Time) DiagnosticResult {
	result := DiagnosticResult{Name: "agent_certificate", Status: DiagnosticPass,
		Message: fmt.Sprintf("certificate is valid until %s", leaf.NotAfter.UTC().Format(time.RFC3339))}
	if now.Before(leaf.NotBefore) {
		result.Status, result.Message = DiagnosticError, "certificate is not valid yet; verify the system clock"
		return result
	}
	if !now.Before(leaf.NotAfter) {
		result.Status, result.Message = DiagnosticError, "certificate has expired"
		return result
	}
	if leaf.NotAfter.Sub(now) <= certificateRenewalLead {
		result.Status = DiagnosticWarning
		result.Message = fmt.Sprintf("certificate renewal is due before %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return result
}

func checkMTLS(ctx context.Context, endpointURL string, certificate tls.Certificate, roots *x509.CertPool) DiagnosticResult {
	result := DiagnosticResult{Name: "mtls_connectivity", Status: DiagnosticPass, Message: "TLS 1.3 mutual-authentication handshake succeeded"}
	parsed, err := url.Parse(endpointURL)
	if err != nil {
		result.Status, result.Message = DiagnosticError, "endpoint URL is invalid"
		return result
	}
	address := parsed.Host
	if parsed.Port() == "" {
		address = net.JoinHostPort(parsed.Hostname(), "443")
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: diagnosticTimeout},
		Config: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: parsed.Hostname(), RootCAs: roots,
			Certificates: []tls.Certificate{certificate}},
	}
	checkContext, cancel := context.WithTimeout(ctx, diagnosticTimeout)
	defer cancel()
	connection, err := dialer.DialContext(checkContext, "tcp", address)
	if err != nil {
		result.Status, result.Message = DiagnosticError, fmt.Sprintf("mTLS connection failed: %v", err)
		return result
	}
	_ = connection.Close()
	return result
}
