package agentapp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mossward/internal/agentintegrity"
	"mossward/internal/agentupdate"
	"mossward/internal/model"
	"mossward/internal/networkpolicy"
)

const (
	agentRequestTimeout    = 30 * time.Second
	certificateRenewalLead = 30 * 24 * time.Hour
	maximumRetryExponent   = 8
)

var Version = "development"

type App struct {
	client            *http.Client
	checkInURL        string
	renewURL          string
	interval          time.Duration
	config            Config
	certificate       *x509.Certificate
	updateKeyID       string
	updateKey         ed25519.PublicKey
	moduleTrust       map[string]ed25519.PublicKey
	networkExclusions model.NetworkTelemetryExclusions
	identityKey       *ecdsa.PrivateKey
}

func New(config Config) (*App, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	localNetworkExclusions, err := networkpolicy.Normalize(config.NetworkExclusions)
	if err != nil {
		return nil, err
	}
	config.NetworkExclusions = localNetworkExclusions

	certificate, leaf, roots, err := loadIdentity(config.StateDirectory)
	if err != nil {
		return nil, err
	}
	updateKeyID, updateKey, err := config.UpdateTrust()
	if err != nil {
		return nil, err
	}
	moduleTrust, err := config.ModuleTrust()
	if err != nil {
		return nil, err
	}
	identityKey, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("endpoint-agent identity key must be ECDSA")
	}
	base := strings.TrimRight(config.EndpointURL, "/")
	return &App{
		client:      identityClient(certificate, roots),
		checkInURL:  base + "/api/agent/v1/check-in",
		renewURL:    base + "/api/agent/v1/certificate/renew",
		interval:    config.CheckInInterval(),
		config:      config,
		certificate: leaf,
		updateKeyID: updateKeyID,
		updateKey:   updateKey,
		moduleTrust: moduleTrust,
		identityKey: identityKey,
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	slog.Info("Mossward endpoint agent started", "check_in_interval", a.interval)
	failures := 0
	for {
		if time.Until(a.certificate.NotAfter) <= certificateRenewalLead {
			if err := a.renew(ctx); err != nil {
				slog.Warn("Endpoint-agent certificate renewal failed", "error", err)
			}
		}

		err := a.checkIn(ctx)
		if errors.Is(err, agentupdate.ErrRestartRequired) {
			return err
		}
		delay := a.interval
		if err != nil && !errors.Is(err, context.Canceled) {
			failures++
			delay = retryDelay(a.interval, failures)
			slog.Warn("Endpoint-agent check-in failed", "error", err, "retry_in", delay)
		} else {
			failures = 0
		}
		if waitForNextCheckIn(ctx, delay) {
			continue
		}

		slog.Info("Mossward endpoint agent stopped")
		return nil
	}
}

func (a *App) checkIn(ctx context.Context) error {
	now := time.Now().UTC()
	osInventory, err := collectOSInventory(a.config.CollectorAllowlist, now)
	if err != nil {
		slog.Warn("Endpoint OS inventory collection failed", "error", err)
	}
	softwareInventory, err := collectSoftwareInventory(a.config.CollectorAllowlist, now)
	if err != nil {
		slog.Warn("Endpoint software inventory collection failed", "error", err)
	}
	listeningInventory, err := collectListeningInventory(a.config.CollectorAllowlist, now)
	if err != nil {
		slog.Warn("Endpoint listening-service inventory collection failed", "error", err)
	}
	postureInventory, err := collectPostureInventory(a.config.CollectorAllowlist, now)
	if err != nil {
		slog.Warn("Endpoint security-posture collection failed", "error", err)
	}
	networkInventory, err := collectNetworkInventory(a.config.CollectorAllowlist, now, a.config.NetworkExclusions, a.networkExclusions)
	if err != nil {
		slog.Warn("Endpoint network metadata collection failed", "error", err)
	}
	integritySnapshot, err := collectIntegritySnapshot(a.config, now)
	if err != nil {
		slog.Warn("Endpoint-agent integrity fingerprint collection degraded", "error", err)
	}
	sequence, err := nextIntegritySequence(a.config.StateDirectory)
	if err != nil {
		return fmt.Errorf("advance endpoint integrity sequence: %w", err)
	}
	signedIntegrity, err := agentintegrity.Sign(a.identityKey, sequence, *integritySnapshot)
	if err != nil {
		return fmt.Errorf("sign endpoint integrity snapshot: %w", err)
	}
	payload, err := json.Marshal(model.AgentCheckIn{SchemaVersion: 2, GeneratedAt: now, SoftwareVersion: Version,
		OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH, SupportedCollectors: supportedCollectorIDs(), ModuleHealth: moduleHealth(a.config.ModuleDirectory()), OSInventory: osInventory, SoftwareInventory: softwareInventory, ListeningInventory: listeningInventory, PostureInventory: postureInventory, NetworkInventory: networkInventory, IntegritySnapshot: &signedIntegrity})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.checkInURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("endpoint check-in returned status %d", response.StatusCode)
	}
	var result model.AgentCheckInResponse
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("decode endpoint check-in: %w", err)
	}
	if err := validateCollectorAllowlist(result.AllowedCollectors); err != nil {
		return fmt.Errorf("reject endpoint collector policy: %w", err)
	}
	networkExclusions, err := networkpolicy.Normalize(result.NetworkExclusions)
	if err != nil {
		return fmt.Errorf("reject endpoint network-exclusion policy: %w", err)
	}
	a.networkExclusions = networkExclusions
	effective := effectiveCollectors(a.config.CollectorAllowlist, result.AllowedCollectors)
	slog.Info("Endpoint collector policy received", "server_allowed", len(result.AllowedCollectors), "effective", len(effective),
		"network_application_exclusions", len(networkExclusions.Applications), "network_destination_exclusions", len(networkExclusions.Destinations))
	if err := agentupdate.ConfirmHealthy(a.config.UpdateStateDirectory(), Version, time.Now().UTC()); err != nil {
		return fmt.Errorf("confirm endpoint-agent update health: %w", err)
	}
	if err := a.applyUpdateOffer(ctx, result.UpdateEnvelope); err != nil {
		return err
	}
	if a.config.ModulesEnabled {
		if err := applyModuleOffers(a.config.ModuleDirectory(), result.ModuleOffers, a.moduleTrust); err != nil {
			return fmt.Errorf("apply endpoint module offers: %w", err)
		}
	}
	return nil
}

func (a *App) renew(ctx context.Context) error {
	_, csr, key, err := newIdentityMaterial()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{"csr_pem": string(csr)})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.renewURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("certificate renewal returned status %d", response.StatusCode)
	}

	var result enrollmentResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode certificate renewal: %w", err)
	}
	certificate, err := tls.X509KeyPair([]byte(result.CertificatePEM), key)
	if err != nil {
		return errors.New("renewed certificate does not match generated key")
	}
	leaf, err := parseLeaf(certificate)
	if err != nil {
		return err
	}
	roots, err := rootsFromPEM([]byte(result.CAChainPEM))
	if err != nil {
		return err
	}
	if err := saveIdentity(a.config.StateDirectory, key, []byte(result.CertificatePEM), []byte(result.CAChainPEM), result.Endpoint); err != nil {
		return err
	}

	previousTransport, _ := a.client.Transport.(*http.Transport)
	a.client = identityClient(certificate, roots)
	a.certificate = leaf
	identityKey, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("renewed endpoint-agent identity key must be ECDSA")
	}
	a.identityKey = identityKey
	if previousTransport != nil {
		previousTransport.CloseIdleConnections()
	}
	slog.Info("Mossward endpoint-agent certificate renewed", "expires_at", leaf.NotAfter)
	return nil
}

func loadIdentity(directory string) (tls.Certificate, *x509.Certificate, *x509.CertPool, error) {
	certificatePath := filepath.Join(directory, "agent-cert.pem")
	keyPath := filepath.Join(directory, "agent-key.pem")
	if err := requirePrivatePermissions(keyPath); err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("load endpoint-agent identity: %w", err)
	}
	leaf, err := parseLeaf(certificate)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	roots, err := loadRoots(filepath.Join(directory, "agent-ca.pem"))
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	return certificate, leaf, roots, nil
}

func parseLeaf(certificate tls.Certificate) (*x509.Certificate, error) {
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("endpoint-agent certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.New("endpoint-agent certificate is invalid")
	}
	return leaf, nil
}

func identityClient(certificate tls.Certificate, roots *x509.CertPool) *http.Client {
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	}}
	return &http.Client{Timeout: agentRequestTimeout, Transport: transport}
}

func retryDelay(interval time.Duration, failures int) time.Duration {
	exponent := min(failures, maximumRetryExponent)
	return min(interval, time.Duration(1<<exponent)*time.Second)
}

func waitForNextCheckIn(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func loadRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read endpoint-agent CA: %w", err)
	}
	return rootsFromPEM(data)
}

func rootsFromPEM(data []byte) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("endpoint-agent CA contains no certificates")
	}
	return roots, nil
}

func requirePrivatePermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect endpoint-agent private key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("endpoint-agent private key permissions are too broad")
	}
	return nil
}
