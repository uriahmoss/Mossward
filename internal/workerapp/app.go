package workerapp

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"mossward/internal/model"
	"mossward/internal/privatefs"
	"mossward/internal/probe"
	"mossward/internal/workerclient"
	"mossward/internal/workerevidence"
)

const workerHTTPTimeout = 45 * time.Second

type App struct {
	runtime      *workerclient.Runtime
	transport    *workerclient.Transport
	outbox       *workerclient.Outbox
	ledger       *workerclient.ReplayLedger
	worker       model.ScannerWorker
	retry        *workerclient.RetryScheduler
	pollInterval time.Duration
}

func New(config Config) (*App, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	certificate, signer, roots, err := loadWorkerTLSIdentity(config)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: workerHTTPTimeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}}
	transport, err := workerclient.NewTransport(config.ServerURL, client)
	if err != nil {
		return nil, err
	}
	outbox, err := workerclient.OpenOutbox(filepath.Join(config.StateDirectory, "outbox.db"),
		filepath.Join(config.StateDirectory, "outbox.key"), workerclient.OutboxLimits{MaxItems: config.OutboxMaximumItems, MaxBytes: config.OutboxMaximumBytes})
	if err != nil {
		return nil, err
	}
	ledger, err := workerclient.OpenReplayLedger(filepath.Join(config.StateDirectory, "replay.db"))
	if err != nil {
		_ = outbox.Close()
		return nil, err
	}
	executor, err := workerclient.NewExecutor(probe.New(config.ProbeTimeout()), func(batch model.WorkerEvidenceBatch) (model.SignedWorkerEvidenceBatch, error) {
		return workerevidence.Sign(batch, certificate.Leaf, signer)
	})
	if err != nil {
		_ = ledger.Close()
		_ = outbox.Close()
		return nil, err
	}
	publicKey, _ := config.JobPublicKey()
	worker := config.Worker()
	// The local execution identity must expire with its authenticated certificate.
	// A zero expiry makes every otherwise valid signed job fail closed.
	worker.ExpiresAt = certificate.Leaf.NotAfter
	workerRuntime, err := workerclient.NewRuntime(transport, outbox, executor, worker, publicKey, ledger,
		workerclient.DefaultBackpressurePolicy())
	if err != nil {
		_ = ledger.Close()
		_ = outbox.Close()
		return nil, err
	}
	retry, _ := workerclient.NewRetryScheduler(workerclient.DefaultRetryPolicy())
	return &App{runtime: workerRuntime, transport: transport, outbox: outbox, ledger: ledger, worker: worker,
		retry: retry, pollInterval: config.PollInterval()}, nil
}

func (a *App) Run(ctx context.Context) error {
	slog.Info("Mossward scanner worker started", "poll_interval", a.pollInterval)
	consecutiveFailures := 0
	for {
		delay := a.pollInterval
		err := a.runCycle(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			consecutiveFailures++
			retryAfter := time.Duration(0)
			var transportError *workerclient.TransportError
			if errors.As(err, &transportError) {
				retryAfter = transportError.RetryAfter
			}
			delay, _ = a.retry.Delay(consecutiveFailures, retryAfter)
			slog.Warn("Scanner-worker cycle failed", "error", err, "retry_in", delay)
		} else {
			consecutiveFailures = 0
		}
		if !waitForWorkerCycle(ctx, delay) {
			slog.Info("Mossward scanner worker stopped")
			return nil
		}
	}
}

func (a *App) runCycle(ctx context.Context) error {
	heartbeat := model.WorkerHeartbeat{SchemaVersion: 1, SoftwareVersion: "1.0.0", OperatingSystem: runtime.GOOS,
		Architecture: runtime.GOARCH, Capabilities: a.worker.Capabilities, AvailableConcurrency: a.worker.MaxConcurrent,
		Health: model.WorkerHealthHealthy}
	if err := a.transport.CheckIn(ctx, heartbeat); err != nil {
		return fmt.Errorf("send scanner-worker heartbeat: %w", err)
	}
	return a.runtime.RunOnce(ctx)
}

func waitForWorkerCycle(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (a *App) Close() error {
	a.transport.CloseIdleConnections()
	return errors.Join(a.ledger.Close(), a.outbox.Close())
}

func loadWorkerTLSIdentity(config Config) (tls.Certificate, crypto.Signer, *x509.CertPool, error) {
	if err := requirePrivateKeyPermissions(config.PrivateKeyFile); err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	certificate, err := tls.LoadX509KeyPair(config.CertificateFile, config.PrivateKeyFile)
	if err != nil {
		return certificate, nil, nil, fmt.Errorf("load scanner-worker certificate and key: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return certificate, nil, nil, errors.New("scanner-worker certificate chain is empty")
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return certificate, nil, nil, fmt.Errorf("parse scanner-worker certificate: %w", err)
	}
	if err := validateWorkerCertificate(certificate.Leaf, config.WorkerID, time.Now().UTC()); err != nil {
		return certificate, nil, nil, err
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return certificate, nil, nil, errors.New("scanner-worker private key cannot sign evidence")
	}
	caPEM, err := os.ReadFile(config.CAFile)
	if err != nil {
		return certificate, nil, nil, fmt.Errorf("read scanner-worker CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return certificate, nil, nil, errors.New("scanner-worker CA file contains no certificates")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range certificate.Certificate[1:] {
		issuer, err := x509.ParseCertificate(raw)
		if err != nil {
			return certificate, nil, nil, errors.New("invalid scanner-worker certificate chain")
		}
		intermediates.AddCert(issuer)
	}
	if _, err := certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return certificate, nil, nil, errors.New("scanner-worker certificate is not trusted for client authentication")
	}
	return certificate, signer, roots, nil
}

func validateWorkerCertificate(certificate *x509.Certificate, workerID string, now time.Time) error {
	if certificate == nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("scanner-worker certificate is not currently valid")
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("scanner-worker certificate cannot sign evidence")
	}
	wantedIdentity := "spiffe://mossward/scanner-worker/" + workerID
	for _, identity := range certificate.URIs {
		if identity.String() == wantedIdentity {
			return nil
		}
	}
	return errors.New("scanner-worker certificate does not match the configured worker ID")
}

func requirePrivateKeyPermissions(path string) error {
	return privatefs.Check(path)
}
