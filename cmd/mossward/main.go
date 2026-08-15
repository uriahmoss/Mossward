package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"mossward/internal/agentidentity"
	"mossward/internal/agentmodulecatalog"
	"mossward/internal/agentupdatecatalog"
	"mossward/internal/api"
	"mossward/internal/auth"
	"mossward/internal/config"
	"mossward/internal/intelligence"
	"mossward/internal/model"
	"mossward/internal/notification"
	"mossward/internal/scanlaunch"
	"mossward/internal/scanner"
	"mossward/internal/scheduling"
	"mossward/internal/serverbackup"
	"mossward/internal/store"
	"mossward/internal/transport"
	"mossward/internal/workerjob"
)

const (
	serverReadHeaderTimeout = 5 * time.Second
	serverReadTimeout       = 15 * time.Second
	serverWriteTimeout      = 30 * time.Second
	serverIdleTimeout       = 60 * time.Second
	shutdownTimeout         = 10 * time.Second
	defaultCVELookbackDays  = 120
	maxCVELookbackDays      = 120
	publicNVDPageDelay      = 6 * time.Second
	keyedNVDPageDelay       = 700 * time.Millisecond
)

func main() {
	if err := runPlatform(run); err != nil {
		slog.Error("Mossward stopped", "error", err)
		os.Exit(1)
	}
}

func run(stop <-chan string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if len(os.Args) > 2 && os.Args[1] == "backup" && (os.Args[2] == "restore" || os.Args[2] == "inspect") {
		return runBackupCommand(cfg, nil, os.Args[2:])
	}
	maintenanceCommand := len(os.Args) > 1 && (os.Args[1] == "backup" || os.Args[1] == "identity-key" || os.Args[1] == "cve")
	if !maintenanceCommand {
		if err := validateTLSConfiguration(cfg); err != nil {
			return err
		}
	}

	repository, err := store.NewSQLiteStore(cfg.DatabaseFile, cfg.LegacyDataFile)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := repository.Close(); closeErr != nil {
			slog.Warn("Could not close the database cleanly", "error", closeErr)
		}
	}()
	if len(os.Args) > 1 && os.Args[1] == "cve" {
		return runCVECommand(repository, os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "backup" {
		return runBackupCommand(cfg, repository, os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "identity-key" {
		return runIdentityKeyCommand(cfg, repository, os.Args[2:])
	}
	secretBox, err := auth.LoadOrCreateSecretBox(cfg.IdentityKeyFile)
	if err != nil {
		return err
	}
	webauthnManager, err := auth.NewWebAuthnManager(cfg.WebAuthnRPID, cfg.WebAuthnOrigins)
	if err != nil {
		return err
	}
	identityService, err := auth.NewService(repository, secretBox, webauthnManager)
	if err != nil {
		return err
	}

	engine, err := scanner.New(cfg, repository)
	if err != nil {
		return err
	}
	defer engine.Shutdown()
	notificationService := notification.New(repository, secretBox)
	agentIdentity, workerDispatcher, err := newAgentIdentity(cfg, repository)
	if err != nil {
		return err
	}
	updateKeyID, updateKey, err := cfg.AgentUpdateTrust()
	if err != nil {
		return err
	}
	agentUpdates := agentupdatecatalog.New(repository, updateKeyID, updateKey)
	agentModules := agentmodulecatalog.New(repository)
	if agentUpdates != nil {
		slog.Info("Mossward endpoint-agent release trust loaded", "key_id", updateKeyID)
	}
	policyLauncher, err := scanlaunch.New(repository, engine, workerDispatcher)
	if err != nil {
		return err
	}
	scheduleRunner := scheduling.NewRunner(repository, engine, notificationService, policyLauncher)
	scheduleRunner.Start()
	defer scheduleRunner.Close()
	acmeManager, err := newACMEManager(cfg, repository)
	if err != nil {
		return err
	}
	if acmeManager != nil {
		defer acmeManager.Close()
	}
	options := api.RuntimeOptions{}
	if acmeManager != nil {
		options.CertificateStatus = acmeManager.Status
	}
	options.AgentIdentity = agentIdentity
	options.AgentUpdates = agentUpdates
	options.AgentModules = agentModules
	options.Notifications = notificationService
	options.PolicyLauncher = policyLauncher
	handler := api.New(cfg, repository, engine, identityService, options)
	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	var challengeServer *http.Server
	var agentServer *http.Server
	if acmeManager != nil {
		server.TLSConfig = acmeManager.TLSConfig()
		challengeServer = &http.Server{Addr: cfg.ACMEHTTPListen, Handler: acmeManager.HTTPHandler(),
			ReadHeaderTimeout: serverReadHeaderTimeout, ReadTimeout: serverReadTimeout,
			WriteTimeout: serverWriteTimeout, IdleTimeout: serverIdleTimeout}
	}
	if agentIdentity != nil {
		agentServer = &http.Server{Addr: cfg.AgentListen, Handler: agentIdentity.Handler(), TLSConfig: agentIdentity.TLSConfig(),
			ReadHeaderTimeout: serverReadHeaderTimeout, ReadTimeout: serverReadTimeout,
			WriteTimeout: serverWriteTimeout, IdleTimeout: serverIdleTimeout}
	}

	serverErrors := make(chan error, 3)
	go func() {
		slog.Info("Mossward server started", "address", cfg.ListenAddress, "transport", cfg.TransportMode)
		if serveErr := serve(server, cfg); !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrors <- serveErr
		}
	}()
	if challengeServer != nil {
		go func() {
			slog.Info("Mossward ACME HTTP-01 listener started", "address", cfg.ACMEHTTPListen)
			if serveErr := challengeServer.ListenAndServe(); !errors.Is(serveErr, http.ErrServerClosed) {
				serverErrors <- fmt.Errorf("serve ACME HTTP-01 challenge: %w", serveErr)
			}
		}()
	}
	if agentServer != nil {
		go func() {
			slog.Info("Mossward endpoint mTLS listener started", "address", cfg.AgentListen)
			if serveErr := agentServer.ListenAndServeTLS("", ""); !errors.Is(serveErr, http.ErrServerClosed) {
				serverErrors <- fmt.Errorf("serve endpoint mTLS API: %w", serveErr)
			}
		}()
	}

	select {
	case received := <-stop:
		slog.Info("Mossward shutdown requested", "source", received)
	case serveErr := <-serverErrors:
		return fmt.Errorf("serve Mossward: %w", serveErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shut down HTTP server: %w", err)
	}
	if challengeServer != nil {
		if err := challengeServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("shut down ACME HTTP-01 server: %w", err)
		}
	}
	if agentServer != nil {
		if err := agentServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("shut down endpoint mTLS server: %w", err)
		}
	}
	slog.Info("Mossward server stopped")
	return nil
}

func runIdentityKeyCommand(cfg config.Config, repository *store.SQLiteStore, args []string) error {
	if len(args) == 0 || args[0] != "rotate" {
		return errors.New("usage: mossward identity-key rotate --backup <archive> --confirm-rotation")
	}
	flags := flag.NewFlagSet("identity-key rotate", flag.ContinueOnError)
	backupPath := flags.String("backup", "", "required pre-rotation backup archive")
	confirmed := flags.Bool("confirm-rotation", false, "confirm offline identity-key rotation")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *backupPath == "" || !*confirmed {
		return errors.New("identity-key rotation requires --backup <archive> and --confirm-rotation; stop the Mossward service first")
	}
	source := serverbackup.Source{IdentityKeyFile: cfg.IdentityKeyFile,
		ACMECacheDir: cfg.ACMECacheDirectory, AgentPKIDir: cfg.AgentPKIDirectory}
	if err := serverbackup.Create(*backupPath, repository, source, time.Now().UTC()); err != nil {
		return fmt.Errorf("create mandatory pre-rotation backup: %w", err)
	}
	box, err := auth.BeginIdentityKeyRotation(cfg.IdentityKeyFile)
	if err != nil {
		return err
	}
	rotated, err := repository.RotateIdentityCiphertexts(box, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := box.FinalizeIdentityKeyRotation(cfg.IdentityKeyFile); err != nil {
		return fmt.Errorf("finalize identity keyring: %w", err)
	}
	slog.Info("Mossward identity encryption key rotated", "ciphertexts", rotated, "backup", *backupPath)
	return nil
}

func runBackupCommand(cfg config.Config, repository *store.SQLiteStore, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mossward backup create|inspect|restore")
	}
	flags := flag.NewFlagSet("backup "+args[0], flag.ContinueOnError)
	input := flags.String("input", "", "backup archive to inspect or restore")
	output := flags.String("output", "", "new backup archive path")
	confirmRestore := flags.Bool("confirm-restore", false, "confirm replacement of current server data")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "create":
		if repository == nil || *output == "" {
			return errors.New("usage: mossward backup create --output <archive>")
		}
		source := serverbackup.Source{IdentityKeyFile: cfg.IdentityKeyFile,
			ACMECacheDir: cfg.ACMECacheDirectory, AgentPKIDir: cfg.AgentPKIDirectory}
		if err := serverbackup.Create(*output, repository, source, time.Now().UTC()); err != nil {
			return err
		}
		slog.Info("Mossward backup created", "archive", *output)
		return nil
	case "inspect":
		if *input == "" {
			return errors.New("usage: mossward backup inspect --input <archive>")
		}
		manifest, err := serverbackup.Inspect(*input)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(manifest)
	case "restore":
		if *input == "" || !*confirmRestore {
			return errors.New("restore requires --input <archive> and --confirm-restore; stop the Mossward service first")
		}
		targets := serverbackup.RestoreTargets{DatabaseFile: cfg.DatabaseFile, IdentityKeyFile: cfg.IdentityKeyFile,
			ACMECacheDir: cfg.ACMECacheDirectory, AgentPKIDir: cfg.AgentPKIDirectory}
		result, err := serverbackup.Restore(*input, targets, time.Now().UTC())
		if err != nil {
			return err
		}
		slog.Info("Mossward backup restored", "archive", *input, "recovery_paths", result.RecoveryPaths)
		return nil
	default:
		return errors.New("usage: mossward backup create|inspect|restore")
	}
}

func newAgentIdentity(cfg config.Config, repository store.Repository) (*agentidentity.Service, *workerjob.Dispatcher, error) {
	if cfg.AgentListen == "" {
		return nil, nil, nil
	}
	pki, err := agentidentity.LoadOrCreatePKI(cfg.AgentPKIDirectory, cfg.AgentServerNames, time.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	slog.Info("Mossward endpoint certificate authority loaded", "directory", cfg.AgentPKIDirectory)
	jobSigner, err := workerjob.LoadOrCreateSigner(cfg.AgentPKIDirectory)
	if err != nil {
		return nil, nil, fmt.Errorf("load scanner-worker job signer: %w", err)
	}
	slog.Info("Mossward scanner-worker job signer loaded", "key_id", jobSigner.KeyID())
	dispatcher, err := workerjob.NewDispatcher(repository, jobSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize scanner-worker dispatcher: %w", err)
	}
	return agentidentity.NewService(repository, pki, jobSigner), dispatcher, nil
}

func serve(server *http.Server, cfg config.Config) error {
	if cfg.TransportMode == config.TransportTLS {
		return server.ListenAndServeTLS(cfg.TLSCertificateFile, cfg.TLSPrivateKeyFile)
	}
	if cfg.TransportMode == config.TransportACME {
		return server.ListenAndServeTLS("", "")
	}
	return server.ListenAndServe()
}

func newACMEManager(cfg config.Config, repository store.Repository) (*transport.ACMEManager, error) {
	if cfg.TransportMode != config.TransportACME {
		return nil, nil
	}
	if err := transport.PrepareACMECache(cfg.ACMECacheDirectory); err != nil {
		return nil, err
	}
	origin, err := url.Parse(cfg.PublicOrigin)
	if err != nil {
		return nil, fmt.Errorf("parse ACME public origin: %w", err)
	}
	onCertificate := func(event transport.CertificateEvent) {
		details := fmt.Sprintf(`{"hostname":%q,"expires_at":%q}`, event.Hostname, event.ExpiresAt.Format(time.RFC3339))
		auditEvent := model.AuditEvent{OccurredAt: time.Now().UTC(), Action: "transport.acme.certificate_" + event.Action,
			Severity: model.AuditInfo, TargetType: "certificate", TargetID: event.Hostname, Details: details}
		if err := repository.AppendAuditEvent(auditEvent); err != nil {
			slog.Warn("Could not record ACME certificate audit event", "action", event.Action, "error", err)
		}
	}
	return transport.NewACMEManager(transport.ACMEConfig{Hostname: origin.Hostname(), Email: cfg.ACMEEmail,
		CacheDir: cfg.ACMECacheDirectory, DirectoryURL: cfg.ACMEDirectoryURL}, onCertificate), nil
}

func validateTLSConfiguration(cfg config.Config) error {
	if cfg.TransportMode != config.TransportTLS {
		return nil
	}
	origin, err := url.Parse(cfg.PublicOrigin)
	if err != nil {
		return fmt.Errorf("parse public origin: %w", err)
	}
	status, err := transport.ValidateCertificate(cfg.TLSCertificateFile, cfg.TLSPrivateKeyFile, origin.Hostname(), time.Now())
	if err != nil {
		return err
	}
	if status.Warn {
		slog.Warn("TLS certificate expires soon", "expires_at", status.ExpiresAt)
	}
	return nil
}

func runCVECommand(repository store.Repository, args []string) error {
	if len(args) == 0 || args[0] != "sync" {
		return errors.New("usage: mossward cve sync [--days 120]")
	}
	flags := flag.NewFlagSet("cve sync", flag.ContinueOnError)
	days := flags.Int("days", defaultCVELookbackDays, "published-date lookback in days (maximum 120)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *days < 1 || *days > maxCVELookbackDays {
		return errors.New("--days must be between 1 and 120")
	}
	delay := publicNVDPageDelay
	apiKey := os.Getenv("MOSSWARD_NVD_API_KEY")
	if apiKey != "" {
		delay = keyedNVDPageDelay
	}
	client := intelligence.NVDClient{APIKey: apiKey, PageDelay: delay}
	until := time.Now().UTC()
	count, err := client.Sync(context.Background(), repository, until.AddDate(0, 0, -*days), until)
	if err != nil {
		return err
	}
	slog.Info("Mossward CVE intelligence updated", "records_processed", count)
	return nil
}
