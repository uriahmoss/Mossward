package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mossward/internal/api"
	"mossward/internal/auth"
	"mossward/internal/config"
	"mossward/internal/intelligence"
	"mossward/internal/scanner"
	"mossward/internal/store"
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
	if err := run(); err != nil {
		slog.Error("Mossward stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
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
	handler := api.New(cfg, repository, engine, identityService)
	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}

	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("Mossward server started", "address", cfg.ListenAddress)
		if serveErr := server.ListenAndServe(); !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrors <- serveErr
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case received := <-stop:
		slog.Info("Mossward shutdown requested", "signal", received.String())
	case serveErr := <-serverErrors:
		return fmt.Errorf("serve Mossward: %w", serveErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shut down HTTP server: %w", err)
	}
	slog.Info("Mossward server stopped")
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
