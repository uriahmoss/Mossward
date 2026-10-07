package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"mossward/internal/auth"
	"mossward/internal/config"
	"mossward/internal/serverbackup"
	"mossward/internal/store"
)

const defaultMaintenanceTimeout = time.Hour

func runPostgreSQLMaintenance(cfg config.Config, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: mossward backup create|inspect|restore or identity-key rotate")
	}
	flags := flag.NewFlagSet(args[0]+" "+args[1], flag.ContinueOnError)
	input := flags.String("input", "", "trusted backup archive to inspect or restore")
	output := flags.String("output", "", "new backup archive path")
	backup := flags.String("backup", "", "new mandatory pre-rotation backup archive")
	tools := flags.String("pg-tools-dir", "", "directory containing pg_dump and pg_restore (default PATH)")
	timeout := flags.Duration("timeout", defaultMaintenanceTimeout, "maximum PostgreSQL maintenance duration")
	offline := flags.Bool("confirm-offline", false, "confirm the Mossward service is stopped")
	restore := flags.Bool("confirm-restore", false, "confirm recovery into an empty database and new file destinations")
	rotation := flags.Bool("confirm-rotation", false, "confirm offline identity-key rotation")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		return errors.New("maintenance requires a positive timeout and no positional arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	options := serverbackup.PostgreSQLOptions{URL: cfg.DatabaseURL, ToolsDir: *tools}
	source := serverbackup.Source{IdentityKeyFile: cfg.IdentityKeyFile, ACMECacheDir: cfg.ACMECacheDirectory, AgentPKIDir: cfg.AgentPKIDirectory}
	switch args[0] + " " + args[1] {
	case "backup inspect":
		if *input == "" {
			return errors.New("backup inspect requires --input <archive>")
		}
		manifest, err := serverbackup.Inspect(*input)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(manifest)
	case "backup create":
		if *output == "" || !*offline {
			return errors.New("PostgreSQL backup requires --output <archive> and --confirm-offline; stop Mossward first")
		}
		return serverbackup.CreatePostgreSQL(ctx, *output, options, source, time.Now().UTC())
	case "backup restore":
		if *input == "" || !*offline || !*restore {
			return errors.New("PostgreSQL restore requires --input <trusted archive>, --confirm-offline, and --confirm-restore")
		}
		targets := serverbackup.RestoreTargets{IdentityKeyFile: cfg.IdentityKeyFile, ACMECacheDir: cfg.ACMECacheDirectory, AgentPKIDir: cfg.AgentPKIDirectory}
		_, err := serverbackup.RestorePostgreSQL(ctx, *input, options, targets)
		return err
	case "identity-key rotate":
		if *backup == "" || !*rotation {
			return errors.New("identity-key rotation requires --backup <new archive> and --confirm-rotation; stop Mossward first")
		}
		return rotatePostgreSQLIdentityKey(ctx, cfg, options, source, *backup)
	default:
		return errors.New("unsupported PostgreSQL maintenance command")
	}
}

func rotatePostgreSQLIdentityKey(ctx context.Context, cfg config.Config, options serverbackup.PostgreSQLOptions, source serverbackup.Source, backup string) error {
	if err := serverbackup.CreatePostgreSQL(ctx, backup, options, source, time.Now().UTC()); err != nil {
		return fmt.Errorf("create and verify mandatory pre-rotation backup: %w", err)
	}
	repository, err := store.OpenPostgreSQL(ctx, cfg.DatabaseURL)
	if err != nil {
		return errors.New("open PostgreSQL rotation repository failed")
	}
	defer repository.Close()
	box, err := auth.BeginIdentityKeyRotation(cfg.IdentityKeyFile)
	if err != nil {
		return err
	}
	rotated, err := repository.RotateIdentityCiphertextsContext(ctx, box, time.Now().UTC())
	if err != nil {
		slog.Error("PostgreSQL identity-key rotation failed; retain the pending keyring and pre-rotation backup")
		return err
	}
	if err := box.FinalizeIdentityKeyRotation(cfg.IdentityKeyFile); err != nil {
		return fmt.Errorf("ciphertexts rotated; retain the pending keyring and retry rotation before starting Mossward: %w", err)
	}
	slog.Info("PostgreSQL identity encryption key rotated", "ciphertexts", rotated)
	return nil
}
