package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"

	"mossward/internal/workerapp"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Mossward scanner worker stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("mossward-worker", flag.ContinueOnError)
	configPath := flags.String("config", os.Getenv("MOSSWARD_WORKER_CONFIG"), "absolute path to the scanner-worker JSON configuration")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("scanner-worker configuration is required with --config or MOSSWARD_WORKER_CONFIG")
	}
	config, err := workerapp.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	app, err := workerapp.New(config)
	if err != nil {
		return err
	}
	defer func() {
		if err := app.Close(); err != nil {
			slog.Warn("Could not close scanner-worker state cleanly", "error", err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return app.Run(ctx)
}
