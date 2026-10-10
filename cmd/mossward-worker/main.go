package main

import (
	"errors"
	"flag"
	"log/slog"
	"os"

	"mossward/internal/workerapp"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Mossward scanner worker stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	return runArguments(os.Args[1:])
}

func runArguments(args []string) error {
	if len(args) > 0 && args[0] == "service" {
		return manageWorkerService(args[1:])
	}
	flags := flag.NewFlagSet("mossward-worker", flag.ContinueOnError)
	configPath := flags.String("config", os.Getenv("MOSSWARD_WORKER_CONFIG"), "absolute path to the scanner-worker JSON configuration")
	check := flags.Bool("check-config", false, "validate configuration and identity without network or state changes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || flags.NArg() != 0 {
		return errors.New("scanner-worker configuration is required with --config or MOSSWARD_WORKER_CONFIG")
	}
	config, err := workerapp.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *check {
		if err := workerapp.CheckConfig(config); err != nil {
			return err
		}
		slog.Info("Scanner-worker configuration and identity validated; no network or state changes")
		return nil
	}
	return runWorkerPlatform(config)
}
